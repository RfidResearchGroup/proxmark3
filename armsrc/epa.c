//-----------------------------------------------------------------------------
// Frederik Möllers - August 2012
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support the German electronic "Personalausweis" (ID card)
// Note that the functions which do not implement USB commands do NOT initialize
// the card (with iso14443a_select_card etc.). If You want to use these
// functions, You need to do the setup before calling them!
//-----------------------------------------------------------------------------
#include "epa.h"

// Protocol and Parameter Selection Request for ISO 14443 type A cards
// use regular (1x) speed in both directions
// CRC is already included
static const uint8_t pps[] = {0xD0, 0x11, 0x00, 0x52, 0xA6};

// APDUs for communication with German Identification Card

// General Authenticate (request encrypted nonce) WITHOUT the Le at the end
static const uint8_t apdu_general_authenticate_pace_get_nonce[] = {
	0x10, // CLA
	0x86, // INS
	0x00, // P1
	0x00, // P2
	0x02, // Lc
	0x7C, // Type: Dynamic Authentication Data
	0x00, // Length: 0 bytes
};

// MSE: Set AT (only CLA, INS, P1 and P2)
static const uint8_t apdu_mse_set_at_start[] = {
	0x00, // CLA
	0x22, // INS
	0xC1, // P1
	0xA4, // P2
};

// SELECT BINARY with the ID for EF.CardAccess
static const uint8_t apdu_select_binary_cardaccess[] = {
	0x00, // CLA
	0xA4, // INS
	0x02, // P1
	0x0C, // P2
	0x02, // Lc
	0x01, // ID
	0x1C  // ID
};

// READ BINARY
static const uint8_t apdu_read_binary[] = {
	0x00, // CLA
	0xB0, // INS
	0x00, // P1
	0x00, // P2
	0x38  // Le
};


// the leading bytes of a PACE OID
static const uint8_t oid_pace_start[] = {
    0x04, // itu-t, identified-organization
    0x00, // etsi
    0x7F, // reserved
    0x00, // etsi-identified-organization
    0x07, // bsi-de
    0x02, // protocols
    0x02, // smartcard
    0x04 // id-PACE
};

// APDUs for replaying:
// MSE: Set AT (initiate PACE)
static uint8_t apdu_replay_mse_set_at_pace[41];
// General Authenticate (Get Nonce)
static uint8_t apdu_replay_general_authenticate_pace_get_nonce[8];
// General Authenticate (Map Nonce)
static uint8_t apdu_replay_general_authenticate_pace_map_nonce[75];
// General Authenticate (Mutual Authenticate)
static uint8_t apdu_replay_general_authenticate_pace_mutual_authenticate[75];
// General Authenticate (Perform Key Agreement)
static uint8_t apdu_replay_general_authenticate_pace_perform_key_agreement[18];
// pointers to the APDUs (for iterations)
static struct {
	uint8_t len;
	uint8_t *data;
} const apdus_replay[] = {
	{sizeof(apdu_replay_mse_set_at_pace), apdu_replay_mse_set_at_pace},
	{sizeof(apdu_replay_general_authenticate_pace_get_nonce), apdu_replay_general_authenticate_pace_get_nonce},
	{sizeof(apdu_replay_general_authenticate_pace_map_nonce), apdu_replay_general_authenticate_pace_map_nonce},
	{sizeof(apdu_replay_general_authenticate_pace_mutual_authenticate), apdu_replay_general_authenticate_pace_mutual_authenticate},
	{sizeof(apdu_replay_general_authenticate_pace_perform_key_agreement), apdu_replay_general_authenticate_pace_perform_key_agreement}
};

// lengths of the replay APDUs
static uint8_t apdu_lengths_replay[5];

// type of card (ISO 14443 A or B)
static char iso_type = 0;

//-----------------------------------------------------------------------------
// Wrapper for sending APDUs to type A and B cards
//-----------------------------------------------------------------------------
int EPA_APDU(uint8_t *apdu, size_t length, uint8_t *response)
{
	switch(iso_type)
	{
		case 'a':
			return iso14_apdu(apdu, (uint16_t) length, response);
			break;
		case 'b':
			return iso14443b_apdu(apdu, length, response);
			break;
		default:
			return 0;
			break;
	}
}

//-----------------------------------------------------------------------------
// Closes the communication channel and turns off the field
//-----------------------------------------------------------------------------
void EPA_Finish()
{
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	iso_type = 0;
}

//-----------------------------------------------------------------------------
// Parses DER encoded data, e.g. from EF.CardAccess and fills out the given
// structs. If a pointer is 0, it is ignored.
// The function returns 0 on success and if an error occured, it returns the
// offset where it occured.
//
// TODO: This function can access memory outside of the given data if the DER
//       encoding is broken
// TODO: Support skipping elements with a length > 0x7F
// TODO: Support OIDs with a length > 7F
// TODO: Support elements with long tags (tag is longer than 1 byte)
// TODO: Support proprietary PACE domain parameters
//-----------------------------------------------------------------------------
size_t EPA_Parse_CardAccess(uint8_t *data,
                            size_t length,
                            pace_version_info_t *pace_info)
{
	size_t index = 0;

	while (index <= length - 2) {
		// determine type of element
		// SET or SEQUENCE
		if (data[index] == 0x31 || data[index] == 0x30) {
			// enter the set (skip tag + length)
			index += 2;
			// check for extended length
			if ((data[index - 1] & 0x80) != 0) {
				index += (data[index-1] & 0x7F);
			}
		}
		// OID
		else if (data[index] == 0x06) {
			// is this a PACE OID?
			if (data[index + 1] == 0x0A // length matches
			    && memcmp(data + index + 2,
			              oid_pace_start,
			              sizeof(oid_pace_start)) == 0 // content matches
			    && pace_info != NULL)
			{
				// first, clear the pace_info struct
				memset(pace_info, 0, sizeof(pace_version_info_t));
				memcpy(pace_info->oid, data + index + 2, sizeof(pace_info->oid));
				// a PACE OID is followed by the version
				index += data[index + 1] + 2;
				if (data[index] == 02 && data[index + 1] == 01) {
					pace_info->version = data[index + 2];
					index += 3;
				}
				else {
					return index;
				}
				// after that there might(!) be the parameter ID
				if (data[index] == 02 && data[index + 1] == 01) {
					pace_info->parameter_id = data[index + 2];
					index += 3;
				}
			}
			else {
				// skip this OID
				index += 2 + data[index + 1];
			}
		}
		// if the length is 0, something is wrong
		// TODO: This needs to be extended to support long tags
		else if (data[index + 1] == 0) {
			return index;
		}
		else {
			// skip this part
			// TODO: This needs to be extended to support long tags
			// TODO: This needs to be extended to support unknown elements with
			//       a size > 0x7F
			index += 2 + data[index + 1];
		}
	}

	// TODO: We should check whether we reached the end in error, but for that
	//       we need a better parser (e.g. with states like IN_SET or IN_PACE_INFO)
	return 0;
}

//-----------------------------------------------------------------------------
// Read the file EF.CardAccess and save it into a buffer (at most max_length bytes)
// Returns -1 on failure or the length of the data on success
// TODO: for the moment this sends only 1 APDU regardless of the requested length
//-----------------------------------------------------------------------------
int EPA_Read_CardAccess(uint8_t *buffer, size_t max_length)
{
	// the response APDU of the card
	// since the card doesn't always care for the expected length we send it,
	// we reserve 262 bytes here just to be safe (256-byte APDU + SW + ISO frame)
	uint8_t response_apdu[262];
	int rapdu_length = 0;

	// select the file EF.CardAccess
	rapdu_length = EPA_APDU((uint8_t *)apdu_select_binary_cardaccess,
	                          sizeof(apdu_select_binary_cardaccess),
	                          response_apdu);
	if (rapdu_length < 6
	    || response_apdu[rapdu_length - 4] != 0x90
	    || response_apdu[rapdu_length - 3] != 0x00)
	{
		DbpString("Failed to select EF.CardAccess!");
		return -1;
	}

	// read the file
	rapdu_length = EPA_APDU((uint8_t *)apdu_read_binary,
	                          sizeof(apdu_read_binary),
	                          response_apdu);
	if (rapdu_length <= 6
	    || response_apdu[rapdu_length - 4] != 0x90
	    || response_apdu[rapdu_length - 3] != 0x00)
	{
		Dbprintf("Failed to read EF.CardAccess!");
		return -1;
	}

	// copy the content into the buffer
	// length of data available: apdu_length - 4 (ISO frame) - 2 (SW)
	size_t to_copy = rapdu_length - 6;
	to_copy = to_copy < max_length ? to_copy : max_length;
	memcpy(buffer, response_apdu+2, to_copy);
	return to_copy;
}

//-----------------------------------------------------------------------------
// Abort helper function for EPA_PACE_Collect_Nonce
// sets relevant data in ack, sends the response
//-----------------------------------------------------------------------------
static void EPA_PACE_Collect_Nonce_Abort(uint8_t step, int func_return)
{
	// power down the field
	EPA_Finish();

	// send the USB packet
	cmd_send(CMD_ACK,step,func_return,0,0,0);
}

//-----------------------------------------------------------------------------
// Acquire one encrypted PACE nonce
//-----------------------------------------------------------------------------
void EPA_PACE_Collect_Nonce(UsbCommand *c)
{
	/*
	 * ack layout:
	 * 	arg:
	 * 		1. element
	 *           step where the error occured or 0 if no error occured
     *       2. element
     *           return code of the last executed function
	 * 	d:
	 * 		Encrypted nonce
	 */

	// return value of a function
	int func_return = 0;

	// set up communication
	func_return = EPA_Setup();
	if (func_return != 0) {	
		EPA_PACE_Collect_Nonce_Abort(1, func_return);
		return;
	}

	// read the CardAccess file
	// this array will hold the CardAccess file
	uint8_t card_access[256] = {0};
	int card_access_length = EPA_Read_CardAccess(card_access, 256);
	// the response has to be at least this big to hold the OID
	if (card_access_length < 18) {
		EPA_PACE_Collect_Nonce_Abort(2, card_access_length);
		return;
	}

	// this will hold the PACE info of the card
	pace_version_info_t pace_version_info;
	// search for the PACE OID
	func_return = EPA_Parse_CardAccess(card_access,
	                                   card_access_length,
	                                   &pace_version_info);
	if (func_return != 0 || pace_version_info.version == 0) {
		EPA_PACE_Collect_Nonce_Abort(3, func_return);
		return;
	}

	// initiate the PACE protocol
	// use the CAN for the password since that doesn't change
	func_return = EPA_PACE_MSE_Set_AT(pace_version_info, 2);

	// now get the nonce
	uint8_t nonce[256] = {0};
	uint8_t requested_size = (uint8_t)c->arg[0];
	func_return = EPA_PACE_Get_Nonce(requested_size, nonce);
	// check if the command succeeded
	if (func_return < 0)
	{
		EPA_PACE_Collect_Nonce_Abort(4, func_return);
		return;
	}

	// all done, return
	EPA_Finish();

	// save received information
	cmd_send(CMD_ACK,0,func_return,0,nonce,func_return);
}

//-----------------------------------------------------------------------------
// Performs the "Get Nonce" step of the PACE protocol and saves the returned
// nonce. The caller is responsible for allocating enough memory to store the
// nonce. Note that the returned size might be less or than or greater than the
// requested size!
// Returns the actual size of the nonce on success or a less-than-zero error
// code on failure.
//-----------------------------------------------------------------------------
int EPA_PACE_Get_Nonce(uint8_t requested_length, uint8_t *nonce)
{
	// build the APDU
	uint8_t apdu[sizeof(apdu_general_authenticate_pace_get_nonce) + 1];
	// copy the constant part
	memcpy(apdu,
	       apdu_general_authenticate_pace_get_nonce,
	       sizeof(apdu_general_authenticate_pace_get_nonce));
	// append Le (requested length + 2 due to tag/length taking 2 bytes) in RAPDU
	apdu[sizeof(apdu_general_authenticate_pace_get_nonce)] = requested_length + 4;

	// send it
	uint8_t response_apdu[262];
	int send_return = EPA_APDU(apdu,
	                             sizeof(apdu),
	                             response_apdu);
	// check if the command succeeded
	if (send_return < 6
		|| response_apdu[send_return - 4] != 0x90
		|| response_apdu[send_return - 3] != 0x00)
	{
		return -1;
	}

	// if there is no nonce in the RAPDU, return here
	if (send_return < 10)
	{
		// no error
		return 0;
	}
	// get the actual length of the nonce
	uint8_t nonce_length = response_apdu[5];
	if (nonce_length > send_return - 10)
	{
		nonce_length = send_return - 10;
	}
	// copy the nonce
	memcpy(nonce, response_apdu + 6, nonce_length);

	return nonce_length;
}

//-----------------------------------------------------------------------------
// Initializes the PACE protocol by performing the "MSE: Set AT" step
// Returns 0 on success or a non-zero error code on failure
//-----------------------------------------------------------------------------
int EPA_PACE_MSE_Set_AT(pace_version_info_t pace_version_info, uint8_t password)
{
	// create the MSE: Set AT APDU
	uint8_t apdu[23];
	// the minimum length (will be increased as more data is added)
	size_t apdu_length = 20;
	// copy the constant part
	memcpy(apdu,
	       apdu_mse_set_at_start,
	       sizeof(apdu_mse_set_at_start));
	// type: OID
	apdu[5] = 0x80;
	// length of the OID
	apdu[6] = sizeof(pace_version_info.oid);
	// copy the OID
	memcpy(apdu + 7,
	       pace_version_info.oid,
	       sizeof(pace_version_info.oid));
	// type: password
	apdu[17] = 0x83;
	// length: 1
	apdu[18] = 1;
	// password
	apdu[19] = password;
	// if standardized domain parameters are used, copy the ID
	if (pace_version_info.parameter_id != 0) {
		apdu_length += 3;
		// type: domain parameter
		apdu[20] = 0x84;
		// length: 1
		apdu[21] = 1;
		// copy the parameter ID
		apdu[22] = pace_version_info.parameter_id;
	}
	// now set Lc to the actual length
	apdu[4] = apdu_length - 5;
	// send it
	uint8_t response_apdu[6];
	int send_return = EPA_APDU(apdu,
	                             apdu_length,
	                             response_apdu);
	// check if the command succeeded
	if (send_return != 6
		|| response_apdu[send_return - 4] != 0x90
		|| response_apdu[send_return - 3] != 0x00)
	{
		return 1;
	}
	return 0;
}

//-----------------------------------------------------------------------------
// Perform the PACE protocol by replaying given APDUs
//-----------------------------------------------------------------------------
void EPA_PACE_Replay(UsbCommand *c)
{
	uint32_t timings[sizeof(apdu_lengths_replay) / sizeof(apdu_lengths_replay[0])] = {0};

	// if an APDU has been passed, save it
	if (c->arg[0] != 0) {
		// make sure it's not too big
		if(c->arg[2] > apdus_replay[c->arg[0] - 1].len)
		{
			cmd_send(CMD_ACK, 1, 0, 0, NULL, 0);
		}
		memcpy(apdus_replay[c->arg[0] - 1].data + c->arg[1],
	           c->d.asBytes,
	           c->arg[2]);
		// save/update APDU length
		if (c->arg[1] == 0) {
			apdu_lengths_replay[c->arg[0] - 1] = c->arg[2];
		} else {
			apdu_lengths_replay[c->arg[0] - 1] += c->arg[2];
		}
		cmd_send(CMD_ACK, 0, 0, 0, NULL, 0);
		return;
	}

	// return value of a function
	int func_return;

	// set up communication
	func_return = EPA_Setup();
	if (func_return != 0) {
		EPA_Finish();
		cmd_send(CMD_ACK, 2, func_return, 0, NULL, 0);
		return;
	}

	// increase the timeout (at least some cards really do need this!)/////////////
	// iso14a_set_timeout(0x0003FFFF);

	// response APDU
	uint8_t response_apdu[300] = {0};

	// now replay the data and measure the timings
	for (int i = 0; i < sizeof(apdu_lengths_replay); i++) {
		StartCountUS();
		func_return = EPA_APDU(apdus_replay[i].data,
		                         apdu_lengths_replay[i],
		                         response_apdu);
		timings[i] = GetCountUS();
		// every step but the last one should succeed
		if (i < sizeof(apdu_lengths_replay) - 1
		    && (func_return < 6
		        || response_apdu[func_return - 4] != 0x90
		        || response_apdu[func_return - 3] != 0x00))
		{
			EPA_Finish();
			cmd_send(CMD_ACK, 3 + i, func_return, 0, timings, 20);
			return;
		}
	}
	EPA_Finish();
	cmd_send(CMD_ACK,0,0,0,timings,20);
	return;
}

//-----------------------------------------------------------------------------
// Set up a communication channel (Card Select, PPS)
// Returns 0 on success or a non-zero error code on failure
//-----------------------------------------------------------------------------
int EPA_Setup()
{
	int return_code = 0;
	uint8_t uid[10];
	uint8_t pps_response[3];
	uint8_t pps_response_par[1];
	iso14a_card_select_t card_a_info;
	iso14b_card_select_t card_b_info;

	// first, look for type A cards
	// power up the field
	iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
	// select the card
	return_code = iso14443a_select_card(uid, &card_a_info, NULL, true, 0, false);
	if (return_code == 1) {
		// send the PPS request
		ReaderTransmit((uint8_t *)pps, sizeof(pps), NULL);
		return_code = ReaderReceive(pps_response, pps_response_par);
		if (return_code != 3 || pps_response[0] != 0xD0) {
			return return_code == 0 ? 2 : return_code;
		}
		Dbprintf("ISO 14443 Type A");
		iso_type = 'a';
		return 0;
	}

	// if we're here, there is no type A card, so we look for type B
	// power up the field
	iso14443b_setup();
	// select the card
	return_code = iso14443b_select_card( &card_b_info );
	if (return_code == 1) {
		Dbprintf("ISO 14443 Type B");
		iso_type = 'b';
		return 0;
	}
	Dbprintf("No card found.");
	return 1;
}
