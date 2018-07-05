//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Smartcard module commands
//-----------------------------------------------------------------------------
#include "cmdsmartcard.h"

static int CmdHelp(const char *Cmd);

int usage_sm_raw(void) {
	PrintAndLogEx(NORMAL, "Usage: sc raw [h|r|c] d <0A 0B 0C ... hex>");
	PrintAndLogEx(NORMAL, "       h          :  this help");
	PrintAndLogEx(NORMAL, "       r          :  do not read response");
	PrintAndLogEx(NORMAL, "       c          :  calculate and append CRC");
	PrintAndLogEx(NORMAL, "       d <bytes>  :  bytes to send");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        sc raw d 11223344");	
	return 0;
}
int usage_sm_reader(void) {
	PrintAndLogEx(NORMAL, "Usage: s reader [h|s]");
	PrintAndLogEx(NORMAL, "       h          :  this help");
	PrintAndLogEx(NORMAL, "       s          :  silent (no messages)");
	return 0;
}
int usage_sm_upgrade(void) {
	PrintAndLogEx(NORMAL, "Upgrade firmware");
	PrintAndLogEx(NORMAL, "Usage:  sc upgrade f <file name>");
	PrintAndLogEx(NORMAL, "  f <filename>  :      file name");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        sc upgrade f myfile");
	return 0;
}

int CmdSmartRaw(const char *Cmd) {

	int hexlen = 0;
	uint8_t cmdp = 0;
	bool errors = false;
	uint8_t data[USB_CMD_DATA_SIZE] = {0x00};
		
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (tolower(param_getchar(Cmd, cmdp))) {
		case 'd': {
			switch (param_gethex_to_eol(Cmd, cmdp+1, data, sizeof(data), &hexlen)) {
			case 1:
				PrintAndLogEx(WARNING, "Invalid HEX value.");
				return 1;
			case 2:
				PrintAndLogEx(WARNING, "Too many bytes.  Max %d bytes", sizeof(data));
				return 1;
			case 3:
				PrintAndLogEx(WARNING, "Hex must have even number of digits.");
				return 1;
			}
			cmdp += 2;
			break;
		}
		case 'h':
			return usage_sm_raw();
		default:
			PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	
	//Validations
	if (errors || cmdp == 0 ) return usage_sm_raw();			
	

	UsbCommand c = {CMD_SMART_RAW, {hexlen, 0, 0}};		
	memcpy(c.d.asBytes, data, hexlen );
	clearCommandBuffer();
	SendCommand(&c);
	
	// reading response from smart card
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
		PrintAndLogEx(WARNING, "smart card response failed");
		return 1;
	}
	PrintAndLogEx(SUCCESS,"resp:  %s", sprint_hex(resp.d.asBytes, resp.arg[0]));
	return 0;;
}
int CmdSmartUpgrade(const char *Cmd) {

	FILE *f;
	char filename[FILE_PATH_SIZE] = {0};
	uint8_t cmdp = 0;
	bool errors = false;
	
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (tolower(param_getchar(Cmd, cmdp))) {
		case 'f':
			//File handling and reading
			if ( param_getstr(Cmd, cmdp+1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE ) {
				PrintAndLogEx(FAILED, "Filename too long");
				errors = true;
				break;
			}			
			cmdp += 2;			
			break;
		case 'h':
			return usage_sm_upgrade();
		default:
			PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	
	//Validations
	if (errors || cmdp == 0 ) return usage_sm_upgrade();			

	// load file
	f = fopen(filename, "rb");
	if ( !f ){
		PrintAndLogEx(FAILED, "File: %s: not found or locked.", filename);
		return 1;
	}	
	
	// get filesize in order to malloc memory
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (fsize < 0) 	{
		PrintAndLogDevice(WARNING, "error, when getting filesize");
		fclose(f);
		return 1;
	}
		
	uint8_t *dump = calloc(fsize, sizeof(uint8_t));
	if (!dump) {
		PrintAndLogDevice(WARNING, "error, cannot allocate memory ");
		fclose(f);
		return 1;
	}
	
	size_t bytes_read = fread(dump, 1, fsize, f);
	if (f)
		fclose(f);
	
	PrintAndLogEx(SUCCESS, "Smartcard socket firmware uploading to PM3");
	//Send to device
	uint32_t index = 0;
	uint32_t bytes_sent = 0;
	uint32_t bytes_remaining = bytes_read;

	while (bytes_remaining > 0){
		uint32_t bytes_in_packet = MIN(USB_CMD_DATA_SIZE, bytes_remaining);		
		UsbCommand c = {CMD_SMART_UPLOAD, {index + bytes_sent, bytes_in_packet, 0}};

		// Fill usb bytes with 0xFF
		memset(c.d.asBytes, 0xFF, USB_CMD_DATA_SIZE);
		memcpy(c.d.asBytes, dump + bytes_sent, bytes_in_packet);
		clearCommandBuffer();
		SendCommand(&c);	
		if ( !WaitForResponseTimeout(CMD_ACK, NULL, 2000) ) {
			PrintAndLogEx(WARNING, "timeout while waiting for reply.");
			free(dump);
			return 1;
		}
		
		bytes_remaining -= bytes_in_packet;
		bytes_sent += bytes_in_packet;
		printf("."); fflush(stdout);
	}
	free(dump);
	printf("\n");
	PrintAndLogEx(SUCCESS, "Smartcard socket firmware updating,  don\'t turn off your PM3!");
	
	// trigger the firmware upgrade
	UsbCommand c = {CMD_SMART_UPGRADE, {bytes_read, 0, 0}};		
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if ( !WaitForResponseTimeout(CMD_ACK, &resp, 2500) ) {
		PrintAndLogEx(WARNING, "timeout while waiting for reply.");
		return 1;
	}
	if ( (resp.arg[0] && 0xFF ) )
		PrintAndLogEx(SUCCESS, "Smartcard socket firmware upgraded successful");
	else
		PrintAndLogEx(FAILED, "Smartcard socket firmware updating failed");
	return 0;
}

int CmdSmartInfo(const char *Cmd){

//	char filename[FILE_PATH_SIZE] = {0};	
	uint8_t cmdp = 0;
	bool errors = false;
	
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (tolower(param_getchar(Cmd, cmdp))) {
		case 'h': return usage_sm_reader();
		default:
			PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	
	//Validations
	if (errors || cmdp == 0 ) return usage_sm_reader();
/*
	PrintAndLogEx(NORMAL, "downloading %u bytes from flashmem", len);
	if ( !GetFromDevice(SMARTCARD_FW, dump, len, start_index, NULL, -1, true) ) {
		PrintAndLogEx(FAILED, "ERROR; downloading firmware");
		free(dump);
		return 1;
	}

	saveFile(filename, "bin", dump, len);
	free(dump);
	*/
	return 0;
}
int CmdSmartReader(const char *Cmd){

	uint8_t cmdp = 0;
	bool errors = false;
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (tolower(param_getchar(Cmd, cmdp))) {
		case 'h': return usage_sm_reader();	
		default:
			PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
		
	//Validations
	if (errors ) return usage_sm_reader();
			
	UsbCommand c = {CMD_SMART_ATR, {0, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if ( !WaitForResponseTimeout(CMD_ACK, &resp, 2500) ) {
		PrintAndLogEx(WARNING, "timeout while waiting for reply.");
		return 1;
	}
	
	uint8_t isok = resp.arg[0] & 0xFF;
	if (!isok) {
		PrintAndLogEx(FAILED, "failed");
		return 1;
	}		
	
	smart_card_atr_t *card = (smart_card_atr_t *)resp.d.asBytes;
	
	// print header
	PrintAndLogEx(INFO, "\n--- Smartcard Information ---------");
	PrintAndLogEx(INFO, "-------------------------------------------------------------");
	PrintAndLogEx(INFO, "ATR : %s", sprint_hex(card->atr, sizeof(card->atr_len)));
	return 0;
}

static command_t CommandTable[] = {
	{"help",	CmdHelp,            1, "This help"},
	{"info",	CmdSmartInfo,		1, "Tag information [rdv40]"},
	{"reader",	CmdSmartReader,		1, "Act like an IS07816 reader [rdv40]"},
	{"raw",		CmdSmartRaw,		1, "Send raw hex data to tag [rdv40]"},
	{"upgrade",	CmdSmartUpgrade,	1, "Upgrade firmware [rdv40]"},
	{NULL, NULL, 0, NULL}
};

int CmdSmartcard(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
