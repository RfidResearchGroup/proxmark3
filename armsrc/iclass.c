//-----------------------------------------------------------------------------
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
// Gerhard de Koning Gans - May 2011
// Gerhard de Koning Gans - June 2012 - Added iClass card and reader emulation
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support iClass.
//-----------------------------------------------------------------------------
// Based on ISO14443a implementation. Still in experimental phase.
// Contribution made during a security research at Radboud University Nijmegen
//
// Please feel free to contribute and extend iClass support!!
//-----------------------------------------------------------------------------
//
// FIX:
// ====
// We still have sometimes a demodulation error when sniffing iClass communication.
// The resulting trace of a read-block-03 command may look something like this:
//
//  +  22279:    :     0c  03  e8  01
//
//    ...with an incorrect answer...
//
//  +     85:   0: TAG ff! ff! ff! ff! ff! ff! ff! ff! bb  33  bb  00  01! 0e! 04! bb     !crc
//
// We still left the error signalling bytes in the traces like 0xbb
//
// A correct trace should look like this:
//
// +  21112:    :     0c  03  e8  01
// +     85:   0: TAG ff  ff  ff  ff  ff  ff  ff  ff  ea  f5
//
//-----------------------------------------------------------------------------

#include "iclass.h"

#include "proxmark3_arm.h"
#include "cmd.h"
// Needed for CRC in emulation mode;
// same construction as in ISO 14443;
// different initial value (CRC_ICLASS)
#include "crc16.h"
#include "optimized_cipher.h"

#include "appmain.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "string.h"
#include "util.h"
#include "dbprint.h"
#include "protocols.h"
#include "ticks.h"
#include "iso15693.h"

static int g_wait = 290;
static int timeout = 5000;
static uint32_t time_rdr = 0;
static uint32_t time_response = 0;

static int SendIClassAnswer(uint8_t *resp, int respLen, uint16_t delay);
int doIClassSimulation(int simulationMode, uint8_t *reader_mac_buf);

// The length of a received command will in most cases be no more than 18 bytes.
// we expect max 34 bytes as tag answer (response to READ4)
#ifndef ICLASS_BUFFER_SIZE
#define ICLASS_BUFFER_SIZE 34
#endif

// iCLASS has a slightly different timing compared to ISO15693. According to the picopass data sheet the tag response is expected 330us after
// the reader command. This is measured from end of reader EOF to first modulation of the tag's SOF which starts with a 56,64us unmodulated period.
// 330us = 140 ssp_clk cycles @ 423,75kHz when simulating.
// 56,64us = 24 ssp_clk_cycles
#define DELAY_ICLASS_VCD_TO_VICC_SIM     (140 - 24)

// times in ssp_clk_cycles @ 3,3625MHz when acting as reader
#define DELAY_ICLASS_VICC_TO_VCD_READER  DELAY_ISO15693_VICC_TO_VCD_READER

// times in samples @ 212kHz when acting as reader
#define ICLASS_READER_TIMEOUT_ACTALL     330 // 1558us, nominal 330us + 7slots*160us = 1450us
#define ICLASS_READER_TIMEOUT_UPDATE    3390 // 16000us, nominal 4-15ms
#define ICLASS_READER_TIMEOUT_OTHERS      80 // 380us, nominal 330us

#define AddCrc(data, len) compute_crc(CRC_ICLASS, (data), (len), (data)+(len), (data)+(len)+1)

static void OnError(uint8_t reason) {
    reply_mix(CMD_ACK, 0, reason, 0, 0, 0);
    switch_off();
}

/*
* CARD TO READER
* in ISO15693-2 mode -  Manchester
* in ISO 14443b - BPSK coding
*
* Timings:
*  ISO 15693-2
*           Tout = 330 µs, Tprog 1 = 4 to 15 ms, Tslot = 330 µs + (number of slots x 160 µs)
*  ISO 14443a
*           Tout = 100 µs, Tprog = 4 to 15 ms, Tslot = 100 µs+ (number of slots x 80 µs)
*  ISO 14443b
            Tout = 76 µs, Tprog = 4 to 15 ms, Tslot = 119 µs+ (number of slots x 150 µs)
*
*
*  So for current implementation in ISO15693, its 330 µs from end of reader, to start of card.
*/

//=============================================================================
// a `sniffer' for iClass communication
// Both sides of communication!
//=============================================================================
void SniffIClass(uint8_t jam_search_len, uint8_t *jam_search_string) {
    SniffIso15693(jam_search_len, jam_search_string);
}

static void rotateCSN(uint8_t *original_csn, uint8_t *rotated_csn) {
    for (uint8_t i = 0; i < 8; i++)
        rotated_csn[i] = (original_csn[i] >> 3) | (original_csn[(i + 1) % 8] << 5);
}

// Encode SOF only
static void CodeIClassTagSOF(void) {
	ToSendReset();
	ToSend[++ToSendMax] = 0x1D;
	ToSendMax++;
}


/*
 * SOF comprises 3 parts;
 * * An unmodulated time of 56.64 us
 * * 24 pulses of 423.75 kHz (fc/32)
 * * A logic 1, which starts with an unmodulated time of 18.88us
 *   followed by 8 pulses of 423.75kHz (fc/32)
 *
 *
 * EOF comprises 3 parts:
 * - A logic 0 (which starts with 8 pulses of fc/32 followed by an unmodulated
 *   time of 18.88us.
 * - 24 pulses of fc/32
 * - An unmodulated time of 56.64 us
 *
 *
 * A logic 0 starts with 8 pulses of fc/32
 * followed by an unmodulated time of 256/fc (~18,88us).
 *
 * A logic 0 starts with unmodulated time of 256/fc (~18,88us) followed by
 * 8 pulses of fc/32 (also 18.88us)
 *
 * The mode FPGA_HF_SIMULATOR_MODULATE_424K_8BIT which we use to simulate tag,
 * works like this.
 * - A 1-bit input to the FPGA becomes 8 pulses on 423.5kHz (fc/32) (18.88us).
 * - A 0-bit input to the FPGA becomes an unmodulated time of 18.88us
 *
 * In this mode
 * SOF can be written as 00011101 = 0x1D
 * EOF can be written as 10111000 = 0xb8
 * logic 1 be written as 01 = 0x1
 * logic 0 be written as 10 = 0x2
 *
 *
 */


/**
 * @brief SimulateIClass simulates an iClass card.
 * @param arg0 type of simulation
 *          - 0 uses the first 8 bytes in usb data as CSN
 *          - 2 "dismantling iclass"-attack. This mode iterates through all CSN's specified
 *          in the usb data. This mode collects MAC from the reader, in order to do an offline
 *          attack on the keys. For more info, see "dismantling iclass" and proxclone.com.
 *          - Other : Uses the default CSN (031fec8af7ff12e0)
 * @param arg1 - number of CSN's contained in datain (applicable for mode 2 only)
 * @param arg2
 * @param datain
 */
// turn off afterwards
void SimulateIClass(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain) {

    if (DBGLEVEL > 3) Dbprintf("[+] iClass_simulate Enter");

    LEDsoff();

	Iso15693InitTag();
   
    clear_trace();
    set_tracing(true);

    uint32_t simType = arg0;
    uint32_t numberOfCSNS = arg1;

    //Use the emulator memory for SIM
    uint8_t *emulator = BigBuf_get_EM_addr();
    uint8_t mac_responses[PM3_CMD_DATA_SIZE] = { 0 };

    if (simType == ICLASS_SIM_MODE_CSN) {
        // Use the CSN from commandline
        memcpy(emulator, datain, 8);
        doIClassSimulation(ICLASS_SIM_MODE_CSN, NULL);
    } else if (simType == ICLASS_SIM_MODE_CSN_DEFAULT) {
        //Default CSN
        uint8_t csn[] = { 0x03, 0x1f, 0xec, 0x8a, 0xf7, 0xff, 0x12, 0xe0 };
        // Use the CSN from commandline
        memcpy(emulator, csn, 8);
        doIClassSimulation(ICLASS_SIM_MODE_CSN, NULL);
    } else if (simType == ICLASS_SIM_MODE_READER_ATTACK) {

        Dbprintf("[+] going into attack mode, %d CSNS sent", numberOfCSNS);
        // In this mode, a number of csns are within datain. We'll simulate each one, one at a time
        // in order to collect MAC's from the reader. This can later be used in an offlne-attack
        // in order to obtain the keys, as in the "dismantling iclass"-paper.
        #define EPURSE_MAC_SIZE 16
        int i = 0;
        for (; i < numberOfCSNS && i * EPURSE_MAC_SIZE + 8 < PM3_CMD_DATA_SIZE; i++) {

            memcpy(emulator, datain + (i * 8), 8);

            if (doIClassSimulation(ICLASS_SIM_MODE_EXIT_AFTER_MAC, mac_responses + i * EPURSE_MAC_SIZE)) {
                // Button pressed
                reply_old(CMD_ACK, CMD_HF_ICLASS_SIMULATE, i, 0, mac_responses, i * EPURSE_MAC_SIZE);
                goto out;
            }
        }
        reply_old(CMD_ACK, CMD_HF_ICLASS_SIMULATE, i, 0, mac_responses, i * EPURSE_MAC_SIZE);

    } else if (simType == ICLASS_SIM_MODE_FULL) {
        //This is 'full sim' mode, where we use the emulator storage for data.
        //ie:  BigBuf_get_EM_addr should be previously filled with data from the "eload" command
        doIClassSimulation(ICLASS_SIM_MODE_FULL, NULL);
    } else if (simType == ICLASS_SIM_MODE_READER_ATTACK_KEYROLL) {

        // This is the KEYROLL version of sim 2.
        // the collected data (mac_response) is doubled out since we are trying to collect both keys in the keyroll process.
        // Keyroll iceman  9 csns * 8 * 2 = 144
        // keyroll CARL55  15csns * 8 * 2 = 15 * 8 * 2 = 240
        Dbprintf("[+] going into attack keyroll mode, %d CSNS sent", numberOfCSNS);
        // In this mode, a number of csns are within datain. We'll simulate each one, one at a time
        // in order to collect MAC's from the reader. This can later be used in an offlne-attack
        // in order to obtain the keys, as in the "dismantling iclass"-paper.

        // keyroll mode,   reader swaps between old key and new key alternatively when fail a authentication.
        // attack below is same as SIM 2, but we run the CSN twice to collected the mac for both keys.
        int i = 0;
        // The usb data is 512 bytes, fitting 65 8-byte CSNs in there.  iceman fork uses 9 CSNS
        for (; i < numberOfCSNS && i * EPURSE_MAC_SIZE + 8 < PM3_CMD_DATA_SIZE; i++) {

            memcpy(emulator, datain + (i * 8), 8);

            // keyroll 1
            if (doIClassSimulation(MODE_EXIT_AFTER_MAC, mac_responses + i * EPURSE_MAC_SIZE)) {
                reply_old(CMD_ACK, CMD_HF_ICLASS_SIMULATE, i * 2, 0, mac_responses, i * EPURSE_MAC_SIZE * 2);
                // Button pressed
                goto out;
            }

            // keyroll 2
            if (doIClassSimulation(MODE_EXIT_AFTER_MAC, mac_responses + (i + numberOfCSNS) * EPURSE_MAC_SIZE)) {
                reply_old(CMD_ACK, CMD_HF_ICLASS_SIMULATE, i * 2, 0, mac_responses, i * EPURSE_MAC_SIZE * 2);
                // Button pressed
                goto out;
            }
        }
        // double the amount of collected data.
        reply_old(CMD_ACK, CMD_HF_ICLASS_SIMULATE, i * 2, 0, mac_responses, i * EPURSE_MAC_SIZE * 2);

    } else {
        // We may want a mode here where we hardcode the csns to use (from proxclone).
        // That will speed things up a little, but not required just yet.
        DbpString("[-] the mode is not implemented, reserved for future use");
    }

out:
    switch_off();
    BigBuf_free_keep_EM();
}

/**
 * @brief Does the actual simulation
 * @param csn - csn to use
 * @param breakAfterMacReceived if true, returns after reader MAC has been received.
 */
int doIClassSimulation(int simulationMode, uint8_t *reader_mac_buf) {

    // free eventually allocated BigBuf memory
    BigBuf_free_keep_EM();

	uint16_t page_size = 32 * 8;
	uint8_t current_page = 0;

	// maintain cipher states for both credit and debit key for each page
	State cipher_state_KD[8];
	State cipher_state_KC[8];
	State *cipher_state = &cipher_state_KD[0];
    
    uint8_t *emulator = BigBuf_get_EM_addr();
    uint8_t *csn = emulator;

    // CSN followed by two CRC bytes
    uint8_t anticoll_data[10] = { 0 };
    uint8_t csn_data[10] = { 0 };
    memcpy(csn_data, csn, sizeof(csn_data));

    // Construct anticollision-CSN
    rotateCSN(csn_data, anticoll_data);

    // Compute CRC on both CSNs
    AddCrc(anticoll_data, 8);
    AddCrc(csn_data, 8);

	uint8_t diversified_kd[8] = { 0 };
	uint8_t diversified_kc[8] = { 0 };
	uint8_t *diversified_key = diversified_kd;

	// configuration block
	uint8_t conf_block[10] = {0x12, 0xFF, 0xFF, 0xFF, 0x7F, 0x1F, 0xFF, 0x3C, 0x00, 0x00};

    // e-Purse
    uint8_t card_challenge_data[8] = { 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    // AIA
    uint8_t aia_data[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00};
    
    if (simulationMode == ICLASS_SIM_MODE_FULL) {

		memcpy(conf_block, emulator + (8 * 1), 8);            // blk 1
		memcpy(card_challenge_data, emulator + (8 * 2), 8); // e-purse, blk 2
		memcpy(diversified_kd, emulator + (8 * 3), 8);      // Kd, blk 3
		memcpy(diversified_kc, emulator + (8 * 4), 8);      // Kc, blk 4
        
        
        // (iceman) this only works for 2KS / 16KS tags.
        // Use application data from block 5
        memcpy(aia_data, emulator + (8 * 5), 8);
        // older 2K / 16K tags has its application issuer data on block 2
    }

    AddCrc(conf_block, 8);
    AddCrc(aia_data, 8);

    // set epurse of sim2,4 attack
    if (reader_mac_buf != NULL) {
        memcpy(reader_mac_buf, card_challenge_data, 8);
    }

	if ((conf_block[5] & 0x80) == 0x80) {
		page_size = 256 * 8;
	}

	// From PicoPass DS:
	// When the page is in personalization mode this bit is equal to 1.
	// Once the application issuer has personalized and coded its dedicated areas, this bit must be set to 0:
	// the page is then "in application mode".
	bool personalization_mode = conf_block[7] & 0x80;

	// chip memory may be divided in 8 pages
	uint8_t max_page = ((conf_block[4] & 0x10) == 0x10) ? 0 : 7;

	// Precalculate the cipher states, feeding it the CC
	cipher_state_KD[0] = opt_doTagMAC_1(card_challenge_data, diversified_kd);
	cipher_state_KC[0] = opt_doTagMAC_1(card_challenge_data, diversified_kc);

	if (simulationMode == ICLASS_SIM_MODE_FULL) {

		for (int i = 1; i < max_page; i++) {

            // does all pages has their own epurse??)
			uint8_t *epurse = emulator + (i * page_size) + (8 * 2);
			uint8_t *kd = emulator + (i * page_size) + (8 * 3);
			uint8_t *kc = emulator + (i * page_size) + (8 * 4);

			cipher_state_KD[i] = opt_doTagMAC_1(epurse, kd);
			cipher_state_KC[i] = opt_doTagMAC_1(epurse, kc);
		}
	}

    int exitLoop = 0;

    // Anti-collision process:
    // Reader 0a
    // Tag    0f
    // Reader 0c
    // Tag    anticoll. CSN
    // Reader 81 anticoll. CSN
    // Tag    CSN

    uint8_t *modulated_response = NULL;
    int modulated_response_size = 0;
    uint8_t *trace_data = NULL;
    int trace_data_size = 0;

    // Respond SOF -- takes 1 bytes
    uint8_t *resp_sof = BigBuf_malloc(1);
    int resp_sof_len;

    // Anticollision CSN (rotated CSN)
    // 22: Takes 2 bytes for SOF/EOF and 10 * 2 = 20 bytes (2 bytes/byte)
    uint8_t *resp_anticoll = BigBuf_malloc(28);
    int resp_anticoll_len;

    // CSN
    // 22: Takes 2 bytes for SOF/EOF and 10 * 2 = 20 bytes (2 bytes/byte)
    uint8_t *resp_csn = BigBuf_malloc(28);
    int resp_csn_len;

    // configuration (blk 1) PICOPASS 2ks
    uint8_t *resp_conf = BigBuf_malloc(28);
    int resp_conf_len;

    // e-Purse
    // 18: Takes 2 bytes for SOF/EOF and 8 * 2 = 16 bytes (2 bytes/bit)
    uint8_t *resp_cc = BigBuf_malloc(28);
    int resp_cc_len;

	// Kd, Kc (blocks 3 and 4). Cannot be read. Always respond with 0xff bytes only
	uint8_t *resp_ff = BigBuf_malloc(22);
	int resp_ff_len;
	uint8_t ff_data[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00};
	AddCrc(ff_data, 8);

    // Application Issuer Area
    uint8_t *resp_aia = BigBuf_malloc(28);
    int resp_aia_len;

    // receive command
    uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);

    // Prepare card messages
    ToSendMax = 0;

    // First card answer: SOF
    CodeIClassTagSOF();
    memcpy(resp_sof, ToSend, ToSendMax);
    resp_sof_len = ToSendMax;

    // Anticollision CSN
    CodeIso15693AsTag(anticoll_data, sizeof(anticoll_data));
    memcpy(resp_anticoll, ToSend, ToSendMax);
    resp_anticoll_len = ToSendMax;

    // CSN (block 0)
    CodeIso15693AsTag(csn_data, sizeof(csn_data));
    memcpy(resp_csn, ToSend, ToSendMax);
    resp_csn_len = ToSendMax;

    // Configuration (block 1)
    CodeIso15693AsTag(conf_block, sizeof(conf_block));
    memcpy(resp_conf, ToSend, ToSendMax);
    resp_conf_len = ToSendMax;

    // e-Purse (block 2)
    CodeIso15693AsTag(card_challenge_data, sizeof(card_challenge_data));
    memcpy(resp_cc, ToSend, ToSendMax);
    resp_cc_len = ToSendMax;

	// Kd, Kc (blocks 3 and 4)
	CodeIso15693AsTag(ff_data, sizeof(ff_data));
	memcpy(resp_ff, ToSend, ToSendMax);
	resp_ff_len = ToSendMax;

    // Application Issuer Area (block 5)
    CodeIso15693AsTag(aia_data, sizeof(aia_data));
    memcpy(resp_aia, ToSend, ToSendMax);
    resp_aia_len = ToSendMax;

    //This is used for responding to READ-block commands or other data which is dynamically generated
    //First the 'trace'-data, not encoded for FPGA
    uint8_t *data_generic_trace = BigBuf_malloc(32 + 2);//8 bytes data + 2byte CRC is max tag answer

    //Then storage for the modulated data
    //Each bit is doubled when modulated for FPGA, and we also have SOF and EOF (2 bytes)
    uint8_t *data_response = BigBuf_malloc((32 + 2) * 2 + 2);

	enum { IDLE, ACTIVATED, SELECTED, HALTED } chip_state = IDLE;

    bool button_pressed = false;
    uint8_t cmd, options, block;
    int len = 0;

    while (exitLoop == false) {
        WDT_HIT();
            
		uint32_t reader_eof_time = 0;
		len = GetIso15693CommandFromReader(receivedCmd, MAX_FRAME_SIZE, &reader_eof_time);
        if (len < 0) {
            button_pressed = true;
            exitLoop = true;
            continue;
        }

		// Now look at the reader command and provide appropriate responses
		// default is no response:
		modulated_response = NULL;
		modulated_response_size = 0;
		trace_data = NULL;
		trace_data_size = 0;

        // extra response data
        cmd = receivedCmd[0] & 0xF;
        options = (receivedCmd[0] >> 4) & 0xFF;
        block = receivedCmd[1];

        if (cmd == ICLASS_CMD_ACTALL && len == 1) {   // 0x0A
            // Reader in anticollission phase
            if (chip_state != HALTED) { 
                modulated_response = resp_sof;
                modulated_response_size = resp_sof_len; //order = 1;
				chip_state = ACTIVATED;
                goto send;
            }

        } else if (cmd == ICLASS_CMD_READ_OR_IDENTIFY) { // 0x0C
            if (len == 1) {
                // Reader asks for anticollission CSN
                if (chip_state == SELECTED || chip_state == ACTIVATED) {
                    modulated_response = resp_anticoll;
                    modulated_response_size = resp_anticoll_len; //order = 2;
                    trace_data = anticoll_data;
                    trace_data_size = sizeof(anticoll_data);
                    goto send;
                }
            }

            if (len == 4) {
                if (chip_state == SELECTED) {
                    // block0,1,2,5 is always readable.
                    switch (block) {
                        case 0: // csn (0c 00)
                            modulated_response = resp_csn;
                            modulated_response_size = resp_csn_len;
                            trace_data = csn_data;
                            trace_data_size = sizeof(csn_data);
                            goto send;
                        case 1: // configuration (0c 01)
                            modulated_response = resp_conf;
                            modulated_response_size = resp_conf_len;
                            trace_data = conf_data;
                            trace_data_size = sizeof(conf_data);
                            goto send;
                        case 2: // e-purse (0c 02)
                            modulated_response = resp_cc;
                            modulated_response_size = resp_cc_len;
                            trace_data = card_challenge_data;
                            trace_data_size = sizeof(card_challenge_data);
                            // set epurse of sim2,4 attack
                            if (reader_mac_buf != NULL) {
                                memcpy(reader_mac_buf, card_challenge_data, 8);
                            }
                            goto send;
						case 3:
						case 4: // Kd, Kc, always respond with 0xff bytes
							modulated_response = resp_ff;
							modulated_response_size = resp_ff_len;
							trace_data = ff_data;
							trace_data_size = sizeof(ff_data);
							goto send;
                        case 5:// Application Issuer Area (0c 05)
                            modulated_response = resp_aia;
                            modulated_response_size = resp_aia_len;
                            trace_data = aia_data;
                            trace_data_size = sizeof(aia_data);
                            goto send;
                        default : {
                            if (simulationMode == ICLASS_SIM_MODE_FULL) { // 0x0C
                                //Read block
                                //Take the data...
                                memcpy(data_generic_trace, emulator + (block << 3), 8);
                                AddCrc(data_generic_trace, 8);
                                trace_data = data_generic_trace;
                                trace_data_size = 10;
                                CodeIClassTagAnswer(trace_data, trace_data_size);
                                memcpy(modulated_response, ToSend, ToSendMax);
                                modulated_response_size = ToSendMax;
                                goto send;
                            }
                            break;
                        }
                    } // swith
                } // selected
            } // if 4
        } else if (cmd == ICLASS_CMD_SELECT) { // 0x81
            // Reader selects anticollission CSN.
            // Tag sends the corresponding real CSN
            modulated_response = resp_csn;
            modulated_response_size = resp_csn_len; //order = 3;
            trace_data = csn_data;
            trace_data_size = sizeof(csn_data);
            goto send;
        } else if (cmd == ICLASS_CMD_READCHECK) {  // 0x88
            // Read e-purse KD (88 02)  KC  (18 02)
            modulated_response = resp_cc;
            modulated_response_size = resp_cc_len; //order = 4;
            trace_data = card_challenge_data;
            trace_data_size = sizeof(card_challenge_data);
            LED_B_ON();
            goto send;
        } else if (cmd == ICLASS_CMD_CHECK) { // 0x05
            // Reader random and reader MAC!!!
            if (simulationMode == ICLASS_SIM_MODE_FULL) {
                // NR, from reader, is in receivedCmd +1
                opt_doTagMAC_2(cipher_state, receivedCmd + 1, data_generic_trace, diversified_key);

                trace_data = data_generic_trace;
                trace_data_size = 4;
                CodeIClassTagAnswer(trace_data, trace_data_size);
                memcpy(data_response, ToSend, ToSendMax);
                modulated_response = data_response;
                modulated_response_size = ToSendMax;
            } else {
                // Not fullsim, we don't respond
                // We do not know what to answer, so lets keep quiet
                modulated_response = resp_sof;
                modulated_response_size = 0;
                trace_data = NULL;
                trace_data_size = 0;

                if (simulationMode == MODE_EXIT_AFTER_MAC) {

                    if (DBGLEVEL ==  DBG_EXTENDED) {
                        Dbprintf("[+] CSN: %02x %02x %02x %02x %02x %02x %02x %02x", csn[0], csn[1], csn[2], csn[3], csn[4], csn[5], csn[6], csn[7]);
                        Dbprintf("[+] RDR:  (len=%02d): %02x %02x %02x %02x %02x %02x %02x %02x %02x", len,
                                 receivedCmd[0], receivedCmd[1], receivedCmd[2],
                                 receivedCmd[3], receivedCmd[4], receivedCmd[5],
                                 receivedCmd[6], receivedCmd[7], receivedCmd[8]);
                    } else {
                        Dbprintf("[+] CSN: %02x .... %02x OK", csn[0], csn[7]);
                    }
                    if (reader_mac_buf != NULL) {
                        memcpy(reader_mac_buf + 8, receivedCmd + 1, 8);
                    }
                    exitLoop = true;
                }
            }
            goto send;
        } else if (cmd == ICLASS_CMD_HALT && options == 0 && len == 1) {

			if (chip_state == SELECTED) {
                // Reader ends the session
                modulated_response = resp_sof;
                modulated_response_size = resp_sof_Len;
                chip_state = HALTED;
                goto send;
            }
        } else if (simulationMode == ICLASS_SIM_MODE_FULL && cmd == ICLASS_CMD_READ4 && len == 4) {  // 0x06

			if (chip_state == SELECTED) {
                //Read block
                memcpy(data_generic_trace, emulator + (current_page * page_size) + (block * 8), 8 * 4);
                AddCrc(data_generic_trace, 8 * 4);
                trace_data = data_generic_trace;
                trace_data_size = 34;
                CodeIso15693AsTag(trace_data, trace_data_size);
                memcpy(modulated_response, ToSend, ToSendMax);
                modulated_response_size = ToSendMax;
                goto send;
            }
        } else if (simulationMode == ICLASS_SIM_MODE_FULL && cmd == ICLASS_CMD_UPDATE) {

            //Probably the reader wants to update the nonce. Let's just ignore that for now.
            // OBS! If this is implemented, don't forget to regenerate the cipher_state
            //We're expected to respond with the data+crc, exactly what's already in the receivedcmd
            //receivedcmd is now UPDATE 1b | ADDRESS 1b| DATA 8b| Signature 4b or CRC 2b|

            //Take the data...
            memcpy(data_generic_trace, receivedCmd + 2, 8);
            AddCrc(data_generic_trace, 8);
            trace_data = data_generic_trace;
            trace_data_size = 10;
            CodeIClassTagAnswer(trace_data, trace_data_size);

            memcpy(data_response, ToSend, ToSendMax);
            modulated_response = data_response;
            modulated_response_size = ToSendMax;
//            response_delay = 4600 * 1.5;  // tPROG 4-15ms
            goto send;
//            } else if(receivedCmd[0] == ICLASS_CMD_PAGESEL) {  // 0x84
            //Pagesel
            //Pagesel enables to select a page in the selected chip memory and return its configuration block
            //Chips with a single page will not answer to this command
            // It appears we're fine ignoring this.
            //Otherwise, we should answer 8bytes (block) + 2bytes CRC
//            } else if(receivedCmd[0] == ICLASS_CMD_DETECT) {  // 0x0F
		} else if (receivedCmd[0] == 0x26 && len == 5) {
			// standard ISO15693 INVENTORY command. Ignore.
        } else {
            // Never seen this command before
            if (DBGLEVEL >= DBG_EXTENDED)
                print_result("[-] Unhandled command received ", receivedCmd, len);
        }

send:
        /**
        A legit tag has about 330us delay between reader EOT and tag SOF.
        **/
        if (modulated_response_size > 0) {
            uint32_t response_time = reader_eof_time + DELAY_ICLASS_VCD_TO_VICC_SIM;
            TransmitTo15693Reader(modulated_response, modulated_response_size, &response_time, 0, false);
			LogTrace(trace_data, trace_data_size, response_time*32, response_time*32 + modulated_response_size*32*64, NULL, false);
        }
    }

    LEDsoff();

    if (button_pressed)
        DbpString("[+] button pressed");

    return button_pressed;
}


/// THE READER CODE

//-----------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitIClassCommand(const uint8_t *cmd, int len, int *wait) {

    int c = 0;
    bool firstpart = true;
    uint8_t sendbyte;

    time_rdr = 0;

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);

    AT91C_BASE_SSC->SSC_THR = 0x00;

    // make sure we timeout previous comms.
    if (*wait)
        SpinDelayUs(*wait);

    for (;;) {

        WDT_HIT();

        // Put byte into tx holding register as soon as it is ready
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {

            // DOUBLE THE SAMPLES!
            if (firstpart) {
                sendbyte = (cmd[c] & 0xf0) | (cmd[c] >> 4);
            } else {
                sendbyte = (cmd[c] & 0x0f) | (cmd[c] << 4);
                c++;
            }

            if (sendbyte == 0xff)
                sendbyte = 0xfe;

            AT91C_BASE_SSC->SSC_THR = sendbyte;
            firstpart = !firstpart;

            if (c >= len) break;
        }
    }

    time_rdr = GetCountSspClk();
}

static void ReaderTransmitIClass(uint8_t *frame, int len, uint32_t *start_time) {

	CodeIso15693AsReader(frame, len);
	TransmitTo15693Tag(ToSend, ToSendMax, start_time);
	uint32_t end_time = *start_time + 32 * (8 * ToSendMax - 4); // substract the 4 padding bits after EOF

    LogTrace(frame, len,  *start_time * 4, end_time * 4, NULL, true);
}

static bool sendCmdGetResponseWithRetries(uint8_t* command, size_t cmdsize, uint8_t* resp, size_t max_resp_size,
										  uint8_t expected_size, uint8_t tries, uint32_t start_time,
                                          uint32_t timeout, uint32_t *eof_time) {
    while (tries-- > 0) {

        ReaderTransmitIClass(command, cmdsize, &start_time);
		if (expected_size == GetIso15693AnswerFromTag(resp, max_resp_size, timeout, eof_time)) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Talks to an iclass tag, sends the commands to get CSN and CC.
 * @param card_data where the CSN, CONFIG, CC are stored for return
 *        8 bytes csn + 8 bytes config + 8 bytes CC
 * @return false = fail
 *         true = Got all.
 */
static bool selectIclassTag(uint8_t *card_data, bool use_credit_key, uint32_t *eof_time) {

    static uint8_t act_all[] = { ICLASS_CMD_ACTALL };
    static uint8_t identify[] = { ICLASS_CMD_READ_OR_IDENTIFY, 0x00, 0x73, 0x33 };
    static uint8_t select[] = { 0x80 | ICLASS_CMD_SELECT, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	static uint8_t read_conf[] = { ICLASS_CMD_READ_OR_IDENTIFY, 0x01, 0xfa, 0x22 };
    static uint8_t read_check_cc[] = { 0x80 | ICLASS_CMD_READCHECK, 0x02 };

    // Bit 4: K.If this bit equals to one, the READCHECK will use the Credit Key (Kc); if equals to zero, Debit Key (Kd) willbe used
    // bit 7: parity.

    if (use_credit_key)
        readcheck_cc[0] = 0x10 | ICLASS_CMD_READCHECK;

    uint8_t resp[ICLASS_BUFFER_SIZE] = {0};
    
    uint32_t start_time = GetCountSspClk();

    ReaderTransmitIClass(act_all, 1, &start_time);

	// card present?
	if (GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_ACTALL, eof_time) < 0)
        return false;

    // send Identify
    start_time = *eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
	ReaderTransmitIClass(identify, 1, &start_time);

    // expect a 10-byte response here, 8 byte anticollision-CSN and 2 byte CRC
    uint8_t len = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_OTHERS, eof_time);
    if (len != 10)
        return false;

    // copy the Anti-collision CSN to our select-packet
    memcpy(&select[1], resp, 8);

    // select the card
	start_time = *eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
	ReaderTransmitIClass(select, sizeof(select), &start_time);

    // expect a 10-byte response here, 8 byte CSN and 2 byte CRC
	len = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_OTHERS, eof_time);
	if (len != 10) 
        return false;

    //Save CSN in response data
    memcpy(card_data, resp, 8);

    // card selected, now read config (block1) (only 8 bytes no CRC)
	start_time = *eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
	ReaderTransmitIClass(read_conf, sizeof(read_conf), &start_time);
   
    // expect a 8-byte response here
	len = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_OTHERS, eof_time);
	if (len != 8) 
        return false;

    //Save CC (e-purse) in response data
    memcpy(card_data + 8, resp, 8);

    // card selected, now read e-purse (cc) (block2) (only 8 bytes no CRC)
	start_time = *eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
	ReaderTransmitIClass(readcheck_cc, sizeof(readcheck_cc), &start_time);
   
    // expect a 8-byte response here
	len = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_OTHERS, eof_time);
	if (len != 8) 
        return false;

    //Save CC (e-purse) in response data
    memcpy(card_data + 16, resp, 8);
    return true;
}

// Reader iClass Anticollission
// turn off afterwards
void ReaderIClass(uint8_t arg0) {

    uint8_t card_data[6 * 8] = {0};
    uint8_t last_csn[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t resp[ICLASS_BUFFER_SIZE];

    memset(card_data, 0xFF, sizeof(card_data));
    memset(resp, 0xFF, sizeof(resp));

    bool abort_after_read = arg0 & FLAG_ICLASS_READER_ONLY_ONCE;  // flag to read until one tag is found successfully
    bool try_once = arg0 & FLAG_ICLASS_READER_ONE_TRY;            // flag to not to loop continuously, looking for tag
    bool use_credit_key = arg0 & FLAG_ICLASS_READER_CEDITKEY;     // flag to use credit key
    bool flagReadAIA = arg0 & FLAG_ICLASS_READER_AIA;             // flag to read block5, application issuer area

	if (flags & FLAG_ICLASS_READER_INIT) {
		Iso15693InitReader();
	}

	if (flags & FLAG_ICLASS_READER_CLEARTRACE) {
		set_tracing(true);
		clear_trace();
		StartCountSspClk();
	}

	uint32_t start_time = 0;
	uint32_t eof_time = 0;

    int read_status = selectIclassTag(card_data, use_credit_key, &eof_time);
    if (read_status == 0) {
        reply_mix(CMD_ACK, 0xFF, 0, 0, card_data, 0);
        switch_off();
        return;
    }
    
    uint8_t result_status = FLAG_ICLASS_READER_CSN | FLAG_ICLASS_READER_CONF | FLAG_ICLASS_READER_CC;

    //Read block 5, AIA
    if (flagReadAIA) {
        //Read App Issuer Area block CRC(0x05) => 0xde  0x64
        uint8_t readAA[] = { ICLASS_CMD_READ_OR_IDENTIFY, 0x05, 0xde, 0x64};

        if (sendCmdGetResponseWithRetries(readAA, sizeof(readAA), resp, sizeof(resp), 10, 10, start_time, ICLASS_READER_TIMEOUT_OTHERS, &eof_time)) {
            result_status |= FLAG_ICLASS_READER_AIA;
            memcpy(card_data + (8 * 5), resp, 8);
        } else {
            if (DBGLEVEL >= DBG_EXTENDED) DbpString("Failed to dump AA block");
        }
    }

    // 0 : CSN
    // 1 : Configuration
    // 2 : e-purse
    // 3 : kd / debit / aa2 (write-only)
    // 4 : kc / credit / aa1 (write-only)
    // 5 : AIA, Application issuer area
    //
    //Then we can 'ship' back the 6 * 8 bytes of data,
    // with 0xFF:s in block 3 and 4.

    LED_B_ON();

    //Send back to client, but don't bother if we already sent this -
    //  only useful if looping in arm (not try_once && not abort_after_read)
    if (memcmp(last_csn, card_data, 8) != 0) {
            
        if (send) {
            reply_mix(CMD_ACK, result_status, 0, 0, card_data, sizeof(card_data));
            if (abort_after_read) {
                LED_B_OFF();
                return;
            }
        }
        LED_B_OFF();
    }

    if (userCancelled) {
        reply_mix(CMD_ACK, 0xFF, 0, 0, card_data, 0);
        switch_off();
    } else {
        reply_mix(CMD_ACK, 0, 0, 0, card_data, 0);
    }
}

// turn off afterwards
void ReaderIClass_Replay(uint8_t arg0, uint8_t *mac) {

    uint8_t cardsize = 0;
    uint8_t mem = 0;
    uint8_t check[] = { 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t read[]  = { 0x0c, 0x00, 0x00, 0x00 };
    uint8_t card_data[PM3_CMD_DATA_SIZE] = {0};
    uint8_t resp[ICLASS_BUFFER_SIZE] = {0};

    static struct memory_t {
        int k16;
        int book;
        int k2;
        int lockauth;
        int keyaccess;
    } memory;

    setupIclassReader();

    while (!BUTTON_PRESS()) {

        WDT_HIT();

        uint8_t read_status = handshakeIclassTag(card_data);
        if (read_status < 2) continue;

        //for now replay captured auth (as cc not updated)
        memcpy(check + 5, mac, 4);

        if (!sendCmdGetResponseWithRetries(check, sizeof(check), resp, 4, 5)) {
            DbpString("Error: Authentication Fail!");
            continue;
        }

        //first get configuration block (block 1)
        read[1] = 1;
        AddCrc(read + 1, 1);

        if (!sendCmdGetResponseWithRetries(read, sizeof(read), resp, 10, 5)) {
            DbpString("Dump config (block 1) failed");
            continue;
        }

        mem = resp[5];
        memory.k16 = (mem & 0x80);
        memory.book = (mem & 0x20);
        memory.k2 = (mem & 0x8);
        memory.lockauth = (mem & 0x2);
        memory.keyaccess = (mem & 0x1);

        cardsize = memory.k16 ? 255 : 32;

        WDT_HIT();
        //Set card_data to all zeroes, we'll fill it with data
        memset(card_data, 0x0, PM3_CMD_DATA_SIZE);
        uint8_t failedRead = 0;
        uint32_t stored_data_length = 0;

        //then loop around remaining blocks
        for (uint16_t block = 0; block < cardsize; block++) {

            read[1] = block;
            AddCrc(read + 1, 1);

            if (sendCmdGetResponseWithRetries(read, sizeof(read), resp, 10, 5)) {
                Dbprintf("     %02x: %02x %02x %02x %02x %02x %02x %02x %02x",
                         block, resp[0], resp[1], resp[2],
                         resp[3], resp[4], resp[5],
                         resp[6], resp[7]
                        );

                //Fill up the buffer
                memcpy(card_data + stored_data_length, resp, 8);
                stored_data_length += 8;
                if (stored_data_length + 8 > PM3_CMD_DATA_SIZE) {
                    //Time to send this off and start afresh
                    reply_old(CMD_ACK,
                              stored_data_length,//data length
                              failedRead,//Failed blocks?
                              0,//Not used ATM
                              card_data,
                              stored_data_length
                             );
                    //reset
                    stored_data_length = 0;
                    failedRead = 0;
                }
            } else {
                failedRead = 1;
                stored_data_length += 8;//Otherwise, data becomes misaligned
                Dbprintf("Failed to dump block %d", block);
            }
        }

        //Send off any remaining data
        if (stored_data_length > 0) {
            reply_old(CMD_ACK,
                      stored_data_length,//data length
                      failedRead,//Failed blocks?
                      0,//Not used ATM
                      card_data,
                      stored_data_length
                     );
        }
        //If we got here, let's break
        break;
    }
    //Signal end of transmission
    reply_old(CMD_ACK,
              0,//data length
              0,//Failed blocks?
              0,//Not used ATM
              card_data,
              0
             );
    switch_off();
}

// not used. ?!? ( CMD_HF_ICLASS_READCHECK)
// turn off afterwards
void iClass_ReadCheck(uint8_t blockno, uint8_t keytype) {
    uint8_t readcheck[] = { keytype, blockno };
    uint8_t resp[] = {0, 0, 0, 0, 0, 0, 0, 0};
   	bool isOK = sendCmdGetResponseWithRetries(readcheck, sizeof(readcheck), resp, sizeof(resp), 8, 3, 0, ICLASS_READER_TIMEOUT_OTHERS, &eof_time);
    reply_mix(CMD_ACK, isOK, 0, 0, 0, 0);
    switch_off();
}

// used with function select_and_auth (cmdhficlass.c)
// which needs to authenticate before doing more things like read/write
void iClass_Authentication(uint8_t *mac) {
    uint8_t check[] = { ICLASS_CMD_CHECK, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t resp[ICLASS_BUFFER_SIZE];

    // copy MAC to check command (readersignature)
    check[5] = mac[0];
    check[6] = mac[1];
    check[7] = mac[2];
    check[8] = mac[3];
    //memcpy(check+5, mac, 4);

    // 6 retries
    uint8_t isOK = sendCmdGetResponseWithRetries(check, sizeof(check), resp, 4, 6);
    reply_ng(CMD_HF_ICLASS_AUTH, PM3_SUCCESS, (uint8_t *)&isOK, sizeof(uint8_t));
}

typedef struct iclass_premac {
    uint8_t mac[4];
} iclass_premac_t;

/* this function works on the following assumptions.
* - one select first, to get CSN / CC (e-purse)
* - calculate before diversified keys and precalc mac based on CSN/KEY.
* - data in contains of diversified keys, mac
* - key loop only test one type of authtication key. Ie two calls needed
*   to cover debit and credit key. (AA1/AA2)
*/
void iClass_Authentication_fast(uint64_t arg0, uint64_t arg1, uint8_t *datain) {
    uint8_t i = 0, isOK = 0;
    uint8_t lastChunk = ((arg0 >> 8) & 0xFF);
    bool use_credit_key = ((arg0 >> 16) & 0xFF);
    uint8_t keyCount = arg1 & 0xFF;
    uint8_t check[] = { ICLASS_CMD_CHECK, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t resp[ICLASS_BUFFER_SIZE];
    uint8_t readcheck_cc[] = { 0x80 | ICLASS_CMD_READCHECK, 0x02 };

    if (use_credit_key)
        readcheck_cc[0] = 0x10 | ICLASS_CMD_READCHECK;

    // select card / e-purse
    uint8_t card_data[6 * 8] = {0};

    iclass_premac_t *keys = (iclass_premac_t *)datain;

    LED_A_ON();

    switch_off();
    SpinDelay(20);

    setupIclassReader();

    uint16_t checked = 0;
    int read_status = 0;
    uint8_t startup_limit = 10;
    while (read_status != 2) {

        if (checked == 1000) {
            if (BUTTON_PRESS() || !data_available()) goto out;
            checked = 0;
        }
        ++checked;

        read_status = handshakeIclassTag_ext(card_data, use_credit_key);
        if (startup_limit-- == 0) {
            Dbprintf("[-] Handshake status | %d (fail 10)", read_status);
            isOK = 99;
            goto out;
        }
    };
    // since handshakeIclassTag_ext call sends s readcheck,  we start with sending first response.

    checked = 0;

    // Keychunk loop
    for (i = 0; i < keyCount; i++) {

        // Allow button press / usb cmd to interrupt device
        if (checked == 1000) {
            if (BUTTON_PRESS() || !data_available()) goto out;
            checked = 0;
        }
        ++checked;

        WDT_HIT();
        LED_B_ON();

        // copy MAC to check command (readersignature)
        check[5] = keys[i].mac[0];
        check[6] = keys[i].mac[1];
        check[7] = keys[i].mac[2];
        check[8] = keys[i].mac[3];

        // expect 4bytes, 3 retries times..
        isOK = sendCmdGetResponseWithRetries(check, sizeof(check), resp, 4, 3);
        if (isOK)
            goto out;

        // Auth Sequence MUST begin with reading e-purse. (block2)
        // Card selected, now read e-purse (cc) (block2) (only 8 bytes no CRC)
        ReaderTransmitIClass(readcheck_cc, sizeof(readcheck_cc));

        LED_B_OFF();
    }

out:
    // send keyindex.
    reply_mix(CMD_ACK, isOK, i, 0, 0, 0);

    if (isOK >= 1 || lastChunk) {
        switch_off();
        LED_A_OFF();
    }

    LED_B_OFF();
    LED_C_OFF();
}

// Tries to read block.
// retries 10times.
static bool iClass_ReadBlock(uint8_t blockno, uint8_t *data) {
    uint8_t resp[10];
    uint8_t cmd[] = {ICLASS_CMD_READ_OR_IDENTIFY, blockno, 0x00, 0x00};
    AddCrc(cmd + 1, 1);
    uint32_t eof_time;
	bool isOK = sendCmdGetResponseWithRetries(readcmd, sizeof(readcmd), resp, sizeof(resp), 10, 10, 0, ICLASS_READER_TIMEOUT_OTHERS, &eof_time);
    memcpy(data, resp, 8);
    return isOK;
}

// turn off afterwards
// readblock 8 + 2.  only want 8.
void iClass_ReadBlk(uint8_t blockno) {
    struct p {
        bool isOK;
        uint8_t blockdata[8];
    } PACKED result;

    LED_A_ON();
    result.isOK = iClass_ReadBlock(blockno, result.blockdata);
    switch_off();
    reply_ng(CMD_HF_ICLASS_READBL, PM3_SUCCESS, (uint8_t *)&result, sizeof(result));
}

// turn off afterwards
void iClass_Dump(uint8_t blockno, uint8_t numblks) {
    BigBuf_free();
    uint8_t *dataout = BigBuf_malloc(0xFF * 8);
    if (dataout == NULL) {
        DbpString("[!] fail to allocate memory");
        OnError(1);
        return;
    }
    memset(dataout, 0xFF, 0xFF * 8);

    uint8_t blockdata[8] = {0};
    uint8_t blkCnt = 0;
    bool isOK;
    for (; blkCnt < numblks; blkCnt++) {
        isOK = iClass_ReadBlock(blockno + blkCnt, blockdata);

        // 0xBB is the internal debug separator byte..
        if (!isOK || (blockdata[0] == 0xBB || blockdata[7] == 0xBB || blockdata[2] == 0xBB)) { //try again
            isOK = iClass_ReadBlock(blockno + blkCnt, blockdata);
            if (!isOK) {
                Dbprintf("[!] block %02X failed to read", blkCnt + blockno);
                break;
            }
        }
        memcpy(dataout + (blkCnt * 8), blockdata, 8);
    }

    switch_off();
    //return pointer to dump memory in arg3
    reply_mix(CMD_ACK, isOK, blkCnt, BigBuf_max_traceLen(), 0, 0);
    BigBuf_free();
}

static bool iClass_WriteBlock_ext(uint8_t blockno, uint8_t *data) {

    uint8_t write[] = { 0x80 | ICLASS_CMD_UPDATE, blockno, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memcpy(write + 2, data, 12); // data + mac
    AddCrc(write + 1, 13);

    uint8_t resp[10] = {0};    
    uint32_t eof_time = 0;
	bool isOK = sendCmdGetResponseWithRetries(write, sizeof(write), resp, sizeof(resp), 10, 3, 0, ICLASS_READER_TIMEOUT_UPDATE, &eof_time);
	if (isOK == false) {
		return false;
	}
    
   	uint8_t all_ff[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	if (blockNo == 2) {
        // check response. e-purse update swaps first and second half
		if (memcmp(data+4, resp, 4) || memcmp(data, resp+4, 4)) { 
			return false;
		}
	} else if (blockNo == 3 || blockNo == 4) {
        // check response. Key updates always return 0xffffffffffffffff
		if (memcmp(all_ff, resp, 8)) { 
			return false;
		}
	} else {
        // check response. All other updates return unchanged data
		if (memcmp(data, resp, 8)) { 
			return false;
		}
	}

    return true;
}

// turn off afterwards
void iClass_WriteBlock(uint8_t blockno, uint8_t *data) {
	LED_A_ON();
    uint8_t isOK = iClass_WriteBlock_ext(blockno, data);
    switch_off();
    reply_ng(CMD_HF_ICLASS_WRITEBL, PM3_SUCCESS, (uint8_t *)&isOK, sizeof(uint8_t));
}

// turn off afterwards
void iClass_Clone(uint8_t startblock, uint8_t endblock, uint8_t *data) {
    LED_A_ON();
    uint16_t written = 0;
    uint16_t total_blocks = (endblock - startblock) + 1;
    for (uint8_t b = startblock; b < total_blocks; b++) {

        if (iClass_WriteBlock_ext(b, data + ((b - startblock) * 12))) {
            Dbprintf("Write block [%02x] successful", b);
            written++;
        } else {
            Dbprintf("Write block [%02x] failed", b);
        }
    }

    switch_off();
    uint8_t isOK = (written == total_blocks) ? 1 : 0;
    reply_ng(CMD_HF_ICLASS_CLONE, PM3_SUCCESS, (uint8_t *)&isOK, sizeof(uint8_t));
}
