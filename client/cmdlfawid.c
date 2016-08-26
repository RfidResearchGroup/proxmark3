//-----------------------------------------------------------------------------
// Authored by Craig Young <cyoung@tripwire.com> based on cmdlfhid.c structure
//
// cmdlfhid.c is Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency AWID26/50 commands
//-----------------------------------------------------------------------------
#include "cmdlfawid.h"  // AWID function declarations
 
static int CmdHelp(const char *Cmd);

int usage_lf_awid_fskdemod(void) {
	PrintAndLog("Enables AWID compatible reader mode printing details of scanned AWID26 or AWID50 tags.");
	PrintAndLog("By default, values are printed and logged until the button is pressed or another USB command is issued.");
	PrintAndLog("If the [1] option is provided, reader mode is exited after reading a single AWID card.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid fskdemod [h] [1]");
	PrintAndLog("Options:");
	PrintAndLog("      h :  This help");	
	PrintAndLog("      1 : (optional) stop after reading a single card");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("       lf awid fskdemod");
	PrintAndLog("       lf awid fskdemod 1");
	return 0;
}

int usage_lf_awid_sim(void) {
	PrintAndLog("Enables simulation of AWID card with specified facility-code and card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid sim [h] <format> <facility-code> <card-number>");
	PrintAndLog("Options:");
	PrintAndLog("                h :  This help");	
	PrintAndLog("         <format> :  format length 26|50");
	PrintAndLog("  <facility-code> :  8|16bit value facility code");
	PrintAndLog("    <card number> :  16|32-bit value card number");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("       lf awid sim 26 224 1337");
	PrintAndLog("       lf awid sim 50 2001 13371337");
	return 0;
}

int usage_lf_awid_clone(void) {
	PrintAndLog("Enables cloning of AWID card with specified facility-code and card number onto T55x7.");
	PrintAndLog("The T55x7 must be on the antenna when issuing this command.  T55x7 blocks are calculated and printed in the process.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid clone [h] <format> <facility-code> <card-number> [Q5]");
	PrintAndLog("Options:");
	PrintAndLog("                h :  This help");	
	PrintAndLog("         <format> :  format length 26|50");
	PrintAndLog("  <facility-code> :  8|16bit value facility code");
	PrintAndLog("    <card number> :  16|32-bit value card number");
	PrintAndLog("               Q5 :  optional - clone to Q5 (T5555) instead of T55x7 chip");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("       lf awid clone 26 224 1337");
	PrintAndLog("       lf awid clone 50 2001 13371337");
	return 0;
}

int usage_lf_awid_brute(void){
	PrintAndLog("Enables bruteforce of AWID reader with specified facility-code.");
	PrintAndLog("This is a attack against reader. if cardnumber is given, it starts with it and goes up / down one step");
	PrintAndLog("if cardnumber is not given, it starts with 1 and goes up to 65535");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid brute [h] a <format> f <facility-code> c <cardnumber> d <delay>");
	PrintAndLog("Options:");
	PrintAndLog("       h                 :  This help");
	PrintAndLog("       a <format>        :  format length 26|50");
	PrintAndLog("       f <facility-code> :  8|16bit value facility code");
	PrintAndLog("       c <cardnumber>    :  (optional) cardnumber to start with, max 65535");
	PrintAndLog("       d <delay>         :  delay betweens attempts in ms. Default 1000ms");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("       lf awid brute a 26 f 224");
	PrintAndLog("       lf awid brute a 50 f 2001 d 2000");
	PrintAndLog("       lf awid brute a 50 f 2001 c 200 d 2000");
	return 0;
}

static int sendPing(void){
	UsbCommand ping = {CMD_PING, {1, 2, 3}};
	SendCommand(&ping);
	SendCommand(&ping);	
	SendCommand(&ping);	
	clearCommandBuffer();
	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK, &resp, 1000))
		return 0;
	return 1;
}

static bool sendTry(uint8_t fmtlen, uint32_t fc, uint32_t cn, uint32_t delay, uint8_t *bs, size_t bs_len){

	PrintAndLog("Trying FC: %u; CN: %u", fc, cn);		
	if ( !getAWIDBits(fmtlen, fc, cn, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return FALSE;
	}

	uint64_t arg1 = (10<<8) + 8; // fcHigh = 10, fcLow = 8
	uint64_t arg2 = 50; 		 // clk RF/50 invert=0
	UsbCommand c = {CMD_FSK_SIM_TAG, {arg1, arg2, bs_len}};
	memcpy(c.d.asBytes, bs, bs_len);
	clearCommandBuffer();
	SendCommand(&c);
	msleep(delay);
	sendPing();
	return TRUE;
}


int CmdAWIDDemodFSK(const char *Cmd) {
	int findone = 0;
	if (Cmd[0] == 'h' || Cmd[0] == 'H') return usage_lf_awid_fskdemod();
	if (Cmd[0] == '1') findone = 1;

	UsbCommand c = {CMD_AWID_DEMOD_FSK, {findone, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;   
}

//refactored by marshmellow
int getAWIDBits(uint8_t fmtlen, uint32_t fc, uint32_t cn, uint8_t *bits) {

	// the return bits, preamble 0000 0001 
	bits[7] = 1;  
	
	uint8_t pre[66];
	memset(pre, 0, sizeof(pre));

	// add formatlength
	num_to_bytebits(fmtlen, 8, pre);
	
	// add facilitycode, cardnumber and wiegand parity bits
	if ( fmtlen == 26 ) {
		uint8_t wiegand[24];
		num_to_bytebits(fc, 8, wiegand);
		num_to_bytebits(cn, 16, wiegand+8);
		wiegand_add_parity(pre+8, wiegand,  sizeof(wiegand));
	} else {
		uint8_t wiegand[48];
		num_to_bytebits(fc, 16, wiegand);
		num_to_bytebits(cn, 32, wiegand+16);
		wiegand_add_parity(pre+8, wiegand, sizeof(wiegand));
	}
	
	// add AWID 4bit parity 
	size_t bitLen = addParity(pre, bits+8, 66, 4, 1);

	if (bitLen != 88) return 0;
	return 1;
}

int CmdAWIDSim(const char *Cmd) {
	uint32_t fc = 0, cn = 0;
	uint8_t fmtlen = 0;
	uint8_t bits[96];
	uint8_t *bs = bits;
	size_t size = sizeof(bits);
	memset(bs, 0x00, size);

	uint64_t arg1 = ( 10 << 8 ) + 8; // fcHigh = 10, fcLow = 8
	uint64_t arg2 = 50; // clk RF/50 invert=0
  
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_awid_sim();
	
  	fmtlen = param_get8(Cmd, 0);
	fc = param_get32ex(Cmd, 1, 0, 10);	
	cn = param_get32ex(Cmd, 2, 0, 10);
	if ( !fc || !cn) return usage_lf_awid_sim();
	
	switch(fmtlen) {
		case 26:
			if ((fc & 0xFF) != fc) {
				fc &= 0xFF;
				PrintAndLog("Facility-Code Truncated to 8-bits (AWID26): %u", fc);
			}

			if ((cn & 0xFFFF) != cn) {
				cn &= 0xFFFF;
				PrintAndLog("Card Number Truncated to 16-bits (AWID26): %u", cn);
			}
			break;
		case 50:
			if ((fc & 0xFFFF) != fc) {
				fc &= 0xFFFF;
				PrintAndLog("Facility-Code Truncated to 16-bits (AWID50): %u", fc);
			}
			break;
		default: break;
	}
	
	PrintAndLog("Emulating AWID %u -- FC: %u; CN: %u\n", fmtlen, fc, cn);
	PrintAndLog("Press pm3-button to abort simulation or run another command");
	
	if (!getAWIDBits(fmtlen, fc, cn, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}
	// AWID uses: fcHigh: 10, fcLow: 8, clk: 50, invert: 0
	// arg1 --- fcHigh<<8 + fcLow
	// arg2 --- Inversion and clk setting
	// 96   --- Bitstream length: 96-bits == 12 bytes
	UsbCommand c = {CMD_FSK_SIM_TAG, {arg1, arg2, size}};  
	memcpy(c.d.asBytes, bs, size);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdAWIDClone(const char *Cmd) {
	uint32_t blocks[4] = {T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_50 | 3<<T55x7_MAXBLOCK_SHIFT, 0, 0, 0};
	uint32_t fc = 0, cn = 0;
	uint8_t fmtlen = 0;
	uint8_t bits[96];
	uint8_t *bs=bits;
	memset(bs,0,sizeof(bits));
	
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_awid_clone();

  	fmtlen = param_get8(Cmd, 0);
	fc = param_get32ex(Cmd, 1, 0, 10);
	cn = param_get32ex(Cmd, 2, 0, 10);

	if ( !fc || !cn) return usage_lf_awid_clone();
	
	switch(fmtlen) {
		case 50:
			if ((fc & 0xFFFF) != fc) {
				fc &= 0xFFFF;
				PrintAndLog("Facility-Code Truncated to 16-bits (AWID50): %u", fc);
			}
			break;
		default: 
			fmtlen = 26;
			if ((fc & 0xFF) != fc) {
				fc &= 0xFF;
				PrintAndLog("Facility-Code Truncated to 8-bits (AWID26): %u", fc);
			}

			if ((cn & 0xFFFF) != cn) {
				cn &= 0xFFFF;
				PrintAndLog("Card Number Truncated to 16-bits (AWID26): %u", cn);
			}
			break;
	}
	
	if (param_getchar(Cmd, 4) == 'Q' || param_getchar(Cmd, 4) == 'q')
		//t5555 (Q5) BITRATE = (RF-2)/2 (iceman)
		blocks[0] = T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | 50<<T5555_BITRATE_SHIFT | 3<<T5555_MAXBLOCK_SHIFT;

	if ( !getAWIDBits(fmtlen, fc, cn, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	blocks[1] = bytebits_to_byte(bs,32);
	blocks[2] = bytebits_to_byte(bs+32,32);
	blocks[3] = bytebits_to_byte(bs+64,32);

	PrintAndLog("Preparing to clone AWID %u to T55x7 with FC: %u, CN: %u", fmtlen, fc, cn);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	PrintAndLog(" 00 | 0x%08x", blocks[0]);
	PrintAndLog(" 01 | 0x%08x", blocks[1]);
	PrintAndLog(" 02 | 0x%08x", blocks[2]);
	PrintAndLog(" 03 | 0x%08x", blocks[3]);	
	
	UsbCommand resp;
	UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	for (uint8_t i=0; i<4; i++) {
		c.arg[0] = blocks[i];
		c.arg[1] = i;
		clearCommandBuffer();
		SendCommand(&c);
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)){
			PrintAndLog("Error occurred, device did not respond during write operation.");
			return -1;
		}
	}
	return 0;
}

int CmdAWIDBrute(const char *Cmd){
	
	bool errors = false;
	uint32_t fc = 0, cn = 0, delay = 1000;
	uint8_t fmtlen = 0;
	uint8_t bits[96];
	uint8_t *bs = bits;
	size_t size = sizeof(bits);
	memset(bs, 0x00, size);
	uint8_t cmdp = 0;
	
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_lf_awid_brute();
		case 'f':
		case 'F':
		  	fc =  param_get32ex(Cmd ,cmdp+1, 0, 10);
			if ( !fc )
				errors = true;
			cmdp += 2;
			break;
		case 'd':
		case 'D':
			// delay between attemps,  defaults to 1000ms. 
			delay = param_get32ex(Cmd, cmdp+1, 1000, 10);
			cmdp += 2;
			break;
		case 'c':
		case 'C':
			cn = param_get32ex(Cmd, cmdp+1, 0, 10);
			// truncate cardnumber.
			cn &= 0xFFFF;
			cmdp += 2;
			break;
		case 'a':
		case 'A':
			fmtlen = param_get8(Cmd, cmdp+1);
			cmdp += 2;
			break;
		default:
			PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	if ( fc == 0 )errors = true;
	if ( errors ) return usage_lf_awid_brute();

	// limit fc according to selected format
	switch(fmtlen) {
		case 50:
			if ((fc & 0xFFFF) != fc) {
				fc &= 0xFFFF;
				PrintAndLog("Facility-code truncated to 16-bits (AWID50): %u", fc);
			}
			break;
		default:
			if ((fc & 0xFF) != fc) {
				fc &= 0xFF;
				PrintAndLog("Facility-code truncated to 8-bits (AWID26): %u", fc);
			}
			break;
	}
	
	PrintAndLog("Bruteforceing AWID %d Reader", fmtlen);
	PrintAndLog("Press pm3-button to abort simulation or press key");

	uint16_t up = cn;
	uint16_t down = cn;
	
	for (;;){
	
		if ( offline ) {
			printf("Device offline\n");
			return  2;
		}
		if (ukbhit()) {
			PrintAndLog("aborted via keyboard!");
			return sendPing();
		}
		
		// Do one up
		if ( up < 0xFFFF )
			if ( !sendTry(fmtlen, fc, up++, delay, bs, size)) return 1;
		
		// Do one down  (if cardnumber is given)
		if ( cn > 1 )
			if ( down > 1 )
				if ( !sendTry(fmtlen, fc, --down, delay, bs, size)) return 1;
	}
	return 0;
}

static command_t CommandTable[] = {
	{"help",      CmdHelp,         1, "This help"},
	{"fskdemod",  CmdAWIDDemodFSK, 0, "Realtime AWID FSK demodulator"},
	{"sim",       CmdAWIDSim,      0, "AWID tag simulator"},
	{"clone",     CmdAWIDClone,    0, "Clone AWID to T55x7"},
	{"brute",	  CmdAWIDBrute,	   0, "Bruteforce card number against reader"},
	{NULL, NULL, 0, NULL}
};

int CmdLFAWID(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
