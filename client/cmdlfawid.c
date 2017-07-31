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
// FSK2a, RF/50, 96 bits (complete)
//-----------------------------------------------------------------------------
#include "cmdlfawid.h"  // AWID function declarations
 
static int CmdHelp(const char *Cmd);

int usage_lf_awid_read(void) {
	PrintAndLog("Enables AWID compatible reader mode printing details of scanned AWID26 or AWID50 tags.");
	PrintAndLog("By default, values are printed and logged until the button is pressed or another USB command is issued.");
	PrintAndLog("If the [1] option is provided, reader mode is exited after reading a single AWID card.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid read [h] [1]");
	PrintAndLog("Options:");
	PrintAndLog("      h :  This help");	
	PrintAndLog("      1 : (optional) stop after reading a single card");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("       lf awid read");
	PrintAndLog("       lf awid read 1");
	return 0;
}

int usage_lf_awid_sim(void) {
	PrintAndLog("Enables simulation of AWID card with specified facility-code and card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid sim [h] <format> <facility-code> <card-number>");
	PrintAndLog("Options:");
	PrintAndLog("                h :  This help");	
	PrintAndLog("         <format> :  format length 26|34|37|50");
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
	PrintAndLog("         <format> :  format length 26|34|37|50");
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
		return false;
	}

	uint64_t arg1 = (10<<8) + 8; // fcHigh = 10, fcLow = 8
	uint64_t arg2 = 50; 		 // clk RF/50 invert=0
	UsbCommand c = {CMD_FSK_SIM_TAG, {arg1, arg2, bs_len}};
	memcpy(c.d.asBytes, bs, bs_len);
	clearCommandBuffer();
	SendCommand(&c);
	msleep(delay);
	sendPing();
	return true;
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
	switch (fmtlen) {
		case 26:{
			uint8_t wiegand[24];
			num_to_bytebits(fc, 8, wiegand);
			num_to_bytebits(cn, 16, wiegand+8);
			wiegand_add_parity(pre+8, wiegand,  sizeof(wiegand));
			break;
		}
		case 34:{
			uint8_t wiegand[32];
			num_to_bytebits(fc, 8, wiegand);
			num_to_bytebits(cn, 24, wiegand+8);
			wiegand_add_parity(pre+8, wiegand,  sizeof(wiegand));
			break;
		}
		case 37:{
			uint8_t wiegand[31];
			num_to_bytebits(fc, 13, wiegand);
			num_to_bytebits(cn, 18, wiegand+13);
			wiegand_add_parity(pre+8, wiegand,  sizeof(wiegand));
			break;
		}
		case 50: {
			uint8_t wiegand[48];
			num_to_bytebits(fc, 16, wiegand);
			num_to_bytebits(cn, 32, wiegand+16);
			wiegand_add_parity(pre+8, wiegand, sizeof(wiegand));
			break;
		}
	}
	
	// add AWID 4bit parity 
	size_t bitLen = addParity(pre, bits+8, 66, 4, 1);

	if (bitLen != 88) return 0;
	return 1;
}

static void verify_values(uint8_t *fmtlen, uint32_t *fc, uint32_t *cn){
	switch (*fmtlen) {
		case 50:
			if ((*fc & 0xFFFF) != *fc) {
				*fc &= 0xFFFF;
				PrintAndLog("Facility-Code Truncated to 16-bits (AWID50): %u", *fc);
			}
			break;
		case 37:
			if ((*fc & 0x1FFF) != *fc) {
				*fc &= 0x1FFF;
				PrintAndLog("Facility-Code Truncated to 13-bits (AWID37): %u", *fc);
			}
			if ((*cn & 0x3FFFF) != *cn) {
				*cn &= 0x3FFFF;
				PrintAndLog("Card Number Truncated to 18-bits (AWID37): %u", *cn);
			}			
			break;
		case 34:
			if ((*fc & 0xFF) != *fc) {
				*fc &= 0xFF;
				PrintAndLog("Facility-Code Truncated to 8-bits (AWID34): %u", *fc);
			}
			if ((*cn & 0xFFFFFF) != *cn) {
				*cn &= 0xFFFFFF;
				PrintAndLog("Card Number Truncated to 24-bits (AWID34): %u", *cn);
			}
			break;
		case 26:
		default:
			*fmtlen = 26;
			if ((*fc & 0xFF) != *fc) {
				*fc &= 0xFF;
				PrintAndLog("Facility-Code Truncated to 8-bits (AWID26): %u", *fc);
			}
			if ((*cn & 0xFFFF) != *cn) {
				*cn &= 0xFFFF;
				PrintAndLog("Card Number Truncated to 16-bits (AWID26): %u", *cn);
			}
			break;
	}
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
int CmdAWIDRead(const char *Cmd) {
	lf_read(true, 12000);
	return CmdAWIDDemod(Cmd);
}
// this read loops on device side.
// uses the demod in lfops.c
int CmdAWIDRead_device(const char *Cmd) {

	if (Cmd[0] == 'h' || Cmd[0] == 'H') return usage_lf_awid_read();
	uint8_t findone = (Cmd[0] == '1') ? 1 : 0;
	UsbCommand c = {CMD_AWID_DEMOD_FSK, {findone, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;   
}

//by marshmellow
//AWID Prox demod - FSK RF/50 with preamble of 00000001  (always a 96 bit data stream)
//print full AWID Prox ID and some bit format details if found
int CmdAWIDDemod(const char *Cmd) {
	uint8_t bits[MAX_GRAPH_TRACE_LEN]={0};
	size_t size = getFromGraphBuf(bits);
	if (size==0) {
		PrintAndLog("DEBUG: Error - AWID not enough samples");
		return 0;
	}
	//get binary from fsk wave
	int waveIdx = 0;

	int idx = detectAWID(bits, &size, &waveIdx);
	if (idx <= 0){
		if (g_debugMode){
			if (idx == -1)
				PrintAndLog("DEBUG: Error - AWID not enough samples");
			else if (idx == -2)
				PrintAndLog("DEBUG: Error - AWID only noise found");
			else if (idx == -3)
				PrintAndLog("DEBUG: Error - AWID problem during FSK demod");
			else if (idx == -4)
				PrintAndLog("DEBUG: Error - AWID preamble not found");
			else if (idx == -5)
				PrintAndLog("DEBUG: Error - AWID size not correct: %d", size);
			else
				PrintAndLog("DEBUG: Error - AWID error %d",idx);
		}
		return 0;
	}

	// Index map
	// 0            10            20            30              40            50              60
	// |            |             |             |               |             |               |
	// 01234567 890 1 234 5 678 9 012 3 456 7 890 1 234 5 678 9 012 3 456 7 890 1 234 5 678 9 012 3 - to 96
	// -----------------------------------------------------------------------------
	// 00000001 000 1 110 1 101 1 011 1 101 1 010 0 000 1 000 1 010 0 001 0 110 1 100 0 000 1 000 1
	// premable bbb o bbb o bbw o fff o fff o ffc o ccc o ccc o ccc o ccc o ccc o wxx o xxx o xxx o - to 96
	//          |---26 bit---|    |-----117----||-------------142-------------|
	// b = format bit len, o = odd parity of last 3 bits
	// f = facility code, c = card number
	// w = wiegand parity
	// (26 bit format shown)
 
	//get raw ID before removing parities
	uint32_t rawLo = bytebits_to_byte(bits + idx + 64, 32);
	uint32_t rawHi = bytebits_to_byte(bits + idx + 32, 32);
	uint32_t rawHi2 = bytebits_to_byte(bits + idx, 32);
	setDemodBuf(bits, 96, idx);

	size = removeParity(bits, idx+8, 4, 1, 88);
	if (size != 66){
		if (g_debugMode) PrintAndLog("DEBUG: Error - AWID at parity check-tag size does not match AWID format");
		return 0;
	}
	// ok valid card found!

	// Index map
	// 0           10         20        30          40        50        60
	// |           |          |         |           |         |         |
	// 01234567 8 90123456 7890123456789012 3 456789012345678901234567890123456
	// -----------------------------------------------------------------------------
	// 00011010 1 01110101 0000000010001110 1 000000000000000000000000000000000
	// bbbbbbbb w ffffffff cccccccccccccccc w xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	// |26 bit|   |-117--| |-----142------|
    //
	// 00110010 0 0000111110100000 00000000000100010010100010000111 1 000000000 
	// bbbbbbbb w ffffffffffffffff cccccccccccccccccccccccccccccccc w xxxxxxxxx
	// |50 bit|   |----4000------| |-----------2248975------------| 
	// b = format bit len, o = odd parity of last 3 bits
	// f = facility code, c = card number
	// w = wiegand parity

	uint32_t fc = 0;
	uint32_t cardnum = 0;
	uint32_t code1 = 0;
	uint32_t code2 = 0;
	uint8_t fmtLen = bytebits_to_byte(bits, 8);

	switch(fmtLen) {
		case 26: 
			fc = bytebits_to_byte(bits + 9, 8);
			cardnum = bytebits_to_byte(bits + 17, 16);
			code1 = bytebits_to_byte(bits + 8,fmtLen);
			PrintAndLog("AWID Found - BitLength: %d, FC: %d, Card: %u - Wiegand: %x, Raw: %08x%08x%08x", fmtLen, fc, cardnum, code1, rawHi2, rawHi, rawLo);
			break;
		case 34:
			fc = bytebits_to_byte(bits + 9, 8);
			cardnum = bytebits_to_byte(bits + 17, 24);
			code1 = bytebits_to_byte(bits + 8, (fmtLen-32) );
			code2 = bytebits_to_byte(bits + 8 + (fmtLen-32), 32);			
			PrintAndLog("AWID Found - BitLength: %d, FC: %d, Card: %u - Wiegand: %x%08x, Raw: %08x%08x%08x", fmtLen, fc, cardnum, code1, code2, rawHi2, rawHi, rawLo);			
			break;
		case 37:
			fc = bytebits_to_byte(bits + 9, 13);
			cardnum = bytebits_to_byte(bits + 22, 18);
			code1 = bytebits_to_byte(bits + 8, (fmtLen-32) );
			code2 = bytebits_to_byte(bits + 8 + (fmtLen-32), 32);			
			PrintAndLog("AWID Found - BitLength: %d, FC: %d, Card: %u - Wiegand: %x%08x, Raw: %08x%08x%08x", fmtLen, fc, cardnum, code1, code2, rawHi2, rawHi, rawLo);
			break;
		// case 40:
		// break;		
		case 50:
			fc = bytebits_to_byte(bits + 9, 16);
			cardnum = bytebits_to_byte(bits + 25, 32);
			code1 = bytebits_to_byte(bits + 8, (fmtLen-32) );
			code2 = bytebits_to_byte(bits + 8 + (fmtLen-32), 32);
			PrintAndLog("AWID Found - BitLength: %d, FC: %d, Card: %u - Wiegand: %x%08x, Raw: %08x%08x%08x", fmtLen, fc, cardnum, code1, code2, rawHi2, rawHi, rawLo);
			break;
		default:
			if (fmtLen > 32 ) {
				cardnum = bytebits_to_byte(bits + 8 + (fmtLen-17), 16);
				code1 = bytebits_to_byte(bits + 8, fmtLen-32);
				code2 = bytebits_to_byte(bits + 8 + (fmtLen-32), 32);
				PrintAndLog("AWID Found - BitLength: %d -unknown BitLength- (%u) - Wiegand: %x%08x, Raw: %08x%08x%08x", fmtLen, cardnum, code1, code2, rawHi2, rawHi, rawLo);
			} else {
				cardnum = bytebits_to_byte(bits + 8 + (fmtLen-17), 16);
				code1 = bytebits_to_byte(bits + 8, fmtLen);
				PrintAndLog("AWID Found - BitLength: %d -unknown BitLength- (%u) - Wiegand: %x, Raw: %08x%08x%08x", fmtLen, cardnum, code1, rawHi2, rawHi, rawLo);
			}
			break;		
	}

	if (g_debugMode){
		PrintAndLog("DEBUG: AWID idx: %d, Len: %d Printing Demod Buffer:", idx, 96);
		printDemodBuff();
	}
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
	
	verify_values(&fmtlen, &fc, &cn);
	
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
	
	if (param_getchar(Cmd, 3) == 'Q' || param_getchar(Cmd, 3) == 'q')
		//t5555 (Q5) BITRATE = (RF-2)/2 (iceman)
		blocks[0] = T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(50) | 3<<T5555_MAXBLOCK_SHIFT;

	verify_values(&fmtlen, &fc, &cn);
		
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
		if (!WaitForResponseTimeout(CMD_ACK, &resp, T55XX_WRITE_TIMEOUT)){
			PrintAndLog("Error occurred, device did not respond during write operation.");
			return -1;
		}
	}
	return 0;
}

int CmdAWIDBrute(const char *Cmd) {
	
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
			int gc = getchar(); (void)gc;
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
	{"help",	CmdHelp,		1, "This help"},
	{"demod",	CmdAWIDDemod,	0, "Demodulate an AWID FSK tag from the GraphBuffer"},
	{"read",	CmdAWIDRead,	0, "Attempt to read and extract tag data"},
	{"sim",		CmdAWIDSim,		0, "AWID tag simulator"},
	{"clone",	CmdAWIDClone,	0, "Clone AWID to T55x7"},
	{"brute",	CmdAWIDBrute,	0, "Bruteforce card number against reader"},
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
