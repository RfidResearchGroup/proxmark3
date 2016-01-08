//-----------------------------------------------------------------------------
// Authored by Craig Young <cyoung@tripwire.com> based on cmdlfhid.c structure
//
// cmdlfhid.c is Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency AWID26 commands
//-----------------------------------------------------------------------------

#include <stdio.h>      // sscanf
#include "proxmark3.h"  // Definitions, USB controls, etc
#include "ui.h"         // PrintAndLog
#include "cmdparser.h"  // CmdsParse, CmdsHelp
#include "cmdlfawid.h"  // AWID function declarations
#include "lfdemod.h"    // parityTest
#include "util.h"       // weigandparity
#include "protocols.h"  // for T55xx config register definitions
#include "cmdmain.h"
 #include "sleep.h"
 
static int CmdHelp(const char *Cmd);

int usage_lf_awid_fskdemod(void) {
	PrintAndLog("Enables AWID26 compatible reader mode printing details of scanned AWID26 tags.");
	PrintAndLog("By default, values are printed and logged until the button is pressed or another USB command is issued.");
	PrintAndLog("If the ['1'] option is provided, reader mode is exited after reading a single AWID26 card.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid fskdemod ['1']");
	PrintAndLog("Options :");
	PrintAndLog("  1 : (optional) stop after reading a single card");
	PrintAndLog("");
	PrintAndLog("Samples : lf awid fskdemod");
	PrintAndLog("          : lf awid fskdemod 1");
	return 0;
}

int usage_lf_awid_sim(void) {
	PrintAndLog("Enables simulation of AWID26 card with specified facility-code and card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("Per AWID26 format, the facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid sim <Facility-Code> <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("  <Facility-Code> :  8-bit value AWID facility code");
	PrintAndLog("  <Card Number>   : 16-bit value AWID card number");
	PrintAndLog("");
	PrintAndLog("Sample : lf awid sim 224 1337");
	return 0;
}

int usage_lf_awid_clone(void) {
	PrintAndLog("Enables cloning of AWID26 card with specified facility-code and card number onto T55x7.");
	PrintAndLog("The T55x7 must be on the antenna when issuing this command.  T55x7 blocks are calculated and printed in the process.");
	PrintAndLog("Per AWID26 format, the facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid clone <Facility-Code> <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("  <Facility-Code> : 8-bit value AWID facility code");
	PrintAndLog("  <Card Number>   : 16-bit value AWID card number");
	PrintAndLog("  Q5              : optional - clone to Q5 (T5555) instead of T55x7 chip");
	PrintAndLog("");
	PrintAndLog("Sample  : lf awid clone 224 1337");
	return 0;
}

int usage_lf_awid_brute(void){
	PrintAndLog("Enables bruteforce of AWID26 card with specified facility-code.");
	PrintAndLog("Per AWID26 format, the facility-code (FC) is 8-bit and the card number is 16-bit.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf awid brute <Facility-Code>");
	PrintAndLog("Options :");
	PrintAndLog("  <Facility-Code> :  8-bit value AWID facility code");
	PrintAndLog("");
	PrintAndLog("Sample  : lf awid brute 224");
	return 0;
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
int getAWIDBits(uint32_t fc, uint32_t cn, uint8_t	*AWIDBits) {
	uint8_t pre[66];
	memset(pre, 0, sizeof(pre));
	AWIDBits[7]=1;
	num_to_bytebits(26, 8, pre);

	uint8_t wiegand[24];
	num_to_bytebits(fc, 8, wiegand);
	num_to_bytebits(cn, 16, wiegand+8);

	wiegand_add_parity(pre+8, wiegand, 24);
	size_t bitLen = addParity(pre, AWIDBits+8, 66, 4, 1);

	if (bitLen != 88) return 0;
	return 1;
}

int CmdAWIDSim(const char *Cmd) {
	uint32_t fcode = 0, cnum = 0, fc = 0, cn = 0;
	uint8_t bits[96];
	uint8_t *bs = bits;
	size_t size = sizeof(bits);
	memset(bs, 0x00, size);

	uint64_t arg1 = ( 10 << 8 ) + 8; // fcHigh = 10, fcLow = 8
	uint64_t arg2 = 50; // clk RF/50 invert=0
  
	if (sscanf(Cmd, "%u %u", &fc, &cn ) != 2) return usage_lf_awid_sim();

	fcode = (fc & 0x000000FF);
	cnum = (cn & 0x0000FFFF);
	
	if (fc != fcode) PrintAndLog("Facility-Code (%u) truncated to 8-bits: %u", fc, fcode);
	if (cn != cnum)  PrintAndLog("Card number (%u) truncated to 16-bits: %u", cn, cnum);
	
	PrintAndLog("Emulating AWID26 -- FC: %u; CN: %u\n", fcode, cnum);
	PrintAndLog("Press pm3-button to abort simulation or run another command");
	
	if (!getAWIDBits(fc, cn, bs)) {
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
	uint32_t fc=0,cn=0;
	uint8_t bits[96];
	uint8_t *bs=bits;
	memset(bs,0,sizeof(bits));
	
	if (sscanf(Cmd, "%u %u", &fc, &cn ) != 2) return usage_lf_awid_clone();

	if (param_getchar(Cmd, 3) == 'Q' || param_getchar(Cmd, 3) == 'q')
		blocks[0] = T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | 50<<T5555_BITRATE_SHIFT | 3<<T5555_MAXBLOCK_SHIFT;

	if ((fc & 0xFF) != fc) {
		fc &= 0xFF;
		PrintAndLog("Facility-Code Truncated to 8-bits (AWID26): %u", fc);
	}

	if ((cn & 0xFFFF) != cn) {
		cn &= 0xFFFF;
		PrintAndLog("Card Number Truncated to 16-bits (AWID26): %u", cn);
	}
	
	if ( !getAWIDBits(fc, cn, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	blocks[1] = bytebits_to_byte(bs,32);
	blocks[2] = bytebits_to_byte(bs+32,32);
	blocks[3] = bytebits_to_byte(bs+64,32);

	PrintAndLog("Preparing to clone AWID26 to T55x7 with FC: %u, CN: %u", 
	    fc, cn);
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
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)){
			PrintAndLog("Error occurred, device did not respond during write operation.");
			return -1;
		}
	}
	return 0;
}

int CmdAWIDBrute(const char *Cmd){
	
	uint8_t fc = 0x00;
	uint8_t bits[96];
	uint8_t *bs = bits;
	size_t size = sizeof(bits);
	memset(bs, 0x00, size);

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 3 || strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_awid_brute();
	
  	fc =  param_get8(Cmd, 0);
	if ( fc == 0) return usage_lf_awid_brute();
	
	PrintAndLog("Bruteforceing AWID26");
	PrintAndLog("Press pm3-button to abort simulation or run another command");

	uint64_t arg1 = (10<<8) + 8; // fcHigh = 10, fcLow = 8
	uint64_t arg2 = 50; 		 // clk RF/50 invert=0
	UsbCommand c = {CMD_FSK_SIM_TAG, {arg1, arg2, size}};  

	for ( uint16_t cn = 1; cn < 0xFFFF; ++cn){
		if (ukbhit()) {
			PrintAndLog("aborted via keyboard!");
			c.cmd = CMD_PING;
			c.arg[0] = 0x00;
			c.arg[1] = 0x00;
			c.arg[2] = 0x00;
			clearCommandBuffer();
			SendCommand(&c);
			return 1;
		}
			
		(void)getAWIDBits(fc, cn, bs);
		memcpy(c.d.asBytes, bs, size);
		clearCommandBuffer();
		SendCommand(&c);
		
		PrintAndLog("Trying FC: %u; CN: %u", fc, cn);
		// pause
		sleep(1);
	}
	return 0;
}

static command_t CommandTable[] = {
	{"help",      CmdHelp,         1, "This help"},
	{"fskdemod",  CmdAWIDDemodFSK, 0, "['1'] Realtime AWID FSK demodulator (option '1' for one tag only)"},
	{"sim",       CmdAWIDSim,      0, "<Facility-Code> <Card Number> -- AWID tag simulator"},
	{"clone",     CmdAWIDClone,    0, "<Facility-Code> <Card Number> <Q5> -- Clone AWID to T55x7"},
	{"brute",	  CmdAWIDBrute,	   0, "<Facility-Code> -- bruteforce card number"},
	{NULL, NULL, 0, NULL}
};

int CmdLFAWID(const char *Cmd) {
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
