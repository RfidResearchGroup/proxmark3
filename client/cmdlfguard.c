//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Farpoint / Pyramid tag commands
//-----------------------------------------------------------------------------
#include <string.h>
#include <inttypes.h>
#include "cmdlfguard.h"
static int CmdHelp(const char *Cmd);

int usage_lf_guard_clone(void){
	PrintAndLog("clone a Guardall tag to a T55x7 tag.");
	PrintAndLog("The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated. ");
	PrintAndLog("Currently work only on 26bit");
	PrintAndLog("");
	PrintAndLog("Usage: lf guard clone <Facility-Code> <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("  <Facility-Code> :  8-bit value facility code");
	PrintAndLog("  <Card Number>   : 16-bit value card number");
	PrintAndLog("");
	PrintAndLog("Sample  : lf guard clone 123 11223");
	return 0;
}

int usage_lf_guard_sim(void) {
	PrintAndLog("Enables simulation of Guardall card with specified card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
	PrintAndLog("Currently work only on 26bit");
	PrintAndLog("");
	PrintAndLog("Usage:  lf guard sim <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("  <Facility-Code> :  8-bit value facility code");
	PrintAndLog("  <Card Number>   : 16-bit value card number");
	PrintAndLog("");
	PrintAndLog("Sample  : lf guard sim 123 11223");
	return 0;
}


// Works for 26bits.
int GetGuardBits(uint32_t fc, uint32_t cn, uint8_t *guardBits) {
  
	// Intializes random number generator
	time_t t;
	srand((unsigned) time(&t));

	uint8_t pre[96];
	memset(pre, 0x00, sizeof(pre));

	uint8_t index = 8;
	
	// preamble  6bits
	pre[0] = 1;
	pre[1] = 1;
	pre[2] = 1;
	pre[3] = 1;
	pre[4] = 1;
	//pre[5] = 0;

	// add xor key
	uint8_t xorKey = rand() % 0xFF;
	num_to_bytebits(xorKey, 8, pre+index);
	index += 8;
	
	// add format length
	// len | hex | bin  wiegand pos fc/cn   
	//  26 | 1A  | 0001 1010
	num_to_bytebits(26, 8, pre+index);
	//  36 | 24  | 0010 0100
	//num_to_bytebits(36, 8, pre+index);
	//  40 | 28  | 0010 1000
	//num_to_bytebits(40, 8, pre+index);

	index += 8;
	
	// 2bit checksum
	// unknown today.
	index += 2;
	
	// Get 26 wiegand from FacilityCode, CardNumber	
	uint8_t wiegand[24];
	memset(wiegand, 0x00, sizeof(wiegand));
	num_to_bytebits(fc, 8, wiegand);
	num_to_bytebits(cn, 16, wiegand+8);

	// add wiegand parity bits (dest, source, len)
	wiegand_add_parity(pre+index, wiegand, 24);

	uint8_t tmp = 0, i = 0;
	for (i = 2; i < 12; ++i) {
		// // xor all bytes
		// tmp = xorKey ^ bytebits_to_byte(pre + (i*8), 8);
		
		// // copy to out..
		// num_to_bytebits(tmp, 8, pre + (i*8) );
	}

	// add spacer bit 0 every 5
	
	// swap nibbles
	
	
	// copy to outarray
	memcpy(guardBits, pre, sizeof(pre));
	
	printf(" | %s\n", sprint_bin(guardBits, 96) );
	return 1;
}

int CmdGuardRead(const char *Cmd) {
	CmdLFRead("s");
	getSamples("30000",false);
	return CmdG_Prox_II_Demod("");
}

int CmdGuardClone(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_guard_clone();

	uint32_t facilitycode=0, cardnumber=0, fc = 0, cn = 0;
	uint8_t i;
	uint8_t bs[96];
	memset(bs, 0x00, sizeof(bs));
	
	//GuardProxII - compat mode, ASK/Biphase,  data rate 64, 3 data blocks
	uint32_t blocks[5] = {T55x7_MODULATION_BIPHASE | T55x7_BITRATE_RF_64 | 3<<T55x7_MAXBLOCK_SHIFT, 0, 0, 0, 0};
	
//	if (param_getchar(Cmd, 3) == 'Q' || param_getchar(Cmd, 3) == 'q')
//		blocks[0] = T5555_MODULATION_FSK2 | 50<<T5555_BITRATE_SHIFT | 4<<T5555_MAXBLOCK_SHIFT;

	if (sscanf(Cmd, "%u %u", &fc, &cn ) != 2) return usage_lf_guard_clone();

	facilitycode = (fc & 0x000000FF);
	cardnumber = (cn & 0x0000FFFF);
	
	if ( !GetGuardBits(facilitycode, cardnumber, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	blocks[1] = bytebits_to_byte(bs,32);
	blocks[2] = bytebits_to_byte(bs+32,32);
	blocks[3] = bytebits_to_byte(bs+64,32);

	PrintAndLog("Preparing to clone Guardall to T55x7 with Facility Code: %u, Card Number: %u", facilitycode, cardnumber);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	for ( i = 0; i<4; ++i )
		PrintAndLog(" %02d | %08x", i, blocks[i]);

	// UsbCommand resp;
	// UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	// for ( i = 0; i<5; ++i ) {
		// c.arg[0] = blocks[i];
		// c.arg[1] = i;
		// clearCommandBuffer();
		// SendCommand(&c);
		// if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)){
			// PrintAndLog("Error occurred, device did not respond during write operation.");
			// return -1;
		// }
	// }
    return 0;
}

int CmdGuardSim(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_guard_sim();

	uint32_t facilitycode = 0, cardnumber = 0, fc = 0, cn = 0;
	
	uint8_t bs[96];
	size_t size = sizeof(bs);
	memset(bs, 0x00, size);
	
	// Pyramid uses:  ASK Biphase, clk: 32, invert: 0
	uint64_t arg1, arg2;
	arg1 = (10 << 8) + 8;
	arg2 = 32 | 0;

	if (sscanf(Cmd, "%u %u", &fc, &cn ) != 2) return usage_lf_guard_sim();

	facilitycode = (fc & 0x000000FF);
	cardnumber = (cn & 0x0000FFFF);
	
	if ( !GetGuardBits(facilitycode, cardnumber, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	PrintAndLog("Simulating Guardall - Facility Code: %u, CardNumber: %u", facilitycode, cardnumber );
	
	UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
	memcpy(c.d.asBytes, bs, size);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
    {"help",	CmdHelp,		1, "This help"},
	{"read",	CmdGuardRead,  0, "Attempt to read and extract tag data"},
	{"clone",	CmdGuardClone, 0, "<Facility-Code> <Card Number>  clone Guardall tag"},
	{"sim",		CmdGuardSim,   0, "<Facility-Code> <Card Number>  simulate Guardall tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFGuard(const char *Cmd) {
	clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
