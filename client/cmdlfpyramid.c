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
#include "cmdlfpyramid.h"
static int CmdHelp(const char *Cmd);

int usage_lf_pyramid_clone(void){
	PrintAndLog("clone a Farepointe/Pyramid tag to a T55x7 tag.");
	PrintAndLog("Per pyramid format, the facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
	PrintAndLog("");
	PrintAndLog("Usage: lf pyramid clone <Facility-Code> <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("  <Facility-Code> :  8-bit value facility code");
	PrintAndLog("  <Card Number>   : 16-bit value card number");
	PrintAndLog("");
	PrintAndLog("Sample  : lf pyramid clone 123 11223");
	return 0;
}

int usage_lf_pyramid_sim(void) {
	PrintAndLog("Enables simulation of Farepointe/Pyramid card with specified card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("Per pyramid format, the facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf pyramid sim <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("  <Facility-Code> :  8-bit value facility code");
	PrintAndLog("  <Card Number>   : 16-bit value card number");
	PrintAndLog("");
	PrintAndLog("Sample  : lf pyramid sim 123 11223");
	return 0;
}

// calc checksum
int GetWiegandFromPyramid(const char *id, uint32_t *fc, uint32_t *cn) {
	return 0;
}

int GetPyramidBits(uint32_t fc, uint32_t cn, uint8_t *pyramidBits) {

	uint8_t pre[128];
	memset(pre, 0x00, sizeof(pre));

	// add preamble
	pyramidBits[7]=1;
	num_to_bytebits(26, 8, pre);

	// get wiegand
	uint8_t wiegand[24];
	num_to_bytebits(fc, 8, wiegand);
	num_to_bytebits(cn, 16, wiegand+8);

	// add wiegand parity bits
	wiegand_add_parity(pre+8, wiegand, 24);

	// add paritybits	
	addParity(pre, pyramidBits+8, 66, 4, 1);
	
	// add checksum		
	// this is wrong.
	uint32_t crc = CRC8Maxim(wiegand, 13);
	num_to_bytebits(crc, 8, pre+120);
	
	return 1;
}

int CmdPyramidRead(const char *Cmd) {
	// read lf silently
	CmdLFRead("s");
	// get samples silently
	getSamples("30000",false);
	// demod and output Pyramid ID	
	return CmdFSKdemodPyramid("");
}

int CmdPyramidClone(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_pyramid_clone();

	uint32_t facilitycode=0, cardnumber=0;
	uint8_t bits[128];
	uint8_t *bs = bits;
	memset(bs,0,sizeof(bits));
	//Pyramid - compat mode, FSK2a, data rate 50, 4 data blocks
	uint32_t blocks[5] = {T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_50 | 4<<T55x7_MAXBLOCK_SHIFT, 0, 0, 0, 0};
	
//	if (param_getchar(Cmd, 3) == 'Q' || param_getchar(Cmd, 3) == 'q')
//		blocks[0] = T5555_MODULATION_FSK2 | 50<<T5555_BITRATE_SHIFT | 4<<T5555_MAXBLOCK_SHIFT;

	// get wiegand from printed number.
	GetWiegandFromPyramid(Cmd, &facilitycode, &cardnumber);
	
	if ((facilitycode & 0xFF) != facilitycode) {
		facilitycode &= 0xFF;
		PrintAndLog("Facility Code Truncated to 8-bits (Pyramid): %u", facilitycode);
	}

	if ((cardnumber & 0xFFFF) != cardnumber) {
		cardnumber &= 0xFFFF;
		PrintAndLog("Card Number Truncated to 16-bits (Pyramid): %u", cardnumber);
	}
	
	if ( !GetPyramidBits(facilitycode, cardnumber, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	blocks[1] = bytebits_to_byte(bs,32);
	blocks[2] = bytebits_to_byte(bs+32,32);
	blocks[3] = bytebits_to_byte(bs+64,32);
	blocks[4] = bytebits_to_byte(bs+96,32);

	PrintAndLog("Preparing to clone Farepointe/Pyramid to T55x7 with Facility Code: %u, Card Number: %u", facilitycode, cardnumber);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	for ( uint8_t i=0; i<5; ++i )
		PrintAndLog(" %02d | 0x%08x",i , blocks[i]);
	
	UsbCommand resp;
	//UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	for ( uint8_t i=0; i<5; ++i ) {
		//c.arg[0] = blocks[i];
		//c.arg[1] = i;
		clearCommandBuffer();
		// SendCommand(&c);
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000)){
			PrintAndLog("Error occurred, device did not respond during write operation.");
			return -1;
		}
	}
    return 0;
}

int CmdPyramidSim(const char *Cmd) {
	// uint32_t id = 0;
	// uint64_t rawID = 0;
	// uint8_t clk = 50, encoding = 1, separator = 0, invert = 0;

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_pyramid_sim();

	// id = param_get32ex(Cmd, 0, 0, 16);
	// if (id == 0) return usage_lf_pyramid_sim();

	//rawID = getPyramidBits(id);

	// uint16_t arg1, arg2;
	// size_t size = 64;
	// arg1 = clk << 8 | encoding;
	// arg2 = invert << 8 | separator;

	// PrintAndLog("Simulating - ID: %08X, Raw: %08X%08X",id,(uint32_t)(rawID >> 32),(uint32_t) (rawID & 0xFFFFFFFF));
	
	// UsbCommand c = {CMD_FSK_SIM_TAG, {arg1, arg2, size}};
	// num_to_bytebits(rawID, size, c.d.asBytes);
	// clearCommandBuffer();
	// SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
    {"help",	CmdHelp,		1, "This help"},
	{"read",	CmdPyramidRead,  0, "Attempt to read and extract tag data"},
	{"clone",	CmdPyramidClone, 0, "<Facility-Code> <Card Number>  clone pyramid tag"},
	{"sim",		CmdPyramidSim,   0, "<Facility-Code> <Card Number>  simulate pyramid tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFPyramid(const char *Cmd) {
	clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
