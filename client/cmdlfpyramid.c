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
	PrintAndLog("clone a Farpointe/Pyramid tag to a T55x7 tag.");
	PrintAndLog("The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated. ");
	PrintAndLog("Currently work only on 26bit");
	PrintAndLog("");
	PrintAndLog("Usage: lf pyramid clone <Facility-Code> <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("  <Facility-Code> :  8-bit value facility code");
	PrintAndLog("  <Card Number>   : 16-bit value card number");
	PrintAndLog("  Q5              : optional - clone to Q5 (T5555) instead of T55x7 chip");
	PrintAndLog("");
	PrintAndLog("Sample  : lf pyramid clone 123 11223");
	return 0;
}

int usage_lf_pyramid_sim(void) {
	PrintAndLog("Enables simulation of Farpointe/Pyramid card with specified card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
	PrintAndLog("Currently work only on 26bit");
	PrintAndLog("");
	PrintAndLog("Usage:  lf pyramid sim <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("  <Facility-Code> :  8-bit value facility code");
	PrintAndLog("  <Card Number>   : 16-bit value card number");
	PrintAndLog("");
	PrintAndLog("Sample  : lf pyramid sim 123 11223");
	return 0;
}

// Works for 26bits.
int GetPyramidBits(uint32_t fc, uint32_t cn, uint8_t *pyramidBits) {

	uint8_t pre[128];
	memset(pre, 0x00, sizeof(pre));

	// format start bit
	pre[79] = 1;
	
	// Get 26 wiegand from FacilityCode, CardNumber	
	uint8_t wiegand[24];
	memset(wiegand, 0x00, sizeof(wiegand));
	num_to_bytebits(fc, 8, wiegand);
	num_to_bytebits(cn, 16, wiegand+8);

	// add wiegand parity bits (dest, source, len)
	wiegand_add_parity(pre+80, wiegand, 24);
	
	// add paritybits	(bitsource, dest, sourcelen, paritylen, parityType (odd, even,)
	addParity(pre+8, pyramidBits+8, 102, 8, 1);

	// add checksum		
	uint8_t csBuff[13];
	for (uint8_t i = 0; i < 13; i++)
		csBuff[i] = bytebits_to_byte(pyramidBits + 16 + (i*8), 8);

	uint32_t crc = CRC8Maxim(csBuff, 13);
	num_to_bytebits(crc, 8, pyramidBits+120);
	return 1;
}

int CmdPyramidRead(const char *Cmd) {
	CmdLFRead("s");
	getSamples("30000",false);
	return CmdFSKdemodPyramid("");
}

int CmdPyramidClone(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_pyramid_clone();

	uint32_t facilitycode=0, cardnumber=0, fc = 0, cn = 0;
	uint32_t blocks[5];
	uint8_t i;
	uint8_t bs[128];
	memset(bs, 0x00, sizeof(bs));

	if (sscanf(Cmd, "%u %u", &fc, &cn ) != 2) return usage_lf_pyramid_clone();

	facilitycode = (fc & 0x000000FF);
	cardnumber = (cn & 0x0000FFFF);
	
	if ( !GetPyramidBits(facilitycode, cardnumber, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	//Pyramid - compat mode, FSK2a, data rate 50, 4 data blocks
	blocks[0] = T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_50 | 4<<T55x7_MAXBLOCK_SHIFT;

	if (param_getchar(Cmd, 3) == 'Q' || param_getchar(Cmd, 3) == 'q')
		//t5555 (Q5) BITRATE = (RF-2)/2 (iceman)
		blocks[0] = T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | 50<<T5555_BITRATE_SHIFT | 4<<T5555_MAXBLOCK_SHIFT;

	blocks[1] = bytebits_to_byte(bs,32);
	blocks[2] = bytebits_to_byte(bs+32,32);
	blocks[3] = bytebits_to_byte(bs+64,32);
	blocks[4] = bytebits_to_byte(bs+96,32);

	PrintAndLog("Preparing to clone Farpointe/Pyramid to T55x7 with Facility Code: %u, Card Number: %u", facilitycode, cardnumber);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	for ( i = 0; i<5; ++i )
		PrintAndLog(" %02d | %08" PRIx32, i, blocks[i]);

	UsbCommand resp;
	UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	for ( i = 0; i<5; ++i ) {
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

int CmdPyramidSim(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_pyramid_sim();

	uint32_t facilitycode = 0, cardnumber = 0, fc = 0, cn = 0;
	
	uint8_t bs[128];
	size_t size = sizeof(bs);
	memset(bs, 0x00, size);
	
	// Pyramid uses:  fcHigh: 10, fcLow: 8, clk: 50, invert: 0
	uint64_t arg1, arg2;
	arg1 = (10 << 8) + 8;
	arg2 = 50 | 0;

	if (sscanf(Cmd, "%u %u", &fc, &cn ) != 2) return usage_lf_pyramid_sim();

	facilitycode = (fc & 0x000000FF);
	cardnumber = (cn & 0x0000FFFF);
	
	if ( !GetPyramidBits(facilitycode, cardnumber, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	PrintAndLog("Simulating Farpointe/Pyramid - Facility Code: %u, CardNumber: %u", facilitycode, cardnumber );
	
	UsbCommand c = {CMD_FSK_SIM_TAG, {arg1, arg2, size}};
	memcpy(c.d.asBytes, bs, size);
	clearCommandBuffer();
	SendCommand(&c);
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
