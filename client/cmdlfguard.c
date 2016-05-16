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
	//uint8_t xorKey = rand() % 0xFF;
	uint8_t xorKey = 0x66;
	uint8_t i;
	
	
	uint8_t pre[96];
	memset(pre, 0x00, sizeof(pre));

	// Get 26 wiegand from FacilityCode, CardNumber	
	uint8_t wiegand[24];
	memset(wiegand, 0x00, sizeof(wiegand));
	num_to_bytebits(fc, 8, wiegand);
	num_to_bytebits(cn, 16, wiegand+8);

	// add wiegand parity bits (dest, source, len)
	wiegand_add_parity(pre, wiegand, 24);

	// lets start. 12bytes of data to be produced.
	uint8_t rawbytes[12];
	memset(rawbytes, 0x00, sizeof(rawbytes));

	// xor key
	rawbytes[0] = xorKey;

	// add format length (decimal)
	// len | hex | bin
	//  26 | 1A  | 0001 1010
	rawbytes[1] = (26 << 2);
	//  36 | 24  | 0010 0100
	//rawbytes[1] = (36 << 2);
	//  40 | 28  | 0010 1000
	//rawbytes[1] = (40 << 2);
	
	// 2bit checksum, unknown today, 
	// these two bits are the last ones of rawbyte[1], hence the LSHIFT above.
	rawbytes[2] = 1;
	rawbytes[3] = 0;
	
	// add wiegand to rawbytes
	for (i = 0; i < 4; ++i)
		rawbytes[i+4] = bytebits_to_byte( pre + (i*8), 8);
	
	if (g_debugMode) printf(" WIE | %s\n", sprint_hex(rawbytes, sizeof(rawbytes)));	
	
	// XOR (only works on wiegand stuff)
	for (i = 1; i < 12; ++i)
		rawbytes[i] ^= xorKey ;
	
	if (g_debugMode) printf(" XOR | %s \n", sprint_hex(rawbytes, sizeof(rawbytes)));

	// convert rawbytes to bits in pre
	for (i = 0; i < 12; ++i)
		num_to_bytebitsLSBF( rawbytes[i], 8, pre + (i*8));

	if (g_debugMode) printf("\n Raw | %s \n", sprint_hex(rawbytes, sizeof(rawbytes)));
	if (g_debugMode) printf(" Raw | %s\n", sprint_bin(pre, 64) );
	
	// add spacer bit 0 every 4 bits, starting with index 0,
	// 12 bytes, 24 nibbles.  24+1 extra bites. 3bytes.  ie 9bytes | 1byte xorkey, 8bytes rawdata (64bits, should be enough for a 40bit wiegand)
	addParity(pre, guardBits+6, 64, 5, 3);

	// preamble
	guardBits[0] = 1;
	guardBits[1] = 1;
	guardBits[2] = 1;
	guardBits[3] = 1;
	guardBits[4] = 1;
	guardBits[5] = 0;
	
	if (g_debugMode) printf(" FIN | %s\n", sprint_bin(guardBits, 96) );
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
	//t5555 (Q5) BITRATE = (RF-2)/2 (iceman)
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

	UsbCommand resp;
	UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	for ( i = 0; i<4; ++i ) {
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

int CmdGuardSim(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_guard_sim();

	uint32_t facilitycode = 0, cardnumber = 0, fc = 0, cn = 0;
	uint8_t clock = 64, encoding = 2, separator = 0, invert = 0;
	
	uint8_t bs[96];
	memset(bs, 0x00, sizeof(bs));
	
	if (sscanf(Cmd, "%u %u", &fc, &cn ) != 2) return usage_lf_guard_sim();

	facilitycode = (fc & 0x000000FF);
	cardnumber = (cn & 0x0000FFFF);
	
	if ( !GetGuardBits(facilitycode, cardnumber, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	PrintAndLog("Simulating Guardall - Facility Code: %u, CardNumber: %u", facilitycode, cardnumber );

	// Guard uses:  clk: 64, invert: 0, encoding: 2 (ASK Biphase)
	uint64_t arg1, arg2;
	arg1 = (clock << 8) | encoding;
	arg2 = (invert << 8) | separator;

	uint8_t rawbytes[12];
	size_t size = sizeof(rawbytes);
	for (uint8_t i=0; i < size; ++i){
		rawbytes[i] =  bytebits_to_byte( bs + (i*8), 8);
	}

	UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
	memcpy(c.d.asBytes, rawbytes, size );
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
