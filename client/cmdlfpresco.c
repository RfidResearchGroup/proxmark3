//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Presco tag commands
//-----------------------------------------------------------------------------
#include <string.h>
#include <inttypes.h>
#include "cmdlfpresco.h"
static int CmdHelp(const char *Cmd);

int usage_lf_presco_clone(void){
	PrintAndLog("clone a Presco tag to a T55x7 tag.");
	PrintAndLog("Usage: lf presco clone <Card ID - 9 digits> <Q5>");
	PrintAndLog("Options :");
	PrintAndLog("  <Card Number>  : 9 digit presco card number");
	//PrintAndLog("  <Q5>           : specify write to Q5 (t5555 instead of t55x7)");
	PrintAndLog("");
	PrintAndLog("Sample  : lf presco clone 123456789");
	return 0;
}

int usage_lf_presco_sim(void) {
	PrintAndLog("Enables simulation of presco card with specified card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("Per presco format, the card number is 9 digit number and can contain *# chars. Larger values are truncated.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf presco sim <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("  <Card Number>   : 9 digit presco card number");
	PrintAndLog("");
	PrintAndLog("Sample  : lf presco sim 123456789");
	return 0;
}

// calc checksum
int GetWiegandFromPresco(const char *id, uint32_t *sitecode, uint32_t *usercode) {
	
	uint8_t val = 0;
	for (int index =0; index < strlen(id); ++index) {
		
		// Get value from number string.
		if ( id[index] == '*' ) val = 10;
		if ( id[index] == '#')	val = 11;		
		if ( id[index] >= 0x30 && id[index] <= 0x39 )
			val = id[index] - 0x30;
		
		*sitecode += val;
		
		// last digit is only added, not multipled.
		if ( index < strlen(id)-1 ) 
			*sitecode *= 12;
	}
	*usercode = *sitecode % 65536;
	*sitecode /= 16777216;
	return 0;
}

int GetPrescoBits(uint32_t sitecode, uint32_t usercode, uint8_t	*prescoBits) {
	uint8_t pre[66];
	memset(pre, 0, sizeof(pre));
	prescoBits[7]=1;
	num_to_bytebits(26, 8, pre);

	uint8_t wiegand[24];
	num_to_bytebits(sitecode, 8, wiegand);
	num_to_bytebits(usercode, 16, wiegand+8);

	wiegand_add_parity(pre+8, wiegand, 24);
	size_t bitLen = addParity(pre, prescoBits+8, 66, 4, 1);

	if (bitLen != 88) return 0;
	return 1;
}
//see ASKDemod for what args are accepted
int CmdPrescoDemod(const char *Cmd) {
	if (!ASKDemod(Cmd, false, false, 1)) {
		if (g_debugMode) PrintAndLog("ASKDemod failed");
		return 0;
	}
	size_t size = DemodBufferLen;
	//call lfdemod.c demod for Viking
	int ans = PrescoDemod(DemodBuffer, &size);
	if (ans < 0) {
		if (g_debugMode) PrintAndLog("Error Presco_Demod %d", ans);
		return 0;
	}
	//got a good demod
	uint32_t raw1 = bytebits_to_byte(DemodBuffer+ans, 32);
	uint32_t raw2 = bytebits_to_byte(DemodBuffer+ans+32, 32);
	uint32_t cardid = bytebits_to_byte(DemodBuffer+ans+24, 32);
	PrintAndLog("Presco Tag Found: Card ID %08X", cardid);
	PrintAndLog("Raw: %08X%08X", raw1,raw2);
	setDemodBuf(DemodBuffer+ans, 64, 0);
	
	// uint32_t sitecode = 0, usercode = 0;
	// GetWiegandFromPresco(id, &sitecode, &usercode);
	// PrintAndLog8("SiteCode %d  |  UserCode %d", sitecode, usercode);
	
	return 1;
}

//see ASKDemod for what args are accepted
int CmdPrescoRead(const char *Cmd) {
	//	Presco Number: 123456789 --> Sitecode 30 | usercode 8665

	// read lf silently
	CmdLFRead("s");
	// get samples silently
	getSamples("30000",false);
	// demod and output Presco ID	
	return CmdPrescoDemod(Cmd);
}

int CmdPrescoClone(const char *Cmd) {

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_presco_clone();

	uint32_t sitecode=0, usercode=0;
	uint8_t bits[96];
	uint8_t *bs = bits;
	memset(bs,0,sizeof(bits));
	uint32_t blocks[5] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | 4<<T55x7_MAXBLOCK_SHIFT | T55x7_ST_TERMINATOR, 0, 0, 0, 5};
	
	if (param_getchar(Cmd, 3) == 'Q' || param_getchar(Cmd, 3) == 'q')
		blocks[0] = T5555_MODULATION_MANCHESTER | 32<<T5555_BITRATE_SHIFT | 4<<T5555_MAXBLOCK_SHIFT | T5555_ST_TERMINATOR;

	// get wiegand from printed number.
	GetWiegandFromPresco(Cmd, &sitecode, &usercode);
	
	if ((sitecode & 0xFF) != sitecode) {
		sitecode &= 0xFF;
		PrintAndLog("Facility-Code Truncated to 8-bits (Presco): %u", sitecode);
	}

	if ((usercode & 0xFFFF) != usercode) {
		usercode &= 0xFFFF;
		PrintAndLog("Card Number Truncated to 16-bits (Presco): %u", usercode);
	}
	
	if ( !GetPrescoBits(sitecode, usercode, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	

	blocks[1] = bytebits_to_byte(bs,32);
	blocks[2] = bytebits_to_byte(bs+32,32);
	blocks[3] = bytebits_to_byte(bs+64,32);
	blocks[4] = bytebits_to_byte(bs+96,32);

	PrintAndLog("Preparing to clone Presco to T55x7 with SiteCode: %u, UserCode: %u", sitecode, usercode);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	PrintAndLog(" 00 | 0x%08x", blocks[0]);
	PrintAndLog(" 01 | 0x%08x", blocks[1]);
	PrintAndLog(" 02 | 0x%08x", blocks[2]);
	PrintAndLog(" 03 | 0x%08x", blocks[3]);	
	PrintAndLog(" 04 | 0x%08x", blocks[4]);	
	
	// UsbCommand resp;
	// UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	// for (uint8_t i=0; i<5; i++) {
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

int CmdPrescoSim(const char *Cmd) {
	// uint32_t id = 0;
	// uint64_t rawID = 0;
	// uint8_t clk = 32, encoding = 1, separator = 0, invert = 0;

	// char cmdp = param_getchar(Cmd, 0);
	// if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_presco_sim();

	// id = param_get32ex(Cmd, 0, 0, 16);
	// if (id == 0) return usage_lf_presco_sim();

	//rawID = getVikingBits(id);

	// uint16_t arg1, arg2;
	// size_t size = 64;
	// arg1 = clk << 8 | encoding;
	// arg2 = invert << 8 | separator;

	// PrintAndLog("Simulating - ID: %08X, Raw: %08X%08X",id,(uint32_t)(rawID >> 32),(uint32_t) (rawID & 0xFFFFFFFF));
	
	// UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
	// num_to_bytebits(rawID, size, c.d.asBytes);
	// clearCommandBuffer();
	// SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
    {"help",	CmdHelp,		1, "This help"},
	{"read",	CmdPrescoRead,  0, "Attempt to read and Extract tag data"},
	{"clone",	CmdPrescoClone, 0, "<8 digit ID number> clone presco tag"},
//	{"sim",		CmdPrescoSim,   0, "<8 digit ID number> simulate presco tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFPresco(const char *Cmd) {
	clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
