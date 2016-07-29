//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Presco tag commands
//-----------------------------------------------------------------------------
#include "cmdlfjablotron.h"

static int CmdHelp(const char *Cmd);

int usage_lf_jablotron_clone(void){
	PrintAndLog("clone a Jablotron tag to a T55x7 tag.");
	PrintAndLog("Usage: lf jablotron clone [h] <card ID> <Q5>");
	PrintAndLog("Options:");
	PrintAndLog("      h          : This help");
	PrintAndLog("      <card ID>  : jablotron card ID");
	PrintAndLog("      <Q5>       : specify write to Q5 (t5555 instead of t55x7)");
	PrintAndLog("");
	PrintAndLog("Sample: lf jablotron clone d 112233");
	return 0;
}

int usage_lf_jablotron_sim(void) {
	PrintAndLog("Enables simulation of jablotron card with specified card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf jablotron sim [h] <card ID>");
	PrintAndLog("Options:");
	PrintAndLog("      h          : This help");
	PrintAndLog("      <card ID>  : jablotron card ID");
	PrintAndLog("");
	PrintAndLog("Sample: lf jablotron sim d 112233");
	return 0;
}

int getJablotronBits(uint64_t fullcode, uint8_t *bits) {	
	//preamp
	num_to_bytebits(0xFFFF, 16, bits);

	//fullcode
	num_to_bytebits(fullcode, 40, bits+16);

	//chksum byte
	uint8_t crc = 0;
	for (int i=16; i < 56; i += 8) {
		crc += bytebits_to_byte(bits+i,8);
	}
	crc ^= 0x3A;
	num_to_bytebits(crc, 8, bits+56);
		
	return 1;
}

//see ASKDemod for what args are accepted
int CmdJablotronDemod(const char *Cmd) {

	//Differential Biphase / di-phase (inverted biphase)
	//get binary from ask wave
	if (!ASKbiphaseDemod("0 64 1 0", FALSE)) {
		if (g_debugMode) PrintAndLog("Error Jablotron: ASKbiphaseDemod failed");
		return 0;
	}
	size_t size = DemodBufferLen;
	int ans = JablotronDemod(DemodBuffer, &size);
	if (ans < 0){
		if (g_debugMode){
			// if (ans == -5)
				// PrintAndLog("DEBUG: Error - not enough samples");
			// else if (ans == -1)
				// PrintAndLog("DEBUG: Error - only noise found");
			// else if (ans == -2)
				// PrintAndLog("DEBUG: Error - problem during ASK/Biphase demod");
			if (ans == -3)
				PrintAndLog("DEBUG: Error - Size not correct: %d", size);
			else if (ans == -4)
				PrintAndLog("DEBUG: Error - Jablotron preamble not found");
			else
				PrintAndLog("DEBUG: Error - ans: %d", ans);
		}
		return 0;
	}
	//got a good demod
	uint32_t raw1 = bytebits_to_byte(DemodBuffer+ans, 32);
	uint32_t raw2 = bytebits_to_byte(DemodBuffer+ans+32, 32);
	uint64_t cardid = (raw1 & 0x0000FFFF);
	cardid <<= 32;
	cardid |= (raw2 >> 8);
	
	PrintAndLog("Jablotron Tag Found: Card ID %012X", cardid);
	PrintAndLog("Raw: %08X%08X", raw1 ,raw2);

	setDemodBuf(DemodBuffer+ans, 64, 0);
	
	//PrintAndLog("1410-%u-%u-%08X-%02X", fullcode);	
	return 1;
}

int CmdJablotronRead(const char *Cmd) {
	CmdLFRead("s");
	getSamples("30000",false);
	return CmdJablotronDemod(Cmd);
}

int CmdJablotronClone(const char *Cmd) {

	uint64_t fullcode = 0;
	uint32_t blocks[3] = {T55x7_MODULATION_DIPHASE | T55x7_BITRATE_RF_64 | 2<<T55x7_MAXBLOCK_SHIFT, 0, 0};

	uint8_t bits[64];
	uint8_t *bs = bits;
	memset(bs, 0, sizeof(bits));
	
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_jablotron_clone();

	fullcode = param_get64ex(Cmd, 0, 0, 16);
	
	//Q5
	if (param_getchar(Cmd, 1) == 'Q' || param_getchar(Cmd, 1) == 'q') {
		//t5555 (Q5) BITRATE = (RF-2)/2 (iceman)
		blocks[0] = T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | 64<<T5555_BITRATE_SHIFT | 2<<T5555_MAXBLOCK_SHIFT;
	}
	
	if ((fullcode & 0xFFFFFFFFFFFF) != fullcode) {
		fullcode &= 0xFFFFFFFFFFFF;
		PrintAndLog("Card Number Truncated to 40-bits: %u", fullcode);
	}

	if ( !getJablotronBits(fullcode, bs)) {
		PrintAndLog("Error with tag bitstream generation.");
		return 1;
	}	
	
	// 
	blocks[1] = bytebits_to_byte(bs,32);
	blocks[2] = bytebits_to_byte(bs+32,32);

	PrintAndLog("Preparing to clone Jablotron to T55x7 with FullCode: %012X", fullcode);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	PrintAndLog(" 00 | 0x%08x", blocks[0]);
	PrintAndLog(" 01 | 0x%08x", blocks[1]);
	PrintAndLog(" 02 | 0x%08x", blocks[2]);
	
	UsbCommand resp;
	UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	for (int i=4; i>=0; i--) {
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

int CmdJablotronSim(const char *Cmd) {
	uint64_t fullcode = 0;

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_jablotron_sim();

	fullcode = param_get64ex(Cmd, 0, 0, 16);
	
	uint8_t clk = 64, encoding = 2, separator = 0, invert = 1;
	uint16_t arg1, arg2;
	size_t size = 64;
	arg1 = clk << 8 | encoding;
	arg2 = invert << 8 | separator;

	PrintAndLog("Simulating Jablotron - FullCode: %012X", fullcode);

	UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
	getJablotronBits(fullcode, c.d.asBytes);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
    {"help",	CmdHelp,			1, "This help"},
	{"read",	CmdJablotronRead,	0, "Attempt to read and extract tag data"},
	{"clone",	CmdJablotronClone,	0, "clone jablotron tag"},
	{"sim",		CmdJablotronSim,	0, "simulate jablotron tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFJablotron(const char *Cmd) {
	clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
