//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Presco tag commands
//-----------------------------------------------------------------------------

#include "cmdlfvisa2000.h"

#define BL0CK1 0x56495332

static int CmdHelp(const char *Cmd);

int usage_lf_visa2k_clone(void){
	PrintAndLog("clone a Visa2000 tag to a T55x7 tag.");
	PrintAndLog("Usage: lf visa2k clone [h] <card ID> <Q5>");
	PrintAndLog("Options:");
	PrintAndLog("      h          : This help");
	PrintAndLog("      <card ID>  : Visa2k card ID");
	PrintAndLog("      <Q5>       : specify write to Q5 (t5555 instead of t55x7)");
	PrintAndLog("");
	PrintAndLog("Sample: lf visa2k clone 112233");
	return 0;
}

int usage_lf_visa2k_sim(void) {
	PrintAndLog("Enables simulation of visa2k card with specified card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf visa2k sim [h] <card ID>");
	PrintAndLog("Options:");
	PrintAndLog("      h          : This help");
	PrintAndLog("      <card ID>  : Visa2k card ID");
	PrintAndLog("");
	PrintAndLog("Sample: lf visa2k sim 112233");
	return 0;
}

static uint8_t visa_chksum( uint32_t id ) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < 32; i += 4)
        sum ^=  (id >> i) & 0xF;
    return sum & 0xF;
}

//see ASKDemod for what args are accepted
int CmdVisa2kDemod(const char *Cmd) {

	// save GraphBuffer - to restore it later	
	save_restoreGB(1);
	
	CmdAskEdgeDetect("");
	
	//ASK / Manchester
	bool st = TRUE;
	if (!ASKDemod_ext("64 0 0", FALSE, FALSE, 1, &st)) {
		if (g_debugMode) PrintAndLog("DEBUG: Error - Visa2k: ASK/Manchester Demod failed");
		save_restoreGB(0);
		return 0;
	}
	size_t size = DemodBufferLen;
	int ans = Visa2kDemod_AM(DemodBuffer, &size);
	if (ans < 0){
		if (g_debugMode){
			if (ans == -1)
				PrintAndLog("DEBUG: Error - Visa2k: too few bits found");
			else if (ans == -2)
				PrintAndLog("DEBUG: Error - Visa2k: preamble not found");
			else if (ans == -3)
				PrintAndLog("DEBUG: Error - Visa2k: Size not correct: %d", size);
			else
				PrintAndLog("DEBUG: Error - Visa2k: ans: %d", ans);
		}
		save_restoreGB(0);
		return 0;
	}
	setDemodBuf(DemodBuffer, 96, ans);
	
	//got a good demod
	uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
	uint32_t raw2 = bytebits_to_byte(DemodBuffer+32, 32);
	uint32_t raw3 = bytebits_to_byte(DemodBuffer+64, 32);

	// chksum
	uint8_t calc = visa_chksum(raw2);
	uint8_t chk = raw3 & 0xF;	
	// test checksums
	if ( chk != calc ) { 
		printf("DEBUG: error: Visa2000 checksum failed %x - %x\n", chk, calc);
		save_restoreGB(0);
		return 0;
	}
	PrintAndLog("Visa2000 Tag Found: Card ID %u,  Raw: %08X%08X%08X", raw2,  raw1 ,raw2, raw3);
	save_restoreGB(0);
	return 1;
}

int CmdVisa2kRead(const char *Cmd) {
	CmdLFRead("s");
	getSamples("20000",TRUE);
	return CmdVisa2kDemod(Cmd);
}

int CmdVisa2kClone(const char *Cmd) {

	uint64_t id = 0;
	uint32_t blocks[4] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_64 | T55x7_ST_TERMINATOR |3<<T55x7_MAXBLOCK_SHIFT, BL0CK1, 0};

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_visa2k_clone();

	id = param_get32ex(Cmd, 0, 0, 10);
	
	//Q5
	if (param_getchar(Cmd, 1) == 'Q' || param_getchar(Cmd, 1) == 'q') {
		//t5555 (Q5) BITRATE = (RF-2)/2 (iceman)
		blocks[0] = T5555_MODULATION_MANCHESTER | 64<<T5555_BITRATE_SHIFT | T5555_ST_TERMINATOR | 3<<T5555_MAXBLOCK_SHIFT;
	}
	
	// 
	blocks[2] = id;
	blocks[3] = visa_chksum(id);

	PrintAndLog("Preparing to clone Visa2000 to T55x7 with CardId: %u", id);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	for(int i = 0; i<4; ++i)
		PrintAndLog(" %02d | 0x%08x", i , blocks[i]);
	
	UsbCommand resp;
	UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	for (int i = 3; i >= 0; --i) {
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

int CmdVisa2kSim(const char *Cmd) {

	uint32_t id = 0;
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_visa2k_sim();

	id = param_get32ex(Cmd, 0, 0, 10);

	uint8_t clk = 64, encoding = 1, separator = 1, invert = 0;
	uint16_t arg1, arg2;
	size_t size = 96;
	arg1 = clk << 8 | encoding;
	arg2 = invert << 8 | separator;

	PrintAndLog("Simulating Visa2000 - CardId: %u", id);

	UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};

	uint32_t blocks[3] = { BL0CK1, id,  visa_chksum(id) };

	for(int i=0; i<3; ++i)
		num_to_bytebits(blocks[i], 32, c.d.asBytes + i*32);

	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
    {"help",	CmdHelp,		1, "This help"},
	{"read",	CmdVisa2kRead,	0, "Attempt to read and extract tag data"},
	{"clone",	CmdVisa2kClone,	0, "clone Visa2000 tag"},
	{"sim",		CmdVisa2kSim,	0, "simulate Visa2000 tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFVisa2k(const char *Cmd) {
	clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
