//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency visa 2000 tag commands
// by iceman
// ASK/Manchester, RF/64, STT, 96 bits (complete)
//-----------------------------------------------------------------------------

#include "cmdlfvisa2000.h"

#define BL0CK1 0x56495332

static int CmdHelp(const char *Cmd);

int usage_lf_visa2k_clone(void){
	PrintAndLogEx(NORMAL, "clone a Visa2000 tag to a T55x7 tag.");
	PrintAndLogEx(NORMAL, "Usage: lf visa2000 clone [h] <card ID> <Q5>");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h          : This help");
	PrintAndLogEx(NORMAL, "      <card ID>  : Visa2k card ID");
	PrintAndLogEx(NORMAL, "      <Q5>       : specify write to Q5 (t5555 instead of t55x7)");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "      lf visa2000 clone 112233");
	return 0;
}

int usage_lf_visa2k_sim(void) {
	PrintAndLogEx(NORMAL, "Enables simulation of visa2k card with specified card number.");
	PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Usage:  lf visa2000 sim [h] <card ID>");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "      h          : This help");
	PrintAndLogEx(NORMAL, "      <card ID>  : Visa2k card ID");
	PrintAndLogEx(NORMAL, "");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "        lf visa2000 sim 112233");
	return 0;
}

static uint8_t visa_chksum( uint32_t id ) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < 32; i += 4)
        sum ^=  (id >> i) & 0xF;
    return sum & 0xF;
}

static uint8_t visa_parity( uint32_t id) {
	// 4bit parity LUT
	uint8_t par_lut[] = {
		0,1,1,0
		,1,0,0,1
		,1,0,0,1
		,0,1,1,0
	};	
	uint8_t par = 0;
	par |= par_lut[ (id >> 28) & 0xF ] << 7;
	par |= par_lut[ (id >> 24) & 0xF ] << 6;
	par |= par_lut[ (id >> 20) & 0xF ] << 5;
	par |= par_lut[ (id >> 16) & 0xF ] << 4;
	par |= par_lut[ (id >> 12) & 0xF ] << 3;
	par |= par_lut[ (id >>  8) & 0xF ] << 2;
	par |= par_lut[ (id >>  4) & 0xF ] << 1;
	par |= par_lut[ (id & 0xF) ];
	return par;	
}

// by iceman
// find Visa2000 preamble in already demoded data
int detectVisa2k(uint8_t *dest, size_t *size) {
	if (*size < 96) return -1; //make sure buffer has data
	size_t startIdx = 0;
	uint8_t preamble[] = {0,1,0,1,0,1,1,0,0,1,0,0,1,0,0,1,0,1,0,1,0,0,1,1,0,0,1,1,0,0,1,0};
	if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
		return -2; //preamble not found
	if (*size != 96) return -3; //wrong demoded size
	//return start position
	return (int)startIdx;
}

/**
*
* 56495332 00096ebd 00000077 —> tag id 618173
* aaaaaaaa iiiiiiii -----ppc
*
* a = fixed value  ascii 'VIS2'
* i = card id
* p = even parity bit for each nibble in card id.
* c = checksum  (xor of card id)
* 
**/
//see ASKDemod for what args are accepted
int CmdVisa2kDemod(const char *Cmd) {

	// save GraphBuffer - to restore it later	
	save_restoreGB(1);
	
	//sCmdAskEdgeDetect("");
	
	//ASK / Manchester
	bool st = true;
	if (!ASKDemod_ext("64 0 0", false, false, 1, &st)) {
		PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: ASK/Manchester Demod failed");
		save_restoreGB(0);
		return 0;
	}
	size_t size = DemodBufferLen;
	int ans = detectVisa2k(DemodBuffer, &size);
	if (ans < 0){
		if (ans == -1)
			PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: too few bits found");
		else if (ans == -2)
			PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: preamble not found");
		else if (ans == -3)
			PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: Size not correct: %d", size);
		else
			PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: ans: %d", ans);

		save_restoreGB(0);
		return 0;
	}
	setDemodBuf(DemodBuffer, 96, ans);
	setClockGrid(g_DemodClock, g_DemodStartIdx + (ans*g_DemodClock));
		
	//got a good demod
	uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
	uint32_t raw2 = bytebits_to_byte(DemodBuffer+32, 32);
	uint32_t raw3 = bytebits_to_byte(DemodBuffer+64, 32);
	
	// chksum
	uint8_t calc = visa_chksum(raw2);
	uint8_t chk = raw3 & 0xF;	
		
	// test checksums
	if ( chk != calc ) { 
		PrintAndLogEx(DEBUG, "DEBUG: error: Visa2000 checksum failed %x - %x\n", chk, calc);
		save_restoreGB(0);
		return 0;
	}
	// parity
	uint8_t calc_par = visa_parity(raw2);
	uint8_t chk_par = (raw3 & 0xFF0) >> 4;
	if ( calc_par != chk_par) {
		PrintAndLogEx(DEBUG, "DEBUG: error: Visa2000 parity failed %x - %x\n", chk_par, calc_par);
		save_restoreGB(0);
		return 0;		
	}
	PrintAndLogEx(SUCCESS, "Visa2000 Tag Found: Card ID %u,  Raw: %08X%08X%08X", raw2,  raw1 ,raw2, raw3);
	save_restoreGB(0);
	return 1;
}

// 64*96*2=12288 samples just in case we just missed the first preamble we can still catch 2 of them
int CmdVisa2kRead(const char *Cmd) {
	lf_read(true, 12500);
	return CmdVisa2kDemod(Cmd);
}

int CmdVisa2kClone(const char *Cmd) {

	uint64_t id = 0;
	uint32_t blocks[4] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_64 | T55x7_ST_TERMINATOR | 3 << T55x7_MAXBLOCK_SHIFT, BL0CK1, 0};

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_visa2k_clone();

	id = param_get32ex(Cmd, 0, 0, 10);
	
	//Q5
	if (param_getchar(Cmd, 1) == 'Q' || param_getchar(Cmd, 1) == 'q')
		blocks[0] = T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(64) | T5555_ST_TERMINATOR | 3 << T5555_MAXBLOCK_SHIFT;
	
	blocks[2] = id;
	blocks[3] =  (visa_parity(id) << 4) | visa_chksum(id);	

	PrintAndLogEx(INFO, "Preparing to clone Visa2000 to T55x7 with CardId: %u", id);
	print_blocks(blocks, 4);
	
	UsbCommand resp;
	UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0,0,0}};

	for (uint8_t i = 0; i < 4; i++) {
		c.arg[0] = blocks[i];
		c.arg[1] = i;
		clearCommandBuffer();
		SendCommand(&c);
		if (!WaitForResponseTimeout(CMD_ACK, &resp, T55XX_WRITE_TIMEOUT)){
			PrintAndLogEx(WARNING, "Error occurred, device did not respond during write operation.");
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

	PrintAndLogEx(NORMAL, "Simulating Visa2000 - CardId: %u", id);

	UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};

	uint32_t blocks[3] = { BL0CK1, id, (visa_parity(id) << 4) | visa_chksum(id) };

	for(int i = 0; i < 3; ++i)
		num_to_bytebits(blocks[i], 32, c.d.asBytes + i*32);

	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
    {"help",	CmdHelp,		1, "This help"},
	{"demod",	CmdVisa2kDemod,	1, "demodulate an VISA2000 tag from the GraphBuffer"},	
	{"read",	CmdVisa2kRead,	0, "attempt to read and extract tag data from the antenna"},
	{"clone",	CmdVisa2kClone,	0, "clone Visa2000 to t55x7"},
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
