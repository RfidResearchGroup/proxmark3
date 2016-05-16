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
	PrintAndLog("Usage: lf presco clone d <Card-ID> H <hex-ID> <Q5>");
	PrintAndLog("Options :");
	PrintAndLog("  d <Card-ID>   : 9 digit presco card ID");
	PrintAndLog("  H <hex-ID>    : 8 digit hex card number");
	PrintAndLog("  <Q5>          : specify write to Q5 (t5555 instead of t55x7)");
	PrintAndLog("");
	PrintAndLog("Sample  : lf presco clone d 123456789");
	return 0;
}

int usage_lf_presco_sim(void) {
	PrintAndLog("Enables simulation of presco card with specified card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("Per presco format, the card number is 9 digit number and can contain *# chars. Larger values are truncated.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf presco sim d <Card-ID> or H <hex-ID>");
	PrintAndLog("Options :");
	PrintAndLog("  d <Card-ID>   : 9 digit presco card number");
	PrintAndLog("  H <hex-ID>    : 8 digit hex card number");
	PrintAndLog("");
	PrintAndLog("Sample  : lf presco sim d 123456789");
	return 0;
}

// convert base 12 ID to sitecode & usercode & 8 bit other unknown code
int GetWiegandFromPresco(const char *Cmd, uint32_t *sitecode, uint32_t *usercode, uint32_t *fullcode, bool *Q5) {
	
	uint8_t val = 0;
	bool hex = false, errors = false;
	uint8_t cmdp = 0;
	char id[11];
	int stringlen = 0;
	memset(id, 0x00, sizeof(id));
	
	while(param_getchar(Cmd, cmdp) != 0x00) {
		switch(param_getchar(Cmd, cmdp)) {
			case 'h':
				return -1;
			case 'H':
				hex = true;
				//get hex
				*fullcode = param_get32ex(Cmd, cmdp+1, 0, 10);
				cmdp+=2;
				break;
			case 'P':
			case 'p':
				//param get string int param_getstr(const char *line, int paramnum, char * str)
				stringlen = param_getstr(Cmd, cmdp+1, id);
				if (stringlen < 2) return -1;
				cmdp+=2;
				break;
			case 'Q':
			case 'q':
				*Q5 = true;
				cmdp++;
				break;
			default:
				PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = 1;
				break;
		}
		if(errors) break;
	}
	// No args
	if(cmdp == 0) errors = 1;

	//Validations
	if(errors) return -1;

	if (!hex) {
		for (int index =0; index < strlen(id); ++index) {
		
			// Get value from number string.
			if ( id[index] == '*' ) val = 10;
			if ( id[index] == '#')	val = 11;		
			if ( id[index] >= 0x30 && id[index] <= 0x39 )
				val = id[index] - 0x30;
			
				*fullcode += val;
			
			// last digit is only added, not multipled.
			if ( index < strlen(id)-1 ) 
					*fullcode *= 12;
		}
	}

	*usercode = *fullcode & 0x0000FFFF; //% 65566
	*sitecode = (*fullcode >> 24) & 0x000000FF;  // /= 16777216;
	return 0;
}

// calc not certain - intended to get bitstream for programming / sim
int GetPrescoBits(uint32_t fullcode, uint8_t *prescoBits) {
	num_to_bytebits(0x10D00000, 32, prescoBits);
	num_to_bytebits(0x00000000, 32, prescoBits+32);
	num_to_bytebits(0x00000000, 32, prescoBits+64);
	num_to_bytebits(fullcode  , 32, prescoBits+96);
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
	uint32_t raw3 = bytebits_to_byte(DemodBuffer+ans+64, 32);
	uint32_t raw4 = bytebits_to_byte(DemodBuffer+ans+96, 32);
	uint32_t cardid = raw4;
	PrintAndLog("Presco Tag Found: Card ID %08X", cardid);
	PrintAndLog("Raw: %08X%08X%08X%08X", raw1,raw2,raw3,raw4);
	setDemodBuf(DemodBuffer+ans, 128, 0);
	
	uint32_t sitecode = 0, usercode = 0, fullcode = 0;
	bool Q5=false;
	char cmd[12] = {0};
	sprintf(cmd, "H %08X", cardid);
	GetWiegandFromPresco(cmd, &sitecode, &usercode, &fullcode, &Q5);
	PrintAndLog("SiteCode %u, UserCode %u, FullCode, %08X", sitecode, usercode, fullcode);
	
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

// takes base 12 ID converts to hex
// Or takes 8 digit hex ID
int CmdPrescoClone(const char *Cmd) {

	bool Q5 = false;
	uint32_t sitecode=0, usercode=0, fullcode=0;
	uint32_t blocks[5] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | 4<<T55x7_MAXBLOCK_SHIFT | T55x7_ST_TERMINATOR, 0, 0, 0, 5};
	
	// get wiegand from printed number.
	if (GetWiegandFromPresco(Cmd, &sitecode, &usercode, &fullcode, &Q5) == -1) return usage_lf_presco_clone();

	if (Q5)
		//t5555 (Q5) BITRATE = (RF-2)/2 (iceman)
		blocks[0] = T5555_MODULATION_MANCHESTER | 32<<T5555_BITRATE_SHIFT | 4<<T5555_MAXBLOCK_SHIFT | T5555_ST_TERMINATOR;

	if ((sitecode & 0xFF) != sitecode) {
		sitecode &= 0xFF;
		PrintAndLog("Facility-Code Truncated to 8-bits (Presco): %u", sitecode);
	}

	if ((usercode & 0xFFFF) != usercode) {
		usercode &= 0xFFFF;
		PrintAndLog("Card Number Truncated to 16-bits (Presco): %u", usercode);
	}
	
	blocks[1] = 0x10D00000; //preamble
	blocks[2] = 0x00000000;
	blocks[3] = 0x00000000;
	blocks[4] = fullcode;

	PrintAndLog("Preparing to clone Presco to T55x7 with SiteCode: %u, UserCode: %u, FullCode: %08x", sitecode, usercode, fullcode);
	PrintAndLog("Blk | Data ");
	PrintAndLog("----+------------");
	PrintAndLog(" 00 | 0x%08x", blocks[0]);
	PrintAndLog(" 01 | 0x%08x", blocks[1]);
	PrintAndLog(" 02 | 0x%08x", blocks[2]);
	PrintAndLog(" 03 | 0x%08x", blocks[3]);	
	PrintAndLog(" 04 | 0x%08x", blocks[4]);	
	
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

// takes base 12 ID converts to hex
// Or takes 8 digit hex ID
int CmdPrescoSim(const char *Cmd) {
	uint32_t sitecode=0, usercode=0, fullcode=0;
	bool Q5=false;
	// get wiegand from printed number.
	if (GetWiegandFromPresco(Cmd, &sitecode, &usercode, &fullcode, &Q5) == -1) return usage_lf_presco_sim();

	uint8_t clk = 32, encoding = 1, separator = 1, invert = 0;
	uint16_t arg1, arg2;
	size_t size = 128;
	arg1 = clk << 8 | encoding;
	arg2 = invert << 8 | separator;

	PrintAndLog("Simulating Presco - SiteCode: %u, UserCode: %u, FullCode: %08X",sitecode, usercode, fullcode);

	UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
	GetPrescoBits(fullcode, c.d.asBytes);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
    {"help",	CmdHelp,		1, "This help"},
	{"read",	CmdPrescoRead,  0, "Attempt to read and Extract tag data"},
	{"clone", CmdPrescoClone, 0, "d <9 digit ID> or h <hex> [Q5] clone presco tag"},
	{"sim",   CmdPrescoSim,   0, "d <9 digit ID> or h <hex> simulate presco tag"},
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
