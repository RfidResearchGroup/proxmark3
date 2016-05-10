//-----------------------------------------------------------------------------
// Copyright (C) 2016 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Analyse bytes commands
//-----------------------------------------------------------------------------
#include "cmdanalyse.h"

static int CmdHelp(const char *Cmd);

int usage_analyse_lcr(void) {
	PrintAndLog("Specifying the bytes of a UID with a known LRC will find the last byte value");
	PrintAndLog("needed to generate that LRC with a rolling XOR. All bytes should be specified in HEX.");
	PrintAndLog("");
	PrintAndLog("Usage:  analyse lcr [h] <bytes>");
	PrintAndLog("Options:");
	PrintAndLog("           h          This help");
	PrintAndLog("           <bytes>    bytes to calc missing XOR in a LCR");
	PrintAndLog("");
	PrintAndLog("Samples:");
	PrintAndLog("           analyse lcr 04008064BA");
	PrintAndLog("expected output: Target (BA) requires final LRC XOR byte value: 5A");
	return 0;
}
static uint8_t calculateLRC( uint8_t* bytes, uint8_t len) {
    uint8_t LRC = 0;
    for (uint8_t i = 0; i < len; i++)
        LRC ^= bytes[i];
    return LRC;
}
	
int CmdAnalyseLCR(const char *Cmd) {
	uint8_t data[50];
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0|| cmdp == 'h' || cmdp == 'H') return usage_analyse_lcr();
	
	int len = 0;
	param_gethex_ex(Cmd, 0, data, &len);
	if ( len%2 ) return usage_analyse_lcr();
	len >>= 1;	
	uint8_t finalXor = calculateLRC(data, len);
	PrintAndLog("Target [%02X] requires final LRC XOR byte value: 0x%02X",data[len-1] ,finalXor);
	return 0;
}

static command_t CommandTable[] = {
	{"help",            CmdHelp,            1, "This help"},
	{"lcr",				CmdAnalyseLCR,		0, "Generate final byte for XOR LRC"},
	{NULL, NULL, 0, NULL}
};

int CmdAnalyse(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
