//-----------------------------------------------------------------------------
// Authored by Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency COTAG commands
//-----------------------------------------------------------------------------
#include "cmdlfcotag.h"  // COTAG function declarations
 
static int CmdHelp(const char *Cmd);

int usage_lf_cotag_read(void){
	PrintAndLog("Usage: lf COTAG read [h] <signaldata>");
	PrintAndLog("Options:");
	PrintAndLog("      h          : This help");
	PrintAndLog("      <0|1|2>    : 0 - HIGH/LOW signal; maxlength bigbuff");
	PrintAndLog("                 : 1 - translation of HI/LO into bytes with manchester 0,1");
	PrintAndLog("                 : 2 - raw signal; maxlength bigbuff");
	PrintAndLog("");
	PrintAndLog("Sample:");
	PrintAndLog("        lf cotag read 0");
	PrintAndLog("        lf cotag read 1");
	return 0;
}
int CmdCOTAGDemod(const char *Cmd) {
	return 0;
}

// When reading a COTAG.
// 0 = HIGH/LOW signal - maxlength bigbuff
// 1 = translation for HI/LO into bytes with manchester 0,1 - length 300
// 2 = raw signal -  maxlength bigbuff		
int CmdCOTAGRead(const char *Cmd) {
	
	if (Cmd[0] == 'h' || Cmd[0] == 'H') return usage_lf_cotag_read();
	
	uint8_t bits[320] = {0};
	uint32_t rawsignal = 0;
	sscanf(Cmd, "%u", &rawsignal);
 
	UsbCommand c = {CMD_COTAG, {rawsignal, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	if ( !WaitForResponseTimeout(CMD_ACK, NULL, 7000) ) {
		PrintAndLog("command execution time out");
		return 1;	
	}
	
	switch ( rawsignal ){
		case 0: 
		case 2: {
			CmdPlot("");
			CmdGrid("384");
			getSamples("", true); break;
		}
		case 1: {
			GetFromBigBuf(bits, sizeof(bits), 0);
			UsbCommand response;
			if ( !WaitForResponseTimeout(CMD_ACK, &response, 500) ) {
					PrintAndLog("timeout while waiting for reply.");
					return 1;
			}
			
			size_t size = sizeof(bits);
			int err = manrawdecode(bits, &size, 1);
			if (err){
				PrintAndLog("DEBUG: Error - COTAG too many errors: %d", err);
				return 0;
			}
			PrintAndLog("%s", sprint_bin(bits, size));
			setDemodBuf(bits, sizeof(bits), 0);
			
			// CmdCOTAGDemod();
			break;
		}
	}	
	return 0;
}

static command_t CommandTable[] = {
	{"help",      CmdHelp,         1, "This help"},
	{"demod",     CmdCOTAGDemod,   1, "Tries to decode a COTAG signal"},
	{"read",      CmdCOTAGRead,    0, "Attempt to read and extract tag data"},
	{NULL, NULL, 0, NULL}
};

int CmdLFCOTAG(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
