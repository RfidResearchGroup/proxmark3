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

int CmdCOTAGRead(const char *Cmd) {

//	if (Cmd[0] == 'h' || Cmd[0] == 'H') return usage_lf_cotag_read();

	UsbCommand c = {CMD_COTAG, {0, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);

	getSamples("20000", TRUE);
	return CmdFSKdemodAWID(Cmd);
}

static command_t CommandTable[] = {
	{"help",      CmdHelp,         1, "This help"},
	{"read",      CmdCOTAGRead,     0, "Attempt to read and extract tag data"},
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
