//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Viking tag commands
//-----------------------------------------------------------------------------
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdmain.h"
#include "cmdlf.h"
#include "cmdlfviking.h"
#include "lfdemod.h"
static int CmdHelp(const char *Cmd);

int usage_lf_viking_clone(void){
	PrintAndLog("clone a Viking AM tag to a T55x7 tag.");
	PrintAndLog("Usage: lf viking clone <Card ID - 8 hex digits> <Q5>");
	PrintAndLog("Options :");
	PrintAndLog("  <Card Number>  : 8 digit hex viking card number");
	PrintAndLog("  <Q5>           : specify write to Q5 (t5555 instead of t55x7)");
	PrintAndLog("");
	PrintAndLog("Sample  : lf viking clone 1A337 Q5");
	return 0;
}

int usage_lf_viking_sim(void) {
	PrintAndLog("Enables simulation of viking card with specified card number.");
	PrintAndLog("Simulation runs until the button is pressed or another USB command is issued.");
	PrintAndLog("Per viking format, the card number is 8 digit hex number.  Larger values are truncated.");
	PrintAndLog("");
	PrintAndLog("Usage:  lf viking sim <Card-Number>");
	PrintAndLog("Options :");
	PrintAndLog("  <Card Number>   : 8 digit hex viking card number");
	PrintAndLog("");
	PrintAndLog("Sample  : lf viking sim 1A337");
	return 0;
}

// calc checksum
uint64_t getVikingBits(uint32_t id) {
	uint8_t checksum = ((id>>24) & 0xFF) ^ ((id>>16) & 0xFF) ^ ((id>>8) & 0xFF) ^ (id & 0xFF) ^ 0xF2 ^ 0xA8;
	uint64_t ret = (uint64_t)0xF2 << 56;
	ret |= (uint64_t)id << 8;
	ret	|= checksum;
	return ret;
}

//by marshmellow
//see ASKDemod for what args are accepted
int CmdVikingRead(const char *Cmd) {
	// read lf silently
	CmdLFRead("s");
	// get samples silently
	getSamples("30000",false);
	// demod and output viking ID	
	return CmdVikingDemod(Cmd);
}

int CmdVikingClone(const char *Cmd) {
	uint32_t id = 0;
	uint64_t rawID = 0;
	bool Q5 = false;
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_viking_clone();
	
	id = param_get32ex(Cmd, 0, 0, 16);
	if (id == 0) return usage_lf_viking_clone();
	
	cmdp = param_getchar(Cmd, 1);
	if ( cmdp == 'Q' || cmdp == 'q')
		Q5 = true;

	rawID = getVikingBits(id);
	
	PrintAndLog("Cloning - ID: %08X, Raw: %08X%08X",id,(uint32_t)(rawID >> 32),(uint32_t) (rawID & 0xFFFFFFFF));
	UsbCommand c = {CMD_VIKING_CLONE_TAG,{rawID >> 32, rawID & 0xFFFFFFFF, Q5}};
	clearCommandBuffer();
    SendCommand(&c);
	//check for ACK
	WaitForResponse(CMD_ACK,NULL);
    return 0;
}

int CmdVikingSim(const char *Cmd) {
	uint32_t id = 0;
	uint64_t rawID = 0;
	uint8_t clk = 32, encoding = 1, separator = 0, invert = 0;

	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_viking_sim();

	id = param_get32ex(Cmd, 0, 0, 16);
	if (id == 0) return usage_lf_viking_sim();

	rawID = getVikingBits(id);

	uint16_t arg1, arg2;
	size_t size = 64;
	arg1 = clk << 8 | encoding;
	arg2 = invert << 8 | separator;

	PrintAndLog("Simulating - ID: %08X, Raw: %08X%08X",id,(uint32_t)(rawID >> 32),(uint32_t) (rawID & 0xFFFFFFFF));
	
	UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
	num_to_bytebits(rawID, size, c.d.asBytes);
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
    {"help",	CmdHelp,		1, "This help"},
	{"read",	CmdVikingRead,  0, "Attempt to read and Extract tag data"},
	{"clone",	CmdVikingClone, 0, "<8 digit ID number> clone viking tag"},
	{"sim",		CmdVikingSim,   0, "<8 digit ID number> simulate viking tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFViking(const char *Cmd) {
	clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
