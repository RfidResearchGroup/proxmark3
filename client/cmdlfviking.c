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
	PrintAndLog("Usage: lf viking clone <Card ID 16 bytes of hex number>");
	return 0;
}

//by marshmellow
//see ASKDemod for what args are accepted
int CmdVikingDemod(const char *Cmd)
{
	CmdLFRead("s");
	getSamples("30000",false);
	
 	if (!ASKDemod(Cmd, false, false, 1)) {
		if (g_debugMode) PrintAndLog("ASKDemod failed");
		return 0;
	}
	size_t size = DemodBufferLen;

	int ans = VikingDemod_AM(DemodBuffer, &size);
	if (ans < 0) {
		if (g_debugMode) PrintAndLog("Error Viking_Demod");
		return 0;
	}
	//got a good demod
	uint32_t raw1 = bytebits_to_byte(DemodBuffer+ans, 32);
	uint32_t raw2 = bytebits_to_byte(DemodBuffer+ans+32, 32);
	uint32_t cardid = bytebits_to_byte(DemodBuffer+ans+24, 32);
	uint8_t checksum = bytebits_to_byte(DemodBuffer+ans+32+24, 8);
	PrintAndLog("Viking Tag Found: Card ID %08X, Checksum: %02X", cardid, checksum);
	PrintAndLog("Raw: %08X%08X", raw1,raw2);
	setDemodBuf(DemodBuffer+ans, 64, 0);
	return 1;
}

int CmdVikingClone(const char *Cmd)
{
    uint32_t b1,b2;
    // get the tag number 64 bits (8 bytes) in hex
    uint8_t id[8];
 
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) < 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_viking_clone();
	
	if (param_gethex(Cmd, 0, id, 16) == 1)
		return usage_lf_viking_clone();
	
    b1 = bytes_to_num(id, sizeof(uint32_t));
    b2 = bytes_to_num(id + sizeof(uint32_t), sizeof(uint32_t));
    UsbCommand c = {CMD_VIKING_CLONE_TAG,{b1,b2}};
	clearCommandBuffer();
    SendCommand(&c);
	//check for ACK?
    return 0;
}

static command_t CommandTable[] =
{
    {"help",	CmdHelp,		1, "This help"},
    {"demod",	CmdVikingDemod, 1, "Extract tag data"},
    {"clone",	CmdVikingClone,	1, "<16 digits card data>  clone viking tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFViking(const char *Cmd)
{
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd)
{
    CmdsHelp(CommandTable);
    return 0;
}
