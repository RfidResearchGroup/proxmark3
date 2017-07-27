//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Honeywell NexWatch tag commands
// PSK1 RF/16, RF/2, 128 bits long (known)
//-----------------------------------------------------------------------------
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include "cmdlfnexwatch.h"
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"

static int CmdHelp(const char *Cmd);

int CmdPSKNexWatch(const char *Cmd)
{
	if (!PSKDemod("", false)) return 0;

	uint8_t preamble[28] = {0,0,0,0,0,1,0,1,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	size_t startIdx = 0, size = DemodBufferLen;

	// sanity check. 
	if ( size < sizeof(preamble) + 100) return 0;

	bool invert = false;
	if (!preambleSearch(DemodBuffer, preamble, sizeof(preamble), &size, &startIdx)){
		// if didn't find preamble try again inverting
		if (!PSKDemod("1", false)) return 0;
		
		size = DemodBufferLen;
		if (!preambleSearch(DemodBuffer, preamble, sizeof(preamble), &size, &startIdx)) return 0;
		invert = true;
	}
	if (size != 128) return 0;
	setDemodBuf(DemodBuffer, size, startIdx+4);
	//setClockGrid(g_DemodClock, g_DemodStartIdx + ((startIdx+4)*g_DemodClock));
	startIdx = 8+32; // 8 = preamble, 32 = reserved bits (always 0)
	//get ID
	uint32_t ID = 0;
	for (uint8_t wordIdx=0; wordIdx<4; wordIdx++){
		for (uint8_t idx=0; idx<8; idx++){
			ID = (ID << 1) | DemodBuffer[startIdx+wordIdx+(idx*4)];
		}	
	}
	//parity check (TBD)

	//checksum check (TBD)

	//output
	PrintAndLog("NexWatch ID: %d", ID);
	if (invert){
		PrintAndLog("DEBUG: Error - NexWatch had to Invert - probably NexKey");
		for (uint8_t idx=0; idx<size; idx++)
			DemodBuffer[idx] ^= 1;
	} 

	CmdPrintDemodBuff("x");
	return 1;
}

//by marshmellow
//see ASKDemod for what args are accepted
int CmdNexWatchRead(const char *Cmd) {
	// read lf silently
	//lf_read(true, 10000);
	
	CmdLFRead("s");
	getSamples("10000",true);
	
	// demod and output viking ID	
	return CmdPSKNexWatch(Cmd);
}

static command_t CommandTable[] = {
	{"help",  CmdHelp,          1, "This help"},
	{"demod", CmdPSKNexWatch,   1, "Demodulate a NexWatch tag (nexkey, quadrakey) from the GraphBuffer"},
	{"read",  CmdNexWatchRead,  0, "Attempt to Read and Extract tag data from the antenna"},
	{NULL, NULL, 0, NULL}
};

int CmdLFNexWatch(const char *Cmd) {
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
