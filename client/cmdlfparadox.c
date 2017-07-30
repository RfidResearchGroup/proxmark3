//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Paradox tag commands
// FSK2a, rf/50, 96 bits (completely known)
//-----------------------------------------------------------------------------
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "cmdlfparadox.h"
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
static int CmdHelp(const char *Cmd);


// loop to get raw paradox waveform then FSK demodulate the TAG ID from it
int detectParadox(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo, int *waveStartIdx) {
	if (justNoise(dest, *size)) return -1;
	
	size_t numStart = 0, startIdx = 0;
	// FSK demodulator
	*size = fskdemod(dest, *size, 50, 1, 10, 8, waveStartIdx); //fsk2a
	if (*size < 96) return -2;

	// 00001111 bit pattern represent start of frame, 01 pattern represents a 0 and 10 represents a 1
	uint8_t preamble[] = {0,0,0,0,1,1,1,1};
	if (preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx)) 
		return -3; //preamble not found

	numStart = startIdx + sizeof(preamble);
	// final loop, go over previously decoded FSK data and manchester decode into usable tag ID
	for (size_t idx = numStart; (idx-numStart) < *size - sizeof(preamble); idx+=2){
		if (dest[idx] == dest[idx+1]) 
			return -4; //not manchester data
		*hi2 = (*hi2<<1)|(*hi>>31);
		*hi = (*hi<<1)|(*lo>>31);
		//Then, shift in a 0 or one into low
		if (dest[idx] && !dest[idx+1])	// 1 0
			*lo=(*lo<<1)|1;
		else // 0 1
			*lo=(*lo<<1)|0;
	}
	return (int)startIdx;
}

//by marshmellow
//Paradox Prox demod - FSK RF/50 with preamble of 00001111 (then manchester encoded)
//print full Paradox Prox ID and some bit format details if found
int CmdParadoxDemod(const char *Cmd) {
	//raw fsk demod no manchester decoding no start bit finding just get binary from wave
	uint8_t bits[MAX_GRAPH_TRACE_LEN]={0};
	size_t BitLen = getFromGraphBuf(bits);
	if (BitLen==0) return 0;

	uint32_t hi2=0, hi=0, lo=0;	
	int waveIdx=0;
	//get binary from fsk wave
	int idx = detectParadox(bits, &BitLen, &hi2, &hi, &lo, &waveIdx);
	if (idx < 0){
		if (g_debugMode){
			if (idx == -1){
				PrintAndLog("DEBUG: Error - Paradox just noise detected");     
			} else if (idx == -2) {
				PrintAndLog("DEBUG: Error - Paradox error demoding fsk");
			} else if (idx == -3) {
				PrintAndLog("DEBUG: Error - Paradox preamble not found");
			} else if (idx == -4) {
				PrintAndLog("DEBUG: Error - Paradox error in Manchester data");
			} else {
				PrintAndLog("DEBUG: Error - Paradox error demoding fsk %d", idx);
			}
		}
		return 0;
	}
	if (hi2==0 && hi==0 && lo==0){
		if (g_debugMode) PrintAndLog("DEBUG: Error - Paradox no value found");
		return 0;
	}
	uint32_t fc = ((hi & 0x3)<<6) | (lo>>26);
	uint32_t cardnum = (lo>>10) & 0xFFFF;
	uint32_t rawLo = bytebits_to_byte(bits + idx + 64, 32);
	uint32_t rawHi = bytebits_to_byte(bits + idx + 32, 32);
	uint32_t rawHi2 = bytebits_to_byte(bits + idx, 32);

	PrintAndLog("Paradox TAG ID: %x%08x - FC: %d - Card: %d - Checksum: %02x - RAW: %08x%08x%08x",
		hi >> 10,
		(hi & 0x3)<<26 | (lo>>10), 
		fc, cardnum,
		(lo>>2) & 0xFF,
		rawHi2,
		rawHi,
		rawLo
	);

	setDemodBuf(bits, BitLen, idx);
	setClockGrid(50, waveIdx + (idx*50));
	
	if (g_debugMode){ 
		PrintAndLog("DEBUG: Paradox idx: %d, len: %d, Printing Demod Buffer:", idx, BitLen);
		printDemodBuff();
	}
	return 1;
}
//by marshmellow
//see ASKDemod for what args are accepted
int CmdParadoxRead(const char *Cmd) {
	lf_read(true, 10000);	
	return CmdParadoxDemod(Cmd);
}

static command_t CommandTable[] = {
	{"help",  CmdHelp,			1, "This help"},
	{"demod", CmdParadoxDemod,	1, "Demodulate a Paradox FSK tag from the GraphBuffer"},
	{"read",  CmdParadoxRead,	0, "Attempt to read and Extract tag data from the antenna"},
	{NULL, NULL, 0, NULL}
};

int CmdLFParadox(const char *Cmd) {
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
