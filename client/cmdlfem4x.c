//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x commands
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
#include "cmdlf.h"
#include "cmdlfem4x.h"
#include "lfdemod.h"

#define llx PRIx64

char *global_em410xId;

static int CmdHelp(const char *Cmd);

int CmdEMdemodASK(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	int findone = (cmdp == '1') ? 1 : 0;
	UsbCommand c={CMD_EM410X_DEMOD};
	c.arg[0]=findone;
	SendCommand(&c);
	return 0;
}

/* Read the ID of an EM410x tag.
 * Format:
 *   1111 1111 1           <-- standard non-repeatable header
 *   XXXX [row parity bit] <-- 10 rows of 5 bits for our 40 bit tag ID
 *   ....
 *   CCCC                  <-- each bit here is parity for the 10 bits above in corresponding column
 *   0                     <-- stop bit, end of tag
 */
int CmdEM410xRead(const char *Cmd)
{
	uint32_t hi=0;
	uint64_t lo=0;

	if(!AskEm410xDemod("", &hi, &lo, false)) return 0;
	PrintAndLog("EM410x pattern found: ");
	printEM410x(hi, lo);
	if (hi){
		PrintAndLog ("EM410x XL pattern found");
		return 0;
	}
	char id[12] = {0x00};
	sprintf(id, "%010llx",lo);
	
	global_em410xId = id;
	return 1;
}

// emulate an EM410X tag
int CmdEM410xSim(const char *Cmd)
{
	int i, n, j, binary[4], parity[4];

	char cmdp = param_getchar(Cmd, 0);
	uint8_t uid[5] = {0x00};

	if (cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  lf em4x 410xsim <UID>");
		PrintAndLog("");
		PrintAndLog("     sample: lf em4x 410xsim 0F0368568B");
		return 0;
	}

	if (param_gethex(Cmd, 0, uid, 10)) {
		PrintAndLog("UID must include 10 HEX symbols");
		return 0;
	}
	
	PrintAndLog("Starting simulating UID %02X%02X%02X%02X%02X", uid[0],uid[1],uid[2],uid[3],uid[4]);
	PrintAndLog("Press pm3-button to about simulation");

	/* clock is 64 in EM410x tags */
	int clock = 64;

	/* clear our graph */
	ClearGraph(0);

		/* write 9 start bits */
		for (i = 0; i < 9; i++)
			AppendGraph(0, clock, 1);

		/* for each hex char */
		parity[0] = parity[1] = parity[2] = parity[3] = 0;
		for (i = 0; i < 10; i++)
		{
			/* read each hex char */
			sscanf(&Cmd[i], "%1x", &n);
			for (j = 3; j >= 0; j--, n/= 2)
				binary[j] = n % 2;

			/* append each bit */
			AppendGraph(0, clock, binary[0]);
			AppendGraph(0, clock, binary[1]);
			AppendGraph(0, clock, binary[2]);
			AppendGraph(0, clock, binary[3]);

			/* append parity bit */
			AppendGraph(0, clock, binary[0] ^ binary[1] ^ binary[2] ^ binary[3]);

			/* keep track of column parity */
			parity[0] ^= binary[0];
			parity[1] ^= binary[1];
			parity[2] ^= binary[2];
			parity[3] ^= binary[3];
		}

		/* parity columns */
		AppendGraph(0, clock, parity[0]);
		AppendGraph(0, clock, parity[1]);
		AppendGraph(0, clock, parity[2]);
		AppendGraph(0, clock, parity[3]);

		/* stop bit */
	AppendGraph(1, clock, 0);
 
	CmdLFSim("0"); //240 start_gap.
	return 0;
}

/* Function is equivalent of lf read + data samples + em410xread
 * looped until an EM410x tag is detected 
 * 
 * Why is CmdSamples("16000")?
 *  TBD: Auto-grow sample size based on detected sample rate.  IE: If the
 *       rate gets lower, then grow the number of samples
 *  Changed by martin, 4000 x 4 = 16000, 
 *  see http://www.proxmark.org/forum/viewtopic.php?pid=7235#p7235
*/
int CmdEM410xWatch(const char *Cmd)
{
	do {
		if (ukbhit()) {
			printf("\naborted via keyboard!\n");
			break;
		}
		
		CmdLFRead("s");
		getSamples("8201",true); //capture enough to get 2 complete preambles (4096*2+9)	
	} while (!CmdEM410xRead(""));

	return 0;
}

//currently only supports manchester modulations
int CmdEM410xWatchnSpoof(const char *Cmd)
{
	CmdEM410xWatch(Cmd);
	PrintAndLog("# Replaying captured ID: %s",global_em410xId);
	CmdLFaskSim("");
	return 0;
}

int CmdEM410xWrite(const char *Cmd)
{
	uint64_t id = 0xFFFFFFFFFFFFFFFF; // invalid id value
	int card = 0xFF; // invalid card value
	unsigned int clock = 0; // invalid clock value

	sscanf(Cmd, "%" PRIx64 " %d %d", &id, &card, &clock);

	// Check ID
	if (id == 0xFFFFFFFFFFFFFFFF) {
		PrintAndLog("Error! ID is required.\n");
		return 0;
	}
	if (id >= 0x10000000000) {
		PrintAndLog("Error! Given EM410x ID is longer than 40 bits.\n");
		return 0;
	}

	// Check Card
	if (card == 0xFF) {
		PrintAndLog("Error! Card type required.\n");
		return 0;
	}
	if (card < 0) {
		PrintAndLog("Error! Bad card type selected.\n");
		return 0;
	}

	// Check Clock
	if (card == 1)
	{
		// Default: 64
		if (clock == 0)
			clock = 64;

		// Allowed clock rates: 16, 32 and 64
		if ((clock != 16) && (clock != 32) && (clock != 64)) {
			PrintAndLog("Error! Clock rate %d not valid. Supported clock rates are 16, 32 and 64.\n", clock);
			return 0;
		}
	}
	else if (clock != 0)
	{
		PrintAndLog("Error! Clock rate is only supported on T55x7 tags.\n");
		return 0;
	}

	if (card == 1) {
		PrintAndLog("Writing %s tag with UID 0x%010" PRIx64 " (clock rate: %d)", "T55x7", id, clock);
		// NOTE: We really should pass the clock in as a separate argument, but to
		//   provide for backwards-compatibility for older firmware, and to avoid
		//   having to add another argument to CMD_EM410X_WRITE_TAG, we just store
		//   the clock rate in bits 8-15 of the card value
		card = (card & 0xFF) | (((uint64_t)clock << 8) & 0xFF00);
	}
	else if (card == 0)
		PrintAndLog("Writing %s tag with UID 0x%010" PRIx64, "T5555", id, clock);
	else {
		PrintAndLog("Error! Bad card type selected.\n");
		return 0;
	}

	UsbCommand c = {CMD_EM410X_WRITE_TAG, {card, (uint32_t)(id >> 32), (uint32_t)id}};
	SendCommand(&c);

	return 0;
}

bool EM_EndParityTest(uint8_t *BitStream, size_t size, uint8_t rows, uint8_t cols, uint8_t pType)
{
	if (rows*cols>size) return false;
	uint8_t colP=0;
	//assume last col is a parity and do not test
	for (uint8_t colNum = 0; colNum < cols-1; colNum++) {
		for (uint8_t rowNum = 0; rowNum < rows; rowNum++) {
			colP ^= BitStream[(rowNum*cols)+colNum];
		}
		if (colP != pType) return false;
	}
	return true;
}

bool EM_ByteParityTest(uint8_t *BitStream, size_t size, uint8_t rows, uint8_t cols, uint8_t pType)
{
	if (rows*cols>size) return false;
	uint8_t rowP=0;
	//assume last row is a parity row and do not test
	for (uint8_t rowNum = 0; rowNum < rows-1; rowNum++) {
		for (uint8_t colNum = 0; colNum < cols; colNum++) {
			rowP ^= BitStream[(rowNum*cols)+colNum];
		}
		if (rowP != pType) return false;
	}
	return true;
}

uint32_t OutputEM4x50_Block(uint8_t *BitStream, size_t size, bool verbose, bool pTest)
{
	if (size<45) return 0;
	uint32_t code = bytebits_to_byte(BitStream,8);
	code = code<<8 | bytebits_to_byte(BitStream+9,8);
	code = code<<8 | bytebits_to_byte(BitStream+18,8);
	code = code<<8 | bytebits_to_byte(BitStream+27,8);
	if (verbose || g_debugMode){
		for (uint8_t i = 0; i<5; i++){
			if (i == 4) PrintAndLog(""); //parity byte spacer
			PrintAndLog("%d%d%d%d%d%d%d%d %d -> 0x%02x",
			    BitStream[i*9],
			    BitStream[i*9+1],
			    BitStream[i*9+2],
			    BitStream[i*9+3],
			    BitStream[i*9+4],
			    BitStream[i*9+5],
			    BitStream[i*9+6],
			    BitStream[i*9+7],
			    BitStream[i*9+8],
			    bytebits_to_byte(BitStream+i*9,8)
			);
		}
		if (pTest)
			PrintAndLog("Parity Passed");
		else
			PrintAndLog("Parity Failed");
	}
	return code;
}
/* Read the transmitted data of an EM4x50 tag
 * Format:
 *
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  CCCCCCCC                         <- column parity bits
 *  0                                <- stop bit
 *  LW                               <- Listen Window
 *
 * This pattern repeats for every block of data being transmitted.
 * Transmission starts with two Listen Windows (LW - a modulated
 * pattern of 320 cycles each (32/32/128/64/64)).
 *
 * Note that this data may or may not be the UID. It is whatever data
 * is stored in the blocks defined in the control word First and Last
 * Word Read values. UID is stored in block 32.
 */
 //completed by Marshmellow
int EM4x50Read(const char *Cmd, bool verbose)
{
	uint8_t fndClk[] = {8,16,32,40,50,64,128};
	int clk = 0; 
	int invert = 0;
	int tol = 0;
	int i, j, startblock, skip, block, start, end, low, high, minClk;
	bool complete = false;
	int tmpbuff[MAX_GRAPH_TRACE_LEN / 64];
	uint32_t Code[6];
	char tmp[6];
	char tmp2[20];
	int phaseoff;
	high = low = 0;
	memset(tmpbuff, 0, MAX_GRAPH_TRACE_LEN / 64);

	// get user entry if any
	sscanf(Cmd, "%i %i", &clk, &invert);
	
	// save GraphBuffer - to restore it later	
	save_restoreGB(1);

	// first get high and low values
	for (i = 0; i < GraphTraceLen; i++) {
		if (GraphBuffer[i] > high)
			high = GraphBuffer[i];
		else if (GraphBuffer[i] < low)
			low = GraphBuffer[i];
	}

	i = 0;
	j = 0;
	minClk = 255;
	// get to first full low to prime loop and skip incomplete first pulse
	while ((GraphBuffer[i] < high) && (i < GraphTraceLen))
		++i;
	while ((GraphBuffer[i] > low) && (i < GraphTraceLen))
		++i;
	skip = i;

	// populate tmpbuff buffer with pulse lengths
	while (i < GraphTraceLen) {
		// measure from low to low
		while ((GraphBuffer[i] > low) && (i < GraphTraceLen))
			++i;
		start= i;
		while ((GraphBuffer[i] < high) && (i < GraphTraceLen))
			++i;
		while ((GraphBuffer[i] > low) && (i < GraphTraceLen))
			++i;
		if (j>=(MAX_GRAPH_TRACE_LEN/64)) {
			break;
		}
		tmpbuff[j++]= i - start;
		if (i-start < minClk && i < GraphTraceLen) {
			minClk = i - start;
		}
	}
	// set clock
	if (!clk) {
		for (uint8_t clkCnt = 0; clkCnt<7; clkCnt++) {
			tol = fndClk[clkCnt]/8;
			if (minClk >= fndClk[clkCnt]-tol && minClk <= fndClk[clkCnt]+1) { 
				clk=fndClk[clkCnt];
				break;
			}
		}
		if (!clk) return 0;
	} else tol = clk/8;

	// look for data start - should be 2 pairs of LW (pulses of clk*3,clk*2)
	start = -1;
	for (i= 0; i < j - 4 ; ++i) {
		skip += tmpbuff[i];
		if (tmpbuff[i] >= clk*3-tol && tmpbuff[i] <= clk*3+tol)  //3 clocks
			if (tmpbuff[i+1] >= clk*2-tol && tmpbuff[i+1] <= clk*2+tol)  //2 clocks
				if (tmpbuff[i+2] >= clk*3-tol && tmpbuff[i+2] <= clk*3+tol) //3 clocks
					if (tmpbuff[i+3] >= clk-tol)  //1.5 to 2 clocks - depends on bit following
					{
						start= i + 4;
						break;
					}
	}
	startblock = i + 4;

	// skip over the remainder of LW
	skip += tmpbuff[i+1] + tmpbuff[i+2] + clk;
	if (tmpbuff[i+3]>clk) 
		phaseoff = tmpbuff[i+3]-clk;
	else
		phaseoff = 0;
	// now do it again to find the end
	end = skip;
	for (i += 3; i < j - 4 ; ++i) {
		end += tmpbuff[i];
		if (tmpbuff[i] >= clk*3-tol && tmpbuff[i] <= clk*3+tol)  //3 clocks
			if (tmpbuff[i+1] >= clk*2-tol && tmpbuff[i+1] <= clk*2+tol)  //2 clocks
				if (tmpbuff[i+2] >= clk*3-tol && tmpbuff[i+2] <= clk*3+tol) //3 clocks
					if (tmpbuff[i+3] >= clk-tol)  //1.5 to 2 clocks - depends on bit following
					{
						complete= true;
						break;
					}
	}
	end = i;
	// report back
	if (verbose || g_debugMode) {
		if (start >= 0) {
			PrintAndLog("\nNote: one block = 50 bits (32 data, 12 parity, 6 marker)");
		}	else {
			PrintAndLog("No data found!, clock tried:%d",clk);
			PrintAndLog("Try again with more samples.");
			PrintAndLog("  or after a 'data askedge' command to clean up the read");
			return 0;
		}
	} else if (start < 0) return 0;
	start = skip;
	snprintf(tmp2, sizeof(tmp2),"%d %d 1000 %d", clk, invert, clk*47);
	// get rid of leading crap 
	snprintf(tmp, sizeof(tmp), "%i", skip);
	CmdLtrim(tmp);
	bool pTest;
	bool AllPTest = true;
	// now work through remaining buffer printing out data blocks
	block = 0;
	i = startblock;
	while (block < 6) {
		if (verbose || g_debugMode) PrintAndLog("\nBlock %i:", block);
		skip = phaseoff;
		
		// look for LW before start of next block
		for ( ; i < j - 4 ; ++i) {
			skip += tmpbuff[i];
			if (tmpbuff[i] >= clk*3-tol && tmpbuff[i] <= clk*3+tol)
				if (tmpbuff[i+1] >= clk-tol)
					break;
		}
		if (i >= j-4) break; //next LW not found
		skip += clk;
		if (tmpbuff[i+1]>clk)
			phaseoff = tmpbuff[i+1]-clk;
		else
			phaseoff = 0;
		i += 2;
		if (ASKDemod(tmp2, false, false, 1) < 1) {
			save_restoreGB(0);
			return 0;
		}
		//set DemodBufferLen to just one block
		DemodBufferLen = skip/clk;
		//test parities
		pTest = EM_ByteParityTest(DemodBuffer,DemodBufferLen,5,9,0);	
		pTest &= EM_EndParityTest(DemodBuffer,DemodBufferLen,5,9,0);
		AllPTest &= pTest;
		//get output
		Code[block] = OutputEM4x50_Block(DemodBuffer,DemodBufferLen,verbose, pTest);
		if (g_debugMode) PrintAndLog("\nskipping %d samples, bits:%d", skip, skip/clk);
		//skip to start of next block
		snprintf(tmp,sizeof(tmp),"%i",skip);
		CmdLtrim(tmp);
		block++;
		if (i >= end) break; //in case chip doesn't output 6 blocks
	}
	//print full code:
	if (verbose || g_debugMode || AllPTest){
		if (!complete) {
			PrintAndLog("*** Warning!");
			PrintAndLog("Partial data - no end found!");
			PrintAndLog("Try again with more samples.");
		}
		PrintAndLog("Found data at sample: %i - using clock: %i", start, clk);    
		end = block;
		for (block=0; block < end; block++){
			PrintAndLog("Block %d: %08x",block,Code[block]);
		}
		if (AllPTest) {
			PrintAndLog("Parities Passed");
		} else {
			PrintAndLog("Parities Failed");
			PrintAndLog("Try cleaning the read samples with 'data askedge'");
		}
	}

	//restore GraphBuffer
	save_restoreGB(0);
	return (int)AllPTest;
}

int CmdEM4x50Read(const char *Cmd)
{
	return EM4x50Read(Cmd, true);
}

int CmdReadWord(const char *Cmd)
{
	int Word = -1; //default to invalid word
	UsbCommand c;
	
	sscanf(Cmd, "%d", &Word);
	
	if ( (Word > 15) | (Word < 0) ) {
		PrintAndLog("Word must be between 0 and 15");
		return 1;
	}
	
	PrintAndLog("Reading word %d", Word);
	
	c.cmd = CMD_EM4X_READ_WORD;
	c.d.asBytes[0] = 0x0; //Normal mode
	c.arg[0] = 0;
	c.arg[1] = Word;
	c.arg[2] = 0;
	SendCommand(&c);
	return 0;
}

int CmdReadWordPWD(const char *Cmd)
{
	int Word = -1; //default to invalid word
	int Password = 0xFFFFFFFF; //default to blank password
	UsbCommand c;
	
	sscanf(Cmd, "%d %x", &Word, &Password);
	
	if ( (Word > 15) | (Word < 0) ) {
		PrintAndLog("Word must be between 0 and 15");
		return 1;
	}
	
	PrintAndLog("Reading word %d with password %08X", Word, Password);
	
	c.cmd = CMD_EM4X_READ_WORD;
	c.d.asBytes[0] = 0x1; //Password mode
	c.arg[0] = 0;
	c.arg[1] = Word;
	c.arg[2] = Password;
	SendCommand(&c);
	return 0;
}

int CmdWriteWord(const char *Cmd)
{
	int Word = 16; //default to invalid block
	int Data = 0xFFFFFFFF; //default to blank data
	UsbCommand c;
	
	sscanf(Cmd, "%x %d", &Data, &Word);
	
	if (Word > 15) {
		PrintAndLog("Word must be between 0 and 15");
		return 1;
	}
	
	PrintAndLog("Writing word %d with data %08X", Word, Data);
	
	c.cmd = CMD_EM4X_WRITE_WORD;
	c.d.asBytes[0] = 0x0; //Normal mode
	c.arg[0] = Data;
	c.arg[1] = Word;
	c.arg[2] = 0;
	SendCommand(&c);
	return 0;
}

int CmdWriteWordPWD(const char *Cmd)
{
	int Word = 16; //default to invalid word
	int Data = 0xFFFFFFFF; //default to blank data
	int Password = 0xFFFFFFFF; //default to blank password
	UsbCommand c;
	
	sscanf(Cmd, "%x %d %x", &Data, &Word, &Password);
	
	if (Word > 15) {
		PrintAndLog("Word must be between 0 and 15");
		return 1;
	}
	
	PrintAndLog("Writing word %d with data %08X and password %08X", Word, Data, Password);
	
	c.cmd = CMD_EM4X_WRITE_WORD;
	c.d.asBytes[0] = 0x1; //Password mode
	c.arg[0] = Data;
	c.arg[1] = Word;
	c.arg[2] = Password;
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] =
{
	{"help", CmdHelp, 1, "This help"},
	{"em410xdemod", CmdEMdemodASK, 0, "[findone] -- Extract ID from EM410x tag (option 0 for continuous loop, 1 for only 1 tag)"},  
	{"em410xread", CmdEM410xRead, 1, "[clock rate] -- Extract ID from EM410x tag in GraphBuffer"},
	{"em410xsim", CmdEM410xSim, 0, "<UID> -- Simulate EM410x tag"},
	{"em410xwatch", CmdEM410xWatch, 0, "['h'] -- Watches for EM410x 125/134 kHz tags (option 'h' for 134)"},
	{"em410xspoof", CmdEM410xWatchnSpoof, 0, "['h'] --- Watches for EM410x 125/134 kHz tags, and replays them. (option 'h' for 134)" },
	{"em410xwrite", CmdEM410xWrite, 0, "<UID> <'0' T5555> <'1' T55x7> [clock rate] -- Write EM410x UID to T5555(Q5) or T55x7 tag, optionally setting clock rate"},
	{"em4x50read", CmdEM4x50Read, 1, "Extract data from EM4x50 tag"},
	{"readword", CmdReadWord, 1, "<Word> -- Read EM4xxx word data"},
	{"readwordPWD", CmdReadWordPWD, 1, "<Word> <Password> -- Read EM4xxx word data in password mode"},
	{"writeword", CmdWriteWord, 1, "<Data> <Word> -- Write EM4xxx word data"},
	{"writewordPWD", CmdWriteWordPWD, 1, "<Data> <Word> <Password> -- Write EM4xxx word data in password mode"},
	{NULL, NULL, 0, NULL}
};

int CmdLFEM4X(const char *Cmd)
{
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd)
{
	CmdsHelp(CommandTable);
	return 0;
}
