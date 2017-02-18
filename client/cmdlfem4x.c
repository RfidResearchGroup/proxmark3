//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x commands
//-----------------------------------------------------------------------------

#include "cmdlfem4x.h"

uint64_t g_em410xid = 0;

static int CmdHelp(const char *Cmd);

int CmdEMdemodASK(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	uint8_t findone = (cmdp == '1') ? 1 : 0;
	UsbCommand c = {CMD_EM410X_DEMOD, {findone, 0, 0}};
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
	g_em410xid = lo;
	return 1;
}


int usage_lf_em410x_sim(void) {
	PrintAndLog("Simulating EM410x tag");
	PrintAndLog("");
	PrintAndLog("Usage:  lf em4x em410xsim [h] <uid> <clock>");
	PrintAndLog("Options:");
	PrintAndLog("       h         - this help");
	PrintAndLog("       uid       - uid (10 HEX symbols)");
	PrintAndLog("       clock     - clock (32|64) (optional)");
	PrintAndLog("samples:");
	PrintAndLog("      lf em4x em410xsim 0F0368568B");
	PrintAndLog("      lf em4x em410xsim 0F0368568B 32");
	return 0;
}

// emulate an EM410X tag
int CmdEM410xSim(const char *Cmd)
{
	int i, n, j, binary[4], parity[4];
	uint8_t uid[5] = {0x00};

	char cmdp = param_getchar(Cmd, 0);
	if (cmdp == 'h' || cmdp == 'H') return usage_lf_em410x_sim();

	/* clock is 64 in EM410x tags */
	uint8_t clock = 64;

	if (param_gethex(Cmd, 0, uid, 10)) {
		PrintAndLog("UID must include 10 HEX symbols");
		return 0;
	}
	
	param_getdec(Cmd, 1, &clock);
	
	PrintAndLog("Starting simulating UID %02X%02X%02X%02X%02X  clock: %d", uid[0],uid[1],uid[2],uid[3],uid[4],clock);
	PrintAndLog("Press pm3-button to about simulation");

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
// todo: helptext
int CmdEM410xWatchnSpoof(const char *Cmd)
{
	// loops if the captured ID was in XL-format.
	CmdEM410xWatch(Cmd);
	PrintAndLog("# Replaying captured ID: %llu", g_em410xid);
	CmdLFaskSim("");
	return 0;
}

int CmdEM410xWrite(const char *Cmd)
{
	uint64_t id = 0xFFFFFFFFFFFFFFFF; // invalid id value
	int card = 0xFF; // invalid card value
	uint32_t clock = 0; // invalid clock value

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
		// Default: 64
	if (clock == 0)
		clock = 64;

	// Allowed clock rates: 16, 32, 40 and 64
	if ((clock != 16) && (clock != 32) && (clock != 64) && (clock != 40)) {
		PrintAndLog("Error! Clock rate %d not valid. Supported clock rates are 16, 32, 40 and 64.\n", clock);
		return 0;
	}

	if (card == 1) {
		PrintAndLog("Writing %s tag with UID 0x%010" PRIx64 " (clock rate: %d)", "T55x7", id, clock);
		// NOTE: We really should pass the clock in as a separate argument, but to
		//   provide for backwards-compatibility for older firmware, and to avoid
		//   having to add another argument to CMD_EM410X_WRITE_TAG, we just store
		//   the clock rate in bits 8-15 of the card value
		card = (card & 0xFF) | ((clock << 8) & 0xFF00);
	}	else if (card == 0) {
		PrintAndLog("Writing %s tag with UID 0x%010" PRIx64, "T5555", id, clock);
		card = (card & 0xFF) | ((clock << 8) & 0xFF00);
	} else {
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


//////////////// 4050 / 4450 commands
int usage_lf_em4x50_dump(void) {
	PrintAndLog("Dump EM4x50/EM4x69.  Tag must be on antenna. ");
	PrintAndLog("");
	PrintAndLog("Usage:  lf em 4x50dump [h] <pwd>");
	PrintAndLog("Options:");
	PrintAndLog("       h         - this help");
	PrintAndLog("       pwd       - password (hex) (optional)");
	PrintAndLog("samples:");
	PrintAndLog("      lf em 4x50dump");
	PrintAndLog("      lf em 4x50dump 11223344");
	return 0;
}
int usage_lf_em4x50_read(void) {
	PrintAndLog("Read EM 4x50/EM4x69.  Tag must be on antenna. ");
	PrintAndLog("");
	PrintAndLog("Usage:  lf em 4x50read [h] <address> <pwd>");
	PrintAndLog("Options:");
	PrintAndLog("       h         - this help");
	PrintAndLog("       address   - memory address to read. (0-15)");
	PrintAndLog("       pwd       - password (hex) (optional)");
	PrintAndLog("samples:");
	PrintAndLog("      lf em 4x50read 1");
	PrintAndLog("      lf em 4x50read 1 11223344");
	return 0;
}
int usage_lf_em4x50_write(void) {
	PrintAndLog("Write EM 4x50/4x69.  Tag must be on antenna. ");
	PrintAndLog("");
	PrintAndLog("Usage:  lf em 4x50write [h] <address> <data> <pwd>");
	PrintAndLog("Options:");
	PrintAndLog("       h         - this help");
	PrintAndLog("       address   - memory address to write to. (0-15)");
	PrintAndLog("       data      - data to write (hex)");	
	PrintAndLog("       pwd       - password (hex) (optional)");
	PrintAndLog("samples:");
	PrintAndLog("      lf em 4x50write 1 deadc0de");
	PrintAndLog("      lf em 4x50write 1 deadc0de 11223344");
	return 0;
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


/* Read the transmitted data of an EM4x50 tag from the graphbuffer
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
int EM4x50Read(const char *Cmd, bool verbose) {
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
		if (!clk) {
			PrintAndLog("ERROR: EM4x50 - didn't find a clock");
			return 0;
		}
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

int CmdEM4x50Read(const char *Cmd) {
	uint8_t ctmp = param_getchar(Cmd, 0);
	if ( ctmp == 'H' || ctmp == 'h' ) return usage_lf_em4x50_read();	
	return EM4x50Read(Cmd, true);
}

int CmdEM4x50Write(const char *Cmd){
	uint8_t ctmp = param_getchar(Cmd, 0);
	if ( ctmp == 'H' || ctmp == 'h' ) return usage_lf_em4x50_write();
	PrintAndLog("no implemented yet");
	return 0;
}
int CmdEM4x50Dump(const char *Cmd){
	uint8_t ctmp = param_getchar(Cmd, 0);
	if ( ctmp == 'H' || ctmp == 'h' ) return usage_lf_em4x50_dump();
	PrintAndLog("no implemented yet");
	return 0;
}

#define EM_PREAMBLE_LEN 6
// download samples from device
// and copy them to Graphbuffer
bool downloadSamplesEM(){
	
	// 8 bit preamble + 32 bit word response (max clock (128) * 40bits = 5120 samples)
	uint8_t got[6000];
	GetFromBigBuf(got, sizeof(got), 0);
	if ( !WaitForResponseTimeout(CMD_ACK, NULL, 2500) ) {
		PrintAndLog("command execution time out");
		return FALSE;
	}
	setGraphBuf(got, sizeof(got));
	return TRUE;
}
//search for given preamble in given BitStream and return success=1 or fail=0 and startIndex
bool doPreambleSearch(size_t *startIdx){
	
	// sanity check
	if ( DemodBufferLen < EM_PREAMBLE_LEN) {
		if (g_debugMode) PrintAndLog("DEBUG: Error - EM4305 demodbuffer too small");
		return FALSE;
	}
	
	// skip first two 0 bits as they might have been missed in the demod 
	uint8_t preamble[EM_PREAMBLE_LEN] = {0,0,1,0,1,0};
	
	// set size to 15 to only test first 4 positions for the preamble
	size_t size = (15 > DemodBufferLen) ? DemodBufferLen : 15;
	*startIdx = 0; 
	uint8_t found = 0;
	
	// em only sends preamble once, so look for it once in the first x bits
	for (int idx = 0; idx < size - EM_PREAMBLE_LEN; idx++){
		if (memcmp(DemodBuffer+idx, preamble, EM_PREAMBLE_LEN) == 0){
			//first index found
			*startIdx = idx;
			found = 1;
			break;
		}
	}
	
	if ( !found) {
		if (g_debugMode) PrintAndLog("DEBUG: Error - EM4305 preamble not found :: %d", *startIdx);
		return FALSE;
	} 
	return TRUE;
}

bool detectFSK(){
	// detect fsk clock
	if (!GetFskClock("", FALSE, FALSE)) {
		if (g_debugMode) PrintAndLog("DEBUG: Error - EM: FSK clock failed");
		return FALSE;
	}
	// demod
	int ans = FSKrawDemod("0 0", FALSE);
	if (!ans) {
		if (g_debugMode) PrintAndLog("DEBUG: Error - EM: FSK Demod failed");
		return FALSE;
	}
	return TRUE;
}
// PSK clocks should be easy to detect ( but difficult to demod a non-repeating pattern... )
bool detectPSK(){	
	int	ans = GetPskClock("", FALSE, FALSE);
	if (ans <= 0) {
		if (g_debugMode) PrintAndLog("DEBUG: Error - EM: PSK clock failed");
		return FALSE;
	}
	//demod
	//try psk1 -- 0 0 6 (six errors?!?)
	ans = PSKDemod("0 0 6", FALSE);
	if (!ans) {
		if (g_debugMode) PrintAndLog("DEBUG: Error - EM: PSK1 Demod failed");

		//try psk1 inverted
		ans = PSKDemod("0 1 6", FALSE);
		if (!ans) {
			if (g_debugMode) PrintAndLog("DEBUG: Error - EM: PSK1 inverted Demod failed");
			return FALSE;
		}
	}
	// either PSK1 or PSK1 inverted is ok from here.
	// lets check PSK2 later.
	return TRUE;
}
// try manchester - NOTE: ST only applies to T55x7 tags.
bool detectASK_MAN(){
	bool stcheck = FALSE;
	int ans = ASKDemod_ext("0 0 0", FALSE, FALSE, 1, &stcheck);
	if (!ans) {
		if (g_debugMode) PrintAndLog("DEBUG: Error - EM: ASK/Manchester Demod failed");
		return FALSE;
	} 
	return TRUE;
}
bool detectASK_BI(){
	int ans = ASKbiphaseDemod("0 0 1", FALSE);
	if (!ans) { 
		if (g_debugMode) PrintAndLog("DEBUG: Error - EM: ASK/biphase normal demod failed");
		
		ans = ASKbiphaseDemod("0 1 1", FALSE);
		if (!ans) {
			if (g_debugMode) PrintAndLog("DEBUG: Error - EM: ASK/biphase inverted demod failed");
			return FALSE;
		}
	}
	return TRUE;
}

// param: idx - start index in demoded data.
bool setDemodBufferEM(uint32_t *word, size_t idx){

	//test for even parity bits.
	size_t size = removeParity(DemodBuffer, idx + EM_PREAMBLE_LEN, 9, 0, 44);
	if (!size) {
		if (g_debugMode) PrintAndLog("DEBUG: Error -EM Parity not detected");
		return FALSE;
	}

	//todo test last 8 bits for even parity || (xor)
	setDemodBuf(DemodBuffer, 40, 0);

	*word = bytebits_to_byteLSBF(DemodBuffer, 32);

	uint8_t lo  = (uint8_t) bytebits_to_byteLSBF(DemodBuffer     , 8);
	uint8_t lo2 = (uint8_t) bytebits_to_byteLSBF(DemodBuffer +  8, 8);
	uint8_t hi  = (uint8_t) bytebits_to_byteLSBF(DemodBuffer + 16, 8);
	uint8_t hi2 = (uint8_t) bytebits_to_byteLSBF(DemodBuffer + 24, 8);
	uint8_t cs  = (uint8_t) bytebits_to_byteLSBF(DemodBuffer + 32, 8);
	uint8_t cs2 = lo ^ lo2 ^ hi ^ hi2;
	if (g_debugMode) PrintAndLog("EM4x05/4x69 : %08X CS: %02X %s"
						, *word
						, cs
						, (cs2==cs) ? "Passed" : "Failed"
					);

	return (cs2==cs);
}

// FSK, PSK, ASK/MANCHESTER, ASK/BIPHASE, ASK/DIPHASE 
// should cover 90% of known used configs
// the rest will need to be manually demoded for now...
bool demodEM4x05resp(uint32_t *word) {
	size_t idx = 0;	
	
	if (detectASK_MAN() && doPreambleSearch( &idx ))
		return setDemodBufferEM(word, idx);
	
	if (detectASK_BI() && doPreambleSearch( &idx ))
		return setDemodBufferEM(word, idx);
	
	if (detectFSK() && doPreambleSearch( &idx ))
		return setDemodBufferEM(word, idx);
	
	if (detectPSK()) {
		if (doPreambleSearch( &idx ))
			return setDemodBufferEM(word, idx);
		
		psk1TOpsk2(DemodBuffer, DemodBufferLen);
		if (doPreambleSearch( &idx ))
			return setDemodBufferEM(word, idx);
	}
	return FALSE;
}

//////////////// 4205 / 4305 commands
int usage_lf_em4x05_dump(void) {
	PrintAndLog("Dump EM4x05/EM4x69.  Tag must be on antenna. ");
	PrintAndLog("");
	PrintAndLog("Usage:  lf em 4x05dump [h] <pwd>");
	PrintAndLog("Options:");
	PrintAndLog("       h         - this help");
	PrintAndLog("       pwd       - password (hex) (optional)");
	PrintAndLog("samples:");
	PrintAndLog("      lf em 4x05dump");
	PrintAndLog("      lf em 4x05dump 11223344");
	return 0;
}
int usage_lf_em4x05_read(void) {
	PrintAndLog("Read EM4x05/EM4x69.  Tag must be on antenna. ");
	PrintAndLog("");
	PrintAndLog("Usage:  lf em 4x05read [h] <address> <pwd>");
	PrintAndLog("Options:");
	PrintAndLog("       h         - this help");
	PrintAndLog("       address   - memory address to read. (0-15)");
	PrintAndLog("       pwd       - password (hex) (optional)");
	PrintAndLog("samples:");
	PrintAndLog("      lf em 4x05read 1");
	PrintAndLog("      lf em 4x05read 1 11223344");
	return 0;
}
int usage_lf_em4x05_write(void) {
	PrintAndLog("Write EM4x05/4x69.  Tag must be on antenna. ");
	PrintAndLog("");
	PrintAndLog("Usage:  lf em 4x05write [h] <address> <data> <pwd>");
	PrintAndLog("Options:");
	PrintAndLog("       h         - this help");
	PrintAndLog("       address   - memory address to write to. (0-15)");
	PrintAndLog("       data      - data to write (hex)");	
	PrintAndLog("       pwd       - password (hex) (optional)");
	PrintAndLog("samples:");
	PrintAndLog("      lf em 4x05write 1 deadc0de");
	PrintAndLog("      lf em 4x05write 1 deadc0de 11223344");
	return 0;
}

int CmdEM4x05Dump(const char *Cmd) {
	uint8_t addr = 0;
	uint32_t pwd;
	bool usePwd = false;
	uint8_t ctmp = param_getchar(Cmd, 0);
	if ( ctmp == 'H' || ctmp == 'h' ) return usage_lf_em4x05_dump();

	// for now use default input of 1 as invalid (unlikely 1 will be a valid password...)
	pwd = param_get32ex(Cmd, 0, 1, 16);
	
	if ( pwd != 1 ) {
		usePwd = true;
	}
	int success = 1;
	for (; addr < 16; addr++) {
		if (addr == 2) {
			if (usePwd) {
				PrintAndLog("PWD Address %02u | %08X",addr,pwd);
			} else {
				PrintAndLog("PWD Address 02 | cannot read");
			}
		} else {
			//success &= EM4x05Read(addr, pwd, usePwd);
		}
	}

	return success;
}

int CmdEM4x05Read(const char *Cmd) {
	int addr, pwd;
	bool usePwd = false;
	uint8_t ctmp = param_getchar(Cmd, 0);
	if ( strlen(Cmd) == 0 || ctmp == 'H' || ctmp == 'h' ) return usage_lf_em4x05_read();

	addr = param_get8ex(Cmd, 0, -1, 10);
	pwd =  param_get32ex(Cmd, 1, -1, 16);
	
	if ( (addr > 15) || (addr < 0 ) || ( addr == -1) ) {
		PrintAndLog("Address must be between 0 and 15");
		return 1;
	}
	if ( pwd == -1 )
		PrintAndLog("Reading address %d", addr);
	else {
		usePwd = true;
		PrintAndLog("Reading address %d | password %08X", addr, pwd);
	}
	
	UsbCommand c = {CMD_EM4X_READ_WORD, {addr, pwd, usePwd}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;	
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)){
		PrintAndLog("Command timed out");
		return -1;
	}

	if (!downloadSamplesEM())
		return -1;
	
	int testLen = (GraphTraceLen < 1000) ? GraphTraceLen : 1000;
	if (graphJustNoise(GraphBuffer, testLen)) {
		PrintAndLog("Tag not found");
		return -1;
	}

	//attempt demod
	uint32_t word = 0;
	int isOk = demodEM4x05resp(&word);
	if (isOk)
		PrintAndLog("Got Address %02d | %08X",addr, word);
	else
		PrintAndLog("Read failed");
	
	return isOk;
}

int CmdEM4x05Write(const char *Cmd) {
	uint8_t ctmp = param_getchar(Cmd, 0);
	if ( strlen(Cmd) == 0 || ctmp == 'H' || ctmp == 'h' ) return usage_lf_em4x05_write();
	
	bool usePwd = false;		
	int addr = 16; // default to invalid address
	int data = 0xFFFFFFFF; // default to blank data
	int pwd = 0xFFFFFFFF; // default to blank password
	
	addr = param_get8ex(Cmd, 0, -1, 10);
	data = param_get32ex(Cmd, 1, -1, 16);
	pwd =  param_get32ex(Cmd, 2, -1, 16);
	
	if ( (addr > 15) || (addr < 0 ) || ( addr == -1) ) {
		PrintAndLog("Address must be between 0 and 15");
		return 1;
	}
	if ( pwd == -1 )
		PrintAndLog("Writing address %d data %08X", addr, data);	
	else {
		usePwd = true;
		PrintAndLog("Writing address %d data %08X using password %08X", addr, data, pwd);		
	}
	
	uint16_t flag = (addr << 8 ) | usePwd;
	
	UsbCommand c = {CMD_EM4X_WRITE_WORD, {flag, data, pwd}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;	
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)){
		PrintAndLog("Error occurred, device did not respond during write operation.");
		return -1;
	}
	
	if (!downloadSamplesEM())
		return -1;

	//todo: check response for 00001010 then write data for write confirmation!
	
	//attempt demod:
	//need 0 bits demoded (after preamble) to verify write cmd
	uint32_t dummy = 0;
	int isOk = demodEM4x05resp(&dummy);
	if (isOk)
		PrintAndLog("Write Verified");

	return isOk;
}

static command_t CommandTable[] = {
	{"help", 		CmdHelp, 			1, "This help"},
	{"410xdemod",	CmdEMdemodASK, 		0, "[findone] -- Extract ID from EM410x tag (option 0 for continuous loop, 1 for only 1 tag)"},  
	{"410xread",	CmdEM410xRead, 		1, "[clock rate] -- Extract ID from EM410x tag in GraphBuffer"},
	{"410xsim",		CmdEM410xSim, 		0, "<UID> -- Simulate EM410x tag"},
	{"410xwatch",	CmdEM410xWatch, 	0, "['h'] -- Watches for EM410x 125/134 kHz tags (option 'h' for 134)"},
	{"410xspoof",	CmdEM410xWatchnSpoof, 0, "['h'] --- Watches for EM410x 125/134 kHz tags, and replays them. (option 'h' for 134)" },
	{"410xwrite",	CmdEM410xWrite, 	0, "<UID> <'0' T5555> <'1' T55x7> [clock rate] -- Write EM410x UID to T5555(Q5) or T55x7 tag, optionally setting clock rate"},
	{"4x05read",	CmdEM4x05Read, 		0, "read word data from EM4205/4305"},
	{"4x05write",	CmdEM4x05Write,		0, "write word data to EM4205/4305"},
	{"4x05dump",	CmdEM4x05Dump,		0, "dump EM4205/4305 tag"},
	{"4x50read",	CmdEM4x50Read, 		0, "read word data from EM4x50"},
	{"4x50write",	CmdEM4x50Write, 	0, "write word data to EM4x50"},
	{"4x50dump",	CmdEM4x50Dump,		0, "dump EM4x50 tag"},
	{NULL, NULL, 0, NULL}
};

int CmdLFEM4X(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
