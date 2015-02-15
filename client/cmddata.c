//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data and Graph commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "proxmark3.h"
#include "data.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "util.h"
#include "cmdmain.h"
#include "cmddata.h"
#include "lfdemod.h"
#include "usb_cmd.h"

uint8_t DemodBuffer[MAX_DEMOD_BUF_LEN];
uint8_t g_debugMode;
int DemodBufferLen;
static int CmdHelp(const char *Cmd);

//set the demod buffer with given array of binary (one bit per byte)
//by marshmellow
void setDemodBuf(uint8_t *buff, size_t size, size_t startIdx)
{
	size_t i = 0;
	for (; i < size; i++){
		DemodBuffer[i]=buff[startIdx++];
	}
	DemodBufferLen=size;
	return;
}

int CmdSetDebugMode(const char *Cmd)
{
  int demod=0;
  sscanf(Cmd, "%i", &demod);
  g_debugMode=(uint8_t)demod;
  return 1;
}

//by marshmellow
void printDemodBuff()
{
	uint32_t i = 0;
	int bitLen = DemodBufferLen;
	if (bitLen<16) {
		PrintAndLog("no bits found in demod buffer");
		return;
	}
	if (bitLen>512) bitLen=512; //max output to 512 bits if we have more - should be plenty
		
	// ensure equally divided by 16
	bitLen &= 0xfff0;
	
	for (i = 0; i <= (bitLen-16); i+=16) {
		PrintAndLog("%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i",
			DemodBuffer[i],
			DemodBuffer[i+1],
			DemodBuffer[i+2],
			DemodBuffer[i+3],
			DemodBuffer[i+4],
			DemodBuffer[i+5],
			DemodBuffer[i+6],
			DemodBuffer[i+7],
			DemodBuffer[i+8],
			DemodBuffer[i+9],
			DemodBuffer[i+10],
			DemodBuffer[i+11],
			DemodBuffer[i+12],
			DemodBuffer[i+13],
			DemodBuffer[i+14],
			DemodBuffer[i+15]);
	}
	return;
}


int CmdAmp(const char *Cmd)
{
  int i, rising, falling;
  int max = INT_MIN, min = INT_MAX;

  for (i = 10; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] > max)
      max = GraphBuffer[i];
    if (GraphBuffer[i] < min)
      min = GraphBuffer[i];
  }

  if (max != min) {
    rising = falling= 0;
    for (i = 0; i < GraphTraceLen; ++i) {
      if (GraphBuffer[i + 1] < GraphBuffer[i]) {
        if (rising) {
          GraphBuffer[i] = max;
          rising = 0;
        }
        falling = 1;
      }
      if (GraphBuffer[i + 1] > GraphBuffer[i]) {
        if (falling) {
          GraphBuffer[i] = min;
          falling = 0;
        }
        rising= 1;
      }
    }
  }
  RepaintGraphWindow();
  return 0;
}

/*
 * Generic command to demodulate ASK.
 *
 * Argument is convention: positive or negative (High mod means zero
 * or high mod means one)
 *
 * Updates the Graph trace with 0/1 values
 *
 * Arguments:
 * c : 0 or 1
 */
 //this method is dependant on all highs and lows to be the same(or clipped)  this creates issues[marshmellow] it also ignores the clock
int Cmdaskdemod(const char *Cmd)
{
  int i;
  int c, high = 0, low = 0;

  // TODO: complain if we do not give 2 arguments here !
  // (AL - this doesn't make sense! we're only using one argument!!!)
  sscanf(Cmd, "%i", &c);

  /* Detect high and lows and clock */
	// (AL - clock???)
  for (i = 0; i < GraphTraceLen; ++i)
  {
    if (GraphBuffer[i] > high)
      high = GraphBuffer[i];
    else if (GraphBuffer[i] < low)
      low = GraphBuffer[i];
  }
  high=abs(high*.75);
  low=abs(low*.75);
  if (c != 0 && c != 1) {
    PrintAndLog("Invalid argument: %s", Cmd);
    return 0;
  }
  //prime loop
  if (GraphBuffer[0] > 0) {
    GraphBuffer[0] = 1-c;
  } else {
    GraphBuffer[0] = c;
  }
  for (i = 1; i < GraphTraceLen; ++i) {
    /* Transitions are detected at each peak
     * Transitions are either:
     * - we're low: transition if we hit a high
     * - we're high: transition if we hit a low
     * (we need to do it this way because some tags keep high or
     * low for long periods, others just reach the peak and go
     * down)
     */
    //[marhsmellow] change == to >= for high and <= for low for fuzz
    if ((GraphBuffer[i] == high) && (GraphBuffer[i - 1] == c)) {
      GraphBuffer[i] = 1 - c;
    } else if ((GraphBuffer[i] == low) && (GraphBuffer[i - 1] == (1 - c))){
      GraphBuffer[i] = c;
    } else {
      /* No transition */
      GraphBuffer[i] = GraphBuffer[i - 1];
    }
  }
  RepaintGraphWindow();
  return 0;
}

//by marshmellow
void printBitStream(uint8_t BitStream[], uint32_t bitLen)
{
	uint32_t i = 0;
	if (bitLen<16) {
		PrintAndLog("Too few bits found: %d",bitLen);
		return;
	}
	if (bitLen>512) bitLen=512;

	  // ensure equally divided by 16
	bitLen &= 0xfff0;


	for (i = 0; i <= (bitLen-16); i+=16) {
		PrintAndLog("%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i",
		  BitStream[i],
		  BitStream[i+1],
		  BitStream[i+2],
		  BitStream[i+3],
		  BitStream[i+4],
		  BitStream[i+5],
		  BitStream[i+6],
		  BitStream[i+7],
		  BitStream[i+8],
		  BitStream[i+9],
		  BitStream[i+10],
		  BitStream[i+11],
		  BitStream[i+12],
		  BitStream[i+13],
		  BitStream[i+14],
		  BitStream[i+15]);
	}
	return;
}
//by marshmellow
//print EM410x ID in multiple formats
void printEM410x(uint64_t id)
{
  if (id !=0){
    uint64_t iii=1;
    uint64_t id2lo=0;
    uint32_t ii=0;
    uint32_t i=0;
    for (ii=5; ii>0;ii--){
      for (i=0;i<8;i++){
        id2lo=(id2lo<<1LL) | ((id & (iii << (i+((ii-1)*8)))) >> (i+((ii-1)*8)));
      }
    }
    //output em id
    PrintAndLog("EM TAG ID    : %010llx", id);
    PrintAndLog("Unique TAG ID: %010llx",  id2lo);
    PrintAndLog("DEZ 8        : %08lld",id & 0xFFFFFF);
    PrintAndLog("DEZ 10       : %010lld",id & 0xFFFFFF);
    PrintAndLog("DEZ 5.5      : %05lld.%05lld",(id>>16LL) & 0xFFFF,(id & 0xFFFF));
    PrintAndLog("DEZ 3.5A     : %03lld.%05lld",(id>>32ll),(id & 0xFFFF));
    PrintAndLog("DEZ 14/IK2   : %014lld",id);
    PrintAndLog("DEZ 15/IK3   : %015lld",id2lo);
    PrintAndLog("Other        : %05lld_%03lld_%08lld",(id&0xFFFF),((id>>16LL) & 0xFF),(id & 0xFFFFFF));
  }
  return;
}

//by marshmellow
//takes 3 arguments - clock, invert and maxErr as integers
//attempts to demodulate ask while decoding manchester
//prints binary found and saves in graphbuffer for further commands
int CmdAskEM410xDemod(const char *Cmd)
{
  int invert=0;
  int clk=0;
  int maxErr=100;
  char cmdp = param_getchar(Cmd, 0);
  if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H') {
    PrintAndLog("Usage:  data askem410xdemod [clock] <0|1> [maxError]");
    PrintAndLog("     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLog("     <invert>, 1 for invert output");
    PrintAndLog("     [set maximum allowed errors], default = 100.");
    PrintAndLog("");
    PrintAndLog("    sample: data askem410xdemod        = demod an EM410x Tag ID from GraphBuffer");
    PrintAndLog("          : data askem410xdemod 32     = demod an EM410x Tag ID from GraphBuffer using a clock of RF/32");
    PrintAndLog("          : data askem410xdemod 32 1   = demod an EM410x Tag ID from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLog("          : data askem410xdemod 1      = demod an EM410x Tag ID from GraphBuffer while inverting data");
    PrintAndLog("          : data askem410xdemod 64 1 0 = demod an EM410x Tag ID from GraphBuffer using a clock of RF/64 and inverting data and allowing 0 demod errors");

    return 0;
  }


  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  sscanf(Cmd, "%i %i %i", &clk, &invert, &maxErr);
  if (invert != 0 && invert != 1) {
    PrintAndLog("Invalid argument: %s", Cmd);
    return 0;
  }
  size_t BitLen = getFromGraphBuf(BitStream);

  if (g_debugMode==1) PrintAndLog("DEBUG: Bitlen from grphbuff: %d",BitLen);
  if (BitLen==0) return 0;
  int errCnt=0;
  errCnt = askmandemod(BitStream, &BitLen, &clk, &invert, maxErr);
  if (errCnt<0||BitLen<16){  //if fatal error (or -1)
    if (g_debugMode==1) PrintAndLog("no data found %d, errors:%d, bitlen:%d, clock:%d",errCnt,invert,BitLen,clk);
    return 0;
  }
  PrintAndLog("\nUsing Clock: %d - Invert: %d - Bits Found: %d",clk,invert,BitLen);

  //output
  if (errCnt>0){
    PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d",errCnt);
  }
  //PrintAndLog("ASK/Manchester decoded bitstream:");
  // Now output the bitstream to the scrollback by line of 16 bits
  setDemodBuf(BitStream,BitLen,0);
  //printDemodBuff();
  uint64_t lo =0;
  size_t idx=0;
  lo = Em410xDecode(BitStream, &BitLen, &idx);
  if (lo>0){
    //set GraphBuffer for clone or sim command
    setDemodBuf(BitStream, BitLen, idx);
    if (g_debugMode){
      PrintAndLog("DEBUG: idx: %d, Len: %d, Printing Demod Buffer:", idx, BitLen);
      printDemodBuff();
    }
    PrintAndLog("EM410x pattern found: ");
    printEM410x(lo);
    return 1;
  }
  return 0;
}

//by marshmellow
//takes 3 arguments - clock, invert, maxErr as integers
//attempts to demodulate ask while decoding manchester
//prints binary found and saves in graphbuffer for further commands
int Cmdaskmandemod(const char *Cmd)
{
  int invert=0;
  int clk=0;
  int maxErr=100;
  char cmdp = param_getchar(Cmd, 0);
  if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H') {
    PrintAndLog("Usage:  data rawdemod am [clock] <0|1> [maxError]");
    PrintAndLog("     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLog("     <invert>, 1 for invert output");
    PrintAndLog("     [set maximum allowed errors], default = 100.");
    PrintAndLog("");
    PrintAndLog("    sample: data rawdemod am        = demod an ask/manchester tag from GraphBuffer");
    PrintAndLog("          : data rawdemod am 32     = demod an ask/manchester tag from GraphBuffer using a clock of RF/32");
    PrintAndLog("          : data rawdemod am 32 1   = demod an ask/manchester tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLog("          : data rawdemod am 1      = demod an ask/manchester tag from GraphBuffer while inverting data");
    PrintAndLog("          : data rawdemod am 64 1 0 = demod an ask/manchester tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");

    return 0;
  }
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  sscanf(Cmd, "%i %i %i", &clk, &invert, &maxErr);
  if (invert != 0 && invert != 1) {
    PrintAndLog("Invalid argument: %s", Cmd);
    return 0;
  }
  if (clk==1){
    invert=1;
    clk=0;
  }
  size_t BitLen = getFromGraphBuf(BitStream);
  if (g_debugMode==1) PrintAndLog("DEBUG: Bitlen from grphbuff: %d",BitLen);
  if (BitLen==0) return 0;
  int errCnt=0;
  errCnt = askmandemod(BitStream, &BitLen, &clk, &invert, maxErr);
  if (errCnt<0||BitLen<16){  //if fatal error (or -1)
    if (g_debugMode==1) PrintAndLog("no data found %d, errors:%d, bitlen:%d, clock:%d",errCnt,invert,BitLen,clk);
    return 0;
  }
  PrintAndLog("\nUsing Clock: %d - Invert: %d - Bits Found: %d",clk,invert,BitLen);

  //output
  if (errCnt>0){
    PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d",errCnt);
  }
  PrintAndLog("ASK/Manchester decoded bitstream:");
  // Now output the bitstream to the scrollback by line of 16 bits
  setDemodBuf(BitStream,BitLen,0);
  printDemodBuff();
  uint64_t lo =0;
  size_t idx=0;
  lo = Em410xDecode(BitStream, &BitLen, &idx);
  if (lo>0){
    //set GraphBuffer for clone or sim command
    setDemodBuf(BitStream, BitLen, idx);
    if (g_debugMode){
      PrintAndLog("DEBUG: idx: %d, Len: %d, Printing Demod Buffer:", idx, BitLen);
      printDemodBuff();
    }
    PrintAndLog("EM410x pattern found: ");
    printEM410x(lo);
    return 1;
  }
  return 1;
}

//by marshmellow
//manchester decode
//stricktly take 10 and 01 and convert to 0 and 1
int Cmdmandecoderaw(const char *Cmd)
{
  int i =0;
  int errCnt=0;
  size_t size=0;
  size_t maxErr = 20;
  char cmdp = param_getchar(Cmd, 0);
  if (strlen(Cmd) > 1 || cmdp == 'h' || cmdp == 'H') {
    PrintAndLog("Usage:  data manrawdecode");
    PrintAndLog("     Takes 10 and 01 and converts to 0 and 1 respectively");
    PrintAndLog("     --must have binary sequence in demodbuffer (run data askrawdemod first)");
    PrintAndLog("");
    PrintAndLog("    sample: data manrawdecode   = decode manchester bitstream from the demodbuffer");
    return 0;
  }
  if (DemodBufferLen==0) return 0;
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  int high=0,low=0;
  for (;i<DemodBufferLen;++i){
    if (DemodBuffer[i]>high) high=DemodBuffer[i];
    else if(DemodBuffer[i]<low) low=DemodBuffer[i];
    BitStream[i]=DemodBuffer[i];
  }
  if (high>1 || low <0 ){
    PrintAndLog("Error: please raw demod the wave first then mancheseter raw decode");
    return 0;
  }
  size=i;
  errCnt=manrawdecode(BitStream, &size);
  if (errCnt>=maxErr){
    PrintAndLog("Too many errors: %d",errCnt);
    return 0;
  }
  PrintAndLog("Manchester Decoded - # errors:%d - data:",errCnt);
  printBitStream(BitStream, size);
  if (errCnt==0){
    uint64_t id = 0;
    size_t idx=0;
    id = Em410xDecode(BitStream, &size, &idx);
    if (id>0){
      //need to adjust to set bitstream back to manchester encoded data
      //setDemodBuf(BitStream, size, idx);

      printEM410x(id);
    }
  }
  return 1;
}

//by marshmellow
//biphase decode
//take 01 or 10 = 0 and 11 or 00 = 1
//takes 2 arguments "offset" default = 0 if 1 it will shift the decode by one bit
// and "invert" default = 0 if 1 it will invert output
//  since it is not like manchester and doesn't have an incorrect bit pattern we
//  cannot determine if our decode is correct or if it should be shifted by one bit
//  the argument offset allows us to manually shift if the output is incorrect
//  (better would be to demod and decode at the same time so we can distinguish large
//    width waves vs small width waves to help the decode positioning) or askbiphdemod
int CmdBiphaseDecodeRaw(const char *Cmd)
{
	int i = 0;
	int errCnt=0;
	size_t size=0;
	int offset=0;
	int invert=0;
	int high=0, low=0;
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 3 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  data biphaserawdecode [offset] <invert>");
		PrintAndLog("     Converts 10 or 01 to 0 and 11 or 00 to 1");
		PrintAndLog("     --must have binary sequence in demodbuffer (run data askrawdemod first)");
		PrintAndLog("");
		PrintAndLog("     [offset <0|1>], set to 0 not to adjust start position or to 1 to adjust decode start position");
		PrintAndLog("     [invert <0|1>], set to 1 to invert output");
		PrintAndLog("");
		PrintAndLog("    sample: data biphaserawdecode     = decode biphase bitstream from the demodbuffer");
		PrintAndLog("    sample: data biphaserawdecode 1 1 = decode biphase bitstream from the demodbuffer, set offset, and invert output");
		return 0;
	}
	sscanf(Cmd, "%i %i", &offset, &invert);
	if (DemodBufferLen==0) return 0;
	uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
	//get graphbuffer & high and low
	for (;i<DemodBufferLen;++i){
		if(DemodBuffer[i]>high)high=DemodBuffer[i];
		else if(DemodBuffer[i]<low)low=DemodBuffer[i];
		BitStream[i]=DemodBuffer[i];
	}
	if (high>1 || low <0){
		PrintAndLog("Error: please raw demod the wave first then decode");
		return 0;
	}
	size=i;
	errCnt=BiphaseRawDecode(BitStream, &size, offset, invert);
	if (errCnt>=20){
		PrintAndLog("Too many errors attempting to decode: %d",errCnt);
		return 0;
	}
	PrintAndLog("Biphase Decoded using offset: %d - # errors:%d - data:",offset,errCnt);
	printBitStream(BitStream, size);
	PrintAndLog("\nif bitstream does not look right try offset=1");
	return 1;
}

//by marshmellow
//takes 4 arguments - clock, invert, maxErr as integers and amplify as char
//attempts to demodulate ask only
//prints binary found and saves in graphbuffer for further commands
int Cmdaskrawdemod(const char *Cmd)
{
  int invert=0;
  int clk=0;
  int maxErr=100;
  uint8_t askAmp = 0;
  char amp = param_getchar(Cmd, 0);
  char cmdp = param_getchar(Cmd, 0);
  if (strlen(Cmd) > 12 || cmdp == 'h' || cmdp == 'H') {
    PrintAndLog("Usage:  data rawdemod ar [clock] <invert> [maxError] [amplify]");
    PrintAndLog("     [set clock as integer] optional, if not set, autodetect");
    PrintAndLog("     <invert>, 1 to invert output");
    PrintAndLog("     [set maximum allowed errors], default = 100");
    PrintAndLog("     <amplify>, 'a' to attempt demod with ask amplification, default = no amp");
    PrintAndLog("");
    PrintAndLog("    sample: data rawdemod ar          = demod an ask tag from GraphBuffer");
    PrintAndLog("          : data rawdemod ar a        = demod an ask tag from GraphBuffer, amplified");
    PrintAndLog("          : data rawdemod ar 32       = demod an ask tag from GraphBuffer using a clock of RF/32");
    PrintAndLog("          : data rawdemod ar 32 1     = demod an ask tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLog("          : data rawdemod ar 1        = demod an ask tag from GraphBuffer while inverting data");
    PrintAndLog("          : data rawdemod ar 64 1 0   = demod an ask tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    PrintAndLog("          : data rawdemod ar 64 1 0 a = demod an ask tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors, and amp");
    return 0;
  }
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  sscanf(Cmd, "%i %i %i %c", &clk, &invert, &maxErr, &amp);
  if (invert != 0 && invert != 1) {
    PrintAndLog("Invalid argument: %s", Cmd);
    return 0;
  }
  if (clk==1){
    invert=1;
    clk=0;
  }
  if (amp == 'a' || amp == 'A') askAmp=1; 
  size_t BitLen = getFromGraphBuf(BitStream);
  if (BitLen==0) return 0;
  int errCnt=0;
  errCnt = askrawdemod(BitStream, &BitLen, &clk, &invert, maxErr, askAmp);
  if (errCnt==-1||BitLen<16){  //throw away static - allow 1 and -1 (in case of threshold command first)
    PrintAndLog("no data found");
    if (g_debugMode==1) PrintAndLog("errCnt: %d, BitLen: %d, clk: %d, invert: %d", errCnt, BitLen, clk, invert);
    return 0;
  }
  PrintAndLog("Using Clock: %d - invert: %d - Bits Found: %d", clk, invert, BitLen);
  
  //move BitStream back to DemodBuffer
  setDemodBuf(BitStream,BitLen,0);

  //output
  if (errCnt>0){
    PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d", errCnt);
  }
  PrintAndLog("ASK demoded bitstream:");
  // Now output the bitstream to the scrollback by line of 16 bits
  printBitStream(BitStream,BitLen);

  return 1;
}

int CmdAutoCorr(const char *Cmd)
{
  static int CorrelBuffer[MAX_GRAPH_TRACE_LEN];

  int window = atoi(Cmd);

  if (window == 0) {
    PrintAndLog("needs a window");
    return 0;
  }
  if (window >= GraphTraceLen) {
    PrintAndLog("window must be smaller than trace (%d samples)",
      GraphTraceLen);
    return 0;
  }

  PrintAndLog("performing %d correlations", GraphTraceLen - window);

  for (int i = 0; i < GraphTraceLen - window; ++i) {
    int sum = 0;
    for (int j = 0; j < window; ++j) {
      sum += (GraphBuffer[j]*GraphBuffer[i + j]) / 256;
    }
    CorrelBuffer[i] = sum;
  }
  GraphTraceLen = GraphTraceLen - window;
  memcpy(GraphBuffer, CorrelBuffer, GraphTraceLen * sizeof (int));

  RepaintGraphWindow();
  return 0;
}

int CmdBitsamples(const char *Cmd)
{
  int cnt = 0;
  uint8_t got[12288];

  GetFromBigBuf(got,sizeof(got),0);
  WaitForResponse(CMD_ACK,NULL);

    for (int j = 0; j < sizeof(got); j++) {
      for (int k = 0; k < 8; k++) {
        if(got[j] & (1 << (7 - k))) {
          GraphBuffer[cnt++] = 1;
        } else {
          GraphBuffer[cnt++] = 0;
        }
      }
  }
  GraphTraceLen = cnt;
  RepaintGraphWindow();
  return 0;
}

/*
 * Convert to a bitstream
 */
int CmdBitstream(const char *Cmd)
{
  int i, j;
  int bit;
  int gtl;
  int clock;
  int low = 0;
  int high = 0;
  int hithigh, hitlow, first;

  /* Detect high and lows and clock */
  for (i = 0; i < GraphTraceLen; ++i)
  {
    if (GraphBuffer[i] > high)
      high = GraphBuffer[i];
    else if (GraphBuffer[i] < low)
      low = GraphBuffer[i];
  }

  /* Get our clock */
  clock = GetAskClock(Cmd, high, 1);
  gtl = ClearGraph(0);

  bit = 0;
  for (i = 0; i < (int)(gtl / clock); ++i)
  {
    hithigh = 0;
    hitlow = 0;
    first = 1;
    /* Find out if we hit both high and low peaks */
    for (j = 0; j < clock; ++j)
    {
      if (GraphBuffer[(i * clock) + j] == high)
        hithigh = 1;
      else if (GraphBuffer[(i * clock) + j] == low)
        hitlow = 1;
      /* it doesn't count if it's the first part of our read
         because it's really just trailing from the last sequence */
      if (first && (hithigh || hitlow))
        hithigh = hitlow = 0;
      else
        first = 0;

      if (hithigh && hitlow)
        break;
    }

    /* If we didn't hit both high and low peaks, we had a bit transition */
    if (!hithigh || !hitlow)
      bit ^= 1;

    AppendGraph(0, clock, bit);
  }

  RepaintGraphWindow();
  return 0;
}

int CmdBuffClear(const char *Cmd)
{
  UsbCommand c = {CMD_BUFF_CLEAR};
  SendCommand(&c);
  ClearGraph(true);
  return 0;
}

int CmdDec(const char *Cmd)
{
  for (int i = 0; i < (GraphTraceLen / 2); ++i)
    GraphBuffer[i] = GraphBuffer[i * 2];
  GraphTraceLen /= 2;
  PrintAndLog("decimated by 2");
  RepaintGraphWindow();
  return 0;
}
/**
 * Undecimate - I'd call it 'interpolate', but we'll save that
 * name until someone does an actual interpolation command, not just
 * blindly repeating samples
 * @param Cmd
 * @return
 */
int CmdUndec(const char *Cmd)
{
	if(param_getchar(Cmd, 0) == 'h')
	{
		PrintAndLog("Usage: data undec [factor]");
		PrintAndLog("This function performs un-decimation, by repeating each sample N times");
		PrintAndLog("Options:        ");
		PrintAndLog("       h            This help");
		PrintAndLog("       factor       The number of times to repeat each sample.[default:2]");
		PrintAndLog("Example: 'data undec 3'");
		return 0;
	}

	uint8_t factor = param_get8ex(Cmd, 0,2, 10);
	//We have memory, don't we?
	int swap[MAX_GRAPH_TRACE_LEN] = { 0 };
	uint32_t g_index = 0 ,s_index = 0;
	while(g_index < GraphTraceLen && s_index < MAX_GRAPH_TRACE_LEN)
	{
		int count = 0;
		for(count = 0; count < factor && s_index+count < MAX_GRAPH_TRACE_LEN; count ++)
			swap[s_index+count] = GraphBuffer[g_index];
		s_index+=count;
	}

	memcpy(GraphBuffer,swap, s_index * sizeof(int));
	GraphTraceLen = s_index;
	RepaintGraphWindow();
	return 0;
}

//by marshmellow
//shift graph zero up or down based on input + or -
int CmdGraphShiftZero(const char *Cmd)
{

  int shift=0;
  //set options from parameters entered with the command
  sscanf(Cmd, "%i", &shift);
  int shiftedVal=0;
  for(int i = 0; i<GraphTraceLen; i++){
    shiftedVal=GraphBuffer[i]+shift;
    if (shiftedVal>127) 
      shiftedVal=127;
    else if (shiftedVal<-127) 
      shiftedVal=-127;
    GraphBuffer[i]= shiftedVal;
  }
  CmdNorm("");
  return 0;
}

//by marshmellow
//use large jumps in read samples to identify edges of waves and then amplify that wave to max
//similar to dirtheshold, threshold, and askdemod commands 
//takes a threshold length which is the measured length between two samples then determines an edge
int CmdAskEdgeDetect(const char *Cmd)
{
  int thresLen = 25;
  sscanf(Cmd, "%i", &thresLen); 
  int shift = 127;
  int shiftedVal=0;
  for(int i = 1; i<GraphTraceLen; i++){
    if (GraphBuffer[i]-GraphBuffer[i-1]>=thresLen) //large jump up
      shift=127;
    else if(GraphBuffer[i]-GraphBuffer[i-1]<=-1*thresLen) //large jump down
      shift=-127;

    shiftedVal=GraphBuffer[i]+shift;

    if (shiftedVal>127) 
      shiftedVal=127;
    else if (shiftedVal<-127) 
      shiftedVal=-127;
    GraphBuffer[i-1] = shiftedVal;
  }
  RepaintGraphWindow();
  //CmdNorm("");
  return 0;
}

/* Print our clock rate */
// uses data from graphbuffer
// adjusted to take char parameter for type of modulation to find the clock - by marshmellow.
int CmdDetectClockRate(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	if (strlen(Cmd) > 3 || strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  data detectclock [modulation]");
		PrintAndLog("     [modulation as char], specify the modulation type you want to detect the clock of");
		PrintAndLog("       'a' = ask, 'f' = fsk, 'n' = nrz/direct, 'p' = psk");
		PrintAndLog("");
		PrintAndLog("    sample: data detectclock a    = detect the clock of an ask modulated wave in the GraphBuffer");
		PrintAndLog("            data detectclock f    = detect the clock of an fsk modulated wave in the GraphBuffer");
		PrintAndLog("            data detectclock p    = detect the clock of an psk modulated wave in the GraphBuffer");
		PrintAndLog("            data detectclock n    = detect the clock of an nrz/direct modulated wave in the GraphBuffer");
	}
	int ans=0;
	if (cmdp == 'a'){
		ans = GetAskClock("", true, false);
	} else if (cmdp == 'f'){
		ans = GetFskClock("", true, false);
	} else if (cmdp == 'n'){
		ans = GetNrzClock("", true, false);
	} else if (cmdp == 'p'){
		ans = GetPskClock("", true, false);
	} else {
		PrintAndLog ("Please specify a valid modulation to detect the clock of - see option h for help");
	}
	return ans;
}

//by marshmellow
//fsk raw demod and print binary
//takes 4 arguments - Clock, invert, fchigh, fclow
//defaults: clock = 50, invert=1, fchigh=10, fclow=8 (RF/10 RF/8 (fsk2a))
int CmdFSKrawdemod(const char *Cmd)
{
  //raw fsk demod  no manchester decoding no start bit finding just get binary from wave
  //set defaults
  int rfLen = 0;
  int invert=0;
  int fchigh=0;
  int fclow=0;
  char cmdp = param_getchar(Cmd, 0);
  if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H') {
    PrintAndLog("Usage:  data rawdemod fs [clock] <invert> [fchigh] [fclow]");
    PrintAndLog("     [set clock as integer] optional, omit for autodetect.");
    PrintAndLog("     <invert>, 1 for invert output, can be used even if the clock is omitted");
    PrintAndLog("     [fchigh], larger field clock length, omit for autodetect");
    PrintAndLog("     [fclow], small field clock length, omit for autodetect");
    PrintAndLog("");
    PrintAndLog("    sample: data rawdemod fs           = demod an fsk tag from GraphBuffer using autodetect");
    PrintAndLog("          : data rawdemod fs 32        = demod an fsk tag from GraphBuffer using a clock of RF/32, autodetect fc");
    PrintAndLog("          : data rawdemod fs 1         = demod an fsk tag from GraphBuffer using autodetect, invert output");   
    PrintAndLog("          : data rawdemod fs 32 1      = demod an fsk tag from GraphBuffer using a clock of RF/32, invert output, autodetect fc");
    PrintAndLog("          : data rawdemod fs 64 0 8 5  = demod an fsk1 RF/64 tag from GraphBuffer");
    PrintAndLog("          : data rawdemod fs 50 0 10 8 = demod an fsk2 RF/50 tag from GraphBuffer");
    PrintAndLog("          : data rawdemod fs 50 1 10 8 = demod an fsk2a RF/50 tag from GraphBuffer");
    return 0;
  }
  //set options from parameters entered with the command
  sscanf(Cmd, "%i %i %i %i", &rfLen, &invert, &fchigh, &fclow);

  if (strlen(Cmd)>0 && strlen(Cmd)<=2) {
     if (rfLen==1){
      invert=1;   //if invert option only is used
      rfLen = 0;
     }
  }

  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  size_t BitLen = getFromGraphBuf(BitStream);
  if (BitLen==0) return 0;
  //get field clock lengths
  uint16_t fcs=0;
  uint8_t dummy=0;
  if (fchigh==0 || fclow == 0){
    fcs=countFC(BitStream, BitLen, &dummy);
    if (fcs==0){
      fchigh=10;
      fclow=8;
    }else{
      fchigh = (fcs >> 8) & 0xFF;
      fclow = fcs & 0xFF;
    }
  }
  //get bit clock length
  if (rfLen==0){
    rfLen = detectFSKClk(BitStream, BitLen, fchigh, fclow);
    if (rfLen == 0) rfLen = 50;
  }
  PrintAndLog("Args invert: %d - Clock:%d - fchigh:%d - fclow: %d",invert,rfLen,fchigh, fclow);
  int size = fskdemod(BitStream,BitLen,(uint8_t)rfLen,(uint8_t)invert,(uint8_t)fchigh,(uint8_t)fclow);
  if (size>0){
    PrintAndLog("FSK decoded bitstream:");
    setDemodBuf(BitStream,size,0);

    // Now output the bitstream to the scrollback by line of 16 bits
    if(size > (8*32)+2) size = (8*32)+2; //only output a max of 8 blocks of 32 bits  most tags will have full bit stream inside that sample size
    printBitStream(BitStream,size);
    return 1;
  } else{
    PrintAndLog("no FSK data found");
  }
  return 0;
}

//by marshmellow (based on existing demod + holiman's refactor)
//HID Prox demod - FSK RF/50 with preamble of 00011101 (then manchester encoded)
//print full HID Prox ID and some bit format details if found
int CmdFSKdemodHID(const char *Cmd)
{
  //raw fsk demod no manchester decoding no start bit finding just get binary from wave
  uint32_t hi2=0, hi=0, lo=0;

  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  size_t BitLen = getFromGraphBuf(BitStream);
  if (BitLen==0) return 0;
  //get binary from fsk wave
  int idx = HIDdemodFSK(BitStream,&BitLen,&hi2,&hi,&lo);
  if (idx<0){
    if (g_debugMode){
      if (idx==-1){
        PrintAndLog("DEBUG: Just Noise Detected");
      } else if (idx == -2) {
        PrintAndLog("DEBUG: Error demoding fsk");
      } else if (idx == -3) {
        PrintAndLog("DEBUG: Preamble not found");
      } else if (idx == -4) {
        PrintAndLog("DEBUG: Error in Manchester data, SIZE: %d", BitLen);
      } else {
        PrintAndLog("DEBUG: Error demoding fsk %d", idx);
      }   
    }
    return 0;
  }
  if (hi2==0 && hi==0 && lo==0) {
    if (g_debugMode) PrintAndLog("DEBUG: Error - no values found");
    return 0;
  }
  if (hi2 != 0){ //extra large HID tags
    PrintAndLog("HID Prox TAG ID: %x%08x%08x (%d)",
       (unsigned int) hi2, (unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF);
  }
  else {  //standard HID tags <38 bits
    uint8_t fmtLen = 0;
    uint32_t fc = 0;
    uint32_t cardnum = 0;
    if (((hi>>5)&1)==1){//if bit 38 is set then < 37 bit format is used
      uint32_t lo2=0;
      lo2=(((hi & 31) << 12) | (lo>>20)); //get bits 21-37 to check for format len bit
      uint8_t idx3 = 1;
      while(lo2>1){ //find last bit set to 1 (format len bit)
        lo2=lo2>>1;
        idx3++;
      }
      fmtLen =idx3+19;
      fc =0;
      cardnum=0;
      if(fmtLen==26){
        cardnum = (lo>>1)&0xFFFF;
        fc = (lo>>17)&0xFF;
      }
      if(fmtLen==34){
        cardnum = (lo>>1)&0xFFFF;
        fc= ((hi&1)<<15)|(lo>>17);
      }
      if(fmtLen==35){
        cardnum = (lo>>1)&0xFFFFF;
        fc = ((hi&1)<<11)|(lo>>21);
      }
    }
    else { //if bit 38 is not set then 37 bit format is used
      fmtLen = 37;
      fc = 0;
      cardnum = 0;
      if(fmtLen == 37){
        cardnum = (lo>>1)&0x7FFFF;
        fc = ((hi&0xF)<<12)|(lo>>20);
      }
    }
    PrintAndLog("HID Prox TAG ID: %x%08x (%d) - Format Len: %dbit - FC: %d - Card: %d",
      (unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF,
      (unsigned int) fmtLen, (unsigned int) fc, (unsigned int) cardnum);
  }
  setDemodBuf(BitStream,BitLen,idx);
  if (g_debugMode){ 
    PrintAndLog("DEBUG: idx: %d, Len: %d, Printing Demod Buffer:", idx, BitLen);
    printDemodBuff();
  }
  return 1;
}

//by marshmellow
//Paradox Prox demod - FSK RF/50 with preamble of 00001111 (then manchester encoded)
//print full Paradox Prox ID and some bit format details if found
int CmdFSKdemodParadox(const char *Cmd)
{
  //raw fsk demod no manchester decoding no start bit finding just get binary from wave
  uint32_t hi2=0, hi=0, lo=0;

  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  size_t BitLen = getFromGraphBuf(BitStream);
  if (BitLen==0) return 0;
  //get binary from fsk wave
  int idx = ParadoxdemodFSK(BitStream,&BitLen,&hi2,&hi,&lo);
  if (idx<0){
    if (g_debugMode){
      if (idx==-1){
        PrintAndLog("DEBUG: Just Noise Detected");     
      } else if (idx == -2) {
        PrintAndLog("DEBUG: Error demoding fsk");
      } else if (idx == -3) {
        PrintAndLog("DEBUG: Preamble not found");
      } else if (idx == -4) {
        PrintAndLog("DEBUG: Error in Manchester data");
      } else {
        PrintAndLog("DEBUG: Error demoding fsk %d", idx);
      }
    }
    return 0;
  }
  if (hi2==0 && hi==0 && lo==0){
    if (g_debugMode) PrintAndLog("DEBUG: Error - no value found");
    return 0;
  }
  uint32_t fc = ((hi & 0x3)<<6) | (lo>>26);
  uint32_t cardnum = (lo>>10)&0xFFFF;
  
  PrintAndLog("Paradox TAG ID: %x%08x - FC: %d - Card: %d - Checksum: %02x",
    hi>>10, (hi & 0x3)<<26 | (lo>>10), fc, cardnum, (lo>>2) & 0xFF );
  setDemodBuf(BitStream,BitLen,idx);
  if (g_debugMode){ 
    PrintAndLog("DEBUG: idx: %d, len: %d, Printing Demod Buffer:", idx, BitLen);
    printDemodBuff();
  }
  return 1;
}

//by marshmellow
//IO-Prox demod - FSK RF/64 with preamble of 000000001
//print ioprox ID and some format details
int CmdFSKdemodIO(const char *Cmd)
{
  //raw fsk demod no manchester decoding no start bit finding just get binary from wave
  //set defaults
  int idx=0;
  //something in graphbuffer?
  if (GraphTraceLen < 65) {
    if (g_debugMode)PrintAndLog("DEBUG: not enough samples in GraphBuffer");
    return 0;
  }
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  size_t BitLen = getFromGraphBuf(BitStream);
  if (BitLen==0) return 0;

  //get binary from fsk wave
  idx = IOdemodFSK(BitStream,BitLen);
  if (idx<0){
    if (g_debugMode){
      if (idx==-1){
        PrintAndLog("DEBUG: Just Noise Detected");     
      } else if (idx == -2) {
        PrintAndLog("DEBUG: not enough samples");
      } else if (idx == -3) {
        PrintAndLog("DEBUG: error during fskdemod");        
      } else if (idx == -4) {
        PrintAndLog("DEBUG: Preamble not found");
      } else if (idx == -5) {
        PrintAndLog("DEBUG: Separator bits not found");
      } else {
        PrintAndLog("DEBUG: Error demoding fsk %d", idx);
      }
    }
    return 0;
  }
  if (idx==0){
    if (g_debugMode==1){
      PrintAndLog("DEBUG: IO Prox Data not found - FSK Bits: %d",BitLen);
      if (BitLen > 92) printBitStream(BitStream,92);
    } 
    return 0;
  }
    //Index map
    //0           10          20          30          40          50          60
    //|           |           |           |           |           |           |
    //01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
    //-----------------------------------------------------------------------------
    //00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1 ???????? 11
    //
    //XSF(version)facility:codeone+codetwo (raw)
    //Handle the data
  if (idx+64>BitLen) {
    if (g_debugMode==1) PrintAndLog("not enough bits found - bitlen: %d",BitLen);
    return 0;
  }
  PrintAndLog("%d%d%d%d%d%d%d%d %d",BitStream[idx],    BitStream[idx+1],  BitStream[idx+2], BitStream[idx+3], BitStream[idx+4], BitStream[idx+5], BitStream[idx+6], BitStream[idx+7], BitStream[idx+8]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d",BitStream[idx+9],  BitStream[idx+10], BitStream[idx+11],BitStream[idx+12],BitStream[idx+13],BitStream[idx+14],BitStream[idx+15],BitStream[idx+16],BitStream[idx+17]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d facility",BitStream[idx+18], BitStream[idx+19], BitStream[idx+20],BitStream[idx+21],BitStream[idx+22],BitStream[idx+23],BitStream[idx+24],BitStream[idx+25],BitStream[idx+26]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d version",BitStream[idx+27], BitStream[idx+28], BitStream[idx+29],BitStream[idx+30],BitStream[idx+31],BitStream[idx+32],BitStream[idx+33],BitStream[idx+34],BitStream[idx+35]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d code1",BitStream[idx+36], BitStream[idx+37], BitStream[idx+38],BitStream[idx+39],BitStream[idx+40],BitStream[idx+41],BitStream[idx+42],BitStream[idx+43],BitStream[idx+44]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d code2",BitStream[idx+45], BitStream[idx+46], BitStream[idx+47],BitStream[idx+48],BitStream[idx+49],BitStream[idx+50],BitStream[idx+51],BitStream[idx+52],BitStream[idx+53]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d%d checksum",BitStream[idx+54],BitStream[idx+55],BitStream[idx+56],BitStream[idx+57],BitStream[idx+58],BitStream[idx+59],BitStream[idx+60],BitStream[idx+61],BitStream[idx+62],BitStream[idx+63]);

  uint32_t code = bytebits_to_byte(BitStream+idx,32);
  uint32_t code2 = bytebits_to_byte(BitStream+idx+32,32);
  uint8_t version = bytebits_to_byte(BitStream+idx+27,8); //14,4
  uint8_t facilitycode = bytebits_to_byte(BitStream+idx+18,8) ;
  uint16_t number = (bytebits_to_byte(BitStream+idx+36,8)<<8)|(bytebits_to_byte(BitStream+idx+45,8)); //36,9
  PrintAndLog("IO Prox XSF(%02d)%02x:%05d (%08x%08x)",version,facilitycode,number,code,code2);
  setDemodBuf(BitStream,64,idx);
  if (g_debugMode){
    PrintAndLog("DEBUG: idx: %d, Len: %d, Printing demod buffer:",idx,64);
    printDemodBuff();
  }
  return 1;
}

//by marshmellow
//AWID Prox demod - FSK RF/50 with preamble of 00000001  (always a 96 bit data stream)
//print full AWID Prox ID and some bit format details if found
int CmdFSKdemodAWID(const char *Cmd)
{

  //int verbose=1;
  //sscanf(Cmd, "%i", &verbose);

  //raw fsk demod no manchester decoding no start bit finding just get binary from wave
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  size_t size = getFromGraphBuf(BitStream);
  if (size==0) return 0;

  //get binary from fsk wave
  int idx = AWIDdemodFSK(BitStream, &size);
  if (idx<=0){
    if (g_debugMode==1){
      if (idx == -1)
        PrintAndLog("DEBUG: Error - not enough samples");
      else if (idx == -2)
        PrintAndLog("DEBUG: Error - only noise found");
      else if (idx == -3)
        PrintAndLog("DEBUG: Error - problem during FSK demod");
      else if (idx == -4)
        PrintAndLog("DEBUG: Error - AWID preamble not found");
      else if (idx == -5)
        PrintAndLog("DEBUG: Error - Size not correct: %d", size);
      else
        PrintAndLog("DEBUG: Error %d",idx);
    }
    return 0;
  }

  // Index map
  // 0            10            20            30              40            50              60
  // |            |             |             |               |             |               |
  // 01234567 890 1 234 5 678 9 012 3 456 7 890 1 234 5 678 9 012 3 456 7 890 1 234 5 678 9 012 3 - to 96
  // -----------------------------------------------------------------------------
  // 00000001 000 1 110 1 101 1 011 1 101 1 010 0 000 1 000 1 010 0 001 0 110 1 100 0 000 1 000 1
  // premable bbb o bbb o bbw o fff o fff o ffc o ccc o ccc o ccc o ccc o ccc o wxx o xxx o xxx o - to 96
  //          |---26 bit---|    |-----117----||-------------142-------------|
  // b = format bit len, o = odd parity of last 3 bits
  // f = facility code, c = card number
  // w = wiegand parity
  // (26 bit format shown)
 
  //get raw ID before removing parities
  uint32_t rawLo = bytebits_to_byte(BitStream+idx+64,32);
  uint32_t rawHi = bytebits_to_byte(BitStream+idx+32,32);
  uint32_t rawHi2 = bytebits_to_byte(BitStream+idx,32);
  setDemodBuf(BitStream,96,idx);

  size = removeParity(BitStream, idx+8, 4, 1, 88);
  if (size != 66){
    if (g_debugMode==1) PrintAndLog("DEBUG: Error - at parity check-tag size does not match AWID format");
    return 0;
  }
  // ok valid card found!

  // Index map
  // 0           10         20        30          40        50        60
  // |           |          |         |           |         |         |
  // 01234567 8 90123456 7890123456789012 3 456789012345678901234567890123456
  // -----------------------------------------------------------------------------
  // 00011010 1 01110101 0000000010001110 1 000000000000000000000000000000000
  // bbbbbbbb w ffffffff cccccccccccccccc w xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  // |26 bit|   |-117--| |-----142------|
  // b = format bit len, o = odd parity of last 3 bits
  // f = facility code, c = card number
  // w = wiegand parity
  // (26 bit format shown)

  uint32_t fc = 0;
  uint32_t cardnum = 0;
  uint32_t code1 = 0;
  uint32_t code2 = 0;
  uint8_t fmtLen = bytebits_to_byte(BitStream,8);
  if (fmtLen==26){
    fc = bytebits_to_byte(BitStream+9, 8);
    cardnum = bytebits_to_byte(BitStream+17, 16);
    code1 = bytebits_to_byte(BitStream+8,fmtLen);
    PrintAndLog("AWID Found - BitLength: %d, FC: %d, Card: %d - Wiegand: %x, Raw: %x%08x%08x", fmtLen, fc, cardnum, code1, rawHi2, rawHi, rawLo);
  } else {
    cardnum = bytebits_to_byte(BitStream+8+(fmtLen-17), 16);
    if (fmtLen>32){
      code1 = bytebits_to_byte(BitStream+8,fmtLen-32);
      code2 = bytebits_to_byte(BitStream+8+(fmtLen-32),32);
      PrintAndLog("AWID Found - BitLength: %d -unknown BitLength- (%d) - Wiegand: %x%08x, Raw: %x%08x%08x", fmtLen, cardnum, code1, code2, rawHi2, rawHi, rawLo);
    } else{
      code1 = bytebits_to_byte(BitStream+8,fmtLen);
      PrintAndLog("AWID Found - BitLength: %d -unknown BitLength- (%d) - Wiegand: %x, Raw: %x%08x%08x", fmtLen, cardnum, code1, rawHi2, rawHi, rawLo);
    }
  }
  if (g_debugMode){
    PrintAndLog("DEBUG: idx: %d, Len: %d Printing Demod Buffer:", idx, 96);
    printDemodBuff();
  }
  //todo - convert hi2, hi, lo to demodbuffer for future sim/clone commands
  return 1;
}

//by marshmellow
//Pyramid Prox demod - FSK RF/50 with preamble of 0000000000000001  (always a 128 bit data stream)
//print full Farpointe Data/Pyramid Prox ID and some bit format details if found
int CmdFSKdemodPyramid(const char *Cmd)
{
  //raw fsk demod no manchester decoding no start bit finding just get binary from wave
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  size_t size = getFromGraphBuf(BitStream);
  if (size==0) return 0;

  //get binary from fsk wave
  int idx = PyramiddemodFSK(BitStream, &size);
  if (idx < 0){
    if (g_debugMode==1){
      if (idx == -5)
        PrintAndLog("DEBUG: Error - not enough samples");
      else if (idx == -1)
        PrintAndLog("DEBUG: Error - only noise found");
      else if (idx == -2)
        PrintAndLog("DEBUG: Error - problem during FSK demod");
      else if (idx == -3)
        PrintAndLog("DEBUG: Error - Size not correct: %d", size);
      else if (idx == -4)
        PrintAndLog("DEBUG: Error - Pyramid preamble not found");
      else
        PrintAndLog("DEBUG: Error - idx: %d",idx);
    }
    return 0;
  }
  // Index map
  // 0           10          20          30            40          50          60
  // |           |           |           |             |           |           |
  // 0123456 7 8901234 5 6789012 3 4567890 1 2345678 9 0123456 7 8901234 5 6789012 3
  // -----------------------------------------------------------------------------
  // 0000000 0 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1
  // premable  xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o

  // 64    70            80          90          100         110           120
  // |     |             |           |           |           |             |
  // 4567890 1 2345678 9 0123456 7 8901234 5 6789012 3 4567890 1 2345678 9 0123456 7
  // -----------------------------------------------------------------------------
  // 0000000 1 0000000 1 0000000 1 0110111 0 0011000 1 0000001 0 0001100 1 1001010 0
  // xxxxxxx o xxxxxxx o xxxxxxx o xswffff o ffffccc o ccccccc o ccccccw o ppppppp o
  //                                  |---115---||---------71---------|
  // s = format start bit, o = odd parity of last 7 bits
  // f = facility code, c = card number
  // w = wiegand parity, x = extra space for other formats
  // p = unknown checksum
  // (26 bit format shown)
  
  //get raw ID before removing parities
  uint32_t rawLo = bytebits_to_byte(BitStream+idx+96,32);
  uint32_t rawHi = bytebits_to_byte(BitStream+idx+64,32);
  uint32_t rawHi2 = bytebits_to_byte(BitStream+idx+32,32);
  uint32_t rawHi3 = bytebits_to_byte(BitStream+idx,32);
  setDemodBuf(BitStream,128,idx);

  size = removeParity(BitStream, idx+8, 8, 1, 120);
  if (size != 105){
    if (g_debugMode==1) PrintAndLog("DEBUG: Error at parity check-tag size does not match Pyramid format, SIZE: %d, IDX: %d, hi3: %x",size, idx, rawHi3);
    return 0;
  }

  // ok valid card found!

  // Index map
  // 0         10        20        30        40        50        60        70
  // |         |         |         |         |         |         |         |
  // 01234567890123456789012345678901234567890123456789012345678901234567890
  // -----------------------------------------------------------------------
  // 00000000000000000000000000000000000000000000000000000000000000000000000
  // xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

  // 71         80         90          100
  // |          |          |           |
  // 1 2 34567890 1234567890123456 7 8901234
  // ---------------------------------------
  // 1 1 01110011 0000000001000110 0 1001010
  // s w ffffffff cccccccccccccccc w ppppppp
  //     |--115-| |------71------|
  // s = format start bit, o = odd parity of last 7 bits
  // f = facility code, c = card number
  // w = wiegand parity, x = extra space for other formats
  // p = unknown checksum
  // (26 bit format shown)

  //find start bit to get fmtLen
  int j;
  for (j=0; j<size; j++){
    if(BitStream[j]) break;
  }
  uint8_t fmtLen = size-j-8;
  uint32_t fc = 0;
  uint32_t cardnum = 0;
  uint32_t code1 = 0;
  //uint32_t code2 = 0;
  if (fmtLen==26){
    fc = bytebits_to_byte(BitStream+73, 8);
    cardnum = bytebits_to_byte(BitStream+81, 16);
    code1 = bytebits_to_byte(BitStream+72,fmtLen);
    PrintAndLog("Pyramid ID Found - BitLength: %d, FC: %d, Card: %d - Wiegand: %x, Raw: %x%08x%08x%08x", fmtLen, fc, cardnum, code1, rawHi3, rawHi2, rawHi, rawLo);
  } else if (fmtLen==45){
    fmtLen=42; //end = 10 bits not 7 like 26 bit fmt
    fc = bytebits_to_byte(BitStream+53, 10);
    cardnum = bytebits_to_byte(BitStream+63, 32);
    PrintAndLog("Pyramid ID Found - BitLength: %d, FC: %d, Card: %d - Raw: %x%08x%08x%08x", fmtLen, fc, cardnum, rawHi3, rawHi2, rawHi, rawLo);
  } else {
    cardnum = bytebits_to_byte(BitStream+81, 16);
    if (fmtLen>32){
      //code1 = bytebits_to_byte(BitStream+(size-fmtLen),fmtLen-32);
      //code2 = bytebits_to_byte(BitStream+(size-32),32);
      PrintAndLog("Pyramid ID Found - BitLength: %d -unknown BitLength- (%d), Raw: %x%08x%08x%08x", fmtLen, cardnum, rawHi3, rawHi2, rawHi, rawLo);
    } else{
      //code1 = bytebits_to_byte(BitStream+(size-fmtLen),fmtLen);
      PrintAndLog("Pyramid ID Found - BitLength: %d -unknown BitLength- (%d), Raw: %x%08x%08x%08x", fmtLen, cardnum, rawHi3, rawHi2, rawHi, rawLo);
    }
  }
  if (g_debugMode){
    PrintAndLog("DEBUG: idx: %d, Len: %d, Printing Demod Buffer:", idx, 128);
    printDemodBuff();
  }
  return 1;
}

int CmdFSKdemod(const char *Cmd) //old CmdFSKdemod needs updating
{
  static const int LowTone[]  = {
    1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
    1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
    1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
    1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
    1,  1,  1,  1,  1, -1, -1, -1, -1, -1
  };
  static const int HighTone[] = {
    1,  1,  1,  1,  1,     -1, -1, -1, -1,
    1,  1,  1,  1,         -1, -1, -1, -1,
    1,  1,  1,  1,         -1, -1, -1, -1,
    1,  1,  1,  1,         -1, -1, -1, -1,
    1,  1,  1,  1,         -1, -1, -1, -1,
    1,  1,  1,  1,     -1, -1, -1, -1, -1,
  };

  int lowLen = sizeof (LowTone) / sizeof (int);
  int highLen = sizeof (HighTone) / sizeof (int);
  int convLen = (highLen > lowLen) ? highLen : lowLen;
  uint32_t hi = 0, lo = 0;

  int i, j;
  int minMark = 0, maxMark = 0;

  for (i = 0; i < GraphTraceLen - convLen; ++i) {
    int lowSum = 0, highSum = 0;

    for (j = 0; j < lowLen; ++j) {
      lowSum += LowTone[j]*GraphBuffer[i+j];
    }
    for (j = 0; j < highLen; ++j) {
      highSum += HighTone[j] * GraphBuffer[i + j];
    }
    lowSum = abs(100 * lowSum / lowLen);
    highSum = abs(100 * highSum / highLen);
    GraphBuffer[i] = (highSum << 16) | lowSum;
  }

  for(i = 0; i < GraphTraceLen - convLen - 16; ++i) {
    int lowTot = 0, highTot = 0;
    // 10 and 8 are f_s divided by f_l and f_h, rounded
    for (j = 0; j < 10; ++j) {
      lowTot += (GraphBuffer[i+j] & 0xffff);
    }
    for (j = 0; j < 8; j++) {
      highTot += (GraphBuffer[i + j] >> 16);
    }
    GraphBuffer[i] = lowTot - highTot;
    if (GraphBuffer[i] > maxMark) maxMark = GraphBuffer[i];
    if (GraphBuffer[i] < minMark) minMark = GraphBuffer[i];
  }

  GraphTraceLen -= (convLen + 16);
  RepaintGraphWindow();

  // Find bit-sync (3 lo followed by 3 high) (HID ONLY)
  int max = 0, maxPos = 0;
  for (i = 0; i < 6000; ++i) {
    int dec = 0;
    for (j = 0; j < 3 * lowLen; ++j) {
      dec -= GraphBuffer[i + j];
    }
    for (; j < 3 * (lowLen + highLen ); ++j) {
      dec += GraphBuffer[i + j];
    }
    if (dec > max) {
      max = dec;
      maxPos = i;
    }
  }

  // place start of bit sync marker in graph
  GraphBuffer[maxPos] = maxMark;
  GraphBuffer[maxPos + 1] = minMark;

  maxPos += j;

  // place end of bit sync marker in graph
  GraphBuffer[maxPos] = maxMark;
  GraphBuffer[maxPos+1] = minMark;

  PrintAndLog("actual data bits start at sample %d", maxPos);
  PrintAndLog("length %d/%d", highLen, lowLen);

  uint8_t bits[46] = {0x00};

  // find bit pairs and manchester decode them
  for (i = 0; i < arraylen(bits) - 1; ++i) {
    int dec = 0;
    for (j = 0; j < lowLen; ++j) {
      dec -= GraphBuffer[maxPos + j];
    }
    for (; j < lowLen + highLen; ++j) {
      dec += GraphBuffer[maxPos + j];
    }
    maxPos += j;
    // place inter bit marker in graph
    GraphBuffer[maxPos] = maxMark;
    GraphBuffer[maxPos + 1] = minMark;

    // hi and lo form a 64 bit pair
    hi = (hi << 1) | (lo >> 31);
    lo = (lo << 1);
    // store decoded bit as binary (in hi/lo) and text (in bits[])
    if(dec < 0) {
      bits[i] = '1';
      lo |= 1;
    } else {
      bits[i] = '0';
    }
  }
  PrintAndLog("bits: '%s'", bits);
  PrintAndLog("hex: %08x %08x", hi, lo);
  return 0;
}

//by marshmellow
//attempt to psk1 demod graph buffer
int PSKDemod(const char *Cmd, uint8_t verbose)
{
  int invert=0;
  int clk=0;
  int maxErr=100;
  sscanf(Cmd, "%i %i %i", &clk, &invert, &maxErr);
  if (clk==1){
    invert=1;
    clk=0;
  }
  if (invert != 0 && invert != 1) {
    PrintAndLog("Invalid argument: %s", Cmd);
    return -1;
  }
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  size_t BitLen = getFromGraphBuf(BitStream);
  if (BitLen==0) return 0;
  int errCnt=0;
  errCnt = pskRawDemod(BitStream, &BitLen,&clk,&invert);
  if (errCnt > maxErr){
    if (g_debugMode==1) PrintAndLog("Too many errors found, clk: %d, invert: %d, numbits: %d, errCnt: %d",clk,invert,BitLen,errCnt);
    return -1;
  } 
  if (errCnt<0|| BitLen<16){  //throw away static - allow 1 and -1 (in case of threshold command first)
    if (g_debugMode==1) PrintAndLog("no data found, clk: %d, invert: %d, numbits: %d, errCnt: %d",clk,invert,BitLen,errCnt);
    return -1;
  }
  if (verbose) PrintAndLog("Tried PSK Demod using Clock: %d - invert: %d - Bits Found: %d",clk,invert,BitLen);
  //prime demod buffer for output
  setDemodBuf(BitStream,BitLen,0);
  return errCnt;
}

// Indala 26 bit decode
// by marshmellow
// optional arguments - same as CmdpskNRZrawDemod (clock & invert)
int CmdIndalaDecode(const char *Cmd)
{
	int ans;
	if (strlen(Cmd)>0){
		ans = PSKDemod(Cmd, 0);
	} else{ //default to RF/32
		ans = PSKDemod("32", 0);
	}

	if (ans < 0){
		if (g_debugMode==1) 
			PrintAndLog("Error1: %d",ans);
		return 0;
	}
	uint8_t invert=0;
	ans = indala26decode(DemodBuffer,(size_t *) &DemodBufferLen, &invert);
	if (ans < 1) {
		if (g_debugMode==1)
			PrintAndLog("Error2: %d",ans);
		return -1;
	}
	char showbits[251]={0x00};
	if (invert)
		if (g_debugMode==1)
 			PrintAndLog("Had to invert bits");

	//convert UID to HEX
	uint32_t uid1, uid2, uid3, uid4, uid5, uid6, uid7;
	int idx;
	uid1=0;
	uid2=0;
	PrintAndLog("BitLen: %d",DemodBufferLen);
	if (DemodBufferLen==64){
		for( idx=0; idx<64; idx++) {
			uid1=(uid1<<1)|(uid2>>31);
			if (DemodBuffer[idx] == 0) {
				uid2=(uid2<<1)|0;
				showbits[idx]='0';
			} else {
				uid2=(uid2<<1)|1;
				showbits[idx]='1';
			}
		}
		showbits[idx]='\0';
		PrintAndLog("Indala UID=%s (%x%08x)", showbits, uid1, uid2);
	}
	else {
		uid3=0;
		uid4=0;
		uid5=0;
		uid6=0;
		uid7=0;
		for( idx=0; idx<DemodBufferLen; idx++) {
			uid1=(uid1<<1)|(uid2>>31);
			uid2=(uid2<<1)|(uid3>>31);
			uid3=(uid3<<1)|(uid4>>31);
			uid4=(uid4<<1)|(uid5>>31);
			uid5=(uid5<<1)|(uid6>>31);
			uid6=(uid6<<1)|(uid7>>31);
			if (DemodBuffer[idx] == 0) {
				uid7=(uid7<<1)|0;
				showbits[idx]='0';
			}
			else {
				uid7=(uid7<<1)|1;
				showbits[idx]='1';
			}
		}
		showbits[idx]='\0';
		PrintAndLog("Indala UID=%s (%x%08x%08x%08x%08x%08x%08x)", showbits, uid1, uid2, uid3, uid4, uid5, uid6, uid7);
	}
	if (g_debugMode){
		PrintAndLog("DEBUG: printing demodbuffer:");
		printDemodBuff();
	}
	return 1;
}

// by marshmellow
// takes 3 arguments - clock, invert, maxErr as integers
// attempts to demodulate nrz only
// prints binary found and saves in demodbuffer for further commands
int CmdNRZrawDemod(const char *Cmd)
{
  int invert=0;
  int clk=0;
  int maxErr=100;
  char cmdp = param_getchar(Cmd, 0);
  if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H') {
    PrintAndLog("Usage:  data rawdemod nr [clock] <0|1> [maxError]");
    PrintAndLog("     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLog("     <invert>, 1 for invert output");
    PrintAndLog("     [set maximum allowed errors], default = 100.");
    PrintAndLog("");
    PrintAndLog("    sample: data nrzrawdemod        = demod a nrz/direct tag from GraphBuffer");
    PrintAndLog("          : data nrzrawdemod 32     = demod a nrz/direct tag from GraphBuffer using a clock of RF/32");
    PrintAndLog("          : data nrzrawdemod 32 1   = demod a nrz/direct tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLog("          : data nrzrawdemod 1      = demod a nrz/direct tag from GraphBuffer while inverting data");
    PrintAndLog("          : data nrzrawdemod 64 1 0 = demod a nrz/direct tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");

    return 0;
  }
 
  sscanf(Cmd, "%i %i %i", &clk, &invert, &maxErr);
  if (clk==1){
    invert=1;
    clk=0;
  }
  if (invert != 0 && invert != 1) {
    PrintAndLog("Invalid argument: %s", Cmd);
    return 0;
  }
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  size_t BitLen = getFromGraphBuf(BitStream);
  if (BitLen==0) return 0;
  int errCnt=0;
  errCnt = nrzRawDemod(BitStream, &BitLen, &clk, &invert, maxErr);
  if (errCnt > maxErr){
    if (g_debugMode==1) PrintAndLog("Too many errors found, clk: %d, invert: %d, numbits: %d, errCnt: %d",clk,invert,BitLen,errCnt);
    return 0;
  } 
  if (errCnt<0|| BitLen<16){  //throw away static - allow 1 and -1 (in case of threshold command first)
    if (g_debugMode==1) PrintAndLog("no data found, clk: %d, invert: %d, numbits: %d, errCnt: %d",clk,invert,BitLen,errCnt);
    return 0;
  }
  PrintAndLog("Tried NRZ Demod using Clock: %d - invert: %d - Bits Found: %d",clk,invert,BitLen);
  //prime demod buffer for output
  setDemodBuf(BitStream,BitLen,0);

  if (errCnt>0){
    PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d",errCnt);
  }else{
  }
  PrintAndLog("NRZ demoded bitstream:");
  // Now output the bitstream to the scrollback by line of 16 bits
  printDemodBuff();
  return 1;
}

// by marshmellow
// takes 3 arguments - clock, invert, maxErr as integers
// attempts to demodulate psk only
// prints binary found and saves in demodbuffer for further commands
int CmdPSK1rawDemod(const char *Cmd)
{
  int errCnt;
  char cmdp = param_getchar(Cmd, 0);
  if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H') {
    PrintAndLog("Usage:  data rawdemod p1 [clock] <0|1> [maxError]");
    PrintAndLog("     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLog("     <invert>, 1 for invert output");
    PrintAndLog("     [set maximum allowed errors], default = 100.");
    PrintAndLog("");
    PrintAndLog("    sample: data psk1rawdemod        = demod a psk1 tag from GraphBuffer");
    PrintAndLog("          : data psk1rawdemod 32     = demod a psk1 tag from GraphBuffer using a clock of RF/32");
    PrintAndLog("          : data psk1rawdemod 32 1   = demod a psk1 tag from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLog("          : data psk1rawdemod 1      = demod a psk1 tag from GraphBuffer while inverting data");
    PrintAndLog("          : data psk1rawdemod 64 1 0 = demod a psk1 tag from GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors");
    return 0;
  }
  errCnt = PSKDemod(Cmd, 1);
  //output
  if (errCnt<0){
    if (g_debugMode) PrintAndLog("Error demoding: %d",errCnt); 
    return 0;
  }
  if (errCnt>0){
    PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d",errCnt);
  }else{
  }
  PrintAndLog("PSK demoded bitstream:");
  // Now output the bitstream to the scrollback by line of 16 bits
  printDemodBuff();
  return 1;
}

// by marshmellow
// takes same args as cmdpsk1rawdemod
int CmdPSK2rawDemod(const char *Cmd)
{
  int errCnt=0;
  char cmdp = param_getchar(Cmd, 0);
  if (strlen(Cmd) > 10 || cmdp == 'h' || cmdp == 'H') {
    PrintAndLog("Usage:  data rawdemod p2 [clock] <0|1> [maxError]");
    PrintAndLog("     [set clock as integer] optional, if not set, autodetect.");
    PrintAndLog("     <invert>, 1 for invert output");
    PrintAndLog("     [set maximum allowed errors], default = 100.");
    PrintAndLog("");
    PrintAndLog("    sample: data psk2rawdemod        = demod a psk2 tag from GraphBuffer, autodetect clock");
    PrintAndLog("          : data psk2rawdemod 32     = demod a psk2 tag from GraphBuffer using a clock of RF/32");
    PrintAndLog("          : data psk2rawdemod 32 1   = demod a psk2 tag from GraphBuffer using a clock of RF/32 and inverting output");
    PrintAndLog("          : data psk2rawdemod 1      = demod a psk2 tag from GraphBuffer, autodetect clock and invert output");
    PrintAndLog("          : data psk2rawdemod 64 1 0 = demod a psk2 tag from GraphBuffer using a clock of RF/64, inverting output and allowing 0 demod errors");
    return 0;
  }
  errCnt=PSKDemod(Cmd, 1);
  if (errCnt<0){
    if (g_debugMode) PrintAndLog("Error demoding: %d",errCnt);  
    return 0;
  } 
  psk1TOpsk2(DemodBuffer, DemodBufferLen);
  if (errCnt>0){
    if (g_debugMode){
      PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d",errCnt);
      PrintAndLog("PSK2 demoded bitstream:");
      // Now output the bitstream to the scrollback by line of 16 bits
      printDemodBuff();
    }
  }else{
    PrintAndLog("PSK2 demoded bitstream:");
    // Now output the bitstream to the scrollback by line of 16 bits
    printDemodBuff();  
  }
  return 1;
}

// by marshmellow - combines all raw demod functions into one menu command
int CmdRawDemod(const char *Cmd)
{
	char cmdp = Cmd[0]; //param_getchar(Cmd, 0);

	if (strlen(Cmd) > 14 || cmdp == 'h' || cmdp == 'H' || strlen(Cmd)<2) {
		PrintAndLog("Usage:  data rawdemod [modulation] <help>|<options>");
		PrintAndLog("   [modulation] as 2 char, 'am' for ask/manchester, 'ar' for ask/raw, 'fs' for fsk, 'nr' for nrz/direct, 'p1' for psk1, 'p2' for psk2");		
		PrintAndLog("   <help> as 'h', prints the help for the specific modulation");	
		PrintAndLog("   <options> see specific modulation help for optional parameters");				
		PrintAndLog("");
		PrintAndLog("    sample: data rawdemod fs h         = print help for ask/raw demod");
		PrintAndLog("          : data rawdemod fs           = demod GraphBuffer using: fsk - autodetect");
		PrintAndLog("          : data rawdemod am           = demod GraphBuffer using: ask/manchester - autodetect");
		PrintAndLog("          : data rawdemod ar           = demod GraphBuffer using: ask/raw - autodetect");
		PrintAndLog("          : data rawdemod nr           = demod GraphBuffer using: nrz/direct - autodetect");
		PrintAndLog("          : data rawdemod p1           = demod GraphBuffer using: psk1 - autodetect");
		PrintAndLog("          : data rawdemod p2           = demod GraphBuffer using: psk2 - autodetect");
		return 0;
	}
	char cmdp2 = Cmd[1];
	int ans = 0;
	if (cmdp == 'f' && cmdp2 == 's'){
		ans = CmdFSKrawdemod(Cmd+3);
	} else if(cmdp == 'a' && cmdp2 == 'm'){
		ans = Cmdaskmandemod(Cmd+3);
	} else if(cmdp == 'a' && cmdp2 == 'r'){
		ans = Cmdaskrawdemod(Cmd+3);
	} else if(cmdp == 'n' && cmdp2 == 'r'){
		ans = CmdNRZrawDemod(Cmd+3);
	} else if(cmdp == 'p' && cmdp2 == '1'){
		ans = CmdPSK1rawDemod(Cmd+3);
	} else if(cmdp == 'p' && cmdp2 == '2'){
		ans = CmdPSK2rawDemod(Cmd+3);
	} else { 
		PrintAndLog("unknown modulation entered - see help ('h') for parameter structure");
	}
	return ans;
}

int CmdGrid(const char *Cmd)
{
  sscanf(Cmd, "%i %i", &PlotGridX, &PlotGridY);
  PlotGridXdefault= PlotGridX;
  PlotGridYdefault= PlotGridY;
  RepaintGraphWindow();
  return 0;
}

int CmdHexsamples(const char *Cmd)
{
  int i, j;
  int requested = 0;
  int offset = 0;
  char string_buf[25];
  char* string_ptr = string_buf;
  uint8_t got[BIGBUF_SIZE];

  sscanf(Cmd, "%i %i", &requested, &offset);

  /* if no args send something */
  if (requested == 0) {
    requested = 8;
  }
  if (offset + requested > sizeof(got)) {
    PrintAndLog("Tried to read past end of buffer, <bytes> + <offset> > %d", BIGBUF_SIZE);
    return 0;
	}

  GetFromBigBuf(got,requested,offset);
  WaitForResponse(CMD_ACK,NULL);

  i = 0;
  for (j = 0; j < requested; j++) {
    i++;
    string_ptr += sprintf(string_ptr, "%02x ", got[j]);
    if (i == 8) {
      *(string_ptr - 1) = '\0';    // remove the trailing space
      PrintAndLog("%s", string_buf);
      string_buf[0] = '\0';
      string_ptr = string_buf;
      i = 0;
    }
    if (j == requested - 1 && string_buf[0] != '\0') { // print any remaining bytes
      *(string_ptr - 1) = '\0';
      PrintAndLog("%s", string_buf);
      string_buf[0] = '\0';
    }
  }
  return 0;
}

int CmdHide(const char *Cmd)
{
  HideGraphWindow();
  return 0;
}

int CmdHpf(const char *Cmd)
{
  int i;
  int accum = 0;

  for (i = 10; i < GraphTraceLen; ++i)
    accum += GraphBuffer[i];
  accum /= (GraphTraceLen - 10);
  for (i = 0; i < GraphTraceLen; ++i)
    GraphBuffer[i] -= accum;

  RepaintGraphWindow();
  return 0;
}
typedef struct {
	uint8_t * buffer;
	uint32_t numbits;
	uint32_t position;
}BitstreamOut;

bool _headBit( BitstreamOut *stream)
{
	int bytepos = stream->position >> 3; // divide by 8
	int bitpos = (stream->position++) & 7; // mask out 00000111
	return (*(stream->buffer + bytepos) >> (7-bitpos)) & 1;
}

uint8_t getByte(uint8_t bits_per_sample, BitstreamOut* b)
{
	int i;
	uint8_t val = 0;
	for(i =0 ; i < bits_per_sample; i++)
	{
		val |= (_headBit(b) << (7-i));
	}
	return val;
}

int CmdSamples(const char *Cmd)
{
	//If we get all but the last byte in bigbuf,
	// we don't have to worry about remaining trash
	// in the last byte in case the bits-per-sample
	// does not line up on byte boundaries
	uint8_t got[BIGBUF_SIZE-1] = { 0 };

	int n = strtol(Cmd, NULL, 0);
	if (n == 0)
		n = sizeof(got);

	if (n > sizeof(got))
		n = sizeof(got);

	PrintAndLog("Reading %d bytes from device memory\n", n);
	GetFromBigBuf(got,n,0);
	PrintAndLog("Data fetched");
	UsbCommand response;
	WaitForResponse(CMD_ACK, &response);
	uint8_t bits_per_sample = 8;

	//Old devices without this feature would send 0 at arg[0]
	if(response.arg[0] > 0)
	{
		sample_config *sc = (sample_config *) response.d.asBytes;
		PrintAndLog("Samples @ %d bits/smpl, decimation 1:%d ", sc->bits_per_sample
					, sc->decimation);
		bits_per_sample = sc->bits_per_sample;
	}
	if(bits_per_sample < 8)
	{
		PrintAndLog("Unpacking...");
		BitstreamOut bout = { got, bits_per_sample * n,  0};
		int j =0;
		for (j = 0; j * bits_per_sample < n * 8 && j < sizeof(GraphBuffer); j++) {
			uint8_t sample = getByte(bits_per_sample, &bout);
			GraphBuffer[j] = ((int) sample )- 128;
		}
		GraphTraceLen = j;
		PrintAndLog("Unpacked %d samples" , j );
	}else
	{
		for (int j = 0; j < n; j++) {
			GraphBuffer[j] = ((int)got[j]) - 128;
		}
		GraphTraceLen = n;
	}

	RepaintGraphWindow();
	return 0;
}

int CmdTuneSamples(const char *Cmd)
{
	int timeout = 0;
	printf("\nMeasuring antenna characteristics, please wait...");

	UsbCommand c = {CMD_MEASURE_ANTENNA_TUNING};
	SendCommand(&c);

	UsbCommand resp;
	while(!WaitForResponseTimeout(CMD_MEASURED_ANTENNA_TUNING,&resp,1000)) {
		timeout++;
		printf(".");
		if (timeout > 7) {
			PrintAndLog("\nNo response from Proxmark. Aborting...");
			return 1;
		}
	}

	int peakv, peakf;
	int vLf125, vLf134, vHf;
	vLf125 = resp.arg[0] & 0xffff;
	vLf134 = resp.arg[0] >> 16;
	vHf = resp.arg[1] & 0xffff;;
	peakf = resp.arg[2] & 0xffff;
	peakv = resp.arg[2] >> 16;
	PrintAndLog("");
	PrintAndLog("# LF antenna: %5.2f V @   125.00 kHz", vLf125/1000.0);
	PrintAndLog("# LF antenna: %5.2f V @   134.00 kHz", vLf134/1000.0);
	PrintAndLog("# LF optimal: %5.2f V @%9.2f kHz", peakv/1000.0, 12000.0/(peakf+1));
	PrintAndLog("# HF antenna: %5.2f V @    13.56 MHz", vHf/1000.0);

#define LF_UNUSABLE_V		2948		// was 2000. Changed due to bugfix in voltage measurements. LF results are now 47% higher.
#define LF_MARGINAL_V		14739		// was 10000. Changed due to bugfix bug in voltage measurements. LF results are now 47% higher.
#define HF_UNUSABLE_V		3167		// was 2000. Changed due to bugfix in voltage measurements. HF results are now 58% higher.
#define HF_MARGINAL_V		7917		// was 5000. Changed due to bugfix in voltage measurements. HF results are now 58% higher.

	if (peakv < LF_UNUSABLE_V)
		PrintAndLog("# Your LF antenna is unusable.");
	else if (peakv < LF_MARGINAL_V)
		PrintAndLog("# Your LF antenna is marginal.");
	if (vHf < HF_UNUSABLE_V)
		PrintAndLog("# Your HF antenna is unusable.");
	else if (vHf < HF_MARGINAL_V)
		PrintAndLog("# Your HF antenna is marginal.");

	if (peakv >= LF_UNUSABLE_V)	{
		for (int i = 0; i < 256; i++) {
			GraphBuffer[i] = resp.d.asBytes[i] - 128;
		}
		PrintAndLog("Displaying LF tuning graph. Divisor 89 is 134khz, 95 is 125khz.\n");
		PrintAndLog("\n");
		GraphTraceLen = 256;
		ShowGraphWindow();
		RepaintGraphWindow();
	}

	return 0;
}


int CmdLoad(const char *Cmd)
{
  char filename[FILE_PATH_SIZE] = {0x00};
  int len = 0;

  len = strlen(Cmd);
  if (len > FILE_PATH_SIZE) len = FILE_PATH_SIZE;
  memcpy(filename, Cmd, len);
	
  FILE *f = fopen(filename, "r");
  if (!f) {
     PrintAndLog("couldn't open '%s'", filename);
    return 0;
  }

  GraphTraceLen = 0;
  char line[80];
  while (fgets(line, sizeof (line), f)) {
    GraphBuffer[GraphTraceLen] = atoi(line);
    GraphTraceLen++;
  }
  fclose(f);
  PrintAndLog("loaded %d samples", GraphTraceLen);
  RepaintGraphWindow();
  return 0;
}

int CmdLtrim(const char *Cmd)
{
  int ds = atoi(Cmd);

  for (int i = ds; i < GraphTraceLen; ++i)
    GraphBuffer[i-ds] = GraphBuffer[i];
  GraphTraceLen -= ds;

  RepaintGraphWindow();
  return 0;
}

// trim graph to input argument length
int CmdRtrim(const char *Cmd)
{
  int ds = atoi(Cmd);

  GraphTraceLen = ds;

  RepaintGraphWindow();
  return 0;
}

/*
 * Manchester demodulate a bitstream. The bitstream needs to be already in
 * the GraphBuffer as 0 and 1 values
 *
 * Give the clock rate as argument in order to help the sync - the algorithm
 * resyncs at each pulse anyway.
 *
 * Not optimized by any means, this is the 1st time I'm writing this type of
 * routine, feel free to improve...
 *
 * 1st argument: clock rate (as number of samples per clock rate)
 *               Typical values can be 64, 32, 128...
 */
int CmdManchesterDemod(const char *Cmd)
{
  int i, j, invert= 0;
  int bit;
  int clock;
  int lastval = 0;
  int low = 0;
  int high = 0;
  int hithigh, hitlow, first;
  int lc = 0;
  int bitidx = 0;
  int bit2idx = 0;
  int warnings = 0;

  /* check if we're inverting output */
  if (*Cmd == 'i')
  {
    PrintAndLog("Inverting output");
    invert = 1;
    ++Cmd;
    do
      ++Cmd;
    while(*Cmd == ' '); // in case a 2nd argument was given
  }

  /* Holds the decoded bitstream: each clock period contains 2 bits       */
  /* later simplified to 1 bit after manchester decoding.                 */
  /* Add 10 bits to allow for noisy / uncertain traces without aborting   */
  /* int BitStream[GraphTraceLen*2/clock+10]; */

  /* But it does not work if compiling on WIndows: therefore we just allocate a */
  /* large array */
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN] = {0};

  /* Detect high and lows */
  for (i = 0; i < GraphTraceLen; i++)
  {
    if (GraphBuffer[i] > high)
      high = GraphBuffer[i];
    else if (GraphBuffer[i] < low)
      low = GraphBuffer[i];
  }

  /* Get our clock */
  clock = GetAskClock(Cmd, high, 1);

  int tolerance = clock/4;

  /* Detect first transition */
  /* Lo-Hi (arbitrary)       */
  /* skip to the first high */
  for (i= 0; i < GraphTraceLen; i++)
    if (GraphBuffer[i] == high)
      break;
  /* now look for the first low */
  for (; i < GraphTraceLen; i++)
  {
    if (GraphBuffer[i] == low)
    {
      lastval = i;
      break;
    }
  }

  /* If we're not working with 1/0s, demod based off clock */
  if (high != 1)
  {
    bit = 0; /* We assume the 1st bit is zero, it may not be
              * the case: this routine (I think) has an init problem.
              * Ed.
              */
    for (; i < (int)(GraphTraceLen / clock); i++)
    {
      hithigh = 0;
      hitlow = 0;
      first = 1;

      /* Find out if we hit both high and low peaks */
      for (j = 0; j < clock; j++)
      {
        if (GraphBuffer[(i * clock) + j] == high)
          hithigh = 1;
        else if (GraphBuffer[(i * clock) + j] == low)
          hitlow = 1;

        /* it doesn't count if it's the first part of our read
           because it's really just trailing from the last sequence */
        if (first && (hithigh || hitlow))
          hithigh = hitlow = 0;
        else
          first = 0;

        if (hithigh && hitlow)
          break;
      }

      /* If we didn't hit both high and low peaks, we had a bit transition */
      if (!hithigh || !hitlow)
        bit ^= 1;

      BitStream[bit2idx++] = bit ^ invert;
    }
  }

  /* standard 1/0 bitstream */
  else
  {

    /* Then detect duration between 2 successive transitions */
    for (bitidx = 1; i < GraphTraceLen; i++)
    {
      if (GraphBuffer[i-1] != GraphBuffer[i])
      {
        lc = i-lastval;
        lastval = i;

        // Error check: if bitidx becomes too large, we do not
        // have a Manchester encoded bitstream or the clock is really
        // wrong!
        if (bitidx > (GraphTraceLen*2/clock+8) ) {
          PrintAndLog("Error: the clock you gave is probably wrong, aborting.");
          return 0;
        }
        // Then switch depending on lc length:
        // Tolerance is 1/4 of clock rate (arbitrary)
        if (abs(lc-clock/2) < tolerance) {
          // Short pulse : either "1" or "0"
          BitStream[bitidx++]=GraphBuffer[i-1];
        } else if (abs(lc-clock) < tolerance) {
          // Long pulse: either "11" or "00"
          BitStream[bitidx++]=GraphBuffer[i-1];
          BitStream[bitidx++]=GraphBuffer[i-1];
        } else {
        // Error
          warnings++;
          PrintAndLog("Warning: Manchester decode error for pulse width detection.");
          PrintAndLog("(too many of those messages mean either the stream is not Manchester encoded, or clock is wrong)");

          if (warnings > 10)
          {
            PrintAndLog("Error: too many detection errors, aborting.");
            return 0;
          }
        }
      }
    }

    // At this stage, we now have a bitstream of "01" ("1") or "10" ("0"), parse it into final decoded bitstream
    // Actually, we overwrite BitStream with the new decoded bitstream, we just need to be careful
    // to stop output at the final bitidx2 value, not bitidx
    for (i = 0; i < bitidx; i += 2) {
      if ((BitStream[i] == 0) && (BitStream[i+1] == 1)) {
        BitStream[bit2idx++] = 1 ^ invert;
      } else if ((BitStream[i] == 1) && (BitStream[i+1] == 0)) {
        BitStream[bit2idx++] = 0 ^ invert;
      } else {
        // We cannot end up in this state, this means we are unsynchronized,
        // move up 1 bit:
        i++;
        warnings++;
        PrintAndLog("Unsynchronized, resync...");
        PrintAndLog("(too many of those messages mean the stream is not Manchester encoded)");

        if (warnings > 10)
        {
          PrintAndLog("Error: too many decode errors, aborting.");
          return 0;
        }
      }
    }
  }

  PrintAndLog("Manchester decoded bitstream");
  // Now output the bitstream to the scrollback by line of 16 bits
  for (i = 0; i < (bit2idx-16); i+=16) {
    PrintAndLog("%i %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i",
      BitStream[i],
      BitStream[i+1],
      BitStream[i+2],
      BitStream[i+3],
      BitStream[i+4],
      BitStream[i+5],
      BitStream[i+6],
      BitStream[i+7],
      BitStream[i+8],
      BitStream[i+9],
      BitStream[i+10],
      BitStream[i+11],
      BitStream[i+12],
      BitStream[i+13],
      BitStream[i+14],
      BitStream[i+15]);
  }
  return 0;
}

/* Modulate our data into manchester */
int CmdManchesterMod(const char *Cmd)
{
  int i, j;
  int clock;
  int bit, lastbit, wave;

  /* Get our clock */
  clock = GetAskClock(Cmd, 0, 1);

  wave = 0;
  lastbit = 1;
  for (i = 0; i < (int)(GraphTraceLen / clock); i++)
  {
    bit = GraphBuffer[i * clock] ^ 1;

    for (j = 0; j < (int)(clock/2); j++)
      GraphBuffer[(i * clock) + j] = bit ^ lastbit ^ wave;
    for (j = (int)(clock/2); j < clock; j++)
      GraphBuffer[(i * clock) + j] = bit ^ lastbit ^ wave ^ 1;

    /* Keep track of how we start our wave and if we changed or not this time */
    wave ^= bit ^ lastbit;
    lastbit = bit;
  }

  RepaintGraphWindow();
  return 0;
}

int CmdNorm(const char *Cmd)
{
  int i;
  int max = INT_MIN, min = INT_MAX;

  for (i = 10; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] > max)
      max = GraphBuffer[i];
    if (GraphBuffer[i] < min)
      min = GraphBuffer[i];
  }

  if (max != min) {
    for (i = 0; i < GraphTraceLen; ++i) {
			GraphBuffer[i] = (GraphBuffer[i] - ((max + min) / 2)) * 256 /
        (max - min);
				//marshmelow: adjusted *1000 to *256 to make +/- 128 so demod commands still work
    }
  }
  RepaintGraphWindow();
  return 0;
}

int CmdPlot(const char *Cmd)
{
  ShowGraphWindow();
  return 0;
}

int CmdSave(const char *Cmd)
{
  char filename[FILE_PATH_SIZE] = {0x00};
  int len = 0;

  len = strlen(Cmd);
  if (len > FILE_PATH_SIZE) len = FILE_PATH_SIZE;
  memcpy(filename, Cmd, len);
   

  FILE *f = fopen(filename, "w");
  if(!f) {
    PrintAndLog("couldn't open '%s'", filename);
    return 0;
  }
  int i;
  for (i = 0; i < GraphTraceLen; i++) {
    fprintf(f, "%d\n", GraphBuffer[i]);
  }
  fclose(f);
  PrintAndLog("saved to '%s'", Cmd);
  return 0;
}

int CmdScale(const char *Cmd)
{
  CursorScaleFactor = atoi(Cmd);
  if (CursorScaleFactor == 0) {
    PrintAndLog("bad, can't have zero scale");
    CursorScaleFactor = 1;
  }
  RepaintGraphWindow();
  return 0;
}

int CmdThreshold(const char *Cmd)
{
  int threshold = atoi(Cmd);

  for (int i = 0; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] >= threshold)
      GraphBuffer[i] = 1;
    else
      GraphBuffer[i] = -1;
  }
  RepaintGraphWindow();
  return 0;
}

int CmdDirectionalThreshold(const char *Cmd)
{
  int8_t upThres = param_get8(Cmd, 0);
  int8_t downThres = param_get8(Cmd, 1);

  printf("Applying Up Threshold: %d, Down Threshold: %d\n", upThres, downThres);

  int lastValue = GraphBuffer[0];
  GraphBuffer[0] = 0; // Will be changed at the end, but init 0 as we adjust to last samples value if no threshold kicks in.

  for (int i = 1; i < GraphTraceLen; ++i) {
    // Apply first threshold to samples heading up
    if (GraphBuffer[i] >= upThres && GraphBuffer[i] > lastValue)
    {
      lastValue = GraphBuffer[i]; // Buffer last value as we overwrite it.
      GraphBuffer[i] = 1;
    }
    // Apply second threshold to samples heading down
    else if (GraphBuffer[i] <= downThres && GraphBuffer[i] < lastValue)
    {
      lastValue = GraphBuffer[i]; // Buffer last value as we overwrite it.
      GraphBuffer[i] = -1;
    }
    else
    {
      lastValue = GraphBuffer[i]; // Buffer last value as we overwrite it.
      GraphBuffer[i] = GraphBuffer[i-1];

    }
  }
  GraphBuffer[0] = GraphBuffer[1]; // Aline with first edited sample.
  RepaintGraphWindow();
  return 0;
}

int CmdZerocrossings(const char *Cmd)
{
  // Zero-crossings aren't meaningful unless the signal is zero-mean.
  CmdHpf("");

  int sign = 1;
  int zc = 0;
  int lastZc = 0;

  for (int i = 0; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] * sign >= 0) {
      // No change in sign, reproduce the previous sample count.
      zc++;
      GraphBuffer[i] = lastZc;
    } else {
      // Change in sign, reset the sample count.
      sign = -sign;
      GraphBuffer[i] = lastZc;
      if (sign > 0) {
        lastZc = zc;
        zc = 0;
      }
    }
  }

  RepaintGraphWindow();
  return 0;
}

static command_t CommandTable[] =
{
  {"help",          CmdHelp,            1, "This help"},
  {"amp",           CmdAmp,             1, "Amplify peaks"},
  //{"askdemod",      Cmdaskdemod,        1, "<0 or 1> -- Attempt to demodulate simple ASK tags"},
  {"askedgedetect", CmdAskEdgeDetect,   1, "[threshold] Adjust Graph for manual ask demod using length of sample differences to detect the edge of a wave (default = 25)"},
  {"askem410xdemod",CmdAskEM410xDemod,  1, "[clock] [invert<0|1>] [maxErr] -- Demodulate an EM410x tag from GraphBuffer (args optional)"},
  //{"askmandemod",   Cmdaskmandemod,     1, "[clock] [invert<0|1>] [maxErr] -- Attempt to demodulate ASK/Manchester tags and output binary (args optional)"},
  //{"askrawdemod",   Cmdaskrawdemod,     1, "[clock] [invert<0|1>] -- Attempt to demodulate ASK tags and output bin (args optional)"},
  {"autocorr",      CmdAutoCorr,        1, "<window length> -- Autocorrelation over window"},
  {"biphaserawdecode",CmdBiphaseDecodeRaw,1,"[offset] [invert<0|1>] Biphase decode bin stream in DemodBuffer (offset = 0|1 bits to shift the decode start)"},
  {"bitsamples",    CmdBitsamples,      0, "Get raw samples as bitstring"},
  //{"bitstream",     CmdBitstream,       1, "[clock rate] -- Convert waveform into a bitstream"},
  {"buffclear",     CmdBuffClear,       1, "Clear sample buffer and graph window"},
  {"dec",           CmdDec,             1, "Decimate samples"},
  {"detectclock",   CmdDetectClockRate, 1, "[modulation] Detect clock rate of wave in GraphBuffer (options: 'a','f','n','p' for ask, fsk, nrz, psk respectively)"},
  //{"fskdemod",      CmdFSKdemod,        1, "Demodulate graph window as a HID FSK"},
  {"fskawiddemod",  CmdFSKdemodAWID,    1, "Demodulate an AWID FSK tag from GraphBuffer"},
  //{"fskfcdetect",   CmdFSKfcDetect,     1, "Try to detect the Field Clock of an FSK wave"},
  {"fskhiddemod",   CmdFSKdemodHID,     1, "Demodulate a HID FSK tag from GraphBuffer"},
  {"fskiodemod",    CmdFSKdemodIO,      1, "Demodulate an IO Prox FSK tag from GraphBuffer"},
  {"fskpyramiddemod",CmdFSKdemodPyramid,1, "Demodulate a Pyramid FSK tag from GraphBuffer"},
  {"fskparadoxdemod",CmdFSKdemodParadox,1, "Demodulate a Paradox FSK tag from GraphBuffer"},
  //{"fskrawdemod",   CmdFSKrawdemod,     1, "[clock rate] [invert] [rchigh] [rclow] Demodulate graph window from FSK to bin (clock = 50)(invert = 1|0)(rchigh = 10)(rclow=8)"},
  {"grid",          CmdGrid,            1, "<x> <y> -- overlay grid on graph window, use zero value to turn off either"},
  {"hexsamples",    CmdHexsamples,      0, "<bytes> [<offset>] -- Dump big buffer as hex bytes"},
  {"hide",          CmdHide,            1, "Hide graph window"},
  {"hpf",           CmdHpf,             1, "Remove DC offset from trace"},
  {"load",          CmdLoad,            1, "<filename> -- Load trace (to graph window"},
  {"ltrim",         CmdLtrim,           1, "<samples> -- Trim samples from left of trace"},
  {"rtrim",         CmdRtrim,           1, "<location to end trace> -- Trim samples from right of trace"},
  //{"mandemod",      CmdManchesterDemod, 1, "[i] [clock rate] -- Manchester demodulate binary stream (option 'i' to invert output)"},
  {"manrawdecode",  Cmdmandecoderaw,    1, "Manchester decode binary stream in DemodBuffer"},
  {"manmod",        CmdManchesterMod,   1, "[clock rate] -- Manchester modulate a binary stream"},
  {"norm",          CmdNorm,            1, "Normalize max/min to +/-128"},
  //{"nrzdetectclock",CmdDetectNRZClockRate, 1, "Detect ASK, PSK, or NRZ clock rate"},
  //{"nrzrawdemod",   CmdNRZrawDemod,     1, "[clock] [invert<0|1>] [maxErr] -- Attempt to demodulate nrz tags and output binary (args optional)"},
  {"plot",          CmdPlot,            1, "Show graph window (hit 'h' in window for keystroke help)"},
  //{"pskdetectclock",CmdDetectPSKClockRate, 1, "Detect ASK, PSK, or NRZ clock rate"},
  {"pskindalademod",CmdIndalaDecode,    1, "[clock] [invert<0|1>] -- Demodulate an indala tag (PSK1) from GraphBuffer (args optional)"},
  //{"psk1rawdemod",  CmdPSK1rawDemod,    1, "[clock] [invert<0|1>] [maxErr] -- Attempt to demodulate psk1 tags and output binary (args optional)"},
  //{"psk2rawdemod",  CmdPSK2rawDemod,    1, "[clock] [invert<0|1>] [maxErr] -- Attempt to demodulate psk2 tags and output binary (args optional)"},
  {"rawdemod",      CmdRawDemod,        1, "[modulation] ... <options> -see help (h option) -- Demodulate the data in the GraphBuffer and output binary"},  
  {"samples",       CmdSamples,         0, "[512 - 40000] -- Get raw samples for graph window (GraphBuffer)"},
  {"save",          CmdSave,            1, "<filename> -- Save trace (from graph window)"},
  {"scale",         CmdScale,           1, "<int> -- Set cursor display scale"},
  {"setdebugmode",  CmdSetDebugMode,    1, "<0|1> -- Turn on or off Debugging Mode for demods"},
  {"shiftgraphzero",CmdGraphShiftZero,  1, "<shift> -- Shift 0 for Graphed wave + or - shift value"},
  //{"threshold",     CmdThreshold,       1, "<threshold> -- Maximize/minimize every value in the graph window depending on threshold"},
  {"dirthreshold",  CmdDirectionalThreshold,   1, "<thres up> <thres down> -- Max rising higher up-thres/ Min falling lower down-thres, keep rest as prev."},
  {"tune",          CmdTuneSamples,     0, "Get hw tune samples for graph window"},
  {"undec",         CmdUndec,           1, "Un-decimate samples by 2"},
  {"zerocrossings", CmdZerocrossings,   1, "Count time between zero-crossings"},
  {NULL, NULL, 0, NULL}
};

int CmdData(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
