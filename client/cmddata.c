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
//#include <inttypes.h>
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

static int CmdHelp(const char *Cmd);

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

void printBitStream(uint8_t BitStream[], uint32_t bitLen){
  uint32_t i = 0;
  if (bitLen<16) {
    PrintAndLog("Too few bits found: %d",bitLen);
    return;
  }
  if (bitLen>512) bitLen=512;
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
void printEM410x(uint64_t id)
{
  if (id !=0){
      uint64_t iii=1;
      uint64_t id2lo=0; //id2hi=0,
      uint32_t ii=0;
      uint32_t i=0;
      for (ii=5; ii>0;ii--){
        for (i=0;i<8;i++){
          id2lo=(id2lo<<1LL)|((id & (iii<<(i+((ii-1)*8))))>>(i+((ii-1)*8)));
        }
      }
      //output em id
      PrintAndLog("EM TAG ID    : %010llx", id);
      PrintAndLog("Unique TAG ID: %010llx",  id2lo); //id2hi,
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

int CmdEm410xDecode(const char *Cmd)
{
  uint64_t id=0;
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  uint32_t i=0;
  for (i=0;i<GraphTraceLen;++i){
    BitStream[i]=(uint8_t)(GraphBuffer[i]+128);
  }
  id = Em410xDecode(BitStream,i);
  printEM410x(id);
  return 0;
}

int getFromGraphBuf(uint8_t *buff)
{
  uint32_t i;
  for (i=0;i<GraphTraceLen;++i)
    buff[i]=(uint8_t)(GraphBuffer[i]+128);
  return i;
}

//by marshmellow
//takes 2 arguments - clock and invert both as integers
//attempts to demodulate ask while decoding manchester 
//prints binary found and saves in graphbuffer for further commands
int Cmdaskmandemod(const char *Cmd)
{
  int invert=0; 
  int clk=0; 
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  sscanf(Cmd, "%i %i", &clk, &invert);    
  if (invert != 0 && invert != 1) {
    PrintAndLog("Invalid argument: %s", Cmd);
    return 0;
  }
  uint32_t BitLen = getFromGraphBuf(BitStream);

  int errCnt=0;
   errCnt = askmandemod(BitStream, &BitLen,&clk,&invert);
  if (errCnt==-1){  //if fatal error (or -1)
    PrintAndLog("no data found"); 
    return 0;
  } 
  PrintAndLog("Using Clock: %d  and invert=%d",clk,invert);
    //PrintAndLog("Data start pos:%d, lastBit:%d, stop pos:%d, numBits:%d",iii,lastBit,i,bitnum);
    //move BitStream back to GraphBuffer
    /*
      ClearGraph(0);
      for (i=0; i < bitnum; ++i){
        GraphBuffer[i]=BitStream[i];
      }
      GraphTraceLen=bitnum;
      RepaintGraphWindow();
    */
    //output
  if (errCnt>0){
    PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d",errCnt);
  }
  PrintAndLog("ASK/Manchester decoded bitstream:");
  // Now output the bitstream to the scrollback by line of 16 bits
  printBitStream(BitStream,BitLen);
  uint64_t lo =0;
  lo = Em410xDecode(BitStream,BitLen);
  printEM410x(lo);
  
  return 0;
}

//by marshmellow
//biphase demod = 10 (or 01)=1 / 00 (or 11)=0


//by marshmellow
//manchester demod
//stricktly take 10 and 01 and convert to 0 and 1
int Cmdmandecoderaw(const char *Cmd)
{
  int i =0;
  int errCnt=0;
  int bitnum=0;
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  int high=0,low=0;
  for (;i<GraphTraceLen;++i){
    if (GraphBuffer[i]>high) high=GraphBuffer[i];
    else if(GraphBuffer[i]<low) low=GraphBuffer[i];
    BitStream[i]=GraphBuffer[i];
  }
  if (high>1 || low <0 ){
    PrintAndLog("Error: please raw demod the wave first then mancheseter raw decode");
    return 0;
  }
  bitnum=i;
  errCnt=manrawdemod(BitStream,&bitnum);
  if (errCnt>=20){
    PrintAndLog("Too many errors: %d",errCnt);
    return 0;
  }
  PrintAndLog("Manchester Decoded - # errors:%d - data:",errCnt);
  printBitStream(BitStream,bitnum);
  if (errCnt==0){
    //put back in graphbuffer
    ClearGraph(0);
    for (i=0; i<bitnum;++i){
      GraphBuffer[i]=BitStream[i];
    }  
    GraphTraceLen=bitnum;
    RepaintGraphWindow();
    uint64_t id = 0; 
    id = Em410xDecode(BitStream,i);
    printEM410x(id);     
  }
  return 0;
}

//by marshmellow
//takes 2 arguments - clock and invert both as integers
//attempts to demodulate ask only
//prints binary found and saves in graphbuffer for further commands
int Cmdaskrawdemod(const char *Cmd)
{
  uint32_t i;
  int invert=0; 
  int clk=0; 
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  sscanf(Cmd, "%i %i", &clk, &invert);    
  if (invert != 0 && invert != 1) {
    PrintAndLog("Invalid argument: %s", Cmd);
    return 0;
  }
  int BitLen = getFromGraphBuf(BitStream);
  int errCnt=0;
  errCnt = askrawdemod(BitStream, &BitLen,&clk,&invert);
  if (errCnt==-1){  //throw away static - allow 1 and -1 (in case of threshold command first)
    PrintAndLog("no data found"); 
    return 0;
  } 
  PrintAndLog("Using Clock: %d  and invert=%d",clk,invert);
    //PrintAndLog("Data start pos:%d, lastBit:%d, stop pos:%d, numBits:%d",iii,lastBit,i,bitnum);
    //move BitStream back to GraphBuffer
    
  ClearGraph(0);
  for (i=0; i < BitLen; ++i){
    GraphBuffer[i]=BitStream[i];
  }
  GraphTraceLen=BitLen;
  RepaintGraphWindow();
    
    //output
  if (errCnt>0){
    PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d",errCnt);
  }
  PrintAndLog("ASK demoded bitstream:");
  // Now output the bitstream to the scrollback by line of 16 bits
  printBitStream(BitStream,BitLen);
  
  return 0;
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
  clock = GetClock(Cmd, high, 1);
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
  //    for (j = 0; j < (int)(clock/2); j++)
  //      GraphBuffer[(i * clock) + j] = bit ^ 1;
  //    for (j = (int)(clock/2); j < clock; j++)
  //      GraphBuffer[(i * clock) + j] = bit;
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

/* Print our clock rate */
int CmdDetectClockRate(const char *Cmd)
{
  int clock = DetectClock(0);
  PrintAndLog("Auto-detected clock rate: %d", clock);
  return 0;
}

//by marshmellow
//fsk raw demod and print binary
//takes 2 arguments - Clock and invert
//defaults: clock = 50, invert=0
int CmdFSKrawdemod(const char *Cmd)
{
  //raw fsk demod  no manchester decoding no start bit finding just get binary from wave
  //set defaults
  uint8_t rfLen = 50;
  uint8_t invert=0;
  //set options from parameters entered with the command
  if (strlen(Cmd)>0 && strlen(Cmd)<=2) {
     rfLen=param_get8(Cmd, 0); //if rfLen option only is used
     if (rfLen==1){
      invert=1;   //if invert option only is used
      rfLen = 50;
     } else if(rfLen==0) rfLen=50;
  } 
  if (strlen(Cmd)>2) {
    rfLen=param_get8(Cmd, 0);  //if both options are used
    invert=param_get8(Cmd,1);
  }
  PrintAndLog("Args invert: %d \nClock:%d",invert,rfLen);
  uint32_t i=0;
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  uint32_t BitLen = getFromGraphBuf(BitStream);
  int size  = fskdemod(BitStream,BitLen,rfLen,invert); 
  
  PrintAndLog("FSK decoded bitstream:");
  ClearGraph(0);
  for (i=0;i<size;++i){
    GraphBuffer[i]=BitStream[i];
  }
  GraphTraceLen=size;
  RepaintGraphWindow();
  
  // Now output the bitstream to the scrollback by line of 16 bits
  if(size > (8*32)+2) size = (8*32)+2; //only output a max of 8 blocks of 32 bits  most tags will have full bit stream inside that sample size
  printBitStream(BitStream,size);
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
  uint32_t BitLen = getFromGraphBuf(BitStream);
  //get binary from fsk wave
  size_t size  = HIDdemodFSK(BitStream,BitLen,&hi2,&hi,&lo); 
  if (size<0){
    PrintAndLog("Error demoding fsk");
    return 0;
  }
  if (hi2 != 0){ //extra large HID tags
    PrintAndLog("TAG ID: %x%08x%08x (%d)",
       (unsigned int) hi2, (unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF);
  }
  else {  //standard HID tags <38 bits
    //Dbprintf("TAG ID: %x%08x (%d)",(unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF); //old print cmd
    uint8_t bitlen = 0;
    uint32_t fc = 0;
    uint32_t cardnum = 0;
    if (((hi>>5)&1)==1){//if bit 38 is set then < 37 bit format is used
      uint32_t lo2=0;
      lo2=(((hi & 15) << 12) | (lo>>20)); //get bits 21-37 to check for format len bit
      uint8_t idx3 = 1;
      while(lo2>1){ //find last bit set to 1 (format len bit)
        lo2=lo2>>1;
        idx3++;
      }
      bitlen =idx3+19;  
      fc =0;
      cardnum=0;
      if(bitlen==26){
        cardnum = (lo>>1)&0xFFFF;
        fc = (lo>>17)&0xFF;
      }
      if(bitlen==37){
        cardnum = (lo>>1)&0x7FFFF;
        fc = ((hi&0xF)<<12)|(lo>>20);
      }
      if(bitlen==34){
        cardnum = (lo>>1)&0xFFFF;
        fc= ((hi&1)<<15)|(lo>>17);
      }
      if(bitlen==35){
        cardnum = (lo>>1)&0xFFFFF;
        fc = ((hi&1)<<11)|(lo>>21);
      }
    }
    else { //if bit 38 is not set then 37 bit format is used
      bitlen= 37;
      fc =0;
      cardnum=0;
      if(bitlen==37){
        cardnum = (lo>>1)&0x7FFFF;
        fc = ((hi&0xF)<<12)|(lo>>20);
      }
    }    
    PrintAndLog("TAG ID: %x%08x (%d) - Format Len: %dbit - FC: %d - Card: %d",
      (unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF,
      (unsigned int) bitlen, (unsigned int) fc, (unsigned int) cardnum);
    return 0;
  }
  return 0;
}

//by marshmellow
//IO-Prox demod - FSK RF/64 with preamble of 000000001
//print ioprox ID and some format details
int CmdFSKdemodIO(const char *Cmd)
{
  //raw fsk demod no manchester decoding no start bit finding just get binary from wave
  //set defaults
  int idx=0; 
  //test samples are not just noise
  if (GraphTraceLen < 64) return 0;
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN]={0};
  uint32_t BitLen = getFromGraphBuf(BitStream);
  //get binary from fsk wave
  idx = IOdemodFSK(BitStream,BitLen); 
  if (idx<0){
    PrintAndLog("Error demoding fsk");
    return 0;
  }
  if (idx==0){
    PrintAndLog("IO Prox Data not found - FSK Data:");
    printBitStream(BitStream,92);
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
        
  PrintAndLog("%d%d%d%d%d%d%d%d %d",BitStream[idx],    BitStream[idx+1],  BitStream[idx+2], BitStream[idx+3], BitStream[idx+4], BitStream[idx+5], BitStream[idx+6], BitStream[idx+7], BitStream[idx+8]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d",BitStream[idx+9],  BitStream[idx+10], BitStream[idx+11],BitStream[idx+12],BitStream[idx+13],BitStream[idx+14],BitStream[idx+15],BitStream[idx+16],BitStream[idx+17]);       
  PrintAndLog("%d%d%d%d%d%d%d%d %d",BitStream[idx+18], BitStream[idx+19], BitStream[idx+20],BitStream[idx+21],BitStream[idx+22],BitStream[idx+23],BitStream[idx+24],BitStream[idx+25],BitStream[idx+26]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d",BitStream[idx+27], BitStream[idx+28], BitStream[idx+29],BitStream[idx+30],BitStream[idx+31],BitStream[idx+32],BitStream[idx+33],BitStream[idx+34],BitStream[idx+35]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d",BitStream[idx+36], BitStream[idx+37], BitStream[idx+38],BitStream[idx+39],BitStream[idx+40],BitStream[idx+41],BitStream[idx+42],BitStream[idx+43],BitStream[idx+44]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d",BitStream[idx+45], BitStream[idx+46], BitStream[idx+47],BitStream[idx+48],BitStream[idx+49],BitStream[idx+50],BitStream[idx+51],BitStream[idx+52],BitStream[idx+53]);
  PrintAndLog("%d%d%d%d%d%d%d%d %d%d",BitStream[idx+54],BitStream[idx+55],BitStream[idx+56],BitStream[idx+57],BitStream[idx+58],BitStream[idx+59],BitStream[idx+60],BitStream[idx+61],BitStream[idx+62],BitStream[idx+63]);

  uint32_t code = bytebits_to_byte(BitStream+idx,32);
  uint32_t code2 = bytebits_to_byte(BitStream+idx+32,32); 
  short version = bytebits_to_byte(BitStream+idx+27,8); //14,4
  uint8_t facilitycode = bytebits_to_byte(BitStream+idx+19,8) ;
  uint16_t number = (bytebits_to_byte(BitStream+idx+36,8)<<8)|(bytebits_to_byte(BitStream+idx+45,8)); //36,9
  
  PrintAndLog("XSF(%02d)%02x:%d (%08x%08x)",version,facilitycode,number,code,code2);    
  return 0;
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
  int convLen = (highLen > lowLen) ? highLen : lowLen; //if highlen > lowLen then highlen else lowlen
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

  uint8_t bits[46];
  bits[sizeof(bits)-1] = '\0';

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
  uint8_t got[40000];
 
  sscanf(Cmd, "%i %i", &requested, &offset);

  /* if no args send something */
  if (requested == 0) {
    requested = 8;
  }
  if (offset + requested > sizeof(got)) {
    PrintAndLog("Tried to read past end of buffer, <bytes> + <offset> > 40000");
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

int CmdSamples(const char *Cmd)
{
  int cnt = 0;
  int n;
  uint8_t got[40000];

  n = strtol(Cmd, NULL, 0);
  if (n == 0) n = 6000;
  if (n > sizeof(got)) n = sizeof(got);
  
  PrintAndLog("Reading %d samples\n", n);
  GetFromBigBuf(got,n,0);
  WaitForResponse(CMD_ACK,NULL);
  for (int j = 0; j < n; j++) {
    GraphBuffer[cnt++] = ((int)got[j]) - 128;
  }
  
  PrintAndLog("Done!\n");
  GraphTraceLen = n;
  RepaintGraphWindow();
  return 0;
}

int CmdTuneSamples(const char *Cmd)
{
  int cnt = 0;
  int n = 255;
  uint8_t got[255];

  PrintAndLog("Reading %d samples\n", n);
  GetFromBigBuf(got,n,7256); // armsrc/apps.h: #define FREE_BUFFER_OFFSET 7256
  WaitForResponse(CMD_ACK,NULL);
  for (int j = 0; j < n; j++) {
    GraphBuffer[cnt++] = ((int)got[j]) - 128;
  }
  
  PrintAndLog("Done! Divisor 89 is 134khz, 95 is 125khz.\n");
  PrintAndLog("\n");
  GraphTraceLen = n;
  RepaintGraphWindow();
  return 0;
}

int CmdLoad(const char *Cmd)
{
  FILE *f = fopen(Cmd, "r");
  if (!f) {
    PrintAndLog("couldn't open '%s'", Cmd);
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
  clock = GetClock(Cmd, high, 1);

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
  clock = GetClock(Cmd, 0, 1);

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
      GraphBuffer[i] = (GraphBuffer[i] - ((max + min) / 2)) * 1000 /
        (max - min);
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
  FILE *f = fopen(Cmd, "w");
  if(!f) {
    PrintAndLog("couldn't open '%s'", Cmd);
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
  {"askdemod",      Cmdaskdemod,        1, "<0 or 1> -- Attempt to demodulate simple ASK tags"},
  {"askmandemod",   Cmdaskmandemod,     1, "[clock] [invert<0 or 1>] -- Attempt to demodulate ASK/Manchester tags and output binary (args optional[clock will try Auto-detect])"},
  {"askrawdemod",   Cmdaskrawdemod,     1, "[clock] [invert<0 or 1>] -- Attempt to demodulate ASK tags and output binary (args optional[clock will try Auto-detect])"},
  {"autocorr",      CmdAutoCorr,        1, "<window length> -- Autocorrelation over window"},
  {"bitsamples",    CmdBitsamples,      0, "Get raw samples as bitstring"},
  {"bitstream",     CmdBitstream,       1, "[clock rate] -- Convert waveform into a bitstream"},
  {"buffclear",     CmdBuffClear,       1, "Clear sample buffer and graph window"},
  {"dec",           CmdDec,             1, "Decimate samples"},
  {"detectclock",   CmdDetectClockRate, 1, "Detect clock rate"},
  {"fskdemod",      CmdFSKdemod,        1, "Demodulate graph window as a HID FSK"},
  {"fskhiddemod",   CmdFSKdemodHID,     1, "Demodulate graph window as a HID FSK using raw"},
  {"fskiodemod",    CmdFSKdemodIO,      1, "Demodulate graph window as an IO Prox FSK using raw"},
  {"fskrawdemod",   CmdFSKrawdemod,     1, "[clock rate] [invert] Demodulate graph window from FSK to binary (clock = 64 or 50)(invert = 1 or 0)"},
  {"grid",          CmdGrid,            1, "<x> <y> -- overlay grid on graph window, use zero value to turn off either"},
  {"hexsamples",    CmdHexsamples,      0, "<bytes> [<offset>] -- Dump big buffer as hex bytes"},  
  {"hide",          CmdHide,            1, "Hide graph window"},
  {"hpf",           CmdHpf,             1, "Remove DC offset from trace"},
  {"load",          CmdLoad,            1, "<filename> -- Load trace (to graph window"},
  {"ltrim",         CmdLtrim,           1, "<samples> -- Trim samples from left of trace"},
  {"mandemod",      CmdManchesterDemod, 1, "[i] [clock rate] -- Manchester demodulate binary stream (option 'i' to invert output)"},
  {"manrawdecode",  Cmdmandecoderaw,    1, "Manchester decode binary stream already in graph buffer"},
  {"manmod",        CmdManchesterMod,   1, "[clock rate] -- Manchester modulate a binary stream"},
  {"norm",          CmdNorm,            1, "Normalize max/min to +/-500"},
  {"plot",          CmdPlot,            1, "Show graph window (hit 'h' in window for keystroke help)"},
  {"samples",       CmdSamples,         0, "[512 - 40000] -- Get raw samples for graph window"},
  {"tune",          CmdTuneSamples,     0, "Get hw tune samples for graph window"},
  {"save",          CmdSave,            1, "<filename> -- Save trace (from graph window)"},
  {"scale",         CmdScale,           1, "<int> -- Set cursor display scale"},
  {"threshold",     CmdThreshold,       1, "<threshold> -- Maximize/minimize every value in the graph window depending on threshold"},
  {"zerocrossings", CmdZerocrossings,   1, "Count time between zero-crossings"},
  {"dirthreshold",  CmdDirectionalThreshold,   1, "<thres up> <thres down> -- Max rising higher up-thres/ Min falling lower down-thres, keep rest as prev."},
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
