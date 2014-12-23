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

void printBitStream(int BitStream[], uint32_t bitLen){
  uint32_t i = 0;
  if (bitLen<16) return;
  if (bitLen>512) bitLen=512;
   for (i = 0; i < (bitLen-16); i+=16) {
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
void printBitStream2(uint8_t BitStream[], uint32_t bitLen){
  uint32_t i = 0;
  if (bitLen<16) {
    PrintAndLog("Too few bits found: %d",bitLen);
    return;
  }
  if (bitLen>512) bitLen=512;
   for (i = 0; i < (bitLen-16); i+=16) {
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
//takes 1s and 0s and searches for EM410x format - output EM ID
int Em410xDecode(const char *Cmd)
{
  //no arguments needed - built this way in case we want this to be a direct call from "data " cmds in the future
  //  otherwise could be a void with no arguments
  //set defaults
  int high=0, low=0;
  uint32_t hi=0, lo=0;

  uint32_t i = 0;
  uint32_t initLoopMax = 1000;
  if (initLoopMax>GraphTraceLen) initLoopMax=GraphTraceLen;

  for (;i < initLoopMax; ++i) //1000 samples should be plenty to find high and low values
  {
    if (GraphBuffer[i] > high)
      high = GraphBuffer[i];
    else if (GraphBuffer[i] < low)
      low = GraphBuffer[i];
  }
  if (((high !=1)||(low !=0))){  //allow only 1s and 0s 
    PrintAndLog("no data found"); 
    return 0;
  }
  uint8_t parityTest=0;
   // 111111111 bit pattern represent start of frame
  int frame_marker_mask[] = {1,1,1,1,1,1,1,1,1};
  uint32_t idx = 0;
  uint32_t ii=0;
  uint8_t resetCnt = 0;
  while( (idx + 64) < GraphTraceLen) {
restart:
    // search for a start of frame marker
    if ( memcmp(GraphBuffer+idx, frame_marker_mask, sizeof(frame_marker_mask)) == 0)
    { // frame marker found
      idx+=9;//sizeof(frame_marker_mask);
      for (i=0; i<10;i++){
        for(ii=0; ii<5; ++ii){
          parityTest += GraphBuffer[(i*5)+ii+idx];        
        }
        if (parityTest== ((parityTest>>1)<<1)){
          parityTest=0;
          for (ii=0; ii<4;++ii){
            hi = (hi<<1)|(lo>>31);
            lo=(lo<<1)|(GraphBuffer[(i*5)+ii+idx]);
          }
          //PrintAndLog("DEBUG: EM parity passed parity val: %d, i:%d, ii:%d,idx:%d, Buffer: %d%d%d%d%d,lo: %d",parityTest,i,ii,idx,GraphBuffer[idx+ii+(i*5)-5],GraphBuffer[idx+ii+(i*5)-4],GraphBuffer[idx+ii+(i*5)-3],GraphBuffer[idx+ii+(i*5)-2],GraphBuffer[idx+ii+(i*5)-1],lo);          
        }else {//parity failed
          //PrintAndLog("DEBUG: EM parity failed parity val: %d, i:%d, ii:%d,idx:%d, Buffer: %d%d%d%d%d",parityTest,i,ii,idx,GraphBuffer[idx+ii+(i*5)-5],GraphBuffer[idx+ii+(i*5)-4],GraphBuffer[idx+ii+(i*5)-3],GraphBuffer[idx+ii+(i*5)-2],GraphBuffer[idx+ii+(i*5)-1]);
          parityTest=0;
          idx-=8;
          if (resetCnt>5)return 0;
          resetCnt++;
          goto restart;//continue;
        }
      }
      //skip last 5 bit parity test for simplicity.

      //output em id
      PrintAndLog("EM TAG ID    : %02x%08x", hi, lo);
      //get Unique ID
      uint32_t iii=1;
      uint32_t id2hi=0,id2lo=0;
      for (i=0;i<8;i++){
        id2hi=(id2hi<<1)|((hi & (iii<<(i)))>>i);
      }
      for (ii=4; ii>0;ii--){
        for (i=0;i<8;i++){
          id2lo=(id2lo<<1)|((lo & (iii<<(i+((ii-1)*8))))>>(i+((ii-1)*8)));
        }
      }
      PrintAndLog("Unique TAG ID: %02x%08x", id2hi, id2lo);
      PrintAndLog("DEZ 8        : %08d",lo & 0xFFFFFF);
      PrintAndLog("DEZ 10       : %010d",lo & 0xFFFFFF);
      PrintAndLog("DEZ 5.5      : %05d.%05d",(lo>>16) & 0xFFFF,lo & 0xFFFF);
      PrintAndLog("DEZ 3.5A     : %03d.%05d",hi,lo &0xFFFF);      
      return 0;
    }else{
      idx++;
    }
  }
  return 0;
}


//by marshmellow
//takes 2 arguments - clock and invert both as integers 
//prints binary found and saves in graphbuffer for further commands
int Cmdaskrawdemod(const char *Cmd)
{
  uint32_t i;
  int invert=0;  //invert default
  int high = 0, low = 0;
  int clk=64; //clock default
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN] = {0};
  sscanf(Cmd, "%i %i", &clk, &invert);
  if (!(clk>8)){
    PrintAndLog("Invalid argument: %s",Cmd);
    return 0;
  }
  if (invert != 0 && invert != 1) {
    PrintAndLog("Invalid argument: %s", Cmd);
    return 0;
  }
  uint32_t initLoopMax = 1000;
  if (initLoopMax>GraphTraceLen) initLoopMax=GraphTraceLen;
  // Detect high and lows 
  PrintAndLog("Using Clock: %d  and invert=%d",clk,invert);
  for (i = 0; i < initLoopMax; ++i) //1000 samples should be plenty to find high and low values
  {
    if (GraphBuffer[i] > high)
      high = GraphBuffer[i];
    else if (GraphBuffer[i] < low)
      low = GraphBuffer[i];
  }
  if ((high < 30) && ((high !=1)||(low !=-1))){  //throw away static - allow 1 and -1 (in case of threshold command first)
    PrintAndLog("no data found"); 
    return 0;
  }
  //13% fuzz in case highs and lows aren't clipped [marshmellow]
  high=(int)(0.75*high);
  low=(int)(0.75*low);

  //PrintAndLog("DEBUG - valid high: %d - valid low: %d",high,low);
  int lastBit = 0;  //set first clock check
  uint32_t bitnum = 0;     //output counter
  uint8_t tol = 0;  //clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
  if (clk==32)tol=1;    //clock tolerance may not be needed anymore currently set to + or - 1 but could be increased for poor waves or removed entirely 
  uint32_t iii = 0;
  uint32_t gLen = GraphTraceLen;
  if (gLen > 500) gLen=500;
  uint8_t errCnt =0;
  uint32_t bestStart = GraphTraceLen;
  uint32_t bestErrCnt = (GraphTraceLen/1000);
  //PrintAndLog("DEBUG - lastbit - %d",lastBit);

  //loop to find first wave that works
  for (iii=0; iii < gLen; ++iii){
    if ((GraphBuffer[iii]>=high)||(GraphBuffer[iii]<=low)){
      lastBit=iii-clk;    
      //loop through to see if this start location works
      for (i = iii; i < GraphTraceLen; ++i) {   
        if ((GraphBuffer[i] >= high) && ((i-lastBit)>(clk-tol))){
          lastBit+=clk;
          BitStream[bitnum] =  invert;
          bitnum++;
        } else if ((GraphBuffer[i] <= low) && ((i-lastBit)>(clk-tol))){
          //low found and we are expecting a bar
          lastBit+=clk;
          BitStream[bitnum] = 1-invert; 
          bitnum++;
        } else {
          //mid value found or no bar supposed to be here
          if ((i-lastBit)>(clk+tol)){
            //should have hit a high or low based on clock!!

             
            //debug
            //PrintAndLog("DEBUG - no wave in expected area - location: %d, expected: %d-%d, lastBit: %d - resetting search",i,(lastBit+(clk-((int)(tol)))),(lastBit+(clk+((int)(tol)))),lastBit);
            if (bitnum > 0){
              BitStream[bitnum]=77;
              bitnum++;
            }
            

            errCnt++;
            lastBit+=clk;//skip over until hit too many errors
            if (errCnt>((GraphTraceLen/1000))){  //allow 1 error for every 1000 samples else start over
              errCnt=0;
              bitnum=0;//start over
              break;
            }
          }
        }
      }
      //we got more than 64 good bits and not all errors
      if ((bitnum > (64+errCnt)) && (errCnt<(GraphTraceLen/1000))) {
        //possible good read
        if (errCnt==0) break;  //great read - finish
        if (bestStart = iii) break;  //if current run == bestErrCnt run (after exhausted testing) then finish 
        if (errCnt<bestErrCnt){  //set this as new best run
          bestErrCnt=errCnt;
          bestStart = iii;
        }
      }
    }
    if (iii>=gLen){ //exhausted test
      //if there was a ok test go back to that one and re-run the best run (then dump after that run)
      if (bestErrCnt < (GraphTraceLen/1000)) iii=bestStart;
    }
  }
  if (bitnum>16){
    PrintAndLog("Data start pos:%d, lastBit:%d, stop pos:%d, numBits:%d",iii,lastBit,i,bitnum);
    //move BitStream back to GraphBuffer
    ClearGraph(0);
    for (i=0; i < bitnum; ++i){
      GraphBuffer[i]=BitStream[i];
    }
    GraphTraceLen=bitnum;
    RepaintGraphWindow();
    //output
    if (errCnt>0){
      PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d",errCnt);
    }
    PrintAndLog("ASK decoded bitstream:");
    // Now output the bitstream to the scrollback by line of 16 bits
    printBitStream2(BitStream,bitnum);
    Em410xDecode(Cmd);
  }  
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
//demod GraphBuffer wave to 0s and 1s for each wave - 0s for short waves 1s for long waves
size_t fsk_wave_demod(int size)
{
  uint32_t last_transition = 0;
  uint32_t idx = 1;
  uint32_t maxVal = 0;
  // we don't care about actual value, only if it's more or less than a
  // threshold essentially we capture zero crossings for later analysis
  for(idx=1; idx<size; idx++){
    if(maxVal<GraphBuffer[idx]) maxVal = GraphBuffer[idx];
  }
  // set close to the top of the wave threshold with 13% margin for error
  // less likely to get a false transition up there. 
  // (but have to be careful not to go too high and miss some short waves)
  uint32_t threshold_value = (uint32_t)(maxVal*.87);
  idx=1;
  // int threshold_value = 100;
  
  // sync to first lo-hi transition, and threshold
  //  PrintAndLog("FSK init complete size: %d",size);//debug
  // Need to threshold first sample
  if(GraphBuffer[0] < threshold_value) GraphBuffer[0] = 0;
  else GraphBuffer[0] = 1;
  size_t numBits = 0;
  // count cycles between consecutive lo-hi transitions, there should be either 8 (fc/8)
  // or 10 (fc/10) cycles but in practice due to noise etc we may end up with with anywhere
  // between 7 to 11 cycles so fuzz it by treat anything <9 as 8 and anything else as 10
  for(idx = 1; idx < size; idx++) {
    // threshold current value 
    if (GraphBuffer[idx] < threshold_value) GraphBuffer[idx] = 0;
    else GraphBuffer[idx] = 1;
    // Check for 0->1 transition
    if (GraphBuffer[idx-1] < GraphBuffer[idx]) { // 0 -> 1 transition
      if (idx-last_transition<6){
        // do nothing with extra garbage (shouldn't be any) noise tolerance?
      } else if(idx-last_transition < 9) {
          GraphBuffer[numBits]=1;             
          // Other fsk demods reverse this making the short waves 1 and long waves 0
          // this is really backwards...  smaller waves will typically be 0 and larger 1 [marshmellow]
          // but will leave as is and invert when needed later
      } else{
          GraphBuffer[numBits]=0;
      } 
      last_transition = idx;
      numBits++;
      //  PrintAndLog("numbits %d",numBits);
    }
  }
  return numBits; //Actually, it returns the number of bytes, but each byte represents a bit: 1 or 0
}
uint32_t myround(float f)
{
  if (f >= UINT_MAX) return UINT_MAX;
  return (uint32_t) (f + (float)0.5);
}

//by marshmellow (from holiman's base)
//translate 11111100000 to 10
size_t aggregate_bits(int size, uint8_t rfLen, uint8_t maxConsequtiveBits, uint8_t invert) //,uint8_t l2h_crossing_value
{
  int lastval=GraphBuffer[0];
  uint32_t idx=0;
  size_t numBits=0;
  uint32_t n=1;
  uint32_t n2=0;
  for( idx=1; idx < size; idx++) {

    if (GraphBuffer[idx]==lastval) {
      n++;
      continue;
    }
    // if lastval was 1, we have a 1->0 crossing
    if ( GraphBuffer[idx-1]==1 ) {
      n=myround((float)(n+1)/((float)(rfLen)/(float)8)); //-2 noise tolerance

     // n=(n+1) / h2l_crossing_value;    
                                       //truncating could get us into trouble 
                                       //now we will try with actual clock (RF/64 or RF/50) variable instead
                                       //then devide with float casting then truncate after more acurate division
                                       //and round to nearest int
                                       //like n = (((float)n)/(float)rfLen/(float)10);
    } else {// 0->1 crossing
      n=myround((float)(n+1)/((float)(rfLen-2)/(float)10));  // as int 120/6 = 20 as float 120/(64/10) = 18  (18.75)
      //n=(n+1) / l2h_crossing_value;
    }
    if (n == 0) n = 1; //this should never happen...  should we error if it does?

    if (n < maxConsequtiveBits) // Consecutive  //when the consecutive bits are low - the noise tolerance can be high
                                                //if it is high then we must be careful how much noise tolerance we allow
    {
      if (invert==0){ // do not invert bits 
        for (n2=0; n2<n; n2++){
          GraphBuffer[numBits+n2]=GraphBuffer[idx-1];
        }
        //memset(GraphBuffer+numBits, GraphBuffer[idx-1] , n);
      }else{        // invert bits
        for (n2=0; n2<n; n2++){
          GraphBuffer[numBits+n2]=GraphBuffer[idx-1]^1;
        }
        //memset(GraphBuffer+numBits, GraphBuffer[idx-1]^1 , n);  
      }      
      numBits += n;
    }
    n=0;
    lastval=GraphBuffer[idx];
  }//end for
  return numBits;
}

//by marshmellow  (from holiman's base)
// full fsk demod from GraphBuffer wave to decoded 1s and 0s (no mandemod)
size_t fskdemod(uint8_t rfLen, uint8_t invert)
{
  //uint8_t h2l_crossing_value = 6;
  //uint8_t l2h_crossing_value = 5;
  
  // if (rfLen==64)  //currently only know settings for RF/64 change from default if option entered
  // {
  //   h2l_crossing_value=8;  //or 8  as 64/8 = 8
  //   l2h_crossing_value=6;  //or 6.4 as 64/10 = 6.4
  // }
  size_t size  = GraphTraceLen; 
    // FSK demodulator
  size = fsk_wave_demod(size);
  size = aggregate_bits(size,rfLen,192,invert);
 // size = aggregate_bits(size, h2l_crossing_value, l2h_crossing_value,192, invert); //192=no limit to same values
  //done messing with GraphBuffer - repaint
  RepaintGraphWindow();
  return size;
}
uint32_t bytebits_to_byte(int* src, int numbits)
{
  uint32_t num = 0;
  for(int i = 0 ; i < numbits ; i++)
  {
    num = (num << 1) | (*src);
    src++;
  }
  return num;
}

//by marshmellow
//fsk demod and print binary
int CmdFSKrawdemod(const char *Cmd)
{
  //raw fsk demod no manchester decoding no start bit finding just get binary from wave
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
 
  size_t size  = fskdemod(rfLen,invert); 
  
  PrintAndLog("FSK decoded bitstream:");
  // Now output the bitstream to the scrollback by line of 16 bits
  if(size > (7*32)+2) size = (7*32)+2; //only output a max of 7 blocks of 32 bits  most tags will have full bit stream inside that sample size
  printBitStream(GraphBuffer,size);

  ClearGraph(1);
  return 0;
}

//by marshmellow
int CmdFSKdemodHID(const char *Cmd)
{
  //raw fsk demod no manchester decoding no start bit finding just get binary from wave
  //set defaults
  uint8_t rfLen = 50;
  uint8_t invert=0;//param_get8(Cmd, 0);
  size_t idx=0; 
  uint32_t hi2=0, hi=0, lo=0;

  //get binary from fsk wave
  size_t size = fskdemod(rfLen,invert); 
  
    // final loop, go over previously decoded fsk data and now manchester decode into usable tag ID
    // 111000 bit pattern represent start of frame, 01 pattern represents a 1 and 10 represents a 0
  int frame_marker_mask[] = {1,1,1,0,0,0};
  int numshifts = 0;
  idx = 0;
  while( idx + 6 < size) {
    // search for a start of frame marker

    if ( memcmp(GraphBuffer+idx, frame_marker_mask, sizeof(frame_marker_mask)) == 0)
    { // frame marker found
      idx+=6;//sizeof(frame_marker_mask); //size of int is >6
      while(GraphBuffer[idx] != GraphBuffer[idx+1] && idx < size-2)
      { 
        // Keep going until next frame marker (or error)
        // Shift in a bit. Start by shifting high registers
        hi2 = (hi2<<1)|(hi>>31);
        hi = (hi<<1)|(lo>>31);
        //Then, shift in a 0 or one into low
        if (GraphBuffer[idx] && !GraphBuffer[idx+1])  // 1 0
          lo=(lo<<1)|0;
        else // 0 1
          lo=(lo<<1)|1;
        numshifts++;
        idx += 2;
      }

      //PrintAndLog("Num shifts: %d ", numshifts);
      // Hopefully, we read a tag and  hit upon the next frame marker
      if(idx + 6 < size)
      {
        if ( memcmp(GraphBuffer+(idx), frame_marker_mask, sizeof(frame_marker_mask)) == 0)
        {
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
            ClearGraph(1);
            return 0;
          }
        }
      }
      // reset
      hi2 = hi = lo = 0;
      numshifts = 0;
    }else
    {
      idx++;
    }
  }
  if (idx + sizeof(frame_marker_mask) >= size){
    PrintAndLog("start bits for hid not found");
    PrintAndLog("FSK decoded bitstream:");
    // Now output the bitstream to the scrollback by line of 16 bits
    printBitStream(GraphBuffer,size);
 
  }
  ClearGraph(1);
  return 0;
}

//by marshmellow
int CmdFSKdemodIO(const char *Cmd)
{
  //raw fsk demod no manchester decoding no start bit finding just get binary from wave
  //set defaults
  uint8_t rfLen = 64;
  uint8_t invert=1;
  size_t idx=0; 
  uint8_t testMax=0;
  //test samples are not just noise
  if (GraphTraceLen < 64) return 0;
  for(idx=0;idx<64;idx++){
    if (testMax<GraphBuffer[idx]) testMax=GraphBuffer[idx];
  }
  idx=0;
  //get full binary from fsk wave
  size_t size = fskdemod(rfLen,invert); 
 
  //if not just noise
  //PrintAndLog("testMax %d",testMax);
  if (testMax>40){
    //Index map
    //0           10          20          30          40          50          60
    //|           |           |           |           |           |           |
    //01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
    //-----------------------------------------------------------------------------
    //00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1 ???????? 11
    //
    //XSF(version)facility:codeone+codetwo (raw)
    //Handle the data
    int mask[] = {0,0,0,0,0,0,0,0,0,1};
    for( idx=0; idx < (size - 74); idx++) {
      if ( memcmp(GraphBuffer + idx, mask, sizeof(mask))==0) { 
        //frame marker found
        if (GraphBuffer[idx+17]==1 && GraphBuffer[idx+26]==1 && GraphBuffer[idx+35]==1 && GraphBuffer[idx+44]==1 && GraphBuffer[idx+53]==1){
          //confirmed proper separator bits found
          
          PrintAndLog("%d%d%d%d%d%d%d%d %d",GraphBuffer[idx],    GraphBuffer[idx+1],  GraphBuffer[idx+2], GraphBuffer[idx+3], GraphBuffer[idx+4], GraphBuffer[idx+5], GraphBuffer[idx+6], GraphBuffer[idx+7], GraphBuffer[idx+8]);
          PrintAndLog("%d%d%d%d%d%d%d%d %d",GraphBuffer[idx+9],  GraphBuffer[idx+10], GraphBuffer[idx+11],GraphBuffer[idx+12],GraphBuffer[idx+13],GraphBuffer[idx+14],GraphBuffer[idx+15],GraphBuffer[idx+16],GraphBuffer[idx+17]);       
          PrintAndLog("%d%d%d%d%d%d%d%d %d",GraphBuffer[idx+18], GraphBuffer[idx+19], GraphBuffer[idx+20],GraphBuffer[idx+21],GraphBuffer[idx+22],GraphBuffer[idx+23],GraphBuffer[idx+24],GraphBuffer[idx+25],GraphBuffer[idx+26]);
          PrintAndLog("%d%d%d%d%d%d%d%d %d",GraphBuffer[idx+27], GraphBuffer[idx+28], GraphBuffer[idx+29],GraphBuffer[idx+30],GraphBuffer[idx+31],GraphBuffer[idx+32],GraphBuffer[idx+33],GraphBuffer[idx+34],GraphBuffer[idx+35]);
          PrintAndLog("%d%d%d%d%d%d%d%d %d",GraphBuffer[idx+36], GraphBuffer[idx+37], GraphBuffer[idx+38],GraphBuffer[idx+39],GraphBuffer[idx+40],GraphBuffer[idx+41],GraphBuffer[idx+42],GraphBuffer[idx+43],GraphBuffer[idx+44]);
          PrintAndLog("%d%d%d%d%d%d%d%d %d",GraphBuffer[idx+45], GraphBuffer[idx+46], GraphBuffer[idx+47],GraphBuffer[idx+48],GraphBuffer[idx+49],GraphBuffer[idx+50],GraphBuffer[idx+51],GraphBuffer[idx+52],GraphBuffer[idx+53]);
          PrintAndLog("%d%d%d%d%d%d%d%d %d%d",GraphBuffer[idx+54],GraphBuffer[idx+55],GraphBuffer[idx+56],GraphBuffer[idx+57],GraphBuffer[idx+58],GraphBuffer[idx+59],GraphBuffer[idx+60],GraphBuffer[idx+61],GraphBuffer[idx+62],GraphBuffer[idx+63]);
      
          uint32_t code = bytebits_to_byte(GraphBuffer+idx,32);
          uint32_t code2 = bytebits_to_byte(GraphBuffer+idx+32,32); 
          short version = bytebits_to_byte(GraphBuffer+idx+27,8); //14,4
          uint8_t facilitycode = bytebits_to_byte(GraphBuffer+idx+19,8) ;
          uint16_t number = (bytebits_to_byte(GraphBuffer+idx+36,8)<<8)|(bytebits_to_byte(GraphBuffer+idx+45,8)); //36,9
          
          PrintAndLog("XSF(%02d)%02x:%d (%08x%08x)",version,facilitycode,number,code,code2);    
          ClearGraph(1); 
          return 0;
        } else {
          PrintAndLog("thought we had a valid tag but did not match format");
        }
      }   
    }
    if (idx >= (size-74)){
      PrintAndLog("start bits for io prox not found");
      PrintAndLog("FSK decoded bitstream:");
      // Now output the bitstream to the scrollback by line of 16 bits
      printBitStream(GraphBuffer,size);  
    }
  }
  ClearGraph(1);
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
  {"askrawdemod",   Cmdaskrawdemod,     1, "[clock] [invert<0 or 1>] -- Attempt to demodulate simple ASK tags and output binary (args optional-defaults='64 0')"},
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
