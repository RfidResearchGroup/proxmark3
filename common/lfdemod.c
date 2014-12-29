//-----------------------------------------------------------------------------
// Copyright (C) 2014 
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency commands
//-----------------------------------------------------------------------------

//#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <inttypes.h>
//#include <limits.h>
#include "lfdemod.h"
//#include "proxmark3.h"
//#include "data.h"
//#include "ui.h"
//#include "graph.h"
//#include "cmdparser.h"
//#include "util.h"
//#include "cmdmain.h"
//#include "cmddata.h"
//uint8_t BinStream[MAX_GRAPH_TRACE_LEN];
//uint8_t BinStreamLen;

//by marshmellow
//takes 1s and 0s and searches for EM410x format - output EM ID
uint64_t Em410xDecode(uint8_t *BitStream,uint32_t BitLen)
{
  //no arguments needed - built this way in case we want this to be a direct call from "data " cmds in the future
  //  otherwise could be a void with no arguments
  //set defaults
  int high=0, low=0;
  uint64_t lo=0; //hi=0,

  uint32_t i = 0;
  uint32_t initLoopMax = 65;
  if (initLoopMax>BitLen) initLoopMax=BitLen;

  for (;i < initLoopMax; ++i) //65 samples should be plenty to find high and low values
  {
    if (BitStream[i] > high)
      high = BitStream[i];
    else if (BitStream[i] < low)
      low = BitStream[i];
  }
  if (((high !=1)||(low !=0))){  //allow only 1s and 0s 
   // PrintAndLog("no data found"); 
    return 0;
  }
  uint8_t parityTest=0;
   // 111111111 bit pattern represent start of frame
  uint8_t frame_marker_mask[] = {1,1,1,1,1,1,1,1,1};
  uint32_t idx = 0;
  uint32_t ii=0;
  uint8_t resetCnt = 0;
  while( (idx + 64) < BitLen) {
 restart:
    // search for a start of frame marker
    if ( memcmp(BitStream+idx, frame_marker_mask, sizeof(frame_marker_mask)) == 0)
    { // frame marker found
      idx+=9;//sizeof(frame_marker_mask);
      for (i=0; i<10;i++){
        for(ii=0; ii<5; ++ii){
          parityTest += BitStream[(i*5)+ii+idx];        
        }
        if (parityTest== ((parityTest>>1)<<1)){
          parityTest=0;
          for (ii=0; ii<4;++ii){
            //hi = (hi<<1)|(lo>>31);
            lo=(lo<<1LL)|(BitStream[(i*5)+ii+idx]);
          }
          //PrintAndLog("DEBUG: EM parity passed parity val: %d, i:%d, ii:%d,idx:%d, Buffer: %d%d%d%d%d,lo: %d",parityTest,i,ii,idx,BitStream[idx+ii+(i*5)-5],BitStream[idx+ii+(i*5)-4],BitStream[idx+ii+(i*5)-3],BitStream[idx+ii+(i*5)-2],BitStream[idx+ii+(i*5)-1],lo);          
        }else {//parity failed
          //PrintAndLog("DEBUG: EM parity failed parity val: %d, i:%d, ii:%d,idx:%d, Buffer: %d%d%d%d%d",parityTest,i,ii,idx,BitStream[idx+ii+(i*5)-5],BitStream[idx+ii+(i*5)-4],BitStream[idx+ii+(i*5)-3],BitStream[idx+ii+(i*5)-2],BitStream[idx+ii+(i*5)-1]);
          parityTest=0;
          idx-=8;
          if (resetCnt>5)return 0;
          resetCnt++;
          goto restart;//continue;
        }
      }
      //skip last 5 bit parity test for simplicity.
      return lo;
    }else{
      idx++;
    }
  }
  return 0;
}

//by marshmellow
//takes 2 arguments - clock and invert both as integers
//attempts to demodulate ask while decoding manchester 
//prints binary found and saves in graphbuffer for further commands
int askmandemod(uint8_t * BinStream,uint32_t *BitLen,int *clk, int *invert)
{
  uint32_t i;
  //int invert=0;  //invert default
  int high = 0, low = 0;
  *clk=DetectClock2(BinStream,(size_t)*BitLen,*clk); //clock default
  uint8_t BitStream[252] = {0};

  //sscanf(Cmd, "%i %i", &clk, &invert);    
  if (*clk<8) *clk =64;
  if (*clk<32) *clk=32;
  if (*invert != 0 && *invert != 1) *invert=0;
  uint32_t initLoopMax = 200;
  if (initLoopMax>*BitLen) initLoopMax=*BitLen;
  // Detect high and lows 
  //PrintAndLog("Using Clock: %d  and invert=%d",clk,invert);
  for (i = 0; i < initLoopMax; ++i) //200 samples should be enough to find high and low values
  {
    if (BinStream[i] > high)
      high = BinStream[i];
    else if (BinStream[i] < low)
      low = BinStream[i];
  }
  if ((high < 30) && ((high !=1)||(low !=-1))){  //throw away static - allow 1 and -1 (in case of threshold command first)
    //PrintAndLog("no data found"); 
    return -1;
  }
  //13% fuzz in case highs and lows aren't clipped [marshmellow]
  high=(int)(0.75*high);
  low=(int)(0.75*low);

  //PrintAndLog("DEBUG - valid high: %d - valid low: %d",high,low);
  int lastBit = 0;  //set first clock check
  uint32_t bitnum = 0;     //output counter
  uint8_t tol = 0;  //clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
  if (*clk==32)tol=1;    //clock tolerance may not be needed anymore currently set to + or - 1 but could be increased for poor waves or removed entirely 
  uint32_t iii = 0;
  uint32_t gLen = *BitLen;
  if (gLen > 500) gLen=500;
  uint8_t errCnt =0;
  uint32_t bestStart = *BitLen;
  uint32_t bestErrCnt = (*BitLen/1000);
  //PrintAndLog("DEBUG - lastbit - %d",lastBit);
  //loop to find first wave that works
  for (iii=0; iii < gLen; ++iii){
    if ((BinStream[iii]>=high)||(BinStream[iii]<=low)){
      lastBit=iii-*clk;    
      bitnum=0;
      //loop through to see if this start location works
      for (i = iii; i < *BitLen; ++i) {   
        if ((BinStream[i] >= high) && ((i-lastBit)>(*clk-tol))){
          lastBit+=*clk;
          BitStream[bitnum] =  *invert;
          bitnum++;
        } else if ((BinStream[i] <= low) && ((i-lastBit)>(*clk-tol))){
          //low found and we are expecting a bar
          lastBit+=*clk;
          BitStream[bitnum] = 1-*invert; 
          bitnum++;
        } else {
          //mid value found or no bar supposed to be here
          if ((i-lastBit)>(*clk+tol)){
            //should have hit a high or low based on clock!!

             
            //debug
            //PrintAndLog("DEBUG - no wave in expected area - location: %d, expected: %d-%d, lastBit: %d - resetting search",i,(lastBit+(clk-((int)(tol)))),(lastBit+(clk+((int)(tol)))),lastBit);
            if (bitnum > 0){
              BitStream[bitnum]=77;
              bitnum++;
            }
            

            errCnt++;
            lastBit+=*clk;//skip over until hit too many errors
            if (errCnt>((*BitLen/1000))){  //allow 1 error for every 1000 samples else start over
              errCnt=0;
              bitnum=0;//start over
              break;
            }
          }
        }
        if (bitnum >250) break;
      }
      //we got more than 64 good bits and not all errors
      if ((bitnum > (64+errCnt)) && (errCnt<(*BitLen/1000))) {
        //possible good read
        if (errCnt==0) break;  //great read - finish
        if (bestStart == iii) break;  //if current run == bestErrCnt run (after exhausted testing) then finish 
        if (errCnt<bestErrCnt){  //set this as new best run
          bestErrCnt=errCnt;
          bestStart = iii;
        }
      }
    }
    if (iii>=gLen){ //exhausted test
      //if there was a ok test go back to that one and re-run the best run (then dump after that run)
      if (bestErrCnt < (*BitLen/1000)) iii=bestStart;
    }
  }
  if (bitnum>16){
    
   // PrintAndLog("Data start pos:%d, lastBit:%d, stop pos:%d, numBits:%d",iii,lastBit,i,bitnum);
    //move BitStream back to GraphBuffer
    //ClearGraph(0);
    for (i=0; i < bitnum; ++i){
      BinStream[i]=BitStream[i];
    }
    *BitLen=bitnum;
    //RepaintGraphWindow();
    //output
    //if (errCnt>0){
     // PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d",errCnt);
    //}
   // PrintAndLog("ASK decoded bitstream:");
    // Now output the bitstream to the scrollback by line of 16 bits
   // printBitStream2(BitStream,bitnum);
   // Em410xDecode(Cmd);
  }  
  return errCnt;
}

//by marshmellow
//take 10 and 01 and manchester decode
//run through 2 times and take least errCnt
int manrawdemod(uint8_t * BitStream, int *bitLen)
{
  uint8_t BitStream2[252]={0};
  int bitnum=0;
  int errCnt =0;
  int i=1;
  int bestErr = 1000;
  int bestRun = 0;
  int finish = 0;
  int ii=1;
  for (ii=1;ii<3;++ii){
  	i=1;
		for (i=i+ii;i<*bitLen-2;i+=2){
		  if(BitStream[i]==1 && (BitStream[i+1]==0)){
		    BitStream2[bitnum++]=0;
		  } else if((BitStream[i]==0)&& BitStream[i+1]==1){
		    BitStream2[bitnum++]=1;
	    } else {
		    BitStream2[bitnum++]=77;
		      errCnt++;
	    }
	    if(bitnum>250) break;
		}
		if (bestErr>errCnt){
		  bestErr=errCnt;
		  bestRun=ii;
		}	
		if (ii>1 || finish==1) {
			if (bestRun==ii) {
				break;
			}  else{
			  ii=bestRun-1;
		    finish=1;
		  }	
		}
		errCnt=0;
		bitnum=0;
  }
  errCnt=bestErr;
  if (errCnt<20){
    for (i=0; i<bitnum;++i){
      BitStream[i]=BitStream2[i];
    }  
    *bitLen=bitnum;
  }
  return errCnt;
}

//by marshmellow
//takes 2 arguments - clock and invert both as integers
//attempts to demodulate ask only
//prints binary found and saves in graphbuffer for further commands
int askrawdemod(uint8_t *BinStream, int *bitLen,int *clk, int *invert)
{
  uint32_t i;
 // int invert=0;  //invert default
  int high = 0, low = 0;
  *clk=DetectClock2(BinStream,*bitLen,*clk); //clock default
  uint8_t BitStream[502] = {0};

  if (*clk<8) *clk =64;
  if (*clk<32) *clk=32;
  if (*invert != 0 && *invert != 1) *invert =0;
  uint32_t initLoopMax = 200;
  if (initLoopMax>*bitLen) initLoopMax=*bitLen;
  // Detect high and lows 
  for (i = 0; i < initLoopMax; ++i) //200 samples should be plenty to find high and low values
  {
    if (BinStream[i] > high)
      high = BinStream[i];
    else if (BinStream[i] < low)
      low = BinStream[i];
  }
  if ((high < 30) && ((high !=1)||(low !=-1))){  //throw away static - allow 1 and -1 (in case of threshold command first)
 //   PrintAndLog("no data found"); 
    return -1;
  }
  //25% fuzz in case highs and lows aren't clipped [marshmellow]
  high=(int)(0.75*high);
  low=(int)(0.75*low);

  //PrintAndLog("DEBUG - valid high: %d - valid low: %d",high,low);
  int lastBit = 0;  //set first clock check
  uint32_t bitnum = 0;     //output counter
  uint8_t tol = 0;  //clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
  if (*clk==32)tol=1;    //clock tolerance may not be needed anymore currently set to + or - 1 but could be increased for poor waves or removed entirely 
  uint32_t iii = 0;
  uint32_t gLen = *bitLen;
  if (gLen > 500) gLen=500;
  uint8_t errCnt =0;
  uint32_t bestStart = *bitLen;
  uint32_t bestErrCnt = (*bitLen/1000);
  uint8_t midBit=0;
  //PrintAndLog("DEBUG - lastbit - %d",lastBit);
  //loop to find first wave that works
  for (iii=0; iii < gLen; ++iii){
    if ((BinStream[iii]>=high)||(BinStream[iii]<=low)){
      lastBit=iii-*clk;    
      //loop through to see if this start location works
      for (i = iii; i < *bitLen; ++i) {  
        if ((BinStream[i] >= high) && ((i-lastBit)>(*clk-tol))){
          lastBit+=*clk;
          BitStream[bitnum] =  *invert;
          bitnum++;
          midBit=0;
        } else if ((BinStream[i] <= low) && ((i-lastBit)>(*clk-tol))){
          //low found and we are expecting a bar
          lastBit+=*clk;
          BitStream[bitnum] = 1-*invert; 
          bitnum++;
          midBit=0;
        } else if ((BinStream[i]<=low) && (midBit==0) && ((i-lastBit)>((*clk/2)-tol))){
          //mid bar?
          midBit=1;
          BitStream[bitnum]= 1-*invert;
          bitnum++;
        } else if ((BinStream[i]>=high)&&(midBit==0) && ((i-lastBit)>((*clk/2)-tol))){
          //mid bar?
          midBit=1;
          BitStream[bitnum]= *invert;
          bitnum++;
        } else if ((i-lastBit)>((*clk/2)+tol)&&(midBit==0)){
          //no mid bar found
          midBit=1;
          BitStream[bitnum]= BitStream[bitnum-1];
          bitnum++;
        } else {
          //mid value found or no bar supposed to be here

          if ((i-lastBit)>(*clk+tol)){
            //should have hit a high or low based on clock!!
            //debug
            //PrintAndLog("DEBUG - no wave in expected area - location: %d, expected: %d-%d, lastBit: %d - resetting search",i,(lastBit+(clk-((int)(tol)))),(lastBit+(clk+((int)(tol)))),lastBit);
            if (bitnum > 0){
              BitStream[bitnum]=77;
              bitnum++;
            }
            

            errCnt++;
            lastBit+=*clk;//skip over until hit too many errors
            if (errCnt>((*bitLen/1000))){  //allow 1 error for every 1000 samples else start over
              errCnt=0;
              bitnum=0;//start over
              break;
            }
          }          
        }
        if (bitnum>500) break;
      }
      //we got more than 64 good bits and not all errors
      if ((bitnum > (64+errCnt)) && (errCnt<(*bitLen/1000))) {
        //possible good read
        if (errCnt==0) break;  //great read - finish
        if (bestStart == iii) break;  //if current run == bestErrCnt run (after exhausted testing) then finish 
        if (errCnt<bestErrCnt){  //set this as new best run
          bestErrCnt=errCnt;
          bestStart = iii;
        }
      }
    }
    if (iii>=gLen){ //exhausted test
      //if there was a ok test go back to that one and re-run the best run (then dump after that run)
      if (bestErrCnt < (*bitLen/1000)) iii=bestStart;
    }
  }
  if (bitnum>16){
    
   // PrintAndLog("Data start pos:%d, lastBit:%d, stop pos:%d, numBits:%d",iii,lastBit,i,bitnum);
    //move BitStream back to BinStream
   // ClearGraph(0);
    for (i=0; i < bitnum; ++i){
      BinStream[i]=BitStream[i];
    }
    *bitLen=bitnum;
   // RepaintGraphWindow();
    //output
   // if (errCnt>0){
   //   PrintAndLog("# Errors during Demoding (shown as 77 in bit stream): %d",errCnt);
   // }
   // PrintAndLog("ASK decoded bitstream:");
    // Now output the bitstream to the scrollback by line of 16 bits
   // printBitStream2(BitStream,bitnum);
    //int errCnt=0;
    //errCnt=manrawdemod(BitStream,bitnum);

 //   Em410xDecode(Cmd);
  } else return -1;
  return errCnt;
}
//translate wave to 11111100000 (1 for each short wave 0 for each long wave) 
size_t fsk_wave_demod(uint8_t * dest, size_t size)
{
	uint32_t last_transition = 0;
	uint32_t idx = 1;
	uint32_t maxVal=0;
	
	// we do care about the actual theshold value as sometimes near the center of the
	// wave we may get static that changes direction of wave for one value
	// if our value is too low it might affect the read.  and if our tag or
	// antenna is weak a setting too high might not see anything. [marshmellow]
	if (size<100) return 0;
	for(idx=1; idx<100; idx++){
    	if(maxVal<dest[idx]) maxVal = dest[idx];
    }
    // set close to the top of the wave threshold with 13% margin for error
    // less likely to get a false transition up there. 
    // (but have to be careful not to go too high and miss some short waves)
  	uint8_t threshold_value = (uint8_t)(maxVal*.87); 	idx=1;
		//uint8_t threshold_value = 127;
	
	// sync to first lo-hi transition, and threshold

	// Need to threshold first sample
	if(dest[0] < threshold_value) dest[0] = 0;
	else dest[0] = 1;

	size_t numBits = 0;
	// count cycles between consecutive lo-hi transitions, there should be either 8 (fc/8)
	// or 10 (fc/10) cycles but in practice due to noise etc we may end up with with anywhere
	// between 7 to 11 cycles so fuzz it by treat anything <9 as 8 and anything else as 10
	for(idx = 1; idx < size; idx++) {
		// threshold current value
		if (dest[idx] < threshold_value) dest[idx] = 0;
		else dest[idx] = 1;

		// Check for 0->1 transition
		if (dest[idx-1] < dest[idx]) { // 0 -> 1 transition
			if (idx-last_transition<6){            //0-5 = garbage noise
				//do nothing with extra garbage
			} else if (idx-last_transition <  9) { //6-8 = 8 waves
				dest[numBits]=1;
			} else {							//9+ = 10 waves
				dest[numBits]=0;
			}
			last_transition = idx;
			numBits++;
		}
	}
	return numBits; //Actually, it returns the number of bytes, but each byte represents a bit: 1 or 0
}

uint32_t myround2(float f)
{
  if (f >= 2000) return 2000;//something bad happened
  return (uint32_t) (f + (float)0.5);
}

//translate 11111100000 to 10 
size_t aggregate_bits(uint8_t *dest,size_t size,  uint8_t rfLen, uint8_t maxConsequtiveBits, uint8_t invert )// uint8_t h2l_crossing_value,uint8_t l2h_crossing_value, 
{
	uint8_t lastval=dest[0];
	uint32_t idx=0;
	size_t numBits=0;
	uint32_t n=1;

	for( idx=1; idx < size; idx++) {

		if (dest[idx]==lastval) {
			n++;
			continue;
		}
		//if lastval was 1, we have a 1->0 crossing
		if ( dest[idx-1]==1 ) {
			n=myround2((float)(n+1)/((float)(rfLen)/(float)8));
			//n=(n+1) / h2l_crossing_value;
		} else {// 0->1 crossing
			n=myround2((float)(n+1)/((float)(rfLen-2)/(float)10));  //-2 for fudge factor
			//n=(n+1) / l2h_crossing_value;
		}
		if (n == 0) n = 1;

		if(n < maxConsequtiveBits) //Consecutive 
		{
			if(invert==0){ //invert bits 
				memset(dest+numBits, dest[idx-1] , n);
			}else{
				memset(dest+numBits, dest[idx-1]^1 , n);	
			}			
			numBits += n;
		}
		n=0;
		lastval=dest[idx];
	}//end for
	return numBits;
}
//by marshmellow  (from holiman's base)
// full fsk demod from GraphBuffer wave to decoded 1s and 0s (no mandemod)
int fskdemod(uint8_t *dest, size_t size, uint8_t rfLen, uint8_t invert)
{
  //uint8_t h2l_crossing_value = 6;
  //uint8_t l2h_crossing_value = 5;
  
  // if (rfLen==64)  //currently only know settings for RF/64 change from default if option entered
  // {
  //   h2l_crossing_value=8;  //or 8  as 64/8 = 8
  //   l2h_crossing_value=6;  //or 6.4 as 64/10 = 6.4
  // }
 // size_t size  = GraphTraceLen; 
    // FSK demodulator
  size = fsk_wave_demod(dest, size);
  size = aggregate_bits(dest, size,rfLen,192,invert);
 // size = aggregate_bits(size, h2l_crossing_value, l2h_crossing_value,192, invert); //192=no limit to same values
  //done messing with GraphBuffer - repaint
  //RepaintGraphWindow();
  return size;
}
// loop to get raw HID waveform then FSK demodulate the TAG ID from it
int HIDdemodFSK(uint8_t *dest, size_t size, uint32_t *hi2, uint32_t *hi, uint32_t *lo)
{
	
	size_t idx=0; //, found=0; //size=0,
	// FSK demodulator
	size = fskdemod(dest, size,50,0);

	// final loop, go over previously decoded manchester data and decode into usable tag ID
	// 111000 bit pattern represent start of frame, 01 pattern represents a 1 and 10 represents a 0
	uint8_t frame_marker_mask[] = {1,1,1,0,0,0};
	int numshifts = 0;
	idx = 0;
	//one scan
	while( idx + sizeof(frame_marker_mask) < size) {
	// search for a start of frame marker
		if ( memcmp(dest+idx, frame_marker_mask, sizeof(frame_marker_mask)) == 0)
		{ // frame marker found
			idx+=sizeof(frame_marker_mask);
			while(dest[idx] != dest[idx+1] && idx < size-2)
			{	
				// Keep going until next frame marker (or error)
				// Shift in a bit. Start by shifting high registers
				*hi2 = (*hi2<<1)|(*hi>>31);
				*hi = (*hi<<1)|(*lo>>31);
				//Then, shift in a 0 or one into low
				if (dest[idx] && !dest[idx+1])	// 1 0
					*lo=(*lo<<1)|0;
				else // 0 1
					*lo=(*lo<<1)|1;
				numshifts++;
				idx += 2;
			}
			// Hopefully, we read a tag and	 hit upon the next frame marker
			if(idx + sizeof(frame_marker_mask) < size)
			{
				if ( memcmp(dest+idx, frame_marker_mask, sizeof(frame_marker_mask)) == 0)
				{
					//good return 
					return idx;
				}
			}
			// reset
			*hi2 = *hi = *lo = 0;
			numshifts = 0;
		}else	{
			idx++;
		}
	}
	return -1;
}

uint32_t bytebits_to_byte(uint8_t* src, int numbits)
{
	uint32_t num = 0;
	for(int i = 0 ; i < numbits ; i++)
	{
		num = (num << 1) | (*src);
		src++;
	}
	return num;
}

int IOdemodFSK(uint8_t *dest, size_t size)
{
  uint32_t idx=0;
	//make sure buffer has data
	if (size < 64) return -1;
	//test samples are not just noise
	uint8_t testMax=0;
	for(idx=0;idx<64;idx++){
		if (testMax<dest[idx]) testMax=dest[idx];
	}
	idx=0;
	//if not just noise
	if (testMax>170){
		// FSK demodulator
		size = fskdemod(dest, size,64,1);
		//Index map
		//0           10          20          30          40          50          60
		//|           |           |           |           |           |           |
		//01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
		//-----------------------------------------------------------------------------
		//00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1 ???????? 11
		//
		//XSF(version)facility:codeone+codetwo
		//Handle the data
 	  uint8_t mask[] = {0,0,0,0,0,0,0,0,0,1};
		for( idx=0; idx < (size - 74); idx++) {
    	if ( memcmp(dest + idx, mask, sizeof(mask))==0) {
    		//frame marker found
    		if (!dest[idx+8] && dest[idx+17]==1 && dest[idx+26]==1 && dest[idx+35]==1 && dest[idx+44]==1 && dest[idx+53]==1){
    			//confirmed proper separator bits found
    			//return start position
					return (int) idx;
				}
			}		
		}
	}	
	return 0;
}

// by marshmellow
// not perfect especially with lower clocks or VERY good antennas (heavy wave clipping)
// maybe somehow adjust peak trimming value based on samples to fix?
int DetectClock2(uint8_t dest[], size_t size, int clock)
{
  int i=0;
  int peak=0;
  int low=0;
  int clk[]={16,32,40,50,64,100,128,256};
  for (;i<8;++i)
  	if (clk[i]==clock) return clock;
  if (!peak){
    for (i=0;i<size;++i){
      if(dest[i]>peak){
        peak = dest[i]; 
      }
      if(dest[i]<low){
        low = dest[i];
      }
    }
    peak=(int)(peak*.75);
    low= (int)(low*.75);
  }
  int ii;
  int loopCnt = 256;
  if (size<loopCnt) loopCnt = size;
  int clkCnt;
  int tol = 0;
  int bestErr=1000;
  int errCnt[]={0,0,0,0,0,0,0,0};
  for(clkCnt=0; clkCnt<6;++clkCnt){
    if (clk[clkCnt]==32){
      tol=1;
    }else{
      tol=0;
    }
    bestErr=1000;
    for (ii=0; ii<loopCnt; ++ii){
      if ((dest[ii]>=peak) || (dest[ii]<=low)){
        errCnt[clkCnt]=0;
        for (i=0; i<((int)(size/clk[clkCnt])-1); ++i){
          if (dest[ii+(i*clk[clkCnt])]>=peak || dest[ii+(i*clk[clkCnt])]<=low){
         }else if(dest[ii+(i*clk[clkCnt])-tol]>=peak || dest[ii+(i*clk[clkCnt])-tol]<=low){
          }else if(dest[ii+(i*clk[clkCnt])+tol]>=peak || dest[ii+(i*clk[clkCnt])+tol]<=low){
          }else{  //error no peak detected
            errCnt[clkCnt]++;
          }    
        }
        if(errCnt[clkCnt]==0) return clk[clkCnt];
        if(errCnt[clkCnt]<bestErr) bestErr=errCnt[clkCnt];
      }
    } 
    errCnt[clkCnt]=bestErr;
  }
  int iii=0;
  int best=0;
  for (iii=0; iii<6;++iii){
    if (errCnt[iii]<errCnt[best]){
      best = iii;
    }
  }
  return clk[best];
}
