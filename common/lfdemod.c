//-----------------------------------------------------------------------------
// Copyright (C) 2014 
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lfdemod.h"

//by marshmellow
//takes 1s and 0s and searches for EM410x format - output EM ID
uint64_t Em410xDecode(uint8_t *BitStream, uint32_t BitLen)
{
	//no arguments needed - built this way in case we want this to be a direct call from "data " cmds in the future
	//  otherwise could be a void with no arguments
	//set defaults
	int high = 0, low = 128;
	uint64_t lo = 0; 
	uint32_t i = 0;
	uint32_t initLoopMax = 65;

	if (initLoopMax > BitLen) 
		initLoopMax = BitLen;

	for (; i < initLoopMax; ++i) //65 samples should be plenty to find high and low values
	{
		if (BitStream[i] > high)
			high = BitStream[i];
		else if (BitStream[i] < low)
			low = BitStream[i];
	}

	if (((high !=1)||(low !=0))){  //allow only 1s and 0s 
		return 0;
	}

	uint8_t parityTest = 0;
	// 111111111 bit pattern represent start of frame
	uint8_t frame_marker_mask[] = {1,1,1,1,1,1,1,1,1};
	uint32_t idx = 0;
	uint32_t j = 0;
	uint8_t resetCnt = 0;
	while( (idx + 64) < BitLen) {

	restart:

    // search for a start of frame marker
    if ( memcmp(BitStream+idx, frame_marker_mask, sizeof(frame_marker_mask)) == 0) {
		// frame marker found
		idx += 9;//sizeof(frame_marker_mask);
		for ( i = 0; i < 10; ++i){
			for( j = 0; j < 5; ++j){
				parityTest += BitStream[(i*5) + j + idx];        
			}
			if (parityTest == ( (parityTest >> 1) << 1)){
				parityTest = 0;
				for (j = 0; j < 4; ++j){
					lo = ( lo << 1LL)|( BitStream[( i * 5 ) + j + idx]);
				}
			} else {
				//parity failed
				parityTest = 0;
				idx -= 8;
				if (resetCnt > 5) return 0;
				resetCnt++;
				goto restart;//continue;
			}
		}
		//skip last 5 bit parity test for simplicity.
		return lo;
		} else {
			idx++;
		}
	}	
	return 0;
}

//by marshmellow
//takes 2 arguments - clock and invert both as integers
//attempts to demodulate ask while decoding manchester 
//prints binary found and saves in graphbuffer for further commands
int askmandemod(uint8_t *BinStream, uint32_t *BitLen, int *clk, int *invert)
{
	int i;
	int high = 0, low = 128;
	*clk = DetectASKClock(BinStream, (size_t)*BitLen, *clk); //clock default
	
	if (*clk < 8 )    *clk = 64;
	if (*clk < 32 )	  *clk = 32;
	if (*invert != 1) *invert = 0;
	
	uint32_t initLoopMax = 200;
	if (initLoopMax > *BitLen) 
		initLoopMax = *BitLen;
  
	// Detect high and lows 
	// 200 samples should be enough to find high and low values
	for (i = 0; i < initLoopMax; ++i) {
		if (BinStream[i] > high)
			high = BinStream[i];
		else if (BinStream[i] < low)
			low = BinStream[i];
	}
  
	//throw away static 
	if ((high < 158) )
		return -2;

	//25% fuzz in case highs and lows aren't clipped [marshmellow]
	high = (int)(high * .75);
	low  = (int)(low+128 * .25);
 
	int lastBit = 0;      // set first clock check
	uint32_t bitnum = 0;  // output counter

	// clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
	//clock tolerance may not be needed anymore currently set to + or - 1 but could be increased for poor waves or removed entirely 
	int tol = ( *clk == 32 ) ? 1 : 0;  

	int j = 0;
	uint32_t gLen = *BitLen;

	if (gLen > 3000) gLen = 3000;

	uint8_t errCnt = 0;
	uint32_t bestStart = *BitLen;
	uint32_t bestErrCnt = (*BitLen/1000);
	uint32_t maxErr = bestErrCnt;

  //loop to find first wave that works
	for (j=0; j < gLen; ++j){
  
		if ((BinStream[j] >= high)||(BinStream[j] <= low)){
		  lastBit = j - *clk;    
		  errCnt = 0;
	  
      //loop through to see if this start location works
      for (i = j; i < *BitLen; ++i) {   
        if ((BinStream[i] >= high) && ((i-lastBit)>(*clk-tol))){
          lastBit += *clk;
        } else if ((BinStream[i] <= low) && ((i-lastBit)>(*clk-tol))){
          //low found and we are expecting a bar
          lastBit += *clk;
        } else {
          //mid value found or no bar supposed to be here
          if ((i-lastBit) > (*clk + tol)){
            //should have hit a high or low based on clock!!
           
            errCnt++;
            lastBit += *clk;//skip over until hit too many errors
            if (errCnt > maxErr) break;  //allow 1 error for every 1000 samples else start over
          }
        }
        if ((i-j) >(400 * *clk)) break; //got plenty of bits
      }
      //we got more than 64 good bits and not all errors
      if ((((i-j)/ *clk) > (64 + errCnt)) && (errCnt < maxErr)) {
        //possible good read
        if (errCnt == 0){
			bestStart = j;
			bestErrCnt = errCnt;
			break;  //great read - finish
        } 
        if (errCnt < bestErrCnt){  //set this as new best run
          bestErrCnt = errCnt;
          bestStart = j;
        }
      }
    }
  }
  if (bestErrCnt < maxErr){
  	//best run is good enough set to best run and set overwrite BinStream
  	j = bestStart;
  	lastBit = bestStart - *clk;
  	bitnum = 0;
    for (i = j; i < *BitLen; ++i) {   
		if ((BinStream[i] >= high) && ((i-lastBit)>(*clk-tol))){
			lastBit += *clk;
			BinStream[bitnum] = *invert;
			bitnum++;
		} else if ((BinStream[i] <= low) && ((i-lastBit)>(*clk-tol))){
			//low found and we are expecting a bar
			lastBit += *clk;
			BinStream[bitnum] = 1 - *invert; 
			bitnum++;
		} else {
			//mid value found or no bar supposed to be here
			if ((i-lastBit) > (*clk+tol)){
				//should have hit a high or low based on clock!!
				if (bitnum > 0){
					BinStream[bitnum] = 77;
					bitnum++;
				}
				lastBit += *clk;//skip over error
			}
		}
		if (bitnum >= 400) break;
		}
		*BitLen = bitnum;
	} else {
		*invert = bestStart;
		*clk = j;
		return -1; 
	}	
  return bestErrCnt;
}

//by marshmellow
//take 10 and 01 and manchester decode
//run through 2 times and take least errCnt
int manrawdecode(uint8_t * bits, int *bitlen)
{
  int bitnum = 0;
  int errCnt = 0;
  int bestErr = 1000;
  int bestRun = 0;
  int i = 1;
  int j = 1;

	for (; j < 3; ++j){
		i = 1;
		for ( i = i + j; i < *bitlen-2; i += 2){
			if ( bits[i]==1 && (bits[i+1]==0)){
			} else if ((bits[i]==0)&& bits[i+1]==1){
			} else {
				errCnt++;
			}
			if(bitnum > 300) break;
		}
		if (bestErr > errCnt){
			bestErr = errCnt;
			bestRun = j;
		}	
		errCnt = 0;
	}
	errCnt = bestErr;
	if (errCnt < 20){
		j = bestRun;
		i = 1;
		for ( i = i+j; i < *bitlen-2; i += 2){
			if ( bits[i] == 1 && bits[i + 1] == 0 ){
					bits[bitnum++] = 0;
			} else if ( bits[i] == 0 && bits[i + 1] == 1 ){
					bits[bitnum++] = 1;
			} else {
				bits[bitnum++] = 77;
			}
			if ( bitnum > 300 ) break;
		}
		*bitlen = bitnum;
	}   
	return errCnt;
}


//by marshmellow
//take 01 or 10 = 0 and 11 or 00 = 1
int BiphaseRawDecode(uint8_t * bits, int *bitlen, int offset)
{
	uint8_t bitnum = 0;
	uint32_t errCnt = 0;
	uint32_t i = offset;
	
	for (; i < *bitlen-2; i += 2 ){
		if ( (bits[i]==1 && bits[i+1]==0)||
			 (bits[i]==0 && bits[i+1]==1)){
			bits[bitnum++] = 1;
		} else if ( (bits[i]==0 && bits[i+1]==0)||
					(bits[i]==1 && bits[i+1]==1)){
			bits[bitnum++] = 0;
		} else {
			bits[bitnum++] = 77;
			errCnt++;
		}
		if ( bitnum > 250) break;
	}  
	*bitlen = bitnum;
	return errCnt;
}

//by marshmellow
//takes 2 arguments - clock and invert both as integers
//attempts to demodulate ask only
//prints binary found and saves in graphbuffer for further commands
int askrawdemod(uint8_t *BinStream, int *bitLen, int *clk, int *invert)
{
  uint32_t i;
  uint32_t initLoopMax = 200;
  int high = 0, low = 128;
  uint8_t BitStream[502] = {0x00};
  
  *clk = DetectASKClock(BinStream, *bitLen, *clk); //clock default
  
  if (*clk < 8)		*clk = 64;	
  if (*clk < 32)	*clk = 32;	
  if (*invert != 1) *invert = 0;

  if (initLoopMax > *bitLen) 
	initLoopMax = *bitLen;
  
  // Detect high and lows 
  for (i = 0; i < initLoopMax; ++i) //200 samples should be plenty to find high and low values
  {
    if (BinStream[i] > high)
		high = BinStream[i];
    else if (BinStream[i] < low)
		low = BinStream[i];
  }
  
  //throw away static
	if ((high < 158)){  
		return -2;
	}
  
	//25% fuzz in case highs and lows aren't clipped [marshmellow]
	high = (int)(high * .75);
	low  = (int)(low+128 * .25);

  int lastBit = 0;			//set first clock check
  uint32_t bitnum = 0;		//output counter
  
  uint8_t tol = 0;			//clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
  if (*clk==32) tol = 1;	//clock tolerance may not be needed anymore currently set to + or - 1 but could be increased for poor waves or removed entirely 

  uint32_t gLen = *bitLen;
  if (gLen > 500) gLen = 500;

  uint32_t j = 0;
  uint8_t errCnt = 0;
  uint32_t bestStart = *bitLen;
  uint32_t bestErrCnt = (*bitLen / 1000);
  uint32_t errCntLimit = bestErrCnt;
  uint8_t midBit = 0;
  
  //loop to find first wave that works
  for (j = 0; j < gLen; ++j){
  
    if ((BinStream[j] >= high)||(BinStream[j] <= low)){
      lastBit = j - *clk;    
      //loop through to see if this start location works
      for (i = j; i < *bitLen; ++i) {  
        if ((BinStream[i] >= high) && ((i-lastBit)>(*clk-tol))){
          lastBit += *clk;
          BitStream[bitnum] =  *invert;
          bitnum++;
          midBit = 0;
        } else if ((BinStream[i] <= low) && ((i-lastBit)>(*clk-tol))){
          //low found and we are expecting a bar
          lastBit += *clk;
          BitStream[bitnum] = 1-*invert; 
          bitnum++;
          midBit=0;
        } else if ((BinStream[i]<=low) && (midBit==0) && ((i-lastBit)>((*clk/2)-tol))){
          //mid bar?
          midBit = 1;
          BitStream[bitnum] = 1 - *invert;
          bitnum++;
        } else if ((BinStream[i]>=high)&&(midBit==0) && ((i-lastBit)>((*clk/2)-tol))){
          //mid bar?
          midBit = 1;
          BitStream[bitnum] = *invert;
          bitnum++;
        } else if ((i-lastBit)>((*clk/2)+tol)&&(midBit==0)){
          //no mid bar found
          midBit = 1;
          BitStream[bitnum] = BitStream[bitnum-1];
          bitnum++;
        } else {
          //mid value found or no bar supposed to be here

          if (( i - lastBit) > ( *clk + tol)){
            //should have hit a high or low based on clock!!

            if (bitnum > 0){
              BitStream[bitnum] = 77;
              bitnum++;
            }

            errCnt++;
            lastBit += *clk;//skip over until hit too many errors
            if (errCnt > errCntLimit){  //allow 1 error for every 1000 samples else start over
              errCnt = 0;
              bitnum = 0;//start over
              break;
            }
          }          
        }
        if (bitnum > 500) break;
      }
      //we got more than 64 good bits and not all errors
	  //possible good read
      if ((bitnum > (64 + errCnt)) && (errCnt < errCntLimit)) {

		//great read - finish
        if (errCnt == 0) break;  
		
		//if current run == bestErrCnt run (after exhausted testing) then finish 
        if (bestStart == j) break;  
        
		//set this as new best run
		if (errCnt < bestErrCnt){
          bestErrCnt = errCnt;
          bestStart = j;
        }
      }
    }
    if (j >= gLen){ //exhausted test
      //if there was a ok test go back to that one and re-run the best run (then dump after that run)
      if (bestErrCnt < errCntLimit) 
		j = bestStart;
    }
  }
	if (bitnum > 16){

		for (i = 0; i < bitnum; ++i){
			BinStream[i] = BitStream[i];
		}
		*bitLen = bitnum;
	} else {
		return -1;
	}
  return errCnt;
}
//translate wave to 11111100000 (1 for each short wave 0 for each long wave) 
size_t fsk_wave_demod(uint8_t * dest, size_t size, uint8_t fchigh, uint8_t fclow)
{
	uint32_t last_transition = 0;
	uint32_t idx = 1;
	uint32_t maxVal = 0;
	
	if (fchigh == 0) fchigh = 10;
	if (fclow == 0) fclow = 8;
	
	// we do care about the actual theshold value as sometimes near the center of the
	// wave we may get static that changes direction of wave for one value
	// if our value is too low it might affect the read.  and if our tag or
	// antenna is weak a setting too high might not see anything. [marshmellow]
	if ( size < 100)
		return 0;
	
	// Find high from first 100 samples
	for ( idx = 1; idx < 100; idx++ ){
		if ( maxVal < dest[idx]) 
			maxVal = dest[idx];
	}
	
    // set close to the top of the wave threshold with 25% margin for error
    // less likely to get a false transition up there. 
    // (but have to be careful not to go too high and miss some short waves)
	uint8_t threshold_value = (uint8_t)(maxVal * .75);
	
	// sync to first lo-hi transition, and threshold
	// Need to threshold first sample
	
	dest[0] = (dest[0] < threshold_value) ? 0 : 1;

	size_t numBits = 0;
	
	// count cycles between consecutive lo-hi transitions, there should be either 8 (fc/8)
	// or 10 (fc/10) cycles but in practice due to noise etc we may end up with with anywhere
	// between 7 to 11 cycles so fuzz it by treat anything <9 as 8 and anything else as 10
	for(idx = 1; idx < size; idx++) {

		// threshold current value
		dest[idx] = (dest[idx] < threshold_value) ? 0 : 1;

		// Check for 0->1 transition
		if (dest[idx-1] < dest[idx]) { // 0 -> 1 transition
			if ( ( idx - last_transition ) <( fclow - 2 ) ) {      //0-5 = garbage noise
				//do nothing with extra garbage
			} else if ((idx - last_transition) < ( fchigh - 1 )) { //6-8 = 8 waves
				dest[numBits]=1;
			} else {							//9+ = 10 waves
				dest[numBits]=0;
			}
			last_transition = idx;
			numBits++;
		}
	}
	//it returns the number of bytes, but each byte represents a bit: 1 or 0
	return numBits; 
}

uint32_t myround2(float f)
{
  if (f >= 2000) return 2000;//something bad happened
  return (uint32_t) (f + (float)0.5);
}

//translate 11111100000 to 10 
size_t aggregate_bits(uint8_t *dest, size_t size, uint8_t rfLen, uint8_t maxConsequtiveBits, uint8_t invert, uint8_t fchigh, uint8_t fclow )
{
	uint8_t lastval = dest[0];
	uint32_t idx = 0;
	uint32_t n = 1;
	size_t numBits = 0;

	for( idx = 1; idx < size; idx++) {

		if (dest[idx] == lastval) {
			n++;
			continue;
		}
		//if lastval was 1, we have a 1->0 crossing
		if ( dest[idx-1] == 1 ) {
			n = myround2( (float)( n + 1 ) / ((float)(rfLen)/(float)fclow));
		} else { // 0->1 crossing
			n = myround2( (float)( n + 1 ) / ((float)(rfLen-2)/(float)fchigh));  //-2 for fudge factor
		}
		if (n == 0) n = 1;

		if(n < maxConsequtiveBits) //Consecutive 
		{
			if(invert == 0){ //invert bits 
				memset(dest+numBits, dest[idx-1] , n);
			}else{
				memset(dest+numBits, dest[idx-1]^1 , n);	
			}			
			numBits += n;
		}
		n = 0;
		lastval = dest[idx];
	}//end for
	return numBits;
}

//by marshmellow  (from holiman's base)
// full fsk demod from GraphBuffer wave to decoded 1s and 0s (no mandemod)
int fskdemod(uint8_t *dest, size_t size, uint8_t rfLen, uint8_t invert, uint8_t fchigh, uint8_t fclow)
{
	// FSK demodulator
	size = fsk_wave_demod(dest, size, fchigh, fclow);
	if ( size > 0 )
		size = aggregate_bits(dest, size, rfLen, 192, invert, fchigh, fclow);
	return size;
}

// loop to get raw HID waveform then FSK demodulate the TAG ID from it
int HIDdemodFSK(uint8_t *dest, size_t size, uint32_t *hi2, uint32_t *hi, uint32_t *lo)
{
	size_t idx = 0;
	int numshifts = 0;

	// FSK demodulator
	size = fskdemod(dest, size, 50, 0, 10, 8);

	// final loop, go over previously decoded manchester data and decode into usable tag ID
	// 111000 bit pattern represent start of frame, 01 pattern represents a 1 and 10 represents a 0
	uint8_t frame_marker_mask[] = {1,1,1,0,0,0};

	uint8_t mask_len =  sizeof frame_marker_mask /  sizeof frame_marker_mask[0];
	
	//one scan
	while( idx + mask_len < size) {
	// search for a start of frame marker
		if ( memcmp(dest+idx, frame_marker_mask, sizeof(frame_marker_mask)) == 0)
		{ // frame marker found
			idx += mask_len;
			while(dest[idx] != dest[idx+1] && idx < size-2)
			{	
				// Keep going until next frame marker (or error)
				// Shift in a bit. Start by shifting high registers
				*hi2 = ( *hi2 << 1 ) | ( *hi >> 31 );
				*hi = ( *hi << 1 ) | ( *lo >> 31 );
				//Then, shift in a 0 or one into low
				if (dest[idx] && !dest[idx+1])	// 1 0
					*lo = ( *lo << 1 ) | 0;
				else // 0 1
					*lo = ( *lo << 1 ) | 1;
				numshifts++;
				idx += 2;
			}
			// Hopefully, we read a tag and	 hit upon the next frame marker
			if(idx + mask_len < size)
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

uint32_t bytebits_to_byte(uint8_t *src, int numbits)
{
	//HACK:  potential overflow in numbits is larger then uint32 bits.
	
	uint32_t num = 0;
	for(int i = 0 ; i < numbits ; ++i)	{
		num = (num << 1) | (*src);
		src++;
	}
	return num;
}

int IOdemodFSK(uint8_t *dest, size_t size)
{
	//make sure buffer has data
	if (size < 100) return -1;
	
	uint32_t idx = 0;
	uint8_t testMax = 0;
	
	//test samples are not just noise
	for (; idx < 65; ++idx ){
		if (testMax < dest[idx])
			testMax = dest[idx];
	}

	//if not, just noise
	if (testMax < 20) return -2;
		
	// FSK demodulator
	size = fskdemod(dest, size, 64, 1, 10, 8);  //  RF/64 and invert
	
	//did we get a good demod?
	if (size < 65) return -3;
	
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
	
	for( idx = 0; idx < (size - 65); ++idx) {
	if ( memcmp(dest + idx, mask, sizeof(mask))==0) {
		//frame marker found
		if (!dest[idx+8] && 
			dest[idx+17] == 1 &&
			dest[idx+26] == 1 &&
			dest[idx+35] == 1 &&
			dest[idx+44] == 1 &&
			dest[idx+53] == 1){
				//confirmed proper separator bits found
				//return start position
				return (int) idx;
			}
		}		
	}
	return 0;
}

// by marshmellow
// not perfect especially with lower clocks or VERY good antennas (heavy wave clipping)
// maybe somehow adjust peak trimming value based on samples to fix?
int DetectASKClock(uint8_t dest[], size_t size, int clock)
{
	int i = 0;
	int clk[] = {16,32,40,50,64,100,128,256};
	uint8_t clkLen = sizeof clk / sizeof clk[0];
	
	//if we already have a valid clock quit
	for (; i < clkLen; ++i)
		if (clk[i] == clock) 
			return clock;
			
	int peak = 0;
	int low = 128;	
	int loopCnt = 256;
	if (size < loopCnt) 
		loopCnt = size;
	
	//get high and low peak
	for ( i = 0; i < loopCnt; ++i ){
		if(dest[i] > peak) 
			peak = dest[i]; 
		if(dest[i] < low) 
			low = dest[i];
	}

	peak = (int)(peak * .75);
	low  = (int)(low+128 * .25);
 
	int ii, cnt, bestErr, tol = 0;
	int errCnt[clkLen];
	memset(errCnt, 0x00, clkLen);
	
	int tmpIndex, tmphigh, tmplow;
	
	//test each valid clock from smallest to greatest to see which lines up
	for( cnt = 0; cnt < clkLen; ++cnt ){

		tol = (clk[cnt] == 32) ? 1 : 0;
		bestErr = 1000;
		tmpIndex = tmphigh = tmplow = 0;

		//try lining up the peaks by moving starting point (try first 256) 
		for (ii=0; ii < loopCnt; ++ii){
		
			// not a peak? continue
			if ( (dest[ii] < peak) && (dest[ii] > low)) 
				continue;

			errCnt[cnt] = 0;
			
			// now that we have the first one lined up test rest of wave array
			for ( i = 0; i < ((int)(size / clk[cnt]) - 1); ++i){
			  
				tmpIndex = ii + (i * clk[cnt] );
				tmplow  = dest[ tmpIndex - tol];
				tmphigh = dest[ tmpIndex + tol];
				
				if ( dest[tmpIndex] >= peak || dest[tmpIndex] <= low ) {
				}
				else if ( tmplow >= peak || tmplow <= low){
				}					
				else if ( tmphigh >= peak || tmphigh <= low){
				}
				else 
					errCnt[cnt]++; //error no peak detected
			}

			//if we found no errors this is correct one - return this clock
			if ( errCnt[cnt] == 0 )
				return clk[cnt];

			if ( errCnt[cnt] < bestErr) 
				bestErr = errCnt[cnt];
		}
		// save the least error.
		errCnt[cnt] = bestErr;
	}
	// find best clock which has lowest number of errors
	int j = 0, bestIndex = 0;
	for (; j < clkLen; ++j){
		if ( errCnt[j] < errCnt[bestIndex] )
			bestIndex = j;
	}
	return clk[bestIndex];
}
