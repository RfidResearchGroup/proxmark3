//-----------------------------------------------------------------------------
// Copyright (C) 2014
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency demod/decode commands
//-----------------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>
#include "lfdemod.h"


uint8_t justNoise(uint8_t *BitStream, size_t size)
{
	static const uint8_t THRESHOLD = 123;
	//test samples are not just noise
	uint8_t justNoise1 = 1;
	for(size_t idx=0; idx < size && justNoise1 ;idx++){
		justNoise1 = BitStream[idx] < THRESHOLD;
	}
	return justNoise1;
}

//by marshmellow
//get high and low values of a wave with passed in fuzz factor. also return noise test = 1 for passed or 0 for only noise
int getHiLo(uint8_t *BitStream, size_t size, int *high, int *low, uint8_t fuzzHi, uint8_t fuzzLo)
{
	*high=0;
	*low=255;
	// get high and low thresholds 
	for (int i=0; i < size; i++){
		if (BitStream[i] > *high) *high = BitStream[i];
		if (BitStream[i] < *low) *low = BitStream[i];
	}
	if (*high < 123) return -1; // just noise
	*high = (int)(((*high-128)*(((float)fuzzHi)/100))+128);
	*low = (int)(((*low-128)*(((float)fuzzLo)/100))+128);
	return 1;
}

// by marshmellow
// pass bits to be tested in bits, length bits passed in bitLen, and parity type (even=0 | odd=1) in pType
// returns 1 if passed
uint8_t parityTest(uint32_t bits, uint8_t bitLen, uint8_t pType)
{
	uint8_t ans = 0;
	for (uint8_t i = 0; i < bitLen; i++){
		ans ^= ((bits >> i) & 1);
	}
	//PrintAndLog("DEBUG: ans: %d, ptype: %d",ans,pType);
	return (ans == pType);
}

//by marshmellow
//search for given preamble in given BitStream and return startIndex and length
uint8_t preambleSearch(uint8_t *BitStream, uint8_t *preamble, size_t pLen, size_t *size, size_t *startIdx)
{
  uint8_t foundCnt=0;
  for (int idx=0; idx < *size - pLen; idx++){
    if (memcmp(BitStream+idx, preamble, pLen) == 0){
      //first index found
      foundCnt++;
      if (foundCnt == 1){
        *startIdx = idx;
      }
      if (foundCnt == 2){
        *size = idx - *startIdx;
        return 1;
      }
    }
  }
  return 0;
}


//by marshmellow
//takes 1s and 0s and searches for EM410x format - output EM ID
uint64_t Em410xDecode(uint8_t *BitStream, size_t *size, size_t *startIdx)
{
  //no arguments needed - built this way in case we want this to be a direct call from "data " cmds in the future
  //  otherwise could be a void with no arguments
  //set defaults
  uint64_t lo=0;
  uint32_t i = 0;
  if (BitStream[1]>1){  //allow only 1s and 0s
    // PrintAndLog("no data found");
    return 0;
  }
  // 111111111 bit pattern represent start of frame
  uint8_t preamble[] = {1,1,1,1,1,1,1,1,1};
  uint32_t idx = 0;
  uint32_t parityBits = 0;
  uint8_t errChk = 0;
  *startIdx = 0;
  for (uint8_t extraBitChk=0; extraBitChk<5; extraBitChk++){
    errChk = preambleSearch(BitStream+extraBitChk+*startIdx, preamble, sizeof(preamble), size, startIdx);
    if (errChk == 0) return 0;
    idx = *startIdx + 9;
    for (i=0; i<10;i++){ //loop through 10 sets of 5 bits (50-10p = 40 bits)
      parityBits = bytebits_to_byte(BitStream+(i*5)+idx,5);
      //check even parity
      if (parityTest(parityBits, 5, 0) == 0){
        //parity failed try next bit (in the case of 1111111111) but last 9 = preamble
        startIdx++;
        errChk = 0;
        break;
      }
      //set uint64 with ID from BitStream
      for (uint8_t ii=0; ii<4; ii++){
        lo = (lo << 1LL) | (BitStream[(i*5)+ii+idx]);
      }
    }
    if (errChk != 0) return lo;
    //skip last 5 bit parity test for simplicity.
    // *size = 64;
  }
  return 0;
}

//by marshmellow
//takes 3 arguments - clock, invert, maxErr as integers
//attempts to demodulate ask while decoding manchester
//prints binary found and saves in graphbuffer for further commands
int askmandemod(uint8_t *BinStream, size_t *size, int *clk, int *invert, int maxErr)
{
	int i;
	//int clk2=*clk;
	int start = DetectASKClock(BinStream, *size, clk, 20); //clock default
	if (*clk==0) return -3;
	if (start < 0) return -3;
	// if autodetected too low then adjust  //MAY NEED ADJUSTMENT
	//if (clk2==0 && *clk<8) *clk =64;
	//if (clk2==0 && *clk<32) *clk=32;
	if (*invert != 0 && *invert != 1) *invert=0;
	uint32_t initLoopMax = 200;
	if (initLoopMax > *size) initLoopMax=*size;
	// Detect high and lows
	// 25% fuzz in case highs and lows aren't clipped [marshmellow]
	int high, low, ans;
	ans = getHiLo(BinStream, initLoopMax, &high, &low, 75, 75);
	if (ans<1) return -2; //just noise

	// PrintAndLog("DEBUG - valid high: %d - valid low: %d",high,low);
	int lastBit = 0;  //set first clock check
	uint32_t bitnum = 0;     //output counter
	int tol = 0;  //clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
	if (*clk<=32) tol=1;    //clock tolerance may not be needed anymore currently set to + or - 1 but could be increased for poor waves or removed entirely
	int iii = 0;
	uint32_t gLen = *size;
	if (gLen > 3000) gLen=3000;
	uint8_t errCnt =0;
	uint16_t MaxBits = 500;
	uint32_t bestStart = *size;
	int bestErrCnt = maxErr+1;
	// PrintAndLog("DEBUG - lastbit - %d",lastBit);
	// loop to find first wave that works
	for (iii=0; iii < gLen; ++iii){
		if ((BinStream[iii] >= high) || (BinStream[iii] <= low)){
			lastBit=iii-*clk;
			errCnt=0;
			// loop through to see if this start location works
			for (i = iii; i < *size; ++i) {
				if ((BinStream[i] >= high) && ((i-lastBit) > (*clk-tol))){
					lastBit+=*clk;
				} else if ((BinStream[i] <= low) && ((i-lastBit) > (*clk-tol))){
					//low found and we are expecting a bar
					lastBit+=*clk;
				} else {
					//mid value found or no bar supposed to be here
					if ((i-lastBit)>(*clk+tol)){
						//should have hit a high or low based on clock!!

						//debug
						//PrintAndLog("DEBUG - no wave in expected area - location: %d, expected: %d-%d, lastBit: %d - resetting search",i,(lastBit+(clk-((int)(tol)))),(lastBit+(clk+((int)(tol)))),lastBit);

						errCnt++;
						lastBit+=*clk;//skip over until hit too many errors
						if (errCnt>(maxErr)) break;  //allow 1 error for every 1000 samples else start over
					}
				}
				if ((i-iii) >(MaxBits * *clk)) break; //got plenty of bits
			}
			//we got more than 64 good bits and not all errors
			if ((((i-iii)/ *clk) > (64)) && (errCnt<=maxErr)) {
				//possible good read
				if (errCnt==0){
					bestStart=iii;
					bestErrCnt=errCnt;
					break;  //great read - finish
				}
				if (errCnt<bestErrCnt){  //set this as new best run
					bestErrCnt=errCnt;
					bestStart = iii;
				}
			}
		}
	}
	if (bestErrCnt<=maxErr){
		//best run is good enough set to best run and set overwrite BinStream
		iii=bestStart;
		lastBit = bestStart - *clk;
		bitnum=0;
		for (i = iii; i < *size; ++i) {
			if ((BinStream[i] >= high) && ((i-lastBit) > (*clk-tol))){
				lastBit += *clk;
				BinStream[bitnum] = *invert;
				bitnum++;
			} else if ((BinStream[i] <= low) && ((i-lastBit) > (*clk-tol))){
				//low found and we are expecting a bar
				lastBit+=*clk;
				BinStream[bitnum] = 1-*invert;
				bitnum++;
			} else {
				//mid value found or no bar supposed to be here
				if ((i-lastBit)>(*clk+tol)){
					//should have hit a high or low based on clock!!

					//debug
					//PrintAndLog("DEBUG - no wave in expected area - location: %d, expected: %d-%d, lastBit: %d - resetting search",i,(lastBit+(clk-((int)(tol)))),(lastBit+(clk+((int)(tol)))),lastBit);
					if (bitnum > 0){
						BinStream[bitnum]=77;
						bitnum++;
					}

					lastBit+=*clk;//skip over error
				}
			}
			if (bitnum >=MaxBits) break;
		}
		*size=bitnum;
	} else{
		*invert=bestStart;
		*clk=iii;
		return -1;
	}
	return bestErrCnt;
}

//by marshmellow
//encode binary data into binary manchester 
int ManchesterEncode(uint8_t *BitStream, size_t size)
{
	size_t modIdx=20000, i=0;
	if (size>modIdx) return -1;
	for (size_t idx=0; idx < size; idx++){
		BitStream[idx+modIdx++] = BitStream[idx];
		BitStream[idx+modIdx++] = BitStream[idx]^1;
	}
	for (; i<(size*2); i++){
		BitStream[i] = BitStream[i+20000];
	}
	return i;
}

//by marshmellow
//take 10 and 01 and manchester decode
//run through 2 times and take least errCnt
int manrawdecode(uint8_t * BitStream, size_t *size)
{
	uint16_t bitnum=0;
	uint16_t MaxBits = 500;
	uint16_t errCnt = 0;
	size_t i=1;
	uint16_t bestErr = 1000;
	uint16_t bestRun = 0;
	size_t ii=1;
	if (size == 0) return -1;
	for (ii=1;ii<3;++ii){
		i=1;
		for (i=i+ii;i<*size-2;i+=2){
			if(BitStream[i]==1 && (BitStream[i+1]==0)){
			} else if((BitStream[i]==0)&& BitStream[i+1]==1){
			} else {
				errCnt++;
			}
			if(bitnum>MaxBits) break;
		}
		if (bestErr>errCnt){
			bestErr=errCnt;
			bestRun=ii;
		}
		errCnt=0;
	}
	errCnt=bestErr;
	if (errCnt<20){
		ii=bestRun;
		i=1;
		for (i=i+ii; i < *size-2; i+=2){
			if(BitStream[i] == 1 && (BitStream[i+1] == 0)){
				BitStream[bitnum++]=0;
			} else if((BitStream[i] == 0) && BitStream[i+1] == 1){
				BitStream[bitnum++]=1;
			} else {
				BitStream[bitnum++]=77;
				//errCnt++;
			}
			if(bitnum>MaxBits) break;
		}
		*size=bitnum;
	}
	return errCnt;
}

//by marshmellow
//take 01 or 10 = 0 and 11 or 00 = 1
int BiphaseRawDecode(uint8_t *BitStream, size_t *size, int offset, int invert)
{
	uint16_t bitnum=0;
	uint32_t errCnt =0;
	uint32_t i;
	uint16_t MaxBits=500;
	i=offset;
	if (size == 0) return -1;
	for (;i<*size-2; i+=2){
		if((BitStream[i]==1 && BitStream[i+1]==0) || (BitStream[i]==0 && BitStream[i+1]==1)){
			BitStream[bitnum++]=1^invert;
		} else if((BitStream[i]==0 && BitStream[i+1]==0) || (BitStream[i]==1 && BitStream[i+1]==1)){
			BitStream[bitnum++]=invert;
		} else {
			BitStream[bitnum++]=77;
			errCnt++;
		}
		if(bitnum>MaxBits) break;
	}
	*size=bitnum;
	return errCnt;
}

//by marshmellow
void askAmp(uint8_t *BitStream, size_t size)
{
	int shift = 127;
	int shiftedVal=0;
	for(int i = 1; i<size; i++){
		if (BitStream[i]-BitStream[i-1]>=30) //large jump up
			shift=127;
		else if(BitStream[i]-BitStream[i-1]<=-20) //large jump down
			shift=-127;

		shiftedVal=BitStream[i]+shift;

		if (shiftedVal>255) 
			shiftedVal=255;
		else if (shiftedVal<0) 
			shiftedVal=0;
		BitStream[i-1] = shiftedVal;
	}
	return;
}

//by marshmellow
//takes 3 arguments - clock, invert and maxErr as integers
//attempts to demodulate ask only
int askrawdemod(uint8_t *BinStream, size_t *size, int *clk, int *invert, int maxErr, uint8_t amp)
{
	uint32_t i;
	if (*size==0) return -1;
	int start = DetectASKClock(BinStream, *size, clk, 20); //clock default
	if (*clk==0) return -1;
	if (start<0) return -1;
	if (*invert != 0 && *invert != 1) *invert =0;
	uint32_t initLoopMax = 200;
	if (initLoopMax > *size) initLoopMax=*size;
	// Detect high and lows
	//25% fuzz in case highs and lows aren't clipped [marshmellow]
	int high, low, ans;
	if (amp==1) askAmp(BinStream, *size);
	ans = getHiLo(BinStream, initLoopMax, &high, &low, 75, 75);
	if (ans<1) return -1; //just noise

	//PrintAndLog("DEBUG - valid high: %d - valid low: %d",high,low);
	int lastBit = 0;  //set first clock check
	uint32_t bitnum = 0;     //output counter
	uint8_t tol = 0;  //clock tolerance adjust - waves will be accepted as within the clock
	                  //  if they fall + or - this value + clock from last valid wave
	if (*clk == 32) tol=0;    //clock tolerance may not be needed anymore currently set to
	                          //  + or - 1 but could be increased for poor waves or removed entirely
	uint32_t iii = 0;
	uint32_t gLen = *size;
	if (gLen > 500) gLen=500;
	uint8_t errCnt =0;
	uint32_t bestStart = *size;
	uint32_t bestErrCnt = maxErr; //(*size/1000);
	uint8_t midBit=0;
	uint16_t MaxBits=1000;
	//PrintAndLog("DEBUG - lastbit - %d",lastBit);
	//loop to find first wave that works
	for (iii=start; iii < gLen; ++iii){
		if ((BinStream[iii]>=high) || (BinStream[iii]<=low)){
			lastBit=iii-*clk;
			errCnt=0;
			//loop through to see if this start location works
			for (i = iii; i < *size; ++i) {
				if ((BinStream[i] >= high) && ((i-lastBit)>(*clk-tol))){
					lastBit+=*clk;
					midBit=0;
				} else if ((BinStream[i] <= low) && ((i-lastBit)>(*clk-tol))){
					//low found and we are expecting a bar
					lastBit+=*clk;
					midBit=0;
				} else if ((BinStream[i]<=low) && (midBit==0) && ((i-lastBit)>((*clk/2)-tol))){
					//mid bar?
					midBit=1;
				} else if ((BinStream[i]>=high) && (midBit==0) && ((i-lastBit)>((*clk/2)-tol))){
					//mid bar?
					midBit=1;
				} else if ((i-lastBit)>((*clk/2)+tol) && (midBit==0)){
					//no mid bar found
					midBit=1;
				} else {
					//mid value found or no bar supposed to be here

					if ((i-lastBit)>(*clk+tol)){
						//should have hit a high or low based on clock!!
						//debug
						//PrintAndLog("DEBUG - no wave in expected area - location: %d, expected: %d-%d, lastBit: %d - resetting search",i,(lastBit+(clk-((int)(tol)))),(lastBit+(clk+((int)(tol)))),lastBit);

						errCnt++;
						lastBit+=*clk;//skip over until hit too many errors
						if (errCnt > maxErr){  
							//errCnt=0;
							break;
						}
					}
				}
				if ((i-iii)>(MaxBits * *clk)) break; //got enough bits
			}
			//we got more than 64 good bits and not all errors
			if ((((i-iii)/ *clk) > (64)) && (errCnt<=maxErr)) {
				//possible good read
				if (errCnt==0){
					bestStart=iii;
					bestErrCnt=errCnt;
					break;  //great read - finish
				} 
				if (errCnt<bestErrCnt){  //set this as new best run
					bestErrCnt=errCnt;
					bestStart = iii;
				}
			}
		}
	}
	if (bestErrCnt<=maxErr){
		//best run is good enough - set to best run and overwrite BinStream
		iii = bestStart;
		lastBit = bestStart - *clk;
		bitnum=0;
		for (i = iii; i < *size; ++i) {
			if ((BinStream[i] >= high) && ((i-lastBit) > (*clk-tol))){
				lastBit += *clk;
				BinStream[bitnum] = *invert;
				bitnum++;
				midBit=0;
			} else if ((BinStream[i] <= low) && ((i-lastBit) > (*clk-tol))){
				//low found and we are expecting a bar
				lastBit+=*clk;
				BinStream[bitnum] = 1 - *invert;
				bitnum++;
				midBit=0;
			} else if ((BinStream[i]<=low) && (midBit==0) && ((i-lastBit)>((*clk/2)-tol))){
				//mid bar?
				midBit=1;
				BinStream[bitnum] = 1 - *invert;
				bitnum++;
			} else if ((BinStream[i]>=high) && (midBit==0) && ((i-lastBit)>((*clk/2)-tol))){
				//mid bar?
				midBit=1;
				BinStream[bitnum] = *invert;
				bitnum++;
			} else if ((i-lastBit)>((*clk/2)+tol) && (midBit==0)){
				//no mid bar found
				midBit=1;
				if (bitnum!=0) BinStream[bitnum] = BinStream[bitnum-1];
				bitnum++;
				
			} else {
				//mid value found or no bar supposed to be here
				if ((i-lastBit)>(*clk+tol)){
					//should have hit a high or low based on clock!!

					//debug
					//PrintAndLog("DEBUG - no wave in expected area - location: %d, expected: %d-%d, lastBit: %d - resetting search",i,(lastBit+(clk-((int)(tol)))),(lastBit+(clk+((int)(tol)))),lastBit);
					if (bitnum > 0){
						BinStream[bitnum]=77;
						bitnum++;
					}
					lastBit+=*clk;//skip over error
				}
			}
			if (bitnum >= MaxBits) break;
		}
		*size=bitnum;
	} else{
		*invert=bestStart;
		*clk=iii;
		return -1;
	}
	return bestErrCnt;
}

// demod gProxIIDemod 
// error returns as -x 
// success returns start position in BitStream
// BitStream must contain previously askrawdemod and biphasedemoded data
int gProxII_Demod(uint8_t BitStream[], size_t *size)
{
	size_t startIdx=0;
	uint8_t preamble[] = {1,1,1,1,1,0};

	uint8_t errChk = preambleSearch(BitStream, preamble, sizeof(preamble), size, &startIdx);
	if (errChk == 0) return -3; //preamble not found
	if (*size != 96) return -2; //should have found 96 bits
	//check first 6 spacer bits to verify format
	if (!BitStream[startIdx+5] && !BitStream[startIdx+10] && !BitStream[startIdx+15] && !BitStream[startIdx+20] && !BitStream[startIdx+25] && !BitStream[startIdx+30]){
		//confirmed proper separator bits found
		//return start position
		return (int) startIdx;
	}
	return -5;
}

//translate wave to 11111100000 (1 for each short wave 0 for each long wave)
size_t fsk_wave_demod(uint8_t * dest, size_t size, uint8_t fchigh, uint8_t fclow)
{
	uint32_t last_transition = 0;
	uint32_t idx = 1;
	//uint32_t maxVal=0;
	if (fchigh==0) fchigh=10;
	if (fclow==0) fclow=8;
	//set the threshold close to 0 (graph) or 128 std to avoid static
	uint8_t threshold_value = 123; 

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
			if ((idx-last_transition)<(fclow-2)){            //0-5 = garbage noise
				//do nothing with extra garbage
			} else if ((idx-last_transition) < (fchigh-1)) { //6-8 = 8 waves
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
size_t aggregate_bits(uint8_t *dest, size_t size, uint8_t rfLen, uint8_t maxConsequtiveBits,
    uint8_t invert, uint8_t fchigh, uint8_t fclow)
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
			n=myround2((float)(n+1)/((float)(rfLen)/(float)fclow));
		} else {// 0->1 crossing
			n=myround2((float)(n+1)/((float)(rfLen-1)/(float)fchigh));  //-1 for fudge factor
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
int fskdemod(uint8_t *dest, size_t size, uint8_t rfLen, uint8_t invert, uint8_t fchigh, uint8_t fclow)
{
	// FSK demodulator
	size = fsk_wave_demod(dest, size, fchigh, fclow);
	size = aggregate_bits(dest, size, rfLen, 192, invert, fchigh, fclow);
	return size;
}

// loop to get raw HID waveform then FSK demodulate the TAG ID from it
int HIDdemodFSK(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo)
{
  if (justNoise(dest, *size)) return -1;

  size_t numStart=0, size2=*size, startIdx=0; 
  // FSK demodulator
  *size = fskdemod(dest, size2,50,1,10,8); //fsk2a
  if (*size < 96) return -2;
  // 00011101 bit pattern represent start of frame, 01 pattern represents a 0 and 10 represents a 1
  uint8_t preamble[] = {0,0,0,1,1,1,0,1};
  // find bitstring in array  
  uint8_t errChk = preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx);
  if (errChk == 0) return -3; //preamble not found

  numStart = startIdx + sizeof(preamble);
  // final loop, go over previously decoded FSK data and manchester decode into usable tag ID
  for (size_t idx = numStart; (idx-numStart) < *size - sizeof(preamble); idx+=2){
    if (dest[idx] == dest[idx+1]){
      return -4; //not manchester data
    }
    *hi2 = (*hi2<<1)|(*hi>>31);
    *hi = (*hi<<1)|(*lo>>31);
    //Then, shift in a 0 or one into low
    if (dest[idx] && !dest[idx+1])  // 1 0
      *lo=(*lo<<1)|1;
    else // 0 1
      *lo=(*lo<<1)|0;
  }
  return (int)startIdx;
}

// loop to get raw paradox waveform then FSK demodulate the TAG ID from it
int ParadoxdemodFSK(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo)
{
	if (justNoise(dest, *size)) return -1;
	
	size_t numStart=0, size2=*size, startIdx=0;
	// FSK demodulator
	*size = fskdemod(dest, size2,50,1,10,8); //fsk2a
	if (*size < 96) return -2;

	// 00001111 bit pattern represent start of frame, 01 pattern represents a 0 and 10 represents a 1
	uint8_t preamble[] = {0,0,0,0,1,1,1,1};

	uint8_t errChk = preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx);
	if (errChk == 0) return -3; //preamble not found

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

uint32_t bytebits_to_byte(uint8_t* src, size_t numbits)
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
	if (justNoise(dest, size)) return -1;
	//make sure buffer has data
	if (size < 66*64) return -2;
	// FSK demodulator
	size = fskdemod(dest, size, 64, 1, 10, 8);  // FSK2a RF/64 
	if (size < 65) return -3;  //did we get a good demod?
	//Index map
	//0           10          20          30          40          50          60
	//|           |           |           |           |           |           |
	//01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
	//-----------------------------------------------------------------------------
	//00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1 ???????? 11
	//
	//XSF(version)facility:codeone+codetwo
	//Handle the data
	size_t startIdx = 0;
	uint8_t preamble[] = {0,0,0,0,0,0,0,0,0,1};
	uint8_t errChk = preambleSearch(dest, preamble, sizeof(preamble), &size, &startIdx);
	if (errChk == 0) return -4; //preamble not found

	if (!dest[startIdx+8] && dest[startIdx+17]==1 && dest[startIdx+26]==1 && dest[startIdx+35]==1 && dest[startIdx+44]==1 && dest[startIdx+53]==1){
		//confirmed proper separator bits found
		//return start position
		return (int) startIdx;
	}
	return -5;
}

// by marshmellow
// takes a array of binary values, start position, length of bits per parity (includes parity bit),
//   Parity Type (1 for odd 0 for even), and binary Length (length to run) 
size_t removeParity(uint8_t *BitStream, size_t startIdx, uint8_t pLen, uint8_t pType, size_t bLen)
{
	uint32_t parityWd = 0;
	size_t j = 0, bitCnt = 0;
	for (int word = 0; word < (bLen); word+=pLen){
		for (int bit=0; bit < pLen; bit++){
			parityWd = (parityWd << 1) | BitStream[startIdx+word+bit];
			BitStream[j++] = (BitStream[startIdx+word+bit]);
		}
		j--;
		// if parity fails then return 0
		if (parityTest(parityWd, pLen, pType) == 0) return -1;
		bitCnt+=(pLen-1);
		parityWd = 0;
	}
	// if we got here then all the parities passed
	//return ID start index and size
	return bitCnt;
}

// by marshmellow
// FSK Demod then try to locate an AWID ID
int AWIDdemodFSK(uint8_t *dest, size_t *size)
{
	//make sure buffer has enough data
	if (*size < 96*50) return -1;

	if (justNoise(dest, *size)) return -2;

	// FSK demodulator
	*size = fskdemod(dest, *size, 50, 1, 10, 8);  // fsk2a RF/50 
	if (*size < 96) return -3;  //did we get a good demod?

	uint8_t preamble[] = {0,0,0,0,0,0,0,1};
	size_t startIdx = 0;
	uint8_t errChk = preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx);
	if (errChk == 0) return -4; //preamble not found
	if (*size != 96) return -5;
	return (int)startIdx;
}

// by marshmellow
// FSK Demod then try to locate an Farpointe Data (pyramid) ID
int PyramiddemodFSK(uint8_t *dest, size_t *size)
{
	//make sure buffer has data
	if (*size < 128*50) return -5;

	//test samples are not just noise
	if (justNoise(dest, *size)) return -1;

	// FSK demodulator
	*size = fskdemod(dest, *size, 50, 1, 10, 8);  // fsk2a RF/50 
	if (*size < 128) return -2;  //did we get a good demod?

	uint8_t preamble[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
	size_t startIdx = 0;
	uint8_t errChk = preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx);
	if (errChk == 0) return -4; //preamble not found
	if (*size != 128) return -3;
	return (int)startIdx;
}


uint8_t DetectCleanAskWave(uint8_t dest[], size_t size, int high, int low)
{
	uint8_t allPeaks=1;
	uint16_t cntPeaks=0;
	for (size_t i=20; i<255; i++){
		if (dest[i]>low && dest[i]<high) 
			allPeaks=0;
		else
			cntPeaks++;
	}
	if (allPeaks==0){
		if (cntPeaks>190) return 1;
	}
	return allPeaks;
}

// by marshmellow
// not perfect especially with lower clocks or VERY good antennas (heavy wave clipping)
// maybe somehow adjust peak trimming value based on samples to fix?
// return start index of best starting position for that clock and return clock (by reference)
int DetectASKClock(uint8_t dest[], size_t size, int *clock, int maxErr)
{
  int i=0;
  int clk[]={8,16,32,40,50,64,100,128,256};
  int loopCnt = 256;  //don't need to loop through entire array...
  if (size == 0) return -1;
  if (size<loopCnt) loopCnt = size;
  //if we already have a valid clock quit
  
  for (;i<8;++i)
    if (clk[i] == *clock) return 0;

  //get high and low peak
  int peak, low;
  getHiLo(dest, loopCnt, &peak, &low, 75, 75);
  
  //test for large clean peaks
  if (DetectCleanAskWave(dest, size, peak, low)==1){
	  uint16_t fcTest=0;
	  uint8_t mostFC=0;
	  fcTest=countFC(dest, size, &mostFC);
	  uint8_t fc1 = fcTest >> 8;
	  uint8_t fc2 = fcTest & 0xFF;

	  for (i=0; i<8; i++){
	  	if (clk[i] == fc1) {
	  		*clock=fc1;
	  		return 0;
	  	}
	  	if (clk[i] == fc2) {
	  		*clock=fc2;
	  		return 0;
	  	}
	  }
  }
  
  int ii;
  int clkCnt;
  int tol = 0;
  int bestErr[]={1000,1000,1000,1000,1000,1000,1000,1000,1000};
  int bestStart[]={0,0,0,0,0,0,0,0,0};
  int errCnt=0;
  //test each valid clock from smallest to greatest to see which lines up
  for(clkCnt=0; clkCnt < 8; clkCnt++){
    if (clk[clkCnt] == 32){
      tol=1;
    }else{
      tol=0;
    }
    bestErr[clkCnt]=1000;
    //try lining up the peaks by moving starting point (try first 256)
    for (ii=0; ii < loopCnt; ii++){
      if ((dest[ii] >= peak) || (dest[ii] <= low)){
        errCnt=0;
        // now that we have the first one lined up test rest of wave array
        for (i=0; i<((int)((size-ii-tol)/clk[clkCnt])-1); ++i){
          if (dest[ii+(i*clk[clkCnt])]>=peak || dest[ii+(i*clk[clkCnt])]<=low){
          }else if(dest[ii+(i*clk[clkCnt])-tol]>=peak || dest[ii+(i*clk[clkCnt])-tol]<=low){
          }else if(dest[ii+(i*clk[clkCnt])+tol]>=peak || dest[ii+(i*clk[clkCnt])+tol]<=low){
          }else{  //error no peak detected
            errCnt++;
          }
        }
        //if we found no errors then we can stop here
        //  this is correct one - return this clock
            //PrintAndLog("DEBUG: clk %d, err %d, ii %d, i %d",clk[clkCnt],errCnt,ii,i);
        if(errCnt==0 && clkCnt<6) {
          *clock = clk[clkCnt];
          return ii;
        }
        //if we found errors see if it is lowest so far and save it as best run
        if(errCnt<bestErr[clkCnt]){
          bestErr[clkCnt]=errCnt;
          bestStart[clkCnt]=ii;
        }
      }
    }
  }
  uint8_t iii=0;
  uint8_t best=0;
  for (iii=0; iii<8; ++iii){
    if (bestErr[iii]<bestErr[best]){
      if (bestErr[iii]==0) bestErr[iii]=1;
      // current best bit to error ratio     vs  new bit to error ratio
      if (((size/clk[best])/bestErr[best] < (size/clk[iii])/bestErr[iii]) ){
        best = iii;
      }
    }
  }
  if (bestErr[best]>maxErr) return -1;
  *clock=clk[best];
  return bestStart[best];
}

//by marshmellow
//detect psk clock by reading each phase shift
// a phase shift is determined by measuring the sample length of each wave
int DetectPSKClock(uint8_t dest[], size_t size, int clock)
{
  uint8_t clk[]={255,16,32,40,50,64,100,128,255}; //255 is not a valid clock
  uint16_t loopCnt = 4096;  //don't need to loop through entire array...
  if (size == 0) return 0;
  if (size<loopCnt) loopCnt = size;

  //if we already have a valid clock quit
  size_t i=1;
  for (; i < 8; ++i)
    if (clk[i] == clock) return clock;

  size_t waveStart=0, waveEnd=0, firstFullWave=0, lastClkBit=0;
  uint8_t clkCnt, fc=0, fullWaveLen=0, tol=1;
  uint16_t peakcnt=0, errCnt=0, waveLenCnt=0;
  uint16_t bestErr[]={1000,1000,1000,1000,1000,1000,1000,1000,1000};
  uint16_t peaksdet[]={0,0,0,0,0,0,0,0,0};
  countFC(dest, size, &fc);
  //PrintAndLog("DEBUG: FC: %d",fc);

  //find first full wave
  for (i=0; i<loopCnt; i++){
    if (dest[i] < dest[i+1] && dest[i+1] >= dest[i+2]){
      if (waveStart == 0) {
        waveStart = i+1;
        //PrintAndLog("DEBUG: waveStart: %d",waveStart);
      } else {
        waveEnd = i+1;
        //PrintAndLog("DEBUG: waveEnd: %d",waveEnd);
        waveLenCnt = waveEnd-waveStart;
        if (waveLenCnt > fc){
          firstFullWave = waveStart;
          fullWaveLen=waveLenCnt;
          break;
        } 
        waveStart=0;
      }
    }
  }
  //PrintAndLog("DEBUG: firstFullWave: %d, waveLen: %d",firstFullWave,fullWaveLen);
  
  //test each valid clock from greatest to smallest to see which lines up
  for(clkCnt=7; clkCnt >= 1 ; clkCnt--){
    lastClkBit = firstFullWave; //set end of wave as clock align
    waveStart = 0;
    errCnt=0;
    peakcnt=0;
    //PrintAndLog("DEBUG: clk: %d, lastClkBit: %d",clk[clkCnt],lastClkBit);

    for (i = firstFullWave+fullWaveLen-1; i < loopCnt-2; i++){
      //top edge of wave = start of new wave 
      if (dest[i] < dest[i+1] && dest[i+1] >= dest[i+2]){
        if (waveStart == 0) {
          waveStart = i+1;
          waveLenCnt=0;
        } else { //waveEnd
          waveEnd = i+1;
          waveLenCnt = waveEnd-waveStart;
          if (waveLenCnt > fc){ 
            //if this wave is a phase shift
            //PrintAndLog("DEBUG: phase shift at: %d, len: %d, nextClk: %d, ii: %d, fc: %d",waveStart,waveLenCnt,lastClkBit+clk[clkCnt]-tol,ii+1,fc);
            if (i+1 >= lastClkBit + clk[clkCnt] - tol){ //should be a clock bit
              peakcnt++;
              lastClkBit+=clk[clkCnt];
            } else if (i<lastClkBit+8){
              //noise after a phase shift - ignore
            } else { //phase shift before supposed to based on clock
              errCnt++;
            }
          } else if (i+1 > lastClkBit + clk[clkCnt] + tol + fc){
            lastClkBit+=clk[clkCnt]; //no phase shift but clock bit
          }
          waveStart=i+1;
        }
      }
    }
    if (errCnt == 0){
      return clk[clkCnt];
    }
    if (errCnt <= bestErr[clkCnt]) bestErr[clkCnt]=errCnt;
    if (peakcnt > peaksdet[clkCnt]) peaksdet[clkCnt]=peakcnt;
  } 
  //all tested with errors 
  //return the highest clk with the most peaks found
  uint8_t best=7;
  for (i=7; i>=1; i--){
    if (peaksdet[i] > peaksdet[best]) {
      best = i;
    }
    //PrintAndLog("DEBUG: Clk: %d, peaks: %d, errs: %d, bestClk: %d",clk[iii],peaksdet[iii],bestErr[iii],clk[best]);
  }
  return clk[best];
}

//by marshmellow
//detect nrz clock by reading #peaks vs no peaks(or errors)
int DetectNRZClock(uint8_t dest[], size_t size, int clock)
{
  int i=0;
  int clk[]={8,16,32,40,50,64,100,128,256};
  int loopCnt = 4096;  //don't need to loop through entire array...
  if (size == 0) return 0;
  if (size<loopCnt) loopCnt = size;

  //if we already have a valid clock quit
  for (; i < 8; ++i)
    if (clk[i] == clock) return clock;

  //get high and low peak
  int peak, low;
  getHiLo(dest, loopCnt, &peak, &low, 75, 75);

  //PrintAndLog("DEBUG: peak: %d, low: %d",peak,low);
  int ii;
  uint8_t clkCnt;
  uint8_t tol = 0;
  int peakcnt=0;
  int peaksdet[]={0,0,0,0,0,0,0,0};
  int maxPeak=0;
  //test for large clipped waves
  for (i=0; i<loopCnt; i++){
  	if (dest[i] >= peak || dest[i] <= low){
  		peakcnt++;
  	} else {
  		if (peakcnt>0 && maxPeak < peakcnt){
  			maxPeak = peakcnt;
  		}
  		peakcnt=0;
  	}
  }
  peakcnt=0;
  //test each valid clock from smallest to greatest to see which lines up
  for(clkCnt=0; clkCnt < 8; ++clkCnt){
  	//ignore clocks smaller than largest peak
  	if (clk[clkCnt]<maxPeak) continue;

    //try lining up the peaks by moving starting point (try first 256)
    for (ii=0; ii< loopCnt; ++ii){
      if ((dest[ii] >= peak) || (dest[ii] <= low)){
        peakcnt=0;
        // now that we have the first one lined up test rest of wave array
        for (i=0; i < ((int)((size-ii-tol)/clk[clkCnt])-1); ++i){
          if (dest[ii+(i*clk[clkCnt])]>=peak || dest[ii+(i*clk[clkCnt])]<=low){
            peakcnt++;
          }
        }
        if(peakcnt>peaksdet[clkCnt]) {
          peaksdet[clkCnt]=peakcnt;
        }
      }
    }
  }
  int iii=7;
  int best=0;
  for (iii=7; iii > 0; iii--){
    if (peaksdet[iii] > peaksdet[best]){
    	best = iii;
    }
    //PrintAndLog("DEBUG: Clk: %d, peaks: %d, errs: %d, bestClk: %d",clk[iii],peaksdet[iii],bestErr[iii],clk[best]);
  }
  return clk[best];
}

// by marshmellow
// convert psk1 demod to psk2 demod
// only transition waves are 1s
void psk1TOpsk2(uint8_t *BitStream, size_t size)
{
	size_t i=1;
	uint8_t lastBit=BitStream[0];
	for (; i<size; i++){
		if (lastBit!=BitStream[i]){
			lastBit=BitStream[i];
			BitStream[i]=1;
		} else {
			BitStream[i]=0;
		}
	}
	return;
}

// by marshmellow
// convert psk2 demod to psk1 demod
// from only transition waves are 1s to phase shifts change bit
void psk2TOpsk1(uint8_t *BitStream, size_t size)
{
	uint8_t phase=0;
	for (size_t i=0; i<size; i++){
		if (BitStream[i]==1){
			phase ^=1;
		}
		BitStream[i]=phase;
	}
	return;
}

// redesigned by marshmellow adjusted from existing decode functions
// indala id decoding - only tested on 26 bit tags, but attempted to make it work for more
int indala26decode(uint8_t *bitStream, size_t *size, uint8_t *invert)
{
	//26 bit 40134 format  (don't know other formats)
	int i;
	int long_wait=29;//29 leading zeros in format
	int start;
	int first = 0;
	int first2 = 0;
	int bitCnt = 0;
	int ii;
	// Finding the start of a UID
	for (start = 0; start <= *size - 250; start++) {
		first = bitStream[start];
		for (i = start; i < start + long_wait; i++) {
			if (bitStream[i] != first) {
				break;
			}
		}
		if (i == (start + long_wait)) {
			break;
		}
	}
	if (start == *size - 250 + 1) {
		// did not find start sequence
		return -1;
	}
	// Inverting signal if needed
	if (first == 1) {
		for (i = start; i < *size; i++) {
			bitStream[i] = !bitStream[i];
		}
		*invert = 1;
	}else *invert=0;

	int iii;
	//found start once now test length by finding next one
	for (ii=start+29; ii <= *size - 250; ii++) {
		first2 = bitStream[ii];
		for (iii = ii; iii < ii + long_wait; iii++) {
			if (bitStream[iii] != first2) {
				break;
			}
		}
		if (iii == (ii + long_wait)) {
			break;
		}
	}
	if (ii== *size - 250 + 1){
		// did not find second start sequence
		return -2;
	}
	bitCnt=ii-start;

	// Dumping UID
	i = start;
	for (ii = 0; ii < bitCnt; ii++) {
		bitStream[ii] = bitStream[i++];
	}
	*size=bitCnt;
	return 1;
}

// by marshmellow - demodulate NRZ wave (both similar enough)
// peaks invert bit (high=1 low=0) each clock cycle = 1 bit determined by last peak
// there probably is a much simpler way to do this.... 
int nrzRawDemod(uint8_t *dest, size_t *size, int *clk, int *invert, int maxErr)
{
  if (justNoise(dest, *size)) return -1;
  *clk = DetectNRZClock(dest, *size, *clk);
  if (*clk==0) return -2;
  uint32_t i;
  int high, low, ans;
  ans = getHiLo(dest, 1260, &high, &low, 75, 75); //25% fuzz on high 25% fuzz on low
  if (ans<1) return -2; //just noise
  uint32_t gLen = 256;
  if (gLen>*size) gLen = *size;
  int lastBit = 0;  //set first clock check
  uint32_t bitnum = 0;     //output counter
  uint8_t tol = 1;  //clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
  uint32_t iii = 0;
  uint16_t errCnt =0;
  uint16_t MaxBits = 1000;
  uint32_t bestErrCnt = maxErr+1;
  uint32_t bestPeakCnt = 0;
  uint32_t bestPeakStart=0;
  uint8_t curBit=0;
  uint8_t bitHigh=0;
  uint8_t errBitHigh=0;
  uint16_t peakCnt=0;
  uint8_t ignoreWindow=4;
  uint8_t ignoreCnt=ignoreWindow; //in case of noice near peak
  //loop to find first wave that works - align to clock
  for (iii=0; iii < gLen; ++iii){
    if ((dest[iii]>=high) || (dest[iii]<=low)){
      lastBit=iii-*clk;
      peakCnt=0;
      errCnt=0;
      bitnum=0;
      //loop through to see if this start location works
      for (i = iii; i < *size; ++i) {
        //if we found a high bar and we are at a clock bit
        if ((dest[i]>=high ) && (i>=lastBit+*clk-tol && i<=lastBit+*clk+tol)){
          bitHigh=1;
          lastBit+=*clk;
          bitnum++;
          peakCnt++;
          errBitHigh=0;
          ignoreCnt=ignoreWindow;
        //else if low bar found and we are at a clock point
        }else if ((dest[i]<=low ) && (i>=lastBit+*clk-tol && i<=lastBit+*clk+tol)){
          bitHigh=1;
          lastBit+=*clk;
          bitnum++;
          peakCnt++;
          errBitHigh=0;
          ignoreCnt=ignoreWindow;
        //else if no bars found
        }else if(dest[i] < high && dest[i] > low) {
          if (ignoreCnt==0){
            bitHigh=0;
            if (errBitHigh==1){
              errCnt++;
            }
            errBitHigh=0;
          } else {
            ignoreCnt--;
          }
          //if we are past a clock point
          if (i >= lastBit+*clk+tol){ //clock val
            lastBit+=*clk;
            bitnum++;
          }
        //else if bar found but we are not at a clock bit and we did not just have a clock bit
        }else if ((dest[i]>=high || dest[i]<=low) && (i<lastBit+*clk-tol || i>lastBit+*clk+tol) && (bitHigh==0)){
          //error bar found no clock...
          errBitHigh=1;
        }
        if (bitnum>=MaxBits) break;
      }
      //we got more than 64 good bits and not all errors
      if (bitnum > (64) && (errCnt <= (maxErr))) {
        //possible good read
        if (errCnt == 0){
          //bestStart = iii;
          bestErrCnt = errCnt;
          bestPeakCnt = peakCnt;
          bestPeakStart = iii;
          break;  //great read - finish
        }
        if (errCnt < bestErrCnt){  //set this as new best run
          bestErrCnt = errCnt;
          //bestStart = iii;
        }
        if (peakCnt > bestPeakCnt){
          bestPeakCnt=peakCnt;
          bestPeakStart=iii;
        } 
      }
    }
  }
  //PrintAndLog("DEBUG: bestErrCnt: %d, maxErr: %d, bestStart: %d, bestPeakCnt: %d, bestPeakStart: %d",bestErrCnt,maxErr,bestStart,bestPeakCnt,bestPeakStart);
  if (bestErrCnt <= maxErr){
    //best run is good enough set to best run and set overwrite BinStream
    iii=bestPeakStart;
    lastBit=bestPeakStart-*clk;
    bitnum=0;
    for (i = iii; i < *size; ++i) {
      //if we found a high bar and we are at a clock bit
      if ((dest[i] >= high ) && (i>=lastBit+*clk-tol && i<=lastBit+*clk+tol)){
        bitHigh=1;
        lastBit+=*clk;
        curBit=1-*invert;
        dest[bitnum]=curBit;
        bitnum++;
        errBitHigh=0;
        ignoreCnt=ignoreWindow;
      //else if low bar found and we are at a clock point
      }else if ((dest[i]<=low ) && (i>=lastBit+*clk-tol && i<=lastBit+*clk+tol)){
        bitHigh=1;
        lastBit+=*clk;
        curBit=*invert;
        dest[bitnum]=curBit;
        bitnum++;
        errBitHigh=0;
        ignoreCnt=ignoreWindow;
      //else if no bars found
      }else if(dest[i]<high && dest[i]>low) {
        if (ignoreCnt==0){
          bitHigh=0;
          //if peak is done was it an error peak?
          if (errBitHigh==1){
            dest[bitnum]=77;
            bitnum++;
            errCnt++;
          }
          errBitHigh=0;
        } else {
          ignoreCnt--;
        }
        //if we are past a clock point
        if (i>=lastBit+*clk+tol){ //clock val
          lastBit+=*clk;
          dest[bitnum]=curBit;
          bitnum++;
        }
      //else if bar found but we are not at a clock bit and we did not just have a clock bit
      }else if ((dest[i]>=high || dest[i]<=low) && ((i<lastBit+*clk-tol) || (i>lastBit+*clk+tol)) && (bitHigh==0)){
        //error bar found no clock...
        errBitHigh=1;
      }
      if (bitnum >= MaxBits) break;
    }
    *size=bitnum;
  } else{
    *size=bitnum;
    return -1;
  }

  if (bitnum>16){
    *size=bitnum;
  } else return -1;
  return errCnt;
}

//by marshmellow
//detects the bit clock for FSK given the high and low Field Clocks
uint8_t detectFSKClk(uint8_t *BitStream, size_t size, uint8_t fcHigh, uint8_t fcLow)
{
  uint8_t clk[] = {8,16,32,40,50,64,100,128,0};
  uint16_t rfLens[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  uint8_t rfCnts[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
  uint8_t rfLensFnd = 0;
  uint8_t lastFCcnt=0;
  uint32_t fcCounter = 0;
  uint16_t rfCounter = 0;
  uint8_t firstBitFnd = 0;
  size_t i;
  if (size == 0) return 0;

  uint8_t fcTol = (uint8_t)(0.5+(float)(fcHigh-fcLow)/2);
  rfLensFnd=0;
  fcCounter=0;
  rfCounter=0;
  firstBitFnd=0;
  //PrintAndLog("DEBUG: fcTol: %d",fcTol);
  // prime i to first up transition
  for (i = 1; i < size-1; i++)
    if (BitStream[i] > BitStream[i-1] && BitStream[i]>=BitStream[i+1])
      break;

  for (; i < size-1; i++){
    if (BitStream[i] > BitStream[i-1] && BitStream[i]>=BitStream[i+1]){
      // new peak 
      fcCounter++;
      rfCounter++;
      // if we got less than the small fc + tolerance then set it to the small fc
      if (fcCounter < fcLow+fcTol) 
        fcCounter = fcLow;
      else //set it to the large fc
        fcCounter = fcHigh;

      //look for bit clock  (rf/xx)
      if ((fcCounter<lastFCcnt || fcCounter>lastFCcnt)){
        //not the same size as the last wave - start of new bit sequence

        if (firstBitFnd>1){ //skip first wave change - probably not a complete bit
          for (int ii=0; ii<15; ii++){
            if (rfLens[ii]==rfCounter){
              rfCnts[ii]++;
              rfCounter=0;
              break;
            }
          }
          if (rfCounter>0 && rfLensFnd<15){
            //PrintAndLog("DEBUG: rfCntr %d, fcCntr %d",rfCounter,fcCounter);
            rfCnts[rfLensFnd]++;
            rfLens[rfLensFnd++]=rfCounter;
          }
        } else {
          firstBitFnd++;
        }
        rfCounter=0;
        lastFCcnt=fcCounter;
      }
      fcCounter=0;
    } else {
      // count sample
      fcCounter++;
      rfCounter++;
    }
  }
  uint8_t rfHighest=15, rfHighest2=15, rfHighest3=15;

  for (i=0; i<15; i++){
    //PrintAndLog("DEBUG: RF %d, cnts %d",rfLens[i], rfCnts[i]);
    //get highest 2 RF values  (might need to get more values to compare or compare all?)
    if (rfCnts[i]>rfCnts[rfHighest]){
      rfHighest3=rfHighest2;
      rfHighest2=rfHighest;
      rfHighest=i;
    } else if(rfCnts[i]>rfCnts[rfHighest2]){
      rfHighest3=rfHighest2;
      rfHighest2=i;
    } else if(rfCnts[i]>rfCnts[rfHighest3]){
      rfHighest3=i;
    }
  }  
  // set allowed clock remainder tolerance to be 1 large field clock length+1 
  //   we could have mistakenly made a 9 a 10 instead of an 8 or visa versa so rfLens could be 1 FC off  
  uint8_t tol1 = fcHigh+1; 
  
  //PrintAndLog("DEBUG: hightest: 1 %d, 2 %d, 3 %d",rfLens[rfHighest],rfLens[rfHighest2],rfLens[rfHighest3]);

  // loop to find the highest clock that has a remainder less than the tolerance
  //   compare samples counted divided by
  int ii=7;
  for (; ii>=0; ii--){
    if (rfLens[rfHighest] % clk[ii] < tol1 || rfLens[rfHighest] % clk[ii] > clk[ii]-tol1){
      if (rfLens[rfHighest2] % clk[ii] < tol1 || rfLens[rfHighest2] % clk[ii] > clk[ii]-tol1){
        if (rfLens[rfHighest3] % clk[ii] < tol1 || rfLens[rfHighest3] % clk[ii] > clk[ii]-tol1){
          break;
        }
      }
    }
  }

  if (ii<0) return 0; // oops we went too far

  return clk[ii];
}

//by marshmellow
//countFC is to detect the field clock lengths.
//counts and returns the 2 most common wave lengths
//mainly used for FSK field clock detection
uint16_t countFC(uint8_t *BitStream, size_t size, uint8_t *mostFC)
{
  uint8_t fcLens[] = {0,0,0,0,0,0,0,0,0,0};
  uint16_t fcCnts[] = {0,0,0,0,0,0,0,0,0,0};
  uint8_t fcLensFnd = 0;
  uint8_t lastFCcnt=0;
  uint32_t fcCounter = 0;
  size_t i;
  if (size == 0) return 0;

  // prime i to first up transition
  for (i = 1; i < size-1; i++)
    if (BitStream[i] > BitStream[i-1] && BitStream[i] >= BitStream[i+1])
      break;

  for (; i < size-1; i++){
    if (BitStream[i] > BitStream[i-1] && BitStream[i] >= BitStream[i+1]){
    	// new up transition
    	fcCounter++;
    	
      //if we had 5 and now have 9 then go back to 8 (for when we get a fc 9 instead of an 8)
      if (lastFCcnt==5 && fcCounter==9) fcCounter--;
      //if odd and not rc/5 add one (for when we get a fc 9 instead of 10)
      if ((fcCounter==9 && fcCounter & 1) || fcCounter==4) fcCounter++;

      // save last field clock count  (fc/xx)
      // find which fcLens to save it to:
      for (int ii=0; ii<10; ii++){
        if (fcLens[ii]==fcCounter){
          fcCnts[ii]++;
          fcCounter=0;
          break;
        }
      }
      if (fcCounter>0 && fcLensFnd<10){
        //add new fc length 
        fcCnts[fcLensFnd]++;
        fcLens[fcLensFnd++]=fcCounter;
      }
      fcCounter=0;
    } else {
      // count sample
      fcCounter++;
    }
  }
  
  uint8_t best1=9, best2=9, best3=9;
  uint16_t maxCnt1=0;
  // go through fclens and find which ones are bigest 2  
  for (i=0; i<10; i++){
    // PrintAndLog("DEBUG: FC %d, Cnt %d, Errs %d",fcLens[i],fcCnts[i],errCnt);    
    // get the 3 best FC values
    if (fcCnts[i]>maxCnt1) {
      best3=best2;
      best2=best1;
      maxCnt1=fcCnts[i];
      best1=i;
    } else if(fcCnts[i]>fcCnts[best2]){
      best3=best2;
      best2=i;
    } else if(fcCnts[i]>fcCnts[best3]){
      best3=i;
    }
  }
  uint8_t fcH=0, fcL=0;
  if (fcLens[best1]>fcLens[best2]){
    fcH=fcLens[best1];
    fcL=fcLens[best2];
  } else{
    fcH=fcLens[best2];
    fcL=fcLens[best1];
  }

  *mostFC=fcLens[best1]; 
  // TODO: take top 3 answers and compare to known Field clocks to get top 2

  uint16_t fcs = (((uint16_t)fcH)<<8) | fcL;
  // PrintAndLog("DEBUG: Best %d  best2 %d best3 %d",fcLens[best1],fcLens[best2],fcLens[best3]);
  
  return fcs;
}

//by marshmellow
//countPSK_FC is to detect the psk carrier clock length.
//counts and returns the 1 most common wave length
uint8_t countPSK_FC(uint8_t *BitStream, size_t size)
{
  uint8_t fcLens[] = {0,0,0,0,0,0,0,0,0,0};
  uint16_t fcCnts[] = {0,0,0,0,0,0,0,0,0,0};
  uint8_t fcLensFnd = 0;
  uint32_t fcCounter = 0;
  size_t i;
  if (size == 0) return 0;
  
  // prime i to first up transition
  for (i = 1; i < size-1; i++)
    if (BitStream[i] > BitStream[i-1] && BitStream[i] >= BitStream[i+1])
      break;

  for (; i < size-1; i++){
    if (BitStream[i] > BitStream[i-1] && BitStream[i] >= BitStream[i+1]){
      // new up transition
      fcCounter++;
      
      // save last field clock count  (fc/xx)
      // find which fcLens to save it to:
      for (int ii=0; ii<10; ii++){
        if (fcLens[ii]==fcCounter){
          fcCnts[ii]++;
          fcCounter=0;
          break;
        }
      }
      if (fcCounter>0 && fcLensFnd<10){
        //add new fc length 
        fcCnts[fcLensFnd]++;
        fcLens[fcLensFnd++]=fcCounter;
      }
      fcCounter=0;
    } else {
      // count sample
      fcCounter++;
    }
  }
  
  uint8_t best1=9;
  uint16_t maxCnt1=0;
  // go through fclens and find which ones are bigest  
  for (i=0; i<10; i++){
    //PrintAndLog("DEBUG: FC %d, Cnt %d",fcLens[i],fcCnts[i]);    
    // get the best FC value
    if (fcCnts[i]>maxCnt1) {
      maxCnt1=fcCnts[i];
      best1=i;
    }
  }
  return fcLens[best1]; 
}

//by marshmellow - demodulate PSK1 wave 
//uses wave lengths (# Samples) 
int pskRawDemod(uint8_t dest[], size_t *size, int *clock, int *invert)
{
  uint16_t loopCnt = 4096;  //don't need to loop through entire array...
  if (size == 0) return -1;
  if (*size<loopCnt) loopCnt = *size;

  uint8_t curPhase = *invert;
  size_t i, waveStart=0, waveEnd=0, firstFullWave=0, lastClkBit=0;
  uint8_t fc=0, fullWaveLen=0, tol=1;
  uint16_t errCnt=0, waveLenCnt=0;
  fc = countPSK_FC(dest, *size);
  if (fc!=2 && fc!=4 && fc!=8) return -1;
  //PrintAndLog("DEBUG: FC: %d",fc);
  *clock = DetectPSKClock(dest, *size, *clock);
  if (*clock==0) return -1;
  int avgWaveVal=0, lastAvgWaveVal=0;
  //find first phase shift
  for (i=0; i<loopCnt; i++){
    if (dest[i]+fc < dest[i+1] && dest[i+1] >= dest[i+2]){
      if (waveStart == 0) {
        waveStart = i+1;
        avgWaveVal=dest[i+1];
        //PrintAndLog("DEBUG: waveStart: %d",waveStart);
      } else {
        waveEnd = i+1;
        //PrintAndLog("DEBUG: waveEnd: %d",waveEnd);
        waveLenCnt = waveEnd-waveStart;
        lastAvgWaveVal = avgWaveVal/waveLenCnt;
        if (waveLenCnt > fc){
          firstFullWave = waveStart;
          fullWaveLen=waveLenCnt;
          //if average wave value is > graph 0 then it is an up wave or a 1
          if (lastAvgWaveVal > 128) curPhase^=1;
          break;
        } 
        waveStart=0;
        avgWaveVal=0;
      }
    }
    avgWaveVal+=dest[i+1];
  }
  //PrintAndLog("DEBUG: firstFullWave: %d, waveLen: %d",firstFullWave,fullWaveLen);  
  lastClkBit = firstFullWave; //set start of wave as clock align
  waveStart = 0;
  errCnt=0;
  size_t numBits=0;
  //PrintAndLog("DEBUG: clk: %d, lastClkBit: %d", *clock, lastClkBit);

  for (i = firstFullWave+fullWaveLen-1; i < *size-3; i++){
    //top edge of wave = start of new wave 
    if (dest[i]+fc < dest[i+1] && dest[i+1] >= dest[i+2]){
      if (waveStart == 0) {
        waveStart = i+1;
        waveLenCnt=0;
        avgWaveVal = dest[i+1];
      } else { //waveEnd
        waveEnd = i+1;
        waveLenCnt = waveEnd-waveStart;
        lastAvgWaveVal = avgWaveVal/waveLenCnt;
        if (waveLenCnt > fc){ 
          //PrintAndLog("DEBUG: avgWaveVal: %d, waveSum: %d",lastAvgWaveVal,avgWaveVal);
          //if this wave is a phase shift
          //PrintAndLog("DEBUG: phase shift at: %d, len: %d, nextClk: %d, i: %d, fc: %d",waveStart,waveLenCnt,lastClkBit+*clock-tol,i+1,fc);
          if (i+1 >= lastClkBit + *clock - tol){ //should be a clock bit
            curPhase^=1;
            dest[numBits] = curPhase;
            numBits++;
            lastClkBit += *clock;
          } else if (i<lastClkBit+10){
            //noise after a phase shift - ignore
          } else { //phase shift before supposed to based on clock
            errCnt++;
            dest[numBits] = 77;
            numBits++;
          }
        } else if (i+1 > lastClkBit + *clock + tol + fc){
          lastClkBit += *clock; //no phase shift but clock bit
          dest[numBits] = curPhase;
          numBits++;
        }
        avgWaveVal=0;
        waveStart=i+1;
      }
    }
    avgWaveVal+=dest[i+1];
  }
  *size = numBits;
  return errCnt;
}
