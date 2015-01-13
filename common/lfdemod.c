//-----------------------------------------------------------------------------
// Copyright (C) 2014
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency commands
//-----------------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>
#include "lfdemod.h"

//by marshmellow
//takes 1s and 0s and searches for EM410x format - output EM ID
uint64_t Em410xDecode(uint8_t *BitStream, size_t size)
{
	//no arguments needed - built this way in case we want this to be a direct call from "data " cmds in the future
	//  otherwise could be a void with no arguments
	//set defaults
	uint64_t lo=0;
	uint32_t i = 0;
	if (BitStream[10]>1){  //allow only 1s and 0s
		// PrintAndLog("no data found");
		return 0;
	}
	uint8_t parityTest=0;
	// 111111111 bit pattern represent start of frame
	uint8_t frame_marker_mask[] = {1,1,1,1,1,1,1,1,1};
	uint32_t idx = 0;
	uint32_t ii=0;
	uint8_t resetCnt = 0;
	while( (idx + 64) < size) {
 restart:
		// search for a start of frame marker
		if ( memcmp(BitStream+idx, frame_marker_mask, sizeof(frame_marker_mask)) == 0)
		{ // frame marker found
			idx+=9;
			for (i=0; i<10;i++){
				for(ii=0; ii<5; ++ii){
					parityTest ^= BitStream[(i*5)+ii+idx];
				}
				if (!parityTest){
					parityTest=0;
					for (ii=0; ii<4;++ii){
						lo=(lo<<1LL)|(BitStream[(i*5)+ii+idx]);
					}
					//PrintAndLog("DEBUG: EM parity passed parity val: %d, i:%d, ii:%d,idx:%d, Buffer: %d%d%d%d%d,lo: %d",parityTest,i,ii,idx,BitStream[idx+ii+(i*5)-5],BitStream[idx+ii+(i*5)-4],BitStream[idx+ii+(i*5)-3],BitStream[idx+ii+(i*5)-2],BitStream[idx+ii+(i*5)-1],lo);
				}else {//parity failed
					//PrintAndLog("DEBUG: EM parity failed parity val: %d, i:%d, ii:%d,idx:%d, Buffer: %d%d%d%d%d",parityTest,i,ii,idx,BitStream[idx+ii+(i*5)-5],BitStream[idx+ii+(i*5)-4],BitStream[idx+ii+(i*5)-3],BitStream[idx+ii+(i*5)-2],BitStream[idx+ii+(i*5)-1]);
					parityTest=0;
					idx-=8;
					if (resetCnt>5)return 0; //try 5 times
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
int askmandemod(uint8_t *BinStream, size_t *size, int *clk, int *invert)
{
	int i;
	int high = 0, low = 255;
	*clk=DetectASKClock(BinStream, *size, *clk); //clock default

	if (*clk<8) *clk =64;
	if (*clk<32) *clk=32;
	if (*invert != 0 && *invert != 1) *invert=0;
	uint32_t initLoopMax = 200;
	if (initLoopMax > *size) initLoopMax=*size;
	// Detect high and lows
	for (i = 0; i < initLoopMax; ++i) //200 samples should be enough to find high and low values
	{
		if (BinStream[i] > high)
			high = BinStream[i];
		else if (BinStream[i] < low)
			low = BinStream[i];
	}
	if ((high < 129) ){  //throw away static (anything < 1 graph)
		//PrintAndLog("no data found");
		return -2;
	}
	//25% fuzz in case highs and lows aren't clipped [marshmellow]
	high=(int)(((high-128)*.75)+128);
	low= (int)(((low-128)*.75)+128);

	//PrintAndLog("DEBUG - valid high: %d - valid low: %d",high,low);
	int lastBit = 0;  //set first clock check
	uint32_t bitnum = 0;     //output counter
	int tol = 0;  //clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
	if (*clk==32)tol=1;    //clock tolerance may not be needed anymore currently set to + or - 1 but could be increased for poor waves or removed entirely
	int iii = 0;
	uint32_t gLen = *size;
	if (gLen > 3000) gLen=3000;
	uint8_t errCnt =0;
	uint32_t bestStart = *size;
	uint32_t bestErrCnt = (*size/1000);
	uint32_t maxErr = (*size/1000);
	//PrintAndLog("DEBUG - lastbit - %d",lastBit);
	//loop to find first wave that works
	for (iii=0; iii < gLen; ++iii){
		if ((BinStream[iii] >= high) || (BinStream[iii] <= low)){
			lastBit=iii-*clk;
			errCnt=0;
			//loop through to see if this start location works
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
				if ((i-iii) >(400 * *clk)) break; //got plenty of bits
			}
			//we got more than 64 good bits and not all errors
			if ((((i-iii)/ *clk) > (64+errCnt)) && (errCnt<maxErr)) {
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
	if (bestErrCnt<maxErr){
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
			if (bitnum >=400) break;
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
//take 10 and 01 and manchester decode
//run through 2 times and take least errCnt
int manrawdecode(uint8_t * BitStream, size_t *size)
{
	int bitnum=0;
	int errCnt =0;
	int i=1;
	int bestErr = 1000;
	int bestRun = 0;
	int ii=1;
	for (ii=1;ii<3;++ii){
		i=1;
		for (i=i+ii;i<*size-2;i+=2){
			if(BitStream[i]==1 && (BitStream[i+1]==0)){
			} else if((BitStream[i]==0)&& BitStream[i+1]==1){
			} else {
				errCnt++;
			}
			if(bitnum>300) break;
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
		for (i=i+ii;i < *size-2;i+=2){
			if(BitStream[i] == 1 && (BitStream[i+1] == 0)){
				BitStream[bitnum++]=0;
			} else if((BitStream[i] == 0) && BitStream[i+1] == 1){
				BitStream[bitnum++]=1;
			} else {
				BitStream[bitnum++]=77;
				//errCnt++;
			}
			if(bitnum>300) break;
		}
		*size=bitnum;
	}
	return errCnt;
}


//by marshmellow
//take 01 or 10 = 0 and 11 or 00 = 1
int BiphaseRawDecode(uint8_t *BitStream, size_t *size, int offset)
{
	uint8_t bitnum=0;
	uint32_t errCnt =0;
	uint32_t i=1;
	i=offset;
	for (;i<*size-2;i+=2){
		if((BitStream[i]==1 && BitStream[i+1]==0) || (BitStream[i]==0 && BitStream[i+1]==1)){
			BitStream[bitnum++]=1;
		} else if((BitStream[i]==0 && BitStream[i+1]==0) || (BitStream[i]==1 && BitStream[i+1]==1)){
			BitStream[bitnum++]=0;
		} else {
			BitStream[bitnum++]=77;
			errCnt++;
		}
		if(bitnum>250) break;
	}
	*size=bitnum;
	return errCnt;
}

//by marshmellow
//takes 2 arguments - clock and invert both as integers
//attempts to demodulate ask only
//prints binary found and saves in graphbuffer for further commands
int askrawdemod(uint8_t *BinStream, size_t *size, int *clk, int *invert)
{
	uint32_t i;
	// int invert=0;  //invert default
	int high = 0, low = 255;
	*clk=DetectASKClock(BinStream, *size, *clk); //clock default
	uint8_t BitStream[502] = {0};

	if (*clk<8) *clk =64;
	if (*clk<32) *clk=32;
	if (*invert != 0 && *invert != 1) *invert =0;
	uint32_t initLoopMax = 200;
	if (initLoopMax > *size) initLoopMax=*size;
	// Detect high and lows
	for (i = 0; i < initLoopMax; ++i) //200 samples should be plenty to find high and low values
	{
		if (BinStream[i] > high)
			high = BinStream[i];
		else if (BinStream[i] < low)
			low = BinStream[i];
	}
	if ((high < 129)){  //throw away static  high has to be more than 0 on graph. 
													//noise <= -10 here
		//   PrintAndLog("no data found");
		return -2;
	}
	//25% fuzz in case highs and lows aren't clipped [marshmellow]
	high=(int)(((high-128)*.75)+128);
	low= (int)(((low-128)*.75)+128);

	//PrintAndLog("DEBUG - valid high: %d - valid low: %d",high,low);
	int lastBit = 0;  //set first clock check
	uint32_t bitnum = 0;     //output counter
	uint8_t tol = 0;  //clock tolerance adjust - waves will be accepted as within the clock
	                  //  if they fall + or - this value + clock from last valid wave
	if (*clk == 32) tol=1;    //clock tolerance may not be needed anymore currently set to
	                          //  + or - 1 but could be increased for poor waves or removed entirely
	uint32_t iii = 0;
	uint32_t gLen = *size;
	if (gLen > 500) gLen=500;
	uint8_t errCnt =0;
	uint32_t bestStart = *size;
	uint32_t bestErrCnt = (*size/1000);
	uint8_t midBit=0;
	//PrintAndLog("DEBUG - lastbit - %d",lastBit);
	//loop to find first wave that works
	for (iii=0; iii < gLen; ++iii){
		if ((BinStream[iii]>=high) || (BinStream[iii]<=low)){
			lastBit=iii-*clk;
			//loop through to see if this start location works
			for (i = iii; i < *size; ++i) {
				if ((BinStream[i] >= high) && ((i-lastBit)>(*clk-tol))){
					lastBit+=*clk;
					BitStream[bitnum] = *invert;
					bitnum++;
					midBit=0;
				} else if ((BinStream[i] <= low) && ((i-lastBit)>(*clk-tol))){
					//low found and we are expecting a bar
					lastBit+=*clk;
					BitStream[bitnum] = 1- *invert;
					bitnum++;
					midBit=0;
				} else if ((BinStream[i]<=low) && (midBit==0) && ((i-lastBit)>((*clk/2)-tol))){
					//mid bar?
					midBit=1;
					BitStream[bitnum]= 1- *invert;
					bitnum++;
				} else if ((BinStream[i]>=high) && (midBit==0) && ((i-lastBit)>((*clk/2)-tol))){
					//mid bar?
					midBit=1;
					BitStream[bitnum]= *invert;
					bitnum++;
				} else if ((i-lastBit)>((*clk/2)+tol) && (midBit==0)){
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
						if (errCnt > ((*size/1000))){  //allow 1 error for every 1000 samples else start over
							errCnt=0;
							bitnum=0;//start over
							break;
						}
					}
				}
				if (bitnum>500) break;
			}
			//we got more than 64 good bits and not all errors
			if ((bitnum > (64+errCnt)) && (errCnt<(*size/1000))) {
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
			if (bestErrCnt < (*size/1000)) iii=bestStart;
		}
	}
	if (bitnum>16){
		for (i=0; i < bitnum; ++i){
			BinStream[i]=BitStream[i];
		}
		*size=bitnum;
	} else return -1;
	return errCnt;
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
int HIDdemodFSK(uint8_t *dest, size_t size, uint32_t *hi2, uint32_t *hi, uint32_t *lo)
{

	size_t idx=0; //, found=0; //size=0,
	// FSK demodulator
	size = fskdemod(dest, size,50,0,10,8);

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
	static const uint8_t THRESHOLD = 129;
	uint32_t idx=0;
	//make sure buffer has data
	if (size < 66) return -1;
	//test samples are not just noise
	uint8_t justNoise = 1;
	for(idx=0;idx< size && justNoise ;idx++){
		justNoise = dest[idx] < THRESHOLD;
	}
	if(justNoise) return 0;

	// FSK demodulator
	size = fskdemod(dest, size, 64, 1, 10, 8);  //  RF/64 and invert
	if (size < 65) return -1;  //did we get a good demod?
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
	for( idx=0; idx < (size - 65); idx++) {
		if ( memcmp(dest + idx, mask, sizeof(mask))==0) {
			//frame marker found
			if (!dest[idx+8] && dest[idx+17]==1 && dest[idx+26]==1 && dest[idx+35]==1 && dest[idx+44]==1 && dest[idx+53]==1){
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
	int i=0;
	int peak=0;
	int low=255;
	int clk[]={16,32,40,50,64,100,128,256};
	int loopCnt = 256;  //don't need to loop through entire array...
	if (size<loopCnt) loopCnt = size;

	//if we already have a valid clock quit
	for (;i<8;++i)
		if (clk[i] == clock) return clock;

	//get high and low peak
	for (i=0; i < loopCnt; ++i){
		if(dest[i] > peak){
			peak = dest[i];
		}
		if(dest[i] < low){
			low = dest[i];
		}
	}
	peak=(int)(((peak-128)*.75)+128);
	low= (int)(((low-128)*.75)+128);
	int ii;
	int clkCnt;
	int tol = 0;
	int bestErr[]={1000,1000,1000,1000,1000,1000,1000,1000};
	int errCnt=0;
	//test each valid clock from smallest to greatest to see which lines up
	for(clkCnt=0; clkCnt < 6; ++clkCnt){
		if (clk[clkCnt] == 32){
			tol=1;
		}else{
			tol=0;
		}
		bestErr[clkCnt]=1000;
		//try lining up the peaks by moving starting point (try first 256)
		for (ii=0; ii< loopCnt; ++ii){
			if ((dest[ii] >= peak) || (dest[ii] <= low)){
				errCnt=0;
				// now that we have the first one lined up test rest of wave array
				for (i=0; i<((int)(size/clk[clkCnt])-1); ++i){
					if (dest[ii+(i*clk[clkCnt])]>=peak || dest[ii+(i*clk[clkCnt])]<=low){
					}else if(dest[ii+(i*clk[clkCnt])-tol]>=peak || dest[ii+(i*clk[clkCnt])-tol]<=low){
					}else if(dest[ii+(i*clk[clkCnt])+tol]>=peak || dest[ii+(i*clk[clkCnt])+tol]<=low){
					}else{  //error no peak detected
						errCnt++;
					}
				}
				//if we found no errors this is correct one - return this clock
				if(errCnt==0) return clk[clkCnt];
				//if we found errors see if it is lowest so far and save it as best run
				if(errCnt<bestErr[clkCnt]) bestErr[clkCnt]=errCnt;
			}
		}
	}
	int iii=0;
	int best=0;
	for (iii=0; iii<7;++iii){
		if (bestErr[iii]<bestErr[best]){
			//                current best bit to error ratio     vs  new bit to error ratio
			if (((size/clk[best])/bestErr[best] < (size/clk[iii])/bestErr[iii]) ){
				best = iii;
			}
		}
	}
	return clk[best];
}

//by marshmellow
//detect psk clock by reading #peaks vs no peaks(or errors)
int DetectpskNRZClock(uint8_t dest[], size_t size, int clock)
{
	int i=0;
	int peak=0;
	int low=255;
	int clk[]={16,32,40,50,64,100,128,256};
	int loopCnt = 2048;  //don't need to loop through entire array...
	if (size<loopCnt) loopCnt = size;

	//if we already have a valid clock quit
	for (; i < 8; ++i)
		if (clk[i] == clock) return clock;

	//get high and low peak
	for (i=0; i < loopCnt; ++i){
		if(dest[i] > peak){
			peak = dest[i];
		}
		if(dest[i] < low){
			low = dest[i];
		}
	}
	peak=(int)(((peak-128)*.75)+128);
	low= (int)(((low-128)*.75)+128);
	//PrintAndLog("DEBUG: peak: %d, low: %d",peak,low);
	int ii;
	uint8_t clkCnt;
	uint8_t tol = 0;
	int peakcnt=0;
	int errCnt=0;
	int bestErr[]={1000,1000,1000,1000,1000,1000,1000,1000,1000};
	int peaksdet[]={0,0,0,0,0,0,0,0,0};
	//test each valid clock from smallest to greatest to see which lines up
	for(clkCnt=0; clkCnt < 6; ++clkCnt){
		if (clk[clkCnt] == 32){
			tol=1;
		}else{
			tol=0;
		}
		//try lining up the peaks by moving starting point (try first 256)
		for (ii=0; ii< loopCnt; ++ii){
			if ((dest[ii] >= peak) || (dest[ii] <= low)){
				errCnt=0;
				peakcnt=0;
				// now that we have the first one lined up test rest of wave array
				for (i=0; i < ((int)(size/clk[clkCnt])-1); ++i){
					if (dest[ii+(i*clk[clkCnt])]>=peak || dest[ii+(i*clk[clkCnt])]<=low){
						peakcnt++;
					}else if(dest[ii+(i*clk[clkCnt])-tol]>=peak || dest[ii+(i*clk[clkCnt])-tol]<=low){
						peakcnt++;
					}else if(dest[ii+(i*clk[clkCnt])+tol]>=peak || dest[ii+(i*clk[clkCnt])+tol]<=low){
						peakcnt++;
					}else{  //error no peak detected
						errCnt++;
					}
				}
				if(peakcnt>peaksdet[clkCnt]) {
					peaksdet[clkCnt]=peakcnt;
					bestErr[clkCnt]=errCnt;
				}
			}
		}
	}
	int iii=0;
	int best=0;
	//int ratio2;  //debug
	int ratio;
	//int bits;
	for (iii=0; iii < 7; ++iii){
		ratio=1000;
		//ratio2=1000;  //debug
		//bits=size/clk[iii];  //debug
		if (peaksdet[iii] > 0){
			ratio=bestErr[iii]/peaksdet[iii];
			if (((bestErr[best]/peaksdet[best]) > (ratio)+1)){
				best = iii;
			}
			//ratio2=bits/peaksdet[iii]; //debug
		}
		//PrintAndLog("DEBUG: Clk: %d, peaks: %d, errs: %d, bestClk: %d, ratio: %d, bits: %d, peakbitr: %d",clk[iii],peaksdet[iii],bestErr[iii],clk[best],ratio, bits,ratio2);
	}
	return clk[best];
}

//by marshmellow (attempt to get rid of high immediately after a low)
void pskCleanWave(uint8_t *bitStream, size_t size)
{
	int i;
	int low=255;
	int high=0;
	int gap = 4;
 // int loopMax = 2048;
	int newLow=0;
	int newHigh=0;
	for (i=0; i < size; ++i){
		if (bitStream[i] < low) low=bitStream[i];
		if (bitStream[i] > high) high=bitStream[i];
	}
	high = (int)(((high-128)*.80)+128);
	low = (int)(((low-128)*.90)+128);
	//low = (uint8_t)(((int)(low)-128)*.80)+128;
	for (i=0; i < size; ++i){
		if (newLow == 1){
			bitStream[i]=low+8;
			gap--;
			if (gap == 0){
				newLow=0;
				gap=4;
			}
		}else if (newHigh == 1){
			bitStream[i]=high-8;
			gap--;
			if (gap == 0){
				newHigh=0;
				gap=4;
			}
		}
		if (bitStream[i] <= low) newLow=1;
		if (bitStream[i] >= high) newHigh=1;
	}
	return;
}


//redesigned by marshmellow adjusted from existing decode functions
//indala id decoding - only tested on 26 bit tags, but attempted to make it work for more
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


//by marshmellow - demodulate PSK wave or NRZ wave (both similar enough)
//peaks switch bit (high=1 low=0) each clock cycle = 1 bit determined by last peak
int pskNRZrawDemod(uint8_t *dest, size_t *size, int *clk, int *invert)
{
	pskCleanWave(dest,*size);
	int clk2 = DetectpskNRZClock(dest, *size, *clk);
	*clk=clk2;
	uint32_t i;
	uint8_t high=0, low=255;
	uint32_t gLen = *size;
	if (gLen > 1280) gLen=1280;
	// get high
	for (i=0; i < gLen; ++i){
		if (dest[i] > high) high = dest[i];
		if (dest[i] < low) low = dest[i];
	}
	//fudge high/low bars by 25%
	high = (uint8_t)((((int)(high)-128)*.75)+128);
	low = (uint8_t)((((int)(low)-128)*.80)+128);

	//PrintAndLog("DEBUG - valid high: %d - valid low: %d",high,low);
	int lastBit = 0;  //set first clock check
	uint32_t bitnum = 0;     //output counter
	uint8_t tol = 0;  //clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
	if (*clk==32) tol = 2;    //clock tolerance may not be needed anymore currently set to + or - 1 but could be increased for poor waves or removed entirely
	uint32_t iii = 0;
	uint8_t errCnt =0;
	uint32_t bestStart = *size;
	uint32_t maxErr = (*size/1000);
	uint32_t bestErrCnt = maxErr;
	//uint8_t midBit=0;
	uint8_t curBit=0;
	uint8_t bitHigh=0;
	uint8_t ignorewin=*clk/8;
	//PrintAndLog("DEBUG - lastbit - %d",lastBit);
	//loop to find first wave that works - align to clock
	for (iii=0; iii < gLen; ++iii){
		if ((dest[iii]>=high) || (dest[iii]<=low)){
			lastBit=iii-*clk;
			//loop through to see if this start location works
			for (i = iii; i < *size; ++i) {
				//if we found a high bar and we are at a clock bit
				if ((dest[i]>=high ) && (i>=lastBit+*clk-tol && i<=lastBit+*clk+tol)){
					bitHigh=1;
					lastBit+=*clk;
					ignorewin=*clk/8;
					bitnum++;
				//else if low bar found and we are at a clock point
				}else if ((dest[i]<=low ) && (i>=lastBit+*clk-tol && i<=lastBit+*clk+tol)){
					bitHigh=1;
					lastBit+=*clk;
					ignorewin=*clk/8;
					bitnum++;
				//else if no bars found
				}else if(dest[i] < high && dest[i] > low) {
					if (ignorewin==0){
						bitHigh=0;
					}else ignorewin--;
										//if we are past a clock point
					if (i >= lastBit+*clk+tol){ //clock val
						lastBit+=*clk;
						bitnum++;
					}
				//else if bar found but we are not at a clock bit and we did not just have a clock bit
				}else if ((dest[i]>=high || dest[i]<=low) && (i<lastBit+*clk-tol || i>lastBit+*clk+tol) && (bitHigh==0)){
					//error bar found no clock...
					errCnt++;
				}
				if (bitnum>=1000) break;
			}
			//we got more than 64 good bits and not all errors
			if ((bitnum > (64+errCnt)) && (errCnt < (maxErr))) {
				//possible good read
				if (errCnt == 0){
					bestStart = iii;
					bestErrCnt = errCnt;
					break;  //great read - finish
				}
				if (bestStart == iii) break;  //if current run == bestErrCnt run (after exhausted testing) then finish
				if (errCnt < bestErrCnt){  //set this as new best run
					bestErrCnt = errCnt;
					bestStart = iii;
				}
			}
		}
	}
	if (bestErrCnt < maxErr){
		//best run is good enough set to best run and set overwrite BinStream
		iii=bestStart;
		lastBit=bestStart-*clk;
		bitnum=0;
		for (i = iii; i < *size; ++i) {
			//if we found a high bar and we are at a clock bit
			if ((dest[i] >= high ) && (i>=lastBit+*clk-tol && i<=lastBit+*clk+tol)){
				bitHigh=1;
				lastBit+=*clk;
				curBit=1-*invert;
				dest[bitnum]=curBit;
				ignorewin=*clk/8;
				bitnum++;
			//else if low bar found and we are at a clock point
			}else if ((dest[i]<=low ) && (i>=lastBit+*clk-tol && i<=lastBit+*clk+tol)){
				bitHigh=1;
				lastBit+=*clk;
				curBit=*invert;
				dest[bitnum]=curBit;
				ignorewin=*clk/8;
				bitnum++;
			//else if no bars found
			}else if(dest[i]<high && dest[i]>low) {
				if (ignorewin==0){
					bitHigh=0;
				}else ignorewin--;
				//if we are past a clock point
				if (i>=lastBit+*clk+tol){ //clock val
					lastBit+=*clk;
					dest[bitnum]=curBit;
					bitnum++;
				}
			//else if bar found but we are not at a clock bit and we did not just have a clock bit
			}else if ((dest[i]>=high || dest[i]<=low) && ((i<lastBit+*clk-tol) || (i>lastBit+*clk+tol)) && (bitHigh==0)){
				//error bar found no clock...
				bitHigh=1;
				dest[bitnum]=77;
				bitnum++;
				errCnt++;
			}
			if (bitnum >=1000) break;
		}
		*size=bitnum;
	} else{
		*size=bitnum;
		*clk=bestStart;
		return -1;
	}

	if (bitnum>16){
		*size=bitnum;
	} else return -1;
	return errCnt;
}

