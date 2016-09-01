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
#include "lfdemod.h"
#include <string.h>

//un_comment to allow debug print calls when used not on device
void dummy(char *fmt, ...){}

#ifndef ON_DEVICE
#include "ui.h"
#include "cmdparser.h"
#include "cmddata.h"
#define prnt PrintAndLog
#else 
	uint8_t g_debugMode=0;
#define prnt dummy
#endif

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
	for (size_t i=0; i < size; i++){
		if (BitStream[i] > *high) *high = BitStream[i];
		if (BitStream[i] < *low) *low = BitStream[i];
	}
	if (*high < 123) return -1; // just noise
	*high = ((*high-128)*fuzzHi + 12800)/100;
	*low = ((*low-128)*fuzzLo + 12800)/100;
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
// takes a array of binary values, start position, length of bits per parity (includes parity bit),
//   Parity Type (1 for odd; 0 for even; 2 for Always 1's; 3 for Always 0's), and binary Length (length to run) 
size_t removeParity(uint8_t *BitStream, size_t startIdx, uint8_t pLen, uint8_t pType, size_t bLen)
{
	uint32_t parityWd = 0;
	size_t j = 0, bitCnt = 0;
	for (int word = 0; word < (bLen); word+=pLen){
		for (int bit=0; bit < pLen; bit++){
			parityWd = (parityWd << 1) | BitStream[startIdx+word+bit];
			BitStream[j++] = (BitStream[startIdx+word+bit]);
		}
		j--; // overwrite parity with next data
		// if parity fails then return 0
		switch (pType) {
			case 3: if (BitStream[j]==1) return 0; break; //should be 0 spacer bit
			case 2: if (BitStream[j]==0) return 0; break; //should be 1 spacer bit
			default: //test parity
				if (parityTest(parityWd, pLen, pType) == 0) return 0; break;
		}
		bitCnt+=(pLen-1);
		parityWd = 0;
	}
	// if we got here then all the parities passed
	//return ID start index and size
	return bitCnt;
}

// by marshmellow
// takes a array of binary values, length of bits per parity (includes parity bit),
//   Parity Type (1 for odd; 0 for even; 2 Always 1's; 3 Always 0's), and binary Length (length to run)
//   Make sure *dest is long enough to store original sourceLen + #_of_parities_to_be_added
size_t addParity(uint8_t *BitSource, uint8_t *dest, uint8_t sourceLen, uint8_t pLen, uint8_t pType)
{
	uint32_t parityWd = 0;
	size_t j = 0, bitCnt = 0;
	for (int word = 0; word < sourceLen; word+=pLen-1) {
		for (int bit=0; bit < pLen-1; bit++){
			parityWd = (parityWd << 1) | BitSource[word+bit];
			dest[j++] = (BitSource[word+bit]);
		}
		
		// if parity fails then return 0
		switch (pType) {
			case 3: dest[j++]=0; break; // marker bit which should be a 0
			case 2: dest[j++]=1; break; // marker bit which should be a 1
			default: 
				dest[j++] = parityTest(parityWd, pLen-1, pType) ^ 1;
				break;
		}
		bitCnt += pLen;
		parityWd = 0;
	}
	// if we got here then all the parities passed
	//return ID start index and size
	return bitCnt;
}

uint32_t bytebits_to_byte(uint8_t *src, size_t numbits)
{
	uint32_t num = 0;
	for(int i = 0 ; i < numbits ; i++) {
		num = (num << 1) | (*src);
		src++;
	}
	return num;
}

//least significant bit first
uint32_t bytebits_to_byteLSBF(uint8_t *src, size_t numbits)
{
	uint32_t num = 0;
	for(int i = 0 ; i < numbits ; i++) {
		num = (num << 1) | *(src + (numbits-(i+1)));
	}
	return num;
}

//by marshmellow
//search for given preamble in given BitStream and return success=1 or fail=0 and startIndex and length
uint8_t preambleSearch(uint8_t *BitStream, uint8_t *preamble, size_t pLen, size_t *size, size_t *startIdx)
{
	// Sanity check.  If preamble length is bigger than bitstream length.
	if ( *size <= pLen ) return 0;
	
	uint8_t foundCnt = 0;
	for (int idx = 0; idx < *size - pLen; idx++){
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
uint8_t Em410xDecode(uint8_t *BitStream, size_t *size, size_t *startIdx, uint32_t *hi, uint64_t *lo)
{
	//no arguments needed - built this way in case we want this to be a direct call from "data " cmds in the future
	//  otherwise could be a void with no arguments
	//set defaults
	uint32_t i = 0;
	if (BitStream[1]>1) return 0;  //allow only 1s and 0s

	// 111111111 bit pattern represent start of frame
	//  include 0 in front to help get start pos
	uint8_t preamble[] = {0,1,1,1,1,1,1,1,1,1};
	uint32_t idx = 0;
	uint32_t parityBits = 0;
	uint8_t errChk = 0;
	uint8_t FmtLen = 10;
	*startIdx = 0;
	errChk = preambleSearch(BitStream, preamble, sizeof(preamble), size, startIdx);
	if (errChk == 0 || *size < 64) return 0;
	if (*size > 64) FmtLen = 22;
	*startIdx += 1; //get rid of 0 from preamble
	idx = *startIdx + 9;
	for (i=0; i<FmtLen; i++){ //loop through 10 or 22 sets of 5 bits (50-10p = 40 bits or 88 bits)
		parityBits = bytebits_to_byte(BitStream+(i*5)+idx,5);
		//check even parity - quit if failed
		if (parityTest(parityBits, 5, 0) == 0) return 0;
		//set uint64 with ID from BitStream
		for (uint8_t ii=0; ii<4; ii++){
			*hi = (*hi << 1) | (*lo >> 63);
			*lo = (*lo << 1) | (BitStream[(i*5)+ii+idx]);
		}
	}
	if (errChk != 0) return 1;
	//skip last 5 bit parity test for simplicity.
	// *size = 64 | 128;
	return 0;
}

//by marshmellow
//demodulates strong heavily clipped samples
int cleanAskRawDemod(uint8_t *BinStream, size_t *size, int clk, int invert, int high, int low)
{
	size_t bitCnt=0, smplCnt=0, errCnt=0;
	uint8_t waveHigh = 0;
	for (size_t i=0; i < *size; i++){
		if (BinStream[i] >= high && waveHigh){
			smplCnt++;
		} else if (BinStream[i] <= low && !waveHigh){
			smplCnt++;
		} else { //transition
			if ((BinStream[i] >= high && !waveHigh) || (BinStream[i] <= low && waveHigh)){
				if (smplCnt > clk-(clk/4)-1) { //full clock
					if (smplCnt > clk + (clk/4)+1) { //too many samples
						errCnt++;
						if (g_debugMode==2) prnt("DEBUG ASK: Modulation Error at: %u", i);
						BinStream[bitCnt++]=7;
					} else if (waveHigh) {
						BinStream[bitCnt++] = invert;
						BinStream[bitCnt++] = invert;
					} else if (!waveHigh) {
						BinStream[bitCnt++] = invert ^ 1;
						BinStream[bitCnt++] = invert ^ 1;
					}
					waveHigh ^= 1;  
					smplCnt = 0;
				} else if (smplCnt > (clk/2) - (clk/4)-1) {
					if (waveHigh) {
						BinStream[bitCnt++] = invert;
					} else if (!waveHigh) {
						BinStream[bitCnt++] = invert ^ 1;
					}
					waveHigh ^= 1;  
					smplCnt = 0;
				} else if (!bitCnt) {
					//first bit
					waveHigh = (BinStream[i] >= high);
					smplCnt = 1;
				} else {
					smplCnt++;
					//transition bit oops
				}
			} else { //haven't hit new high or new low yet
				smplCnt++;
			}
		}
	}
	*size = bitCnt;
	return errCnt;
}

//by marshmellow
void askAmp(uint8_t *BitStream, size_t size)
{
	uint8_t last = 128;
	for(size_t i = 1; i < size; ++i){
		if (BitStream[i]-BitStream[i-1] >= 30) //large jump up
			last = 255;
		else if(BitStream[i-1] - BitStream[i] >= 20) //large jump down
			last = 0;
		
		BitStream[i] = last;
	}
}

//by marshmellow
//attempts to demodulate ask modulations, askType == 0 for ask/raw, askType==1 for ask/manchester
int askdemod(uint8_t *BinStream, size_t *size, int *clk, int *invert, int maxErr, uint8_t amp, uint8_t askType)
{
	if (*size==0) return -1;
	int start = DetectASKClock(BinStream, *size, clk, maxErr); //clock default
	if (*clk==0 || start < 0) return -3;
	if (*invert != 1) *invert = 0;
	if (amp==1) askAmp(BinStream, *size);
	if (g_debugMode==2) prnt("DEBUG ASK: clk %d, beststart %d", *clk, start);

	uint8_t initLoopMax = 255;
	if (initLoopMax > *size) initLoopMax = *size;
	// Detect high and lows
	//25% clip in case highs and lows aren't clipped [marshmellow]
	int high, low;
	if (getHiLo(BinStream, initLoopMax, &high, &low, 75, 75) < 1) 
		return -2; //just noise

	size_t errCnt = 0;
	// if clean clipped waves detected run alternate demod
	if (DetectCleanAskWave(BinStream, *size, high, low)) {
		if (g_debugMode==2) prnt("DEBUG ASK: Clean Wave Detected - using clean wave demod");
		errCnt = cleanAskRawDemod(BinStream, size, *clk, *invert, high, low);
		if (askType) //askman
			return manrawdecode(BinStream, size, 0);	
		else //askraw
			return errCnt;
	}
	if (g_debugMode==2) prnt("DEBUG ASK: Weak Wave Detected - using weak wave demod");

	int lastBit;  //set first clock check - can go negative
	size_t i, bitnum = 0;     //output counter
	uint8_t midBit = 0;
	uint8_t tol = 0;  //clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
	if (*clk <= 32) tol = 1;    //clock tolerance may not be needed anymore currently set to + or - 1 but could be increased for poor waves or removed entirely
	size_t MaxBits = 3072;    //max bits to collect
	lastBit = start - *clk;

	for (i = start; i < *size; ++i) {
		if (i-lastBit >= *clk-tol){
			if (BinStream[i] >= high) {
				BinStream[bitnum++] = *invert;
			} else if (BinStream[i] <= low) {
				BinStream[bitnum++] = *invert ^ 1;
			} else if (i-lastBit >= *clk+tol) {
				if (bitnum > 0) {
					if (g_debugMode==2) prnt("DEBUG ASK: Modulation Error at: %u", i);
					BinStream[bitnum++]=7;
					errCnt++;						
				} 
			} else { //in tolerance - looking for peak
				continue;
			}
			midBit = 0;
			lastBit += *clk;
		} else if (i-lastBit >= (*clk/2-tol) && !midBit && !askType){
			if (BinStream[i] >= high) {
				BinStream[bitnum++] = *invert;
			} else if (BinStream[i] <= low) {
				BinStream[bitnum++] = *invert ^ 1;
			} else if (i-lastBit >= *clk/2+tol) {
				BinStream[bitnum] = BinStream[bitnum-1];
				bitnum++;
			} else { //in tolerance - looking for peak
				continue;
			}
			midBit = 1;
		}
		if (bitnum >= MaxBits) break;
	}
	*size = bitnum;
	return errCnt;
}

//by marshmellow
//take 10 and 01 and manchester decode
//run through 2 times and take least errCnt
int manrawdecode(uint8_t * BitStream, size_t *size, uint8_t invert)
{
	uint16_t bitnum=0, MaxBits = 512, errCnt = 0;
	size_t i, ii;
	uint16_t bestErr = 1000, bestRun = 0;
	if (*size < 16) return -1;
	//find correct start position [alignment]
	for (ii=0;ii<2;++ii){
		for (i=ii; i<*size-3; i+=2)
			if (BitStream[i]==BitStream[i+1])
				errCnt++;

		if (bestErr>errCnt){
			bestErr=errCnt;
			bestRun=ii;
		}
		errCnt=0;
	}
	//decode
	for (i=bestRun; i < *size-3; i+=2){
		if(BitStream[i] == 1 && (BitStream[i+1] == 0)){
			BitStream[bitnum++]=invert;
		} else if((BitStream[i] == 0) && BitStream[i+1] == 1){
			BitStream[bitnum++]=invert^1;
		} else {
			BitStream[bitnum++]=7;
		}
		if(bitnum>MaxBits) break;
	}
	*size=bitnum;
	return bestErr;
}

uint32_t manchesterEncode2Bytes(uint16_t datain) {
	uint32_t output = 0;
	uint8_t curBit = 0;
	for (uint8_t i=0; i<16; i++) {
		curBit = (datain >> (15-i) & 1);
		output |= (1<<(((15-i)*2)+curBit));
	}
	return output;
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
//take 01 or 10 = 1 and 11 or 00 = 0
//check for phase errors - should never have 111 or 000 should be 01001011 or 10110100 for 1010
//decodes biphase or if inverted it is AKA conditional dephase encoding AKA differential manchester encoding
int BiphaseRawDecode(uint8_t *BitStream, size_t *size, int offset, int invert)
{
	uint16_t bitnum = 0;
	uint16_t errCnt = 0;
	size_t i = offset;
	uint16_t MaxBits=512;
	//if not enough samples - error
	if (*size < 51) return -1;
	//check for phase change faults - skip one sample if faulty
	uint8_t offsetA = 1, offsetB = 1;
	for (; i<48; i+=2){
		if (BitStream[i+1]==BitStream[i+2]) offsetA=0; 
		if (BitStream[i+2]==BitStream[i+3]) offsetB=0;					
	}
	if (!offsetA && offsetB) offset++;
	for (i=offset; i<*size-3; i+=2){
		//check for phase error
		if (BitStream[i+1]==BitStream[i+2]) {
			BitStream[bitnum++]=7;
			errCnt++;
		}
		if((BitStream[i]==1 && BitStream[i+1]==0) || (BitStream[i]==0 && BitStream[i+1]==1)){
			BitStream[bitnum++]=1^invert;
		} else if((BitStream[i]==0 && BitStream[i+1]==0) || (BitStream[i]==1 && BitStream[i+1]==1)){
			BitStream[bitnum++]=invert;
		} else {
			BitStream[bitnum++]=7;
			errCnt++;
		}
		if(bitnum>MaxBits) break;
	}
	*size=bitnum;
	return errCnt;
}

// by marshmellow
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
	return -5; //spacer bits not found - not a valid gproxII
}

//translate wave to 11111100000 (1 for each short wave [higher freq] 0 for each long wave [lower freq])
size_t fsk_wave_demod(uint8_t * dest, size_t size, uint8_t fchigh, uint8_t fclow)
{
	size_t last_transition = 0;
	size_t idx = 1;
	//uint32_t maxVal=0;
	if (fchigh==0) fchigh=10;
	if (fclow==0) fclow=8;
	//set the threshold close to 0 (graph) or 128 std to avoid static
	uint8_t threshold_value = 123; 
	size_t preLastSample = 0;
	size_t LastSample = 0;
	size_t currSample = 0;
	// sync to first lo-hi transition, and threshold

	// Need to threshold first sample
	// skip 160 samples to allow antenna/samples to settle
	if(dest[160] < threshold_value) dest[0] = 0;
	else dest[0] = 1;

	size_t numBits = 0;
	// count cycles between consecutive lo-hi transitions, there should be either 8 (fc/8)
	// or 10 (fc/10) cycles but in practice due to noise etc we may end up with anywhere
	// between 7 to 11 cycles so fuzz it by treat anything <9 as 8 and anything else as 10
	//  (could also be fc/5 && fc/7 for fsk1 = 4-9)
	for(idx = 161; idx < size-20; idx++) {
		// threshold current value

		if (dest[idx] < threshold_value) dest[idx] = 0;
		else dest[idx] = 1;

		// Check for 0->1 transition
		if (dest[idx-1] < dest[idx]) {
			preLastSample = LastSample;
			LastSample = currSample;
			currSample = idx-last_transition;
			if (currSample < (fclow-2)){            //0-5 = garbage noise (or 0-3)
				//do nothing with extra garbage
			} else if (currSample < (fchigh-1)) {           //6-8 = 8 sample waves  (or 3-6 = 5)
				//correct previous 9 wave surrounded by 8 waves (or 6 surrounded by 5)
				if (LastSample > (fchigh-2) && (preLastSample < (fchigh-1) || preLastSample	== 0 )){
					dest[numBits-1]=1;
				}
				dest[numBits++]=1;

			} else if (currSample > (fchigh) && !numBits) { //12 + and first bit = unusable garbage 
				//do nothing with beginning garbage
			} else if (currSample == (fclow+1) && LastSample == (fclow-1)) { // had a 7 then a 9 should be two 8's (or 4 then a 6 should be two 5's)
				dest[numBits++]=1;
			} else {                                        //9+ = 10 sample waves (or 6+ = 7)
				dest[numBits++]=0;
			}
			last_transition = idx;
		}
	}
	return numBits; //Actually, it returns the number of bytes, but each byte represents a bit: 1 or 0
}

//translate 11111100000 to 10
//rfLen = clock, fchigh = larger field clock, fclow = smaller field clock
size_t aggregate_bits(uint8_t *dest, size_t size, uint8_t rfLen,
		uint8_t invert, uint8_t fchigh, uint8_t fclow)
{
	uint8_t lastval=dest[0];
	size_t idx=0;
	size_t numBits=0;
	uint32_t n=1;
	for( idx=1; idx < size; idx++) {
		n++;
		if (dest[idx]==lastval) continue; 
		
		//find out how many bits (n) we collected
		//if lastval was 1, we have a 1->0 crossing
		if (dest[idx-1]==1) {
			n = (n * fclow + rfLen/2) / rfLen;
		} else {// 0->1 crossing 
			n = (n * fchigh + rfLen/2) / rfLen; 
		}
		if (n == 0) n = 1;

		//add to our destination the bits we collected		
		memset(dest+numBits, dest[idx-1]^invert , n);
		numBits += n;
		n=0;
		lastval=dest[idx];
	}//end for
	// if valid extra bits at the end were all the same frequency - add them in
	if (n > rfLen/fchigh) {
		if (dest[idx-2]==1) {
			n = (n * fclow + rfLen/2) / rfLen;
		} else {
			n = (n * fchigh + rfLen/2) / rfLen;
		}
		memset(dest+numBits, dest[idx-1]^invert , n);
		numBits += n;
	}
	return numBits;
}

//by marshmellow  (from holiman's base)
// full fsk demod from GraphBuffer wave to decoded 1s and 0s (no mandemod)
int fskdemod(uint8_t *dest, size_t size, uint8_t rfLen, uint8_t invert, uint8_t fchigh, uint8_t fclow)
{
	// FSK demodulator
	size = fsk_wave_demod(dest, size, fchigh, fclow);
	size = aggregate_bits(dest, size, rfLen, invert, fchigh, fclow);
	return size;
}

// loop to get raw HID waveform then FSK demodulate the TAG ID from it
int HIDdemodFSK(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo)
{
	if (justNoise(dest, *size)) return -1;

	size_t numStart=0, size2=*size, startIdx=0; 
	// FSK demodulator
	*size = fskdemod(dest, size2,50,1,10,8); //fsk2a
	if (*size < 96*2) return -2;
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
// find viking preamble 0xF200 in already demoded data
int VikingDemod_AM(uint8_t *dest, size_t *size) {
	//make sure buffer has data
	if (*size < 64*2) return -2;

	size_t startIdx = 0;
	uint8_t preamble[] = {1,1,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8_t errChk = preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx);
	if (errChk == 0) return -4; //preamble not found
	uint32_t checkCalc = bytebits_to_byte(dest+startIdx,8) ^ 
						 bytebits_to_byte(dest+startIdx+8,8) ^ 
						 bytebits_to_byte(dest+startIdx+16,8) ^ 
						 bytebits_to_byte(dest+startIdx+24,8) ^ 
						 bytebits_to_byte(dest+startIdx+32,8) ^ 
						 bytebits_to_byte(dest+startIdx+40,8) ^ 
						 bytebits_to_byte(dest+startIdx+48,8) ^ 
						 bytebits_to_byte(dest+startIdx+56,8);
	if ( checkCalc != 0xA8 ) return -5;	
	if (*size != 64) return -6;
	//return start position
	return (int) startIdx;
}

// find presco preamble 0x10D in already demoded data
int PrescoDemod(uint8_t *dest, size_t *size) {
	//make sure buffer has data
	if (*size < 64*2) return -2;

	size_t startIdx = 0;
	uint8_t preamble[] = {1,0,0,0,0,1,1,0,1,0,0,0,0,0,0,0,0,0,0,0};
	uint8_t errChk = preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx);
	if (errChk == 0) return -4; //preamble not found
	//return start position
	return (int) startIdx;
}

// Ask/Biphase Demod then try to locate an ISO 11784/85 ID
// BitStream must contain previously askrawdemod and biphasedemoded data
int FDXBdemodBI(uint8_t *dest, size_t *size)
{
	//make sure buffer has enough data
	if (*size < 128) return -1;

	size_t startIdx = 0;
	uint8_t preamble[] = {0,0,0,0,0,0,0,0,0,0,1};

	uint8_t errChk = preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx);
	if (errChk == 0) return -2; //preamble not found
	return (int)startIdx;
}

// ASK/Diphase fc/64 (inverted Biphase)
// Note: this i s not a demod, this is only a detection
// the parameter *dest needs to be demoded before call
int JablotronDemod(uint8_t *dest, size_t *size){
	//make sure buffer has enough data
	if (*size < 64) return -1;

	size_t startIdx = 0;
	// 0xFFFF preamble, 64bits
	uint8_t preamble[] = {
		        1,1,1,1,
	            1,1,1,1,
				1,1,1,1,
				1,1,1,1,
				0
		};

	uint8_t errChk = preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx);
	if (errChk == 0) return -4; //preamble not found
	if (*size != 64) return -3;
	
	uint8_t checkchksum = 0;
	for (int i=16; i < 56; i += 8) {
		checkchksum += bytebits_to_byte(dest+startIdx+i,8);
	}
	checkchksum ^= 0x3A;

	uint8_t crc = bytebits_to_byte(dest+startIdx+56, 8);
	
	if ( checkchksum != crc ) return -5;	
	return (int)startIdx;
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
// FSK Demod then try to locate a Farpointe Data (pyramid) ID
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

// find nedap preamble in already demoded data
int NedapDemod(uint8_t *dest, size_t *size) {
	//make sure buffer has data
	if (*size < 128) return -3;

	size_t startIdx = 0;
	//uint8_t preamble[] = {1,1,1,1,1,1,1,1,1,0,0,0,1};
	uint8_t preamble[] = {1,1,1,1,1,1,1,1,1,0};
	uint8_t errChk = preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx);
	if (errChk == 0) return -4; //preamble not found
	return (int) startIdx;
}

// by marshmellow
// to detect a wave that has heavily clipped (clean) samples
uint8_t DetectCleanAskWave(uint8_t dest[], size_t size, uint8_t high, uint8_t low)
{
	bool allArePeaks = true;
	uint16_t cntPeaks=0;
	size_t loopEnd = 512+160;
	if (loopEnd > size) loopEnd = size;
	for (size_t i=160; i<loopEnd; i++){
		if (dest[i]>low && dest[i]<high) 
			allArePeaks = false;
		else
			cntPeaks++;
	}
	if (!allArePeaks){
		if (cntPeaks > 300) return true;
	}
	return allArePeaks;
}
// by marshmellow
// to help detect clocks on heavily clipped samples
// based on count of low to low
int DetectStrongAskClock(uint8_t dest[], size_t size, uint8_t high, uint8_t low)
{
	uint8_t fndClk[] = {8,16,32,40,50,64,128};
	size_t startwave;
	size_t i = 100;
	size_t minClk = 255;
		// get to first full low to prime loop and skip incomplete first pulse
	while ((dest[i] < high) && (i < size))
		++i;
	while ((dest[i] > low) && (i < size))
		++i;

	// loop through all samples
	while (i < size) {
		// measure from low to low
		while ((dest[i] > low) && (i < size))
			++i;
		startwave= i;
		while ((dest[i] < high) && (i < size))
			++i;
		while ((dest[i] > low) && (i < size))
			++i;
		//get minimum measured distance
		if (i-startwave < minClk && i < size)
			minClk = i - startwave;
	}
	// set clock
	if (g_debugMode==2) prnt("DEBUG ASK: detectstrongASKclk smallest wave: %d",minClk);
	for (uint8_t clkCnt = 0; clkCnt<7; clkCnt++) {
		if (minClk >= fndClk[clkCnt]-(fndClk[clkCnt]/8) && minClk <= fndClk[clkCnt]+1)
			return fndClk[clkCnt];
	}
	return 0;
}

// by marshmellow
// not perfect especially with lower clocks or VERY good antennas (heavy wave clipping)
// maybe somehow adjust peak trimming value based on samples to fix?
// return start index of best starting position for that clock and return clock (by reference)
int DetectASKClock(uint8_t dest[], size_t size, int *clock, int maxErr)
{
	size_t i=1;
	uint8_t clk[] = {255,8,16,32,40,50,64,100,128,255};
	uint8_t clkEnd = 9;
	uint8_t loopCnt = 255;  //don't need to loop through entire array...
	if (size <= loopCnt+60) return -1; //not enough samples
	size -= 60; //sometimes there is a strange end wave - filter out this....
	//if we already have a valid clock
	uint8_t clockFnd=0;
	for (;i<clkEnd;++i)
		if (clk[i] == *clock) clockFnd = i;
		//clock found but continue to find best startpos

	//get high and low peak
	int peak, low;
	if (getHiLo(dest, loopCnt, &peak, &low, 75, 75) < 1) return -1;
	
	//test for large clean peaks
	if (!clockFnd){
		if (DetectCleanAskWave(dest, size, peak, low)==1){
			int ans = DetectStrongAskClock(dest, size, peak, low);
			if (g_debugMode==2) prnt("DEBUG ASK: detectaskclk Clean Ask Wave Detected: clk %d",ans);
			for (i=clkEnd-1; i>0; i--){
				if (clk[i] == ans) {
					*clock = ans;
					//clockFnd = i;
					return 0;  // for strong waves i don't use the 'best start position' yet...
					//break; //clock found but continue to find best startpos [not yet]
				}
			}
		}
	}
	uint8_t ii;
	uint8_t clkCnt, tol = 0;
	uint16_t bestErr[]={1000,1000,1000,1000,1000,1000,1000,1000,1000};
	uint8_t bestStart[]={0,0,0,0,0,0,0,0,0};
	size_t errCnt = 0;
	size_t arrLoc, loopEnd;

	if (clockFnd>0) {
		clkCnt = clockFnd;
		clkEnd = clockFnd+1;
	}
	else clkCnt=1;

	//test each valid clock from smallest to greatest to see which lines up
	for(; clkCnt < clkEnd; clkCnt++){
		if (clk[clkCnt] <= 32){
			tol=1;
		}else{
			tol=0;
		}
		//if no errors allowed - keep start within the first clock
		if (!maxErr && size > clk[clkCnt]*2 + tol && clk[clkCnt]<128) loopCnt=clk[clkCnt]*2;
		bestErr[clkCnt]=1000;
		//try lining up the peaks by moving starting point (try first few clocks)
		for (ii=0; ii < loopCnt; ii++){
			if (dest[ii] < peak && dest[ii] > low) continue;

			errCnt=0;
			// now that we have the first one lined up test rest of wave array
			loopEnd = ((size-ii-tol) / clk[clkCnt]) - 1;
			for (i=0; i < loopEnd; ++i){
				arrLoc = ii + (i * clk[clkCnt]);
				if (dest[arrLoc] >= peak || dest[arrLoc] <= low){
				}else if (dest[arrLoc-tol] >= peak || dest[arrLoc-tol] <= low){
				}else if (dest[arrLoc+tol] >= peak || dest[arrLoc+tol] <= low){
				}else{  //error no peak detected
					errCnt++;
				}
			}
			//if we found no errors then we can stop here and a low clock (common clocks)
			//  this is correct one - return this clock
			if (g_debugMode == 2) prnt("DEBUG ASK: clk %d, err %d, startpos %d, endpos %d",clk[clkCnt],errCnt,ii,i);
			if(errCnt==0 && clkCnt<7) { 
				if (!clockFnd) *clock = clk[clkCnt];
				return ii;
			}
			//if we found errors see if it is lowest so far and save it as best run
			if(errCnt<bestErr[clkCnt]){
				bestErr[clkCnt]=errCnt;
				bestStart[clkCnt]=ii;
			}
		}
	}
	uint8_t iii;
	uint8_t best=0;
	for (iii=1; iii<clkEnd; ++iii){
		if (bestErr[iii] < bestErr[best]){
			if (bestErr[iii] == 0) bestErr[iii]=1;
			// current best bit to error ratio     vs  new bit to error ratio
			if ( (size/clk[best])/bestErr[best] < (size/clk[iii])/bestErr[iii] ){
				best = iii;
			}
		}
		if (g_debugMode == 2) prnt("DEBUG ASK: clk %d, # Errors %d, Current Best Clk %d, bestStart %d",clk[iii],bestErr[iii],clk[best],bestStart[best]);
	}
	if (!clockFnd) *clock = clk[best];
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
	if (size<loopCnt) loopCnt = size-20;

	//if we already have a valid clock quit
	size_t i=1;
	for (; i < 8; ++i)
		if (clk[i] == clock) return clock;

	size_t waveStart=0, waveEnd=0, firstFullWave=0, lastClkBit=0;
	uint8_t clkCnt, fc=0, fullWaveLen=0, tol=1;
	uint16_t peakcnt=0, errCnt=0, waveLenCnt=0;
	uint16_t bestErr[]={1000,1000,1000,1000,1000,1000,1000,1000,1000};
	uint16_t peaksdet[]={0,0,0,0,0,0,0,0,0};
	fc = countFC(dest, size, 0);
	if (fc!=2 && fc!=4 && fc!=8) return -1;
	if (g_debugMode==2) prnt("DEBUG PSK: FC: %d",fc);

	//find first full wave
	for (i=160; i<loopCnt; i++){
		if (dest[i] < dest[i+1] && dest[i+1] >= dest[i+2]){
			if (waveStart == 0) {
				waveStart = i+1;
				//prnt("DEBUG: waveStart: %d",waveStart);
			} else {
				waveEnd = i+1;
				//prnt("DEBUG: waveEnd: %d",waveEnd);
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
	if (g_debugMode ==2) prnt("DEBUG PSK: firstFullWave: %d, waveLen: %d",firstFullWave,fullWaveLen);
	
	//test each valid clock from greatest to smallest to see which lines up
	for(clkCnt=7; clkCnt >= 1 ; clkCnt--){
		lastClkBit = firstFullWave; //set end of wave as clock align
		waveStart = 0;
		errCnt=0;
		peakcnt=0;
		if (g_debugMode == 2) prnt("DEBUG PSK: clk: %d, lastClkBit: %d",clk[clkCnt],lastClkBit);

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
						if (g_debugMode == 2) prnt("DEBUG PSK: phase shift at: %d, len: %d, nextClk: %d, i: %d, fc: %d",waveStart,waveLenCnt,lastClkBit+clk[clkCnt]-tol,i+1,fc);
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
		if (g_debugMode == 2) prnt("DEBUG PSK: Clk: %d, peaks: %d, errs: %d, bestClk: %d",clk[i],peaksdet[i],bestErr[i],clk[best]);
	}
	return clk[best];
}

int DetectStrongNRZClk(uint8_t *dest, size_t size, int peak, int low){
	//find shortest transition from high to low
	size_t i = 0;
	size_t transition1 = 0;
	int lowestTransition = 255;
	bool lastWasHigh = false;

	//find first valid beginning of a high or low wave
	while ((dest[i] >= peak || dest[i] <= low) && (i < size))
		++i;
	while ((dest[i] < peak && dest[i] > low) && (i < size))
		++i;
	lastWasHigh = (dest[i] >= peak);

	if (i==size) return 0;
	transition1 = i;

	for (;i < size; i++) {
		if ((dest[i] >= peak && !lastWasHigh) || (dest[i] <= low && lastWasHigh)) {
			lastWasHigh = (dest[i] >= peak);
			if (i-transition1 < lowestTransition) lowestTransition = i-transition1;
			transition1 = i;
		}
	}
	if (lowestTransition == 255) lowestTransition = 0;
	if (g_debugMode==2) prnt("DEBUG NRZ: detectstrongNRZclk smallest wave: %d",lowestTransition);
	return lowestTransition;
}

//by marshmellow
//detect nrz clock by reading #peaks vs no peaks(or errors)
int DetectNRZClock(uint8_t dest[], size_t size, int clock)
{
	size_t i=0;
	uint8_t clk[]={8,16,32,40,50,64,100,128,255};
	size_t loopCnt = 4096;  //don't need to loop through entire array...
	if (size == 0) return 0;
	if (size<loopCnt) loopCnt = size-20;
	//if we already have a valid clock quit
	for (; i < 8; ++i)
		if (clk[i] == clock) return clock;

	//get high and low peak
	int peak, low;
	if (getHiLo(dest, loopCnt, &peak, &low, 75, 75) < 1) return 0;

	int lowestTransition = DetectStrongNRZClk(dest, size-20, peak, low);
	size_t ii;
	uint8_t clkCnt;
	uint8_t tol = 0;
	uint16_t smplCnt = 0;
	int16_t peakcnt = 0;
	int16_t peaksdet[] = {0,0,0,0,0,0,0,0};
	uint16_t maxPeak = 255;
	bool firstpeak = false;
	//test for large clipped waves
	for (i=0; i<loopCnt; i++){
		if (dest[i] >= peak || dest[i] <= low){
			if (!firstpeak) continue;
			smplCnt++;
		} else {
			firstpeak=true;
			if (smplCnt > 6 ){
				if (maxPeak > smplCnt){
					maxPeak = smplCnt;
					//prnt("maxPk: %d",maxPeak);
				}
				peakcnt++;
				//prnt("maxPk: %d, smplCnt: %d, peakcnt: %d",maxPeak,smplCnt,peakcnt);
				smplCnt=0;
			}
		}
	}
	bool errBitHigh = 0;
	bool bitHigh = 0;
	uint8_t ignoreCnt = 0;
	uint8_t ignoreWindow = 4;
	bool lastPeakHigh = 0;
	int lastBit = 0; 
	peakcnt=0;
	//test each valid clock from smallest to greatest to see which lines up
	for(clkCnt=0; clkCnt < 8; ++clkCnt){
		//ignore clocks smaller than smallest peak
		if (clk[clkCnt] < maxPeak - (clk[clkCnt]/4)) continue;
		//try lining up the peaks by moving starting point (try first 256)
		for (ii=20; ii < loopCnt; ++ii){
			if ((dest[ii] >= peak) || (dest[ii] <= low)){
				peakcnt=0;
				bitHigh = false;
				ignoreCnt = 0;
				lastBit = ii-clk[clkCnt]; 
				//loop through to see if this start location works
				for (i = ii; i < size-20; ++i) {
					//if we are at a clock bit
					if ((i >= lastBit + clk[clkCnt] - tol) && (i <= lastBit + clk[clkCnt] + tol)) {
						//test high/low
						if (dest[i] >= peak || dest[i] <= low) {
							//if same peak don't count it
							if ((dest[i] >= peak && !lastPeakHigh) || (dest[i] <= low && lastPeakHigh)) {
						peakcnt++;
							}
							lastPeakHigh = (dest[i] >= peak);
							bitHigh = true;
							errBitHigh = false;
							ignoreCnt = ignoreWindow;
							lastBit += clk[clkCnt];
						} else if (i == lastBit + clk[clkCnt] + tol) {
							lastBit += clk[clkCnt];
						}
					//else if not a clock bit and no peaks
					} else if (dest[i] < peak && dest[i] > low){
						if (ignoreCnt==0){
							bitHigh=false;
							if (errBitHigh==true) peakcnt--;
							errBitHigh=false;
						} else {
							ignoreCnt--;
						}
						// else if not a clock bit but we have a peak
					} else if ((dest[i]>=peak || dest[i]<=low) && (!bitHigh)) {
						//error bar found no clock...
						errBitHigh=true;
					}
				}
				if(peakcnt>peaksdet[clkCnt]) {
					peaksdet[clkCnt]=peakcnt;
				}
			}
		}
	}
	int iii=7;
	uint8_t best=0;
	for (iii=7; iii > 0; iii--){
		if ((peaksdet[iii] >= (peaksdet[best]-1)) && (peaksdet[iii] <= peaksdet[best]+1) && lowestTransition) {
			if (clk[iii] > (lowestTransition - (clk[iii]/8)) && clk[iii] < (lowestTransition + (clk[iii]/8))) {
			best = iii;
		}
		} else if (peaksdet[iii] > peaksdet[best]){
			best = iii;
		}
		if (g_debugMode==2) prnt("DEBUG NRZ: Clk: %d, peaks: %d, maxPeak: %d, bestClk: %d, lowestTrs: %d",clk[iii],peaksdet[iii],maxPeak, clk[best], lowestTransition);
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
		if (BitStream[i]==7){
			//ignore errors
		} else if (lastBit!=BitStream[i]){
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
	uint8_t preamble[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
	uint8_t preamble_i[] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0};
	size_t startidx = 0; 
	if (!preambleSearch(bitStream, preamble, sizeof(preamble), size, &startidx)){
		// if didn't find preamble try again inverting
		if (!preambleSearch(bitStream, preamble_i, sizeof(preamble_i), size, &startidx)) return -1;
		*invert ^= 1;
	} 
	if (*size != 64 && *size != 224) return -2;
	if (*invert==1)
		for (size_t i = startidx; i < *size; i++)
			bitStream[i] ^= 1;

	return (int) startidx;
}

// by marshmellow - demodulate NRZ wave - requires a read with strong signal
// peaks invert bit (high=1 low=0) each clock cycle = 1 bit determined by last peak
int nrzRawDemod(uint8_t *dest, size_t *size, int *clk, int *invert){
	if (justNoise(dest, *size)) return -1;
	*clk = DetectNRZClock(dest, *size, *clk);
	if (*clk==0) return -2;
	size_t i, gLen = 4096;
	if (gLen>*size) gLen = *size-20;
	int high, low;
	if (getHiLo(dest, gLen, &high, &low, 75, 75) < 1) return -3; //25% fuzz on high 25% fuzz on low

	uint8_t bit=0;
	//convert wave samples to 1's and 0's
	for(i=20; i < *size-20; i++){
		if (dest[i] >= high) bit = 1;
		if (dest[i] <= low)  bit = 0;
		dest[i] = bit;
	}
	//now demod based on clock (rf/32 = 32 1's for one 1 bit, 32 0's for one 0 bit) 
	size_t lastBit = 0;
	size_t numBits = 0;
	for(i=21; i < *size-20; i++) {
		//if transition detected or large number of same bits - store the passed bits
		if (dest[i] != dest[i-1] || (i-lastBit) == (10 * *clk)) {
			memset(dest+numBits, dest[i-1] ^ *invert, (i - lastBit + (*clk/4)) / *clk);
			numBits += (i - lastBit + (*clk/4)) / *clk;
			lastBit = i-1;
		}
	}
	*size = numBits;
	return 0;
}

//by marshmellow
//detects the bit clock for FSK given the high and low Field Clocks
uint8_t detectFSKClk(uint8_t *BitStream, size_t size, uint8_t fcHigh, uint8_t fcLow)
{
	uint8_t clk[] = {8,16,32,40,50,64,100,128,0};
	uint16_t rfLens[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8_t rfCnts[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8_t rfLensFnd = 0;
	uint8_t lastFCcnt = 0;
	uint16_t fcCounter = 0;
	uint16_t rfCounter = 0;
	uint8_t firstBitFnd = 0;
	size_t i;
	if (size == 0) return 0;

	uint8_t fcTol = ((fcHigh*100 - fcLow*100)/2 + 50)/100; //(uint8_t)(0.5+(float)(fcHigh-fcLow)/2);
	rfLensFnd=0;
	fcCounter=0;
	rfCounter=0;
	firstBitFnd=0;
	//PrintAndLog("DEBUG: fcTol: %d",fcTol);
	// prime i to first peak / up transition
	for (i = 160; i < size-20; i++)
		if (BitStream[i] > BitStream[i-1] && BitStream[i]>=BitStream[i+1])
			break;

	for (; i < size-20; i++){
		fcCounter++;
		rfCounter++;

		if (BitStream[i] <= BitStream[i-1] || BitStream[i] < BitStream[i+1]) 
			continue;		
		// else new peak 
		// if we got less than the small fc + tolerance then set it to the small fc
		if (fcCounter < fcLow+fcTol) 
			fcCounter = fcLow;
		else //set it to the large fc
			fcCounter = fcHigh;

		//look for bit clock  (rf/xx)
		if ((fcCounter < lastFCcnt || fcCounter > lastFCcnt)){
			//not the same size as the last wave - start of new bit sequence
			if (firstBitFnd > 1){ //skip first wave change - probably not a complete bit
				for (int ii=0; ii<15; ii++){
					if (rfLens[ii] >= (rfCounter-4) && rfLens[ii] <= (rfCounter+4)){
						rfCnts[ii]++;
						rfCounter = 0;
						break;
					}
				}
				if (rfCounter > 0 && rfLensFnd < 15){
					//PrintAndLog("DEBUG: rfCntr %d, fcCntr %d",rfCounter,fcCounter);
					rfCnts[rfLensFnd]++;
					rfLens[rfLensFnd++] = rfCounter;
				}
			} else {
				firstBitFnd++;
			}
			rfCounter=0;
			lastFCcnt=fcCounter;
		}
		fcCounter=0;
	}
	uint8_t rfHighest=15, rfHighest2=15, rfHighest3=15;

	for (i=0; i<15; i++){
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
		if (g_debugMode==2) prnt("DEBUG FSK: RF %d, cnts %d",rfLens[i], rfCnts[i]);
	}  
	// set allowed clock remainder tolerance to be 1 large field clock length+1 
	//   we could have mistakenly made a 9 a 10 instead of an 8 or visa versa so rfLens could be 1 FC off  
	uint8_t tol1 = fcHigh+1; 
	
	if (g_debugMode==2) prnt("DEBUG FSK: most counted rf values: 1 %d, 2 %d, 3 %d",rfLens[rfHighest],rfLens[rfHighest2],rfLens[rfHighest3]);

	// loop to find the highest clock that has a remainder less than the tolerance
	//   compare samples counted divided by
	// test 128 down to 32 (shouldn't be possible to have fc/10 & fc/8 and rf/16 or less)
	int ii=7;
	for (; ii>=2; ii--){
		if (rfLens[rfHighest] % clk[ii] < tol1 || rfLens[rfHighest] % clk[ii] > clk[ii]-tol1){
			if (rfLens[rfHighest2] % clk[ii] < tol1 || rfLens[rfHighest2] % clk[ii] > clk[ii]-tol1){
				if (rfLens[rfHighest3] % clk[ii] < tol1 || rfLens[rfHighest3] % clk[ii] > clk[ii]-tol1){
					if (g_debugMode==2) prnt("DEBUG FSK: clk %d divides into the 3 most rf values within tolerance",clk[ii]);
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
uint16_t countFC(uint8_t *BitStream, size_t size, uint8_t fskAdj)
{
	uint8_t fcLens[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint16_t fcCnts[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8_t fcLensFnd = 0;
	uint8_t lastFCcnt=0;
	uint8_t fcCounter = 0;
	size_t i;
	if (size == 0) return 0;

	// prime i to first up transition
	for (i = 160; i < size-20; i++)
		if (BitStream[i] > BitStream[i-1] && BitStream[i] >= BitStream[i+1])
			break;

	for (; i < size-20; i++){
		if (BitStream[i] > BitStream[i-1] && BitStream[i] >= BitStream[i+1]){
			// new up transition
			fcCounter++;
			if (fskAdj){
				//if we had 5 and now have 9 then go back to 8 (for when we get a fc 9 instead of an 8)
				if (lastFCcnt==5 && fcCounter==9) fcCounter--;
				//if fc=9 or 4 add one (for when we get a fc 9 instead of 10 or a 4 instead of a 5)
				if ((fcCounter==9) || fcCounter==4) fcCounter++;
			// save last field clock count  (fc/xx)
			lastFCcnt = fcCounter;
			}
			// find which fcLens to save it to:
			for (int ii=0; ii<15; ii++){
				if (fcLens[ii]==fcCounter){
					fcCnts[ii]++;
					fcCounter=0;
					break;
				}
			}
			if (fcCounter>0 && fcLensFnd<15){
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
	
	uint8_t best1=14, best2=14, best3=14;
	uint16_t maxCnt1=0;
	// go through fclens and find which ones are bigest 2  
	for (i=0; i<15; i++){
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
		if (g_debugMode==2) prnt("DEBUG countfc: FC %u, Cnt %u, best fc: %u, best2 fc: %u",fcLens[i],fcCnts[i],fcLens[best1],fcLens[best2]);
	}
	if (fcLens[best1]==0) return 0;
	uint8_t fcH=0, fcL=0;
	if (fcLens[best1]>fcLens[best2]){
		fcH=fcLens[best1];
		fcL=fcLens[best2];
	} else{
		fcH=fcLens[best2];
		fcL=fcLens[best1];
	}
	if ((size-180)/fcH/3 > fcCnts[best1]+fcCnts[best2]) {
		if (g_debugMode==2) prnt("DEBUG countfc: fc is too large: %u > %u. Not psk or fsk",(size-180)/fcH/3,fcCnts[best1]+fcCnts[best2]);
		return 0; //lots of waves not psk or fsk
	}
	// TODO: take top 3 answers and compare to known Field clocks to get top 2

	uint16_t fcs = (((uint16_t)fcH)<<8) | fcL;
	if (fskAdj) return fcs;	
	return fcLens[best1];
}

//by marshmellow - demodulate PSK1 wave 
//uses wave lengths (# Samples) 
int pskRawDemod(uint8_t dest[], size_t *size, int *clock, int *invert)
{
	if (size == 0) return -1;
	uint16_t loopCnt = 4096;  //don't need to loop through entire array...
	if (*size<loopCnt) loopCnt = *size;

	size_t numBits=0;
	uint8_t curPhase = *invert;
	size_t i, waveStart=1, waveEnd=0, firstFullWave=0, lastClkBit=0;
	uint8_t fc=0, fullWaveLen=0, tol=1;
	uint16_t errCnt=0, waveLenCnt=0;
	fc = countFC(dest, *size, 0);
	if (fc!=2 && fc!=4 && fc!=8) return -1;
	//PrintAndLog("DEBUG: FC: %d",fc);
	*clock = DetectPSKClock(dest, *size, *clock);
	if (*clock == 0) return -1;
	int avgWaveVal=0, lastAvgWaveVal=0;
	//find first phase shift
	for (i=0; i<loopCnt; i++){
		if (dest[i]+fc < dest[i+1] && dest[i+1] >= dest[i+2]){
			waveEnd = i+1;
			//PrintAndLog("DEBUG: waveEnd: %d",waveEnd);
			waveLenCnt = waveEnd-waveStart;
			if (waveLenCnt > fc && waveStart > fc && !(waveLenCnt > fc+2)){ //not first peak and is a large wave but not out of whack
				lastAvgWaveVal = avgWaveVal/(waveLenCnt);
				firstFullWave = waveStart;
				fullWaveLen=waveLenCnt;
				//if average wave value is > graph 0 then it is an up wave or a 1
				if (lastAvgWaveVal > 123) curPhase ^= 1;  //fudge graph 0 a little 123 vs 128
				break;
			} 
			waveStart = i+1;
			avgWaveVal = 0;
		}
		avgWaveVal += dest[i+2];
	}
	if (firstFullWave == 0) {
		// no phase shift detected - could be all 1's or 0's - doesn't matter where we start
		// so skip a little to ensure we are past any Start Signal
		firstFullWave = 160;
		memset(dest, curPhase, firstFullWave / *clock);
	} else {
		memset(dest, curPhase^1, firstFullWave / *clock);
	}
	//advance bits
	numBits += (firstFullWave / *clock);
	//set start of wave as clock align
	lastClkBit = firstFullWave;
	if (g_debugMode==2) prnt("DEBUG PSK: firstFullWave: %u, waveLen: %u",firstFullWave,fullWaveLen);  
	if (g_debugMode==2) prnt("DEBUG: clk: %d, lastClkBit: %u, fc: %u", *clock, lastClkBit,(unsigned int) fc);
	waveStart = 0;
	dest[numBits++] = curPhase; //set first read bit
	for (i = firstFullWave + fullWaveLen - 1; i < *size-3; i++){
		//top edge of wave = start of new wave 
		if (dest[i]+fc < dest[i+1] && dest[i+1] >= dest[i+2]){
			if (waveStart == 0) {
				waveStart = i+1;
				waveLenCnt = 0;
				avgWaveVal = dest[i+1];
			} else { //waveEnd
				waveEnd = i+1;
				waveLenCnt = waveEnd-waveStart;
				lastAvgWaveVal = avgWaveVal/waveLenCnt;
				if (waveLenCnt > fc){  
					//PrintAndLog("DEBUG: avgWaveVal: %d, waveSum: %d",lastAvgWaveVal,avgWaveVal);
					//this wave is a phase shift
					//PrintAndLog("DEBUG: phase shift at: %d, len: %d, nextClk: %d, i: %d, fc: %d",waveStart,waveLenCnt,lastClkBit+*clock-tol,i+1,fc);
					if (i+1 >= lastClkBit + *clock - tol){ //should be a clock bit
						curPhase ^= 1;
						dest[numBits++] = curPhase;
						lastClkBit += *clock;
					} else if (i < lastClkBit+10+fc){
						//noise after a phase shift - ignore
					} else { //phase shift before supposed to based on clock
						errCnt++;
						dest[numBits++] = 7;
					}
				} else if (i+1 > lastClkBit + *clock + tol + fc){
					lastClkBit += *clock; //no phase shift but clock bit
					dest[numBits++] = curPhase;
				}
				avgWaveVal = 0;
				waveStart = i+1;
			}
		}
		avgWaveVal += dest[i+1];
	}
	*size = numBits;
	return errCnt;
}

//by marshmellow
//attempt to identify a Sequence Terminator in ASK modulated raw wave
bool DetectST(uint8_t buffer[], size_t *size, int *foundclock) {
	size_t bufsize = *size;
	//need to loop through all samples and identify our clock, look for the ST pattern
	uint8_t fndClk[] = {8,16,32,40,50,64,128};
	int clk = 0; 
	int tol = 0;
	int i, j, skip, start, end, low, high, minClk, waveStart;
	bool complete = false;
	int tmpbuff[bufsize / 64];
	int waveLen[bufsize / 64];
	size_t testsize = (bufsize < 512) ? bufsize : 512;
	int phaseoff = 0;
	high = low = 128;
	memset(tmpbuff, 0, sizeof(tmpbuff));

	if ( getHiLo(buffer, testsize, &high, &low, 80, 80) == -1 ) {
		if (g_debugMode==2) prnt("DEBUG STT: just noise detected - quitting");
		return false; //just noise
	}
	i = 0;
	j = 0;
	minClk = 255;
	// get to first full low to prime loop and skip incomplete first pulse
	while ((buffer[i] < high) && (i < bufsize))
		++i;
	while ((buffer[i] > low) && (i < bufsize))
		++i;
	skip = i;

	// populate tmpbuff buffer with pulse lengths
	while (i < bufsize) {
		// measure from low to low
		while ((buffer[i] > low) && (i < bufsize))
			++i;
		start= i;
		while ((buffer[i] < high) && (i < bufsize))
			++i;
		//first high point for this wave
		waveStart = i;
		while ((buffer[i] > low) && (i < bufsize))
			++i;
		if (j >= (bufsize/64)) {
			break;
		}
		waveLen[j] = i - waveStart; //first high to first low
		tmpbuff[j++] = i - start;
		if (i-start < minClk && i < bufsize) {
			minClk = i - start;
		}
	}
	// set clock  - might be able to get this externally and remove this work...
	if (!clk) {
		for (uint8_t clkCnt = 0; clkCnt<7; clkCnt++) {
			tol = fndClk[clkCnt]/8;
			if (minClk >= fndClk[clkCnt]-tol && minClk <= fndClk[clkCnt]+1) { 
				clk=fndClk[clkCnt];
				break;
			}
		}
		// clock not found - ERROR
		if (!clk) {
			if (g_debugMode==2) prnt("DEBUG STT: clock not found - quitting");
			return false;
		}
	} else tol = clk/8;

	*foundclock = clk;

	// look for Sequence Terminator - should be pulses of clk*(1 or 1.5), clk*2, clk*(1.5 or 2)
	start = -1;
	for (i = 0; i < j - 4; ++i) {
		skip += tmpbuff[i];
		if (tmpbuff[i] >= clk*1-tol && tmpbuff[i] <= (clk*2)+tol && waveLen[i] < clk+tol) {           //1 to 2 clocks depending on 2 bits prior
			if (tmpbuff[i+1] >= clk*2-tol && tmpbuff[i+1] <= clk*2+tol && waveLen[i+1] > clk*3/2-tol) {       //2 clocks and wave size is 1 1/2
				if (tmpbuff[i+2] >= (clk*3)/2-tol && tmpbuff[i+2] <= clk*2+tol && waveLen[i+2] > clk-tol) { //1 1/2 to 2 clocks and at least one full clock wave
					if (tmpbuff[i+3] >= clk*1-tol && tmpbuff[i+3] <= clk*2+tol) { //1 to 2 clocks for end of ST + first bit
						start = i + 3;
						break;
					}
				}
			}
		}
	}
	// first ST not found - ERROR
	if (start < 0) {
		if (g_debugMode==2) prnt("DEBUG STT: first STT not found - quitting");
		return false;
	}
	if (waveLen[i+2] > clk*1+tol)
		phaseoff = 0;
	else
		phaseoff = clk/2;
	
	// skip over the remainder of ST
	skip += clk*7/2; //3.5 clocks from tmpbuff[i] = end of st - also aligns for ending point

	// now do it again to find the end
	end = skip;
	for (i += 3; i < j - 4; ++i) {
		end += tmpbuff[i];
		if (tmpbuff[i] >= clk*1-tol && tmpbuff[i] <= (clk*2)+tol) {           //1 to 2 clocks depending on 2 bits prior
			if (tmpbuff[i+1] >= clk*2-tol && tmpbuff[i+1] <= clk*2+tol && waveLen[i+1] > clk*3/2-tol) {       //2 clocks and wave size is 1 1/2
				if (tmpbuff[i+2] >= (clk*3)/2-tol && tmpbuff[i+2] <= clk*2+tol && waveLen[i+2] > clk-tol) { //1 1/2 to 2 clocks and at least one full clock wave
					if (tmpbuff[i+3] >= clk*1-tol && tmpbuff[i+3] <= clk*2+tol) { //1 to 2 clocks for end of ST + first bit
						complete = true;
						break;
					}
				}
			}
		}
	}
	end -= phaseoff;
	//didn't find second ST - ERROR
	if (!complete) {
		if (g_debugMode==2) prnt("DEBUG STT: second STT not found - quitting");
		return false;
	}
	if (g_debugMode==2) prnt("DEBUG STT: start of data: %d end of data: %d, datalen: %d, clk: %d, bits: %d, phaseoff: %d", skip, end, end-skip, clk, (end-skip)/clk, phaseoff);
	//now begin to trim out ST so we can use normal demod cmds
	start = skip;
	size_t datalen = end - start;
	// check validity of datalen (should be even clock increments)  - use a tolerance of up to 1/8th a clock
	if (datalen % clk > clk/8) {
		if (g_debugMode==2) prnt("DEBUG STT: datalen not divisible by clk: %u %% %d = %d - quitting", datalen, clk, datalen % clk);
		return false;
	} else {
		// padd the amount off - could be problematic...  but shouldn't happen often
		datalen += datalen % clk;
	}
	// if datalen is less than one t55xx block - ERROR
	if (datalen/clk < 8*4) {
		if (g_debugMode==2) prnt("DEBUG STT: datalen is less than 1 full t55xx block - quitting");		
		return false;
	}
	size_t dataloc = start;
	size_t newloc = 0;
	i=0;
	// warning - overwriting buffer given with raw wave data with ST removed...
	while ( dataloc < bufsize-(clk/2) ) {
		//compensate for long high at end of ST not being high due to signal loss... (and we cut out the start of wave high part)
		if (buffer[dataloc]<high && buffer[dataloc]>low && buffer[dataloc+3]<high && buffer[dataloc+3]>low) {
			for(i=0; i < clk/2-tol; ++i) {
				buffer[dataloc+i] = high+5;
			}
		}
		for (i=0; i<datalen; ++i) {
			if (i+newloc < bufsize) {
				if (i+newloc < dataloc)
					buffer[i+newloc] = buffer[dataloc];

				dataloc++;				
			}
		}
		newloc += i;
		//skip next ST  -  we just assume it will be there from now on...
		dataloc += clk*4;
	}
	*size = newloc;
	return true;
}
