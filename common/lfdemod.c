//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Low frequency demod/decode commands
//
// NOTES:
// LF Demod functions are placed here to allow the flexibility to use client or
// device side. Most BUT NOT ALL of these functions are currenlty safe for
// device side use currently. (DetectST for example...)
//
// There are likely many improvements to the code that could be made, please
// make suggestions...
//
// we tried to include author comments so any questions could be directed to
// the source.
//
// There are 4 main sections of code below:
//
// Utilities Section:
//    for general utilities used by multiple other functions
//
// Clock / Bitrate Detection Section:
//    for clock detection functions for each modulation
//
// Modulation Demods &/or Decoding Section:
//    for main general modulation demodulating and encoding decoding code.
//
// Tag format detection section:
//    for detection of specific tag formats within demodulated data
//
// marshmellow
//-----------------------------------------------------------------------------

#include "lfdemod.h"
#include <string.h>  // for memset, memcmp and size_t
#include <stdlib.h>  // qsort
#include "parity.h"  // for parity test
#include "pm3_cmd.h" // error codes
#include "commonutil.h"  // Arraylen

// **********************************************************************************************
// ---------------------------------Utilities Section--------------------------------------------
// **********************************************************************************************
#define LOWEST_DEFAULT_CLOCK 32
#define FSK_PSK_THRESHOLD   123

//to allow debug print calls when used not on dev

#ifndef ON_DEVICE
#include "ui.h"
#include "util.h"
# include "cmddata.h"
# define prnt(args...) PrintAndLogEx(DEBUG, ## args );
#else
# include "dbprint.h"
uint8_t g_debugMode = 0;
# define prnt Dbprintf
#endif

static signal_t signalprop = { 255, -255, 0, 0, true };
signal_t *getSignalProperties(void) {
    return &signalprop;
}

static void resetSignal(void) {
    signalprop.low = 255;
    signalprop.high = -255;
    signalprop.mean = 0;
    signalprop.amplitude = 0;
    signalprop.isnoise = true;
}

static void printSignal(void) {
    prnt("LF signal properties:");
    prnt("  high..........%d", signalprop.high);
    prnt("  low...........%d", signalprop.low);
    prnt("  mean..........%d", signalprop.mean);
    prnt("  amplitude.....%d", signalprop.amplitude);
    prnt("  is Noise......%s", (signalprop.isnoise) ? _RED_("Yes") : _GREEN_("No"));
    prnt("  THRESHOLD noise amplitude......%d", NOISE_AMPLITUDE_THRESHOLD);
}

#ifndef ON_DEVICE
static int cmp_uint8(const void *a, const void *b) {
    if (*(const uint8_t *)a < * (const uint8_t *)b)
        return -1;
    else
        return *(const uint8_t *)a > *(const uint8_t *)b;
}
#endif

void computeSignalProperties(const uint8_t *samples, uint32_t size) {
    resetSignal();

    if (samples == NULL || size < SIGNAL_MIN_SAMPLES) return;

    uint32_t sum = 0;
    uint32_t offset_size = size - SIGNAL_IGNORE_FIRST_SAMPLES;

#ifndef ON_DEVICE
    uint8_t tmp[offset_size];
    memcpy(tmp, samples + SIGNAL_IGNORE_FIRST_SAMPLES, sizeof(tmp));
    qsort(tmp, sizeof(tmp), sizeof(uint8_t), cmp_uint8);

    uint8_t low10 = 0.5 * (tmp[(int)(offset_size * 0.1)] + tmp[(int)((offset_size - 1) * 0.1)]);
    uint8_t hi90 =  0.5 * (tmp[(int)(offset_size * 0.9)] + tmp[(int)((offset_size - 1) * 0.9)]);
    uint32_t cnt = 0;
    for (uint32_t i = SIGNAL_IGNORE_FIRST_SAMPLES; i < size; i++) {

        if (samples[i] < signalprop.low) signalprop.low = samples[i];
        if (samples[i] > signalprop.high) signalprop.high = samples[i];

        if (samples[i] < low10 || samples[i] > hi90)
            continue;

        sum += samples[i];
        cnt++;
    }
    if (cnt > 0)
        signalprop.mean = sum / cnt;
    else
        signalprop.mean = 0;
#else
    for (uint32_t i =  SIGNAL_IGNORE_FIRST_SAMPLES; i < size; i++) {
        if (samples[i] < signalprop.low) signalprop.low = samples[i];
        if (samples[i] > signalprop.high) signalprop.high = samples[i];
        sum += samples[i];
    }
    signalprop.mean = sum / offset_size;
#endif

    // measure amplitude of signal
    signalprop.amplitude = signalprop.high - signalprop.mean;
    // By measuring mean and look at amplitude of signal from HIGH / LOW,
    // we can detect noise
    signalprop.isnoise =  signalprop.amplitude < NOISE_AMPLITUDE_THRESHOLD;

    if (g_debugMode)
        printSignal();
}

void removeSignalOffset(uint8_t *samples, uint32_t size) {
    if (samples == NULL || size < SIGNAL_MIN_SAMPLES) return;

    int acc_off = 0;
    uint32_t offset_size = size - SIGNAL_IGNORE_FIRST_SAMPLES;

#ifndef ON_DEVICE

    uint8_t tmp[offset_size];
    memcpy(tmp, samples + SIGNAL_IGNORE_FIRST_SAMPLES, sizeof(tmp));
    qsort(tmp, sizeof(tmp), sizeof(uint8_t), cmp_uint8);

    uint8_t low10 = 0.5 * (tmp[(int)(offset_size * 0.05)] + tmp[(int)((offset_size - 1) * 0.05)]);
    uint8_t hi90 =  0.5 * (tmp[(int)(offset_size * 0.95)] + tmp[(int)((offset_size - 1) * 0.95)]);
    int32_t cnt = 0;
    for (uint32_t i = SIGNAL_IGNORE_FIRST_SAMPLES; i < size; i++) {

        if (samples[i] < low10 || samples[i] > hi90)
            continue;

        acc_off += samples[i] - 128;
        cnt++;
    }
    if (cnt > 0)
        acc_off /= cnt;
    else
        acc_off = 0;
#else
    for (uint32_t i = SIGNAL_IGNORE_FIRST_SAMPLES; i < size; i++)
        acc_off += samples[i] - 128;

    acc_off /= (int)offset_size;
#endif

    // shift and saturate samples to center the mean
    for (uint32_t i = 0; i < size; i++) {
        if (acc_off > 0) {
            samples[i] = (samples[i] >= acc_off) ? samples[i] - acc_off : 0;
        }
        if (acc_off < 0) {
            samples[i] = (255 - samples[i] >=  -acc_off) ? samples[i] - acc_off : 255;
        }
    }
}

// get high and low values of a wave with passed in fuzz factor. also return noise test = 1 for passed or 0 for only noise
// void getHiLo(uint8_t *bits, size_t size, int *high, int *low, uint8_t fuzzHi, uint8_t fuzzLo) {
void getHiLo(int *high, int *low, uint8_t fuzzHi, uint8_t fuzzLo) {
    // add fuzz.
    *high = (signalprop.high * fuzzHi) / 100;
    if (signalprop.low < 0) {
        *low = (signalprop.low * fuzzLo) / 100;
    } else {
        uint8_t range = signalprop.high - signalprop.low;

        *low =  signalprop.low + ((range * (100 - fuzzLo)) / 100);
    }

    // if fuzzing to great and overlap
    if (*high <= *low) {
        *high = signalprop.high;
        *low =  signalprop.low;
    }

    // prnt("getHiLo fuzzed: High %d | Low %d", *high, *low);
}

// pass bits to be tested in bits, length bits passed in bitLen, and parity type (even=0 | odd=1) in pType
// returns 1 if passed
bool parityTest(uint32_t bits, uint8_t bitLen, uint8_t pType) {
    return oddparity32(bits) ^ pType;
}

// takes a array of binary values, start position, length of bits per parity (includes parity bit - MAX 32),
//   Parity Type (1 for odd; 0 for even; 2 for Always 1's; 3 for Always 0's), and binary Length (length to run)
size_t removeParity(uint8_t *bits, size_t startIdx, uint8_t pLen, uint8_t pType, size_t bLen) {
    uint32_t parityWd = 0;
    size_t bitCnt = 0;
    for (int word = 0; word < (bLen); word += pLen) {
        for (int bit = 0; bit < pLen; bit++) {
            if (word + bit >= bLen) break;
            parityWd = (parityWd << 1) | bits[startIdx + word + bit];
            bits[bitCnt++] = (bits[startIdx + word + bit]);
        }
        if (word + pLen > bLen) break;

        bitCnt--; // overwrite parity with next data
        // if parity fails then return 0
        switch (pType) {
            case 3:
                if (bits[bitCnt] == 1) {return 0;}
                break; //should be 0 spacer bit
            case 2:
                if (bits[bitCnt] == 0) {return 0;}
                break; //should be 1 spacer bit
            default:
                if (parityTest(parityWd, pLen, pType) == 0) { return 0; }
                break; //test parity
        }
        parityWd = 0;
    }
    // if we got here then all the parities passed
    //return size
    return bitCnt;
}

static size_t removeEm410xParity(uint8_t *bits, size_t startIdx, bool isLong, bool *validShort, bool *validShortExtended, bool *validLong) {
    uint32_t parityWd = 0;
    size_t bitCnt = 0;
    bool validColParity = false;
    bool validRowParity = true;
    bool validRowParitySkipColP = true;
    *validShort = false;
    *validShortExtended = false;
    *validLong = false;
    uint8_t bLen = isLong ? 110 : 55;
    uint16_t parityCol[4] = { 0, 0, 0, 0 };

    for (int word = 0; word < bLen; word += 5) {
        for (int bit = 0; bit < 5; bit++) {

            if (word + bit >= bLen) {
                break;
            }

            parityWd = (parityWd << 1) | bits[startIdx + word + bit];

            if ((word <= 50) && (bit < 4)) {
                parityCol[bit] = (parityCol[bit] << 1) | bits[startIdx + word + bit];
            }

            bits[bitCnt++] = (bits[startIdx + word + bit]);
        }
        if (word + 5 > bLen) break;

        bitCnt--; // overwrite parity with next data
        validRowParity &= parityTest(parityWd, 5, 0) != 0;
        if (word == 50) { // column parity nibble on short EM and on Electra
            validColParity = parityTest(parityCol[0], 11, 0) != 0;
            validColParity &= parityTest(parityCol[1], 11, 0) != 0;
            validColParity &= parityTest(parityCol[2], 11, 0) != 0;
            validColParity &= parityTest(parityCol[3], 11, 0) != 0;
        } else {
            validRowParitySkipColP &= parityTest(parityWd, 5, 0) != 0;
        }
        parityWd = 0;
    }
    if (!isLong && validRowParitySkipColP && validColParity) {
        *validShort = true;
    }

    if (isLong && validRowParity) {
        *validLong = true;
    }

    if (isLong && validRowParitySkipColP && validColParity) {
        *validShortExtended = true;
    }

    if (*validShort || *validShortExtended || *validLong) {
        return bitCnt;
    } else {
        return 0;
    }
}

// takes a array of binary values, length of bits per parity (includes parity bit),
// Parity Type (1 for odd; 0 for even; 2 Always 1's; 3 Always 0's), and binary Length (length to run)
// Make sure *dest is long enough to store original sourceLen + #_of_parities_to_be_added
size_t addParity(const uint8_t *src, uint8_t *dest, uint8_t sourceLen, uint8_t pLen, uint8_t pType) {
    uint32_t parityWd = 0;
    size_t j = 0, bitCnt = 0;
    for (int word = 0; word < sourceLen; word += pLen - 1) {
        for (int bit = 0; bit < pLen - 1; bit++) {
            parityWd = (parityWd << 1) | src[word + bit];
            dest[j++] = (src[word + bit]);
        }
        // if parity fails then return 0
        switch (pType) {
            case 3:
                dest[j++] = 0;
                break; // marker bit which should be a 0
            case 2:
                dest[j++] = 1;
                break; // marker bit which should be a 1
            default:
                dest[j++] = parityTest(parityWd, pLen - 1, pType) ^ 1;
                break;
        }
        bitCnt += pLen;
        parityWd = 0;
    }
    // if we got here then all the parities passed
    //return ID start index and size
    return bitCnt;
}

// array must be size dividable with 8
int bits_to_array(const uint8_t *bits, size_t size, uint8_t *dest) {
    if ((size == 0) || (size % 8) != 0) return PM3_EINVARG;

    for (uint32_t i = 0; i < (size / 8); i++)
        dest[i] = bytebits_to_byte((uint8_t *) bits + (i * 8), 8);

    return PM3_SUCCESS;
}

uint32_t bytebits_to_byte(uint8_t *src, size_t numbits) {
    uint32_t num = 0;
    for (int i = 0 ; i < numbits ; i++) {
        num = (num << 1) | (*src);
        src++;
    }
    return num;
}

// least significant bit first
uint32_t bytebits_to_byteLSBF(uint8_t *src, size_t numbits) {
    uint32_t num = 0;
    for (int i = 0 ; i < numbits ; i++) {
        num = (num << 1) | *(src + (numbits - (i + 1)));
    }
    return num;
}

// search for given preamble in given BitStream and return success = TRUE or fail = FALSE and startIndex and length
bool preambleSearch(uint8_t *bits, uint8_t *preamble, size_t pLen, size_t *size, size_t *startIdx) {
    return preambleSearchEx(bits, preamble, pLen, size, startIdx, false);
}
// search for given preamble in given BitStream and return success=1 or fail=0 and startIndex (where it was found) and length if not fineone
// fineone does not look for a repeating preamble for em4x05/4x69 sends preamble once, so look for it once in the first pLen bits
// (iceman) FINDONE,  only finds start index. NOT SIZE!.  I see Em410xDecode (lfdemod.c) uses SIZE to determine success
bool preambleSearchEx(uint8_t *bits, uint8_t *preamble, size_t pLen, size_t *size, size_t *startIdx, bool findone) {
    // Sanity check.  If preamble length is bigger than bits length.
    if (*size <= pLen)
        return false;

    uint8_t foundCnt = 0;
    for (size_t idx = 0; idx < *size - pLen; idx++) {
        if (memcmp(bits + idx, preamble, pLen) == 0) {
            //first index found
            foundCnt++;
            if (foundCnt == 1) {
                if (g_debugMode >= 1) prnt("DEBUG: (preambleSearchEx) preamble found at %zu", idx);
                *startIdx = idx;
                if (findone)
                    return true;
            }
            if (foundCnt == 2) {
                if (g_debugMode >= 1) prnt("DEBUG: (preambleSearchEx) preamble 2 found at %zu", idx);
                *size = idx - *startIdx;
                return true;
            }
        }
    }
    return (foundCnt > 0);
}

// find start of modulating data (for fsk and psk) in case of beginning noise or slow chip startup.
static size_t findModStart(const uint8_t *src, size_t size, uint8_t expWaveSize) {
    size_t i = 0;
    size_t waveSizeCnt = 0;
    uint8_t thresholdCnt = 0;
    bool isAboveThreshold = src[i++] >= signalprop.mean; //FSK_PSK_THRESHOLD;
    for (; i < size - 20; i++) {
        if (src[i] < signalprop.mean && isAboveThreshold) {
            thresholdCnt++;
            if (thresholdCnt > 2 && waveSizeCnt < expWaveSize + 1) break;
            isAboveThreshold = false;
            waveSizeCnt = 0;
        } else if (src[i] >= signalprop.mean && !isAboveThreshold) {
            thresholdCnt++;
            if (thresholdCnt > 2 && waveSizeCnt < expWaveSize + 1) break;
            isAboveThreshold = true;
            waveSizeCnt = 0;
        } else {
            waveSizeCnt++;
        }
        if (thresholdCnt > 10) break;
    }
    if (g_debugMode == 2) prnt("DEBUG: threshold Count reached at index %zu, count: %u", i, thresholdCnt);
    return i;
}

static int getClosestClock(int testclk) {
    const uint16_t clocks[] = {8, 16, 32, 40, 50, 64, 100, 128, 256, 272, 384};
    const uint8_t limit[]  =  {1,  2,  4,  4,  5,  8,   8,   8,   8,   24,   24};

    for (uint8_t i = 0; i < ARRAYLEN(clocks); i++) {
        if (testclk >= clocks[i] - limit[i] && testclk <= clocks[i] + limit[i])
            return clocks[i];
    }
    return 0;
}

void getNextLow(const uint8_t *samples, size_t size, int low, size_t *i) {
    while ((samples[*i] > low) && (*i < size))
        *i += 1;
}

void getNextHigh(const uint8_t *samples, size_t size, int high, size_t *i) {
    while ((samples[*i] < high) && (*i < size))
        *i += 1;
}

// load wave counters
bool loadWaveCounters(uint8_t *samples, size_t size, int lowToLowWaveLen[], int highToLowWaveLen[], int *waveCnt, int *skip, int *minClk, int *high, int *low) {
    size_t i = 0;
    //size_t testsize = (size < 512) ? size : 512;

    // just noise - no super good detection. good enough
    if (signalprop.isnoise) {
        if (g_debugMode == 2) prnt("DEBUG STT: just noise detected - quitting");
        return false;
    }

    getHiLo(high, low, 80, 80);

    // get to first full low to prime loop and skip incomplete first pulse
    getNextHigh(samples, size, *high, &i);
    getNextLow(samples, size, *low, &i);
    *skip = i;

    // populate tmpbuff buffer with pulse lengths
    while (i < size) {
        // measure from low to low
        size_t firstLow = i;
        //find first high point for this wave
        getNextHigh(samples, size, *high, &i);
        size_t firstHigh = i;

        getNextLow(samples, size, *low, &i);

        if (*waveCnt >= (size / LOWEST_DEFAULT_CLOCK))
            break;

        highToLowWaveLen[*waveCnt] = i - firstHigh; //first high to first low
        lowToLowWaveLen[*waveCnt] = i - firstLow;
        *waveCnt += 1;
        if (i - firstLow < *minClk && i < size) {
            *minClk = i - firstLow;
        }
    }
    return true;
}

size_t pskFindFirstPhaseShift(const uint8_t *samples, size_t size, uint8_t *curPhase, size_t waveStart, uint16_t fc, uint16_t *fullWaveLen) {
    uint16_t loopCnt = (size + 3 < 4096) ? size : 4096; //don't need to loop through entire array...

    uint16_t avgWaveVal = 0, lastAvgWaveVal;
    size_t i = waveStart, waveEnd, waveLenCnt, firstFullWave;
    for (; i < loopCnt; i++) {
        // find peak // was "samples[i] + fc" but why?  must have been used to weed out some wave error... removed..
        if (samples[i] < samples[i + 1] && samples[i + 1] >= samples[i + 2]) {
            waveEnd = i + 1;
            if (g_debugMode == 2) prnt("DEBUG PSK: waveEnd: %zu, waveStart: %zu", waveEnd, waveStart);
            waveLenCnt = waveEnd - waveStart;
            if (waveLenCnt > fc && waveStart > fc && !(waveLenCnt > fc + 8)) { //not first peak and is a large wave but not out of whack
                lastAvgWaveVal = avgWaveVal / (waveLenCnt);
                firstFullWave = waveStart;
                *fullWaveLen = waveLenCnt;
                //if average wave value is > graph 0 then it is an up wave or a 1 (could cause inverting)
                if (lastAvgWaveVal > FSK_PSK_THRESHOLD) *curPhase ^= 1;
                return firstFullWave;
            }
            waveStart = i + 1;
            avgWaveVal = 0;
        }
        avgWaveVal += samples[i + 2];
    }
    return 0;
}

// amplify based on ask edge detection  -  not accurate enough to use all the time
void askAmp(uint8_t *bits, size_t size) {
    uint8_t last = 128;
    for (size_t i = 1; i < size; ++i) {
        if (bits[i] - bits[i - 1] >= 30) //large jump up
            last = 255;
        else if (bits[i - 1] - bits[i] >= 20) //large jump down
            last = 0;

        bits[i] = last;
    }
}

// iceman, simplify this
uint32_t manchesterEncode2Bytes(uint16_t datain) {
    uint32_t output = 0;
    for (uint8_t i = 0; i < 16; i++) {
        uint8_t b = (datain >> (15 - i) & 1);
        output |= (1 << (((15 - i) * 2) + b));
    }
    return output;
}

void manchesterEncodeUint32(uint32_t data_in, uint8_t bitlen_in, uint8_t *bits_out, uint16_t *index) {
    for (int i = bitlen_in - 1; i >= 0; i--) {
        if ((data_in >> i) & 1) {
            bits_out[(*index)++] = 1;
            bits_out[(*index)++] = 0;
        } else {
            bits_out[(*index)++] = 0;
            bits_out[(*index)++] = 1;
        }
    }
}

// encode binary data into binary manchester
// NOTE: bitstream must have triple the size of "size" available in memory to do the swap
int ManchesterEncode(uint8_t *bits, size_t size) {
    //allow up to 4096b out (means bits must be at least 2048+4096 to handle the swap)
    size = (size > 2048) ? 2048 : size;
    size_t modIdx = size;
    size_t i;
    for (size_t idx = 0; idx < size; idx++) {
        bits[idx + modIdx++] = bits[idx];
        bits[idx + modIdx++] = bits[idx] ^ 1;
    }
    for (i = 0; i < (size * 2); i++) {
        bits[i] = bits[i + size];
    }
    return i;
}

// to detect a wave that has heavily clipped (clean) samples
// loop 1024 samples,   if 250 of them is deemed maxed out,  we assume the wave is clipped.
bool DetectCleanAskWave(const uint8_t *dest, size_t size, uint8_t high, uint8_t low) {
    bool allArePeaks = true;
    uint16_t cntPeaks = 0;
    size_t loopEnd = 1024 + 160;

    // sanity check
    if (loopEnd > size) loopEnd = size;

    for (size_t i = 160; i < loopEnd; i++) {

        if (dest[i] > low && dest[i] < high)
            allArePeaks = false;
        else {
            cntPeaks++;
            //if (g_debugMode == 2) prnt("DEBUG DetectCleanAskWave: peaks (200) %u", cntPeaks);
            if (cntPeaks > 200) return true;
        }
    }

    if (allArePeaks == false) {
        if (g_debugMode == 2) prnt("DEBUG DetectCleanAskWave: peaks (200) %u", cntPeaks);
        if (cntPeaks > 200) return true;
    }
    return allArePeaks;
}


// **********************************************************************************************
// -------------------Clock / Bitrate Detection Section------------------------------------------
// **********************************************************************************************

// to help detect clocks on heavily clipped samples
// based on count of low to low
int DetectStrongAskClock(uint8_t *dest, size_t size, int high, int low, int *clock) {
    size_t i = 100;
    size_t minClk = 768;
    uint16_t shortestWaveIdx = 0;

    // get to first full low to prime loop and skip incomplete first pulse
    getNextHigh(dest, size, high, &i);
    getNextLow(dest, size, low, &i);

    if (i == size)
        return -1;
    if (size < 768)
        return -2;

    // clock, numoftimes, first idx
    uint16_t tmpclk[11][3] = {
        {8,   0, 0},
        {16,  0, 0},
        {32,  0, 0},
        {40,  0, 0},
        {50,  0, 0},
        {64,  0, 0},
        {100, 0, 0},
        {128, 0, 0},
        {256, 0, 0},
        {272, 0, 0},
        {384, 0, 0},
    };

    // loop through all samples (well, we don't want to go out-of-bounds)
    while (i < (size - 768)) {
        // measure from low to low
        size_t startwave = i;

        getNextHigh(dest, size, high, &i);
        getNextLow(dest, size, low, &i);

        //get minimum measured distance
        if (i - startwave < minClk && i < size) {
            minClk = i - startwave;
            shortestWaveIdx = startwave;
        }

        int foo = getClosestClock(minClk);
        if (foo > 0) {
            for (uint8_t j = 0; j < 11; j++) {
                if (tmpclk[j][0] == foo) {
                    tmpclk[j][1]++;

                    if (tmpclk[j][2] == 0) {
                        tmpclk[j][2] = shortestWaveIdx;
                    }
                    break;
                }
            }
        }
    }

    // find the clock with most hits and it the first index it was encountered.
    int possible_clks = 0;
    for (uint8_t j = 0; j < 11; j++) {
        if (tmpclk[j][1] > 0) {
            possible_clks++;
        }
    }

    uint16_t second_shortest = 0;
    int second = 0;
    int max = 0;
    for (int j = 10; j > -1; j--) {
        if (g_debugMode == 2) {
            prnt("DEBUG, ASK,  clocks %u | hits %u | idx %u"
                 , tmpclk[j][0]
                 , tmpclk[j][1]
                 , tmpclk[j][2]
                );
        }

        if (max < tmpclk[j][1]) {
            second = *clock;
            second_shortest = shortestWaveIdx;

            *clock = tmpclk[j][0];
            shortestWaveIdx = tmpclk[j][2];
            max = tmpclk[j][1];
        }
    }

    // ASK clock 8 is very rare and usually gives us false positives
    if (possible_clks > 1 && *clock == 8) {
        *clock = second;
        shortestWaveIdx = second_shortest;
    }

    if (*clock == 0)
        return -1;

    return shortestWaveIdx;
}

// not perfect especially with lower clocks or VERY good antennas (heavy wave clipping)
// maybe somehow adjust peak trimming value based on samples to fix?
// return start index of best starting position for that clock and return clock (by reference)
int DetectASKClock(uint8_t *dest, size_t size, int *clock, int maxErr) {

    //don't need to loop through entire array. (cotag has clock of 384)
    uint16_t loopCnt = 2000;

    // not enough samples
    if (size <= loopCnt + 60) {
        if (g_debugMode == 2) prnt("DEBUG DetectASKClock: not enough samples - aborting");
        return -1;
    }

    // just noise - no super good detection. good enough
    if (signalprop.isnoise) {
        if (g_debugMode == 2) prnt("DEBUG DetectASKClock: just noise detected - aborting");
        return -2;
    }

    size_t i = 1;
    uint8_t num_clks = 10;
    // first 255 value pos0 is placeholder for user inputed clock.
    uint16_t clk[] = {255, 8, 16, 32, 40, 50, 64, 100, 128, 255, 272};

    // sometimes there is a strange end wave - filter out this
    size -= 60;

    // What is purpose?
    // already have a valid clock?
    uint8_t found_clk = 0;
    for (; i < num_clks; ++i) {
        if (clk[i] == *clock) {
            found_clk = i;
        }
    }

    // threshold 75% of high, low peak
    int peak_hi, peak_low;
    getHiLo(&peak_hi, &peak_low, 75, 75);

    // test for large clean, STRONG, CLIPPED peaks

    if (!found_clk) {

        if (DetectCleanAskWave(dest, size, peak_hi, peak_low)) {

            int idx = DetectStrongAskClock(dest, size, peak_hi, peak_low, clock);
            if (g_debugMode == 2)
                prnt("DEBUG ASK: DetectASKClock Clean ASK Wave detected: clk %i, Best Starting Position: %i", *clock, idx);

            // return shortest wave start position
            if (idx > -1)
                return idx;
        }
    }
    // test for weak peaks

    // test clock if given as cmd parameter
    if (*clock > 0)
        clk[0] = *clock;

    uint8_t clkCnt, tol;
    size_t j = 0;
    uint16_t bestErr[] = {1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000};
    uint8_t bestStart[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    size_t errCnt, arrLoc, loopEnd;

    if (found_clk) {
        clkCnt = found_clk;
        num_clks = found_clk + 1;
    } else {
        clkCnt = 1;
    }

    //test each valid clock from smallest to greatest to see which lines up
    for (; clkCnt < num_clks; clkCnt++) {
        if (clk[clkCnt] <= 32) {
            tol = 1;
        } else {
            tol = 0;
        }
        //if no errors allowed - keep start within the first clock
        if (!maxErr && size > clk[clkCnt] * 2 + tol && clk[clkCnt] < 128)
            loopCnt = clk[clkCnt] * 2;

        bestErr[clkCnt] = 1000;

        //try lining up the peaks by moving starting point (try first few clocks)

        // get to first full low to prime loop and skip incomplete first pulse
        getNextHigh(dest, size, peak_hi, &j);
        getNextLow(dest, size, peak_low, &j);

        for (; j < loopCnt; j++) {
            errCnt = 0;
            // now that we have the first one lined up test rest of wave array
            loopEnd = ((size - j - tol) / clk[clkCnt]) - 1;
            for (i = 0; i < loopEnd; ++i) {
                arrLoc = j + (i * clk[clkCnt]);
                if (dest[arrLoc] >= peak_hi || dest[arrLoc] <= peak_low) {
                } else if (dest[arrLoc - tol] >= peak_hi || dest[arrLoc - tol] <= peak_low) {
                } else if (dest[arrLoc + tol] >= peak_hi || dest[arrLoc + tol] <= peak_low) {
                } else {  //error no peak detected
                    errCnt++;
                }
            }
            // if we found no errors then we can stop here and a low clock (common clocks)
            //  this is correct one - return this clock
            // if (g_debugMode == 2) prnt("DEBUG ASK: clk %d, err %d, startpos %d, endpos %d", clk[clkCnt], errCnt, j, i);
            if (errCnt == 0 && clkCnt < 7) {
                if (!found_clk)
                    *clock = clk[clkCnt];
                return j;
            }
            // if we found errors see if it is lowest so far and save it as best run
            if (errCnt < bestErr[clkCnt]) {
                bestErr[clkCnt] = errCnt;
                bestStart[clkCnt] = j;
            }
        }
    }

    uint8_t k, best = 0;

    for (k = 1; k < num_clks; ++k) {
        if (bestErr[k] < bestErr[best]) {
            if (bestErr[k] == 0) bestErr[k] = 1;
            // current best bit to error ratio     vs  new bit to error ratio
            if ((size / clk[best]) / bestErr[best] < (size / clk[k]) / bestErr[k]) {
                best = k;
            }
        }
        //if (g_debugMode == 2) prnt("DEBUG ASK: clk %d, # Errors %d, Current Best Clk %d, bestStart %d", clk[k], bestErr[k], clk[best], bestStart[best]);
    }

    bool chg = false;
    for (i = 0; i < ARRAYLEN(bestErr); i++) {
        chg = (bestErr[i] != 1000);
        if (chg)
            break;
        chg = (bestStart[i] != 0);
        if (chg)
            break;
    }

    // just noise - no super good detection. good enough
    if (chg == false) {
        if (g_debugMode == 2) prnt("DEBUG DetectASKClock: no good values detected - aborting");
        return -2;
    }

    if (!found_clk)
        *clock = clk[best];

    return bestStart[best];
}

int DetectStrongNRZClk(const uint8_t *dest, size_t size, int peak, int low, bool *strong) {
    //find shortest transition from high to low
    *strong = false;
    size_t i = 0;
    size_t transition1 = 0;
    int lowestTransition = 255;
    bool lastWasHigh = false;
    size_t transitionSampleCount = 0;
    //find first valid beginning of a high or low wave
    while ((dest[i] >= peak || dest[i] <= low) && (i < size))
        ++i;
    while ((dest[i] < peak && dest[i] > low) && (i < size))
        ++i;

    lastWasHigh = (dest[i] >= peak);

    if (i == size)
        return 0;

    transition1 = i;

    for (; i < size; i++) {
        if ((dest[i] >= peak && !lastWasHigh) || (dest[i] <= low && lastWasHigh)) {
            lastWasHigh = (dest[i] >= peak);
            if (i - transition1 < lowestTransition)
                lowestTransition = i - transition1;
            transition1 = i;
        } else if (dest[i] < peak && dest[i] > low) {
            transitionSampleCount++;
        }
    }
    if (lowestTransition == 255)
        lowestTransition = 0;

    if (g_debugMode == 2) prnt("DEBUG NRZ: detectstrongNRZclk smallest wave: %d", lowestTransition);
    // if less than 10% of the samples were not peaks (or 90% were peaks) then we have a strong wave
    if (transitionSampleCount / size < 10) {
        *strong = true;
        lowestTransition = getClosestClock(lowestTransition);
    }
    return lowestTransition;
}

// detect nrz clock by reading #peaks vs no peaks(or errors)
int DetectNRZClock(uint8_t *dest, size_t size, int clock, size_t *clockStartIdx) {
    size_t i = 0;
    uint16_t clk[] = {8, 16, 32, 40, 50, 64, 100, 128, 255, 272, 384};
    size_t loopCnt = 4096;  //don't need to loop through entire array...

    //if we already have a valid clock quit
    for (; i < ARRAYLEN(clk); ++i)
        if (clk[i] == clock) return clock;

    if (size < 20) return 0;
    // size must be larger than 20 here
    if (size < loopCnt) loopCnt = size - 20;


    // just noise - no super good detection. good enough
    if (signalprop.isnoise) {
        if (g_debugMode == 2) prnt("DEBUG DetectNZRClock: just noise detected - quitting");
        return 0;
    }

    //get high and low peak
    int peak, low;
    //getHiLo(dest, loopCnt, &peak, &low, 90, 90);
    getHiLo(&peak, &low, 90, 90);

    bool strong = false;
    int lowestTransition = DetectStrongNRZClk(dest, size - 20, peak, low, &strong);
    if (strong) return lowestTransition;
    size_t ii;
    uint8_t clkCnt;
    uint8_t tol = 0;
    uint16_t smplCnt = 0;
    int16_t peakcnt = 0;
    int16_t peaksdet[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint16_t minPeak = 255;
    bool firstpeak = true;
    //test for large clipped waves - ignore first peak
    for (i = 0; i < loopCnt; i++) {
        if (dest[i] >= peak || dest[i] <= low) {
            if (firstpeak) continue;
            smplCnt++;
        } else {
            firstpeak = false;
            if (smplCnt > 0) {
                if (minPeak > smplCnt && smplCnt > 7) minPeak = smplCnt;
                peakcnt++;
                if (g_debugMode == 2) prnt("DEBUG NRZ: minPeak: %d, smplCnt: %d, peakcnt: %d", minPeak, smplCnt, peakcnt);
                smplCnt = 0;
            }
        }
    }
    if (minPeak < 8) return 0;

    bool errBitHigh = 0, bitHigh = 0, lastPeakHigh = 0;
    uint8_t ignoreCnt = 0, ignoreWindow = 4;
    int lastBit = 0;
    size_t bestStart[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    peakcnt = 0;
    //test each valid clock from smallest to greatest to see which lines up
    for (clkCnt = 0; clkCnt < ARRAYLEN(bestStart); ++clkCnt) {
        //ignore clocks smaller than smallest peak
        if (clk[clkCnt] < minPeak - (clk[clkCnt] / 4)) continue;
        //try lining up the peaks by moving starting point (try first 256)
        for (ii = 20; ii < loopCnt; ++ii) {
            if ((dest[ii] >= peak) || (dest[ii] <= low)) {
                peakcnt = 0;
                bitHigh = false;
                ignoreCnt = 0;
                lastBit = ii - clk[clkCnt];
                //loop through to see if this start location works
                for (i = ii; i < size - 20; ++i) {
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
                    } else if (dest[i] < peak && dest[i] > low) {
                        if (ignoreCnt == 0) {
                            bitHigh = false;
                            if (errBitHigh == true)
                                peakcnt--;
                            errBitHigh = false;
                        } else {
                            ignoreCnt--;
                        }
                        // else if not a clock bit but we have a peak
                    } else if ((dest[i] >= peak || dest[i] <= low) && (!bitHigh)) {
                        //error bar found no clock...
                        errBitHigh = true;
                    }
                }
                if (peakcnt > peaksdet[clkCnt]) {
                    bestStart[clkCnt] = ii;
                    peaksdet[clkCnt] = peakcnt;
                }
            }
        }
    }

    uint8_t best = 0;
    for (int m = ARRAYLEN(peaksdet); m > 0; m--) {
        if ((peaksdet[m] >= (peaksdet[best] - 1)) && (peaksdet[m] <= peaksdet[best] + 1) && lowestTransition) {
            if (clk[m] > (lowestTransition - (clk[m] / 8)) && clk[m] < (lowestTransition + (clk[m] / 8))) {
                best = m;
            }
        } else if (peaksdet[m] > peaksdet[best]) {
            best = m;
        }
        if (g_debugMode == 2) prnt("DEBUG NRZ: Clk: %d, peaks: %d, minPeak: %d, bestClk: %d, lowestTrs: %d", clk[m], peaksdet[m], minPeak, clk[best], lowestTransition);
    }
    *clockStartIdx = bestStart[best];
    return clk[best];
}

// countFC is to detect the field clock lengths.
// counts and returns the 2 most common wave lengths
// mainly used for FSK field clock detection
uint16_t countFC(const uint8_t *bits, size_t size, bool fskAdj) {
    uint8_t fcLens[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint16_t fcCnts[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t fcLensFnd = 0;
    uint8_t lastFCcnt = 0;
    uint8_t fcCounter = 0;
    size_t i;
    if (size < 180) return 0;

    // prime i to first up transition
    for (i = 160; i < size - 20; i++)
        if (bits[i] > bits[i - 1] && bits[i] >= bits[i + 1])
            break;

    for (; i < size - 20; i++) {
        if (bits[i] > bits[i - 1] && bits[i] >= bits[i + 1]) {
            // new up transition
            fcCounter++;
            if (fskAdj) {
                //if we had 5 and now have 9 then go back to 8 (for when we get a fc 9 instead of an 8)
                if (lastFCcnt == 5 && fcCounter == 9) fcCounter--;

                //if fc=9 or 4 add one (for when we get a fc 9 instead of 10 or a 4 instead of a 5)
                if ((fcCounter == 9) || fcCounter == 4) fcCounter++;
                // save last field clock count  (fc/xx)
                lastFCcnt = fcCounter;
            }
            // find which fcLens to save it to:
            for (int m = 0; m < 15; m++) {
                if (fcLens[m] == fcCounter) {
                    fcCnts[m]++;
                    fcCounter = 0;
                    break;
                }
            }
            if (fcCounter > 0 && fcLensFnd < 15) {
                //add new fc length
                fcCnts[fcLensFnd]++;
                fcLens[fcLensFnd++] = fcCounter;
            }
            fcCounter = 0;
        } else {
            // count sample
            fcCounter++;
        }
    }

    uint8_t best1 = 14, best2 = 14, best3 = 14;
    uint16_t maxCnt1 = 0;
    // go through fclens and find which ones are bigest 2
    for (i = 0; i < 15; i++) {
        // get the 3 best FC values
        if (fcCnts[i] > maxCnt1) {
            best3 = best2;
            best2 = best1;
            maxCnt1 = fcCnts[i];
            best1 = i;
        } else if (fcCnts[i] > fcCnts[best2]) {
            best3 = best2;
            best2 = i;
        } else if (fcCnts[i] > fcCnts[best3]) {
            best3 = i;
        }
        if (g_debugMode == 2) prnt("DEBUG countfc: FC %u, Cnt %u, best fc: %u, best2 fc: %u", fcLens[i], fcCnts[i], fcLens[best1], fcLens[best2]);
        if (fcLens[i] == 0) break;
    }

    if (fcLens[best1] == 0) return 0;
    uint8_t fcH = 0, fcL = 0;
    if (fcLens[best1] > fcLens[best2]) {
        fcH = fcLens[best1];
        fcL = fcLens[best2];
    } else {
        fcH = fcLens[best2];
        fcL = fcLens[best1];
    }
    /*
    if ((size - 180) / fcH / 3 > fcCnts[best1] + fcCnts[best2]) {
        if (g_debugMode == 2) prnt("DEBUG countfc: fc is too large: %zu > %u. Not psk or fsk", (size - 180) / fcH / 3, fcCnts[best1] + fcCnts[best2]);
        return 0; //lots of waves not psk or fsk
    }
    */
    // TODO: take top 3 answers and compare to known Field clocks to get top 2

    uint16_t fcs = (((uint16_t)fcH) << 8) | fcL;
    if (fskAdj) return fcs;
    return (uint16_t)fcLens[best2] << 8 | fcLens[best1];
}

// detect psk clock by reading each phase shift
// a phase shift is determined by measuring the sample length of each wave
int DetectPSKClock(uint8_t *dest, size_t size, int clock, size_t *firstPhaseShift, uint8_t *curPhase, uint8_t *fc) {
    uint16_t clk[] = {255, 16, 32, 40, 50, 64, 100, 128, 256, 272, 384}; // 255 is not a valid clock
    uint16_t loopCnt = 4096;  // don't need to loop through entire array...

    if (size < 160 + 20) return 0;
    // size must be larger than 20 here, and 160 later on.
    if (size < loopCnt) loopCnt = size - 20;

    uint16_t fcs = countFC(dest, size, 0);

    *fc = fcs & 0xFF;

    if (g_debugMode == 2) prnt("DEBUG PSK: FC: %d, FC2: %d", *fc, fcs >> 8);

    if ((fcs >> 8) == 10 && *fc == 8) return 0;

    if (*fc != 2 && *fc != 4 && *fc != 8) return 0;


    size_t waveEnd, firstFullWave = 0;

    uint8_t clkCnt;
    uint16_t waveLenCnt, fullWaveLen = 0;
    uint16_t bestErr[] = {1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000};
    uint16_t peaksdet[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    //find start of modulating data in trace
    size_t i = findModStart(dest, size, *fc);

    firstFullWave = pskFindFirstPhaseShift(dest, size, curPhase, i, *fc, &fullWaveLen);
    if (firstFullWave == 0) {
        // no phase shift detected - could be all 1's or 0's - doesn't matter where we start
        // so skip a little to ensure we are past any Start Signal
        firstFullWave = 160;
        fullWaveLen = 0;
    }

    *firstPhaseShift = firstFullWave;
    if (g_debugMode == 2) prnt("DEBUG PSK: firstFullWave: %zu, waveLen: %d", firstFullWave, fullWaveLen);

    // Avoid autodetect if user selected a clock
    for (uint8_t validClk = 1; validClk < 8; validClk++) {
        if (clock == clk[validClk]) return (clock);
    }

    //test each valid clock from greatest to smallest to see which lines up
    for (clkCnt = 9; clkCnt >= 1 ; clkCnt--) {
        uint8_t tol = *fc / 2;
        size_t lastClkBit = firstFullWave; //set end of wave as clock align
        size_t waveStart = 0;
        uint16_t errCnt = 0;
        uint16_t peakcnt = 0;
        if (g_debugMode == 2) prnt("DEBUG PSK: clk: %d, lastClkBit: %zu", clk[clkCnt], lastClkBit);

        for (i = firstFullWave + fullWaveLen - 1; i < loopCnt - 2; i++) {
            //top edge of wave = start of new wave
            if (dest[i] < dest[i + 1] && dest[i + 1] >= dest[i + 2]) {
                if (waveStart == 0) {
                    waveStart = i + 1;
                } else { //waveEnd
                    waveEnd = i + 1;
                    waveLenCnt = waveEnd - waveStart;
                    if (waveLenCnt > *fc) {
                        //if this wave is a phase shift
                        if (g_debugMode == 2) prnt("DEBUG PSK: phase shift at: %zu, len: %d, nextClk: %zu, i: %zu, fc: %d", waveStart, waveLenCnt, lastClkBit + clk[clkCnt] - tol, i + 1, *fc);
                        if (i + 1 >= lastClkBit + clk[clkCnt] - tol) { //should be a clock bit
                            peakcnt++;
                            lastClkBit += clk[clkCnt];
                        } else if (i < lastClkBit + 8) {
                            //noise after a phase shift - ignore
                        } else { //phase shift before supposed to based on clock
                            errCnt++;
                        }
                    } else if (i + 1 > lastClkBit + clk[clkCnt] + tol + *fc) {
                        lastClkBit += clk[clkCnt]; //no phase shift but clock bit
                    }
                    waveStart = i + 1;
                }
            }
        }
        if (errCnt == 0) return clk[clkCnt];
        if (errCnt <= bestErr[clkCnt]) bestErr[clkCnt] = errCnt;
        if (peakcnt > peaksdet[clkCnt]) peaksdet[clkCnt] = peakcnt;
    }
    //all tested with errors
    //return the highest clk with the most peaks found
    uint8_t best = 9;
    for (i = 9; i >= 1; i--) {
        if (peaksdet[i] > peaksdet[best])
            best = i;

        if (g_debugMode == 2) prnt("DEBUG PSK: Clk: %d, peaks: %d, errs: %d, bestClk: %d", clk[i], peaksdet[i], bestErr[i], clk[best]);
    }
    return clk[best];
}

// detects the bit clock for FSK given the high and low Field Clocks
uint8_t detectFSKClk(const uint8_t *bits, size_t size, uint8_t fcHigh, uint8_t fcLow, int *firstClockEdge) {

    if (size == 0)
        return 0;

    uint8_t clk[] = {8, 16, 32, 40, 50, 64, 100, 128, 0};
    uint16_t rfLens[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t rfCnts[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t rfLensFnd = 0;
    uint8_t lastFCcnt = 0;
    uint16_t fcCounter = 0;
    uint16_t rfCounter = 0;
    uint8_t firstBitFnd = 0;
    size_t i;
    uint8_t fcTol = ((fcHigh * 100 - fcLow * 100) / 2 + 50) / 100; //(uint8_t)(0.5+(float)(fcHigh-fcLow)/2);

    // prime i to first peak / up transition
    for (i = 160; i < size - 20; i++)
        if (bits[i] > bits[i - 1] && bits[i] >= bits[i + 1])
            break;

    for (; i < size - 20; i++) {
        fcCounter++;
        rfCounter++;

        if (bits[i] <= bits[i - 1] || bits[i] < bits[i + 1])
            continue;
        // else new peak
        // if we got less than the small fc + tolerance then set it to the small fc
        // if it is inbetween set it to the last counter
        if (fcCounter < fcHigh && fcCounter > fcLow)
            fcCounter = lastFCcnt;
        else if (fcCounter < fcLow + fcTol)
            fcCounter = fcLow;
        else //set it to the large fc
            fcCounter = fcHigh;

        //look for bit clock  (rf/xx)
        if ((fcCounter < lastFCcnt || fcCounter > lastFCcnt)) {
            //not the same size as the last wave - start of new bit sequence
            if (firstBitFnd > 1) { //skip first wave change - probably not a complete bit
                for (int ii = 0; ii < 15; ii++) {
                    if (rfLens[ii] >= (rfCounter - 4) && rfLens[ii] <= (rfCounter + 4)) {
                        rfCnts[ii]++;
                        rfCounter = 0;
                        break;
                    }
                }
                if (rfCounter > 0 && rfLensFnd < 15) {
                    //prnt("DEBUG: rfCntr %d, fcCntr %d",rfCounter,fcCounter);
                    rfCnts[rfLensFnd]++;
                    rfLens[rfLensFnd++] = rfCounter;
                }
            } else {
                *firstClockEdge = i;
                firstBitFnd++;
            }
            rfCounter = 0;
            lastFCcnt = fcCounter;
        }
        fcCounter = 0;
    }
    uint8_t rfHighest = 15, rfHighest2 = 15, rfHighest3 = 15;

    for (i = 0; i < 15; i++) {
        //get highest 2 RF values  (might need to get more values to compare or compare all?)
        if (rfCnts[i] > rfCnts[rfHighest]) {
            rfHighest3 = rfHighest2;
            rfHighest2 = rfHighest;
            rfHighest = i;
        } else if (rfCnts[i] > rfCnts[rfHighest2]) {
            rfHighest3 = rfHighest2;
            rfHighest2 = i;
        } else if (rfCnts[i] > rfCnts[rfHighest3]) {
            rfHighest3 = i;
        }
        if (g_debugMode == 2)
            prnt("DEBUG FSK: RF %d, cnts %d", rfLens[i], rfCnts[i]);
    }
    // set allowed clock remainder tolerance to be 1 large field clock length+1
    //   we could have mistakenly made a 9 a 10 instead of an 8 or visa versa so rfLens could be 1 FC off
    uint8_t tol1 = fcHigh + 1;

    if (g_debugMode == 2)
        prnt("DEBUG FSK: most counted rf values: 1 %d, 2 %d, 3 %d", rfLens[rfHighest], rfLens[rfHighest2], rfLens[rfHighest3]);

    // loop to find the highest clock that has a remainder less than the tolerance
    //   compare samples counted divided by
    // test 128 down to 32 (shouldn't be possible to have fc/10 & fc/8 and rf/16 or less)
    int m = 7;
    for (; m >= 2; m--) {
        if (rfLens[rfHighest] % clk[m] < tol1 || rfLens[rfHighest] % clk[m] > clk[m] - tol1) {
            if (rfLens[rfHighest2] % clk[m] < tol1 || rfLens[rfHighest2] % clk[m] > clk[m] - tol1) {
                if (rfLens[rfHighest3] % clk[m] < tol1 || rfLens[rfHighest3] % clk[m] > clk[m] - tol1) {
                    if (g_debugMode == 2)
                        prnt("DEBUG FSK: clk %d divides into the 3 most rf values within tolerance", clk[m]);
                    break;
                }
            }
        }
    }

    if (m < 2) return 0; // oops we went too far

    return clk[m];
}


// **********************************************************************************************
// --------------------Modulation Demods &/or Decoding Section-----------------------------------
// **********************************************************************************************


// look for Sequence Terminator - should be pulses of clk*(1 or 2), clk*2, clk*(1.5 or 2), by idx we mean graph position index...
static bool findST(int *stStopLoc, int *stStartIdx,
                   const int lowToLowWaveLen[], const int highToLowWaveLen[],
                   int clk, int tol, int buffSize, size_t *i) {
    if (buffSize < *i + 4) return false;

    for (; *i < buffSize - 4; *i += 1) {
        *stStartIdx += lowToLowWaveLen[*i]; //caution part of this wave may be data and part may be ST....  to be accounted for in main function for now...
        if (lowToLowWaveLen[*i] >= clk * 1 - tol && lowToLowWaveLen[*i] <= (clk * 2) + tol && highToLowWaveLen[*i] < clk + tol) { //1 to 2 clocks depending on 2 bits prior
            if (lowToLowWaveLen[*i + 1] >= clk * 2 - tol && lowToLowWaveLen[*i + 1] <= clk * 2 + tol && highToLowWaveLen[*i + 1] > clk * 3 / 2 - tol) { //2 clocks and wave size is 1 1/2
                if (lowToLowWaveLen[*i + 2] >= (clk * 3) / 2 - tol && lowToLowWaveLen[*i + 2] <= clk * 2 + tol && highToLowWaveLen[*i + 2] > clk - tol) { //1 1/2 to 2 clocks and at least one full clock wave
                    if (lowToLowWaveLen[*i + 3] >= clk * 1 - tol && lowToLowWaveLen[*i + 3] <= clk * 2 + tol) { //1 to 2 clocks for end of ST + first bit
                        *stStopLoc = *i + 3;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

// attempt to identify a Sequence Terminator in ASK modulated raw wave
bool DetectST(uint8_t *buffer, size_t *size, int *foundclock, size_t *ststart, size_t *stend) {
    size_t bufsize = *size;
    //need to loop through all samples and identify our clock, look for the ST pattern
    int clk = 0;
    int tol = 0;
    int j = 0, high, low, skip = 0, start = 0, end = 0, minClk = 255;
    size_t i = 0;
    //probably should calloc... || test if memory is available ... handle device side? memory danger!!! [marshmellow]
    int tmpbuff[bufsize / LOWEST_DEFAULT_CLOCK]; // low to low wave count //guess rf/32 clock, if click is smaller we will only have room for a fraction of the samples captured
    int waveLen[bufsize / LOWEST_DEFAULT_CLOCK]; // high to low wave count //if clock is larger then we waste memory in array size that is not needed...
    //size_t testsize = (bufsize < 512) ? bufsize : 512;
    int phaseoff = 0;
    high = low = 128;
    memset(tmpbuff, 0, sizeof(tmpbuff));
    memset(waveLen, 0, sizeof(waveLen));

    if (!loadWaveCounters(buffer, bufsize, tmpbuff, waveLen, &j, &skip, &minClk, &high, &low)) return false;
    // set clock  - might be able to get this externally and remove this work...
    clk = getClosestClock(minClk);
    // clock not found - ERROR
    if (!clk) {
        if (g_debugMode == 2) prnt("DEBUG STT: clock not found - quitting");
        return false;
    }
    *foundclock = clk;

    tol = clk / 8;
    if (!findST(&start, &skip, tmpbuff, waveLen, clk, tol, j, &i)) {
        // first ST not found - ERROR
        if (g_debugMode == 2) prnt("DEBUG STT: first STT not found - quitting");
        return false;
    } else {
        if (g_debugMode == 2) prnt("DEBUG STT: first STT found at wave: %i, skip: %i, j=%i", start, skip, j);
    }
    if (waveLen[i + 2] > clk * 1 + tol)
        phaseoff = 0;
    else
        phaseoff = clk / 2;

    // skip over the remainder of ST
    skip += clk * 7 / 2; //3.5 clocks from tmpbuff[i] = end of st - also aligns for ending point

    // now do it again to find the end
    int dummy1 = 0;
    end = skip;
    i += 3;
    if (!findST(&dummy1, &end, tmpbuff, waveLen, clk, tol, j, &i)) {
        //didn't find second ST - ERROR
        if (g_debugMode == 2) prnt("DEBUG STT: second STT not found - quitting");
        return false;
    }
    end -= phaseoff;
    if (g_debugMode == 2) prnt("DEBUG STT: start of data: %d end of data: %d, datalen: %d, clk: %d, bits: %d, phaseoff: %d", skip, end, end - skip, clk, (end - skip) / clk, phaseoff);
    //now begin to trim out ST so we can use normal demod cmds
    start = skip;
    size_t datalen = end - start;
    // check validity of datalen (should be even clock increments)  - use a tolerance of up to 1/8th a clock
    if (clk - (datalen % clk) <= clk / 8) {
        // padd the amount off - could be problematic...  but shouldn't happen often
        datalen += clk - (datalen % clk);
    } else if ((datalen % clk) <= clk / 8) {
        // padd the amount off - could be problematic...  but shouldn't happen often
        datalen -= datalen % clk;
    } else {
        if (g_debugMode == 2) prnt("DEBUG STT: datalen not divisible by clk: %zu %% %d = %zu - quitting", datalen, clk, datalen % clk);
        return false;
    }
    // if datalen is less than one t55xx block - ERROR
    if (datalen / clk < 8 * 4) {
        if (g_debugMode == 2) prnt("DEBUG STT: datalen is less than 1 full t55xx block - quitting");
        return false;
    }
    size_t dataloc = start;
    if (buffer[dataloc - (clk * 4) - (clk / 4)] <= low && buffer[dataloc] <= low && buffer[dataloc - (clk * 4)] >= high) {
        //we have low drift (and a low just before the ST and a low just after the ST) - compensate by backing up the start
        for (i = 0; i <= (clk / 4); ++i) {
            if (buffer[dataloc - (clk * 4) - i] <= low) {
                dataloc -= i;
                break;
            }
        }
    }

    size_t newloc = 0;
    i = 0;
    if (g_debugMode == 2) prnt("DEBUG STT: Starting STT trim - start: %zu, datalen: %zu ", dataloc, datalen);
    bool firstrun = true;
    // warning - overwriting buffer given with raw wave data with ST removed...
    while (dataloc < bufsize - (clk / 2)) {
        //compensate for long high at end of ST not being high due to signal loss... (and we cut out the start of wave high part)
        if (buffer[dataloc] < high && buffer[dataloc] > low && buffer[dataloc + clk / 4] < high && buffer[dataloc + clk / 4] > low) {
            for (i = 0; i < clk / 2 - tol; ++i) {
                buffer[dataloc + i] = high + 5;
            }
        } //test for small spike outlier (high between two lows) in the case of very strong waves
        if (buffer[dataloc] > low && buffer[dataloc + clk / 4] <= low) {
            for (i = 0; i < clk / 4; ++i) {
                buffer[dataloc + i] = buffer[dataloc + clk / 4];
            }
        }
        if (firstrun) {
            *stend = dataloc;
            *ststart = dataloc - (clk * 4);
            firstrun = false;
        }
        for (i = 0; i < datalen; ++i) {
            if (i + newloc < bufsize) {
                if (i + newloc < dataloc)
                    buffer[i + newloc] = buffer[dataloc];

                dataloc++;
            }
        }
        newloc += i;
        //skip next ST  -  we just assume it will be there from now on...
        if (g_debugMode == 2) prnt("DEBUG STT: skipping STT at %zu to %zu", dataloc, dataloc + (clk * 4));
        dataloc += clk * 4;
    }
    *size = newloc;
    return true;
}

// take 11 10 01 11 00 and make 01100 ... miller decoding
// check for phase errors - should never have half a 1 or 0 by itself and should never exceed 1111 or 0000 in a row
// decodes miller encoded binary
// NOTE  askrawdemod will NOT demod miller encoded ask unless the clock is manually set to 1/2 what it is detected as!
/*
static int millerRawDecode(uint8_t *bits, size_t *size, int invert) {
    if (*size < 16) return -1;

    uint16_t MaxBits = 512, errCnt = 0;
    size_t i, bitCnt = 0;
    uint8_t alignCnt = 0, curBit = bits[0], alignedIdx = 0, halfClkErr = 0;

    //find alignment, needs 4 1s or 0s to properly align
    for (i = 1; i < *size - 1; i++) {
        alignCnt = (bits[i] == curBit) ? alignCnt + 1 : 0;
        curBit = bits[i];
        if (alignCnt == 4) break;
    }
    // for now error if alignment not found.  later add option to run it with multiple offsets...
    if (alignCnt != 4) {
        if (g_debugMode) prnt("ERROR MillerDecode: alignment not found so either your bits is not miller or your data does not have a 101 in it");
        return -1;
    }
    alignedIdx = (i - 1) % 2;
    for (i = alignedIdx; i < *size - 3; i += 2) {
        halfClkErr = (uint8_t)((halfClkErr << 1 | bits[i]) & 0xFF);
        if ((halfClkErr & 0x7) == 5 || (halfClkErr & 0x7) == 2 || (i > 2 && (halfClkErr & 0x7) == 0) || (halfClkErr & 0x1F) == 0x1F) {
            errCnt++;
            bits[bitCnt++] = 7;
            continue;
        }
        bits[bitCnt++] = bits[i] ^ bits[i + 1] ^ invert;

        if (bitCnt > MaxBits) break;
    }
    *size = bitCnt;
    return errCnt;
}
*/

// take 01 or 10 = 1 and 11 or 00 = 0
// check for phase errors - should never have 111 or 000 should be 01001011 or 10110100 for 1010
// decodes biphase or if inverted it is AKA conditional dephase encoding AKA differential manchester encoding
int BiphaseRawDecode(uint8_t *bits, size_t *size, int *offset, int invert) {
    //sanity check
    if (*size < 51) return -1;

    if (*offset < 0) *offset = 0;

    uint16_t bitnum = 0;
    uint16_t errCnt = 0;
    size_t i = *offset;
    uint16_t maxbits = 512;

    //check for phase change faults - skip one sample if faulty
    bool offsetA = true, offsetB = true;
    for (; i < *offset + 48; i += 2) {
        if (bits[i + 1] == bits[i + 2]) offsetA = false;
        if (bits[i + 2] == bits[i + 3]) offsetB = false;
    }
    if (!offsetA && offsetB) ++*offset;

    // main loop
    for (i = *offset; i < *size - 1; i += 2) {
        //check for phase error
        if (bits[i + 1] == bits[i + 2]) {
            bits[bitnum++] = 7;
            errCnt++;
        }
        if ((bits[i] == 1 && bits[i + 1] == 0) || (bits[i] == 0 && bits[i + 1] == 1)) {
            bits[bitnum++] = 1 ^ invert;
        } else if ((bits[i] == 0 && bits[i + 1] == 0) || (bits[i] == 1 && bits[i + 1] == 1)) {
            bits[bitnum++] = invert;
        } else {
            bits[bitnum++] = 7;
            errCnt++;
        }
        if (bitnum > maxbits) break;
    }
    *size = bitnum;
    return errCnt;
}

// take 10 and 01 and manchester decode
// run through 2 times and take least errCnt
// "," indicates 00 or 11 wrong bit
uint16_t manrawdecode(uint8_t *bits, size_t *size, uint8_t invert, uint8_t *alignPos) {

    // sanity check
    if (*size < 16) return 0xFFFF;

    int errCnt = 0, bestErr = 1000;
    uint16_t bitnum = 0, maxBits = 512, bestRun = 0;
    size_t i;

    //find correct start position [alignment]
    for (uint8_t k = 0; k < 2; k++) {

        for (i = k; i < *size - 1; i += 2) {

            if (bits[i] == bits[i + 1])
                errCnt++;

            if (errCnt > 50)
                break;
        }

        if (bestErr > errCnt) {
            bestErr = errCnt;
            bestRun = k;
            if (g_debugMode == 2) prnt("DEBUG manrawdecode: bestErr %d | bestRun %u", bestErr, bestRun);
        }
        errCnt = 0;
    }

    *alignPos = bestRun;
    //decode
    for (i = bestRun; i < *size; i += 2) {
        if (bits[i] == 1 && (bits[i + 1] == 0)) {
            bits[bitnum++] = invert;
        } else if ((bits[i] == 0) && bits[i + 1] == 1) {
            bits[bitnum++] = invert ^ 1;
        } else {
            bits[bitnum++] = 7;
        }
        if (bitnum > maxBits) break;
    }
    *size = bitnum;
    return bestErr;
}

// demodulates strong heavily clipped samples
// RETURN: num of errors.  if 0, is ok.
static uint16_t cleanAskRawDemod(uint8_t *bits, size_t *size, int clk, int invert, int high, int low, int *startIdx) {
    *startIdx = 0;
    size_t bitCnt = 0, smplCnt = 1, errCnt = 0, pos = 0;
    uint8_t cl_4 = clk / 4;
    uint8_t cl_2 = clk / 2;
    bool waveHigh = true;

    getNextHigh(bits, *size, high, &pos);
//    getNextLow(bits, *size, low, &pos);

    // do not skip first transition
    if ((pos > cl_2 - cl_4 - 1) && (pos <= clk + cl_4 + 1)) {
        bits[bitCnt++] = invert ^ 1;
    }

    // sample counts,   like clock = 32.. it tries to find  32/4 = 8,  32/2 = 16
    for (size_t i = pos; i < *size; i++) {
        if (bits[i] >= high && waveHigh) {
            smplCnt++;
        } else if (bits[i] <= low && !waveHigh) {
            smplCnt++;
        } else {
            //transition
            if ((bits[i] >= high && !waveHigh) || (bits[i] <= low && waveHigh)) {

                // 8  ::    8-2-1 =  5   8+2+1 = 11
                // 16 ::   16-4-1 = 11  16+4+1 = 21
                // 32 ::   32-8-1 = 23  32+8+1 = 41
                // 64 ::  64-16-1 = 47 64+16+1 = 81
                if (smplCnt > clk - cl_4 - 1) { //full clock

                    if (smplCnt > clk + cl_4 + 1) {
                        //too many samples
                        errCnt++;
                        if (g_debugMode == 2) prnt("DEBUG ASK: cleanAskRawDemod ASK Modulation Error FULL at: %zu  [%zu > %u]", i, smplCnt, clk + cl_4 + 1);
                        bits[bitCnt++] = 7;
                    } else if (waveHigh) {
                        bits[bitCnt++] = invert;
                        bits[bitCnt++] = invert;
                    } else {
                        bits[bitCnt++] = invert ^ 1;
                        bits[bitCnt++] = invert ^ 1;
                    }
                    if (*startIdx == 0) {
                        *startIdx = i - clk;
                        if (g_debugMode == 2) prnt("DEBUG ASK: cleanAskRawDemod minus clock [%d]", *startIdx);
                    }
                    waveHigh = !waveHigh;
                    smplCnt = 0;

                    // 16-8-1 = 7
                } else if (smplCnt > cl_2 - cl_4 - 1) { //half clock

                    if (smplCnt > cl_2 + cl_4 + 1) { //too many samples
                        errCnt++;
                        if (g_debugMode == 2) prnt("DEBUG ASK: cleanAskRawDemod ASK Modulation Error HALF at: %zu  [%zu]", i, smplCnt);
                        bits[bitCnt++] = 7;
                    }

                    if (waveHigh) {
                        bits[bitCnt++] = invert;
                    } else {
                        bits[bitCnt++] = invert ^ 1;
                    }

                    if (*startIdx == 0) {
                        *startIdx = i - cl_2;
                        if (g_debugMode == 2) prnt("DEBUG ASK: cleanAskRawDemod minus half clock [%d]", *startIdx);
                    }
                    waveHigh = !waveHigh;
                    smplCnt = 0;
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

    if (g_debugMode == 2) prnt("DEBUG ASK: cleanAskRawDemod Startidx %d", *startIdx);

    return errCnt;
}

// attempts to demodulate ask modulations, askType == 0 for ask/raw, askType==1 for ask/manchester
int askdemod_ext(uint8_t *bits, size_t *size, int *clk, int *invert, int maxErr, uint8_t amp, uint8_t askType, int *startIdx) {

    if (*size == 0) return -1;

    if (signalprop.isnoise) {
        if (g_debugMode == 2) prnt("DEBUG (askdemod_ext) just noise detected - aborting");
        return -2;
    }

    int start = DetectASKClock(bits, *size, clk, maxErr);
    if (*clk == 0 || start < 0) return -3;

    if (*invert != 1) *invert = 0;

    // amplify signal data.
    // ICEMAN todo,
    if (amp == 1) askAmp(bits, *size);

    if (g_debugMode == 2) prnt("DEBUG (askdemod_ext) clk %d, beststart %d, amp %d", *clk, start, amp);

    // Detect high and lows
    //25% clip in case highs and lows aren't clipped [marshmellow]
    int high, low;
    getHiLo(&high, &low, 75, 75);

    size_t errCnt = 0;
    // if clean clipped waves detected run alternate demod
    if (DetectCleanAskWave(bits, *size, high, low)) {

        //start pos from detect ask clock is 1/2 clock offset
        // NOTE: can be negative (demod assumes rest of wave was there)
        *startIdx = start - (*clk / 2);
        if (g_debugMode == 2) prnt("DEBUG: (askdemod_ext) Clean wave detected  --- startindex %d", *startIdx);

        errCnt = cleanAskRawDemod(bits, size, *clk, *invert, high, low, startIdx);

        if (askType) { //ask/manchester
            uint8_t alignPos = 0;
            errCnt = manrawdecode(bits, size, 0, &alignPos);
            *startIdx += ((*clk / 2) * alignPos);

            if (g_debugMode == 2) prnt("DEBUG: (askdemod_ext) CLEAN: startIdx %i, alignPos %u , bestError %zu", *startIdx, alignPos, errCnt);
        }
        return errCnt;
    }

    *startIdx = start - (*clk / 2);
    if (g_debugMode == 2) prnt("DEBUG: (askdemod_ext) Weak wave detected: startIdx %i", *startIdx);

    int lastBit;              // set first clock check - can go negative
    size_t i, bitnum = 0;     // output counter
    uint8_t midBit = 0;
    uint8_t tol = 0;          // clock tolerance adjust - waves will be accepted as within the clock if they fall + or - this value + clock from last valid wave
    if (*clk <= 32) tol = 1;  // clock tolerance may not be needed anymore currently set to + or - 1 but could be increased for poor waves or removed entirely
    size_t MaxBits = 3072;    // max bits to collect
    lastBit = start - *clk;

    for (i = start; i < *size; ++i) {
        if (i - lastBit >= *clk - tol) {
            if (bits[i] >= high) {
                bits[bitnum++] = *invert;
            } else if (bits[i] <= low) {
                bits[bitnum++] = *invert ^ 1;
            } else if (i - lastBit >= *clk + tol) {
                if (bitnum > 0) {
//                    if (g_debugMode == 2) prnt("DEBUG: (askdemod_ext) Modulation Error at: %u", i);
                    bits[bitnum++] = 7;
                    errCnt++;
                }
            } else { //in tolerance - looking for peak
                continue;
            }
            midBit = 0;
            lastBit += *clk;
        } else if (i - lastBit >= (*clk / 2 - tol) && !midBit && !askType) {
            if (bits[i] >= high) {
                bits[bitnum++] = *invert;
            } else if (bits[i] <= low) {
                bits[bitnum++] = *invert ^ 1;
            } else if (i - lastBit >= *clk / 2 + tol) {
                if (bitnum > 0) {
                    bits[bitnum] = bits[bitnum - 1];
                    bitnum++;
                } else {
                    bits[bitnum] = 0;
                    bitnum++;
                }
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

int askdemod(uint8_t *bits, size_t *size, int *clk, int *invert, int maxErr, uint8_t amp, uint8_t askType) {
    int start = 0;
    return askdemod_ext(bits, size, clk, invert, maxErr, amp, askType, &start);
}

// demodulate NRZ wave - requires a read with strong signal
// peaks invert bit (high=1 low=0) each clock cycle = 1 bit determined by last peak
int nrzRawDemod(uint8_t *dest, size_t *size, int *clk, const int *invert, int *startIdx) {

    if (signalprop.isnoise) {
        if (g_debugMode == 2) prnt("DEBUG nrzRawDemod: just noise detected - quitting");
        return -1;
    }

    size_t clkStartIdx = 0;
    *clk = DetectNRZClock(dest, *size, *clk, &clkStartIdx);
    if (*clk == 0) return -2;

    size_t i;
    int high, low;

    getHiLo(&high, &low, 75, 75);

    uint8_t bit = 0;
    //convert wave samples to 1's and 0's
    for (i = 20; i < *size - 20; i++) {
        if (dest[i] >= high) bit = 1;
        if (dest[i] <= low)  bit = 0;
        dest[i] = bit;
    }
    //now demod based on clock (rf/32 = 32 1's for one 1 bit, 32 0's for one 0 bit)
    size_t lastBit = 0;
    size_t numBits = 0;
    for (i = 21; i < *size - 20; i++) {
        //if transition detected or large number of same bits - store the passed bits
        if (dest[i] != dest[i - 1] || (i - lastBit) == (10 * *clk)) {
            memset(dest + numBits, dest[i - 1] ^ *invert, (i - lastBit + (*clk / 4)) / *clk);
            numBits += (i - lastBit + (*clk / 4)) / *clk;
            if (lastBit == 0) {
                *startIdx = i - (numBits * *clk);
                if (g_debugMode == 2) prnt("DEBUG NRZ: startIdx %i", *startIdx);
            }
            lastBit = i - 1;
        }
    }
    *size = numBits;
    return 0;
}

// translate wave to 11111100000 (1 for each short wave [higher freq] 0 for each long wave [lower freq])
static size_t fsk_wave_demod(uint8_t *dest, size_t size, uint8_t fchigh, uint8_t fclow, int *startIdx) {

    if (size < 1024) return 0;   // not enough samples

    if (fchigh == 0) fchigh = 10;
    if (fclow == 0) fclow = 8;

    //set the threshold close to 0 (graph) or 128 std to avoid static
    size_t preLastSample, LastSample = 0;
    size_t currSample = 0, last_transition = 0;
    size_t idx, numBits = 0;

    //find start of modulating data in trace
    idx = findModStart(dest, size, fchigh);
    // Need to threshold first sample
    dest[idx] = (dest[idx] < signalprop.mean) ? 0 : 1;

    last_transition = idx;
    idx++;

    // Definition:  cycles between consecutive lo-hi transitions
    // Lets define some expected lengths. FSK1 is easier since it has bigger differences between.
    // FSK1 8/5
    // 50/8 = 6         | 40/8 = 5  | 64/8 = 8
    // 50/5 = 10        | 40/5 = 8  | 64/5 = 12

    // FSK2 10/8
    // 50/10 = 5        | 40/10 = 4 | 64/10 = 6
    // 50/8  = 6        | 40/8  = 5 | 64/8  = 8

    // count cycles between consecutive lo-hi transitions,
    // in practice due to noise etc we may end up with anywhere
    // To allow fuzz would mean  +-1 on expected cycle width.
    // FSK1 8/5
    // 50/8 = 6 (5-7)   | 40/8 = 5 (4-6)        | 64/8 = 8 (7-9)
    // 50/5 = 10 (9-11) | 40/5 = 8 (7-9)        | 64/5 = 12 (11-13)

    // FSK2 10/8
    // 50/10 = 5 (4-6)  | 40/10 = 4 (3-5)       | 64/10 = 6 (5-7)
    // 50/8  = 6 (5-7)  | 40/8  = 5 (4-6)       | 64/8  = 8 (7-9)
    //
    // It easy to see to the overgaping, but luckily we the group value also,  like 1111000001111
    // to separate between which bit to demodulate to.

    // process:
    // count width from 0-1 transition to  1-0.
    // determine the width is within FUZZ_min and FUZZ_max tolerances
    // width should be divided with exp_one.  i:e 6+7+6+2=21,  21/5 = 4,
    // the 1-0 to 0-1  width should be divided with exp_zero.   Ie: 3+5+6+7 = 21/6 = 3

    for (; idx < size - 20; idx++) {

        // threshold current value
        dest[idx] = (dest[idx] < signalprop.mean) ? 0 : 1;

        // Check for 0->1 transition
        if (dest[idx - 1] < dest[idx]) {
            preLastSample = LastSample;
            LastSample = currSample;
            currSample = idx - last_transition;
            if (currSample < (fclow - 2)) {         //0-5 = garbage noise (or 0-3)
                //do nothing with extra garbage
            } else if (currSample < (fchigh - 1)) {         //6-8 = 8 sample waves  (or 3-6 = 5)
                //correct previous 9 wave surrounded by 8 waves (or 6 surrounded by 5)
                if (numBits > 1 && LastSample > (fchigh - 2) && (preLastSample < (fchigh - 1))) {
                    dest[numBits - 1] = 1;
                }
                dest[numBits++] = 1;


                if (numBits > 0 && *startIdx == 0)
                    *startIdx = idx - fclow;

            } else if (currSample > (fchigh + 1) && numBits < 3) { //12 + and first two bit = unusable garbage
                //do nothing with beginning garbage and reset..  should be rare..
                numBits = 0;
            } else if (currSample == (fclow + 1) && LastSample == (fclow - 1)) { // had a 7 then a 9 should be two 8's (or 4 then a 6 should be two 5's)
                dest[numBits++] = 1;
                if (numBits > 0 && *startIdx == 0) {
                    *startIdx = idx - fclow;
                }
            } else {                                        //9+ = 10 sample waves (or 6+ = 7)
                dest[numBits++] = 0;
                if (numBits > 0 && *startIdx == 0) {
                    *startIdx = idx - fchigh;
                }
            }
            last_transition = idx;
        }
    }
    return numBits; //Actually, it returns the number of bytes, but each byte represents a bit: 1 or 0
}

// translate 11111100000 to 10
//rfLen = clock, fchigh = larger field clock, fclow = smaller field clock
static size_t aggregate_bits(uint8_t *dest, size_t size, uint8_t clk, uint8_t invert, uint8_t fchigh, uint8_t fclow, int *startIdx) {

    uint8_t lastval = dest[0];
    size_t i = 0;
    size_t numBits = 0;
    uint32_t n = 1;
    uint8_t hclk = clk / 2;

    for (i = 1; i < size; i++) {
        n++;
        if (dest[i] == lastval) continue; //skip until we hit a transition

        //find out how many bits (n) we collected (use 1/2 clk tolerance)

        if (dest[i - 1] == 1)
            //if lastval was 1, we have a 1->0 crossing
            n = (n * fclow + hclk) / clk;
        else
            // 0->1 crossing
            n = (n * fchigh + hclk) / clk;

        if (n == 0)
            n = 1;

        //first transition - save startidx
        if (numBits == 0) {
            if (lastval == 1) {  //high to low
                *startIdx += (fclow * i) - (n * clk);
                if (g_debugMode == 2) prnt("DEBUG (aggregate_bits) FSK startIdx %i, fclow*idx %zu, n*clk %u", *startIdx, fclow * i, n * clk);
            } else {
                *startIdx += (fchigh * i) - (n * clk);
                if (g_debugMode == 2) prnt("DEBUG (aggregate_bits) FSK startIdx %i, fchigh*idx %zu, n*clk %u", *startIdx, fchigh * i, n * clk);
            }
        }

        //add to our destination the bits we collected
        memset(dest + numBits, dest[i - 1] ^ invert, n);

        numBits += n;
        n = 0;
        lastval = dest[i];

    }//end for

    // if valid extra bits at the end were all the same frequency - add them in
    if (n > clk / fchigh) {
        if (dest[i - 2] == 1) {
            n = (n * fclow + clk / 2) / clk;
        } else {
            n = (n * fchigh + clk / 2) / clk;
        }
        memset(dest + numBits, dest[i - 1] ^ invert, n);
        numBits += n;
        if (g_debugMode == 2) prnt("DEBUG (aggregate_bits) extra bits in the end");
    }
    return numBits;
}

// full fsk demod from GraphBuffer wave to decoded 1s and 0s (no mandemod)
size_t fskdemod(uint8_t *dest, size_t size, uint8_t rfLen, uint8_t invert, uint8_t fchigh, uint8_t fclow, int *start_idx) {
    if (signalprop.isnoise) return 0;
    // FSK demodulator
    size = fsk_wave_demod(dest, size, fchigh, fclow, start_idx);
    if (g_debugMode == 2) prnt("DEBUG (fskdemod) got %zu bits", size);
    size = aggregate_bits(dest, size, rfLen, invert, fchigh, fclow, start_idx);
    if (g_debugMode == 2) prnt("DEBUG (fskdemod) got %zu bits", size);
    return size;
}

// convert psk1 demod to psk2 demod
// only transition waves are 1s
// TODO: Iceman - hard coded value 7,  should be #define
void psk1TOpsk2(uint8_t *bits, size_t size) {
    uint8_t lastbit = bits[0];
    for (size_t i = 1; i < size; i++) {
        //ignore errors
        if (bits[i] == 7) continue;

        if (lastbit != bits[i]) {
            lastbit = bits[i];
            bits[i] = 1;
        } else {
            bits[i] = 0;
        }
    }
}

// convert psk2 demod to psk1 demod
// from only transition waves are 1s to phase shifts change bit
void psk2TOpsk1(uint8_t *bits, size_t size) {
    uint8_t phase = 0;
    for (size_t i = 0; i < size; i++) {
        if (bits[i] == 1) {
            phase ^= 1;
        }
        bits[i] = phase;
    }
}

// demodulate PSK1 wave
// uses wave lengths (# Samples)
// TODO: Iceman - hard coded value 7,  should be #define
int pskRawDemod_ext(uint8_t *dest, size_t *size, int *clock, const int *invert, int *startIdx) {

    // sanity check
    if (*size < 170) return -1;

    uint8_t curPhase = *invert;
    uint8_t fc = 0;
    size_t i = 0, numBits = 0, waveStart = 1, waveEnd, firstFullWave = 0, lastClkBit = 0;
    uint16_t fullWaveLen = 0, waveLenCnt;
    //uint16_t avgWaveVal = 0;
    uint16_t errCnt = 0, errCnt2 = 0;

    *clock = DetectPSKClock(dest, *size, *clock, &firstFullWave, &curPhase, &fc);
    if (*clock <= 0) return -1;
    //if clock detect found firstfullwave...
    uint16_t tol = fc / 2;
    if (firstFullWave == 0) {
        //find start of modulating data in trace
        i = findModStart(dest, *size, fc);
        //find first phase shift
        firstFullWave = pskFindFirstPhaseShift(dest, *size, &curPhase, i, fc, &fullWaveLen);
        if (firstFullWave == 0) {
            // no phase shift detected - could be all 1's or 0's - doesn't matter where we start
            // so skip a little to ensure we are past any Start Signal
            firstFullWave = 160;
            memset(dest, curPhase, firstFullWave / *clock);
        } else {
            memset(dest, curPhase ^ 1, firstFullWave / *clock);
        }
    } else {
        memset(dest, curPhase ^ 1, firstFullWave / *clock);
    }
    //advance bits
    numBits += (firstFullWave / *clock);
    *startIdx = firstFullWave - (*clock * numBits) + 2;
    //set start of wave as clock align
    lastClkBit = firstFullWave;
    if (g_debugMode == 2) {
        prnt("DEBUG PSK: firstFullWave: %zu, waveLen: %u, startIdx %i", firstFullWave, fullWaveLen, *startIdx);
        prnt("DEBUG PSK: clk: %d, lastClkBit: %zu, fc: %u", *clock, lastClkBit, fc);
    }

    waveStart = 0;
    dest[numBits++] = curPhase; //set first read bit
    for (i = firstFullWave + fullWaveLen - 1; i < *size - 3; i++) {
        //top edge of wave = start of new wave
        if (dest[i] + fc < dest[i + 1] && dest[i + 1] >= dest[i + 2]) {
            if (waveStart == 0) {
                waveStart = i + 1;
                //avgWaveVal = dest[i + 1];
            } else { //waveEnd
                waveEnd = i + 1;
                waveLenCnt = waveEnd - waveStart;
                if (waveLenCnt > fc) {
                    //this wave is a phase shift
                    /*
                    prnt("DEBUG: phase shift at: %d, len: %d, nextClk: %d, i: %d, fc: %d"
                        , waveStart
                        , waveLenCnt
                        , lastClkBit + *clock - tol
                        , i + 1
                        , fc);
                      */
                    if (i + 1 >= lastClkBit + *clock - tol) { //should be a clock bit
                        curPhase ^= 1;
                        dest[numBits++] = curPhase;
                        lastClkBit += *clock;
                    } else if (i < lastClkBit + 10 + fc) {
                        //noise after a phase shift - ignore
                    } else { //phase shift before supposed to based on clock
                        errCnt++;
                        dest[numBits++] = 7;
                    }
                } else if (i + 1 > lastClkBit + *clock + tol + fc) {
                    lastClkBit += *clock; //no phase shift but clock bit
                    dest[numBits++] = curPhase;
                } else if (waveLenCnt < fc - 1) { //wave is smaller than field clock (shouldn't happen often)
                    errCnt2++;
                    if (errCnt2 > 101) return errCnt2;
                    //avgWaveVal += dest[i + 1];
                    continue;
                }
                //avgWaveVal = 0;
                waveStart = i + 1;
            }
        }
        //avgWaveVal += dest[i + 1];
    }
    *size = numBits;
    return errCnt;
}

int pskRawDemod(uint8_t *dest, size_t *size, int *clock, int *invert) {
    int start_idx = 0;
    return pskRawDemod_ext(dest, size, clock, invert, &start_idx);
}


// **********************************************************************************************
// -----------------Tag format detection section-------------------------------------------------
// **********************************************************************************************

// FSK Demod then try to locate an AWID ID
int detectAWID(uint8_t *dest, size_t *size, int *waveStartIdx) {
    //make sure buffer has enough data (96bits * 50clock samples)
    if (*size < 96 * 50) return -1;

    if (signalprop.isnoise) return -2;

    // FSK2a demodulator  clock 50, invert 1, fcHigh 10, fcLow 8
    *size = fskdemod(dest, *size, 50, 1, 10, 8, waveStartIdx); //awid fsk2a

    //did we get a good demod?
    if (*size < 96) return -3;

    size_t start_idx = 0;
    uint8_t preamble[] = {0, 0, 0, 0, 0, 0, 0, 1};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &start_idx))
        return -4; //preamble not found

    // wrong size?  (between to preambles)
    if (*size != 96) return -5;

    return (int)start_idx;
}

// takes 1s and 0s and searches for EM410x format - output EM ID
int Em410xDecode(uint8_t *bits, size_t *size, size_t *start_idx, uint32_t *hi, uint64_t *lo) {
    // sanity check
    if (bits[1] > 1) return -1;
    if (*size < 64) return -2;

    *start_idx = 0;

    // preamble 0111111111
    // include 0 in front to help get start pos
    uint8_t preamble[] = {0, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    if (!preambleSearch(bits, preamble, sizeof(preamble), size, start_idx))
        return -4;

    bool validShort = false;
    bool validShortExtended = false;
    bool validLong = false;
    *size = removeEm410xParity(bits, *start_idx + sizeof(preamble), *size == 128, &validShort, &validShortExtended, &validLong);

    if (validShort) {
        // std em410x format
        *hi = 0;
        *lo = ((uint64_t)(bytebits_to_byte(bits, 8)) << 32) | (bytebits_to_byte(bits + 8, 32));
        // 1 = Short
        return 1;
    }
    if (validShortExtended || validLong) {
        // store in long em format
        *hi = (bytebits_to_byte(bits, 24));
        *lo = ((uint64_t)(bytebits_to_byte(bits + 24, 32)) << 32) | (bytebits_to_byte(bits + 24 + 32, 32));
        // 2 = Long
        // 4 = ShortExtended
        return ((int)validShortExtended << 2) + ((int)validLong << 1);
    }
    return -6;
}

// loop to get raw HID waveform then FSK demodulate the TAG ID from it
int HIDdemodFSK(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo, int *waveStartIdx) {
    //make sure buffer has data
    if (*size < 96 * 50) return -1;

    if (signalprop.isnoise) return -2;

    // FSK demodulator  fsk2a so invert and fc/10/8
    *size = fskdemod(dest, *size, 50, 1, 10, 8, waveStartIdx); //hid fsk2a

    //did we get a good demod?
    if (*size < 96 * 2) return -3;

    // 00011101 bit pattern represent start of frame, 01 pattern represents a 0 and 10 represents a 1
    size_t start_idx = 0;
    uint8_t preamble[] = {0, 0, 0, 1, 1, 1, 0, 1};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &start_idx))
        return -4; //preamble not found

    // wrong size?  (between to preambles)
    //if (*size != 96) return -5;

    size_t num_start = start_idx + sizeof(preamble);
    // final loop, go over previously decoded FSK data and manchester decode into usable tag ID
    for (size_t idx = num_start; (idx - num_start) < *size - sizeof(preamble); idx += 2) {
        if (dest[idx] == dest[idx + 1]) {
            return -5; //not manchester data
        }
        *hi2 = (*hi2 << 1) | (*hi >> 31);
        *hi = (*hi << 1) | (*lo >> 31);
        //Then, shift in a 0 or one into low
        *lo <<= 1;
        if (dest[idx] && !dest[idx + 1]) // 1 0
            *lo |= 1;
        else // 0 1
            *lo |= 0;
    }
    return (int)start_idx;
}

int detectIOProx(uint8_t *dest, size_t *size, int *waveStartIdx) {
    //make sure buffer has data
    if (*size < 66 * 64) return -1;

    if (signalprop.isnoise) return -2;

    // FSK demodulator  RF/64, fsk2a so invert, and fc/10/8
    *size = fskdemod(dest, *size, 64, 1, 10, 8, waveStartIdx);  //io fsk2a

    //did we get enough demod data?
    if (*size < 64) return -3;

    //Index map
    //0           10          20          30          40          50          60
    //|           |           |           |           |           |           |
    //01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
    //-----------------------------------------------------------------------------
    //00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1 ???????? 11
    //
    //XSF(version)facility:codeone+codetwo

    size_t start_idx = 0;
    uint8_t preamble[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &start_idx))
        return -4; //preamble not found

    // wrong size?  (between to preambles)
    if (*size != 64) return -5;

    if (!dest[start_idx + 8]
            && dest[start_idx + 17] == 1
            && dest[start_idx + 26] == 1
            && dest[start_idx + 35] == 1
            && dest[start_idx + 44] == 1
            && dest[start_idx + 53] == 1) {
        //confirmed proper separator bits found
        //return start position
        return (int) start_idx;
    }
    return -6;
}
