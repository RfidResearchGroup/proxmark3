// Copyright (C) 2014
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency demod related commands
// marshmellow
// note that many of these demods are not the slickest code and they often rely
//   on peaks and clock instead of converting to clean signal. 
//   
//-----------------------------------------------------------------------------

#ifndef LFDEMOD_H__
#define LFDEMOD_H__
#include <stdint.h>  // for uint_32+
#include <stdbool.h> // for bool
#include <string.h>  // for strcmp 
#include <stdlib.h>  // for
#include <stdbool.h> // for bool
#include "parity.h"  // for parity test

//generic
typedef struct {
	int low;
	int high;
	int mean;
	int amplitude;
	bool isnoise;
} signal_t;
extern signal_t* getSignalProperties(void);

extern uint32_t	compute_mean_uint(uint8_t *in, size_t N);
extern int32_t	compute_mean_int(int *in, size_t N);

extern bool		justNoise_int(int *bits, uint32_t size);
extern bool		justNoise(uint8_t *bits, uint32_t size);

void getNextLow(uint8_t *samples, size_t size, int low, size_t *i);
void getNextHigh(uint8_t *samples, size_t size, int high, size_t *i);
bool loadWaveCounters(uint8_t *samples, size_t size, int lowToLowWaveLen[], int highToLowWaveLen[], int *waveCnt, int *skip, int *minClk, int *high, int *low);
size_t pskFindFirstPhaseShift(uint8_t *samples, size_t size, uint8_t *curPhase, size_t waveStart, uint16_t fc, uint16_t *fullWaveLen);

extern size_t   addParity(uint8_t *src, uint8_t *dest, uint8_t sourceLen, uint8_t pLen, uint8_t pType);
extern int      askdemod(uint8_t *bits, size_t *size, int *clk, int *invert, int maxErr, uint8_t amp, uint8_t askType);
extern int      askdemod_ext(uint8_t *bits, size_t *size, int *clk, int *invert, int maxErr, uint8_t amp, uint8_t askType, int *startIdx);
extern void     askAmp(uint8_t *bits, size_t size);
extern int      BiphaseRawDecode(uint8_t *bits, size_t *size, int *offset, int invert);
extern uint8_t bits_to_array(const uint8_t *bits, size_t size, uint8_t *dest);
extern uint32_t bytebits_to_byte(uint8_t *src, size_t numbits);
extern uint32_t bytebits_to_byteLSBF(uint8_t *src, size_t numbits);
extern uint16_t countFC(uint8_t *bits, size_t size, uint8_t fskAdj);
extern int      DetectASKClock(uint8_t *dest, size_t size, int *clock, int maxErr);
extern uint8_t  DetectCleanAskWave(uint8_t *dest, size_t size, uint8_t high, uint8_t low);
extern uint8_t  detectFSKClk(uint8_t *bits, size_t size, uint8_t fcHigh, uint8_t fcLow, int *firstClockEdge);
extern int      DetectNRZClock(uint8_t *dest, size_t size, int clock, size_t *clockStartIdx);
extern int      DetectPSKClock(uint8_t *dest, size_t size, int clock, size_t *firstPhaseShift, uint8_t *curPhase, uint8_t *fc);
extern int      DetectStrongAskClock(uint8_t *dest, size_t size, int high, int low, int *clock);
extern bool     DetectST(uint8_t *buffer, size_t *size, int *foundclock, size_t *ststart, size_t *stend);
extern size_t   fskdemod(uint8_t *dest, size_t size, uint8_t rfLen, uint8_t invert, uint8_t fchigh, uint8_t fclow, int *startIdx);
extern int      getHiLo(uint8_t *bits, size_t size, int *high, int *low, uint8_t fuzzHi, uint8_t fuzzLo);
extern uint32_t manchesterEncode2Bytes(uint16_t datain);
extern int      ManchesterEncode(uint8_t *bits, size_t size);
extern int      manrawdecode(uint8_t *bits, size_t *size, uint8_t invert, uint8_t *alignPos);
extern int      nrzRawDemod(uint8_t *dest, size_t *size, int *clk, int *invert, int *startIdx);
extern bool     parityTest(uint32_t bits, uint8_t bitLen, uint8_t pType);
extern bool		preambleSearch(uint8_t *bits, uint8_t *preamble, size_t pLen, size_t *size, size_t *startIdx);
extern bool		preambleSearchEx(uint8_t *bits, uint8_t *preamble, size_t pLen, size_t *size, size_t *startIdx, bool findone);
extern int      pskRawDemod(uint8_t *dest, size_t *size, int *clock, int *invert);
extern int      pskRawDemod_ext(uint8_t *dest, size_t *size, int *clock, int *invert, int *startIdx);
extern void     psk2TOpsk1(uint8_t *bits, size_t size);
extern void     psk1TOpsk2(uint8_t *bits, size_t size);
extern size_t   removeParity(uint8_t *bits, size_t startIdx, uint8_t pLen, uint8_t pType, size_t bLen);

//tag specific
extern int detectAWID(uint8_t *dest, size_t *size, int *waveStartIdx);
extern int Em410xDecode(uint8_t *dest, size_t *size, size_t *startIdx, uint32_t *hi, uint64_t *lo);
extern int HIDdemodFSK(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo, int *waveStartIdx);
extern int detectIdteck(uint8_t *dest, size_t *size);
extern int detectIOProx(uint8_t *dest, size_t *size, int *waveStartIdx);
#endif
