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
// Low frequency demod related commands
// note that many of these demods are not the slickest code and they often rely
//   on peaks and clock instead of converting to clean signal.
//-----------------------------------------------------------------------------

#ifndef LFDEMOD_H__
#define LFDEMOD_H__

#include "common.h"

// might not be high enough for noisy environments
#define NOISE_AMPLITUDE_THRESHOLD 8
// ignore buffer with less than x samples
#define SIGNAL_MIN_SAMPLES 100
// ignore first x samples of the buffer
#define SIGNAL_IGNORE_FIRST_SAMPLES 10

// generic
typedef struct {
    int low;
    int high;
    int mean;
    int amplitude;
    bool isnoise;
} signal_t;
signal_t *getSignalProperties(void);

void computeSignalProperties(const uint8_t *samples, uint32_t size);
void removeSignalOffset(uint8_t *samples, uint32_t size);
void getNextLow(const uint8_t *samples, size_t size, int low, size_t *i);
void getNextHigh(const uint8_t *samples, size_t size, int high, size_t *i);
bool loadWaveCounters(uint8_t *samples, size_t size, int lowToLowWaveLen[], int highToLowWaveLen[], int *waveCnt, int *skip, int *minClk, int *high, int *low);
size_t pskFindFirstPhaseShift(const uint8_t *samples, size_t size, uint8_t *curPhase, size_t waveStart, uint16_t fc, uint16_t *fullWaveLen);

size_t addParity(const uint8_t *src, uint8_t *dest, uint8_t sourceLen, uint8_t pLen, uint8_t pType);
int askdemod(uint8_t *bits, size_t *size, int *clk, int *invert, int maxErr, uint8_t amp, uint8_t askType);
int askdemod_ext(uint8_t *bits, size_t *size, int *clk, int *invert, int maxErr, uint8_t amp, uint8_t askType, int *startIdx);
void askAmp(uint8_t *bits, size_t size);
int BiphaseRawDecode(uint8_t *bits, size_t *size, int *offset, int invert);
int bits_to_array(const uint8_t *bits, size_t size, uint8_t *dest);
uint32_t bytebits_to_byte(uint8_t *src, size_t numbits);
uint32_t bytebits_to_byteLSBF(uint8_t *src, size_t numbits);
uint16_t countFC(const uint8_t *bits, size_t size, bool fskAdj);
int DetectASKClock(uint8_t *dest, size_t size, int *clock, int maxErr);
bool DetectCleanAskWave(const uint8_t *dest, size_t size, uint8_t high, uint8_t low);
uint8_t detectFSKClk(const uint8_t *bits, size_t size, uint8_t fcHigh, uint8_t fcLow, int *firstClockEdge);
int DetectNRZClock(uint8_t *dest, size_t size, int clock, size_t *clockStartIdx);
int DetectPSKClock(uint8_t *dest, size_t size, int clock, size_t *firstPhaseShift, uint8_t *curPhase, uint8_t *fc);
int DetectStrongAskClock(uint8_t *dest, size_t size, int high, int low, int *clock);
int DetectStrongNRZClk(const uint8_t *dest, size_t size, int peak, int low, bool *strong);
bool DetectST(uint8_t *buffer, size_t *size, int *foundclock, size_t *ststart, size_t *stend);
size_t fskdemod(uint8_t *dest, size_t size, uint8_t rfLen, uint8_t invert, uint8_t fchigh, uint8_t fclow, int *start_idx);
// void getHiLo(uint8_t *bits, size_t size, int *high, int *low, uint8_t fuzzHi, uint8_t fuzzLo);
void getHiLo(int *high, int *low, uint8_t fuzzHi, uint8_t fuzzLo);
uint32_t manchesterEncode2Bytes(uint16_t datain);
void manchesterEncodeUint32(uint32_t data_in, uint8_t bitlen_in, uint8_t *bits_out, uint16_t *index);
int ManchesterEncode(uint8_t *bits, size_t size);
uint16_t manrawdecode(uint8_t *bits, size_t *size, uint8_t invert, uint8_t *alignPos);
int nrzRawDemod(uint8_t *dest, size_t *size, int *clk, const int *invert, int *startIdx);
bool parityTest(uint32_t bits, uint8_t bitLen, uint8_t pType);
bool preambleSearch(uint8_t *bits, uint8_t *preamble, size_t pLen, size_t *size, size_t *startIdx);
bool preambleSearchEx(uint8_t *bits, uint8_t *preamble, size_t pLen, size_t *size, size_t *startIdx, bool findone);
int pskRawDemod(uint8_t *dest, size_t *size, int *clock, int *invert);
int pskRawDemod_ext(uint8_t *dest, size_t *size, int *clock, const int *invert, int *startIdx);
void psk2TOpsk1(uint8_t *bits, size_t size);
void psk1TOpsk2(uint8_t *bits, size_t size);
size_t removeParity(uint8_t *bits, size_t startIdx, uint8_t pLen, uint8_t pType, size_t bLen);

// tag specific
int detectAWID(uint8_t *dest, size_t *size, int *waveStartIdx);
int Em410xDecode(uint8_t *bits, size_t *size, size_t *start_idx, uint32_t *hi, uint64_t *lo);
int HIDdemodFSK(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo, int *waveStartIdx);
int detectIOProx(uint8_t *dest, size_t *size, int *waveStartIdx);

#endif
