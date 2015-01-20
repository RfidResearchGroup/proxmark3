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
#include <stdint.h>

int DetectASKClock(uint8_t dest[], size_t size, int clock);
int askmandemod(uint8_t *BinStream, size_t *size, int *clk, int *invert);
uint64_t Em410xDecode(uint8_t *BitStream, size_t *size, size_t *startIdx);
int ManchesterEncode(uint8_t *BitStream, size_t size);
int manrawdecode(uint8_t *BitStream, size_t *size);
int BiphaseRawDecode(uint8_t * BitStream, size_t *size, int offset, int invert);
int askrawdemod(uint8_t *BinStream, size_t *size, int *clk, int *invert);
int HIDdemodFSK(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo);
int IOdemodFSK(uint8_t *dest, size_t size);
int fskdemod(uint8_t *dest, size_t size, uint8_t rfLen, uint8_t invert, uint8_t fchigh, uint8_t fclow);
uint32_t bytebits_to_byte(uint8_t* src, size_t numbits);
int pskNRZrawDemod(uint8_t *dest, size_t *size, int *clk, int *invert);
int DetectpskNRZClock(uint8_t dest[], size_t size, int clock);
int indala26decode(uint8_t *bitStream, size_t *size, uint8_t *invert);
void pskCleanWave(uint8_t *bitStream, size_t size);
int PyramiddemodFSK(uint8_t *dest, size_t size);
int AWIDdemodFSK(uint8_t *dest, size_t size);
size_t removeParity(uint8_t *BitStream, size_t startIdx, uint8_t pLen, uint8_t pType, size_t bLen);
uint32_t countFC(uint8_t *BitStream, size_t size);
int getHiLo(uint8_t *BitStream, size_t size, int *high, int *low, uint8_t fuzzHi, uint8_t fuzzLo);
size_t ParadoxdemodFSK(uint8_t *dest, size_t *size, uint32_t *hi2, uint32_t *hi, uint32_t *lo);

#endif
