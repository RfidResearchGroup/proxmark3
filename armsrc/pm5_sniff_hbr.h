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
// Proxmark5 14a sniffer at 212 / 424 / 848 kbit/s: decoders for the bytes the 14a sniffer image sends - see
// pm5_sniff_hbr.c. No hardware access.
//-----------------------------------------------------------------------------
#ifndef PM5_SNIFF_HBR_H__
#define PM5_SNIFF_HBR_H__

#include <stdint.h>
#include <stdbool.h>

#define PM5_SNIFF_HBR_MAX_FRAME  256

// Reader -> tag, modified Miller, from the reader nibble (4 slots of 16 fc, 1 = carrier, oldest slot in bit 3)
typedef struct {
    uint8_t  *output;
    uint8_t  *parity;           // as the 106 decoders: 8 parity bits per byte, MSB first
    uint16_t output_len;
    uint16_t len;
    uint32_t startTime;         // in the units of MillerHbrDecode's t
    uint32_t endTime;
    uint32_t lastPause;         // the frame's last pause start
    uint8_t  state;             // 0 waiting for a pause, 1 in a frame
    uint8_t  last;              // previous slot's level
    int8_t   shift;             // the frame's slot grid offset: -1 not known yet
    uint8_t  pend;              // pause start seen in the current bit: 0 none, 1 Z, 2 X
    uint16_t rel;               // slots since the start of communication
    uint8_t  spb;               // slots per bit: 4 at 212 kbit/s, 2 at 424
    uint8_t  prevbit;
    uint16_t shiftReg;
    uint8_t  bitCount;
    uint8_t  parityBits;
    uint8_t  parityLen;
} tMillerHbr;

// Tag -> reader, BPSK, from the tag nibble {valid, bit, valid, bit} (the FPGA decides the bits)
typedef struct {
    uint8_t  *output;
    uint8_t  *parity;
    uint16_t output_len;
    uint16_t len;
    uint32_t startTime;         // the first data bit's half of its byte
    uint32_t endTime;
    uint8_t  state;             // 0 idle, 1 in a frame
    uint8_t  quiet;             // bytes without a bit
    uint16_t shiftReg;
    uint8_t  bitCount;
    uint8_t  par[PM5_SNIFF_HBR_MAX_FRAME];
} tBpskHbr;

void MillerHbrInit(tMillerHbr *m, uint8_t *output, uint8_t *parity, uint16_t output_len);
void MillerHbrReset(tMillerHbr *m);
void MillerHbrSetRate(tMillerHbr *m, uint8_t rate);   // FPGA rate code: 1 = 212, 2 = 424, 3 = 848 kbit/s
// one byte's reader nibble; t = time of its first slot, slot = a slot's length (the ARM: fc, 16, 8 at 848). True
// when a frame is complete.
bool MillerHbrDecode(tMillerHbr *m, uint8_t nibble, uint32_t t, uint8_t slot);

void BpskHbrInit(tBpskHbr *b, uint8_t *output, uint8_t *parity, uint16_t output_len);
void BpskHbrReset(tBpskHbr *b);
// one byte's tag nibble; t, slot as for MillerHbrDecode
bool BpskHbrDecode(tBpskHbr *b, uint8_t nibble, uint32_t t, uint8_t slot);

// a complete frame's times on the air, as the 106 kbit/s edge times (t in fc; rate: FPGA rate code 1 .. 3): the reader's
// first pause start and last pause end, the card's first modulation (its preamble) and end
void MillerHbrAirTimes(const tMillerHbr *m, uint8_t rate, uint32_t *start, uint32_t *end);
void BpskHbrAirTimes(const tBpskHbr *b, uint8_t rate, uint32_t *start, uint32_t *end);

#endif
