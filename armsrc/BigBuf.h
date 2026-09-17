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
// BigBuf and functions to allocate/free parts of it.
//-----------------------------------------------------------------------------

#ifndef __BIGBUF_H
#define __BIGBUF_H

#include "common.h"

#define MAX_FRAME_SIZE          256 // maximum allowed ISO14443 frame
// The 14a demodulator stores 8 parity bits per 8 received bytes and then flushes
// one more byte once the receive buffer is full, so a full MAX_FRAME_SIZE frame
// needs (MAX_FRAME_SIZE / 8) + 1 parity bytes, not (MAX_FRAME_SIZE + 7) / 8
#define MAX_PARITY_SIZE         ((MAX_FRAME_SIZE / 8) + 1)
#define MAX_MIFARE_FRAME_SIZE   19  // biggest Mifare frame is UL AES answer to AUTH (1 + 16 Bytes) + 2 Bytes CRC
#define MAX_MIFARE_PARITY_SIZE  3   // need 19 parity bits for the 19 Byte above. 3 Bytes are enough to store these
// How much of BigBuf a card image may use.  A MIFARE Classic 4K fills 4096 of
// this exactly, so at that size emulator memory was fully committed and nothing
// larger could be simulated at all.
//
// This is carved out of BigBuf, which on AT91 is 33272 bytes, so every byte here
// is a byte traces and LF samples do not get.  The largest allocation any tag
// simulation makes alongside it is 10459 bytes total, leaving 18.7 kB of trace
// at this size.  LF acquisition is unaffected either way -- lfops.c calls
// BigBuf_free(), which drops emulator memory entirely.
//
// The device reports this to the client in capabilities_t, so the client sizes
// eload / esave from what the device has rather than a copy of this constant.
#define CARD_MEMORY_SIZE        8192
// For now we're storing FM11RF08S nonces in the upper 1k of CARD_MEMORY_SIZE
// but we might have to allocate extra space if one day we've to support sth like a FM11RF32S
#define CARD_MEMORY_RF08S_OFFSET 1024

//#define DMA_BUFFER_SIZE         (512 + 256)
#define DMA_BUFFER_SIZE         512

// 8 data bits and 1 parity bit per payload byte, 1 correction bit, 1 SOC bit, 2 EOC bits
#define TOSEND_BUFFER_SIZE (9 * MAX_FRAME_SIZE + 1 + 1 + 2)

uint8_t *BigBuf_get_addr(void);
uint32_t BigBuf_get_size(void);
uint8_t *BigBuf_get_EM_addr(void);
uint32_t BigBuf_get_EM_size(void);
bool BigBuf_is_EM_allocated(void);
uint32_t BigBuf_max_traceLen(void);
uint32_t BigBuf_get_hi(void);

void BigBuf_initialize(void);
void BigBuf_Clear(void);
void BigBuf_Clear_ext(bool verbose);
void BigBuf_Clear_keep_EM(void);
void BigBuf_Clear_EM(void);
uint8_t *BigBuf_malloc(uint32_t);
uint8_t *BigBuf_calloc(uint32_t);
void BigBuf_free(void);
void BigBuf_free_keep_EM(void);
void BigBuf_print_status(void);
uint32_t BigBuf_get_traceLen(void);
void clear_trace(void);
void set_tracing(bool enable);
bool set_tracing_blocked(bool blocked); // Returns the previous block state.
void set_tracelen(uint32_t value);
bool get_tracing(void);

void trace_restart_timeline(void);

bool RAMFUNC LogTrace(const uint8_t *btBytes, uint16_t iLen, uint32_t timestamp_start, uint32_t timestamp_end, const uint8_t *parity, bool reader2tag);
bool RAMFUNC LogTraceBits(const uint8_t *btBytes, uint16_t bitLen, uint32_t timestamp_start, uint32_t timestamp_end, bool reader2tag);
bool LogTrace_ISO15693(const uint8_t *bytes, uint16_t len, uint32_t ts_start, uint32_t ts_end, const uint8_t *parity, bool reader2tag);

int emlSet(const uint8_t *data, uint32_t offset, uint32_t length);
int emlGet(uint8_t *out, uint32_t offset, uint32_t length);

typedef struct {
    int max;
    int bit;
    uint8_t *buf;
} tosend_t;

tosend_t *get_tosend(void);
void tosend_reset(void);
void tosend_stuffbit(int b);

typedef struct {
    uint16_t size;
    uint8_t *buf;
} dmabuf8_t;

typedef struct {
    uint16_t size;
    uint16_t *buf;
} dmabuf16_t;

dmabuf8_t *get_dma8(void);
dmabuf16_t *get_dma16(void);
#endif /* __BIGBUF_H */
