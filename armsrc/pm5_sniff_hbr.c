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
// Proxmark5 14a sniffer at 212 / 424 / 848 kbit/s: decoders for the bytes the 14a sniffer image sends after a PPS.
// Reader: modified Miller, 4 slots a bit at 212 kbit/s (2 at 424 / 848); the first pause in data bit 0 fixes the grid.
// Tag: the FPGA's bits without preamble and start bit; bytes LSB first with odd parity, the last without, then an end
// bit; a frame ends after 2 bytes without a bit. See doc/md/PM5_Start_Here/PM5-14A-SNIFF.md, 5.3.
//-----------------------------------------------------------------------------
#include "pm5_sniff_hbr.h"

static uint8_t odd_parity8(uint8_t v) {
    v ^= v >> 4;
    v ^= v >> 2;
    v ^= v >> 1;
    return (~v) & 1;
}

void MillerHbrInit(tMillerHbr *m, uint8_t *output, uint8_t *parity, uint16_t output_len) {
    m->output = output;
    m->parity = parity;
    m->output_len = output_len;
    m->last = 1;
    m->spb = 4;
    MillerHbrReset(m);
}

// 424 / 848 kbit/s: a bit is 2 slots, a half bit one (848: the FPGA sends bytes twice as often, slots of 8 samples), so
// pauses sit on the slot grid (the FPGA puts their starts mid-slot)
void MillerHbrSetRate(tMillerHbr *m, uint8_t rate) {
    m->spb = (rate == 2 || rate == 3) ? 2 : 4;
}

void MillerHbrReset(tMillerHbr *m) {
    m->state = 0;
    m->len = 0;
    m->shift = -1;
    m->pend = 0;
    m->rel = 0;
    m->prevbit = 0;
    m->shiftReg = 0;
    m->bitCount = 0;
    m->parityBits = 0;
    m->parityLen = 0;
}

static void mhbr_bit(tMillerHbr *m, uint8_t bit) {
    m->shiftReg |= (uint16_t)bit << m->bitCount;
    m->prevbit = bit;
    if (++m->bitCount == 9) {
        if (m->len < m->output_len) {
            m->output[m->len++] = m->shiftReg & 0xFF;
            m->parityBits = (m->parityBits << 1) | ((m->shiftReg >> 8) & 1);
            if ((m->len & 7) == 0) {
                m->parity[m->parityLen++] = m->parityBits;
                m->parityBits = 0;
            }
        }
        m->shiftReg = 0;
        m->bitCount = 0;
    }
}

// end of communication; true when the frame had data. As the 106 decoder (MillerDecoding).
static bool mhbr_end(tMillerHbr *m) {
    m->state = 0;
    if (m->bitCount > 0) {
        m->bitCount--;                                  // the last 0 belongs to the end of communication
        m->shiftReg &= (1u << m->bitCount) - 1;
    }
    if (m->bitCount > 0 && m->len < m->output_len) {    // some bits of a last, short byte
        m->output[m->len++] = m->shiftReg & 0xFF;
        m->parityBits <<= 1;                            // a (void) parity bit
        m->parityBits <<= (8 - (m->len & 7));
        m->parity[m->parityLen++] = m->parityBits;
        return true;
    }
    if (m->len & 7) {
        m->parityBits <<= (8 - (m->len & 7));           // left align the remaining parity bits
        m->parity[m->parityLen++] = m->parityBits;
    }
    return m->len > 0;
}

bool MillerHbrDecode(tMillerHbr *m, uint8_t nibble, uint32_t t, uint8_t slot) {
    bool done = false;
    for (int k = 3; k >= 0; k--) {
        uint8_t level = (nibble >> k) & 1;
        bool start = (m->last == 1 && level == 0);
        m->last = level;
        uint32_t now = t + (3 - k) * slot;
        if (done) {
            continue;                       // a frame ended in this nibble: the next one cannot start in it
        }

        if (m->state == 0) {
            if (start) {
                MillerHbrReset(m);
                m->state = 1;
                m->startTime = now;
                m->lastPause = now;
            }
            continue;
        }

        m->rel++;
        if (start) {
            m->lastPause = now;
        }
        uint8_t spb = m->spb;
        if (m->shift < 0) {
            if (start) {
                // data bit 0's pause: Z at 4, X at 6 at 212 (one more if shifted); at 424 Z at 2, X at 3
                m->shift = (spb == 4) ? (m->rel & 1) : 0;
            } else if (m->rel > 2 * spb) {
                m->state = 0;               // no data bit: not a frame
                continue;
            }
        }
        if (m->shift < 0) {
            continue;
        }
        int rr = m->rel - m->shift;
        // a bit's window ends where the next one's starts: decide it before taking this slot's pause
        if (rr >= 2 * spb && (rr & (spb - 1)) == 0) {
            if (m->pend == 2) {
                mhbr_bit(m, 1);
            } else if (m->pend == 1) {
                mhbr_bit(m, 0);
            } else if (m->prevbit == 1) {
                mhbr_bit(m, 0);
            } else {
                m->endTime = now;
                done = mhbr_end(m);
                continue;
            }
            m->pend = 0;
        }
        if (start && rr >= spb) {
            m->pend = ((rr & (spb - 1)) >= spb / 2) ? 2 : 1;
        }
        if (m->len >= m->output_len) {
            m->endTime = now;
            done = mhbr_end(m);
        }
    }
    return done;
}

void BpskHbrInit(tBpskHbr *b, uint8_t *output, uint8_t *parity, uint16_t output_len) {
    b->output = output;
    b->parity = parity;
    b->output_len = output_len > PM5_SNIFF_HBR_MAX_FRAME ? PM5_SNIFF_HBR_MAX_FRAME : output_len;
    BpskHbrReset(b);
}

void BpskHbrReset(tBpskHbr *b) {
    b->state = 0;
    b->len = 0;
    b->quiet = 0;
    b->shiftReg = 0;
    b->bitCount = 0;
}

static bool bhbr_end(tBpskHbr *b) {
    b->state = 0;
    // under 3 bytes is noise: every block at these rates has its CRC (a card working on a command)
    if (b->len < 3) {
        return false;
    }
    // the last byte has no parity bit (its 9th bit is the end of frame): store the one it would have
    b->par[b->len - 1] = odd_parity8(b->output[b->len - 1]);
    for (uint16_t i = 0; i < (b->len + 7) / 8; i++) {
        b->parity[i] = 0;
    }
    for (uint16_t i = 0; i < b->len; i++) {
        b->parity[i / 8] |= b->par[i] << (7 - (i & 7));
    }
    return true;
}

bool BpskHbrDecode(tBpskHbr *b, uint8_t nibble, uint32_t t, uint8_t slot) {
    uint8_t got = 0;
    for (int k = 0; k < 2; k++) {
        uint8_t valid = (nibble >> (3 - 2 * k)) & 1;
        uint8_t bit = (nibble >> (2 - 2 * k)) & 1;
        if (valid == 0) {
            continue;
        }
        got++;
        if (b->state == 0) {
            BpskHbrReset(b);
            b->state = 1;
            b->startTime = t + k * 2 * slot;    // the second bit of a byte comes half a byte later
        }
        b->shiftReg |= (uint16_t)bit << b->bitCount;
        if (++b->bitCount == 9) {
            if (b->len < b->output_len) {
                b->output[b->len] = b->shiftReg & 0xFF;
                b->par[b->len] = (b->shiftReg >> 8) & 1;
                b->len++;
            }
            b->shiftReg = 0;
            b->bitCount = 0;
        }
        b->endTime = t + 4 * slot;      // the byte's end
    }
    if (b->state == 1) {
        if (got) {
            b->quiet = 0;
        } else if (++b->quiet == 2) {
            return bhbr_end(b);
        }
        if (b->len >= b->output_len) {
            return bhbr_end(b);
        }
    }
    return false;
}

// per FPGA rate code 1 .. 3 (212 / 424 / 848 kbit/s), in fc, measured on recorded captures replayed through the
// gateware: from a pause's slot time back to its half-height start, a pause's half-height width, and from a card's
// first data bit back to its answer's first modulation (the preamble, the start bit and the demodulator's lag)
static const uint16_t mhbr_lag[3] = {111, 110, 57};
static const uint16_t mhbr_width[3] = {28, 19, 10};
static const uint16_t bhbr_lag[3] = {687, 572, 563};

void MillerHbrAirTimes(const tMillerHbr *m, uint8_t rate, uint32_t *start, uint32_t *end) {
    uint8_t i = (rate >= 1 && rate <= 3) ? rate - 1 : 0;
    *start = m->startTime - mhbr_lag[i];
    *end = m->lastPause - mhbr_lag[i] + mhbr_width[i];
}

void BpskHbrAirTimes(const tBpskHbr *b, uint8_t rate, uint32_t *start, uint32_t *end) {
    uint8_t i = (rate >= 1 && rate <= 3) ? rate - 1 : 0;
    uint32_t bit = 128 >> (i + 1);                      // 64, 32, 16 fc
    *start = b->startTime - bhbr_lag[i];
    // a 512 fc preamble, the start bit, 9 bits a byte (the last byte's ninth is the end of frame)
    *end = *start + 512 + bit * (9 * b->len + 1);
}
