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
// Proxmark5 14a sniffer: sample-accurate frame edges from the side bytes of the 14a sniffer image - see pm5_edges.c.
// No hardware access.
//-----------------------------------------------------------------------------
#ifndef PM5_EDGES_H__
#define PM5_EDGES_H__

#include <stdint.h>
#include <stdbool.h>

// times in fc, the decoders' time base (they wrap: compared by their differences)
typedef struct {
    uint32_t rl_first;          // the frame's first and last reader pause lead
    uint32_t rl_last;
    bool     rl;                // a lead seen since the sniff began
    uint32_t to;                // the tag onset (the decision)
    bool     to_ok;
    uint8_t  w_ref;             // this frame's latest clean pause width (EDGE_W with none)
    uint8_t  seq;               // the sequence number the next word carries if none was lost
    uint8_t  alt;               // the same if the last jump was real
    uint8_t  jump;              // words that jump skipped (0: none pending)
    bool     seq_ok;            // two idle words agreed (seq is known)
    uint8_t  bad;               // idle words out of sequence since the last one in it (a slipped link: >= PM5_EDGES_BAD)
    uint8_t  agree;             // idle words since that agree with the pending jump
} pm5_edges_t;

// idle words in a row out of sequence and not confirming a jump: the SSC came back on out of step with the 16-bit words
// (a gap gives 1, 2 with a cut word after it, 3 - 4 at a switch back from 848; the next idle words confirm the jump)
#define PM5_EDGES_BAD       8

void pm5_edges_init(pm5_edges_t *e);
// one word's side byte (0 for a word without one: 848); t_load = 64 x the word's 106 byte number + 63;
// tag_active: the tag decoder is synced. Returns the words found lost before it (FpgaSendCommand turns the SSC off for
// a word or two), confirmed by the idle word after: the caller moves its time base on by them
uint8_t pm5_edges_word(pm5_edges_t *e, uint8_t side, uint32_t t_load, bool tag_active);
// words the caller skipped (DMA overrun)
void pm5_edges_skip(pm5_edges_t *e, uint32_t n);
// pm5_edges_word with its common case inline: an idle word in sequence (from the sniff loop the call cost ~85 cycles)
static inline uint8_t pm5_edges_word_f(pm5_edges_t *e, uint8_t side, uint32_t t_load, bool tag_active) {
    if (side >= 0xE0 && e->seq_ok && e->jump == 0 && (side & 0x1F) == e->seq) {
        e->seq = (e->seq + 1) & 0x1F;
        e->alt = (e->alt + 1) & 0x1F;
        e->bad = 0;
        return 0;
    }
    return pm5_edges_word(e, side, t_load, tag_active);
}
// a decoded frame: ts / te = its decoder's start / end x 16. start / end come in as the slot times to log; each is
// replaced by its edge time where an event matched, else moved back by the slot times' lateness
void pm5_edges_reader(pm5_edges_t *e, uint32_t ts, uint32_t te, uint32_t *start, uint32_t *end);
void pm5_edges_tag(pm5_edges_t *e, uint32_t ts, uint32_t te, uint32_t *start, uint32_t *end);

#endif
