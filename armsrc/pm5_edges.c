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
// Proxmark5 14a sniffer: frame times to the sample, from the side bytes of the 14a sniffer image's 16-bit words
// (format: "The side byte" in fpga/pm5/pm5_hi_iso14443a.v). An event of age a in word N happened at 64 N + 63 - a fc;
// a frame with no matching event keeps its slot times less their median lateness (EDGE_SLOT_*).
// Method and measurements: doc/md/PM5_Start_Here/PM5-14A-SNIFF.md, 5.4.
//-----------------------------------------------------------------------------
#include "pm5_edges.h"

#define EDGE_TO_AGE0        3
#define DELAY_EDGE_READER   64      // the lead's own sample (rd_above's first, -2..+1 of the half-height start)
#define DELAY_EDGE_TAG      87      // DE32 decides 39 after the onset: 64 + 39 - 16
#define EDGE_W              32      // reader end = last lead + the frame's clean pause width (32 with none)
#define EDGE_WIN_R_LO      -160     // a frame's first lead, against the decoder's start x 16
#define EDGE_WIN_R_HI       32
#define EDGE_WIN_T_LO      -105     // the onset, against the decoder's start x 16 (measured -97..-67)
#define EDGE_WIN_T_HI      -59
#define EDGE_SPAN           8       // last - first lead against the decoder's grid
#define EDGE_GAP            300     // a lead this long after the last one begins a frame
#define EDGE_SPLIT_LO      -44      // a frame's end from its last lead when last lead - (end x 16 - 32) is in here
#define EDGE_SPLIT_HI      -6
#define EDGE_SLOT_T         158     // a tag frame's slot times, median lateness (start +158, end +159)
#define EDGE_SLOT_R         73      // a reader frame's (start +74, end +72)

void pm5_edges_init(pm5_edges_t *e) {
    e->rl_first = e->rl_last = e->to = 0;
    e->rl = e->to_ok = e->seq_ok = false;
    e->w_ref = EDGE_W;
    e->seq = e->alt = e->jump = e->bad = e->agree = 0;
}

uint8_t pm5_edges_word(pm5_edges_t *e, uint8_t side, uint32_t t_load, bool tag_active) {
    uint8_t k = 0;
    if (side >= 0xE0) {
        uint8_t s = side & 0x1F;
        if (e->seq_ok == false) {
            // in step once two idle words agree (the first word after the DMA starts can be cut)
            e->seq_ok = (e->jump && s == e->alt);
            e->jump = e->seq_ok ? 0 : 1;
            e->seq = e->alt = s;
        } else if (s == e->seq) {
            e->jump = 0;
            e->bad = 0;
            e->agree = 0;
        } else if (e->jump && s == e->alt && (e->bad <= 2 || e->agree >= 1)) {
            // the jump at the last idle word holds: words were lost there (one cut word cannot fake it). After more
            // idle words out of step (the 848 words still on their way at a switch back to 106, read as 106 ones), two
            // must agree: a slipped link's random ones hardly ever do
            k = e->jump;
            e->seq = s;
            e->jump = 0;
            e->bad = 0;
            e->agree = 0;
        } else if (e->jump && s == e->alt) {
            e->agree++;
        } else {
            e->jump = (s - e->seq) & 0x1F;
            e->alt = s;
            e->agree = 0;
            if (e->bad < 255) {
                e->bad++;
            }
        }
    } else if (side >= 0xC0) {
        e->w_ref = (side & 0x1F) + 24;
    } else if (side >= 0x80) {
        // not while an answer is decoded: field noise after it replaced its onset
        if (tag_active == false) {
            e->to = t_load - (side & 0x3F) - EDGE_TO_AGE0;
            e->to_ok = true;
        }
    } else if (side != 0) {
        uint32_t lead = t_load - side;
        if (e->rl == false || (int32_t)(lead - e->rl_last) > EDGE_GAP) {
            // a new frame: a width kept from an earlier one set the end of every frame after it, for the rest of the
            // sniff (where hardly a pause is clean, every exchange's FDT then came out off by the same amount)
            e->rl_first = lead;
            e->w_ref = EDGE_W;
        }
        e->rl_last = lead;
        e->rl = true;
    }
    e->seq = (e->seq + 1) & 0x1F;
    e->alt = (e->alt + 1) & 0x1F;
    return k;
}

void pm5_edges_skip(pm5_edges_t *e, uint32_t n) {
    e->seq = (e->seq + n) & 0x1F;
    e->alt = (e->alt + n) & 0x1F;
}

void pm5_edges_reader(pm5_edges_t *e, uint32_t ts, uint32_t te, uint32_t *start, uint32_t *end) {
    int32_t f = (int32_t)(e->rl_first - ts);
    int32_t d = (int32_t)(e->rl_last - e->rl_first) - (int32_t)(te - 32 - ts);
    bool ok = e->rl && f >= EDGE_WIN_R_LO && f <= EDGE_WIN_R_HI && d <= EDGE_SPAN && d >= -EDGE_SPAN;
    // the end from the last lead when it fits the decoder's end, even where the start falls back (a frame decoded in
    // fragments: its first lead belongs to the first fragment)
    int32_t s = (int32_t)(e->rl_last - (te - 32));
    bool ok_e = ok || (e->rl && s >= EDGE_SPLIT_LO && s <= EDGE_SPLIT_HI);
    if (ok) {
        *start = e->rl_first - DELAY_EDGE_READER;
    } else {
        *start -= EDGE_SLOT_R;
    }
    if (ok_e) {
        *end = e->rl_last + e->w_ref - DELAY_EDGE_READER;
    } else {
        *end -= EDGE_SLOT_R;
    }
}

void pm5_edges_tag(pm5_edges_t *e, uint32_t ts, uint32_t te, uint32_t *start, uint32_t *end) {
    int32_t o = (int32_t)(e->to - ts);
    if (e->to_ok && o >= EDGE_WIN_T_LO && o <= EDGE_WIN_T_HI) {
        *start = e->to - 16 - DELAY_EDGE_TAG;
        *end = *start + (te - ts);
        e->to_ok = false;               // one answer per onset
    } else {
        *start -= EDGE_SLOT_T;
        *end -= EDGE_SLOT_T;
    }
}
