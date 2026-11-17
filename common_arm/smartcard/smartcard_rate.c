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
// Fi/Di arithmetic: what a card's interface bytes mean for the link rate.
//-----------------------------------------------------------------------------
#include "smartcard_rate.h"

// The fastest rate worth proposing to a card, or 0 for none.
//
// Two rules keep this safe, both learned on the bench rather than assumed:
//
//   - Keep the Fi the card advertised and only lower Di. Proposing a different
//     Fi is refused: a SAM advertising Fi=512 took the whole Fi=512 family and
//     rejected every Fi=768/1024/1536/2048 offer.
//   - R = Fi / (16 * Di) is the module's UART reload. It has to be a whole
//     number or the sampling point drifts - that is the +3.2% which makes
//     Fi=372 unusable beyond Di=1 - and it must not fall below the floor.
//
// The floor is measured, not guessed. It was 8 while the module still waited
// out a turnaround guard before listening, which cost it the second byte of
// every answer above 31250 bit/s. With that guard applied only before
// transmitting (module v4.62), R=2 (125000 bit/s) is clean over repeated runs
// and R=1 still is not: at 16 clocks per etu a character is 192 instruction
// cycles, and the receive loop does not fit in that.
//
// A card with no TA1 offers nothing but the default, so nothing is proposed.
#define SC_PPS_MIN_RELOAD  2

// ISO/IEC 7816-3 tables 7 and 8. 0 marks an RFU entry, which nothing may use.
static const uint16_t s_fi_tab[16] = {372, 372, 558, 744, 1116, 1488, 1860, 0,
                                      0, 512, 768, 1024, 1536, 2048, 0, 0
                                     };
static const uint8_t s_di_tab[16] = {0, 1, 2, 4, 8, 16, 32, 64, 12, 20, 0, 0, 0, 0, 0, 0};

// The module's UART reload for a TA1, or 0 when the pair is unusable. Same
// arithmetic as UART_Set_FiDi() in the module firmware: R = Fi / (16 * Di),
// which has to come out whole or the sampling point drifts across a character.
uint16_t SmartCard_RateReload(uint8_t ta1) {

    uint16_t f = s_fi_tab[(ta1 >> 4) & 0x0F];
    uint8_t  d = s_di_tab[ta1 & 0x0F];

    if ((f == 0) || (d == 0)) {
        return 0;
    }
    if ((f % (uint16_t)(16u * d)) != 0) {
        return 0;
    }
    return (uint16_t)(f / (uint16_t)(16u * d));
}

uint16_t SmartCard_RateEtu(uint8_t ta1) {

    uint16_t f = s_fi_tab[(ta1 >> 4) & 0x0F];
    uint8_t  d = s_di_tab[ta1 & 0x0F];

    if ((f == 0) || (d == 0) || ((f % d) != 0)) {
        return 0;
    }
    return (uint16_t)(f / d);
}

uint8_t SmartCard_RateBestTa1(const uint8_t *atr, uint8_t len) {

    if ((len < 3) || ((atr[1] & 0x10) == 0)) {
        return 0;                       // no TA1 - default only
    }

    uint8_t fi_idx = (uint8_t)((atr[2] >> 4) & 0x0F);
    uint16_t f = s_fi_tab[fi_idx];
    if (f == 0) {
        return 0;                       // RFU
    }

    uint8_t best = 0;
    uint16_t best_clocks = 372;         // has to beat the default to be worth it

    for (uint8_t di_idx = 1; di_idx < 16; di_idx++) {

        uint8_t d = s_di_tab[di_idx];
        if (d == 0) {
            continue;
        }
        if ((f % (uint16_t)(16u * d)) != 0) {
            continue;                   // divisor is not exact, the etu would drift
        }
        if ((f / (uint16_t)(16u * d)) < SC_PPS_MIN_RELOAD) {
            continue;                   // faster than the module can receive
        }

        uint16_t clocks = (uint16_t)(f / d);
        if (clocks >= best_clocks) {
            continue;
        }
        best_clocks = clocks;
        best = (uint8_t)((fi_idx << 4) | di_idx);
    }

    return best;
}
