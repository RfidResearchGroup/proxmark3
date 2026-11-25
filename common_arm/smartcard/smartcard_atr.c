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
// ATR decoding: what the answer to reset says about the card.
//-----------------------------------------------------------------------------
#include "smartcard_atr.h"

#define SC_PROTO_T0     (1 << 0)

// ISO 7816-3 clause 8: offered protocols are the low nibbles of the TDi bytes.
// No TD1 means T=0 only. T=15 is global interface bytes, not a protocol.
uint8_t SmartCard_ATRProtocols(const uint8_t *atr, uint8_t len) {

    if (len < 2) {
        return 0;
    }

    uint8_t y = (uint8_t)(atr[1] >> 4);      // T0
    uint8_t i = 2;
    uint8_t mask = 0;

    while (y) {

        if (y & 0x01) i++;                   // TA(i)
        if (y & 0x02) i++;                   // TB(i)
        if (y & 0x04) i++;                   // TC(i)

        if ((y & 0x08) == 0) {
            break;                           // no TD(i), nothing further named
        }
        if (i >= len) {
            break;                           // truncated ATR
        }

        uint8_t td = atr[i++];
        uint8_t t = (uint8_t)(td & 0x0F);
        if (t < 8) {
            mask |= (uint8_t)(1u << t);
        }
        y = (uint8_t)(td >> 4);
    }

    if (mask == 0) {
        mask = SC_PROTO_T0;                  // clause 8.2.3
    }
    return mask;
}

uint8_t SmartCard_ATRFirstProto(const uint8_t *atr, uint8_t len) {
    if ((len < 2) || ((atr[1] & 0x80) == 0)) {
        return 0;
    }
    uint8_t i = 2;
    if (atr[1] & 0x10) i++;
    if (atr[1] & 0x20) i++;
    if (atr[1] & 0x40) i++;
    return (i < len) ? (uint8_t)(atr[i] & 0x0F) : 0;
}

bool SmartCard_ATRCheckTCK(const uint8_t *atr, uint8_t len) {

    if (len < 2) {
        return true;
    }

    uint8_t pos_td = 1;
    if ((atr[1] & 0x10) == 0x10) pos_td++;
    if ((atr[1] & 0x20) == 0x20) pos_td++;
    if ((atr[1] & 0x40) == 0x40) pos_td++;

    // T0 indicate presence T=0 vs T=1.  T=1 has checksum TCK
    if ((atr[1] & 0x80) == 0) {
        return true;
    }

    pos_td++;

    // 1 == T1 ,  presence of checksum TCK
    if (pos_td >= len || (atr[pos_td] & 0x01) != 0x01) {
        return true;
    }

    uint8_t chksum = 0;
    // xor property.  will be zero when xored with chksum.
    for (uint8_t i = 1; i < len; ++i) {
        chksum ^= atr[i];
    }
    return chksum == 0;
}
