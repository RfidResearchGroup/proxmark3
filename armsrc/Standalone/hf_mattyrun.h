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
// definitions for HF MIFARE Classic chk/ecfill/sim aka MattyRun
//-----------------------------------------------------------------------------

#ifndef HF_MATTYRUN_H__
#define HF_MATTYRUN_H__

#include <inttypes.h>

// Set of standard keys to be used
static uint64_t const MATTYRUN_MFC_DEFAULT_KEYS[] = {
    0xFFFFFFFFFFFF,  // Default key
    0x000000000000,  // Blank key
    0xA0A1A2A3A4A5,  // MAD key
    0x5C8FF9990DA2,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 16 A
    0x75CCB59C9BED,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 17 A
    0xD01AFEEB890A,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 16 B
    0x4B791BEA7BCC,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 17 B
    0xD3F7D3F7D3F7,  // AN1305 MIFARE Classic as NFC Type MIFARE Classic Tag Public Key A

    0x111111111111,
    0x222222222222,
    0x333333333333,
    0x444444444444,
    0x555555555555,
    0x666666666666,
    0x777777777777,
    0x888888888888,
    0x999999999999,
    0xAAAAAAAAAAAA,
    0xBBBBBBBBBBBB,
    0xCCCCCCCCCCCC,
    0xDDDDDDDDDDDD,
    0xEEEEEEEEEEEE,
    0xA5A4A3A2A1A0,
    0xB0B1B2B3B4B5,
    0xC0C1C2C3C4C5,
    0xD0D1D2D3D4D5,
    0xA0B0C0D0E0F0,
    0xA1B1C1D1E1F1,
    0xAABBCCDDEEFF,
    0x001122334455,
    0x112233445566,
    0x010203040506,
    0x0123456789AB,
    0x123456789ABC,

	// You could add more keys from, e.g, mfc_default_keys.dic here.
	// However, be aware that more keys means longer brute-force times
	// and too many keys will resuolt in running out of memory.
	// See https://github.com/RfidResearchGroup/proxmark3/pull/2377#issuecomment-2112658439
	// for a rough benchmark.
};

#endif /* HF_MATTYRUN_H__ */
