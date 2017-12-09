//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Mifare default constants
//-----------------------------------------------------------------------------

#ifndef MIFAREDEFAULT_H__
#define MIFAREDEFAULT_H__

#include <inttypes.h>

#define MIFARE_DEFAULTKEYS_SIZE sizeof(g_mifare_default_keys) / sizeof(uint64_t)

static const uint64_t g_mifare_default_keys[] =
{
	0xffffffffffff, // Default key (first key used by program if no user defined key)
	0x000000000000, // Blank key
	0xa0a1a2a3a4a5, // NFCForum MAD key
	0xb0b1b2b3b4b5,
	0xc0c1c2c3c4c5,
	0xd0d1d2d3d4d5,
	0xaabbccddeeff,
	0x1a2b3c4d5e6f,
	0x123456789abc,
	0x010203040506,
	0x123456abcdef,
	0xabcdef123456,
	0x4d3a99c351dd,
	0x1a982c7e459a,
	0xd3f7d3f7d3f7,
	0x714c5c886e97,
	0x587ee5f9350f,
	0xa0478cc39091,
	0x533cb6c723f6,
	0x8fd0a4f256e9
};

#endif
