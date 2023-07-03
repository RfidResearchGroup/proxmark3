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
// Mifare default constants
//-----------------------------------------------------------------------------

#ifndef MIFAREDEFAULT_H__
#define MIFAREDEFAULT_H__

#include "common.h"

#define AES_KEY_LEN             16
#define MAX_AES_KEYS_LIST_LEN   1024

#define MFKEY_SIZE              6
#define MFBLOCK_SIZE            16

#define MIFARE_4K_MAXBLOCK      256
#define MIFARE_2K_MAXBLOCK      128
#define MIFARE_1K_MAXBLOCK      64
#define MIFARE_MINI_MAXBLOCK    20

#define MIFARE_4K_MAXSECTOR     40
#define MIFARE_2K_MAXSECTOR     32
#define MIFARE_1K_MAXSECTOR     16
#define MIFARE_MINI_MAXSECTOR   5

#define MIFARE_4K_MAX_BYTES     4096
#define MIFARE_2K_MAX_BYTES     2048
#define MIFARE_1K_MAX_BYTES     1024
#define MIFARE_MINI_MAX_BYTES   320

#define MIFARE_KEY_SIZE         6

#define MIFARE_MINI_MAX_KEY_SIZE    (MIFARE_MINI_MAXSECTOR * 2 * MIFARE_KEY_SIZE)
#define MIFARE_1K_MAX_KEY_SIZE      (MIFARE_1K_MAXSECTOR * 2 * MIFARE_KEY_SIZE)
#define MIFARE_2K_MAX_KEY_SIZE      (MIFARE_2K_MAXSECTOR * 2 * MIFARE_KEY_SIZE)
#define MIFARE_4K_MAX_KEY_SIZE      (MIFARE_4K_MAXSECTOR * 2 * MIFARE_KEY_SIZE)


static const uint64_t g_mifare_default_keys[] = {
    0xffffffffffff, // Default key (first key used by program if no user defined key)
    0xa0a1a2a3a4a5, // NFCForum MAD key
    0xd3f7d3f7d3f7, // NDEF public key
    0x4b791bea7bcc, // MFC EV1 Signature 17 B
    0x5C8FF9990DA2, // MFC EV1 Signature 16 A
    0xD01AFEEB890A, // MFC EV1 Signature 16 B
    0x75CCB59C9BED, // MFC EV1 Signature 17 A
    0xfc00018778f7, // Public Transport
    0x6471a5ef2d1a, // SimonsVoss
    0x4E3552426B32, // ID06
    0x6A1987C40A21, // Salto
    0xef1232ab18a0, // Schlage
    0x3B7E4FD575AD, //
    0xb7bf0c13066e, // Gallagher
    0x135b88a94b8b, // Saflok
    0x2A2C13CC242A, // Dorma Kaba
    0x5a7a52d5e20d, // Bosch
    0x314B49474956, // VIGIK1 A
    0x564c505f4d41, // VIGIK1 B
    0x021209197591, // BTCINO
    0x484558414354, // Intratone
    0xEC0A9B1A9E06, // Vingcard
    0x66b31e64ca4b, // Vingcard
    0x97F5DA640B18, // Bangkok metro key
    0xA8844B0BCA06, // Metro Valencia key
    0xE4410EF8ED2D, // Armenian metro
    0x857464D3AAD1, // HTC Eindhoven key
    0x08B386463229, // troika
    0xe00000000000, // icopy
    0x199404281970, // NSP A
    0x199404281998, // NSP B
    0x6A1987C40A21, // SALTO
    0x7F33625BC129, // SALTO
    0x484944204953, // HID
    0x204752454154, // HID
    0x3B7E4FD575AD, // HID
    0x11496F97752A, // HID
    0x3E65E4FB65B3, // Gym
    0x000000000000, // Blank key
    0xb0b1b2b3b4b5,
    0xaabbccddeeff,
    0x1a2b3c4d5e6f,
    0x123456789abc,
    0x010203040506,
    0x123456abcdef,
    0xabcdef123456,
    0x4d3a99c351dd,
    0x1a982c7e459a,
    0x714c5c886e97,
    0x587ee5f9350f,
    0xa0478cc39091,
    0x533cb6c723f6,
    0x8fd0a4f256e9,
    0x0000014b5c31,
    0xb578f38a5c61,
    0x96a301bce267,
};

static const uint8_t g_mifare_default_key[] =  {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t g_mifare_mad_key[] =  {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
static const uint8_t g_mifare_mad_key_b[] = {0x89, 0xEC, 0xA9, 0x7F, 0x8C, 0x2A};

// 16 key B  D01AFEEB890A
static const uint8_t g_mifare_signature_key_a[] = {0x5C, 0x8F, 0xF9, 0x99, 0x0D, 0xA2};
static const uint8_t g_mifare_signature_key_b[] = {0x4b, 0x79, 0x1b, 0xea, 0x7b, 0xcc};

static const uint8_t g_mifare_ndef_key[] = {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7};
static const uint8_t g_mifarep_mad_key[] =  {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7};
static const uint8_t g_mifarep_ndef_key[] = {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7};

extern const char *g_mifare_plus_default_keys[];
extern size_t g_mifare_plus_default_keys_len;

#endif
