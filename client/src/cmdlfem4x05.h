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
// Low frequency EM4x05 commands
//-----------------------------------------------------------------------------

#ifndef CMDLFEM4X05_H__
#define CMDLFEM4X05_H__

#include "common.h"

#define EM_SERIAL_BLOCK 1
#define EM_CONFIG_BLOCK 4
#define EM4305_PROT1_BLOCK 14
#define EM4305_PROT2_BLOCK 15
#define EM4469_PROT_BLOCK 3

#define EM4X05_BITS_BUFSIZE 128

// config blocks
#define EM4305_DEFAULT_CONFIG_BLOCK      (EM4x05_SET_BITRATE(32) | EM4x05_MODULATION_MANCHESTER | EM4x05_SET_NUM_BLOCKS(4) ) // ASK/MAN , data rate 32, 4 data blocks
//#define EM4305_DEFAULT_CONFIG_BLOCK    (EM4x05_SET_BITRATE(32) | EM4x05_MODULATION_BIPHASE | EM4x05_SET_NUM_BLOCKS(4) ) // ASK/BIPHASE , data rate 32, 4 data blocks

#define EM4305_EM_UNIQUE_CONFIG_BLOCK    (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_MANCHESTER | EM4x05_SET_NUM_BLOCKS(2) ) // ASK/MAN, EM4x02/unique - data rate 64, 2 data blocks
#define EM4305_PAXTON_CONFIG_BLOCK       (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_MANCHESTER | EM4x05_SET_NUM_BLOCKS(2) ) // ASK/MAN, EM4x02/paxton - data rate 64, 2 data blocks
#define EM4305_VISA2000_CONFIG_BLOCK     (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_MANCHESTER | EM4x05_SET_NUM_BLOCKS(3) ) // ASK, data rate 64, 3 data blocks
#define EM4305_VIKING_CONFIG_BLOCK       (EM4x05_SET_BITRATE(32) | EM4x05_MODULATION_MANCHESTER | EM4x05_SET_NUM_BLOCKS(2) ) // ASK/MAN, data rate 32, 2 data blocks
#define EM4305_NORALSY_CONFIG_BLOCK      (EM4x05_SET_BITRATE(32) | EM4x05_MODULATION_MANCHESTER | EM4x05_SET_NUM_BLOCKS(3) ) // ASK, data rate 32, 3 data blocks
#define EM4305_PRESCO_CONFIG_BLOCK       (EM4x05_SET_BITRATE(32) | EM4x05_MODULATION_MANCHESTER | EM4x05_SET_NUM_BLOCKS(4) ) // ASK/MAN, data rate 32, 4 data blocks
#define EM4305_SECURAKEY_CONFIG_BLOCK    (EM4x05_SET_BITRATE(40) | EM4x05_MODULATION_MANCHESTER | EM4x05_SET_NUM_BLOCKS(3) ) // ASK/MAN, data rate 40, 3 data blocks
#define EM4305_GALLAGHER_CONFIG_BLOCK    (EM4x05_SET_BITRATE(32) | EM4x05_MODULATION_MANCHESTER | EM4x05_SET_NUM_BLOCKS(3) ) // ASK/MAN, data rate 32, 3 data blocks

#define EM4305_DESTRON_CONFIG_BLOCK      (EM4x05_SET_BITRATE(50) | EM4x05_MODULATION_FSK2 | EM4x05_SET_NUM_BLOCKS(3) ) // FSK2a, hid 26 bit, data rate 50, 3 data blocks
#define EM4305_HID_26_CONFIG_BLOCK       (EM4x05_SET_BITRATE(50) | EM4x05_MODULATION_FSK2 | EM4x05_SET_NUM_BLOCKS(3) ) // FSK2a, hid 26 bit, data rate 50, 3 data blocks
#define EM4305_PARADOX_CONFIG_BLOCK      (EM4x05_SET_BITRATE(50) | EM4x05_MODULATION_FSK2 | EM4x05_SET_NUM_BLOCKS(3) ) // FSK2a, hid 26 bit, data rate 50, 3 data blocks
#define EM4305_AWID_CONFIG_BLOCK         (EM4x05_SET_BITRATE(50) | EM4x05_MODULATION_FSK2 | EM4x05_SET_NUM_BLOCKS(3) ) // FSK2a, hid 26 bit, data rate 50, 3 data blocks
#define EM4305_PYRAMID_CONFIG_BLOCK      (EM4x05_SET_BITRATE(50) | EM4x05_MODULATION_FSK2 | EM4x05_SET_NUM_BLOCKS(4) ) // FSK2a, Pyramid 26 bit, data rate 50, 4 data blocks
#define EM4305_IOPROX_CONFIG_BLOCK       (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_FSK2 | EM4x05_SET_NUM_BLOCKS(2) ) // FSK2a, data rate 64, 2 data blocks

#define EM4305_INDALA_64_CONFIG_BLOCK    (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_PSK1 | EM4x05_PSK_RF_2 | EM4x05_SET_NUM_BLOCKS(2) ) // PSK1, indala 64 bit, psk carrier FC * 2, data rate 32, maxblock 2
#define EM4305_INDALA_224_CONFIG_BLOCK   (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_PSK1 | EM4x05_PSK_RF_2 | EM4x05_SET_NUM_BLOCKS(7) ) // PSK1, indala 224 bit, psk carrier FC * 2, data rate 32, maxblock 7
#define EM4305_MOTOROLA_CONFIG_BLOCK     (EM4x05_SET_BITRATE(32) | EM4x05_MODULATION_PSK1 | EM4x05_PSK_RF_2 | EM4x05_SET_NUM_BLOCKS(2) ) // PSK1, data rate 32, 2 data blocks
#define EM4305_NEXWATCH_CONFIG_BLOCK     (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_PSK1 | EM4x05_PSK_RF_2 | EM4x05_SET_NUM_BLOCKS(3) ) // PSK1 data rate 16, psk carrier FC * 2, 3 data blocks
#define EM4305_KERI_CONFIG_BLOCK         (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_PSK1 | EM4x05_PSK_RF_2 | EM4x05_SET_NUM_BLOCKS(2) ) // PSK1, 2 data blocks
#define EM4305_IDTECK_CONFIG_BLOCK       (EM4x05_SET_BITRATE(32) | EM4x05_MODULATION_PSK1 | EM4x05_PSK_RF_2 | EM4x05_SET_NUM_BLOCKS(2) ) // PSK1, 2 data blocks

#define EM4305_JABLOTRON_CONFIG_BLOCK    (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_BIPHASE | EM4x05_SET_NUM_BLOCKS(2) ) // Biphase, data rate 64, 2 data blocks
#define EM4305_GUARDPROXII_CONFIG_BLOCK  (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_BIPHASE | EM4x05_SET_NUM_BLOCKS(3) ) // Biphase, data rate 64, Direct modulation, 3 data blocks
#define EM4305_NEDAP_64_CONFIG_BLOCK     (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_BIPHASE | EM4x05_SET_NUM_BLOCKS(2) ) // Biphase, data rate 64, 2 data blocks
#define EM4305_NEDAP_128_CONFIG_BLOCK    (EM4x05_SET_BITRATE(64) | EM4x05_MODULATION_BIPHASE | EM4x05_SET_NUM_BLOCKS(4) ) // Biphase, data rate 64, 4 data blocks
#define EM4305_FDXB_CONFIG_BLOCK         (EM4x05_SET_BITRATE(32) | EM4x05_MODULATION_BIPHASE | EM4x05_SET_NUM_BLOCKS(4) ) // Biphase, data rate 32, 4 data blocks

#define EM4305_PAC_CONFIG_BLOCK          (EM4x05_SET_BITRATE(32) | EM4x05_MODULATION_NRZ | EM4x05_SET_NUM_BLOCKS(4) )  // NRZ, data rate 32, 4 data blocks
#define EM4305_VERICHIP_CONFIG_BLOCK     (EM4x05_SET_BITRATE(40) | EM4x05_MODULATION_NRZ | EM4x05_SET_NUM_BLOCKS(4) )  // NRZ, data rate 40, 4 data blocks

typedef enum {
    EM_UNKNOWN,
    EM_4205,
    EM_4305,
    EM_4369,
    EM_4469,
} em_tech_type_t;

int CmdLFEM4X05(const char *Cmd);

bool em4x05_isblock0(uint32_t *word);
int em4x05_read_word_ext(uint8_t addr, uint32_t pwd, bool use_pwd, uint32_t *word);
int em4x05_write_word_ext(uint8_t addr, uint32_t pwd, bool use_pwd, uint32_t data);
int em4x05_clone_tag(uint32_t *blockdata, uint8_t numblocks, uint32_t pwd, bool use_pwd);

int CmdEM4x05Demod(const char *Cmd);
int CmdEM4x05Dump(const char *Cmd);
int CmdEM4x05Read(const char *Cmd);
int CmdEM4x05Write(const char *Cmd);
int CmdEM4x05Wipe(const char *Cmd);
int CmdEM4x05Info(const char *Cmd);
int CmdEM4x05Chk(const char *Cmd);
int CmdEM4x05Unlock(const char *Cmd);
int CmdEM4x05Sniff(const char *Cmd);
int CmdEM4x05Brute(const char *Cmd);

#endif
