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
// High frequency MIFARE  Plus commands
//-----------------------------------------------------------------------------
#ifndef CMDHFMFP_H__
#define CMDHFMFP_H__

#include "common.h"
#include "mifare/mifare4.h"
#include "mifare/mifaredefault.h"  // AES_KEY_LEN
#include "mifare.h"               // iso14a_card_select_t

typedef struct mfp_key_item {
    uint8_t a[16];
    uint8_t b[16];
} mfp_key_item_t;

typedef struct mfp_keys {
    uint8_t success;
    mfp_key_item_t *keys;
} mfp_keys_t;

int CmdHFMFP(const char *Cmd);
int CmdHFMFPNDEFRead(const char *Cmd);
int mfp_data_crypt(mf4Session_t *mf4session, uint8_t *dati, uint8_t *dato, bool rev, int bc);
int mfp_save_aes_keys(const iso14a_card_select_t *card, uint8_t foundKeys[2][64][AES_KEY_LEN + 1]);
int mfp_check_aes_keys(uint8_t *uid, const uint8_t *sector_mask, uint8_t sector_cnt, uint8_t foundKeys[2][64][AES_KEY_LEN + 1]);
#endif
