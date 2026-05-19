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
// FM11RF08S static encrypted nonce recovery
//-----------------------------------------------------------------------------

#ifndef CMDHFMFSEN_H__
#define CMDHFMFSEN_H__

#include <stdint.h>
#include "mifare.h"
#include "mifare/mifaredefault.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FM11_BACKDOOR_KEY_COUNT 3
extern const uint8_t fm11_backdoor_keys[FM11_BACKDOOR_KEY_COUNT][MIFARE_KEY_SIZE];

int fm11_collect_nonces(const uint8_t *key, iso14a_card_select_t *card, iso14a_fm11rf08s_nonces_with_data_t *nonces);
int CmdHF14AMfSEN(const char *Cmd);

#ifdef __cplusplus
}
#endif

#endif /* CMDHFMFSEN_H__ */
