//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Nov 2006
// Copyright (C) Gerhard de Koning Gans - May 2008
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
// Routines to support ISO 14443 type B.
//-----------------------------------------------------------------------------

#ifndef __ISO14443B_H
#define __ISO14443B_H

#include "common.h"

#include "iso14b.h"
#include "pm3_cmd.h"

#ifndef AddCrc14A
# define AddCrc14A(data, len) compute_crc(CRC_14443_A, (data), (len), (data)+(len), (data)+(len)+1)
#endif

#ifndef AddCrc14B
# define AddCrc14B(data, len) compute_crc(CRC_14443_B, (data), (len), (data)+(len), (data)+(len)+1)
#endif

#ifndef AddCrc15
#define AddCrc15(data, len) compute_crc(CRC_ICLASS, (data), (len), (data)+(len), (data)+(len)+1)
#endif

void iso14443b_setup(void);
int iso14443b_apdu(uint8_t const *msg, size_t msg_len, bool send_chaining, void *rxdata, uint16_t rxmaxlen, uint8_t *response_byte, uint16_t *responselen);

int iso14443b_select_card(iso14b_card_select_t *card);

void SimulateIso14443bTag(const uint8_t *pupi);
void read_14b_st_block(uint8_t blocknr);
void SniffIso14443b(void);
void SendRawCommand14443B(iso14b_raw_cmd_t *p);

// States for 14B SIM command
#define SIM_POWER_OFF   0
#define SIM_IDLE        1
#define SIM_READY       2
#define SIM_HALT        3
#define SIM_ACTIVE      4

#endif /* __ISO14443B_H */
