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
// Hitag2 type prototyping
//-----------------------------------------------------------------------------

#ifndef _HITAG2_H_
#define _HITAG2_H_

#include "common.h"
#include "hitag.h"

void SniffHitag2(bool ledcontrol);
void hitag_sniff(void);
void SimulateHitag2(bool ledcontrol);
void ReaderHitag(const lf_hitag_data_t *payload, bool ledcontrol);
void WriterHitag(const lf_hitag_data_t *payload, bool ledcontrol);

bool ht2_packbits(uint8_t *nrz_samples, size_t nrzs, uint8_t *rx, size_t *rxlen);
int ht2_read_uid(uint8_t *uid, bool ledcontrol, bool send_answer, bool keep_field_up);
int ht2_tx_rx(uint8_t *tx, size_t txlen, uint8_t *rx, size_t *rxlen, bool ledcontrol, bool keep_field_up);
#endif
