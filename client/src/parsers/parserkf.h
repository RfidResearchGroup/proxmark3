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
// RKF travel card parser for MIFARE Classic dumps
//
// Resekortsforeningen i Norden, "RKF Type CL-1", the Nordic public transport
// travel card on MIFARE Classic 1K. Layout per RKF-0022 1.0 and RKF-0023 2.00.
//-----------------------------------------------------------------------------

#ifndef PARSERKF_H__
#define PARSERKF_H__

#include "common.h"

// TCAS: Travel Card Applications Status, identifier of the first instance,
// always in block 2 of sector 0
#define RKF_TCAS_IDENTIFIER 0xA0

// True when sector 0 carries a travel card applications status block and either
// the card information block or the directory corroborates it
bool is_valid_rkf_card(const uint8_t *dump, size_t dumplen);

// Decode the support layer and walk the directory, printing every application
// object the specification pins down
int rkf_parser_parse(const uint8_t *dump, size_t dumplen);

// Build a card from the encoder and check the decoder reads it back
int rkf_selftest(void);

#endif
