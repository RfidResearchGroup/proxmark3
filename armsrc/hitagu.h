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
// Hitag µ functions
//-----------------------------------------------------------------------------

#ifndef _HITAGU_H_
#define _HITAGU_H_

#include "common.h"
#include "hitag.h"

void htu_simulate(bool tag_mem_supplied, int8_t threshold, const uint8_t *data, bool ledcontrol);
void htu_read(const lf_hitag_data_t *payload, bool ledcontrol);
void htu_write_page(const lf_hitag_data_t *payload, bool ledcontrol);
int htu_read_uid(uint64_t *uid, bool ledcontrol, bool send_answer);

#endif
