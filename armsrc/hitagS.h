//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/Proxmark/proxmark3/pull/167/files
// Copyright (C) 2016 Oguzhan Cicek, Hendrik Schwartke, Ralf Spenneberg
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
// HitagS emulation (preliminary test version)
//-----------------------------------------------------------------------------

#ifndef _HITAGS_H_
#define _HITAGS_H_

#include "common.h"
#include "hitag.h"

void hts_simulate(bool tag_mem_supplied, const uint8_t *data, bool ledcontrol);
void hts_read(const lf_hitag_data_t *payload, bool ledcontrol);
void hts_write_page(const lf_hitag_data_t *payload, bool ledcontrol);
void hts_check_challenges(const uint8_t *data, uint32_t datalen, bool ledcontrol);
int hts_read_uid(uint32_t *uid, bool ledcontrol, bool send_answer);
#endif
