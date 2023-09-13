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

void SimulateHitagSTag(bool tag_mem_supplied, const uint8_t *data, bool ledcontrol);
void ReadHitagS(hitag_function htf, const hitag_data *htd, bool ledcontrol);
void WritePageHitagS(hitag_function htf, const hitag_data *htd, int page, bool ledcontrol);
void Hitag_check_challenges(const uint8_t *data, uint32_t datalen, bool ledcontrol);
#endif
