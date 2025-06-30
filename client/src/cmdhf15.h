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
// High frequency ISO15693 commands
//-----------------------------------------------------------------------------

#ifndef CMDHF15_H__
#define CMDHF15_H__

#include "common.h"
#include "crc16.h"
#include "iso15.h"           // typedef structs / enum

#ifndef Crc15
# define Crc15(data, len)       Crc16ex(CRC_15693, (data), (len))
#endif
#ifndef CheckCrc15
# define CheckCrc15(data, len)  check_crc(CRC_15693, (data), (len))
#endif
#ifndef AddCrc15
#define AddCrc15(data, len)     compute_crc(CRC_15693, (data), (len), (data)+(len), (data)+(len)+1)
#endif

#ifndef ISO15_RAW_LEN
#define ISO15_RAW_LEN(x)  (sizeof(iso15_raw_cmd_t) + (x))
#endif

int CmdHF15(const char *Cmd);
bool readHF15Uid(bool loop, bool verbose);

#endif
