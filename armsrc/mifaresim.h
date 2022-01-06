//-----------------------------------------------------------------------------
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
// Mifare Classic Card Simulation
//-----------------------------------------------------------------------------

#ifndef __MIFARESIM_H
#define __MIFARESIM_H

#include "common.h"

#ifndef CheckCrc14A
# define CheckCrc14A(data, len) check_crc(CRC_14443_A, (data), (len))
#endif

#define AC_DATA_READ             0
#define AC_DATA_WRITE            1
#define AC_DATA_INC              2
#define AC_DATA_DEC_TRANS_REST   3
#define AC_KEYA_READ             0
#define AC_KEYA_WRITE            1
#define AC_KEYB_READ             2
#define AC_KEYB_WRITE            3
#define AC_AC_READ               4
#define AC_AC_WRITE              5

#define AUTHKEYA                 0
#define AUTHKEYB                 1
#define AUTHKEYNONE              0xff

void Mifare1ksim(uint16_t flags, uint8_t exitAfterNReads, uint8_t *datain, uint16_t atqa, uint8_t sak);

#endif
