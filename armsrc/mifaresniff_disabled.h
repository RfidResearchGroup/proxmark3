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
// Routines to support mifare classic sniffer.
//-----------------------------------------------------------------------------

#ifndef __MIFARESNIFF_H
#define __MIFARESNIFF_H

#include "common.h"

#define SNF_INIT        0
#define SNF_NO_FIELD    1
#define SNF_ATQA        2
#define SNF_UID         3
#define SNF_SAK         4
#define SNF_CARD_IDLE   5
#define SNF_CARD_CMD    6
#define SNF_MAGIC_WUPC2 7

#define SNF_UID_4       0
#define SNF_UID_7       0
#define SNF_UID_10      0

void MfSniffInit(void);
bool RAMFUNC MfSniffLogic(const uint8_t *data, uint16_t len, uint8_t *parity, uint16_t bitCnt, bool reader);
void RAMFUNC MfSniffSend(void);
void MfSniffEnd(void);

#endif
