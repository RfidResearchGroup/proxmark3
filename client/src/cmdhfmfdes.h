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
// High frequency MIFARE Desfire commands
//-----------------------------------------------------------------------------
#ifndef __MFDESFIRE_H
#define __MFDESFIRE_H

#include "common.h"

int CmdHFMFDes(const char *Cmd);

/*
char *getCardSizeStr(uint8_t fsize);
char *getVersionStr(uint8_t major, uint8_t minor);
int getKeySettings(uint8_t *aid);
*/

// Ev1 card limits
#define MAX_NUM_KEYS                0x0F
#define MAX_APPLICATION_COUNT       28
#define MAX_FILE_COUNT              32
#define MAX_FRAME_SIZE              60
#define FRAME_PAYLOAD_SIZE          (MAX_FRAME_SIZE - 5)

// Ev2 card limits

// Ev3 card limits

// Light card limits

// Light Ev1 card limits

#define NOT_YET_AUTHENTICATED       0xFF



#endif
