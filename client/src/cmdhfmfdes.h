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

typedef enum {
    NXP_UNKNOWN = 0,
    DESFIRE_MF3ICD40,
    DESFIRE_EV1,
    DESFIRE_EV2,
    DESFIRE_EV2_XL,
    DESFIRE_EV3,
    DESFIRE_LIGHT,
    PLUS_EV1,
    PLUS_EV2,
    NTAG413DNA,
    NTAG424,
    DUOX,
} nxp_cardtype_t;

typedef struct {
    uint8_t isOK;
    uint8_t uid[7];
    uint8_t uidlen;
    uint8_t versionHW[7];
    uint8_t versionSW[7];
    uint8_t details[14];
} PACKED mfdes_info_res_t;

int CmdHFMFDes(const char *Cmd);

/*
char *getCardSizeStr(uint8_t fsize);
char *getVersionStr(uint8_t major, uint8_t minor);
int getKeySettings(uint8_t *aid);
*/

int desfire_print_signature(uint8_t *uid, uint8_t uidlen, uint8_t *signature, size_t signature_len);
nxp_cardtype_t getCardType(uint8_t type, uint8_t major, uint8_t minor);
int mfdes_get_info(mfdes_info_res_t *info);

#endif
