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
// High frequency ISO14443A / ST  commands
//-----------------------------------------------------------------------------

#include "cmdhfst.h"
#include <string.h>
#include <stdio.h>

#define TIMEOUT 2000

// get ST Microelectronics chip model (from UID)
char *get_st_chip_model(uint8_t pc) {
    static char model[40];
    char *s = model;
    memset(model, 0, sizeof(model));
    switch (pc) {
        case 0x0:
            sprintf(s, "SRIX4K (Special)");
            break;
        case 0x2:
            sprintf(s, "SR176");
            break;
        case 0x3:
            sprintf(s, "SRIX4K");
            break;
        case 0x4:
            sprintf(s, "SRIX512");
            break;
        case 0x6:
            sprintf(s, "SRI512");
            break;
        case 0x7:
            sprintf(s, "SRI4K");
            break;
        case 0xC:
            sprintf(s, "SRT512");
            break;
        case 0xC4:
            sprintf(s, "ST25TA64K");
            break;
        case 0xE2:
            sprintf(s, "ST25??? IKEA Rothult");
            break;
        case 0xE3:
            sprintf(s, "ST25TA02KB");
            break;
        case 0xE4:
            sprintf(s, "ST25TA512B");
            break;
        case 0xA3:
            sprintf(s, "ST25TA02KB-P");
            break;
        case 0xF3:
            sprintf(s, "ST25TA02KB-D");
            break;
        default :
            sprintf(s, "Unknown");
            break;
    }
    return s;
}
/*
// print UID info from SRx chips (ST Microelectronics)
void print_st_general_info(uint8_t *data, uint8_t len) {
    //uid = first 8 bytes in data
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex(SwapEndian64(data, 8, 8), len));
    PrintAndLogEx(SUCCESS, " MFG: %02X, " _YELLOW_("%s"), data[6], getTagInfo(data[6]));
    PrintAndLogEx(SUCCESS, "Chip: %02X, " _YELLOW_("%s"), data[5] >> 2, get_st_chip_model(data[5] >> 2));
}

*/
