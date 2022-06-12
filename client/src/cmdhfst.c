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
const char *get_st_chip_model(uint8_t pc) {
    switch (pc) {
        case 0x0:
            return "SRIX4K (Special)";
        case 0x2:
            return "SR176";
        case 0x3:
            return "SRIX4K";
        case 0x4:
            return "SRIX512";
        case 0x6:
            return "SRI512";
        case 0x7:
            return "SRI4K";
        case 0xC:
            return "SRT512";
        case 0xC4:
            return "ST25TA64K";
        case 0xE2:
            return "ST25??? IKEA Rothult";
        case 0xE3:
            return "ST25TA02KB";
        case 0xE4:
            return "ST25TA512B";
        case 0xA3:
            return "ST25TA02KB-P";
        case 0xF3:
            return "ST25TA02KB-D";
        default:
            return "Unknown";
    }
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
