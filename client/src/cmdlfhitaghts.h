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
// Low frequency Hitag S support
//-----------------------------------------------------------------------------

#ifndef CMDLFHITAGS_H__
#define CMDLFHITAGS_H__

#include "common.h"

typedef struct {
    enum {
        HITAGS_MEMORY_32,
        HITAGS_MEMORY_256,
        HITAGS_MEMORY_2048,
        HITAGS_MEMORY_UNKNOWN
    } memory_type;

    bool authentication;

    enum {
        HITAGS_CODING_MANCHESTER,
        HITAGS_CODING_BIPHASE
    } ttf_coding;

    enum {
        HITAGS_DR_4KBIT,
        HITAGS_DR_8KBIT,
        HITAGS_DR_2KBIT,
        HITAGS_DR_2KBIT_PIGEON
    } ttf_data_rate;

    enum {
        HITAGS_TTF_DISABLED,
        HITAGS_TTF_PAGE45,
        HITAGS_TTF_PAGE4567,
        HITAGS_TTF_PAGE4
    } ttf_mode;

    bool lock_config;
    bool lock_key;
} hitags_config_t;

int CmdLFHitagS(const char *Cmd);

int read_hts_uid(void);
hitags_config_t hitags_config_unpack(const uint8_t *config_bytes);
void hitags_config_pack(hitags_config_t config, uint8_t *out);
void hitags_config_print(hitags_config_t config);

#endif //CMDLFHITAGS_H__
