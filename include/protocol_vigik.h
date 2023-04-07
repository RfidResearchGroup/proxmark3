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
#ifndef PROTOCOL_VIGIK_H
#define PROTOCOL_VIGIK_H
#include "common.h"

typedef struct mfc_vigik_s {
    uint8_t b0[16];
    uint8_t mad[32];
    uint8_t counters;
    uint8_t rtf[15];
    uint32_t service_code;
    uint8_t info_flag;
    uint8_t key_version;
    uint16_t ptr_counter;
    uint8_t counter_num;
    uint8_t slot_access_date[5];
    uint16_t slot_dst_duration;
    uint8_t other_slots[8];
    uint8_t services_counter;
    uint8_t loading_date[5];
    uint16_t reserved_null;
    uint8_t rsa_signature[128];
} mfc_vigik_t;

typedef struct vigik_pk_s {
    const char *desc;
    uint16_t code;
    const char *n;
} vigik_pk_t;

#endif
