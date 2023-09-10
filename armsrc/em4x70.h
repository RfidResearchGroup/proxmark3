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
// Low frequency EM4x70 commands
//-----------------------------------------------------------------------------

#ifndef EM4x70_H
#define EM4x70_H

#include "../include/em4x70.h"

typedef struct {
    uint8_t data[32];
} em4x70_tag_t;

typedef enum {
    RISING_EDGE,
    FALLING_EDGE
} edge_detection_t;

void em4x70_info(const em4x70_data_t *etd, bool ledcontrol);
void em4x70_write(const em4x70_data_t *etd, bool ledcontrol);
void em4x70_brute(const em4x70_data_t *etd, bool ledcontrol);
void em4x70_unlock(const em4x70_data_t *etd, bool ledcontrol);
void em4x70_auth(const em4x70_data_t *etd, bool ledcontrol);
void em4x70_write_pin(const em4x70_data_t *etd, bool ledcontrol);
void em4x70_write_key(const em4x70_data_t *etd, bool ledcontrol);

#endif /* EM4x70_H */
