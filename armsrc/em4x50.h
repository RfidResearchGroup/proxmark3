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
// Low frequency EM4x50 commands
//-----------------------------------------------------------------------------

#ifndef EM4X50_H
#define EM4X50_H

#include "../include/em4x50.h"

void em4x50_setup_read(void);
int standard_read(int *now, uint32_t *words);

void em4x50_setup_sim(void);
void em4x50_handle_commands(int *command, uint32_t *tag, bool ledcontrol);

void em4x50_info(em4x50_data_t *etd, bool ledcontrol);
void em4x50_write(em4x50_data_t *etd, bool ledcontrol);
void em4x50_writepwd(em4x50_data_t *etd, bool ledcontrol);
void em4x50_read(em4x50_data_t *etd, bool ledcontrol);
void em4x50_brute(em4x50_data_t *etd, bool ledcontrol);
void em4x50_login(uint32_t *password, bool ledcontrol);
void em4x50_sim(uint32_t *password, bool ledcontrol);
void em4x50_reader(bool ledcontrol);
void em4x50_chk(uint8_t *filename, bool ledcontrol);

#endif /* EM4X50_H */
