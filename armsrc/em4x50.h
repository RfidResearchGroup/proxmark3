//-----------------------------------------------------------------------------
// Copyright (C) 2020 tharexde
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
