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

int em4x50_standalone_read(uint32_t *words);
int em4x50_standalone_brute(uint32_t start, uint32_t stop, uint32_t *pwd);
bool em4x50_sim_send_listen_window(void);
bool em4x50_sim_send_word(uint32_t word);


void em4x50_info(em4x50_data_t *etd);
void em4x50_write(em4x50_data_t *etd);
void em4x50_write_password(em4x50_data_t *etd);
void em4x50_read(em4x50_data_t *etd);
void em4x50_wipe(uint32_t *password);
void em4x50_brute(em4x50_data_t *etd);
void em4x50_login(uint32_t *password);
void em4x50_reset(void);
void em4x50_watch(void);
void em4x50_restore(em4x50_data_t *etd);
void em4x50_sim(uint32_t *word);

#endif /* EM4X50_H */
