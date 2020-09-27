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

typedef struct {
    uint8_t sectors[34][7];
} em4x50_tag_t;

int em4x50_standalone_read(uint64_t *words);
bool em4x50_sim_send_listen_window(void);
bool em4x50_sim_send_word(uint32_t word);

void em4x50_info(em4x50_data_t *etd);
void em4x50_write(em4x50_data_t *etd);
void em4x50_write_password(em4x50_data_t *etd);
void em4x50_read(em4x50_data_t *etd);
void em4x50_wipe(em4x50_data_t *etd);
void em4x50_brute(em4x50_data_t *etd);

#endif /* EM4X50_H */
