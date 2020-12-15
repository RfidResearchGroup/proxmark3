//-----------------------------------------------------------------------------
// Copyright (C) 2020 sirloins
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
}edge_detection_t;

void em4x70_info(em4x70_data_t *etd);
void em4x70_write(em4x70_data_t *etd);
void em4x70_unlock(em4x70_data_t *etd);
void em4x70_auth(em4x70_data_t *etd);
void em4x70_write_pin(em4x70_data_t *etd);

#endif /* EM4x70_H */
