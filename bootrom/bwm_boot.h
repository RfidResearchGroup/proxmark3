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
// PM5 bootrom BWM UART: DATA_FORWARD is a byte stream of PacketCommandOLD.
//-----------------------------------------------------------------------------
#ifndef BWM_BOOT_H
#define BWM_BOOT_H

#include "common.h"

void bwm_boot_init(void);
void bwm_boot_pump(void);
bool bwm_boot_poll(uint8_t *out, size_t outlen);
int bwm_boot_write(const uint8_t *data, size_t len);

// Baud the ESP answered on, or 0 if none did.
uint32_t bwm_boot_baud(void);

#endif
