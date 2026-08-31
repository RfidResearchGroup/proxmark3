//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef __BWM_UART_AT32_H
#define __BWM_UART_AT32_H

#include "common.h"

#define BWM_UART_BAUD   460800

void bwm_uart_init(void);

void UART4_IRQHandler(void);

int bwm_uart_write(const uint8_t *data, size_t len);

uint16_t bwm_uart_rx_available(void);

uint32_t bwm_uart_read(uint8_t *data, size_t len);

#endif
