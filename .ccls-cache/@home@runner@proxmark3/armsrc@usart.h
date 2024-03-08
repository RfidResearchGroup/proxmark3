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
#ifndef __USART_H
#define __USART_H

#include "common.h"
#include "usart_defs.h"

// Higher baudrates are pointless, only increasing overflow risk

extern uint32_t g_usart_baudrate;
extern uint8_t g_usart_parity;

void usart_init(uint32_t baudrate, uint8_t parity);
int usart_writebuffer_sync(uint8_t *data, size_t len);
uint32_t usart_read_ng(uint8_t *data, size_t len);
uint16_t usart_rxdata_available(void);

#endif
