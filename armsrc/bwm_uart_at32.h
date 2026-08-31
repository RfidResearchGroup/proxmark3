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

// Boot/default baud. Must match UART_BAUD_RATE_DEFAULT in the ESP firmware
// (Proxmark5_BWM_esp32). The link comes up here, then the ARM negotiates up to
// BWM_UART_BAUD_TARGET at runtime via app_com cmd 1011 - the ESP is designed to
// be told, not reflashed (the SET command is explicitly non-persistent).
#define BWM_UART_BAUD          460800

// Target baud to negotiate after link-up. 0 disables negotiation (stay at
// BWM_UART_BAUD). Bounded by the ESP's CONFIG_SOC_UART_BITRATE_MAX and PA0/PA1
// signal integrity; validate on hardware before raising further.
#ifndef BWM_UART_BAUD_TARGET
#define BWM_UART_BAUD_TARGET   921600
#endif

void bwm_uart_init(void);

// Re-init UART4 + RX DMA at a new baud (used by the runtime baud negotiation).
// Discards any bytes already in the RX ring.
void bwm_uart_set_baud(uint32_t baud);

// Baud the link is currently running at (updated by bwm_uart_set_baud).
uint32_t bwm_uart_get_baud(void);

int bwm_uart_write(const uint8_t *data, size_t len);

uint16_t bwm_uart_rx_available(void);

uint32_t bwm_uart_read(uint8_t *data, size_t len);

#endif
