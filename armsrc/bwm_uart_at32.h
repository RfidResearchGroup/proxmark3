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
// AT32F435 UART4 driver for the Proxmark5 BWM link.
//
// PM5 talks to the ESP32-C2 BWM over UART4 (PA0=TX, PA1=RX, MUX8) at 460800 8N1
// - values taken from the firmware's own at32_unit_test.c. This is the AT32
// equivalent of the AT91 armsrc/usart.c (which does NOT run on this chip).
// IRQ-driven RX into a ring buffer; polled TX. Init runs AFTER usb_enable() so
// a UART fault can never block USB enumeration.
//
// Only compiled/used when -DWITH_BWM_FORWARD (PM5 only).
//-----------------------------------------------------------------------------

#ifndef __BWM_UART_AT32_H
#define __BWM_UART_AT32_H

#include "common.h"

#define BWM_UART_BAUD   460800   // must match BWM UART_BAUD_RATE_DEFAULT

// Configure GPIO/clock/UART4 + RX interrupt and enable the port.
// Safe to call once, after usb_enable().
void bwm_uart_init(void);

// Blocking (polled) transmit of len bytes. Returns PM3_SUCCESS.
int bwm_uart_write(const uint8_t *data, size_t len);

// Non-blocking: number of bytes currently buffered from the RX ISR.
uint16_t bwm_uart_rx_available(void);

// Non-blocking: copy up to len buffered RX bytes into data; returns the count.
uint32_t bwm_uart_read(uint8_t *data, size_t len);

#endif // __BWM_UART_AT32_H
