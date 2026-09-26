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
// Proxmark5 CEP (Type-C Extended Port) transport to the Flipper Zero FAP.
//
// USART1 (PA9, single-wire half-duplex, 2400 8N1) carries a one-shot ASCII
// handshake ("iamf0rupm5" -> "yes"); once attached, standard PM3 NG frames
// ride length-prefixed over SPI1 (PA4-7). See GH issue #3667 for the full
// protocol writeup this was extracted from (armsrc/at32_unit_test.c, dxl).
//
// Enabled by -DWITH_CEP. Independent of -DWITH_BWM_FORWARD - both may be
// compiled and running at the same time.
//-----------------------------------------------------------------------------

#ifndef __PM5_CEP_H
#define __PM5_CEP_H

#include "common.h"

// Bring up the CC-controller I2C polling state. Call once from AppMain(),
// after usb_enable() (mirrors bwm_uart_init() placement). Never blocks.
void cep_init(void);

// True once the Flipper handshake has completed and the SPI transport is
// expected to be live. Gate for receive_ng()/reply_ng_internal() so they
// don't pay an SPI-timeout poll on every idle main-loop iteration when no
// Flipper is attached.
bool cep_is_active(void);

// Rate-limited (see PM5_CEP_ATTACH_POLL_MS), non-blocking. Call once per
// AppMain() main-loop iteration, alongside bwm_autooff_check(). Detects the
// Flipper attach/detach transition via the CC controller and, on a fresh
// attach, runs the one-shot UART handshake. Safe no-op the rest of the time.
void cep_attach_poll(void);

// Gate for receive_ng(): true once the length header of an inbound SPI frame
// has been seen. Blocks (with an internal timeout) waiting for the 2-byte
// length header - mirrors usart_rxdata_available()'s call shape, not a
// simple non-blocking peek.
bool cep_spi_data_available(void);

// Read up to `len` raw NG bytes off SPI1. Returns the number of bytes
// actually read before an internal per-byte timeout gave up early.
uint32_t cep_spi_read_ng(uint8_t *data, size_t len);

// Write `len` raw NG bytes (a whole PacketResponseNG/OLD frame) out over
// SPI1 as one length-prefixed packet. Always returns PM3_SUCCESS today (the
// underlying spi_i2s_data_transmit() calls are blocking-until-ready).
int cep_spi_write_sync(uint8_t *data, size_t len);

#endif // __PM5_CEP_H
