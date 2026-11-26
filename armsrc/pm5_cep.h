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

// Refresh the handshake baud divider after an APB2 clock change.
void cep_usart_clock_update(void);

// True once the Flipper handshake has completed and the SPI transport is
// expected to be live. Gate for receive_ng()/reply_ng_internal() so they
// don't pay an SPI-timeout poll on every idle main-loop iteration when no
// Flipper is attached.
bool cep_is_active(void);

// True once the CC controller reports a Flipper physically attached,
// independent of whether the handshake/SPI transport is up yet. Gate for
// AppMain()'s WFI-skip (see appmain.c) - a Flipper merely being plugged in
// is reason enough to stop sleeping between main-loop iterations, before
// any handshake has even started.
bool cep_is_attached(void);

// Rate-limited CC polling. Responds to complete UART handshake requests
// while the CC controller reports a Flipper attached.
void cep_attach_poll(void);

// Check for a command on the SPI RX ring. If bytes are already queued, wait
// briefly for the length header.
bool cep_spi_data_available(void);

// Check for incoming command bytes without waiting. Used by reader loops to
// notice CMD_BREAK_LOOP.
bool cep_spi_rx_pending(void);

// Read len NG bytes from the SPI RX ring, with a timeout for missing bytes.
uint32_t cep_spi_read_ng(uint8_t *data, size_t len);

// Check the remaining command length and discard a mismatched frame.
int cep_spi_check_command_length(size_t remaining);

// Consume the trailing zero at the end of the command.
bool cep_spi_finish_command(void);

// Write `len` raw NG bytes (a whole PacketResponseNG/OLD frame) out over
// SPI1 as one length-prefixed packet. Returns PM3_EIO if the master isn't
// clocking within CEP_SPI_BYTE_TIMEOUT at any point - this can legitimately
// happen (PM5's reply is ready on its own schedule, not the master's), the
// caller just loses this one reply rather than hanging forever.
int cep_spi_write_sync(uint8_t *data, size_t len);

// Hardware-reset SPI1 and bring it back up (see AT32F435/437 errata ES0003
// in pm5_cep.c). Call on any CEP frame error so a corrupted CS-edge sync
// can't persist into the next transaction.
void cep_spi_resync(void);

#endif // __PM5_CEP_H
