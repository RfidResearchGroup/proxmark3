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
// Proxmark5 Battery Wireless Module (BWM) transport shim.
//
// This shim wraps outgoing NG/OLD reply bytes into a SEND_FORWARD_DATA frame and
// de-frames incoming DATA_FORWARD frames back into a raw NG byte stream, so the
// stock reply_ng()/receive_ng() paths work unchanged over the BWM link.
//
// Enabled by -DWITH_BWM_FORWARD (implies WITH_FPC_USART_HOST).
//-----------------------------------------------------------------------------

#ifndef __BWM_FORWARD_H
#define __BWM_FORWARD_H

#include "common.h"
#include "bwm_frame.h"

// Flow control (ack window) - ARM-side only, no BWM firmware change required.
// The ESP already replies to every forward frame with a SLAVE_RESP echoing
// cmd=SEND_FORWARD_DATA, and it sends that ack only *after* app_ble_send() has
// drained the frame to BLE. So the un-acked count is a live measure of how far
// ahead of the wireless link we are. We allow up to BWM_FC_WINDOW frames in
// flight, then block for an ack before sending more - which paces us to the real
// BLE/WiFi rate and prevents the ESP UART-RX overrun that dropped bulk downloads.
// WINDOW frames must fit the ESP UART RX FIFO + wireless send buffer.
// Ceiling on un-acked forward frames. On a download the ESP acks steadily so
// this never bites; it only matters on a bidirectional UPLOAD, where the ESP
// defers the small acks while forwarding large incoming chunks. A tight value
// (4) let inflight hit the cap and stall the AT32 past the client timeout, so
// keep enough headroom to ride out delayed acks. Only ~1 response is ever
// really in flight during an upload, so this does not risk an ESP overrun.
#define BWM_FC_WINDOW               16     // max un-acked forward frames in flight
#ifndef BWM_FC_ACK_TIMEOUT_MS
// Hard cap (ms) on how long a forward write may block the main loop waiting for
// acks. A spin COUNT was unbounded in wall-clock time and could hang the main
// loop long enough that the client gives up and the device looks dead (USB still
// enumerates on interrupts). Time-bounded => the main loop is always serviced.
#define BWM_FC_ACK_TIMEOUT_MS       50     // safety valve: proceed if acks stall, never hard-hang
#endif // safety valve: give up waiting for credit (avoid hard hang)

// Wrap `len` raw reply bytes (a whole PacketResponseNG/OLD frame) into one
// SEND_FORWARD_DATA app_com frame and write it synchronously to the FPC USART.
// Returns PM3_SUCCESS or the underlying usart error. Drop-in for the FPC
// usart_writebuffer_sync() call in reply_ng_internal()/reply_old().
int bwm_fwd_writebuffer_sync(const uint8_t *data, size_t len);

// De-framed read: returns up to `len` raw NG bytes recovered from inbound
// DATA_FORWARD frames, blocking-with-timeout exactly like usart_read_ng().
// Drop-in for usart_read_ng() as the receive_ng() read callback.
uint32_t bwm_read_ng(uint8_t *data, size_t len);

// >0 when raw bytes are waiting on the FPC USART (gate for receive_ng()).
uint16_t bwm_fwd_rxdata_available(void);

// Bring the ESP<->AT32 UART to `target` baud: adopt it if the ESP is already
// there (its baud survives an AT32-only reset), else negotiate up via app_com
// cmd 1011 and re-init UART4 to match. Returns true if the link runs at
// `target`; false (left at the boot baud) if no ESP answered or the switch
// could not be verified. Call once after bwm_uart_init().
bool bwm_fwd_negotiate_baud(uint32_t target);

#endif // __BWM_FORWARD_H
