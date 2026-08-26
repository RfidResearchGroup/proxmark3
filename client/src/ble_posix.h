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
// Native Linux BLE transport for the Proxmark5 BWM (Nordic-style SPP over GATT).
//
// Uses a raw L2CAP socket on the ATT fixed CID (no BlueZ daemon / D-Bus / extra
// libraries beyond libbluetooth, which the client already links). Speaks just
// enough ATT to: exchange MTU, discover the SPP data characteristic by UUID,
// enable notifications via its CCCD, then shuttle raw bytes (TX = Write Command,
// RX = Handle Value Notification). This mirrors the pm5_ble_bridge.py transport.
//
// Linux-only, connect-by-address. Requires HAVE_BLUEZ.
//-----------------------------------------------------------------------------

#ifndef __BLE_POSIX_H
#define __BLE_POSIX_H

#include "common.h"

#ifdef HAVE_BLUEZ

// BWM SPP data characteristic (16-bit UUID; write to TX, notify for RX).
#define BLE_SPP_CHR_UUID16   0xAE88

#define BLE_LEFTOVER_MAX     1024

typedef struct {
    int      fd;                 // connected L2CAP/ATT socket
    uint16_t val_handle;         // SPP characteristic value handle
    uint16_t mtu;                // negotiated ATT_MTU
    uint8_t  leftover[BLE_LEFTOVER_MAX];  // RX bytes not yet consumed
    size_t   leftover_len;
} ble_conn_t;

// Connect to `mac` (LE public), discover the SPP char, subscribe to notifications.
// `chr_uuid16` selects the data characteristic (pass BLE_SPP_CHR_UUID16).
// Returns 0 on success (conn filled), negative on error. On error conn->fd == -1.
int ble_connect(const char *mac, uint16_t chr_uuid16, ble_conn_t *conn);

// Send len bytes to the device, chunked to (mtu-3) as ATT Write Commands.
// Returns 0 on success, negative on error.
int ble_send(ble_conn_t *conn, const uint8_t *data, size_t len);

// Receive up to maxlen payload bytes (drains leftover first, then waits up to
// timeout_ms for notifications). *out_len set to bytes copied. Returns 0 on
// success (including 0 bytes on timeout), negative on error/disconnect.
int ble_recv(ble_conn_t *conn, uint8_t *buf, size_t maxlen, size_t *out_len, int timeout_ms);

void ble_close(ble_conn_t *conn);

#endif // HAVE_BLUEZ
#endif // __BLE_POSIX_H
