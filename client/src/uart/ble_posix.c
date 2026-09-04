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
// Native Linux BLE transport for the Proxmark5 BWM - see ble_posix.h.
//-----------------------------------------------------------------------------

#include "ble_posix.h"

#ifdef HAVE_BLUEZ

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

#include "ui.h"        // PrintAndLogEx
#include "pm3_cmd.h"   // PM3_* (only for messaging parity; returns are 0/neg here)

#define ATT_CID                 4

// ATT opcodes
#define ATT_OP_ERROR            0x01
#define ATT_OP_MTU_REQ          0x02
#define ATT_OP_MTU_RSP          0x03
#define ATT_OP_FIND_INFO_REQ    0x04
#define ATT_OP_FIND_INFO_RSP    0x05
#define ATT_OP_READ_BY_TYPE_REQ 0x08
#define ATT_OP_READ_BY_TYPE_RSP 0x09
#define ATT_OP_WRITE_REQ        0x12
#define ATT_OP_WRITE_RSP        0x13
#define ATT_OP_WRITE_CMD        0x52
#define ATT_OP_HANDLE_NOTIFY    0x1B
#define ATT_OP_HANDLE_INDICATE  0x1D

// GATT attribute type UUIDs
#define GATT_CHARACTERISTIC     0x2803
#define GATT_CCCD               0x2902

#define ATT_DEFAULT_MTU         23
#define ATT_PREFERRED_MTU       517

// ---- small endian helpers ----
static inline void put16(uint8_t *p, uint16_t v) { p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; }
static inline uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

// Blocking send of one ATT PDU (one L2CAP SDU).
static int att_write_pdu(int fd, const uint8_t *pdu, size_t len) {
    ssize_t n = send(fd, pdu, len, 0);
    return (n == (ssize_t)len) ? 0 : -1;
}

// Wait up to timeout_ms for one PDU; returns length (>0), 0 on timeout, -1 error.
static int att_read_pdu(int fd, uint8_t *buf, size_t maxlen, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    int r = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (r < 0) return -1;
    if (r == 0) return 0;
    ssize_t n = recv(fd, buf, maxlen, 0);
    if (n <= 0) return -1;
    return (int)n;
}

// Send a request PDU and read PDUs until we get one starting with want_op (or an
// ATT error). Notifications that arrive early are ignored here (discovery runs
// before we subscribe, so none are expected). Returns rsp length or -1.
static int att_txn(int fd, const uint8_t *req, size_t reqlen, uint8_t want_op,
                   uint8_t *rsp, size_t rspmax) {
    if (att_write_pdu(fd, req, reqlen) != 0) return -1;
    for (int tries = 0; tries < 8; tries++) {
        int n = att_read_pdu(fd, rsp, rspmax, 3000);
        if (n <= 0) return -1;
        if (rsp[0] == want_op) return n;
        if (rsp[0] == ATT_OP_ERROR) return -1;   // caller decides meaning
        // ignore anything unexpected and keep reading
    }
    return -1;
}

static int att_exchange_mtu(int fd, uint16_t *out_mtu) {
    uint8_t req[3] = { ATT_OP_MTU_REQ, 0, 0 };
    put16(&req[1], ATT_PREFERRED_MTU);
    uint8_t rsp[64];
    int n = att_txn(fd, req, sizeof(req), ATT_OP_MTU_RSP, rsp, sizeof(rsp));
    if (n < 3) {
        *out_mtu = ATT_DEFAULT_MTU;   // peer may not support the request; that's fine
        return 0;
    }
    uint16_t server_mtu = get16(&rsp[1]);
    uint16_t neg = (server_mtu < ATT_PREFERRED_MTU) ? server_mtu : ATT_PREFERRED_MTU;
    if (neg < ATT_DEFAULT_MTU) neg = ATT_DEFAULT_MTU;
    *out_mtu = neg;
    return 0;
}

// Discover the value handle of the characteristic whose 16-bit UUID == uuid16,
// via Read-By-Type on the Characteristic declaration (0x2803).
static int att_find_char(int fd, uint16_t uuid16, uint16_t *out_val_handle) {
    uint16_t start = 0x0001;
    while (start != 0x0000) {
        uint8_t req[7] = { ATT_OP_READ_BY_TYPE_REQ };
        put16(&req[1], start);
        put16(&req[3], 0xFFFF);
        put16(&req[5], GATT_CHARACTERISTIC);
        uint8_t rsp[512];
        if (att_write_pdu(fd, req, sizeof(req)) != 0) return -1;
        int n = att_read_pdu(fd, rsp, sizeof(rsp), 3000);
        if (n <= 0) return -1;
        if (rsp[0] == ATT_OP_ERROR) return -1;          // 0x0A = not found -> end
        if (rsp[0] != ATT_OP_READ_BY_TYPE_RSP || n < 2) return -1;

        uint8_t elen = rsp[1];                            // per-entry length
        if (elen < 7) return -1;
        uint16_t last = 0;
        for (int off = 2; off + elen <= n; off += elen) {
            const uint8_t *e = &rsp[off];
            uint16_t attr_handle = get16(&e[0]);          // declaration handle
            uint16_t val_handle  = get16(&e[3]);          // characteristic value handle
            last = attr_handle;
            if (elen == 7) {                              // 16-bit char UUID
                uint16_t cuuid = get16(&e[5]);
                if (cuuid == uuid16) {
                    *out_val_handle = val_handle;
                    return 0;
                }
            }
            // elen == 21 -> 128-bit UUID; the BWM SPP char is 16-bit, skip.
        }
        if (last == 0xFFFF || last == 0) break;
        start = last + 1;
    }
    return -1;   // not found
}

// Find the CCCD (0x2902) handle that belongs to the characteristic value handle,
// via Find-Information over the handles right after it.
static int att_find_cccd(int fd, uint16_t val_handle, uint16_t *out_cccd) {
    uint16_t start = val_handle + 1;
    // scan a small window; the CCCD directly follows a notifiable char in practice
    uint16_t end = val_handle + 8;
    uint8_t req[5] = { ATT_OP_FIND_INFO_REQ };
    put16(&req[1], start);
    put16(&req[3], end);
    uint8_t rsp[512];
    if (att_write_pdu(fd, req, sizeof(req)) != 0) return -1;
    int n = att_read_pdu(fd, rsp, sizeof(rsp), 3000);
    if (n < 2) return -1;
    if (rsp[0] != ATT_OP_FIND_INFO_RSP) return -1;
    uint8_t fmt = rsp[1];                                  // 1 = 16-bit, 2 = 128-bit
    if (fmt != 0x01) return -1;                            // CCCD is a 16-bit UUID
    for (int off = 2; off + 4 <= n; off += 4) {
        uint16_t handle = get16(&rsp[off]);
        uint16_t uuid   = get16(&rsp[off + 2]);
        if (uuid == GATT_CCCD) {
            *out_cccd = handle;
            return 0;
        }
    }
    return -1;
}

static int att_subscribe(int fd, uint16_t cccd_handle) {
    uint8_t req[5] = { ATT_OP_WRITE_REQ };
    put16(&req[1], cccd_handle);
    req[3] = 0x01;   // notifications
    req[4] = 0x00;
    uint8_t rsp[16];
    int n = att_txn(fd, req, sizeof(req), ATT_OP_WRITE_RSP, rsp, sizeof(rsp));
    return (n >= 1) ? 0 : -1;
}

int ble_connect(const char *mac, uint16_t chr_uuid16, ble_conn_t *conn) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;

    int fd = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (fd < 0) {
        PrintAndLogEx(ERR, "BLE: cannot create L2CAP socket (%s)", strerror(errno));
        return -1;
    }

    // Enlarge the kernel RX buffer so bursts of notifications queue instead of
    // being dropped while the comms thread drains them.
    int rcvbuf = 256 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_l2 src = {0};
    src.l2_family = AF_BLUETOOTH;
    src.l2_bdaddr_type = BDADDR_LE_PUBLIC;
    bacpy(&src.l2_bdaddr, BDADDR_ANY);
    src.l2_cid = htobs(ATT_CID);
    if (bind(fd, (struct sockaddr *)&src, sizeof(src)) < 0) {
        PrintAndLogEx(ERR, "BLE: bind failed (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_l2 dst = {0};
    dst.l2_family = AF_BLUETOOTH;
    dst.l2_bdaddr_type = BDADDR_LE_PUBLIC;   // BWM advertises an LE public address
    str2ba(mac, &dst.l2_bdaddr);
    dst.l2_cid = htobs(ATT_CID);
    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        PrintAndLogEx(ERR, "BLE: cannot connect to " _YELLOW_("%s") " (%s)", mac, strerror(errno));
        close(fd);
        return -1;
    }

    conn->fd = fd;

    if (att_exchange_mtu(fd, &conn->mtu) != 0) {
        PrintAndLogEx(ERR, "BLE: ATT MTU exchange failed");
        goto fail;
    }

    if (att_find_char(fd, chr_uuid16, &conn->val_handle) != 0) {
        PrintAndLogEx(ERR, "BLE: SPP characteristic " _YELLOW_("0x%04X") " not found", chr_uuid16);
        goto fail;
    }

    uint16_t cccd = 0;
    if (att_find_cccd(fd, conn->val_handle, &cccd) != 0) {
        PrintAndLogEx(ERR, "BLE: notification descriptor (CCCD) not found");
        goto fail;
    }
    if (att_subscribe(fd, cccd) != 0) {
        PrintAndLogEx(ERR, "BLE: failed to enable notifications");
        goto fail;
    }

    PrintAndLogEx(SUCCESS, "BLE connected, MTU " _GREEN_("%u") ", char handle " _GREEN_("0x%04X"),
                  conn->mtu, conn->val_handle);
    return 0;

fail:
    close(fd);
    conn->fd = -1;
    return -1;
}

int ble_send(ble_conn_t *conn, const uint8_t *data, size_t len) {
    if (conn->fd < 0) return -1;
    size_t chunk = (conn->mtu > 3) ? (size_t)(conn->mtu - 3) : 20;
    uint8_t pdu[3 + 517];
    for (size_t off = 0; off < len; off += chunk) {
        size_t clen = (len - off < chunk) ? (len - off) : chunk;
        pdu[0] = ATT_OP_WRITE_CMD;
        put16(&pdu[1], conn->val_handle);
        memcpy(&pdu[3], data + off, clen);
        if (att_write_pdu(conn->fd, pdu, 3 + clen) != 0) {
            return -1;
        }
    }
    return 0;
}

int ble_recv(ble_conn_t *conn, uint8_t *buf, size_t maxlen, size_t *out_len, int timeout_ms) {
    if (conn->fd < 0) return -1;
    size_t got = 0;

    // 1) drain any leftover payload from a previous oversized notification
    if (conn->leftover_len) {
        size_t take = (conn->leftover_len < maxlen) ? conn->leftover_len : maxlen;
        memcpy(buf, conn->leftover, take);
        got = take;
        size_t rem = conn->leftover_len - take;
        if (rem) memmove(conn->leftover, conn->leftover + take, rem);
        conn->leftover_len = rem;
        if (got == maxlen) { *out_len = got; return 0; }
    }

    // 2) pull notifications until buffer full or a real timeout.
    // NOTE: the client's comms parser requires uart_receive() to return exactly
    // the requested length in one call (it checks rxlen != length). A single NG
    // frame can span several notifications (payload > ATT_MTU-3), so we must keep
    // waiting up to timeout_ms for the in-flight tail, not bail after the first
    // burst. Waiting stops as soon as we reach maxlen, so small single-notification
    // frames still return immediately.
    uint8_t pdu[3 + 517];
    for (;;) {
        int n = att_read_pdu(conn->fd, pdu, sizeof(pdu), timeout_ms);
        if (n < 0) { *out_len = got; return (got > 0) ? 0 : -1; }
        if (n == 0) break;                                  // real timeout / no more
        if ((pdu[0] != ATT_OP_HANDLE_NOTIFY && pdu[0] != ATT_OP_HANDLE_INDICATE) || n < 3)
            continue;                                       // ignore non-notifications
        if (get16(&pdu[1]) != conn->val_handle) continue;   // not our char
        const uint8_t *val = &pdu[3];
        size_t vlen = (size_t)n - 3;
        size_t space = maxlen - got;
        size_t take = (vlen < space) ? vlen : space;
        memcpy(buf + got, val, take);
        got += take;
        if (take < vlen) {                                  // stash the remainder
            size_t rem = vlen - take;
            if (rem > BLE_LEFTOVER_MAX) rem = BLE_LEFTOVER_MAX;
            memcpy(conn->leftover, val + take, rem);
            conn->leftover_len = rem;
        }
        if (got == maxlen) break;
    }

    *out_len = got;
    return 0;
}

void ble_close(ble_conn_t *conn) {
    if (conn && conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

#endif // HAVE_BLUEZ
