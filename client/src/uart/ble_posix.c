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
#include <strings.h>   // strcasecmp
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

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

// ---- name -> address resolution (LE discovery via the BlueZ mgmt API) ----

// AD types carrying the device name (Core Spec, Supplement, Part A).
#define BLE_ADV_NAME_SHORT   0x08
#define BLE_ADV_NAME_FULL    0x09

static long ble_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

// Walk the AD structures of one advertising/scan-response report, looking for a
// Local Name (complete or shortened) that equals `want` (case-insensitive).
// Copies whatever name it finds into `found` for logging. Returns 1 on match.
static int ble_ad_name_matches(const char *want, const uint8_t *ad, size_t adlen,
                               char *found, size_t foundsz) {
    size_t i = 0;
    while (i < adlen) {
        uint8_t flen = ad[i];               // length byte counts the type + value
        if (flen == 0) break;               // padding -> end of meaningful data
        if (i + 1 + flen > adlen) break;    // truncated field -> stop, don't overrun
        uint8_t type = ad[i + 1];
        if (type == BLE_ADV_NAME_FULL || type == BLE_ADV_NAME_SHORT) {
            size_t nlen = flen - 1;
            if (nlen >= foundsz) nlen = foundsz - 1;
            memcpy(found, &ad[i + 2], nlen);
            found[nlen] = 0;
            if (strcasecmp(found, want) == 0) return 1;
        }
        i += flen + 1;
    }
    return 0;
}

// Print an exact, copy-pasteable command to grant the capabilities the LE scan
// needs, using the running binary's own path so it survives rebuilds/renames.
// Also points at the no-privilege alternative (connect by address).
static void ble_print_caps_hint(void) {
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = 0;
        PrintAndLogEx(INFO, "BLE: scanning by name needs extra privileges. Grant them once with:");
        PrintAndLogEx(INFO, "     " _YELLOW_("sudo setcap 'cap_net_raw,cap_net_admin+eip' %s"), exe);
    } else {
        PrintAndLogEx(INFO, "BLE: scanning by name needs " _YELLOW_("CAP_NET_RAW+CAP_NET_ADMIN")
                      " on the client binary (or run with sudo)");
    }
    PrintAndLogEx(INFO, "     or connect by address instead: " _YELLOW_("-p ble:<MAC>") " (no extra privileges)");
}

// ---- BlueZ management (mgmt) API ----
// The legacy hci_le_set_scan_* path is deprecated and returns EIO on many current
// controllers/kernels; discovery now goes through the mgmt control channel (the
// same interface btmgmt and bluetoothd use). mgmt.h isn't shipped by
// libbluetooth-dev, so the small slice of ABI we need is defined here. Still needs
// CAP_NET_RAW (socket) + CAP_NET_ADMIN (discovery) - same as before.
#define MGMT_OP_SET_POWERED           0x0005
#define MGMT_OP_START_DISCOVERY       0x0023
#define MGMT_OP_STOP_DISCOVERY        0x0024
#define MGMT_EV_CMD_COMPLETE          0x0001
#define MGMT_EV_CMD_STATUS            0x0002
#define MGMT_EV_DEVICE_FOUND          0x0012
#define MGMT_ADDR_LE                  0x06   // (1<<1)|(1<<2): LE public + LE random
#define MGMT_STATUS_NOT_POWERED       0x11
#define MGMT_STATUS_PERMISSION_DENIED 0x14

struct mgmt_hdr {
    uint16_t opcode;
    uint16_t index;
    uint16_t len;
} __attribute__((packed));

struct mgmt_ev_device_found {
    bdaddr_t bdaddr;
    uint8_t  addr_type;
    int8_t   rssi;
    uint32_t flags;
    uint16_t eir_len;
    uint8_t  eir[0];
} __attribute__((packed));

// Send one mgmt command (header + up to 8 bytes of parameters). Returns 0 on success.
static int mgmt_send_cmd(int fd, uint16_t opcode, uint16_t index, const void *param, uint16_t plen) {
    uint8_t buf[sizeof(struct mgmt_hdr) + 8];
    if (plen > 8) return -1;
    struct mgmt_hdr *h = (struct mgmt_hdr *)buf;
    h->opcode = htobs(opcode);
    h->index  = htobs(index);
    h->len    = htobs(plen);
    if (plen && param) memcpy(buf + sizeof(*h), param, plen);
    ssize_t w = write(fd, buf, sizeof(*h) + plen);
    return (w == (ssize_t)(sizeof(*h) + plen)) ? 0 : -1;
}

int ble_resolve_name(const char *name, char *out_mac, size_t out_mac_sz, int timeout_ms) {
    if (name == NULL || out_mac == NULL || out_mac_sz < 18) return -1;
    out_mac[0] = 0;

    int index = hci_get_route(NULL);
    if (index < 0) index = 0;                       // default to hci0 if none is "up"

    int fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
    if (fd < 0) {
        PrintAndLogEx(ERR, "BLE: cannot open mgmt socket (%s)", strerror(errno));
        if (errno == EPERM || errno == EACCES) ble_print_caps_hint();
        return -1;
    }

    struct sockaddr_hci sa = {0};
    sa.hci_family  = AF_BLUETOOTH;
    sa.hci_dev     = HCI_DEV_NONE;
    sa.hci_channel = HCI_CHANNEL_CONTROL;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        PrintAndLogEx(ERR, "BLE: cannot bind mgmt control channel (%s)", strerror(errno));
        if (errno == EPERM || errno == EACCES) ble_print_caps_hint();
        close(fd);
        return -1;
    }

    // Power the controller on (idempotent) so discovery works even when bluetoothd
    // is stopped and the adapter was left down.
    uint8_t on = 0x01;
    mgmt_send_cmd(fd, MGMT_OP_SET_POWERED, (uint16_t)index, &on, 1);

    uint8_t scan_type = MGMT_ADDR_LE;
    if (mgmt_send_cmd(fd, MGMT_OP_START_DISCOVERY, (uint16_t)index, &scan_type, 1) != 0) {
        PrintAndLogEx(ERR, "BLE: cannot start LE discovery (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    PrintAndLogEx(INFO, "BLE: scanning up to " _YELLOW_("%d") " ms for " _YELLOW_("%s") " ...", timeout_ms, name);

    int rc = -1;
    char nm[64];
    long deadline = ble_now_ms() + timeout_ms;
    uint8_t buf[512];

    while (ble_now_ms() < deadline) {
        long rem = deadline - ble_now_ms();
        if (rem <= 0) break;
        struct timeval tv = { .tv_sec = rem / 1000, .tv_usec = (rem % 1000) * 1000 };
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(fd, &rs);
        int s = select(fd + 1, &rs, NULL, NULL, &tv);
        if (s < 0) { if (errno == EINTR) break; break; }
        if (s == 0) break;

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < (ssize_t)sizeof(struct mgmt_hdr)) continue;
        struct mgmt_hdr *h = (struct mgmt_hdr *)buf;
        uint16_t ev  = btohs(h->opcode);
        uint16_t idx = btohs(h->index);
        uint16_t len = btohs(h->len);
        if ((size_t)n < sizeof(*h) + len) continue;
        if (idx != (uint16_t)index) continue;           // event for a different controller
        uint8_t *pl = buf + sizeof(*h);

        if (ev == MGMT_EV_DEVICE_FOUND) {
            if (len < sizeof(struct mgmt_ev_device_found)) continue;
            struct mgmt_ev_device_found *df = (struct mgmt_ev_device_found *)pl;
            uint16_t eir_len = btohs(df->eir_len);
            if (sizeof(*df) + eir_len > len) eir_len = (uint16_t)(len - sizeof(*df));
            if (ble_ad_name_matches(name, df->eir, eir_len, nm, sizeof(nm))) {
                ba2str(&df->bdaddr, out_mac);
                PrintAndLogEx(SUCCESS, "BLE: found " _GREEN_("%s") " at " _GREEN_("%s"), nm, out_mac);
                rc = 0;
                break;
            }
        } else if ((ev == MGMT_EV_CMD_STATUS || ev == MGMT_EV_CMD_COMPLETE) && len >= 3) {
            uint16_t cmd = get16(pl);                    // originating command opcode
            uint8_t status = pl[2];
            if (cmd == MGMT_OP_START_DISCOVERY && status != 0) {
                if (status == MGMT_STATUS_PERMISSION_DENIED) {
                    ble_print_caps_hint();
                    break;
                } else if (status == MGMT_STATUS_NOT_POWERED) {
                    PrintAndLogEx(ERR, "BLE: adapter not powered (check " _YELLOW_("rfkill") " / bluetooth service)");
                    break;
                }
                // Busy (0x0A) or similar: a scan may already be running - keep listening.
                PrintAndLogEx(INFO, "BLE: start-discovery returned mgmt status 0x%02x, listening anyway", status);
            }
        }
    }

    uint8_t st = MGMT_ADDR_LE;
    mgmt_send_cmd(fd, MGMT_OP_STOP_DISCOVERY, (uint16_t)index, &st, 1);
    close(fd);

    if (rc != 0)
        PrintAndLogEx(ERR, "BLE: no advertising device named " _YELLOW_("%s") " seen within %d ms", name, timeout_ms);
    return rc;
}

// Retry the L2CAP connect briefly: a create-connection issued as an LE scan
// tears down can be refused, and the peer may be between advertising events.
#define BLE_CONNECT_TRIES        6
#define BLE_CONNECT_BACKOFF_MS   150

// Open an L2CAP/ATT socket and connect to `mac`. Returns the fd on success,
// -1 on a retryable connect failure (errno set to the connect error), or
// -2 on a hard setup failure (socket/bind), which is already logged.
static int ble_l2cap_connect(const char *mac) {
    int fd = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (fd < 0) {
        PrintAndLogEx(ERR, "BLE: cannot create L2CAP socket (%s)", strerror(errno));
        return -2;
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
        return -2;
    }

    struct sockaddr_l2 dst = {0};
    dst.l2_family = AF_BLUETOOTH;
    dst.l2_bdaddr_type = BDADDR_LE_PUBLIC;   // BWM advertises an LE public address
    str2ba(mac, &dst.l2_bdaddr);
    dst.l2_cid = htobs(ATT_CID);
    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        int e = errno;          // close() may clobber errno; preserve it for the caller
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

int ble_connect(const char *mac, uint16_t chr_uuid16, ble_conn_t *conn) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;

    int fd = -1;
    int last_errno = 0;
    for (int attempt = 1; attempt <= BLE_CONNECT_TRIES; attempt++) {
        fd = ble_l2cap_connect(mac);
        if (fd >= 0) break;
        if (fd == -2) return -1;              // hard setup failure, already logged
        last_errno = errno;                   // retryable connect failure
        if (attempt < BLE_CONNECT_TRIES) {
            usleep(BLE_CONNECT_BACKOFF_MS * 1000);
        }
    }
    if (fd < 0) {
        PrintAndLogEx(ERR, "BLE: cannot connect to " _YELLOW_("%s") " (%s)", mac, strerror(last_errno));
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
