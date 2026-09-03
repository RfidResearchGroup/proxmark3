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
// Proxmark5 Battery Wireless Module (BWM) transport shim - see bwm_forward.h.
//-----------------------------------------------------------------------------

#include "bwm_forward.h"

#include "bwm_uart_at32.h"
#include "pm3_cmd.h"    // PM3_CMD_DATA_SIZE, PM3_* return codes
#include "ticks_apis.h" // SpinDelay
#include "string.h"

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

// CRC-16/CCITT-FALSE, byte-identical to the BWM firmware's crc16_ccitt()
// (poly 0x1021, init 0xFFFF, MSB-first, no reflection, no xorout).
static uint16_t bwm_crc16(const uint8_t *data, size_t len, uint16_t crc) {
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (uint8_t b = 0; b < 8; b++) {
            if (crc & 0x8000) {
                crc = (uint16_t)((crc << 1) ^ BWM_CRC16_POLY);
            } else {
                crc = (uint16_t)(crc << 1);
            }
        }
    }
    return crc;
}

// ---------------------------------------------------------------------------
// TX: wrap one reply frame into a SEND_FORWARD_DATA app_com frame.
// A full NG/OLD frame is <= PM3_CMD_DATA_SIZE + a small header/postamble, well
// under the BWM 4096-byte payload cap, so a single frame always suffices.
// ---------------------------------------------------------------------------
#define BWM_TX_OVERHEAD   (2 + 2 + 2 + 2)   // hdr + cmd + len + crc
#define BWM_TX_MAX_PAYLOAD (PM3_CMD_DATA_SIZE + 64)   // NG/OLD frame ceiling
#define BWM_TX_BUFSZ      (BWM_TX_OVERHEAD + BWM_TX_MAX_PAYLOAD)

static void bwm_pump(void);   // fwd decl: TX gate pumps RX to collect forward-frame acks

// --- Flow control (ack window) ---------------------------------------------
// s_fwd_inflight: forward frames sent but not yet acked by the ESP. Bumped on
// send, decremented when a SLAVE_RESP echoing cmd=SEND_FORWARD_DATA arrives.
// We may send while it is below BWM_FC_WINDOW; at the cap we wait for an ack.
static volatile int16_t s_fwd_inflight = 0;

// Set true by the parser when a SLAVE_RESP echoing BWM_CMD_SET_UART_BAUD arrives
// (the ESP's ack for a baud-set request). Consumed by bwm_fwd_negotiate_baud().
static volatile bool s_baud_ack = false;

// Set true by the parser on a SLAVE_RESP for BWM_CMD_GET_UART_BAUD - proof the
// ESP is alive and responding at the baud we just switched to (verify step).
static volatile bool s_getbaud_ack = false;

int bwm_fwd_writebuffer_sync(const uint8_t *data, size_t len) {
    static uint8_t frame[BWM_TX_BUFSZ];   // single-threaded bare-metal: static OK

    if (len > BWM_TX_MAX_PAYLOAD) {
        len = BWM_TX_MAX_PAYLOAD;         // defensive; should never trigger
    }

    size_t idx = 0;
    // Flow control: block while the in-flight window is full, waiting for the
    // ESP to ack an earlier forward frame. bwm_pump() drains the IRQ-filled RX
    // ring, so acks are collected even while we sit inside a tight download loop
    // (the reply_old firehose). The spin cap is a safety valve so a dead or
    // disconnected ESP can't hard-hang us. A window >= 1 means single command
    // replies never block - only sustained bursts hit the cap.
    {
        uint32_t t0 = GetTickCount();
        while (s_fwd_inflight >= BWM_FC_WINDOW) {
            bwm_pump();
            if (GetTickCountDelta(t0) > BWM_FC_ACK_TIMEOUT_MS) {
                s_fwd_inflight = 0;   // best-effort: assume the pipe cleared, never hard-hang
                break;
            }
        }
    }

    frame[idx++] = BWM_HDR_HOST_CMD_1;
    frame[idx++] = BWM_HDR_HOST_CMD_2;
    frame[idx++] = (uint8_t)(BWM_CMD_SEND_FORWARD_DATA & 0xFF);
    frame[idx++] = (uint8_t)((BWM_CMD_SEND_FORWARD_DATA >> 8) & 0xFF);
    frame[idx++] = (uint8_t)(len & 0xFF);
    frame[idx++] = (uint8_t)((len >> 8) & 0xFF);
    if (len) {
        memcpy(&frame[idx], data, len);
        idx += len;
    }
    uint16_t crc = bwm_crc16(frame, idx, BWM_CRC16_INIT);
    frame[idx++] = (uint8_t)(crc & 0xFF);
    frame[idx++] = (uint8_t)((crc >> 8) & 0xFF);

    int wr = bwm_uart_write(frame, idx);
    s_fwd_inflight++;   // one more forward frame awaiting its ack
    return wr;
}

// ---------------------------------------------------------------------------
// RX: persistent app_com de-framer. Feeds raw FPC bytes through a state machine
// and pushes the payloads of valid DATA_FORWARD (0xD2 0xD3 / cmd 8089) frames
// into a byte FIFO that bwm_read_ng() drains. Non-DATA_FORWARD frames (slave
// responses, forwarded logs, cmd-error reports) are validated and discarded.
// ---------------------------------------------------------------------------
#define BWM_DEFIFO_SZ     2048            // >= one full NG frame's payload
#define BWM_RXFRAME_MAX   (PM3_CMD_DATA_SIZE + 64)

typedef enum {
    S_IDLE = 0, S_HDR2, S_CMD_LO, S_CMD_HI, S_LEN_LO, S_LEN_HI, S_PAYLOAD, S_CRC_LO, S_CRC_HI
} bwm_state_t;

typedef struct {
    bwm_state_t state;
    uint8_t     hdr1;
    bool        is_bcast;     // header pair is 0xD2 0xD3
    uint16_t    cmd;
    uint16_t    len;
    uint16_t    got;          // payload bytes received
    uint16_t    crc_calc;     // running CRC over hdr..payload
    uint16_t    crc_recv;
    uint8_t     payload[BWM_RXFRAME_MAX];
} bwm_parser_t;

static bwm_parser_t s_p = { .state = S_IDLE };

// De-framed payload ring
static uint8_t  s_fifo[BWM_DEFIFO_SZ];
static volatile uint16_t s_fifo_head = 0;   // write
static volatile uint16_t s_fifo_tail = 0;   // read

static uint16_t fifo_count(void) {
    return (uint16_t)((s_fifo_head - s_fifo_tail) & (BWM_DEFIFO_SZ - 1));
}
static void fifo_push(uint8_t b) {
    uint16_t next = (uint16_t)((s_fifo_head + 1) & (BWM_DEFIFO_SZ - 1));
    if (next != s_fifo_tail) {              // drop on overflow rather than corrupt
        s_fifo[s_fifo_head] = b;
        s_fifo_head = next;
    }
}
static uint8_t fifo_pop(void) {
    uint8_t b = s_fifo[s_fifo_tail];
    s_fifo_tail = (uint16_t)((s_fifo_tail + 1) & (BWM_DEFIFO_SZ - 1));
    return b;
}

static void bwm_reset_frame(bwm_parser_t *p) {
    p->state = S_IDLE;
}

// Update running CRC one byte at a time (mirrors the streaming update in the
// BWM firmware parser).
static void crc_step(bwm_parser_t *p, uint8_t byte) {
    p->crc_calc = bwm_crc16(&byte, 1, p->crc_calc);
}

static void bwm_feed_byte(bwm_parser_t *p, uint8_t byte) {
    switch (p->state) {
        case S_IDLE:
            if (byte == BWM_HDR_SLAVE_BCAST_1) {
                p->hdr1 = byte;
                p->is_bcast = true;
                p->state = S_HDR2;
            } else if (byte == BWM_HDR_SLAVE_RESP_1) {
                p->hdr1 = byte;
                p->is_bcast = false;
                p->state = S_HDR2;
            }
            // any other byte: stay idle (resync)
            break;

        case S_HDR2: {
            bool ok = (p->is_bcast  && byte == BWM_HDR_SLAVE_BCAST_2) ||
                      (!p->is_bcast && byte == BWM_HDR_SLAVE_RESP_2);
            if (!ok) {
                // header mismatch: reset and re-examine this byte as a potential SOF
                p->state = S_IDLE;
                bwm_feed_byte(p, byte);
                return;
            }
            uint8_t hdr[2] = { p->hdr1, byte };
            p->crc_calc = bwm_crc16(hdr, 2, BWM_CRC16_INIT);
            p->state = S_CMD_LO;
            break;
        }

        case S_CMD_LO:
            p->cmd = byte;
            crc_step(p, byte);
            p->state = S_CMD_HI;
            break;
        case S_CMD_HI:
            p->cmd |= (uint16_t)byte << 8;
            crc_step(p, byte);
            p->state = S_LEN_LO;
            break;
        case S_LEN_LO:
            p->len = byte;
            crc_step(p, byte);
            p->state = S_LEN_HI;
            break;
        case S_LEN_HI:
            p->len |= (uint16_t)byte << 8;
            crc_step(p, byte);
            p->got = 0;
            if (p->len > BWM_RXFRAME_MAX) {            // oversized -> drop frame
                bwm_reset_frame(p);
            } else {
                p->state = (p->len == 0) ? S_CRC_LO : S_PAYLOAD;
            }
            break;

        case S_PAYLOAD:
            p->payload[p->got++] = byte;
            crc_step(p, byte);
            if (p->got >= p->len) {
                p->state = S_CRC_LO;
            }
            break;

        case S_CRC_LO:
            p->crc_recv = byte;
            p->state = S_CRC_HI;
            break;
        case S_CRC_HI:
            p->crc_recv |= (uint16_t)byte << 8;
            if (p->crc_recv == p->crc_calc) {
                if (p->is_bcast && p->cmd == BWM_CMD_DATA_FORWARD) {
                    for (uint16_t i = 0; i < p->len; i++) {
                        fifo_push(p->payload[i]);
                    }
                } else if ((p->is_bcast == false) && p->cmd == BWM_CMD_SEND_FORWARD_DATA) {
                    // SLAVE_RESP ack for a forward frame -> one slot freed
                    if (s_fwd_inflight > 0) {
                        s_fwd_inflight--;
                    }
                } else if ((p->is_bcast == false) && p->cmd == BWM_CMD_SET_UART_BAUD) {
                    // SLAVE_RESP ack for a baud-set request (see negotiate below)
                    s_baud_ack = true;
                } else if ((p->is_bcast == false) && p->cmd == BWM_CMD_GET_UART_BAUD) {
                    // SLAVE_RESP for our GET_BAUD verify probe
                    s_getbaud_ack = true;
                }
            }
            // valid non-DATA_FORWARD frames and CRC failures alike: just resync
            bwm_reset_frame(p);
            break;

        default:
            bwm_reset_frame(p);
            break;
    }
}

// Pull whatever raw framed bytes are waiting and run them through the parser.
static void bwm_pump(void) {
    uint8_t scratch[64];
    uint16_t avail = bwm_uart_rx_available();
    while (avail) {
        uint32_t n = bwm_uart_read(scratch, MIN((uint32_t)avail, (uint32_t)sizeof(scratch)));
        if (n == 0) {
            break;
        }
        for (uint32_t i = 0; i < n; i++) {
            bwm_feed_byte(&s_p, scratch[i]);
        }
        avail = bwm_uart_rx_available();
    }
}

uint16_t bwm_fwd_rxdata_available(void) {
    if (fifo_count() > 0) {
        return fifo_count();
    }
    // No de-framed payload yet, but raw frame bytes may be waiting; pump once so
    // receive_ng()'s gate reflects real forward data.
    bwm_pump();
    return fifo_count();
}

uint32_t bwm_read_ng(uint8_t *data, size_t len) {
    if (len == 0) {
        return 0;
    }

    // Same bounded-retry budget shape as bwm_uart_read(); USART_SLOW_LINK (set
    // for the BWM/BLE link) widens it so a slow round-trip doesn't time out.
    uint32_t tryconstant = 0;
#ifdef USART_SLOW_LINK
    tryconstant = 50000;
#endif
    uint32_t maxtry = 10 * (3000000 / BWM_UART_BAUD) + tryconstant;

    uint32_t out = 0;
    uint32_t try = 0;
    while (out < len) {
        while (out < len && fifo_count() > 0) {
            data[out++] = fifo_pop();
            try = 0;
        }
        if (out >= len) {
            break;
        }
        uint16_t before = fifo_count();
        bwm_pump();
        if (fifo_count() != before) {
            try = 0;
            continue;
        }
        if (try++ >= maxtry) {
                break;
            }
    }
    return out;
}


// ---------------------------------------------------------------------------
// Runtime baud negotiation.
// The ESP boots at BWM_UART_BAUD and accepts a HOST_CMD (cmd 1011) carrying a
// u32 LE target baud. Its handler test-switches, rolls back, acks at the OLD
// baud with a SLAVE_RESP echoing cmd 1011, then commits to the new baud. So we
// send the request at the current baud, wait for that ack, then switch our own
// UART4 to match. On timeout (old ESP without the command, or a lost ack) we
// leave the link at the boot baud - it keeps working, just slower.
//
// The ESP keeps its baud across an AT32-only reset (bootloader, hw reset,
// flash), so probe both rates first and adopt the one it answers at.
// ---------------------------------------------------------------------------
#define BWM_BAUD_ACK_WAIT_MS   300   // per-attempt wait for the ESP ack
#define BWM_BAUD_ATTEMPTS      3     // resend attempts before giving up
#define BWM_BAUD_VERIFY_MS     150   // per-probe wait for the GET_BAUD reply
#define BWM_BAUD_VERIFY_TRIES  5     // GET_BAUD probes before declaring the switch failed
#define BWM_BAUD_PROBE_ROUNDS  4     // boot/target probe pairs

// Probe the ESP at the CURRENT baud with GET_UART_BAUD; true only if it answers,
// i.e. it really is running at the baud we just switched to. Retried by the
// caller so a single lost probe on a good link does not force a needless revert.
static bool bwm_verify_baud(void) {
    uint8_t f[2 + 2 + 2 + 2];
    size_t i = 0;
    f[i++] = BWM_HDR_HOST_CMD_1;
    f[i++] = BWM_HDR_HOST_CMD_2;
    f[i++] = (uint8_t)(BWM_CMD_GET_UART_BAUD & 0xFF);
    f[i++] = (uint8_t)((BWM_CMD_GET_UART_BAUD >> 8) & 0xFF);
    f[i++] = 0;
    f[i++] = 0;
    uint16_t crc = bwm_crc16(f, i, BWM_CRC16_INIT);
    f[i++] = (uint8_t)(crc & 0xFF);
    f[i++] = (uint8_t)((crc >> 8) & 0xFF);

    s_getbaud_ack = false;
    s_p.state = S_IDLE;
    bwm_uart_write(f, i);

    uint32_t t0 = GetTickCount();
    while (GetTickCountDelta(t0) < BWM_BAUD_VERIFY_MS) {
        bwm_pump();
        if (s_getbaud_ack) {
            return true;
        }
    }
    return false;
}

// Switch to `baud` and probe up to `tries` times.
static bool bwm_probe_at(uint32_t baud, int tries) {
    bwm_uart_set_baud(baud);
    SpinDelay(2);
    for (int v = 0; v < tries; v++) {
        if (bwm_verify_baud()) {
            return true;
        }
    }
    return false;
}

// Reset framer, FIFO and flow control after a baud change.
static void bwm_link_reset(void) {
    s_p.state      = S_IDLE;
    s_fifo_head    = 0;
    s_fifo_tail    = 0;
    s_fwd_inflight = 0;
}

bool bwm_fwd_negotiate_baud(uint32_t target) {
    if (target == 0 || target == bwm_uart_get_baud()) {
        return false;
    }
    const uint32_t boot_baud = bwm_uart_get_baud();

    // Locate the ESP: alternate so a cold-booted one (boot baud) and one that
    // survived our reset (target baud) are both found.
    bool at_boot = false, at_target = false;
    for (int r = 0; r < BWM_BAUD_PROBE_ROUNDS && !at_boot && !at_target; r++) {
        at_boot = bwm_probe_at(boot_baud, 1);
        if (!at_boot) {
            at_target = bwm_probe_at(target, 1);
        }
    }
    if (at_target) {
        bwm_link_reset();          // already at target
        return true;
    }
    if (!at_boot) {
        bwm_uart_set_baud(boot_baud);   // no ESP: stay at boot baud
        bwm_link_reset();
        return false;
    }

    // Build the SET_UART_BAUD host-command frame once (payload = u32 LE baud).
    uint8_t frame[2 + 2 + 2 + 4 + 2];
    size_t idx = 0;
    frame[idx++] = BWM_HDR_HOST_CMD_1;
    frame[idx++] = BWM_HDR_HOST_CMD_2;
    frame[idx++] = (uint8_t)(BWM_CMD_SET_UART_BAUD & 0xFF);
    frame[idx++] = (uint8_t)((BWM_CMD_SET_UART_BAUD >> 8) & 0xFF);
    frame[idx++] = (uint8_t)(4 & 0xFF);
    frame[idx++] = (uint8_t)((4 >> 8) & 0xFF);
    frame[idx++] = (uint8_t)(target & 0xFF);
    frame[idx++] = (uint8_t)((target >> 8) & 0xFF);
    frame[idx++] = (uint8_t)((target >> 16) & 0xFF);
    frame[idx++] = (uint8_t)((target >> 24) & 0xFF);
    uint16_t crc = bwm_crc16(frame, idx, BWM_CRC16_INIT);
    frame[idx++] = (uint8_t)(crc & 0xFF);
    frame[idx++] = (uint8_t)((crc >> 8) & 0xFF);

    for (int attempt = 0; attempt < BWM_BAUD_ATTEMPTS; attempt++) {
        s_baud_ack = false;
        s_p.state = S_IDLE;          // drop any half-frame before we listen
        bwm_uart_write(frame, idx);

        for (int ms = 0; ms < BWM_BAUD_ACK_WAIT_MS; ms++) {
            bwm_pump();              // parser sets s_baud_ack on the SLAVE_RESP
            if (s_baud_ack) {
                // ESP acked and is switching; verify it before trusting the
                // new baud, else fall back so both ends stay in sync.
                bool verified = bwm_probe_at(target, BWM_BAUD_VERIFY_TRIES);
                if (verified == false) {
                    bwm_uart_set_baud(boot_baud);
                }
                bwm_link_reset();
                return verified;
            }
            SpinDelay(1);
        }
    }
    bwm_link_reset();
    return false;   // no ack: stay at the boot baud, link still usable
}
