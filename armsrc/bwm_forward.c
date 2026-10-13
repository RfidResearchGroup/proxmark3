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

// ---------------------------------------------------------------------------
// TX: wrap one reply frame into a SEND_FORWARD_DATA app_com frame.
// A full NG/OLD frame is <= PM3_CMD_DATA_SIZE + a small header/postamble, well
// under the BWM 4096-byte payload cap, so a single frame always suffices.
// ---------------------------------------------------------------------------
#define BWM_TX_OVERHEAD   (2 + 2 + 2 + 2)   // hdr + cmd + len + crc
#define BWM_TX_MAX_PAYLOAD (PM3_CMD_DATA_SIZE + 64)   // NG/OLD frame ceiling
#define BWM_TX_BUFSZ      (BWM_TX_OVERHEAD + BWM_TX_MAX_PAYLOAD)

static void bwm_pump(void);   // fwd decl: TX gate pumps RX to collect forward-frame acks

// --- Flow control (byte window) --------------------------------------------
// Forward frames sent but not yet acked by the ESP: their lengths, oldest
// first (acks arrive in order), and their sum. Bumped on every forward frame,
// popped by the parser on the ESP's SLAVE_RESP. See BWM_FC_BYTES.
static volatile uint16_t s_fc_len[BWM_FC_MAX_FRAMES];
static volatile uint8_t  s_fc_head = 0;
static volatile uint8_t  s_fc_count = 0;
static volatile uint32_t s_fc_bytes = 0;
static bwm_fc_stats_t s_fc_stats;         // diagnostics since boot, see bwm_fwd_fc_stats()

static void fc_reset(void) {
    s_fc_head = 0;
    s_fc_count = 0;
    s_fc_bytes = 0;
}

static void fc_push(uint16_t len) {
    s_fc_stats.frames++;
    s_fc_len[(uint8_t)((s_fc_head + s_fc_count) % BWM_FC_MAX_FRAMES)] = len;
    s_fc_count++;
    s_fc_bytes += len;
    if (s_fc_bytes > s_fc_stats.bytes_max) {
        s_fc_stats.bytes_max = s_fc_bytes;
    }
}

// Release the oldest frame: its ack (or CMD_ERROR) came, or the gate gave up on
// it. Acks are not matched to frames, so an ack that was eaten elsewhere (bwm_cmd()
// drains the ring, see #3648) or one that comes after the gate forgot its frame
// just shifts the window by one frame: the gate is one frame too pessimistic or
// too optimistic until the window drains, and drains it does after every command.
static void fc_pop(void) {
    if (s_fc_count == 0) {
        return;
    }
    s_fc_bytes -= s_fc_len[s_fc_head];
    s_fc_head = (uint8_t)((s_fc_head + 1) % BWM_FC_MAX_FRAMES);
    s_fc_count--;
}

void bwm_fwd_fc_stats(bwm_fc_stats_t *out) {
    *out = s_fc_stats;
    out->in_flight_frames = s_fc_count;
    out->in_flight_bytes = s_fc_bytes;
}

// Last LINK_STATE broadcast from the ESP: a client on BLE / on the TCP server.
static volatile uint8_t s_link_ble = 0;
static volatile uint8_t s_link_wifi = 0;

bool bwm_fwd_link_connected(void) {
    return (s_link_ble != 0) || (s_link_wifi != 0);
}

void bwm_fwd_link_seed_ble(bool connected) {
    s_link_ble = connected ? 1 : 0;
}

void bwm_fwd_on_frame_ack(void) {
    s_fc_stats.acks++;
    fc_pop();
}

void bwm_fwd_on_frame_error(void) {
    s_fc_stats.errors++;
    fc_pop();
}

void bwm_fwd_on_link_state(uint8_t ble, uint8_t wifi) {
    s_link_ble = ble;
    s_link_wifi = wifi;
}

int bwm_fwd_writebuffer_sync(const uint8_t *data, size_t len) {
    static uint8_t frame[BWM_TX_BUFSZ];   // single-threaded bare-metal: static OK

    if (len > BWM_TX_MAX_PAYLOAD) {
        len = BWM_TX_MAX_PAYLOAD;         // defensive; should never trigger
    }

    // Flow control: block while this frame would not fit the in-flight byte budget
    // (or the length FIFO is full). bwm_pump() drains the IRQ-filled RX ring, so
    // acks land even inside a tight download loop (the reply_old firehose). The
    // time cap is a safety valve so a dead or disconnected ESP can't hard-hang us.
    {
        uint32_t t0 = GetTickCount();
        uint32_t need = (uint32_t)len + BWM_TX_OVERHEAD;
        while ((s_fc_count >= BWM_FC_MAX_FRAMES) || (s_fc_bytes + need > BWM_FC_BYTES)) {
            bwm_pump();
            if (GetTickCountDelta(t0) > BWM_FC_ACK_TIMEOUT_MS) {
                s_fc_stats.timeouts++;
                // Never hard-hang: make room for this frame only, so a stalled ESP
                // gets one frame per timeout on top of its ring, not a second window.
                while (s_fc_count && ((s_fc_count >= BWM_FC_MAX_FRAMES) || (s_fc_bytes + need > BWM_FC_BYTES))) {
                    fc_pop();
                    s_fc_stats.forgotten++;
                }
                break;
            }
        }
    }

    size_t n = bwm_frame_build(BWM_CMD_SEND_FORWARD_DATA, data, (uint16_t)len,
                               frame, sizeof(frame));
    if (n == 0) {
        return PM3_EOVFLOW;
    }
    int wr = bwm_uart_write(frame, n);
    fc_push((uint16_t)n);   // one more forward frame awaiting its ack
    return wr;
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
            bwm_frame_feed(scratch[i]);
        }
        avail = bwm_uart_rx_available();
    }
}

uint16_t bwm_fwd_rxdata_available(void) {
    if (bwm_fifo_count() > 0) {
        return bwm_fifo_count();
    }
    // No de-framed payload yet, but raw frame bytes may be waiting; pump once so
    // receive_ng()'s gate reflects real forward data.
    bwm_pump();
    return bwm_fifo_count();
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
        while (out < len && bwm_fifo_count() > 0) {
            data[out++] = bwm_fifo_pop();
            try = 0;
        }
        if (out >= len) {
            break;
        }
        uint16_t before = bwm_fifo_count();
        bwm_pump();
        if (bwm_fifo_count() != before) {
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
    uint8_t f[8];
    size_t n = bwm_frame_build(BWM_CMD_GET_UART_BAUD, NULL, 0, f, sizeof(f));
    bwm_frame_clear_getbaud_ack();
    bwm_uart_write(f, n);

    uint32_t t0 = GetTickCount();
    while (GetTickCountDelta(t0) < BWM_BAUD_VERIFY_MS) {
        bwm_pump();
        if (bwm_frame_getbaud_ack()) {
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
    bwm_frame_reset();
    fc_reset();
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
    uint8_t payload[4];
    payload[0] = (uint8_t)(target & 0xFF);
    payload[1] = (uint8_t)((target >> 8) & 0xFF);
    payload[2] = (uint8_t)((target >> 16) & 0xFF);
    payload[3] = (uint8_t)((target >> 24) & 0xFF);
    uint8_t frame[12];
    size_t idx = bwm_frame_build(BWM_CMD_SET_UART_BAUD, payload, 4, frame, sizeof(frame));

    for (int attempt = 0; attempt < BWM_BAUD_ATTEMPTS; attempt++) {
        bwm_frame_clear_baud_ack();
        bwm_uart_write(frame, idx);

        for (int ms = 0; ms < BWM_BAUD_ACK_WAIT_MS; ms++) {
            bwm_pump();              // parser sets s_baud_ack on the SLAVE_RESP
            if (bwm_frame_baud_ack()) {
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
