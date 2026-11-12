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
// BWM app_com de-framer. See bwm_frame.h.
//-----------------------------------------------------------------------------

#include "bwm_frame.h"
#include "string.h"

// CRC-16/CCITT-FALSE, byte-identical to the BWM firmware's crc16_ccitt()
// (poly 0x1021, init 0xFFFF, MSB-first, no reflection, no xorout).
uint16_t bwm_crc16(const uint8_t *data, size_t len, uint16_t crc) {
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
// RX: persistent app_com de-framer. Feeds raw FPC bytes through a state machine
// and pushes the payloads of valid DATA_FORWARD (0xD2 0xD3 / cmd 8089) frames
// into a byte FIFO that bwm_read_ng() drains. Non-DATA_FORWARD frames (slave
// responses, forwarded logs, cmd-error reports) are validated and discarded.
// ---------------------------------------------------------------------------
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
    uint8_t     payload[BWM_FRAME_RX_MAX];
} bwm_parser_t;

static bwm_parser_t s_p = { .state = S_IDLE };

// De-framed payload rings, one per endpoint (bootrom: one)
#ifdef AS_BOOTROM
#define BWM_FIFOS   1
#else
#define BWM_FIFOS   2
#endif
typedef struct {
    uint8_t buf[BWM_FIFO_SZ];
    volatile uint16_t head;   // write
    volatile uint16_t tail;   // read
} bwm_fifo_t;
static bwm_fifo_t s_fifo[BWM_FIFOS];
#ifndef AS_BOOTROM
static volatile bool s_fifo0_untagged = false;
#endif

// --- Flow control (ack window) ---------------------------------------------
// s_fwd_inflight: forward frames sent but not yet acked by the ESP. Bumped on
// send, decremented when a SLAVE_RESP echoing cmd=SEND_FORWARD_DATA arrives.
// We may send while it is below BWM_FC_WINDOW; at the cap we wait for an ack.
static volatile int16_t s_fwd_inflight = 0;
// Bootrom write path waits for this; OS only uses the inflight count.
static volatile bool s_fwd_ack = false;

// Set true by the parser when a SLAVE_RESP echoing BWM_CMD_SET_UART_BAUD arrives
// (the ESP's ack for a baud-set request). Consumed by bwm_fwd_negotiate_baud().
static volatile bool s_baud_ack = false;

// Set true by the parser on a SLAVE_RESP for BWM_CMD_GET_UART_BAUD - proof the
// ESP is alive and responding at the baud we just switched to (verify step).
static volatile bool s_getbaud_ack = false;

#ifndef AS_BOOTROM
// bwm_cmd()'s pending request, see bwm_frame_expect()
static uint16_t s_exp_cmd = 0;          // 0 = none
static volatile int8_t s_exp_state = 0;
static uint8_t *s_exp_buf = NULL;
static uint16_t s_exp_cap = 0;
static uint16_t s_exp_len = 0;
static int32_t s_exp_err = 0;
#endif

static uint16_t fifo_count(bwm_fifo_t *f) {
    return (uint16_t)((f->head - f->tail) & (BWM_FIFO_SZ - 1));
}
static void fifo_push(bwm_fifo_t *f, uint8_t b) {
    uint16_t next = (uint16_t)((f->head + 1) & (BWM_FIFO_SZ - 1));
    if (next != f->tail) {                  // drop on overflow rather than corrupt
        f->buf[f->head] = b;
        f->head = next;
    }
}
static uint8_t fifo_pop(bwm_fifo_t *f) {
    uint8_t b = f->buf[f->tail];
    f->tail = (uint16_t)((f->tail + 1) & (BWM_FIFO_SZ - 1));
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
            if (p->len > BWM_FRAME_RX_MAX) {            // oversized -> drop frame
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
#ifndef AS_BOOTROM
                if ((s_exp_cmd != 0) && (s_exp_state == 0)) {
                    if ((p->is_bcast == false) && (p->cmd == s_exp_cmd)) {
                        s_exp_len = MIN(p->len, s_exp_cap);
                        if (s_exp_len) {
                            memcpy(s_exp_buf, p->payload, s_exp_len);
                        }
                        s_exp_state = 1;
                    } else if (p->is_bcast && (p->cmd == BWM_CMD_CMD_ERROR) && (p->len >= 2) &&
                               (((uint16_t)p->payload[0] | ((uint16_t)p->payload[1] << 8)) == s_exp_cmd)) {
                        s_exp_err = 0;
                        if (p->len >= 6) {
                            s_exp_err = (int32_t)((uint32_t)p->payload[2] | ((uint32_t)p->payload[3] << 8) |
                                                  ((uint32_t)p->payload[4] << 16) | ((uint32_t)p->payload[5] << 24));
                        }
                        s_exp_state = -1;
                    }
                }
#endif
                if (p->is_bcast && p->cmd == BWM_CMD_DATA_FORWARD) {
                    for (uint16_t i = 0; i < p->len; i++) {
                        fifo_push(&s_fifo[0], p->payload[i]);
                    }
#ifndef AS_BOOTROM
                    s_fifo0_untagged = true;
                    bwm_fwd_on_untagged_data();
                } else if (p->is_bcast && p->cmd == BWM_CMD_DATA_FORWARD_FROM && p->len >= 1 &&
                           p->payload[0] < BWM_FIFOS) {
                    bwm_fifo_t *f = &s_fifo[p->payload[0]];
                    for (uint16_t i = 1; i < p->len; i++) {
                        fifo_push(f, p->payload[i]);
                    }
                    if (p->payload[0] == 0) {
                        s_fifo0_untagged = false;
                    }
#endif
                } else if ((p->is_bcast == false) &&
                           (p->cmd == BWM_CMD_SEND_FORWARD_DATA || p->cmd == BWM_CMD_SEND_FORWARD_DATA_TO)) {
                    // SLAVE_RESP ack for a forward frame -> one slot freed
                    if (s_fwd_inflight > 0) {
                        s_fwd_inflight--;
                    }
                    s_fwd_ack = true;
#ifndef AS_BOOTROM
                    bwm_fwd_on_frame_ack();
#endif
                } else if (p->is_bcast && p->cmd == BWM_CMD_CMD_ERROR && p->len >= 2 &&
                           ((((uint16_t)p->payload[0] | ((uint16_t)p->payload[1] << 8)) == BWM_CMD_SEND_FORWARD_DATA) ||
                            (((uint16_t)p->payload[0] | ((uint16_t)p->payload[1] << 8)) == BWM_CMD_SEND_FORWARD_DATA_TO))) {
                    // the ESP could not deliver a forward frame: this is its answer instead of the ack
#ifndef AS_BOOTROM
                    bwm_fwd_on_frame_error();
#endif
                } else if ((p->is_bcast == false) && p->cmd == BWM_CMD_SET_UART_BAUD) {
                    // SLAVE_RESP ack for a baud-set request (see negotiate below)
                    s_baud_ack = true;
                } else if ((p->is_bcast == false) && p->cmd == BWM_CMD_GET_UART_BAUD) {
                    // SLAVE_RESP for our GET_BAUD verify probe
                    s_getbaud_ack = true;
                } else if (p->is_bcast && p->cmd == BWM_CMD_LINK_STATE && p->len >= 2) {
#ifndef AS_BOOTROM
                    bwm_fwd_on_link_state(p->payload[0], p->payload[1]);
#endif
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

void bwm_frame_feed(uint8_t byte) {
    bwm_feed_byte(&s_p, byte);
}

uint16_t bwm_fifo_count(void) {
    return fifo_count(&s_fifo[0]);
}

uint8_t bwm_fifo_pop(void) {
    return fifo_pop(&s_fifo[0]);
}

#ifndef AS_BOOTROM
uint16_t bwm_fifo_count_ep(uint8_t ep) {
    return (ep < BWM_FIFOS) ? fifo_count(&s_fifo[ep]) : 0;
}

uint8_t bwm_fifo_pop_ep(uint8_t ep) {
    return (ep < BWM_FIFOS) ? fifo_pop(&s_fifo[ep]) : 0;
}

bool bwm_fifo_untagged(void) {
    return s_fifo0_untagged;
}
#endif

int16_t bwm_frame_inflight(void) {
    return s_fwd_inflight;
}

void bwm_frame_inflight_inc(void) {
    s_fwd_inflight++;
}

void bwm_frame_inflight_zero(void) {
    s_fwd_inflight = 0;
}

bool bwm_frame_take_fwd_ack(void) {
    if (s_fwd_ack == false) {
        return false;
    }
    s_fwd_ack = false;
    return true;
}

#ifndef AS_BOOTROM
void bwm_frame_expect(uint16_t cmd, uint8_t *buf, uint16_t cap) {
    s_exp_buf = buf;
    s_exp_cap = (buf != NULL) ? cap : 0;
    s_exp_len = 0;
    s_exp_err = 0;
    s_exp_state = 0;
    s_exp_cmd = cmd;
}

int8_t bwm_frame_expect_poll(uint16_t *len, int32_t *esp_err) {
    if (len) {
        *len = s_exp_len;
    }
    if (esp_err) {
        *esp_err = s_exp_err;
    }
    return s_exp_state;
}

void bwm_frame_expect_end(void) {
    s_exp_cmd = 0;
    s_exp_buf = NULL;
}
#endif

bool bwm_frame_baud_ack(void) {
    return s_baud_ack;
}

void bwm_frame_clear_baud_ack(void) {
    s_baud_ack = false;
    s_p.state = S_IDLE;          // drop any half-frame before we listen
}

bool bwm_frame_getbaud_ack(void) {
    return s_getbaud_ack;
}

void bwm_frame_clear_getbaud_ack(void) {
    s_getbaud_ack = false;
    s_p.state = S_IDLE;
}

void bwm_frame_reset(void) {
    s_p.state      = S_IDLE;
    for (int i = 0; i < BWM_FIFOS; i++) {
        s_fifo[i].head = 0;
        s_fifo[i].tail = 0;
    }
#ifndef AS_BOOTROM
    s_fifo0_untagged = false;
#endif
    s_fwd_inflight = 0;
    s_fwd_ack      = false;
    s_baud_ack     = false;
    s_getbaud_ack  = false;
}

size_t bwm_frame_build(uint16_t cmd, const uint8_t *payload, uint16_t len,
                       uint8_t *out, size_t outsz) {
    size_t idx = 0;
    if (out == NULL || outsz < (size_t)(8 + len)) {
        return 0;
    }
    out[idx++] = BWM_HDR_HOST_CMD_1;
    out[idx++] = BWM_HDR_HOST_CMD_2;
    out[idx++] = (uint8_t)(cmd & 0xFF);
    out[idx++] = (uint8_t)((cmd >> 8) & 0xFF);
    out[idx++] = (uint8_t)(len & 0xFF);
    out[idx++] = (uint8_t)((len >> 8) & 0xFF);
    if (len && payload) {
        for (uint16_t i = 0; i < len; i++) {
            out[idx++] = payload[i];
        }
    }
    uint16_t crc = bwm_crc16(out, idx, BWM_CRC16_INIT);
    out[idx++] = (uint8_t)(crc & 0xFF);
    out[idx++] = (uint8_t)((crc >> 8) & 0xFF);
    return idx;
}

#ifndef AS_BOOTROM
// bwm_frame_build() with a one-byte endpoint in front of the payload
size_t bwm_frame_build_ep(uint16_t cmd, uint8_t ep, const uint8_t *payload, uint16_t len,
                          uint8_t *out, size_t outsz) {
    size_t idx = 0;
    uint16_t plen = (uint16_t)(len + 1);
    if (out == NULL || outsz < (size_t)(8 + plen)) {
        return 0;
    }
    out[idx++] = BWM_HDR_HOST_CMD_1;
    out[idx++] = BWM_HDR_HOST_CMD_2;
    out[idx++] = (uint8_t)(cmd & 0xFF);
    out[idx++] = (uint8_t)((cmd >> 8) & 0xFF);
    out[idx++] = (uint8_t)(plen & 0xFF);
    out[idx++] = (uint8_t)((plen >> 8) & 0xFF);
    out[idx++] = ep;
    if (len && payload) {
        memcpy(&out[idx], payload, len);
        idx += len;
    }
    uint16_t crc = bwm_crc16(out, idx, BWM_CRC16_INIT);
    out[idx++] = (uint8_t)(crc & 0xFF);
    out[idx++] = (uint8_t)((crc >> 8) & 0xFF);
    return idx;
}
#endif
