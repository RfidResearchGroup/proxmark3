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
#include "pm3_cmd.h"
#include "string.h"

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

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

#define BWM_TX_OVERHEAD   (2 + 2 + 2 + 2)   // hdr + cmd + len + crc
#define BWM_TX_MAX_PAYLOAD (PM3_CMD_DATA_SIZE + 64)   // NG/OLD frame ceiling
#define BWM_TX_BUFSZ      (BWM_TX_OVERHEAD + BWM_TX_MAX_PAYLOAD)

static void bwm_pump(void);

static volatile int16_t s_fwd_inflight = 0;

int bwm_fwd_writebuffer_sync(const uint8_t *data, size_t len) {
    static uint8_t frame[BWM_TX_BUFSZ];

    if (len > BWM_TX_MAX_PAYLOAD) {
        len = BWM_TX_MAX_PAYLOAD;
    }

    size_t idx = 0;
    {
        uint32_t spins = 0;
        while (s_fwd_inflight >= BWM_FC_WINDOW) {
            bwm_pump();
            if (++spins > BWM_FC_ACK_TIMEOUT_SPINS) {
                s_fwd_inflight = 0;
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
    s_fwd_inflight++;
    return wr;
}

#define BWM_DEFIFO_SZ     2048            // >= one full NG frame's payload
#define BWM_RXFRAME_MAX   (PM3_CMD_DATA_SIZE + 64)

typedef enum {
    S_IDLE = 0, S_HDR2, S_CMD_LO, S_CMD_HI, S_LEN_LO, S_LEN_HI, S_PAYLOAD, S_CRC_LO, S_CRC_HI
} bwm_state_t;

typedef struct {
    bwm_state_t state;
    uint8_t     hdr1;
    bool        is_bcast;
    uint16_t    cmd;
    uint16_t    len;
    uint16_t    got;
    uint16_t    crc_calc;
    uint16_t    crc_recv;
    uint8_t     payload[BWM_RXFRAME_MAX];
} bwm_parser_t;

static bwm_parser_t s_p = { .state = S_IDLE };

static uint8_t  s_fifo[BWM_DEFIFO_SZ];
static volatile uint16_t s_fifo_head = 0;
static volatile uint16_t s_fifo_tail = 0;

static uint16_t fifo_count(void) {
    return (uint16_t)((s_fifo_head - s_fifo_tail) & (BWM_DEFIFO_SZ - 1));
}
static void fifo_push(uint8_t b) {
    uint16_t next = (uint16_t)((s_fifo_head + 1) & (BWM_DEFIFO_SZ - 1));
    if (next != s_fifo_tail) {
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

static void crc_step(bwm_parser_t *p, uint8_t byte) {
    p->crc_calc = bwm_crc16(&byte, 1, p->crc_calc);
}

static void bwm_feed_byte(bwm_parser_t *p, uint8_t byte) {
    switch (p->state) {
        case S_IDLE:
            if (byte == BWM_HDR_SLAVE_BCAST_1) {
                p->hdr1 = byte; p->is_bcast = true;  p->state = S_HDR2;
            } else if (byte == BWM_HDR_SLAVE_RESP_1) {
                p->hdr1 = byte; p->is_bcast = false; p->state = S_HDR2;
            }
            break;

        case S_HDR2: {
            bool ok = (p->is_bcast  && byte == BWM_HDR_SLAVE_BCAST_2) ||
                      (!p->is_bcast && byte == BWM_HDR_SLAVE_RESP_2);
            if (!ok) {
                p->state = S_IDLE;
                bwm_feed_byte(p, byte);
                return;
            }
            uint8_t hdr[2] = { p->hdr1, byte };
            p->crc_calc = bwm_crc16(hdr, 2, BWM_CRC16_INIT);
            p->state = S_CMD_LO;
            break;
        }

        case S_CMD_LO:  p->cmd = byte;                 crc_step(p, byte); p->state = S_CMD_HI; break;
        case S_CMD_HI:  p->cmd |= (uint16_t)byte << 8; crc_step(p, byte); p->state = S_LEN_LO; break;
        case S_LEN_LO:  p->len = byte;                 crc_step(p, byte); p->state = S_LEN_HI; break;
        case S_LEN_HI:
            p->len |= (uint16_t)byte << 8;
            crc_step(p, byte);
            p->got = 0;
            if (p->len > BWM_RXFRAME_MAX) {
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

        case S_CRC_LO:  p->crc_recv = byte;                 p->state = S_CRC_HI; break;
        case S_CRC_HI:
            p->crc_recv |= (uint16_t)byte << 8;
            if (p->crc_recv == p->crc_calc) {
                if (p->is_bcast && p->cmd == BWM_CMD_DATA_FORWARD) {
                    for (uint16_t i = 0; i < p->len; i++) {
                        fifo_push(p->payload[i]);
                    }
                } else if ((p->is_bcast == false) && p->cmd == BWM_CMD_SEND_FORWARD_DATA) {
                    if (s_fwd_inflight > 0) {
                        s_fwd_inflight--;
                    }
                }
            }
            bwm_reset_frame(p);
            break;

        default:
            bwm_reset_frame(p);
            break;
    }
}

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
    bwm_pump();
    return fifo_count();
}

uint32_t bwm_read_ng(uint8_t *data, size_t len) {
    if (len == 0) {
        return 0;
    }

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
