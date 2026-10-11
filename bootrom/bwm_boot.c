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
// Polled UART4 + app_com unwrap. No DMA, no RX FIFO: one byte in the receive
// register. Pump within one byte time (~10.8 us at 921600) or it is lost.
//-----------------------------------------------------------------------------

#ifndef WITH_BWM_FORWARD
#error "bwm_boot.c requires WITH_BWM_FORWARD"
#endif

#include "bwm_boot.h"

#include "bwm_frame.h"
#include "commonutil.h"
#include "pm3_cmd.h"
#include "ticks_apis.h"
#include "at32f435_437.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_usart.h"

extern uint32_t start_addr, end_addr;

#define BWM_UART            UART4
#define BWM_UART_GPIO       GPIOA
#define BWM_UART_TX_PIN     GPIO_PINS_0
#define BWM_UART_RX_PIN     GPIO_PINS_1
#define BWM_UART_TX_SRC     GPIO_PINS_SOURCE0
#define BWM_UART_RX_SRC     GPIO_PINS_SOURCE1
#define BWM_UART_MUX        GPIO_MUX_8

// ESP UART baud is not persistent. Probe both; 921600 is the OS target.
static const uint32_t s_baud_candidates[] = { 921600u, 460800u };

#define BWM_PROBE_ROUNDS    3

// SpinDelayUs() uses SysTick. Do not bound these waits with GetTicks()/TMR5:
// that timer is otherwise unused here, and a dead counter would hang without
// WDT_HIT(). 1 us stays inside one byte time.
#define BWM_SPIN_US         1u
#define BWM_PROBE_WAIT_US   30000u
#define BWM_ACK_WAIT_US     50000u

// Idle flush only: StartTicks() runs TMR5 at 1.5 MHz. If it never advances,
// the delta stays 0 and the flush does not fire.
#define BWM_TICKS_PER_MS    1500u
#define BWM_STAGE_IDLE_MS   1000u

static uint8_t s_cmd[sizeof(PacketCommandOLD)];
static uint16_t s_got;
static uint32_t s_stage_tick;
static uint32_t s_baud;

static bool bwm_old_cmd_ok(const uint8_t *p) {
    const PacketCommandOLD *c = (const PacketCommandOLD *)p;
    uint32_t cmd = (uint32_t)c->cmd;
    uint32_t a0 = (uint32_t)c->arg[0];
    if (c->cmd != cmd) {
        return false;
    }
    switch (cmd) {
        case CMD_DEVICE_INFO:
        case CMD_HARDWARE_RESET:
        case CMD_START_FLASH:
        case CMD_CHIP_INFO:
        case CMD_BL_VERSION:
        case CMD_CHIP_TYPE:
        case CMD_READ_MEM_DOWNLOAD:
            return true;
        case CMD_FINISH_WRITE:
            return (start_addr != end_addr) &&
                   (a0 >= start_addr) &&
                   (a0 < end_addr);
        default:
            return false;
    }
}

static void uart_set_baud(uint32_t baud) {
    crm_periph_clock_enable(CRM_GPIOA_PERIPH_CLOCK, TRUE);
    crm_periph_clock_enable(CRM_UART4_PERIPH_CLOCK, TRUE);

    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_mode           = GPIO_MODE_MUX;
    gpio_init_struct.gpio_out_type       = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_pull           = GPIO_PULL_NONE;
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_pins           = BWM_UART_TX_PIN | BWM_UART_RX_PIN;
    gpio_init(BWM_UART_GPIO, &gpio_init_struct);
    gpio_pin_mux_config(BWM_UART_GPIO, BWM_UART_TX_SRC, BWM_UART_MUX);
    gpio_pin_mux_config(BWM_UART_GPIO, BWM_UART_RX_SRC, BWM_UART_MUX);

    usart_enable(BWM_UART, FALSE);
    usart_init(BWM_UART, baud, USART_DATA_8BITS, USART_STOP_1_BIT);
    usart_parity_selection_config(BWM_UART, USART_PARITY_NONE);
    usart_transmitter_enable(BWM_UART, TRUE);
    usart_receiver_enable(BWM_UART, TRUE);
    usart_enable(BWM_UART, TRUE);
}

static int uart_getc(uint8_t *b) {
    if (usart_flag_get(BWM_UART, USART_ROERR_FLAG) != RESET) {
        (void)usart_data_receive(BWM_UART);
        usart_flag_clear(BWM_UART, USART_ROERR_FLAG);
        return 0;
    }
    if (usart_flag_get(BWM_UART, USART_RDBF_FLAG) == RESET) {
        return 0;
    }
    *b = (uint8_t)usart_data_receive(BWM_UART);
    return 1;
}

void bwm_boot_pump(void) {
    uint8_t b;
    while (uart_getc(&b)) {
        bwm_frame_feed(b);
    }
}

// Pump while waiting for TX: a 552 B frame is ~6 ms of deafness otherwise.
static void uart_write(const uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; i++) {
        while (usart_flag_get(BWM_UART, USART_TDBE_FLAG) == RESET) {
            bwm_boot_pump();
        }
        usart_data_transmit(BWM_UART, d[i]);
    }
    while (usart_flag_get(BWM_UART, USART_TDC_FLAG) == RESET) {
        bwm_boot_pump();
    }
}

static void uart_drain(void) {
    uint8_t dump;
    while (uart_getc(&dump)) {}
}

static bool bwm_probe_once(void) {
    uint8_t f[8];
    size_t n = bwm_frame_build(BWM_CMD_GET_UART_BAUD, NULL, 0, f, sizeof(f));
    if (n == 0) {
        return false;
    }
    bwm_frame_reset();
    uart_write(f, n);
    for (uint32_t us = 0; us < BWM_PROBE_WAIT_US; us += BWM_SPIN_US) {
        bwm_boot_pump();
        if (bwm_frame_getbaud_ack()) {
            bwm_frame_clear_getbaud_ack();
            return true;
        }
        SpinDelayUs(BWM_SPIN_US);
    }
    return false;
}

void bwm_boot_init(void) {
    StartTicks();
    s_got = 0;
    s_stage_tick = GetTicks();
    s_baud = 0;
    for (uint8_t round = 0; round < BWM_PROBE_ROUNDS; round++) {
        for (uint8_t i = 0; i < ARRAYLEN(s_baud_candidates); i++) {
            uart_set_baud(s_baud_candidates[i]);
            uart_drain();
            if (bwm_probe_once()) {
                s_baud = s_baud_candidates[i];
                bwm_frame_reset();
                return;
            }
        }
    }
    uart_set_baud(s_baud_candidates[0]);
    uart_drain();
    bwm_frame_reset();
}

uint32_t bwm_boot_baud(void) {
    return s_baud;
}

bool bwm_boot_poll(uint8_t *out, size_t outlen) {
    if (out == NULL || outlen < sizeof(s_cmd)) {
        return false;
    }
    bwm_boot_pump();
    uint16_t slides = 0;
    for (;;) {
        uint16_t before = s_got;
        while (s_got < sizeof(s_cmd) && bwm_fifo_count() > 0) {
            s_cmd[s_got++] = bwm_fifo_pop();
        }
        if (s_got != before) {
            s_stage_tick = GetTicks();
        }
        if (s_got < sizeof(s_cmd)) {
            // Zero padding of an OLD frame looks like CMD_DEVICE_INFO. Drop a
            // stalled partial rather than lock onto a bogus offset.
            if (s_got && ((GetTicks() - s_stage_tick) > (BWM_STAGE_IDLE_MS * BWM_TICKS_PER_MS))) {
                s_got = 0;
            }
            return false;
        }
        if (bwm_old_cmd_ok(s_cmd)) {
            for (size_t i = 0; i < sizeof(s_cmd); i++) {
                out[i] = s_cmd[i];
            }
            s_got = 0;
            return true;
        }
        for (size_t i = 0; i < sizeof(s_cmd) - 1; i++) {
            s_cmd[i] = s_cmd[i + 1];
        }
        s_got = sizeof(s_cmd) - 1;
        bwm_boot_pump();
        if (++slides >= sizeof(s_cmd)) {
            return false;
        }
    }
}

int bwm_boot_write(const uint8_t *data, size_t len) {
    if (data == NULL || len == 0 || len > 0xFFFF) {
        return PM3_EINVARG;
    }
    uint8_t frame[8 + sizeof(PacketResponseOLD)];
    size_t n = bwm_frame_build(BWM_CMD_SEND_FORWARD_DATA, data, (uint16_t)len,
                               frame, sizeof(frame));
    if (n == 0) {
        return PM3_EOVFLOW;
    }
    (void)bwm_frame_take_fwd_ack();
    uart_write(frame, n);
    bwm_frame_inflight_inc();
    for (uint32_t us = 0; us < BWM_ACK_WAIT_US; us += BWM_SPIN_US) {
        bwm_boot_pump();
        if (bwm_frame_take_fwd_ack()) {
            return PM3_SUCCESS;
        }
        SpinDelayUs(BWM_SPIN_US);
    }
    bwm_frame_inflight_zero();
    return PM3_ETIMEOUT;
}
