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
// AT32F435 UART4 driver for the Proxmark5 BWM link - see bwm_uart_at32.h.
//-----------------------------------------------------------------------------

#include "bwm_uart_at32.h"

#include "pm3_cmd.h"
#include "at32f435_437.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_usart.h"
#include "at32f435_437_misc.h"

#define BWM_UART            UART4
#define BWM_UART_IRQn       UART4_IRQn
#define BWM_UART_GPIO       GPIOA
#define BWM_UART_TX_PIN     GPIO_PINS_0
#define BWM_UART_RX_PIN     GPIO_PINS_1
#define BWM_UART_TX_SRC     GPIO_PINS_SOURCE0
#define BWM_UART_RX_SRC     GPIO_PINS_SOURCE1
#define BWM_UART_MUX        GPIO_MUX_8

#define BWM_RX_RING_SZ      4096
static volatile uint8_t  s_rx_ring[BWM_RX_RING_SZ];
static volatile uint16_t s_rx_head = 0;
static volatile uint16_t s_rx_tail = 0;

static volatile bool s_inited = false;

void bwm_uart_init(void) {
    if (s_inited) {
        return;
    }

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

    usart_init(BWM_UART, BWM_UART_BAUD, USART_DATA_8BITS, USART_STOP_1_BIT);
    usart_parity_selection_config(BWM_UART, USART_PARITY_NONE);
    usart_transmitter_enable(BWM_UART, TRUE);
    usart_receiver_enable(BWM_UART, TRUE);

    s_rx_head = 0;
    s_rx_tail = 0;

    usart_interrupt_enable(BWM_UART, USART_RDBF_INT, TRUE);
    nvic_irq_enable(BWM_UART_IRQn, 2, 0);

    usart_enable(BWM_UART, TRUE);
    s_inited = true;
}

void UART4_IRQHandler(void) {
    if (usart_flag_get(BWM_UART, USART_RDBF_FLAG) != RESET) {
        uint8_t b = (uint8_t)usart_data_receive(BWM_UART);
        uint16_t next = (uint16_t)((s_rx_head + 1) & (BWM_RX_RING_SZ - 1));
        if (next != s_rx_tail) {
            s_rx_ring[s_rx_head] = b;
            s_rx_head = next;
        }
    }
    if (usart_flag_get(BWM_UART, USART_ROERR_FLAG) != RESET) {
        usart_flag_clear(BWM_UART, USART_ROERR_FLAG);
        (void)usart_data_receive(BWM_UART);
    }
}

int bwm_uart_write(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        while (usart_flag_get(BWM_UART, USART_TDBE_FLAG) == RESET) {
        }
        usart_data_transmit(BWM_UART, data[i]);
    }
    while (usart_flag_get(BWM_UART, USART_TDC_FLAG) == RESET) {
    }
    return PM3_SUCCESS;
}

uint16_t bwm_uart_rx_available(void) {
    return (uint16_t)((s_rx_head - s_rx_tail) & (BWM_RX_RING_SZ - 1));
}

uint32_t bwm_uart_read(uint8_t *data, size_t len) {
    uint32_t n = 0;
    while (n < len && s_rx_tail != s_rx_head) {
        data[n++] = s_rx_ring[s_rx_tail];
        s_rx_tail = (uint16_t)((s_rx_tail + 1) & (BWM_RX_RING_SZ - 1));
    }
    return n;
}
