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
//
// RX is serviced by circular DMA (DMA1 channel 2) rather than a per-byte
// RX interrupt. The old RDBF ISR dropped bytes on overrun as soon as the
// main loop was busy (FPGA / USB) - fine at 460800, fatal at higher bauds,
// where the dropped byte becomes an app_com CRC-16 failure and a stall.
// Circular DMA lets the controller sink every byte independent of CPU load,
// so BWM_UART_BAUD can be raised to lift BLE/WiFi transfer rates.
//-----------------------------------------------------------------------------

#include "bwm_uart_at32.h"

#include "pm3_cmd.h"
#include "at32f435_437.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_usart.h"
#include "at32f435_437_dma.h"
#include "at32f435_437_misc.h"

#define BWM_UART            UART4
#define BWM_UART_GPIO       GPIOA
#define BWM_UART_TX_PIN     GPIO_PINS_0
#define BWM_UART_RX_PIN     GPIO_PINS_1
#define BWM_UART_TX_SRC     GPIO_PINS_SOURCE0
#define BWM_UART_RX_SRC     GPIO_PINS_SOURCE1
#define BWM_UART_MUX        GPIO_MUX_8

// SSC already owns DMA1 channel 1 (see fpga_hw_at32.c); UART4 RX uses channel 2.
#define BWM_DMA_CHANNEL     DMA1_CHANNEL2
#define BWM_DMA_MUX_CHANNEL DMA1MUX_CHANNEL2

// Power-of-two so head/tail wrap with a mask. DMA target buffer.
// Must comfortably exceed one full forward frame or the DMA laps the reader.
// A frame is app_com(6) + NG(10) + up to PM3_CMD_DATA_SIZE data + CRC(2); at
// PM3_CMD_DATA_SIZE=4064 that is ~4082 bytes, so 4096 leaves ~14 bytes of slack
// and overruns the instant the consumer lags. 4x headroom on a 512K part.
#define BWM_RX_RING_SZ      16384
static volatile uint8_t  s_rx_ring[BWM_RX_RING_SZ];
static volatile uint16_t s_rx_tail = 0;   // software read cursor; head comes from DMA

static volatile bool     s_inited = false;
static volatile uint32_t s_cur_baud = BWM_UART_BAUD;

// Bytes the DMA controller has written so far, wrapped into the ring.
// The channel's DTCNT counts DOWN from buffer_size and reloads to buffer_size
// at wrap (loop mode), so head = size - remaining, always in [0, size-1].
static inline uint16_t bwm_uart_rx_head(void) {
    return (uint16_t)((BWM_RX_RING_SZ - dma_data_number_get(BWM_DMA_CHANNEL))
                      & (BWM_RX_RING_SZ - 1));
}

// Bring UART4 + circular RX DMA up at `baud`. Safe to call repeatedly: on a
// re-config it tears the channel down first, so the ring restarts empty (which
// also discards bytes straddling a baud switch). Mirrors the SSC RX setup in
// fpga_hw_at32.c.
static void bwm_uart_configure(uint32_t baud) {
    crm_periph_clock_enable(CRM_GPIOA_PERIPH_CLOCK, TRUE);
    crm_periph_clock_enable(CRM_UART4_PERIPH_CLOCK, TRUE);
    crm_periph_clock_enable(CRM_DMA1_PERIPH_CLOCK, TRUE);

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

    // Quiesce before reconfiguring (matters on the re-config path).
    dma_channel_enable(BWM_DMA_CHANNEL, FALSE);
    usart_enable(BWM_UART, FALSE);

    usart_init(BWM_UART, baud, USART_DATA_8BITS, USART_STOP_1_BIT);
    usart_parity_selection_config(BWM_UART, USART_PARITY_NONE);
    usart_transmitter_enable(BWM_UART, TRUE);
    usart_receiver_enable(BWM_UART, TRUE);

    // --- RX via circular DMA ---
    s_rx_tail = 0;

    dma_reset(BWM_DMA_CHANNEL);

    dma_init_type dma_init_struct;
    dma_default_para_init(&dma_init_struct);
    dma_init_struct.buffer_size           = BWM_RX_RING_SZ;
    dma_init_struct.direction             = DMA_DIR_PERIPHERAL_TO_MEMORY;
    dma_init_struct.peripheral_base_addr  = (uint32_t) & (BWM_UART->dt);
    dma_init_struct.peripheral_inc_enable = FALSE;
    dma_init_struct.memory_base_addr      = (uint32_t)s_rx_ring;
    dma_init_struct.memory_inc_enable     = TRUE;
    dma_init_struct.peripheral_data_width = DMA_PERIPHERAL_DATA_WIDTH_BYTE;
    dma_init_struct.memory_data_width     = DMA_MEMORY_DATA_WIDTH_BYTE;
    dma_init_struct.loop_mode_enable      = TRUE;   // circular: reloads at count 0
    // MEDIUM: single-byte requests, must not starve the SSC bulk channel (HIGH).
    dma_init_struct.priority              = DMA_PRIORITY_MEDIUM;
    dma_init(BWM_DMA_CHANNEL, &dma_init_struct);

    dmamux_enable(DMA1, TRUE);
    dmamux_init(BWM_DMA_MUX_CHANNEL, DMAMUX_DMAREQ_ID_UART4_RX);

    usart_dma_receiver_enable(BWM_UART, TRUE);
    dma_channel_enable(BWM_DMA_CHANNEL, TRUE);

    usart_enable(BWM_UART, TRUE);
    s_cur_baud = baud;
}

void bwm_uart_init(void) {
    if (s_inited) {
        return;
    }
    bwm_uart_configure(BWM_UART_BAUD);
    s_inited = true;
}

void bwm_uart_set_baud(uint32_t baud) {
    if (baud == 0 || baud == s_cur_baud) {
        return;
    }
    bwm_uart_configure(baud);
}

uint32_t bwm_uart_get_baud(void) {
    return s_cur_baud;
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
    // An unhandled overrun (ROERR) latches on this USART and stops it feeding the
    // DMA - after one overrun every subsequent byte is lost until a re-init, which
    // is why a stalled OTA "recovers on re-run" but mostly fails in a session.
    // Clear it here so reception resumes on its own. ROERR clears by reading STS
    // then DT; we only do that when the flag is actually set - the DMA is stalled
    // then, so the byte we consume is the already-lost overrun byte.
    if (usart_flag_get(BWM_UART, USART_ROERR_FLAG) != RESET) {
        (void)BWM_UART->sts;
        (void)BWM_UART->dt;
    }
    return (uint16_t)((bwm_uart_rx_head() - s_rx_tail) & (BWM_RX_RING_SZ - 1));
}

uint32_t bwm_uart_read(uint8_t *data, size_t len) {
    uint16_t head = bwm_uart_rx_head();
    uint32_t n = 0;
    while (n < len && s_rx_tail != head) {
        data[n++] = s_rx_ring[s_rx_tail];
        s_rx_tail = (uint16_t)((s_rx_tail + 1) & (BWM_RX_RING_SZ - 1));
    }
    return n;
}
