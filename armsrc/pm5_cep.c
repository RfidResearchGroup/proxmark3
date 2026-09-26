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
// See pm5_cep.h. Extracted from the dead test_f0_com_by_usb_cep() /
// cep_spi_*() code in at32_unit_test.c (GH issue #3667) - the register-level
// handshake and SPI logic is dxl's original work, carried over near-verbatim
// except where noted below.
//
// Hardware-verified (real Flipper Zero, repeated app relaunches without a
// physical cable replug): USART1 handshake, the SPI1 mode below for the
// handshake reply, and the CC-controller I2C address 0x47 all confirmed
// working. Not yet exercised: the post-handshake NG-frame SPI transport
// (cep_spi_read_ng/write_sync) under an actual client command.
//-----------------------------------------------------------------------------

#include "pm5_cep.h"

#include "at32f435_437.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_usart.h"
#include "at32f435_437_spi.h"
#include "gpio_apis.h"
#include "i2c.h"
#include "ticks_apis.h"
#include "dbprint.h"
#include "pm3_cmd.h"
#include "string.h"

#define CEP_CC_CONTROLLER_ADDR   0x47
#define CEP_CC_STATUS_REG        0x09
#define CEP_ATTACH_POLL_MS       50      // CC-controller I2C poll interval
#define CEP_HANDSHAKE_STRING     "iamf0rupm5"
#define CEP_HANDSHAKE_STX        0x02
#define CEP_SPI_BYTE_TIMEOUT     100000  // spin-wait iterations per byte (matches source)
#define CEP_SPI_RESPONSE_TIMEOUT_US  (1000 * 1000)  // 1s, matches source
#define CEP_HANDSHAKE_RX_TIMEOUT_MS  2000  // bail out of the receive loop rather than ever hang the main loop

static bool s_cep_active = false;   // handshake completed, SPI transport live

bool cep_is_active(void) {
    return s_cep_active;
}

// ---------------------------------------------------------------------------
// One-time peripheral bring-up
// ---------------------------------------------------------------------------

static void cep_usart_init(void) {
    crm_periph_clock_enable(CRM_USART1_PERIPH_CLOCK, TRUE);
    crm_periph_clock_enable(CRM_GPIOA_PERIPH_CLOCK, TRUE);

    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_OPEN_DRAIN;
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_pins = GPIO_PINS_9;
    gpio_init_struct.gpio_pull = GPIO_PULL_UP;
    gpio_init(GPIOA, &gpio_init_struct);
    gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE9, GPIO_MUX_7);

    usart_init(USART1, 2400, USART_DATA_8BITS, USART_STOP_1_BIT);
    usart_parity_selection_config(USART1, USART_PARITY_NONE);
    usart_transmitter_enable(USART1, FALSE);   // RX only - the reply goes over SPI, not this UART
    usart_receiver_enable(USART1, TRUE);
    usart_single_line_halfduplex_select(USART1, TRUE);
    usart_enable(USART1, TRUE);

    // PA10 (USB1_ID): read once to pick master/slave role for the SPI pin mux.
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init_struct.gpio_mode = GPIO_MODE_INPUT;
    gpio_init_struct.gpio_pins = GPIO_PINS_10;
    gpio_init(GPIOA, &gpio_init_struct);
}

static spi_master_slave_mode_type s_spi_mode;

static void cep_spi_init(void) {
    bool is_slave_mode = GpioInputStatus(GPIOA, GPIO_PINS_10);
    gpio_inter_usb_spi_role_setup();
    if (is_slave_mode) {
        Gpio_Inter_USB_SPI_Role_High();
    } else {
        Gpio_Inter_USB_SPI_Role_Low();
    }
    s_spi_mode = is_slave_mode ? SPI_MODE_SLAVE : SPI_MODE_MASTER;

    gpio_init_type gpio_init_struct;
    crm_periph_clock_enable(CRM_GPIOA_PERIPH_CLOCK, TRUE);

    // CS (PA4)
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_pull = GPIO_PULL_UP;
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    if (s_spi_mode == SPI_MODE_MASTER) {
        gpio_init_struct.gpio_mode = GPIO_MODE_OUTPUT;
    } else {
        gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
        gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE4, GPIO_MUX_5);
    }
    gpio_init_struct.gpio_pins = GPIO_PINS_4;
    gpio_init(GPIOA, &gpio_init_struct);

    // SCK (PA5)
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_pull = GPIO_PULL_DOWN;
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_pins = GPIO_PINS_5;
    gpio_init(GPIOA, &gpio_init_struct);
    gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE5, GPIO_MUX_5);

    // MISO (PA6)
    gpio_init_struct.gpio_pull = GPIO_PULL_UP;
    gpio_init_struct.gpio_pins = GPIO_PINS_6;
    gpio_init(GPIOA, &gpio_init_struct);
    gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE6, GPIO_MUX_5);

    // MOSI (PA7)
    gpio_init_struct.gpio_pull = GPIO_PULL_UP;
    gpio_init_struct.gpio_pins = GPIO_PINS_7;
    gpio_init(GPIOA, &gpio_init_struct);
    gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE7, GPIO_MUX_5);

    if (s_spi_mode == SPI_MODE_MASTER) {
        gpio_bits_set(GPIOA, GPIO_PINS_4);   // idle CS high, release the slave
    }

    spi_init_type spi_init_struct;
    crm_periph_clock_enable(CRM_SPI1_PERIPH_CLOCK, TRUE);
    spi_default_para_init(&spi_init_struct);
    spi_init_struct.transmission_mode = SPI_TRANSMIT_FULL_DUPLEX;
    spi_init_struct.master_slave_mode = s_spi_mode;
    spi_init_struct.mclk_freq_division = SPI_MCLK_DIV_1024;
    // NOT YET HARDWARE-VERIFIED - see file header comment.
    spi_init_struct.first_bit_transmission = SPI_FIRST_BIT_MSB;
    spi_init_struct.frame_bit_num = SPI_FRAME_8BIT;
    spi_init_struct.clock_polarity = SPI_CLOCK_POLARITY_LOW;
    spi_init_struct.clock_phase = SPI_CLOCK_PHASE_1EDGE;
    spi_init_struct.cs_mode_selection = (s_spi_mode == SPI_MODE_MASTER) ? SPI_CS_SOFTWARE_MODE : SPI_CS_HARDWARE_MODE;
    spi_init(SPI1, &spi_init_struct);
    spi_enable(SPI1, TRUE);
}

void cep_init(void) {
    cep_usart_init();
    cep_spi_init();
    I2C_init(true);
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

// Blocking (bounded by the Flipper's own ~1.1s handshake timeout budget):
// waits for STX then the literal ASCII string, replies "yes" over SPI on a
// match. Only called once, right after cep_attach_poll() sees a fresh attach.
static bool cep_do_handshake(void) {
    uint8_t data[sizeof(CEP_HANDSHAKE_STRING) - 1];
    uint8_t rx_len = 0;
    uint32_t start_tick = GetTickCount();

    while (1) {
        if (GetTickCountDelta(start_tick) > CEP_HANDSHAKE_RX_TIMEOUT_MS) {
            return false;
        }

        if (usart_flag_get(USART1, USART_RDBF_FLAG) != RESET) {
            uint8_t rx_data = usart_data_receive(USART1);
            if (rx_data == CEP_HANDSHAKE_STX) {
                // STX: restart the frame. Unlike the original unit-test code,
                // do NOT discard an extra byte here - the FAP protocol has no
                // byte between STX and the literal string, and doing an
                // unconditional second usart_data_receive() without
                // re-checking RDBF risked reading stale data and ate what
                // should have been the string's first byte.
                rx_len = 0;
                continue;
            }
            if (rx_len < sizeof(data)) {
                data[rx_len++] = rx_data;
            }
        }

        if (rx_len == sizeof(data)) {
            if (memcmp(CEP_HANDSHAKE_STRING, data, sizeof(data)) == 0) {
                break;
            }
            rx_len = 0;   // no match, resync on the next STX
        }
    }

    uint8_t response[] = {0x04, 0x00, 'y', 'e', 's', 0x00};
    for (size_t i = 0; i < sizeof(response); i++) {
        uint32_t wait_start = GetTicks();
        while (spi_i2s_flag_get(SPI1, SPI_I2S_TDBE_FLAG) == RESET) {
            if (GetTicks() - wait_start > CEP_SPI_RESPONSE_TIMEOUT_US) {
                uint8_t cc_ctrl_data;
                bool ret = I2C_BufferReadRaw(&cc_ctrl_data, 1, CEP_CC_STATUS_REG, CEP_CC_CONTROLLER_ADDR << 1);
                if (ret && ((cc_ctrl_data >> 6 & 0x03) == 0)) {
                    return false;   // disconnected mid-reply
                }
            }
        }
        spi_i2s_data_transmit(SPI1, response[i]);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Attach polling (non-blocking, rate-limited)
// ---------------------------------------------------------------------------

void cep_attach_poll(void) {
    static uint32_t last_tick = 0;

    if ((last_tick != 0) && (GetTickCountDelta(last_tick) < CEP_ATTACH_POLL_MS)) {
        return;
    }
    last_tick = GetTickCount();

    uint8_t cc_ctrl_data;
    bool ret = I2C_BufferReadRaw(&cc_ctrl_data, 1, CEP_CC_STATUS_REG, CEP_CC_CONTROLLER_ADDR << 1);
    if (!ret) {
        return;
    }

    bool attached = ((cc_ctrl_data >> 6 & 0x03) != 0);

    if (!attached) {
        s_cep_active = false;
    } else {
        // The FAP re-runs its handshake on every app launch, not just on a
        // fresh physical attach - the CC controller's attach bits don't
        // reliably blip on every relaunch (confirmed on hardware: sometimes
        // they do, sometimes they don't), so gating the handshake listener on
        // that edge alone missed real handshake attempts and required a
        // physical unplug/replug to recover (GH #3667). Instead, watch for a
        // fresh incoming byte any time we're attached, regardless of edge.
        // cep_do_handshake() itself is timeout-bounded so a spurious byte
        // can't hang the main loop.
        if (usart_flag_get(USART1, USART_RDBF_FLAG) != RESET) {
            s_cep_active = cep_do_handshake();
        }
    }

    uint8_t int_state = cc_ctrl_data >> 4 & 0x01;
    if (int_state) {
        cc_ctrl_data |= 1 << 4;   // clear the CC controller's interrupt latch
        I2C_BufferWrite(&cc_ctrl_data, 1, CEP_CC_STATUS_REG, CEP_CC_CONTROLLER_ADDR << 1);
    }
}

// ---------------------------------------------------------------------------
// SPI NG-frame transport (verbatim from the unit test - already correct)
// ---------------------------------------------------------------------------

bool cep_spi_data_available(void) {
    uint8_t len_header[2] = {0x00};
    for (size_t i = 0; i < sizeof(len_header); ++i) {
        uint64_t timeout = 0;
        while (spi_i2s_flag_get(SPI1, SPI_I2S_RDBF_FLAG) == RESET) {
            if (timeout++ > CEP_SPI_BYTE_TIMEOUT) {
                return false;
            }
        }
        len_header[i] = spi_i2s_data_receive(SPI1);
    }
    uint16_t data_len = (len_header[1] << 8) | len_header[0];
    if (data_len > PM3_CMD_DATA_SIZE * 2) {
        return false;
    }
    return true;
}

uint32_t cep_spi_read_ng(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        uint64_t timeout = 0;
        while (spi_i2s_flag_get(SPI1, SPI_I2S_RDBF_FLAG) == RESET) {
            if (timeout++ > CEP_SPI_BYTE_TIMEOUT) {
                return i;
            }
        }
        data[i] = spi_i2s_data_receive(SPI1);
    }
    return len;
}

int cep_spi_write_sync(uint8_t *data, size_t len) {
    while (spi_i2s_flag_get(SPI1, SPI_I2S_TDBE_FLAG) == RESET);
    spi_i2s_data_transmit(SPI1, len & 0xFF);

    while (spi_i2s_flag_get(SPI1, SPI_I2S_TDBE_FLAG) == RESET);
    spi_i2s_data_transmit(SPI1, (len >> 8) & 0xFF);

    for (size_t i = 0; i < len; ++i) {
        while (spi_i2s_flag_get(SPI1, SPI_I2S_TDBE_FLAG) == RESET);
        spi_i2s_data_transmit(SPI1, data[i]);
    }

    // Two trailing zero bytes: the agreed "no more data" idle marker.
    while (spi_i2s_flag_get(SPI1, SPI_I2S_TDBE_FLAG) == RESET);
    spi_i2s_data_transmit(SPI1, 0x00);
    while (spi_i2s_flag_get(SPI1, SPI_I2S_TDBE_FLAG) == RESET);
    spi_i2s_data_transmit(SPI1, 0x00);

    while (spi_i2s_flag_get(SPI1, SPI_I2S_BF_FLAG) == SET);

    return PM3_SUCCESS;
}
