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
#include "pm5_usb_host_cdc.h"

#include "at32f435_437.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_misc.h"
#include "at32f435_437_usart.h"
#include "at32f435_437_spi.h"
#include "gpio_apis.h"
#include "i2c_apis.h"
#include "ticks_apis.h"
#include "dbprint.h"
#include "pm3_cmd.h"

#define CEP_CC_CONTROLLER_ADDR   0x47
#define CEP_CC_STATUS_REG        0x09
#define CEP_ATTACH_POLL_MS       50      // CC-controller I2C poll interval
#define CEP_DETACH_DEBOUNCE_READS  5

// TUSB320 status register bits 7:6 - attach role as seen by the PM5 port.
#define CEP_ATTACH_UNATTACHED    0x00
#define CEP_ATTACH_SRC           0x01    // PM5 sources VBUS -> act as USB host (ICS/ICSD device)
#define CEP_ATTACH_SNK           0x02    // partner sources VBUS -> Flipper Zero (USART1 handshake)
#define CEP_ATTACH_PEER          0x03    // PD peer -> Flipper Zero
#define CEP_HANDSHAKE_STRING     "iamf0rupm5"
#define CEP_HANDSHAKE_STX        0x02
#define CEP_SPI_BYTE_TIMEOUT     100000  // spin-wait iterations per byte (matches source)
// First reply byte races the Flipper's ~120ms poll gap; this timeout spans it.
// Later bytes clock continuously on the short timeout. Measured reply success
// ~22% -> ~100% with this budget.
#define CEP_SPI_HEADER_BYTE_TIMEOUT  2000000
#define CEP_SPI_RESPONSE_TIMEOUT_TICKS  1500000  // 1s at 1.5 MHz
#define CEP_HANDSHAKE_REPLY_MAX_RETRIES 3  // bound the stall-recovery loop below - still-attached isn't still-working forever

// 0x55 filler the Flipper sends while its own SPI poll finds nothing new -
// discard it so the real length header is recognized as soon as it starts,
// instead of ever reading a 0x55 byte as (part of) a frame length.
#define CEP_SYNC_BYTE            0x55
#define CEP_SYNC_MAX_DISCARD     600

// How long cep_attach_poll() will go without seeing a real SPI poll from the
// Flipper before deciding the FAP has quit (see the comment at its one use
// below) and letting AppMain() go back to sleeping between iterations.
#define CEP_ACTIVITY_TIMEOUT_MS      3000

static bool s_cep_active = false;   // handshake completed, SPI transport live
static bool s_cep_attached = false; // CC controller reports a physical attach
static uint32_t s_last_spi_activity_tick = 0; // last time a real SPI poll was seen
static volatile bool s_handshake_pending;

static bool s_usb_host_mode = false;   // OTGFS1 host CDC owns PA9/PA11/PA12
static bool s_usb_host_forced = false; // user explicitly requested host CDC mode (hw pm5 icsd init)
static bool s_usart1_active = false; // USART1 half-duplex owns PA9
static uint8_t s_detach_count = 0;

bool cep_is_active(void) {
    return s_cep_active;
}

bool cep_is_attached(void) {
    return s_cep_attached;
}

// ---------------------------------------------------------------------------
// One-time peripheral bring-up
// ---------------------------------------------------------------------------

void cep_usart_clock_update(void) {
    // USART_BAUDR is set with the USART disabled (AT32F435 manual 12.6.2).
    confirm_state enabled = USART1->ctrl1_bit.uen ? TRUE : FALSE;
    usart_enable(USART1, FALSE);
    usart_init(USART1, 2400, USART_DATA_8BITS, USART_STOP_1_BIT);
    usart_enable(USART1, enabled);
}

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

    cep_usart_clock_update();
    usart_parity_selection_config(USART1, USART_PARITY_NONE);
    usart_transmitter_enable(USART1, FALSE);   // RX only - the reply goes over SPI, not this UART
    usart_receiver_enable(USART1, TRUE);
    usart_single_line_halfduplex_select(USART1, TRUE);
    usart_interrupt_enable(USART1, USART_RDBF_INT, TRUE);
    nvic_irq_enable(USART1_IRQn, 1, 0);
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

// AT32F435/437 errata ES0003, "CS falling edge not synchronized in SPI
// slave hardware CS mode": the peripheral's internal clock sync isn't
// guaranteed to reset on every CS edge, so a bad sync can persist across
// transactions. Artery's documented recovery is to detect the corruption
// (we already do, via the NG frame's CRC) and reset SPI before retrying -
// a register re-init alone isn't enough, the peripheral needs resetting
// through the clock/reset controller to actually clear that state.
void cep_spi_resync(void) {
    spi_enable(SPI1, FALSE);
    crm_periph_reset(CRM_SPI1_PERIPH_RESET, TRUE);
    crm_periph_reset(CRM_SPI1_PERIPH_RESET, FALSE);
    cep_spi_init();
}

void cep_init(void) {
    cep_usart_init();
    s_usart1_active = true;
    cep_spi_init();
    // I2C_init() must be preceded by StartTicks(), like everywhere else.
    StartTicks();
    I2C_init(true);
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

// Drain USART1 between CC polls. STX starts a new request.
void USART1_IRQHandler(void) {
    static uint8_t match;
    const uint32_t errors = USART_FERR_FLAG | USART_NERR_FLAG | USART_ROERR_FLAG;
    uint32_t status = USART1->sts;
    if ((status & (USART_RDBF_FLAG | errors)) == 0) {
        return;
    }

    // Reading status then data clears receive errors.
    uint8_t byte = usart_data_receive(USART1);
    if (status & errors) {
        match = 0;
    } else if (byte == CEP_HANDSHAKE_STX) {
        match = 1;
    } else if (match == 0 || byte != CEP_HANDSHAKE_STRING[match - 1]) {
        match = 0;
    } else if (++match == sizeof(CEP_HANDSHAKE_STRING)) {
        match = 0;
        s_handshake_pending = true;
    }
}

static bool cep_reply_handshake(void) {
    uint8_t response[] = {0x04, 0x00, 'y', 'e', 's', 0x00};
    for (size_t i = 0; i < sizeof(response); i++) {
        uint32_t wait_start = GetTicks();
        int recovery_attempts = 0;
        while (spi_i2s_flag_get(SPI1, SPI_I2S_TDBE_FLAG) == RESET) {
            if (GetTicks() - wait_start >= CEP_SPI_RESPONSE_TIMEOUT_TICKS) {
                // Bound this: "still attached" isn't "still working" forever,
                // and I2C_BufferRead() needs the ticks timer running like
                // every other call site (see cep_attach_poll()'s comment).
                if (++recovery_attempts > CEP_HANDSHAKE_REPLY_MAX_RETRIES) {
                    return false;
                }
                StartTicks();
                I2C_init(true);
                uint8_t cc_ctrl_data;
                bool ret = I2C_BufferRead(&cc_ctrl_data, 1, CEP_CC_STATUS_REG, CEP_CC_CONTROLLER_ADDR << 1);
                if (!ret || ((cc_ctrl_data >> 6 & 0x03) == 0)) {
                    return false;   // disconnected mid-reply, or can't tell - bail either way
                }
                wait_start = GetTicks();
            }
        }
        spi_i2s_data_transmit(SPI1, response[i]);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Attach polling (non-blocking, rate-limited)
// ---------------------------------------------------------------------------

// Release USART1, hand PA9/PA11/PA12 to OTGFS1 (GPIO_MUX_10), then bring up
// the USB host CDC stack. PA11/PA12 are OTGFS1 DM/DP; PA9 is the USART1 line
// being repurposed.
void cep_usb_host_enter(void) {
    usart_enable(USART1, FALSE);
    usart_interrupt_enable(USART1, USART_RDBF_INT, FALSE);
    nvic_irq_disable(USART1_IRQn);

    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init_struct.gpio_pins = GPIO_PINS_9 | GPIO_PINS_11 | GPIO_PINS_12;
    gpio_init(GPIOA, &gpio_init_struct);
    gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE9, GPIO_MUX_10);
    gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE11, GPIO_MUX_10);
    gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE12, GPIO_MUX_10);

    pm5_usb_host_cdc_init();
}

void cep_ensure_usb_host_mode(void) {
    if (!s_usb_host_mode) {
        cep_usb_host_enter();
    }
    s_usb_host_mode = true;
    s_usb_host_forced = true;
    s_usart1_active = false;
}

bool cep_is_usb_host_active(void) {
    return s_usb_host_mode;
}

// Re-establish USART1 half-duplex on PA9 (2400 8N1). The USART1 peripheral
// itself keeps its config across a host-mode stint - only the line and the
// enable bit need restoring.
static void cep_usart1_restore(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_OPEN_DRAIN;
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_pins = GPIO_PINS_9;
    gpio_init_struct.gpio_pull = GPIO_PULL_UP;
    gpio_init(GPIOA, &gpio_init_struct);
    gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE9, GPIO_MUX_7);

    cep_usart_clock_update();
    usart_interrupt_enable(USART1, USART_RDBF_INT, TRUE);
    nvic_irq_enable(USART1_IRQn, 1, 0);
    usart_enable(USART1, TRUE);
}

// Float the shared USB/USART lines to high-impedance inputs.
static void cep_lines_float(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_mode = GPIO_MODE_INPUT;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init_struct.gpio_pins = GPIO_PINS_9 | GPIO_PINS_11 | GPIO_PINS_12;
    gpio_init(GPIOA, &gpio_init_struct);
}

void cep_attach_poll(void) {
    static uint32_t last_tick = 0;

    if ((last_tick != 0) && (GetTickCountDelta(last_tick) < CEP_ATTACH_POLL_MS)) {
        return;
    }
    // A long command kept the main loop from seeing the Flipper's polls.
    if ((last_tick != 0) && (GetTickCountDelta(last_tick) > CEP_ACTIVITY_TIMEOUT_MS)) {
        s_last_spi_activity_tick = GetTickCount();
    }
    last_tick = GetTickCount();

    // I2C_init() must be preceded by StartTicks(), like everywhere else -
    // LF/HF code calls StopTicks() when done, and this poll can land after
    // that (see bwm_lowbatt_poll() for the same pattern).
    StartTicks();
    I2C_init(true);

    uint8_t cc_ctrl_data;
    bool ret = I2C_BufferRead(&cc_ctrl_data, 1, CEP_CC_STATUS_REG, CEP_CC_CONTROLLER_ADDR << 1);
    if (!ret) {
        return;
    }

    uint8_t attach = (cc_ctrl_data >> 6) & 0x03;
    s_cep_attached = (attach != CEP_ATTACH_UNATTACHED);

    if (attach == CEP_ATTACH_SRC) {
        s_detach_count = 0;
        // PM5 sources VBUS: ICS/ICSD device - USB host CDC mode
        if (s_usb_host_mode) {
            pm5_usb_host_cdc_poll();
        }
        // Clear any stale handshake state when in USB host mode
        s_handshake_pending = false;
        s_cep_active = false;
    } else if (attach == CEP_ATTACH_SNK || attach == CEP_ATTACH_PEER) {
        s_detach_count = 0;
        // Partner sources VBUS: Flipper Zero - USART1 handshake + SPI.
        if (s_usb_host_mode && !s_usb_host_forced) {
            pm5_usb_host_cdc_deinit();
            s_usb_host_mode = false;
        }
        if (!s_usart1_active && !s_usb_host_forced) {
            cep_usart1_restore();
            s_usart1_active = true;
        }
        // Interrupt-driven handshake (Adrian, 2026-11-24): the USART1 ISR
        // sets s_handshake_pending when a full request arrives; reply
        // over SPI here. Do NOT poll USART1 RX here - the ISR owns it now.
        if (s_handshake_pending) {
            s_handshake_pending = false;
            s_cep_active = cep_reply_handshake();
            if (s_cep_active) {
                s_last_spi_activity_tick = GetTickCount();
            }
        }
        // The FAP quitting doesn't touch the CC controller's attach bit -
        // losing its SPI poll cadence (normally every 20-120ms) is what
        // actually means it has gone.
        if (s_cep_active && (GetTickCountDelta(s_last_spi_activity_tick) > CEP_ACTIVITY_TIMEOUT_MS)) {
            s_cep_active = false;
        }
    } else {
        // Unattached: release the shared lines and reset state.
        if (s_detach_count < CEP_DETACH_DEBOUNCE_READS) {
            if (++s_detach_count >= CEP_DETACH_DEBOUNCE_READS) {
                s_usb_host_forced = false;
                if (s_usb_host_mode) {
                    pm5_usb_host_cdc_deinit();
                    s_usb_host_mode = false;
                }
                s_handshake_pending = false;
                if (s_usart1_active) {
                    usart_enable(USART1, FALSE);
                    usart_interrupt_enable(USART1, USART_RDBF_INT, FALSE);
                    nvic_irq_disable(USART1_IRQn);
                    s_usart1_active = false;
                }
                s_cep_active = false;
                cep_lines_float();
            }
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

static bool cep_spi_read_byte(uint8_t *out) {
    uint64_t timeout = 0;
    while (spi_i2s_flag_get(SPI1, SPI_I2S_RDBF_FLAG) == RESET) {
        if (timeout++ > CEP_SPI_BYTE_TIMEOUT) {
            return false;
        }
    }
    *out = spi_i2s_data_receive(SPI1);
    return true;
}

// Genuinely non-blocking - a single flag read, no spin-wait at all. For
// data_available()'s use (armsrc/util.c): a tight sampling loop calls that
// every pass purely to notice an incoming CMD_BREAK_LOOP promptly, so it
// needs to cost nothing when idle. cep_spi_data_available() isn't a fit
// here - it waits (bounded, but non-zero) for a first byte to actually
// arrive, which is fine for receive_ng()'s own cadence but would add that
// wait to every iteration of every LF/HF reader loop in the codebase.
bool cep_spi_rx_pending(void) {
    return spi_i2s_flag_get(SPI1, SPI_I2S_RDBF_FLAG) != RESET;
}

bool cep_spi_data_available(void) {
    // SPI1 is full-duplex, no RX FIFO: a byte can freeze in SPI_DT during
    // any main-loop gap (write, I2C poll, WDT_HIT) until read (RM ch
    // 13.2.9). Clear it before it's misread as part of a length header.
    if (spi_i2s_flag_get(SPI1, SPI_I2S_ROERR_FLAG) != RESET) {
        spi_i2s_flag_clear(SPI1, SPI_I2S_ROERR_FLAG);
    }
    uint8_t len_header[2] = {0x00};
    size_t discarded = 0;
    while (1) {
        if (!cep_spi_read_byte(&len_header[0])) {
            return false;
        }
        if (len_header[0] != CEP_SYNC_BYTE) {
            break;
        }
        if (++discarded > CEP_SYNC_MAX_DISCARD) {
            // More sync bytes than the FAP's real preamble (500) can only
            // mean a desynced read (AT32 errata ES0003, see
            // cep_spi_resync()) or bus noise - resync now rather than
            // leaving SPI1 in that state until a later CRC/length check
            // catches it, which may be a full frame away.
            cep_spi_resync();
            return false;
        }
    }
    if (!cep_spi_read_byte(&len_header[1])) {
        return false;
    }
    s_last_spi_activity_tick = GetTickCount(); // FAP is still polling, valid frame or not
    uint16_t data_len = (len_header[1] << 8) | len_header[0];
    if (data_len == 0xFFFF) {
        // FAP's reply-poll drives 0xFF dummy bytes when it has nothing to
        // send (furi_hal_spi_bus_trx with a NULL tx buffer) - not a desync,
        // same treatment as a CEP_SYNC_BYTE run, no resync needed.
        return false;
    }
    if (data_len > PM3_CMD_DATA_SIZE * 2) {
        // Same reasoning: an implausible length is itself evidence of a
        // desynced read, not just "no frame yet."
        cep_spi_resync();
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

// PM5 is the SPI slave: TDBE only clears when the master is actively
// clocking, which happens on the Flipper's own ~20-120ms poll schedule,
// completely async to when PM5 has a reply ready. An unbounded wait here
// hangs the main loop forever (no recovery, not even a watchdog reset) the
// moment a reply is queued between two master polls - bound every wait so
// a slow/absent master degrades to a dropped reply, not a dead device.
static bool cep_spi_wait_tdbe(uint64_t timeout_limit) {
    uint64_t timeout = 0;
    while (spi_i2s_flag_get(SPI1, SPI_I2S_TDBE_FLAG) == RESET) {
        if (timeout++ > timeout_limit) {
            return false;
        }
    }
    return true;
}

int cep_spi_write_sync(uint8_t *data, size_t len) {
    int ret = PM3_SUCCESS;

    // These two length-header bytes are the ones racing against the
    // master's next poll - see CEP_SPI_HEADER_BYTE_TIMEOUT's comment.
    if (!cep_spi_wait_tdbe(CEP_SPI_HEADER_BYTE_TIMEOUT)) {
        ret = PM3_EIO;
        goto cleanup;
    }
    spi_i2s_data_transmit(SPI1, len & 0xFF);

    if (!cep_spi_wait_tdbe(CEP_SPI_HEADER_BYTE_TIMEOUT)) {
        ret = PM3_EIO;
        goto cleanup;
    }
    spi_i2s_data_transmit(SPI1, (len >> 8) & 0xFF);

    for (size_t i = 0; i < len; ++i) {
        if (!cep_spi_wait_tdbe(CEP_SPI_BYTE_TIMEOUT)) {
            ret = PM3_EIO;
            goto cleanup;
        }
        spi_i2s_data_transmit(SPI1, data[i]);
    }

    // Two trailing zero bytes: the agreed "no more data" idle marker.
    if (!cep_spi_wait_tdbe(CEP_SPI_BYTE_TIMEOUT)) {
        ret = PM3_EIO;
        goto cleanup;
    }
    spi_i2s_data_transmit(SPI1, 0x00);
    if (!cep_spi_wait_tdbe(CEP_SPI_BYTE_TIMEOUT)) {
        ret = PM3_EIO;
        goto cleanup;
    }
    spi_i2s_data_transmit(SPI1, 0x00);

    {
        uint64_t timeout = 0;
        while (spi_i2s_flag_get(SPI1, SPI_I2S_BF_FLAG) == SET) {
            if (timeout++ > CEP_SPI_BYTE_TIMEOUT) {
                ret = PM3_EIO;
                goto cleanup;
            }
        }
    }

cleanup:
    // Same full-duplex freeze as cep_spi_data_available() - SPI1 shifted a
    // byte in on MOSI for every byte clocked out above. Clear it here, once,
    // outside the timed write, so the read path never inherits it.
    if (spi_i2s_flag_get(SPI1, SPI_I2S_ROERR_FLAG) != RESET) {
        spi_i2s_flag_clear(SPI1, SPI_I2S_ROERR_FLAG);
    }
    return ret;
}
