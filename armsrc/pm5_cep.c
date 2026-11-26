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
#include "at32f435_437_dma.h"
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
#define CEP_HANDSHAKE_STRING     "iamf0rupm5"
#define CEP_HANDSHAKE_STX        0x02
#define CEP_SPI_BYTE_TIMEOUT     100000  // spin-wait iterations per byte (matches source)
// The Flipper master only clocks the bus in bursts roughly every ~120ms
// (its own idle poll cadence) - CEP_SPI_BYTE_TIMEOUT alone (~3-10ms real
// time) is far shorter than that gap, so the first reply byte - the one
// racing against the master's next poll - needs a budget that actually
// spans it. Once that byte clears, the master is mid-CS and keeps
// clocking continuously, so every later byte stays on the short timeout.
// Took measured CEP reply success from ~22% to ~100% in testing.
#define CEP_SPI_HEADER_BYTE_TIMEOUT  2000000
#define CEP_SPI_RESPONSE_TIMEOUT_TICKS  1500000  // 1s at 1.5 MHz
#define CEP_HANDSHAKE_REPLY_MAX_RETRIES 3  // bound the stall-recovery loop below - still-attached isn't still-working forever

// The Flipper prefixes commands with 0x55 sync bytes.
#define CEP_SYNC_BYTE            0x55
#define CEP_SYNC_MAX_DISCARD     600

// DMA1 channels 1 and 2 serve SSC and BWM USART RX.
#define CEP_RX_DMA               DMA1_CHANNEL3
#define CEP_RX_DMA_MUX           DMA1MUX_CHANNEL3
#define CEP_RX_DMA_DONE          DMA1_FDT3_FLAG
// One complete Flipper command is at most 500 sync + 2 length + 600 data + 1 trailer.
#define CEP_RX_RING_SIZE         2048u
#define CEP_RX_RING_MASK         (CEP_RX_RING_SIZE - 1u)

// How long cep_attach_poll() will go without seeing a real SPI poll from the
// Flipper before deciding the FAP has quit (see the comment at its one use
// below) and letting AppMain() go back to sleeping between iterations.
#define CEP_ACTIVITY_TIMEOUT_MS      3000

static bool s_cep_active = false;   // handshake completed, SPI transport live
static bool s_cep_attached = false; // CC controller reports a physical attach
static uint32_t s_last_spi_activity_tick = 0; // last time a real SPI poll was seen
static volatile bool s_handshake_pending;

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
static volatile uint8_t s_spi_rx_ring[CEP_RX_RING_SIZE];
static volatile uint32_t s_spi_rx_wraps;
static uint32_t s_spi_rx_tail;
static uint32_t s_spi_rx_produced;
static uint32_t s_spi_rx_frame_end;

void DMA1_Channel3_IRQHandler(void) {
    if (dma_flag_get(CEP_RX_DMA_DONE) != RESET) {
        dma_flag_clear(CEP_RX_DMA_DONE);
        s_spi_rx_wraps++;
    }
}

// Drain SPI1 even while the main loop is busy with I2C or USB.
static void cep_spi_rx_init(void) {
    crm_periph_clock_enable(CRM_DMA1_PERIPH_CLOCK, TRUE);
    dma_reset(CEP_RX_DMA);

    s_spi_rx_tail = 0;
    s_spi_rx_produced = 0;
    s_spi_rx_wraps = 0;
    s_spi_rx_frame_end = 0;

    dma_init_type config;
    dma_default_para_init(&config);
    config.buffer_size = CEP_RX_RING_SIZE;
    config.direction = DMA_DIR_PERIPHERAL_TO_MEMORY;
    config.peripheral_base_addr = (uint32_t)&SPI1->dt;
    config.memory_base_addr = (uint32_t)s_spi_rx_ring;
    config.memory_inc_enable = TRUE;
    config.loop_mode_enable = TRUE;
    config.priority = DMA_PRIORITY_MEDIUM;
    dma_init(CEP_RX_DMA, &config);

    dmamux_enable(DMA1, TRUE);
    dmamux_init(CEP_RX_DMA_MUX, DMAMUX_DMAREQ_ID_SPI1_RX);
    dma_interrupt_enable(CEP_RX_DMA, DMA_FDT_INT, TRUE);
    nvic_irq_enable(DMA1_Channel3_IRQn, 1, 0);

    dma_channel_enable(CEP_RX_DMA, TRUE);
    spi_i2s_dma_receiver_enable(SPI1, TRUE);
}

static uint32_t cep_spi_rx_head(void) {
    // The counter and IRQ flag can change while we sample DTCNT at wrap.
    uint32_t wraps;
    uint32_t pending;
    uint32_t remaining;
    do {
        wraps = s_spi_rx_wraps;
        pending = DMA1->sts & CEP_RX_DMA_DONE;
        remaining = CEP_RX_DMA->dtcnt;
    } while (wraps != s_spi_rx_wraps || pending != (DMA1->sts & CEP_RX_DMA_DONE));
    // DTCNT can read as zero before it reloads and the wrap is counted.
    if (remaining != 0) {
        uint32_t head = (wraps + (pending != 0)) * CEP_RX_RING_SIZE
                        + CEP_RX_RING_SIZE - remaining;
        if ((int32_t)(head - s_spi_rx_produced) >= 0) {
            s_spi_rx_produced = head;
        }
    }
    return s_spi_rx_produced;
}

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
    cep_spi_rx_init();
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
    dma_channel_enable(CEP_RX_DMA, FALSE);
    spi_enable(SPI1, FALSE);
    crm_periph_reset(CRM_SPI1_PERIPH_RESET, TRUE);
    crm_periph_reset(CRM_SPI1_PERIPH_RESET, FALSE);
    cep_spi_init();
}

void cep_init(void) {
    cep_usart_init();
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

    bool attached = ((cc_ctrl_data >> 6 & 0x03) != 0);
    s_cep_attached = attached;

    if (!attached) {
        s_cep_active = false;
        s_handshake_pending = false;
    } else {
        // The FAP re-runs its handshake on every app launch, not just on a
        // fresh physical attach - the CC controller's attach bits don't
        // reliably blip on every relaunch (confirmed on hardware: sometimes
        // they do, sometimes they don't), so gating the handshake listener on
        // that edge alone missed real handshake attempts and required a
        // physical unplug/replug to recover (GH #3667). Instead, watch for a
        // complete request any time we're attached, regardless of edge.
        if (s_handshake_pending) {
            s_handshake_pending = false;
            s_cep_active = cep_reply_handshake();
            s_spi_rx_tail = cep_spi_rx_head();
            if (s_cep_active) {
                s_last_spi_activity_tick = GetTickCount();
            }
        }

        // The FAP quitting doesn't touch the CC controller's attach bit - the
        // cable stays connected, so `attached` alone can't tell us it's gone.
        // Losing its SPI poll cadence (normally every 20-120ms) is what
        // actually means it has - fall back to the slower/idle main loop
        // once that cadence has been missing this long.
        if (s_cep_active && (GetTickCountDelta(s_last_spi_activity_tick) > CEP_ACTIVITY_TIMEOUT_MS)) {
            s_cep_active = false;
        }
    }

    uint8_t int_state = cc_ctrl_data >> 4 & 0x01;
    if (int_state) {
        cc_ctrl_data |= 1 << 4;   // clear the CC controller's interrupt latch
        I2C_BufferWrite(&cc_ctrl_data, 1, CEP_CC_STATUS_REG, CEP_CC_CONTROLLER_ADDR << 1);
    }
}

// ---------------------------------------------------------------------------
// SPI NG-frame transport
// ---------------------------------------------------------------------------

static bool cep_spi_read_byte(uint8_t *out) {
    uint64_t timeout = 0;
    uint32_t head;
    do {
        head = cep_spi_rx_head();
        if (timeout++ > CEP_SPI_BYTE_TIMEOUT) {
            return false;
        }
    } while (head == s_spi_rx_tail);
    if (head - s_spi_rx_tail > CEP_RX_RING_SIZE) {
        s_spi_rx_tail = head;
        return false;
    }
    *out = s_spi_rx_ring[s_spi_rx_tail++ & CEP_RX_RING_MASK];
    return true;
}

static bool cep_spi_rewind_ng_magic(uint8_t first) {
    uint32_t magic = COMMANDNG_PREAMBLE_MAGIC;
    if (first != (uint8_t)magic) {
        return false;
    }
    for (size_t i = 1; i < sizeof(magic); i++) {
        uint8_t byte;
        magic >>= 8;
        if (!cep_spi_read_byte(&byte) || byte != (uint8_t)magic) {
            return false;
        }
    }
    s_spi_rx_tail -= sizeof(magic);
    return true;
}

bool cep_spi_rx_pending(void) {
    if (!s_cep_active) {
        return false;
    }
    uint32_t head = cep_spi_rx_head();
    if (head == s_spi_rx_tail) {
        return false;
    }
    // Filler-only polls still keep CEP alive.
    s_last_spi_activity_tick = GetTickCount();
    if (head - s_spi_rx_tail > CEP_RX_RING_SIZE) {
        s_spi_rx_tail = head;
    }
    // Empty Flipper polls and a command's trailing byte do not stop a reader.
    while (s_spi_rx_tail != head) {
        uint8_t byte = s_spi_rx_ring[s_spi_rx_tail & CEP_RX_RING_MASK];
        if (byte != 0xffu && byte != 0x00u) {
            return true;
        }
        s_spi_rx_tail++;
    }
    return false;
}

bool cep_spi_data_available(void) {
    if (spi_i2s_flag_get(SPI1, SPI_I2S_ROERR_FLAG) != RESET) {
        cep_spi_resync();
        return false;
    }

    if (!cep_spi_rx_pending()) {
        return false;
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
        if (++discarded > CEP_SYNC_MAX_DISCARD + 1) {
            // More sync bytes than the FAP's real preamble (500) can only
            // mean a desynced read (AT32 errata ES0003, see
            // cep_spi_resync()) or bus noise - resync now rather than
            // leaving SPI1 in that state until a later CRC/length check
            // catches it, which may be a full frame away.
            // The last 0x55 may be the low byte of the length.
            cep_spi_resync();
            return false;
        }
    }
    if (!cep_spi_read_byte(&len_header[1])) {
        return false;
    }
    uint16_t data_len = (len_header[1] << 8) | len_header[0];
    const size_t max_len = MAX(sizeof(PacketCommandNGRaw), sizeof(PacketCommandOLD));

    // If we skipped the low length byte, len_header[1] starts the NG magic.
    uint16_t sync_len = (len_header[0] << 8) | CEP_SYNC_BYTE;
    if (discarded > 0 && data_len > max_len && sync_len <= sizeof(PacketCommandNGRaw)
            && cep_spi_rewind_ng_magic(len_header[1])) {
        data_len = sync_len;
        discarded--;
    }

    if (data_len == 0xFFFF && discarded <= CEP_SYNC_MAX_DISCARD) {
        // FAP's reply-poll drives 0xFF dummy bytes when it has nothing to
        // send (furi_hal_spi_bus_trx with a NULL tx buffer) - not a desync,
        // same treatment as a CEP_SYNC_BYTE run, no resync needed.
        return false;
    }

    if (discarded > CEP_SYNC_MAX_DISCARD
            || data_len < sizeof(PacketCommandNGPreamble) + sizeof(PacketCommandNGPostamble)
            || data_len > max_len) {
        // Same reasoning: an implausible length is itself evidence of a
        // desynced read, not just "no frame yet."
        cep_spi_resync();
        return false;
    }
    s_spi_rx_frame_end = s_spi_rx_tail + data_len;
    return true;
}

bool cep_spi_finish_command(void) {
    uint8_t trailer;
    return s_spi_rx_tail == s_spi_rx_frame_end
           && cep_spi_read_byte(&trailer) && trailer == 0;
}

int cep_spi_check_command_length(size_t remaining) {
    if (remaining == s_spi_rx_frame_end - s_spi_rx_tail) {
        return PM3_SUCCESS;
    }

    // Discard only this frame if its outer length and trailer are intact.
    uint8_t byte;
    while (s_spi_rx_tail != s_spi_rx_frame_end) {
        if (!cep_spi_read_byte(&byte)) {
            cep_spi_resync();
            return PM3_EIO;
        }
    }
    if (!cep_spi_finish_command()) {
        cep_spi_resync();
        return PM3_EIO;
    }
    return PM3_ENODATA;
}

uint32_t cep_spi_read_ng(uint8_t *data, size_t len) {
    if (len > s_spi_rx_frame_end - s_spi_rx_tail) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        if (!cep_spi_read_byte(data + i)) {
            return i;
        }
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
    // MOSI carries poll padding during a reply.
    s_spi_rx_tail = cep_spi_rx_head();
    return ret;
}
