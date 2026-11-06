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
// Proxmark5 14a sniffer FPGA image (fpga/pm5/pm5_hi_iso14443a.v), embedded in the ARM image.
// `hf 14a sniff` loads it into FPGA SRAM and reloads the image from the FPGA's own flash once
// the sniff has replied (FpgaDownloadAndGo() too, should the sniffer image still be there).
// Only SRAM is configured here: the FPGA flash is never written.
//-----------------------------------------------------------------------------
#include "pm5_sniffimg.h"

#ifdef PM5_SNIFF_EMBED

#include "fpga_apis.h"
#include "fpga_gw_jtag.h"
#include "fpga_loader.h"
#include "gpio_apis.h"
#include "ticks_apis.h"
#include "wdt_apis.h"
#include "dbprint.h"
#include "pm3_cmd.h"
#include "commonutil.h"     // ARRAYLEN
#include "fpga_hw_at32.h"   // SPI_CMD
#include "config_gpio_proxmark5.h"

// objcopy -I binary of the image (armsrc/Makefile, PM5_SNIFF_IMAGE)
extern const uint8_t _binary_obj_pm5_sniff_bin_start[];
extern const uint8_t _binary_obj_pm5_sniff_bin_end[];

typedef enum {
    PM5_SRAM_FLASH,             // the FPGA runs the image from its own flash
    PM5_SRAM_SNIFF,             // the embedded sniffer image
    PM5_SRAM_USER,              // loaded by `hw fpga config -s`: left alone
} pm5_sram_t;

static pm5_sram_t s_sram = PM5_SRAM_FLASH;
static bool s_keep = false;
static bool s_thr_set = false;
static uint16_t s_thr = 0;

// TCK and TDI are SPI3's SCK and MOSI on this board, so SPI3 shifts the image at 144 MHz / 2, 3, 4, 8, 16 or 32 (the stock
// routine: 1.6 s for this image). Every frame carries a CRC16 the FPGA checks, so a transfer that is too fast fails and
// falls through to the next step, the stock routine last. The step that worked is tried first next time.
static const spi_mclk_freq_div_type s_spi_div[] = {
    SPI_MCLK_DIV_2, SPI_MCLK_DIV_3, SPI_MCLK_DIV_4, SPI_MCLK_DIV_8, SPI_MCLK_DIV_16, SPI_MCLK_DIV_32
};
// after done, the JTAG pins (SPI3's: the FPGA's command port once it runs the image) idle this long before the TAP reset
#define PM5_SETTLE_MS           10
static uint8_t s_speed = 0;

static void pm5_resend_thresholds(void) {
    if (s_thr_set) {
        FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, s_thr);
    }
}

// A status read with any of the always-0 bits 18-31 set is not trusted. Read without the debug dump.
static bool pm5_read_status(gowin_status_reg_t *st) {
    st->raw = gowin_jtag_read_status();
    return (st->raw >> 18) == 0;
}

// configuration done after a load into SRAM (the erase cleared it), at most timeout_ms
static bool pm5_wait_done(uint32_t timeout_ms) {
    uint32_t t0 = GetTickCount();
    do {
        gowin_status_reg_t st;
        if (pm5_read_status(&st)) {
            if (st.bits.done_final) {
                return true;
            }
            if (st.bits.crc_error) {
                return false;
            }
        }
    } while (GetTickCountDelta(t0) < timeout_ms);
    return false;
}

// Reload from the FPGA's own flash with the stock routine, which leaves JTAG idle for 200 ms after REPROGRAM (polling the
// status during the reload left the FPGA unconfigured). One more try if the image does not report done.
static void pm5_reload_flash_image(void) {
    bool ok = false;
    for (int i = 0; i < 2 && ok == false; i++) {
        gpio_fpga_download_setup();
        if (gowin_jtag_init() == GOWIN_JTAG_OK) {
            gowin_jtag_reprogram();
            ok = pm5_wait_done(100);
        }
        gowin_jtag_deinit();
    }
    if (ok == false && g_dbglevel >= DBG_ERROR) {
        DbpString(_RED_("FPGA: image reload from the FPGA's flash not confirmed, power cycle the device"));
    }
}

static void pm5_spi_pin(gpio_type *port, uint16_t pin, gpio_pins_source_type src, gpio_mux_sel_type mux, bool spi) {
    gpio_init_type gi;
    gpio_default_para_init(&gi);
    gi.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gi.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gi.gpio_pull = GPIO_PULL_NONE;
    gi.gpio_pins = pin;
    gi.gpio_mode = spi ? GPIO_MODE_MUX : GPIO_MODE_OUTPUT;
    if (spi) {
        gpio_pin_mux_config(port, src, mux);    // function first, so the pin never shows another one
    }
    gpio_init(port, &gi);
}

// The TAP is in Shift-DR. SPI mode 0, MSB first, as the stock routine: TDI changes while TCK is low and is taken on its
// rising edge. TMS (PA15, SPI3's CS) stays low; the last byte goes through the stock routine, which raises TMS on its
// last bit (-> Exit1-DR). TCK is low across each pin switch, so no switch makes an edge the TAP acts on. Two bytes a
// 16-bit frame (the same bits in the same order), registers written directly.
static void pm5_jtag_shift_spi(const uint8_t *data, uint32_t len, uint32_t *pos, spi_mclk_freq_div_type div) {
    set_tms_low();
    set_tck_low();

    crm_periph_clock_enable(SPI_CRM_CLOCK_CMD, TRUE);
    spi_init_type si;
    spi_default_para_init(&si);
    si.transmission_mode = SPI_TRANSMIT_FULL_DUPLEX;
    si.master_slave_mode = SPI_MODE_MASTER;
    si.mclk_freq_division = div;
    si.first_bit_transmission = SPI_FIRST_BIT_MSB;
    si.frame_bit_num = SPI_FRAME_16BIT;
    si.clock_polarity = SPI_CLOCK_POLARITY_LOW;
    si.clock_phase = SPI_CLOCK_PHASE_1EDGE;
    si.cs_mode_selection = SPI_CS_SOFTWARE_MODE;
    spi_init(SPI_CMD, &si);
    spi_enable(SPI_CMD, TRUE);              // SCK idles low before the pins are switched to it

    pm5_spi_pin(AT32_GPIO_SPI_SCK, AT32_GPIO_SPI_SCK_PIN, AT32_GPIO_SPI_SCK_SOURCE, AT32_GPIO_SPI_SCK_MUX, true);
    pm5_spi_pin(AT32_GPIO_SPI_MOSI, AT32_GPIO_SPI_MOSI_PIN, AT32_GPIO_SPI_MOSI_SOURCE, AT32_GPIO_SPI_MOSI_MUX, true);

    uint32_t n = (len - 1) & ~1u;           // the rest, 1 or 2 bytes, through the stock routine
    for (uint32_t i = 0; i < n; i += 2) {
        if ((i & 0xFFF) == 0) {
            WDT_HIT();
        }
        while ((SPI_CMD->sts & SPI_I2S_TDBE_FLAG) == 0) {}
        SPI_CMD->dt = (uint16_t)((data[i] << 8) | data[i + 1]);
    }
    while ((SPI_CMD->sts & SPI_I2S_TDBE_FLAG) == 0) {}
    while ((SPI_CMD->sts & SPI_I2S_BF_FLAG) != 0) {}

    // back to GPIO with TCK low, then let go of SPI3 (FpgaSendCommand() sets it up again each time)
    set_tck_low();
    pm5_spi_pin(AT32_GPIO_FPGA_JTAG_TCK, AT32_GPIO_FPGA_JTAG_TCK_PIN, 0, 0, false);
    pm5_spi_pin(AT32_GPIO_FPGA_JTAG_TDI, AT32_GPIO_FPGA_JTAG_TDI_PIN, 0, 0, false);
    spi_enable(SPI_CMD, FALSE);
    (void)SPI_CMD->dt;                      // the received bytes were not read: clear the overrun
    (void)SPI_CMD->sts;

    *pos = n;
    gowin_jtag_sram_config_write((uint8_t *)data + n, len - n, pos, len);
}

static bool pm5_sram_load(const uint8_t *img, uint32_t len, uint8_t speed) {
    bool ok = false;
    gpio_fpga_download_setup();
    if (gowin_jtag_init() == GOWIN_JTAG_OK) {
        uint32_t pos = 0;
        if (gowin_jtag_sram_config_start(&pos) == GOWIN_JTAG_OK) {
            ok = true;
            if (speed < ARRAYLEN(s_spi_div)) {
                pm5_jtag_shift_spi(img, len, &pos, s_spi_div[speed]);
            } else {
                for (uint32_t i = 0; i < len && ok; i += 4096) {
                    WDT_HIT();
                    uint32_t n = MIN(len - i, 4096);
                    ok = (gowin_jtag_sram_config_write((uint8_t *)img + i, n, &pos, len) == GOWIN_JTAG_OK);
                }
            }
            // done polled instead of the stock finish's fixed 60 ms, then the pins idle
            ok = (gowin_jtag_sram_config_finish_poll(100, PM5_SETTLE_MS) == GOWIN_JTAG_OK) && ok;
            ok = ok && pm5_wait_done(100);
        }
    }
    gowin_jtag_deinit();
    return ok;
}

bool Pm5SniffImgLoad(void) {
    if (s_sram != PM5_SRAM_FLASH) {
        return (s_sram == PM5_SRAM_SNIFF);
    }

    const uint8_t *img = _binary_obj_pm5_sniff_bin_start;
    uint32_t len = _binary_obj_pm5_sniff_bin_end - _binary_obj_pm5_sniff_bin_start;

    uint32_t t0 = GetTickCount();
    bool ok = false;
    for (uint8_t sp = s_speed; sp <= ARRAYLEN(s_spi_div) && ok == false; sp++) {
        ok = pm5_sram_load(img, len, sp);
        if (ok) {
            s_speed = sp;
        }
    }
    FpgaResetBitstream();                   // the next FpgaDownloadAndGo() sets the new image up from scratch

    if (ok == false) {
        if (g_dbglevel >= DBG_ERROR) {
            DbpString(_RED_("FPGA: 14a sniffer image did not load, sniffing at 106 kbit/s with the image in the FPGA's flash"));
        }
        pm5_reload_flash_image();
        pm5_resend_thresholds();
        return false;
    }

    s_sram = PM5_SRAM_SNIFF;
    pm5_resend_thresholds();
    if (g_dbglevel >= DBG_DEBUG) {
        Dbprintf("FPGA: 14a sniffer image loaded into SRAM in %u ms", GetTickCountDelta(t0));
    }
    return true;
}

void Pm5SniffImgRestore(void) {
    if (s_sram != PM5_SRAM_SNIFF || s_keep) {
        return;
    }
    uint32_t t0 = GetTickCount();
    pm5_reload_flash_image();
    s_sram = PM5_SRAM_FLASH;
    FpgaResetBitstream();
    pm5_resend_thresholds();
    if (g_dbglevel >= DBG_DEBUG) {
        Dbprintf("FPGA: image from the FPGA's flash back in %u ms", GetTickCountDelta(t0));
    }
}

void Pm5SniffImgKeep(bool keep) {
    s_keep = keep;
}

void Pm5SniffImgUserConfig(bool sram) {
    s_sram = sram ? PM5_SRAM_USER : PM5_SRAM_FLASH;
}

void Pm5SniffImgSetThresholds(uint16_t value) {
    s_thr = value;
    s_thr_set = true;
}

#endif
