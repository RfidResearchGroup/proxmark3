//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Mar 2006
// Copyright (C) Gerhard de Koning Gans, Sep 2007
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
// The main application code. This is the first thing called after start.c
// executes.
//-----------------------------------------------------------------------------
#include "appmain.h"

#include "sys_apis.h"
#include "usb_cdc_apis.h"
#ifdef WITH_BWM_FORWARD
#include "bwm_uart_at32.h"
#include "bwm_forward.h"   // bwm_fwd_negotiate_baud()
#include "bwm_wifi.h"
#endif
#include "proxmark3_arm.h"
#include "dbprint.h"
#include "pmflash.h"
#include "fpga.h"
#include "fpga_loader.h"
#include "fpga_apis.h"
#include "rssi_apis.h"
#include "rgb_apis.h"
#include "gpio_apis.h"    // gpio_vusb_setup / Gpio_VUSB_Read (USB-present detection)
#include "string.h"
#include "printf.h"
#include "legicrf.h"
#include "BigBuf.h"
#include "iclass_cmd.h"
#include "hfops.h"
#include "iso14443a.h"
#include "secc.h"
#include "iso14443b.h"
#include "iso15693.h"
#include "thinfilm.h"
#include "felica.h"
#include "felicasim.h"
#include "hitag2.h"
#include "hitag2_crack.h"
#include "hitagS.h"
#include "hitagu.h"
#include "em4x50.h"
#include "em4x70.h"
#include "iclass.h"
#include "seos.h"
#include "legicrfsim.h"
//#include "cryptorfsim.h"
#include "epa.h"
#include "hfsnoop.h"
#include "lfops.h"
#include "lfsampling.h"
#include "lfzx.h"
#include "mifarecmd.h"
#include "mifaredesfire.h"
#include "mifaresim.h"
#include "emvsim.h"
#include "pcf7931.h"
#include "Standalone/standalone.h"
#include "util.h"
#include "ticks_apis.h"
#include "commonutil.h"
#include "crc16.h"
#include "protocols.h"
#include "mifareutil.h"
#include "sam_picopass.h"
#include "sam_seos.h"
#include "sam_mfc.h"
#include "sam_sc.h"
#include "cmac_calc.h"
#include "i2c.h"
#include "bwm_charger.h"   // BWM charger / fuel-gauge + low-batt warning (WITH_BWM_*)
#include "buzzer.h"        // PM5 mainboard buzzer API
#include "rgb_indicator.h" // PM5 antenna-RGB power/battery indicator (WITH_PM5_PWR_LED)


#ifdef WITH_PM5_AUTOOFF
// Automatic power-off on USB unplug. When the BWM keeps the PM5 alive on battery,
// users leave it draining. This powers the board down after USB has been absent
// continuously for a grace period, using the SAME latch release as the long-press
// shutdown (Gpio_ARM_Power_ON_Low). Button power-ON is a hardware function and is
// unaffected - once powered off there is no firmware running to interfere with it.
//
// Runtime toggle (default ON) via CMD_PM5_BWM_AUTOOFF; resets to default each boot.
// Standalone / BLE-relay users who run unplugged on purpose can disable it.
#ifndef PM5_AUTOOFF_POLL_MS
#define PM5_AUTOOFF_POLL_MS    250     // how often to sample VUSB
#endif

bool g_autooff_enabled = true;   // default on; toggled by CMD_PM5_BWM_AUTOOFF

static bool s_autooff_setup = false;

// Auto power-off on USB unplug. CRITICAL: only powers off on a USB-present -> absent
// TRANSITION - i.e. the board was running on USB and the cable was pulled. A board that
// booted on battery (button press, no USB) must NOT auto-off, or it could never be used
// unplugged at all (and the hw bwmautooff toggle would be unreachable, since setting it
// needs a client/USB). So we require having seen USB present at least once this session
// before an absent reading triggers shutdown.
static void bwm_autooff_check(void) {
    static uint32_t last_tick = 0;
    static bool usb_was_present = false;   // have we seen USB present since boot?

    if (g_autooff_enabled == false) {
        return;
    }
    if ((last_tick != 0) && (GetTickCountDelta(last_tick) < PM5_AUTOOFF_POLL_MS)) {
        return;
    }
    last_tick = GetTickCount();

    if (s_autooff_setup == false) {
        gpio_vusb_setup();
        s_autooff_setup = true;
    }

    // Gpio_VUSB_Read() == true means USB power present.
    if (Gpio_VUSB_Read()) {
        usb_was_present = true;   // latch: USB has been present this session
        return;
    }

    // USB absent. Only power off if USB had previously been present (a real unplug).
    // If it booted on battery and never saw USB, leave it running.
    if (usb_was_present == false) {
        return;
    }

    LEDsoff();
    Gpio_ARM_Power_ON_Low();
    while (1); // wait for hardware power-off (button press powers back on, in hardware)
}
#endif // WITH_PM5_AUTOOFF

#ifdef WITH_LCD
#include "LCD_disabled.h"
#endif

#ifdef WITH_SMARTCARD
#include "i2c.h"
#endif

#ifdef WITH_FPC_USART
#include "usart.h"
#endif

#ifdef WITH_FLASH
#include "flashmem.h"
#include "spiffs.h"
#endif

int g_dbglevel = DBG_ERROR;
uint8_t g_trigger = 0;
bool g_hf_field_active = false;
bool g_hf_field_timeout_active = false;
extern uint32_t _stack_start[], _stack_end[];
common_area_t g_common_area __attribute__((section(".commonarea")));
static int button_status = BUTTON_NO_CLICK;
static bool allow_send_wtx = false;
static uint32_t g_hf_field_activity_timeout_ms = 0;
uint16_t g_tearoff_delay_us = 0;
bool g_tearoff_enabled = false;
uint8_t g_tearoff_skip = 0;

int tearoff_hook(void) {

    if (g_tearoff_enabled == false) {
        return PM3_SUCCESS;
    }

    // tear off is happening...

    if (g_tearoff_delay_us == 0) {

        if (g_dbglevel >= DBG_ERROR) Dbprintf(_RED_("No tear-off delay configured!"));
        g_tearoff_enabled = false;
        return PM3_SUCCESS; // SUCCESS = the hook didn't do anything
    }

    if (g_tearoff_skip > 0) {
        if (g_dbglevel >= DBG_INFO) Dbprintf(_GREEN_("Tear-off skipped!"));
        g_tearoff_skip--;
        return PM3_SUCCESS; // SUCCESS = the hook didn't do anything
    }

    SpinDelayUsPrecision(g_tearoff_delay_us);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    g_tearoff_enabled = false;

    if (g_dbglevel >= DBG_INFO) Dbprintf(_YELLOW_("Tear-off triggered!"));

    return PM3_ETEAROFF;
}

void hf_field_off(void) {
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    g_hf_field_active = false;
    g_hf_field_timeout_active = false;
}

void send_wtx(uint16_t wtx) {
    if (allow_send_wtx) {
        reply_ng(CMD_WTX, PM3_SUCCESS, (uint8_t *)&wtx, sizeof(wtx));
    }
}

#ifdef WITH_LF
static void MeasureAntennaTuning(void) {

    uint32_t peak = 0;

    // in mVolt
    struct p {
        uint32_t v_lf134;
        uint32_t v_lf125;
        uint32_t v_lfconf;
        uint32_t v_hf;
        uint32_t peak_v;
        uint32_t peak_f;
        int divisor;
        uint8_t results[256];
    } PACKED payload;

    // Need to clear all values to ensure non-random responses.
    memset(&payload, 0, sizeof(payload));
    // memset(payload.results, 0, sizeof(payload.results));

    sample_config *sc = getSamplingConfig();
    payload.divisor = sc->divisor;

    LED_B_ON();

    /*
     * Sweeps the useful LF range of the proxmark from
     * 46.8kHz (divisor=255) to 600kHz (divisor=19) and
     * read the voltage in the antenna, the result left
     * in the buffer is a graph which should clearly show
     * the resonating frequency of your LF antenna
     * ( hopefully around 95 if it is tuned to 125kHz!)
     */

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER | FPGA_LF_ADC_READER_FIELD);
    SpinDelay(50);

    for (uint8_t i = 255; i >= 19; i--) {
        WDT_HIT();
        FpgaSendCommand(FPGA_CMD_SET_DIVISOR, i);
        SpinDelay(20);
        uint32_t adcval = AdcRssiAvgToMilliVolt(ADC_RSSI_CH_LF);
        if (i == LF_DIVISOR_125)
            payload.v_lf125 = adcval; // voltage at 125kHz

        if (i == LF_DIVISOR_134)
            payload.v_lf134 = adcval; // voltage at 134kHz

        if (i == sc->divisor)
            payload.v_lfconf = adcval; // voltage at `lf config --divisor`

        payload.results[i] = adcval >> 9; // scale int to fit in byte for graphing purposes

        if (payload.results[i] > peak) {
            payload.peak_v = adcval;
            payload.peak_f = i;
            peak = payload.results[i];
        }
    }

    LED_A_ON();
    // Let the FPGA drive the high-frequency antenna around 13.56 MHz.
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER);
    SpinDelay(50);

    payload.v_hf = AdcRssiAvgToMilliVolt(ADC_RSSI_CH_HF);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    reply_ng(CMD_MEASURE_ANTENNA_TUNING, PM3_SUCCESS, (uint8_t *)&payload, sizeof(payload));
    LEDsoff();
}
#endif

#ifndef PM5 // TODO DXL: PM5 is temporarily incompatible.

// Measure HF antenna decay after field-off.
// Captures peak-detect capacitor discharge curve via burst ADC sampling.
static void MeasureAntennaTuningHfDecay(const hf_decay_params_t *params) {

    // Parse parameters with defaults
    uint16_t stabilize_ms = params->stabilize_ms;
    uint16_t measure_us = params->measure_us;

    if (stabilize_ms == 0) stabilize_ms = 50;
    if (measure_us == 0) measure_us = 2000;

    // Response: 8-byte header + up to 252 uint16_t samples = 512 bytes max
    hf_decay_response_t payload;
    memset(&payload, 0, sizeof(payload));

    LED_B_ON();

    // Drive HF field and wait for stabilization
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER);
    SpinDelay(stabilize_ms);

    // Baseline measurement (averaged)
    payload.baseline_mv = (MAX_ADC_HF_VOLTAGE * AdcRssiSum(ADC_RSSI_CH_HF, 32)) >> 15;

    // Configure ADC for fast burst mode.
    // Faster ADC clock + shorter S&H trades absolute accuracy for speed.
    // Source impedance is ~0.91 MOhm (voltage divider), ADC input cap 12pF,
    // RC = 10.9us. At SHTIM=3 / ADC_CLK=3MHz, S&H = 1.33us reads ~11.5%
    // of true voltage. This is fine for relative decay shape measurement.
    AT91C_BASE_ADC->ADC_CR = AT91C_ADC_SWRST;
    AT91C_BASE_ADC->ADC_MR =
        ADC_MODE_PRESCALE(7)               // ADC_CLK = MCK / 16 = 3 MHz
        | ADC_MODE_STARTUP_TIME(8)          // (8+1)*8 / 3MHz = 24us (> 20us min)
        | ADC_MODE_SAMPLE_HOLD_TIME(3);     // (3+1) / 3MHz = 1.33us S&H
    AT91C_BASE_ADC->ADC_CHER = ADC_CHANNEL(ADC_CHAN_HF);

    // Start precise timer (1 tick = MCK/32 = 0.667us)
    StartTicks();

    // Field OFF — start decay measurement
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    uint32_t start_ticks = GetTicks();
    uint16_t idx = 0;
    // Convert us to ticks: 1us = 1.5 ticks
    uint32_t measure_ticks = (measure_us * 3) / 2;

    // Trigger first conversion
    AT91C_BASE_ADC->ADC_CR = AT91C_ADC_START;

    while (idx < 252) {
        if (AT91C_BASE_ADC->ADC_SR & ADC_END_OF_CONVERSION(ADC_CHAN_HF)) {
            uint16_t raw = AT91C_BASE_ADC->ADC_CDR[ADC_CHAN_HF] & 0x3FF;
            payload.samples_mv[idx] = (MAX_ADC_HF_VOLTAGE * raw) >> 10;
            idx++;

            if (GetTicksDelta(start_ticks) >= measure_ticks)
                break;

            // Trigger next conversion
            AT91C_BASE_ADC->ADC_CR = AT91C_ADC_START;
        }
    }

    uint32_t elapsed_ticks = GetTicksDelta(start_ticks);
    payload.num_samples = idx;
    payload.measure_window_us = (elapsed_ticks * 2) / 3;
    payload.sample_interval_us = (idx > 1) ? payload.measure_window_us / (idx - 1) : 0;

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    StopTicks();

    uint16_t response_size = 8 + (idx * sizeof(uint16_t));
    reply_ng(CMD_HF_DECAY, PM3_SUCCESS,
             (uint8_t *)&payload, response_size);

    LEDsoff();
}

#endif

void print_stack_usage(void) {
    for (uint32_t *p = _stack_start; ; ++p) {
        if (*p != 0xdeadbeef) {
            Dbprintf("  Max stack usage..... %d / %d bytes", (uint32_t)_stack_end - (uint32_t)p, (uint32_t)_stack_end - (uint32_t)_stack_start);
            break;
        }
    }
}

void ReadMem(int addr) {
    const uint8_t *data = ((uint8_t *)addr);

    Dbprintf("%x: %02x %02x %02x %02x %02x %02x %02x %02x", addr, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
}

/* osimage version information is linked in, cf commonutil.h */
/* bootrom version information is pointed to from _bootphase1_version_pointer */
extern uint32_t _bootphase1_version_pointer[], _flash_start[], _flash_end[], __data_src_start__[];
#ifndef WITH_COMPRESSION
extern uint32_t _bootrom_end[], _bootrom_start[], __os_size__[];
#endif
// noinline: this holds three PM3_CMD_DATA_SIZE sized buffers. Inlined into AppMain they
// would sit in its frame for the whole main loop, not just while CMD_VERSION is handled
static void __attribute__((noinline)) SendVersion(void) {
    char temp[PM3_CMD_DATA_SIZE - 12]; /* Limited data payload in USB packets */
    char VersionString[PM3_CMD_DATA_SIZE - 12] = { '\0' };

    /* Try to find the bootrom version information. Expect to find a pointer at
     * symbol _bootphase1_version_pointer, perform slight sanity checks on the
     * pointer, then use it.
     */
    // dummy casting to avoid "dereferencing type-punned pointer breaking strict-aliasing rules" errors
    uint32_t bootrom_version_ptr = (uint32_t)_bootphase1_version_pointer;
    char *bootrom_version = *(char **)(bootrom_version_ptr);

    strncat(VersionString, " [ "_YELLOW_("ARM")" ]\n", sizeof(VersionString) - strlen(VersionString) - 1);

    if ((uint32_t)bootrom_version < (uint32_t)_flash_start || (uint32_t)bootrom_version >= (uint32_t)_flash_end) {
        strcat(VersionString, "bootrom version information appears invalid\n");
    } else {
        FormatVersionInformation(temp, sizeof(temp), "  Bootrom.... ", bootrom_version);
        strncat(VersionString, temp, sizeof(VersionString) - strlen(VersionString) - 1);
        strncat(VersionString, "\n", sizeof(VersionString) - strlen(VersionString) - 1);
    }

    FormatVersionInformation(temp, sizeof(temp), "  OS......... ", &g_version_information);
    strncat(VersionString, temp, sizeof(VersionString) - strlen(VersionString) - 1);
    strncat(VersionString, "\n", sizeof(VersionString) - strlen(VersionString) - 1);

#if defined(__clang__)
    strncat(VersionString, "  Compiler... Clang/LLVM "__VERSION__"\n", sizeof(VersionString) - strlen(VersionString) - 1);
#elif defined(__GNUC__) || defined(__GNUG__)
    strncat(VersionString, "  Compiler... GCC "__VERSION__"\n", sizeof(VersionString) - strlen(VersionString) - 1);
#endif

#ifndef PM5
    // PM5's FPGA (Gowin) bitstream is loaded at runtime via `hw fpga config` and is
    // not compiled into the firmware, so there is no meaningful built-in FPGA
    // version to report here. g_fpga_version_information[] describes the Xilinx
    // bitstream that PM5 does not run, so omit the section entirely on PM5.
    strncat(VersionString, "\n [ "_YELLOW_("FPGA")" ] \n ", sizeof(VersionString) - strlen(VersionString) - 1);

    for (int i = 0; i < g_fpga_bitstream_num; i++) {
        strncat(VersionString, g_fpga_version_information[i].versionString, sizeof(VersionString) - strlen(VersionString) - 1);
        if (i < g_fpga_bitstream_num - 1) {
            strncat(VersionString, "\n ", sizeof(VersionString) - strlen(VersionString) - 1);
        }
    }
#endif
#ifdef WITH_COMPRESSION
    // Send Chip ID and used flash memory
    uint32_t text_and_rodata_section_size = (uint32_t)__data_src_start__ - (uint32_t)_flash_start;
    uint32_t compressed_data_section_size = g_common_area.arg1;
#endif

    struct p {
        uint32_t id;
        uint32_t section_size;
        uint32_t versionstr_len;
        char versionstr[PM3_CMD_DATA_SIZE - 12];
    } PACKED;

    struct p payload;

    // Set a CHIP ID(not unique id)
    payload.id = GetChipId();

#ifndef WITH_COMPRESSION
    payload.section_size = (uint32_t)_bootrom_end - (uint32_t)_bootrom_start + (uint32_t)__os_size__;
#else
    payload.section_size = text_and_rodata_section_size + compressed_data_section_size;
#endif
    payload.versionstr_len = strlen(VersionString) + 1;
    memcpy(payload.versionstr, VersionString, payload.versionstr_len);

    uint32_t reply_len = 12 + payload.versionstr_len;

    // Append the total on-chip flash size (bytes) AFTER the version string. This is
    // backward compatible: older clients stop at versionstr and ignore the trailing
    // bytes, and this stays valid when talking to older firmware that omits it. It
    // lets the client report memory usage on MCUs whose size can't be derived from
    // the chip id (e.g. AT32). Keep the header layout unchanged (do not break the
    // CMD_VERSION protocol).
    if (reply_len + sizeof(uint32_t) <= sizeof(payload)) {
        uint32_t flash_size = GetChipFlashSize();
        memcpy(payload.versionstr + payload.versionstr_len, &flash_size, sizeof(flash_size));
        reply_len += sizeof(flash_size);
    }

    reply_ng(CMD_VERSION, PM3_SUCCESS, (uint8_t *)&payload, reply_len);
}

#ifdef CHIP_AT91SAM7S // Only AT91SAM7S chip series need calibration.

static void TimingIntervalAcquisition(void) {
    // trigger new acquisition by turning main oscillator off and on
    mck_from_pll_to_slck();
    mck_from_slck_to_pll();
    // wait for MCFR and recompute RTMR scaler
    StartTickCount();
}

#endif

static void print_debug_level(void) {
    char dbglvlstr[20] = {0};
    switch (g_dbglevel) {
        case DBG_NONE:
            sprintf(dbglvlstr, "off");
            break;
        case DBG_ERROR:
            sprintf(dbglvlstr, "error");
            break;
        case DBG_INFO:
            sprintf(dbglvlstr, "info");
            break;
        case DBG_DEBUG:
            sprintf(dbglvlstr, "debug");
            break;
        case DBG_EXTENDED:
            sprintf(dbglvlstr, "extended");
            break;
    }
    Dbprintf("  Debug log level..... %d ( " _YELLOW_("%s")" )", g_dbglevel, dbglvlstr);
}

// measure the Connection Speed by sending SpeedTestBufferSize bytes to client and measuring the elapsed time.
// Note: this mimics GetFromBigbuf(), i.e. we have the overhead of the PacketCommandNG structure included.
static void printConnSpeed(uint32_t wait) {
    DbpString(_CYAN_("Transfer Speed"));
    Dbprintf("  Sending packets to client...");

    uint8_t *test_data = BigBuf_get_addr();
    uint32_t start_time = GetTickCount();
    uint32_t delta_time = 0;
    uint32_t bytes_transferred = 0;
    uint32_t frames_sent = 0;

    LED_B_ON();

    while (delta_time < wait) {
        uint16_t st_len = reply_ng_max_data_size();
        reply_ng(CMD_DOWNLOADED_BIGBUF, PM3_SUCCESS, test_data, st_len);
        bytes_transferred += st_len;
        frames_sent++;
        delta_time = GetTickCountDelta(start_time);
    }
    LED_B_OFF();

    // What actually goes on the wire per reply: the payload plus NG framing. On USB
    // that is ceil(wire_len / 64) bulk packets, and the packet rate is what the link
    // caps - so frames/s and this length are what explain a bytes/s result, not the
    // byte count on its own.
    uint32_t wire_len = sizeof(PacketResponseNGPreamble) + PM3_CMD_DATA_SIZE + sizeof(PacketResponseNGPostamble);

    Dbprintf("  Time elapsed................... %dms", delta_time);
    Dbprintf("  Bytes transferred.............. %d", bytes_transferred);
    Dbprintf("  Frames sent.................... %d ( %d bytes on the wire each )", frames_sent, wire_len);
    if (delta_time) {
        Dbprintf("  Transfer Speed PM3 -> Client... " _YELLOW_("%llu") " bytes/s", 1000 * (uint64_t)bytes_transferred / delta_time);
        Dbprintf("  Frame rate..................... " _YELLOW_("%llu") " frames/s", 1000 * (uint64_t)frames_sent / delta_time);
    }
}

/**
  * Prints runtime information about the PM3.
**/
static void SendStatus(uint32_t wait) {
    BigBuf_print_status();
    Fpga_print_status();
#ifdef WITH_FLASH
    Flashmem_print_status();
#endif
#ifdef WITH_SMARTCARD
    I2C_print_status();
#endif
#ifdef WITH_LF
    printLFConfig();      // LF Sampling config
    printT55xxConfig(); // LF T55XX Config
#endif
#ifdef WITH_ISO14443a
    printHf14aConfig();   // HF 14a config
#endif
#ifdef WITH_ISO14443b
    printHf14bConfig();   // HF 14b config
#endif
#if defined(PM5) && defined(WITH_BWM_STATUS)
    bwm_print_battery_status();
#endif
#ifdef WITH_BWM_FORWARD
    Dbprintf("  BWM link baud....... " _YELLOW_("%u") " bps", bwm_uart_get_baud());
    {
        // Read the ESP firmware version so hw status shows what the BWM runs
        // (and lets you confirm an OTA took: the string flips after a reflash).
        uint8_t bwm_ver[64] = {0};
        uint16_t bwm_ver_len = sizeof(bwm_ver) - 1;
        if (bwm_esp_get_version(bwm_ver, &bwm_ver_len) == PM3_SUCCESS) {
            bwm_ver[bwm_ver_len] = 0x00;
            Dbprintf("  BWM fw version...... " _YELLOW_("%s"), bwm_ver);
        } else {
            Dbprintf("  BWM fw version...... " _YELLOW_("%s"), "unknown");
        }
    }
#endif
    printConnSpeed(wait);
    DbpString(_CYAN_("Various"));

    print_stack_usage();
    print_debug_level();

    tosend_t *ts = get_tosend();
    Dbprintf("  ToSendMax........... %d", ts->max);
    Dbprintf("  ToSend BUFFERSIZE... %d", TOSEND_BUFFER_SIZE);

#ifdef CHIP_AT91SAM7S

    while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
    uint16_t mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;       // Get # main clocks within 16 slow clocks
    Dbprintf("  Slow clock.......... %d Hz", (16 * MAINCK) / mainf);
    uint32_t delta_time = 0;
    uint32_t start_time = GetTickCount();
#define SLCK_CHECK_MS 50
    SpinDelay(SLCK_CHECK_MS);
    delta_time = GetTickCountDelta(start_time);
    if ((delta_time < SLCK_CHECK_MS - 1) || (delta_time > SLCK_CHECK_MS + 1)) {
        // error > 2% with SLCK_CHECK_MS=50
        Dbprintf(_RED_("  Slow Clock speed change detected, run `hw tia`"));
        Dbprintf(_YELLOW_("  Slow Clock actual speed seems closer to %d kHz"),
                 (16 * MAINCK / 1000) / mainf * delta_time / SLCK_CHECK_MS);
    }

#endif

    DbpString(_CYAN_("Installed StandAlone Mode"));
    ModInfo();

#ifdef WITH_FLASH
    DbpString(_CYAN_("Flash memory dictionary loaded"));
    uint32_t num = 0;

    if (exists_in_spiffs(MF_KEYS_FILE)) {
        num = size_in_spiffs(MF_KEYS_FILE) / MF_KEY_LENGTH;
    } else {
        num = 0;
    }

    if (num > 0) {
        Dbprintf("  Mifare... "_YELLOW_("%u")" keys - "_GREEN_("%s"), num, MF_KEYS_FILE);
    } else {
        Dbprintf("  Mifare... "_RED_("%u")" keys - "_RED_("%s"), num, MF_KEYS_FILE);
    }

    if (exists_in_spiffs(T55XX_KEYS_FILE)) {
        num = size_in_spiffs(T55XX_KEYS_FILE) / T55XX_KEY_LENGTH;
    } else {
        num = 0;
    }

    if (num > 0) {
        Dbprintf("  T55xx.... "_YELLOW_("%u")" keys - "_GREEN_("%s"), num, T55XX_KEYS_FILE);
    } else {
        Dbprintf("  T55xx.... "_RED_("%u")" keys - "_RED_("%s"), num, T55XX_KEYS_FILE);
    }

    if (exists_in_spiffs(ICLASS_KEYS_FILE)) {
        num = size_in_spiffs(ICLASS_KEYS_FILE) / ICLASS_KEY_LENGTH;
    } else {
        num = 0;
    }

    if (num > 0) {
        Dbprintf("  iClass... "_YELLOW_("%u")" keys - "_GREEN_("%s"), num, ICLASS_KEYS_FILE);
    } else {
        Dbprintf("  iClass... "_RED_("%u")" keys - "_RED_("%s"), num, ICLASS_KEYS_FILE);
    }

    if (exists_in_spiffs(MFULC_KEYS_FILE)) {
        num = size_in_spiffs(MFULC_KEYS_FILE) / MFULC_KEY_LENGTH;
    } else {
        num = 0;
    }

    if (num > 0) {
        Dbprintf("  UL-C..... "_YELLOW_("%u")" keys - "_GREEN_("%s"), num, MFULC_KEYS_FILE);
    } else {
        Dbprintf("  UL-C..... "_RED_("%u")" keys - "_RED_("%s"), num, MFULC_KEYS_FILE);
    }

    if (exists_in_spiffs(MFULAES_KEYS_FILE)) {
        num = size_in_spiffs(MFULAES_KEYS_FILE) / MFULAES_KEY_LENGTH;
    } else {
        num = 0;
    }

    if (num > 0) {
        Dbprintf("  UL-AES... "_YELLOW_("%u")" keys - "_GREEN_("%s"), num, MFULAES_KEYS_FILE);
    } else {
        Dbprintf("  UL-AES... "_RED_("%u")" keys - "_RED_("%s"), num, MFULAES_KEYS_FILE);
    }


#endif
    DbpString("");
    reply_ng(CMD_STATUS, PM3_SUCCESS, NULL, 0);
}

static void SendCapabilities(void) {
    capabilities_t capabilities = {0};
    capabilities.version = CAPABILITIES_VERSION;
    capabilities.max_cmd_data_size = reply_ng_max_data_size();
    capabilities.via_fpc = g_reply_via_fpc;
    capabilities.via_usb = g_reply_via_usb;
    capabilities.bigbuf_size = BigBuf_get_size();
    capabilities.baudrate = 0; // no real baudrate for USB-CDC
#ifdef WITH_FPC_USART
    if (g_reply_via_fpc)
        capabilities.baudrate = g_usart_baudrate;
#endif
#ifdef WITH_BWM_FORWARD
    // Report the negotiated link baud so the client's timeout math
    // (communication_delay: 12000000 / uart_speed) matches reality and never
    // divides by zero.
    if (g_reply_via_fpc)
        capabilities.baudrate = bwm_uart_get_baud();
#endif

#ifdef RDV4
    capabilities.is_rdv4 = true;
#else
    capabilities.is_rdv4 = false;
#endif

#ifdef PM5
    capabilities.is_pm5 = true;
    capabilities.is_pm5_std_ant = true;
    capabilities.hw_available_fpga_flash = true;
    capabilities.hw_available_i2c_eeprom = true;
#else
    capabilities.is_pm5 = false;
    capabilities.is_pm5_std_ant = false;
    capabilities.hw_available_fpga_flash = false;
    capabilities.hw_available_i2c_eeprom = false;
#endif

#ifdef WITH_FLASH
    capabilities.compiled_with_flash = true;
    capabilities.hw_available_flash = FlashInit();
#else
    capabilities.compiled_with_flash = false;
    capabilities.hw_available_flash = false;
#endif
#ifdef WITH_SMARTCARD
    capabilities.compiled_with_smartcard = true;
    uint8_t maj, min;

    // The module may still be finishing a card exchange from a previous
    // session when this runs, and a single missed answer used to report the
    // hardware as absent for the whole of the next one - every smartcard
    // command then said it was not available in this mode.
    capabilities.hw_available_smartcard = false;
    for (uint8_t i = 0; i < 3; i++) {
        if (I2C_get_version(&maj, &min) == PM3_SUCCESS) {
            capabilities.hw_available_smartcard = true;
            break;
        }
        SpinDelay(50);
    }
#else
    capabilities.compiled_with_smartcard = false;
    capabilities.hw_available_smartcard = false;
#endif
#ifdef WITH_FPC_USART
    capabilities.compiled_with_fpc_usart = true;
#else
    capabilities.compiled_with_fpc_usart = false;
#endif
#ifdef WITH_FPC_USART_DEV
    capabilities.compiled_with_fpc_usart_dev = true;
#else
    capabilities.compiled_with_fpc_usart_dev = false;
#endif
#ifdef WITH_FPC_USART_HOST
    capabilities.compiled_with_fpc_usart_host = true;
#else
    capabilities.compiled_with_fpc_usart_host = false;
#endif
#ifdef WITH_LF
    capabilities.compiled_with_lf = true;
#else
    capabilities.compiled_with_lf = false;
#endif
#ifdef WITH_HITAG
    capabilities.compiled_with_hitag = true;
#else
    capabilities.compiled_with_hitag = false;
#endif
#ifdef WITH_EM4x50
    capabilities.compiled_with_em4x50 = true;
#else
    capabilities.compiled_with_em4x50 = false;
#endif
#ifdef WITH_EM4x70
    capabilities.compiled_with_em4x70 = true;
#else
    capabilities.compiled_with_em4x70 = false;
#endif

#ifdef WITH_HFSNIFF
    capabilities.compiled_with_hfsniff = true;
#else
    capabilities.compiled_with_hfsniff = false;
#endif
#ifdef WITH_HFPLOT
    capabilities.compiled_with_hfplot = true;
#else
    capabilities.compiled_with_hfplot = false;
#endif
#ifdef WITH_ISO14443a
    capabilities.compiled_with_iso14443a = true;
#else
    capabilities.compiled_with_iso14443a = false;
#endif
#ifdef WITH_ISO14443b
    capabilities.compiled_with_iso14443b = true;
#else
    capabilities.compiled_with_iso14443b = false;
#endif
#ifdef WITH_ISO15693
    capabilities.compiled_with_iso15693 = true;
#else
    capabilities.compiled_with_iso15693 = false;
#endif
#ifdef WITH_FELICA
    capabilities.compiled_with_felica = true;
#else
    capabilities.compiled_with_felica = false;
#endif
#ifdef WITH_LEGICRF
    capabilities.compiled_with_legicrf = true;
#else
    capabilities.compiled_with_legicrf = false;
#endif
#ifdef WITH_ICLASS
    capabilities.compiled_with_iclass = true;
#else
    capabilities.compiled_with_iclass = false;
#endif
#ifdef WITH_SEOS
    capabilities.compiled_with_seos = true;
#else
    capabilities.compiled_with_seos = false;
#endif
#ifdef WITH_NFCBARCODE
    capabilities.compiled_with_nfcbarcode = true;
#else
    capabilities.compiled_with_nfcbarcode = false;
#endif
#ifdef WITH_LCD
    capabilities.compiled_with_lcd = true;
#else
    capabilities.compiled_with_lcd = false;
#endif

#ifdef WITH_ZX8211
    capabilities.compiled_with_zx8211 = true;
#else
    capabilities.compiled_with_zx8211 = false;
#endif

    reply_ng(CMD_CAPABILITIES, PM3_SUCCESS, (uint8_t *)&capabilities, sizeof(capabilities));
}

// Show some leds in a pattern to identify StandAlone mod is running
void StandAloneMode(void) {
    DbpString("");
    DbpString("Stand-alone mode, no computer necessary");
    SpinDown(50);
    SpinDelay(50);
    SpinUp(50);
    SpinDelay(50);
    SpinDown(50);
}

/*
OBJECTIVE
Listen and detect an external reader. Determine the best location
for the antenna.

INSTRUCTIONS:
Inside the ListenReaderField() function, there is two mode.
By default, when you call the function, you will enter mode 1.
If you press the PM3 button one time, you will enter mode 2.
If you press the PM3 button a second time, you will exit the function.

DESCRIPTION OF MODE 1:
This mode just listens for an external reader field and lights up green
for HF and/or red for LF. This is the original mode of the detectreader
function.

DESCRIPTION OF MODE 2:
This mode will visually represent, using the LEDs, the actual strength of the
current compared to the maximum current detected. Basically, once you know
what kind of external reader is present, it will help you spot the best location to place
your antenna. You will probably not get some good results if there is a LF and a HF reader
at the same place! :-)
*/
#define LIGHT_LEVELS 20

void ListenReaderField(uint8_t limit) {
#define LF_HF_BOTH 0
#define LF_ONLY 1
#define HF_ONLY 2
#define REPORT_CHANGE 1000    // report new values only if they have changed at least by REPORT_CHANGE mV

    uint16_t lf_av = 0, lf_av_new, lf_baseline = 0, lf_max = 0;
    uint16_t hf_av = 0, hf_av_new,  hf_baseline = 0, hf_max = 0;
    uint16_t mode = 1, display_val, display_max;

    // switch off FPGA - we don't want to measure our own signal
    // 20180315 - iceman,  why load this before and then turn off?
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    LEDsoff();

    if (limit == LF_ONLY || limit == LF_HF_BOTH) {
        lf_av = lf_max = AdcRssiAvgToMilliVolt(ADC_RSSI_CH_LF);
        Dbprintf("LF 125/134kHz Baseline: %dmV", lf_av);
        lf_baseline = lf_av;
    }

    if (limit == HF_ONLY || limit == LF_HF_BOTH) {

        // iceman,  useless,  since we are measuring readerfield,  not our field.  My tests shows a max of 20v from a reader.
        hf_av = hf_max = AdcRssiAvgToMilliVolt(ADC_RSSI_CH_HF);;
        Dbprintf("HF 13.56MHz Baseline: %dmV", hf_av);
        hf_baseline = hf_av;
    }

    for (;;) {

        // Switch modes with button or Enter key
        bool modeSwitched = BUTTON_PRESS();
        if (modeSwitched == false && data_available()) {
            // flush the buffer
            PacketCommandNG rx;
            receive_ng(&rx);
            modeSwitched = true;
        }
        if (modeSwitched) {
            SpinDelay(500);
            switch (mode) {
                case 1:
                    mode = 2;
                    DbpString("Signal Strength Mode");
                    break;
                case 2:
                default:
                    DbpString("Stopped");
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    LEDsoff();
                    return;
            }
        }
        WDT_HIT();

        if (limit == LF_ONLY || limit == LF_HF_BOTH) {
            if (mode == 1) {
                if (ABS(lf_av - lf_baseline) > REPORT_CHANGE)
                    LED_D_ON();
                else
                    LED_D_OFF();
            }

            lf_av_new = AdcRssiAvgToMilliVolt(ADC_RSSI_CH_LF);
            // see if there's a significant change
            if (ABS(lf_av - lf_av_new) > REPORT_CHANGE) {
                Dbprintf("LF 125/134kHz Field Change: %5dmV", lf_av_new);
                lf_av = lf_av_new;
                if (lf_av > lf_max)
                    lf_max = lf_av;
            }
        }

        if (limit == HF_ONLY || limit == LF_HF_BOTH) {
            if (mode == 1) {
                if (ABS(hf_av - hf_baseline) > REPORT_CHANGE)
                    LED_B_ON();
                else
                    LED_B_OFF();
            }

            hf_av_new = AdcRssiAvgToMilliVolt(ADC_RSSI_CH_HF);
            // see if there's a significant change
            if (ABS(hf_av - hf_av_new) > REPORT_CHANGE) {
                Dbprintf("HF 13.56MHz Field Change: %5dmV", hf_av_new);
                hf_av = hf_av_new;
                if (hf_av > hf_max)
                    hf_max = hf_av;
            }
        }

        if (mode == 2) {
            if (limit == LF_ONLY) {
                display_val = lf_av;
                display_max = lf_max;
            } else if (limit == HF_ONLY) {
                display_val = hf_av;
                display_max = hf_max;
            } else { /* Pick one at random */
                if ((hf_max - hf_baseline) > (lf_max - lf_baseline)) {
                    display_val = hf_av;
                    display_max = hf_max;
                } else {
                    display_val = lf_av;
                    display_max = lf_max;
                }
            }

            display_val = display_val * (4 * LIGHT_LEVELS) / MAX(1, display_max);
            uint32_t duty_a = MIN(MAX(display_val, 0 * LIGHT_LEVELS), 1 * LIGHT_LEVELS) - 0 * LIGHT_LEVELS;
            uint32_t duty_b = MIN(MAX(display_val, 1 * LIGHT_LEVELS), 2 * LIGHT_LEVELS) - 1 * LIGHT_LEVELS;
            uint32_t duty_c = MIN(MAX(display_val, 2 * LIGHT_LEVELS), 3 * LIGHT_LEVELS) - 2 * LIGHT_LEVELS;
            uint32_t duty_d = MIN(MAX(display_val, 3 * LIGHT_LEVELS), 4 * LIGHT_LEVELS) - 3 * LIGHT_LEVELS;

            // LED A
            if (duty_a == 0) {
                LED_A_OFF();
            } else if (duty_a == LIGHT_LEVELS) {
                LED_A_ON();
            } else {
                LED_A_ON();
                SpinDelay(duty_a);
                LED_A_OFF();
                SpinDelay(LIGHT_LEVELS - duty_a);
            }

            // LED B
            if (duty_b == 0) {
                LED_B_OFF();
            } else if (duty_b == LIGHT_LEVELS) {
                LED_B_ON();
            } else {
                LED_B_ON();
                SpinDelay(duty_b);
                LED_B_OFF();
                SpinDelay(LIGHT_LEVELS - duty_b);
            }

            // LED C
            if (duty_c == 0) {
                LED_C_OFF();
            } else if (duty_c == LIGHT_LEVELS) {
                LED_C_ON();
            } else {
                LED_C_ON();
                SpinDelay(duty_c);
                LED_C_OFF();
                SpinDelay(LIGHT_LEVELS - duty_c);
            }

            // LED D
            if (duty_d == 0) {
                LED_D_OFF();
            } else if (duty_d == LIGHT_LEVELS) {
                LED_D_ON();
            } else {
                LED_D_ON();
                SpinDelay(duty_d);
                LED_D_OFF();
                SpinDelay(LIGHT_LEVELS - duty_d);
            }
        }
    }
}

#ifdef PM5

// TODO DXL: 一部分QC逻辑可以放在PM5设备端实现，这个函数后面记得复用代码，并且不要放在 appmain.c 中（考虑移动到平台专属的模块）
// failed_item == 0: BLUE LED in Antenna
// failed_item == 1: RGB in mainboard
// failed_item == 2: LEDs * 4 or Buzzer or Button in mainboard
// timeout_ms == 0: run until button press or new usb data
static bool QCTestPM5(uint8_t *failed_item, uint32_t timeout_ms) {
    // 天线蓝灯、主板RGB、主板四颗LED、蜂鸣器、按钮
    StartTicks();
    I2C_init(true);

    uint8_t addr_ant = 0x51; // TODO DXL define move to header?
    uint8_t addr_rgb = 0x48;
    uint8_t data_u8 = 0;
    bool isok = false;
    bool result = false;
    bool data_u8_valid = false;

    // 读取天线当前MAP配置，如果读取不到，则认为天线的控制芯片可能有问题
    isok = I2C_BufferReadRaw(&data_u8, 1, 0x02, addr_ant << 1);
    if (!isok) {
        *failed_item = 0;
        result = false;
        goto out;
    }
    data_u8_valid = true;
    // 重新写入天线的MAP配置，去开灯
    data_u8 |= 0x06; // 0000 0110 // 125 134 250 375 500 HFLED LFLED Q
    isok = I2C_BufferWrite(&data_u8, 1, 0x02, addr_ant << 1);

    // 开启RGB灯自动闪烁
    uint8_t buf_rgb[3] = {0, 0, 128};
    uint8_t buf_flash_time[] = {50, 50}; // 1s on, 500ms off.
    isok = I2C_WriteByte(0, 0x02, addr_rgb << 1); // 写索引寄存器，设置后续操作的RGB索引
    if (!isok) {
        *failed_item = 1;
        result = false;
        goto out;
    }
    isok = I2C_WriteByte(1, 0x01, addr_rgb << 1); // 写数量寄存器，设置硬件挂1个灯,很重要！！！，不然无法闪灯
    if (!isok) {
        *failed_item = 1;
        result = false;
        goto out;
    }
    isok = I2C_BufferWrite(buf_rgb, sizeof(buf_rgb), 0x03, addr_rgb << 1); // 写数据寄存器，每三个字节就是对应的RGB888值
    if (!isok) {
        *failed_item = 1;
        result = false;
        goto out;
    }
    isok = I2C_WriteByte(1, 0x06, addr_rgb << 1); // 写闪灯使能寄存器，使能 0 号灯珠的可控闪烁
    if (!isok) {
        *failed_item = 1;
        result = false;
        goto out;
    }
    isok = I2C_BufferWrite(buf_flash_time, sizeof(buf_flash_time), 0x07, addr_rgb << 1); // 写闪灯使能寄存器，使能 0 号灯珠的可控闪烁
    if (!isok) {
        *failed_item = 1;
        result = false;
        goto out;
    }

    // 在循环中测试LED、蜂鸣器、按钮
    // 蜂鸣器 (PB13 使能, PC9 = TMR8_CH4 调制) 由通用 buzzer 模块驱动
    BuzzerSetup();

    LEDsoff(); // 在开始测试之前先关闭所有LED

    *failed_item = 2;
    // 在开始测试之前，如果按钮是按下的，则认为失败，有可能按钮不良卡住了
    if (BUTTON_PRESS()) {
        result = false;
        goto out;
    }

    uint32_t start_time = GetTickCount();

    while (1) {
        if (BUTTON_PRESS()) {
            result = true;
            goto out;
        }
        if (data_available() || (timeout_ms > 0 && (GetTickCount() - start_time) >= timeout_ms)) {
            result = false;
            goto out;
        }

        LED_A_ON();
        BuzzerTone(999, 500, 20);
        SpinDelay(200);
        LED_A_OFF();

        if (BUTTON_PRESS()) {
            result = true;
            goto out;
        }
        if (data_available() || (timeout_ms > 0 && (GetTickCount() - start_time) >= timeout_ms)) {
            result = false;
            goto out;
        }

        LED_B_ON();
        BuzzerTone(1100, 550, 20);
        SpinDelay(200);
        LED_B_OFF();

        if (BUTTON_PRESS()) {
            result = true;
            goto out;
        }
        if (data_available() || (timeout_ms > 0 && (GetTickCount() - start_time) >= timeout_ms)) {
            result = false;
            goto out;
        }

        LED_C_ON();
        BuzzerTone(1200, 600, 20);
        SpinDelay(200);
        LED_C_OFF();

        if (BUTTON_PRESS()) {
            result = true;
            goto out;
        }
        if (data_available() || (timeout_ms > 0 && (GetTickCount() - start_time) >= timeout_ms)) {
            result = false;
            goto out;
        }

        LED_D_ON();
        BuzzerTone(1300, 650, 20);
        SpinDelay(200);
        LED_D_OFF();
    }

out:
    // Turn off the test LEDs (antenna + RGB flash) before returning
    LEDsoff();
    RgbLedSet(0, 0, 0);
    I2C_WriteByte(0, 0x06, addr_rgb << 1);
    if (data_u8_valid) {
        data_u8 &= ~0x06;
        I2C_BufferWrite(&data_u8, 1, 0x02, addr_ant << 1);
    }
    return result;
}

static int8_t QCTestPM5IO(uint16_t index, uint8_t status) {
    // !!! No one is allowed to modify the definition and order of this list except DXL.
    // Otherwise, the PM5 factory tester will fail to check.
    struct qc_io_map {
        crm_periph_clock_type gpio_clk;
        gpio_type *gpio_group;
        uint16_t gpio_pin;
    } const qc_io_map[] = {
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_14}, // SIGIN1-5x2P-SWD-CLK
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_13}, // SIGIN2-5x2P-SWD-DIO
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_3}, // SIGIN3-5x2P-UART_RX
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_2}, // SIGIN4-5x2P-UART_TX
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_7}, // SIGIN5-CEP-USB_RXP(MOSI)
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_6}, // SIGIN6-CEP-USB_RXN(MISO)
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_9}, // SIGIN7-CEP-USB_SBU(UART-1-line)
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_11}, // SIGIN8-CEP-USB_DN
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_4}, // SIGIN9-CEP-USB_TXP(CSN)
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_12}, // SIGIN10-CEP-USB_DP
        {.gpio_clk = CRM_GPIOA_PERIPH_CLOCK, .gpio_group = GPIOA, .gpio_pin = GPIO_PINS_5}, // SIGIN11-CEP-USB_TXN(CLK)
    };
    if (index >= ARRAYLEN(qc_io_map)) {
        return PM3_EINVARG;
    }
    // For RXP/RXN/TXP/TXN
    gpio_inter_usb_spi_role_setup();
    Gpio_Inter_USB_SPI_Role_High();
    // Enable the clock for the GPIO port and configure the pin as output
    crm_periph_clock_enable(qc_io_map[index].gpio_clk, TRUE);
    // Configure the GPIO pin as output or input based on the status parameter
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_pins = qc_io_map[index].gpio_pin;
    gpio_init_struct.gpio_mode = GPIO_MODE_OUTPUT;
    // Set the GPIO pin state or RESET to default based on the status parameter( -> Preset <- )
    if (status == 0) {
        gpio_bits_reset(qc_io_map[index].gpio_group, qc_io_map[index].gpio_pin);
    } else if (status == 1) {
        gpio_bits_set(qc_io_map[index].gpio_group, qc_io_map[index].gpio_pin);
    } else {
        // Reset to Default state or MUX
        if (index == 0 || index == 1) {
            // SIGIN1-SWD-CLK or SIGIN2-SWD-DIO
            gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
            gpio_init_struct.gpio_pull = index == 0 ?  GPIO_PULL_DOWN : GPIO_PULL_UP;
            gpio_pin_mux_config(qc_io_map[index].gpio_group, qc_io_map[index].gpio_pin, GPIO_MUX_0);
        } else {
            gpio_init_struct.gpio_mode = GPIO_MODE_INPUT;
        }
    }
    gpio_init(qc_io_map[index].gpio_group, &gpio_init_struct);
    return PM3_SUCCESS;
}

#endif

// static, not on the stack: this is 512 bytes and PacketReceived is already deep
// in the call chain on a device with a small stack
static uint8_t g_dl_chunkbuf[sizeof(download_chunk_t) + DOWNLOAD_CHUNK_MAX];

static int reply_download_chunk(uint16_t cmd, uint32_t offset, const uint8_t *data, uint16_t len) {
    uint8_t *buf = g_dl_chunkbuf;
    download_chunk_t *chunk = (download_chunk_t *)buf;
    chunk->offset = offset;
    if (len && data) {
        memcpy(chunk->data, data, len);
    }
    return reply_ng(cmd, PM3_SUCCESS, buf, sizeof(download_chunk_t) + len);
}

static void reply_download_done(uint16_t cmd, uint32_t bytes_sent, uint32_t extra) {
    download_done_t done = {
        .bytes_sent = bytes_sent,
        .extra = extra,
    };
    reply_ng(cmd, PM3_SUCCESS, (uint8_t *)&done, sizeof(done));
}

static void PacketReceived(PacketCommandNG *packet) {
    /*
    if (packet->ng) {
        Dbprintf("received NG frame with %d bytes payload, with command: 0x%04x", packet->length, cmd);
    } else {
        Dbprintf("received OLD frame of %d bytes, with command: 0x%04x and args: %d %d %d", packet->length, packet->cmd, packet->oldarg[0], packet->oldarg[1], packet->oldarg[2]);
    }
    */

    switch (packet->cmd) {
        case CMD_BREAK_LOOP:
            break;
        case CMD_QUIT_SESSION: {
            g_reply_via_fpc = false;
            g_reply_via_usb = false;
            break;
        }
        case CMD_SET_FPGAMODE: {
            uint8_t mode = packet->data.asBytes[0];
            if (mode >= FPGA_BITSTREAM_MIN && mode <= FPGA_BITSTREAM_MAX) {
                FpgaDownloadAndGo(mode);
                reply_ng(CMD_SET_FPGAMODE, PM3_SUCCESS, NULL, 0);
            }
            reply_ng(CMD_SET_FPGAMODE, PM3_EINVARG, NULL, 0);
            break;
        }
        // emulator
        case CMD_SET_DBGMODE: {
            g_dbglevel = packet->data.asBytes[0];
            if (packet->length == 1 || packet->data.asBytes[1] != 0)
                print_debug_level();
            reply_ng(CMD_SET_DBGMODE, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_GET_DBGMODE: {
            reply_ng(CMD_GET_DBGMODE, PM3_SUCCESS, (uint8_t *)&g_dbglevel, 1);
            break;
        }
        case CMD_SET_TEAROFF: {
            tearoff_params_t *payload = (tearoff_params_t *)packet->data.asBytes;
            if (payload->on && payload->off) {
                reply_ng(CMD_SET_TEAROFF, PM3_EINVARG, NULL, 0);
            }

            if (payload->on) {
                g_tearoff_enabled = true;
            }

            if (payload->off) {
                g_tearoff_enabled = false;
            }

            if (payload->delay_us > 0) {
                g_tearoff_delay_us = payload->delay_us;
            }

            if (payload->skip > -1) {
                g_tearoff_skip = payload->skip;
            }
            reply_ng(CMD_SET_TEAROFF, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_SET_HF_FIELD_TIMEOUT: {
            if (packet->length != sizeof(uint32_t)) {
                reply_ng(CMD_SET_HF_FIELD_TIMEOUT, PM3_EINVARG, NULL, 0);
                break;
            }
            uint32_t timeout_ms = 0;
            memcpy(&timeout_ms, packet->data.asBytes, sizeof(timeout_ms));
            g_hf_field_activity_timeout_ms = timeout_ms;
            reply_ng(CMD_SET_HF_FIELD_TIMEOUT, PM3_SUCCESS, NULL, 0);
            break;
        }
        // always available
        case CMD_HF_DROPFIELD: {
            hf_field_off();
            break;
        }
#ifdef WITH_LF
        case CMD_LF_T55XX_SET_CONFIG: {
            if (packet->length != sizeof(t55xx_setconfig_t)) {
                reply_ng(CMD_LF_T55XX_SET_CONFIG, PM3_EINVARG, NULL, 0);
                break;
            }
            const t55xx_setconfig_t *payload = (const t55xx_setconfig_t *)packet->data.asBytes;
            setT55xxConfig(payload->persist, &payload->conf);
            reply_ng(CMD_LF_T55XX_SET_CONFIG, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_LF_SAMPLING_PRINT_CONFIG: {
            printLFConfig();
            break;
        }
        case CMD_LF_SAMPLING_GET_CONFIG: {
            sample_config *config = getSamplingConfig();
            reply_ng(CMD_LF_SAMPLING_GET_CONFIG, PM3_SUCCESS, (uint8_t *)config, sizeof(sample_config));
            break;
        }
        case CMD_LF_SAMPLING_SET_CONFIG: {
            sample_config c;
            memcpy(&c, packet->data.asBytes, sizeof(sample_config));
            setSamplingConfig(&c);
            break;
        }
        case CMD_LF_ACQ_RAW_ADC: {
            lf_sample_payload_t *payload = (lf_sample_payload_t *)packet->data.asBytes;
            if (payload->realtime) {
                ReadLF_realtime(true, payload->cotag, payload->samples);
            } else {
                uint32_t bits = SampleLF(payload->verbose, payload->samples, true, payload->cotag);
                reply_ng(CMD_LF_ACQ_RAW_ADC, PM3_SUCCESS, (uint8_t *)&bits, sizeof(bits));
            }
            break;
        }
        case CMD_LF_MOD_THEN_ACQ_RAW_ADC: {
            struct p {
                uint32_t delay;
                uint16_t period_0;
                uint16_t period_1;
                uint8_t  symbol_extra[LF_CMDREAD_MAX_EXTRA_SYMBOLS];
                uint16_t period_extra[LF_CMDREAD_MAX_EXTRA_SYMBOLS];
                uint32_t samples : 30;
                bool     keep : 1;
                bool     verbose : 1;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            uint8_t  symbol_extra[LF_CMDREAD_MAX_EXTRA_SYMBOLS];
            uint16_t period_extra[LF_CMDREAD_MAX_EXTRA_SYMBOLS];
            memcpy(symbol_extra, payload->symbol_extra, sizeof(symbol_extra));
            memcpy(period_extra, payload->period_extra, sizeof(period_extra));
            ModThenAcquireRawAdcSamples125k(payload->delay, payload->period_0, payload->period_1, symbol_extra, period_extra, packet->data.asBytes + sizeof(struct p), payload->verbose, payload->keep, payload->samples, true);
            break;
        }
        case CMD_LF_SNIFF_RAW_ADC: {
            lf_sample_payload_t *payload = (lf_sample_payload_t *)packet->data.asBytes;
            if (payload->realtime) {
                ReadLF_realtime(false, false, payload->samples);
            } else {
                uint32_t bits = SniffLF(payload->verbose, payload->samples, true);
                reply_ng(CMD_LF_SNIFF_RAW_ADC, PM3_SUCCESS, (uint8_t *)&bits, sizeof(bits));
            }
            break;
        }
        case CMD_LF_HID_WATCH: {
            uint32_t high, low;
            int res = lf_hid_watch(0, &high, &low, true);
            reply_ng(CMD_LF_HID_WATCH, res, NULL, 0);
            break;
        }
        case CMD_LF_HID_SIMULATE: {
            lf_hidsim_t *payload = (lf_hidsim_t *)packet->data.asBytes;
            CmdHIDsimTAG(payload->hi2, payload->hi, payload->lo, payload->longFMT, 1);
            break;
        }
        case CMD_LF_FSK_SIMULATE: {
            lf_fsksim_t *payload = (lf_fsksim_t *)packet->data.asBytes;
            CmdFSKsimTAG(payload->fchigh, payload->fclow, payload->separator, payload->clock, packet->length - sizeof(lf_fsksim_t), payload->data, true);
            break;
        }
        case CMD_LF_ASK_SIMULATE: {
            lf_asksim_t *payload = (lf_asksim_t *)packet->data.asBytes;
            CmdASKsimTAG(payload->encoding, payload->invert, payload->separator, payload->clock, packet->length - sizeof(lf_asksim_t), payload->data, true);
            break;
        }
        case CMD_LF_PSK_SIMULATE: {
            lf_psksim_t *payload = (lf_psksim_t *)packet->data.asBytes;
            CmdPSKsimTAG(payload->carrier, payload->invert, payload->clock, packet->length - sizeof(lf_psksim_t), payload->data, true);
            break;
        }
        case CMD_LF_NRZ_SIMULATE: {
            lf_nrzsim_t *payload = (lf_nrzsim_t *)packet->data.asBytes;
            CmdNRZsimTAG(payload->invert, payload->separator, payload->clock, packet->length - sizeof(lf_nrzsim_t), payload->data, true);
            break;
        }
        case CMD_LF_HID_CLONE: {
            lf_hidsim_t *payload = (lf_hidsim_t *)packet->data.asBytes;
            CopyHIDtoT55x7(payload->hi2, payload->hi, payload->lo, payload->longFMT, payload->Q5, payload->EM, true);
            break;
        }
        case CMD_LF_IO_WATCH: {
            uint32_t high, low;
            int res = lf_io_watch(0, &high, &low, true);
            reply_ng(CMD_LF_IO_WATCH, res, NULL, 0);
            break;
        }
        case CMD_LF_EM410X_WATCH: {
            uint32_t high;
            uint64_t low;
            int res = lf_em410x_watch(0, &high, &low, true);
            reply_ng(CMD_LF_EM410X_WATCH, res, NULL, 0);
            break;
        }
        case CMD_LF_EM410X_CLONE: {
            struct p {
                bool Q5;
                bool EM;
                bool add_electra;
                uint8_t clock;
                uint32_t high;
                uint32_t low;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            uint8_t card = payload->Q5 ? 0 : (payload->EM ? 2 : 1);
            int res = copy_em410x_to_t55xx(card, payload->clock, payload->high, payload->low, payload->add_electra, true);
            reply_ng(CMD_LF_EM410X_CLONE, res, NULL, 0);
            break;
        }
        case CMD_LF_TI_READ: {
            ReadTItag(true);
            break;
        }
        case CMD_LF_TI_WRITE: {
            struct p {
                uint32_t high;
                uint32_t low;
                uint16_t crc;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            WriteTItag(payload->high, payload->low, packet->crc, true);
            break;
        }
        case CMD_LF_SIMULATE: {
            LED_A_ON();
            struct p {
                uint16_t len;
                uint16_t gap;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            // length, start gap, led control
            SimulateTagLowFrequency(payload->len, payload->gap, true);
            reply_ng(CMD_LF_SIMULATE, PM3_EOPABORTED, NULL, 0);
            LED_A_OFF();
            break;
        }
        case CMD_LF_T55XX_READBL: {
            struct p {
                uint32_t password;
                uint8_t  blockno;
                uint8_t  page;
                bool     pwdmode;
                uint8_t  downlink_mode;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            T55xxReadBlock(payload->page, payload->pwdmode, false, payload->blockno, payload->password, payload->downlink_mode, true);
            break;
        }
        case CMD_LF_T55XX_WRITEBL: {
            // uses NG format
            T55xxWriteBlock(packet->data.asBytes, true);
            break;
        }
        case CMD_LF_T55XX_DANGERRAW: {
            T55xxDangerousRawTest(packet->data.asBytes, true);
            break;
        }
        case CMD_LF_T55XX_WAKEUP: {
            struct p {
                uint32_t password;
                uint8_t flags;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            T55xxWakeUp(payload->password, payload->flags, true);
            break;
        }
        case CMD_LF_T55XX_RESET_READ: {
            T55xxResetRead(packet->data.asBytes[0] & 0xff, true);
            break;
        }
        case CMD_LF_T55XX_CHK_PWDS: {
            T55xx_ChkPwds(packet->data.asBytes[0] & 0xff, true);
            break;
        }
        case CMD_LF_PCF7931_READ: {
            ReadPCF7931(true);
            break;
        }
        case CMD_LF_PCF7931_WRITE: {
            if (packet->length != sizeof(pcf7931_write_t)) {
                reply_ng(CMD_LF_PCF7931_WRITE, PM3_EINVARG, NULL, 0);
                break;
            }
            pcf7931_write_t *payload = (pcf7931_write_t *)packet->data.asBytes;
            WritePCF7931(
                payload->pwd[0], payload->pwd[1], payload->pwd[2], payload->pwd[3],
                payload->pwd[4], payload->pwd[5], payload->pwd[6],
                payload->init_delay,
                payload->offset_width - 128, payload->offset_position - 128,
                payload->address,
                payload->byte,
                payload->data,
                true
            );
            break;
        }
        case CMD_LF_EM4X_LOGIN: {
            struct p {
                uint32_t password;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            EM4xLogin(payload->password, true);
            break;
        }
        case CMD_LF_EM4X_BF: {
            struct p {
                uint32_t start_pwd;
                uint32_t n;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            EM4xBruteforce(payload->start_pwd, payload->n, true);
            break;
        }
        case CMD_LF_EM4X_READWORD: {
            struct p {
                uint32_t password;
                uint8_t address;
                uint8_t usepwd;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            EM4xReadWord(payload->address, payload->password, payload->usepwd, true);
            break;
        }
        case CMD_LF_EM4X_WRITEWORD: {
            struct p {
                uint32_t password;
                uint32_t data;
                uint8_t address;
                uint8_t usepwd;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            EM4xWriteWord(payload->address, payload->data, payload->password, payload->usepwd, true);
            break;
        }
        case CMD_LF_EM4X_PROTECTWORD: {
            struct p {
                uint32_t password;
                uint32_t data;
                uint8_t usepwd;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            EM4xProtectWord(payload->data, payload->password, payload->usepwd, true);
            break;
        }
        case CMD_LF_AWID_WATCH:  {
            uint32_t high, low;
            int res = lf_awid_watch(0, &high, &low, true);
            reply_ng(CMD_LF_AWID_WATCH, res, NULL, 0);
            break;
        }
        case CMD_LF_VIKING_CLONE: {
            struct p {
                bool Q5;
                bool EM;
                uint8_t blocks[8];
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            CopyVikingtoT55xx(payload->blocks, payload->Q5, payload->EM, true);
            break;
        }
        case CMD_LF_COTAG_READ: {
            struct p {
                uint8_t mode;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            Cotag(payload->mode, true);
            break;
        }
#endif

#ifdef WITH_HITAG
        case CMD_LF_HITAG_SNIFF: { // Eavesdrop Hitag tag, args = type
            // threshold comes from `lf hitag sniff -t`, 0 = the slope default
            uint8_t sniff_thr = (packet->length >= 1) ? packet->data.asBytes[0] : 0;
            SniffHitag2(true, sniff_thr);
            //hitag_sniff();
            reply_ng(CMD_LF_HITAG_SNIFF, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_LF_HITAG_SIMULATE: {
            // The tag content comes from emulator memory, so the payload only
            // carries the edge detect threshold.  Older clients send nothing.
            uint8_t threshold = 127;
            uint16_t twait = 0;
            uint8_t flags = 0;
            uint8_t sof = 0;
            uint8_t duty = 0;
            if (packet->length >= sizeof(hitag_sim_t)) {
                hitag_sim_t *payload = (hitag_sim_t *)packet->data.asBytes;
                threshold = (uint8_t)payload->threshold;
                twait = payload->twait;
                flags = payload->flags;
                sof = payload->sof;
                duty = payload->duty;
            }
            SimulateHitag2(threshold, twait, flags, sof, duty, true);
            break;
        }
        case CMD_LF_HITAG2_CRACK: {
            lf_hitag_data_t *payload = (lf_hitag_data_t *) packet->data.asBytes;
            ht2_crack1(payload->NrAr);
            break;
        }
        case CMD_LF_HITAG2_CRACK_2: {
            lf_hitag_data_t *payload = (lf_hitag_data_t *) packet->data.asBytes;
            ht2_crack2(payload->NrAr);
            break;
        }
        case CMD_LF_HITAG_READER: { // Reader for Hitag tags, args = type and function
            lf_hitag_data_t *payload = (lf_hitag_data_t *) packet->data.asBytes;

            switch (payload->cmd) {
                case HT2F_UID_ONLY: {
                    ht2_read_uid(NULL, true, true, false);
                    break;
                }
                default: {
                    ReaderHitag(payload, true);
                    break;
                }
            }
            break;
        }
        case CMD_LF_HITAGS_SIMULATE: { // Simulate Hitag s tag, args = memory content
            if (packet->length < sizeof(hitag_sim_t)) {
                reply_ng(CMD_LF_HITAGS_SIMULATE, PM3_EINVARG, NULL, 0);
                break;
            }
            hitag_sim_t *payload = (hitag_sim_t *)packet->data.asBytes;
            hts_simulate((int8_t)payload->threshold, true);
            break;
        }
        case CMD_LF_HITAGS_TEST_TRACES: { // Tests every challenge within the given file
            hts_check_challenges(packet->data.asBytes, packet->length, true);
            break;
        }
        case CMD_LF_HITAGS_READ: { // Reader for only Hitag S tags, args = key or challenge
            lf_hitag_data_t *payload = (lf_hitag_data_t *) packet->data.asBytes;
            hts_read(payload, true);
            break;
        }
        case CMD_LF_HITAGS_WRITE: {
            lf_hitag_data_t *payload = (lf_hitag_data_t *) packet->data.asBytes;
            hts_write_page(payload, true);
            break;
        }
        case CMD_LF_HITAGS_UID: {
            hts_read_uid(NULL, true, true);
            break;
        }
        case CMD_LF_HITAG2_WRITE: {
            lf_hitag_data_t *payload = (lf_hitag_data_t *) packet->data.asBytes;
            WriterHitag(payload, true);
            break;
        }
        case CMD_LF_HITAG_ELOAD: {
            lf_hitag_t *payload = (lf_hitag_t *) packet->data.asBytes;
            uint8_t *mem = BigBuf_get_EM_addr();
            memcpy(mem, payload->data, payload->len);
            break;
        }

        case CMD_LF_HITAGU_READ: {
            lf_hitag_data_t *payload = (lf_hitag_data_t *)packet->data.asBytes;
            htu_read(payload, true);
            break;
        }
        case CMD_LF_HITAGU_WRITE: {
            lf_hitag_data_t *payload = (lf_hitag_data_t *)packet->data.asBytes;
            htu_write_page(payload, true);
            break;
        }
        case CMD_LF_HITAGU_SIMULATE: {
            if (packet->length < sizeof(hitag_sim_t)) {
                reply_ng(CMD_LF_HITAGU_SIMULATE, PM3_EINVARG, NULL, 0);
                break;
            }
            hitag_sim_t *payload = (hitag_sim_t *)packet->data.asBytes;
            htu_simulate((int8_t)payload->threshold, true);
            break;
        }
        case CMD_LF_HITAGU_UID: {
            htu_read_uid(NULL, true, true);
            break;
        }
#endif

#ifdef WITH_EM4x50
        case CMD_LF_EM4X50_INFO: {
            em4x50_info((const em4x50_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X50_WRITE: {
            em4x50_write((const em4x50_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X50_WRITEPWD: {
            em4x50_writepwd((const em4x50_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X50_READ: {
            em4x50_read((const em4x50_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X50_BRUTE: {
            em4x50_brute((const em4x50_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X50_LOGIN: {
            em4x50_login((const uint32_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X50_SIM: {
            //-----------------------------------------------------------------------------
            // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_LF) here although FPGA is not
            // involved in dealing with emulator memory. But if it is called later, it might
            // destroy the Emulator Memory.
            //-----------------------------------------------------------------------------
            FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
            em4x50_sim((const uint32_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X50_READER: {
            em4x50_reader(true);
            break;
        }
        case CMD_LF_EM4X50_ESET: {
            //-----------------------------------------------------------------------------
            // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_LF) here although FPGA is not
            // involved in dealing with emulator memory. But if it is called later, it might
            // destroy the Emulator Memory.
            //-----------------------------------------------------------------------------
            FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

            if (packet->length < sizeof(em4x50_eset_t)) {
                reply_ng(CMD_LF_EM4X50_ESET, PM3_EINVARG, NULL, 0);
                break;
            }

            em4x50_eset_t *payload = (em4x50_eset_t *)packet->data.asBytes;
            if (payload->len > packet->length - sizeof(em4x50_eset_t)) {
                reply_ng(CMD_LF_EM4X50_ESET, PM3_EINVARG, NULL, 0);
                break;
            }

            int res = emlSet(payload->data, payload->offset, payload->len);
            reply_ng(CMD_LF_EM4X50_ESET, res, NULL, 0);
            break;
        }
        case CMD_LF_EM4X50_CHK: {
            //-----------------------------------------------------------------------------
            // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_LF) here although FPGA is not
            // involved in dealing with emulator memory. But if it is called later, it might
            // destroy the Emulator Memory.
            //-----------------------------------------------------------------------------
            FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
            em4x50_chk((const char *)packet->data.asBytes, true);
            break;
        }
#endif

#ifdef WITH_EM4x70
        case CMD_LF_EM4X70_INFO: {
            em4x70_info((em4x70_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X70_WRITE: {
            em4x70_write((em4x70_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X70_UNLOCK: {
            em4x70_unlock((em4x70_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X70_AUTH: {
            em4x70_auth((em4x70_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X70_SETPIN: {
            em4x70_write_pin((em4x70_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X70_SETKEY: {
            em4x70_write_key((em4x70_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_EM4X70_BRUTE: {
            em4x70_brute((em4x70_data_t *)packet->data.asBytes, true);
            break;
        }
#endif

#ifdef WITH_ZX8211
        case CMD_LF_ZX_READ: {
            zx8211_read((zx8211_data_t *)packet->data.asBytes, true);
            break;
        }
        case CMD_LF_ZX_WRITE: {
            zx8211_write((zx8211_data_t *)packet->data.asBytes, true);
            break;
        }
#endif

#ifdef WITH_ISO15693
        case CMD_HF_ISO15693_ACQ_RAW_ADC: {
            AcquireRawAdcSamplesIso15693();
            break;
        }
        case CMD_HF_ISO15693_SNIFF: {
            SniffIso15693(0, NULL, false);
            reply_ng(CMD_HF_ISO15693_SNIFF, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_HF_ISO15693_COMMAND: {
            iso15_raw_cmd_t *payload = (iso15_raw_cmd_t *)packet->data.asBytes;
            SendRawCommand15693(payload);
            break;
        }
        case CMD_HF_ISO15693_FINDAFI: {
            struct p {
                uint32_t flags;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            BruteforceIso15693Afi(payload->flags);
            break;
        }
        case CMD_HF_ISO15693_READER: {
            ReaderIso15693(NULL);
            break;
        }
        case CMD_HF_ISO15693_EML_CLEAR: {
            //-----------------------------------------------------------------------------
            // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_HF_15) here although FPGA is not
            // involved in dealing with emulator memory. But if it is called later, it might
            // destroy the Emulator Memory.
            //-----------------------------------------------------------------------------
            // Resetting the bitstream also frees the BigBuf memory, so we do this here to prevent
            // an inconvenient reset in the future by Iso15693InitTag
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF_15);
            BigBuf_Clear_EM();
            reply_ng(CMD_HF_ISO15693_EML_CLEAR, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_HF_ISO15693_EML_SETMEM: {
            //-----------------------------------------------------------------------------
            // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_HF_15) here although FPGA is not
            // involved in dealing with emulator memory. But if it is called later, it might
            // destroy the Emulator Memory.
            //-----------------------------------------------------------------------------
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF_15);
            struct p {
                uint32_t offset;
                uint16_t count;
                uint8_t data[];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            emlSet(payload->data, payload->offset, payload->count);
            break;
        }
        case CMD_HF_ISO15693_EML_GETMEM: {
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF_15);
            struct p {
                uint32_t offset;
                uint16_t length;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            if (payload->length > PM3_CMD_DATA_SIZE) {
                reply_ng(CMD_HF_ISO15693_EML_GETMEM, PM3_EMALLOC, NULL, 0);
                return;
            }

            uint8_t *buf = BigBuf_calloc(payload->length);
            emlGet(buf, payload->offset, payload->length);
            LED_B_ON();
            reply_ng(CMD_HF_ISO15693_EML_GETMEM, PM3_SUCCESS, buf, payload->length);
            LED_B_OFF();
            BigBuf_free_keep_EM();
            break;
        }
        case CMD_HF_ISO15693_SIMULATE: {
            struct p {
                uint8_t uid[8];
                uint8_t block_size;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            SimTagIso15693(payload->uid, payload->block_size);
            break;
        }
        case CMD_HF_ISO15693_CSETUID: {
            struct p {
                uint8_t uid[8];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            SetTag15693Uid(payload->uid);
            break;
        }
        case CMD_HF_ISO15693_CSETUID_V2: {
            struct p {
                uint8_t uid[8];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            SetTag15693Uid_v2(payload->uid);
            break;
        }
        case CMD_HF_ISO15693_SLIX_DISABLE_EAS: {
            struct p {
                uint8_t pwd[4];
                bool usepwd;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            DisableEAS_AFISlixIso15693(payload->pwd, payload->usepwd);
            break;
        }
        case CMD_HF_ISO15693_SLIX_ENABLE_EAS: {
            struct p {
                uint8_t pwd[4];
                bool usepwd;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            EnableEAS_AFISlixIso15693(payload->pwd, payload->usepwd);
            break;
        }
        case CMD_HF_ISO15693_SLIX_WRITE_PWD: {
            struct p {
                uint8_t old_pwd[4];
                uint8_t new_pwd[4];
                uint8_t pwd_id;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            WritePasswordSlixIso15693(payload->old_pwd, payload->new_pwd, payload->pwd_id);
            break;
        }
        case CMD_HF_ISO15693_SLIX_PROTECT_PAGE: {
            struct p {
                uint8_t read_pwd[4];
                uint8_t write_pwd[4];
                uint8_t divide_ptr;
                uint8_t prot_status;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            ProtectPageSlixIso15693(payload->read_pwd, payload->write_pwd, payload->divide_ptr, payload->prot_status);
            break;
        }
        case CMD_HF_ISO15693_SLIX_DISABLE_PRIVACY: {
            struct p {
                uint8_t pwd[4];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            DisablePrivacySlixIso15693(payload->pwd);
            break;
        }
        case CMD_HF_ISO15693_SLIX_ENABLE_PRIVACY: {
            struct p {
                uint8_t pwd[4];
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            EnablePrivacySlixIso15693(payload->pwd);
            break;
        }
        case CMD_HF_ISO15693_SLIX_PASS_PROTECT_AFI: {
            struct p {
                uint8_t pwd[4];
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            PassProtectAFISlixIso15693(payload->pwd);
            break;
        }
        case CMD_HF_ISO15693_WRITE_AFI: {
            struct p {
                uint8_t pwd[4];
                bool use_pwd;
                uint8_t uid[8];
                bool use_uid;
                uint8_t afi;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            WriteAFIIso15693(payload->pwd, payload->use_pwd, payload->uid, payload->use_uid, payload->afi);
            break;
        }
        case CMD_HF_ISO15693_SLIX_PASS_PROTECT_EAS: {
            struct p {
                uint8_t pwd[4];
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            PassProtextEASSlixIso15693(payload->pwd);
            break;
        }

#endif

#ifdef WITH_LEGICRF
        case CMD_HF_LEGIC_SIMULATE: {
            struct p {
                uint8_t tagtype;
                bool send_reply;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            LegicRfSimulate(payload->tagtype, payload->send_reply);
            break;
        }
        case CMD_HF_LEGIC_WRITER: {
            legic_packet_t *payload = (legic_packet_t *) packet->data.asBytes;
            LegicRfWriter(payload->offset, payload->len, payload->iv, payload->data);
            break;
        }
        case CMD_HF_LEGIC_READER: {
            legic_packet_t *payload = (legic_packet_t *) packet->data.asBytes;
            LegicRfReader(payload->offset, payload->len, payload->iv);
            break;
        }
        case CMD_HF_LEGIC_INFO: {
            LegicRfInfo();
            break;
        }
        case CMD_HF_LEGIC_ESET: {
            //-----------------------------------------------------------------------------
            // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_HF) here although FPGA is not
            // involved in dealing with emulator memory. But if it is called later, it might
            // destroy the Emulator Memory.
            //-----------------------------------------------------------------------------
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
            legic_packet_t *payload = (legic_packet_t *) packet->data.asBytes;
            emlSet(payload->data, payload->offset, payload->len);
            break;
        }
#endif

#ifdef WITH_ISO14443b
        case CMD_HF_SRI_READ: {
            struct p {
                uint8_t blockno;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            read_14b_st_block(payload->blockno);
            break;
        }
        case CMD_HF_ISO14443B_SNIFF: {
            SniffIso14443b();
            reply_ng(CMD_HF_ISO14443B_SNIFF, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_HF_ISO14443B_SIMULATE: {
            SimulateIso14443bTag(packet->data.asBytes);
            break;
        }
        case CMD_HF_ISO14443B_COMMAND: {
            iso14b_raw_cmd_t *payload = (iso14b_raw_cmd_t *)packet->data.asBytes;
            SendRawCommand14443B(payload);
            break;
        }
        case CMD_HF_ISO14443B_PRINT_CONFIG: {
            printHf14bConfig();
            break;
        }
        case CMD_HF_ISO14443B_GET_CONFIG: {
            hf14b_config_t *c = getHf14bConfig();
            reply_ng(CMD_HF_ISO14443B_GET_CONFIG, PM3_SUCCESS, (uint8_t *)c, sizeof(hf14b_config_t));
            break;
        }
        case CMD_HF_ISO14443B_SET_CONFIG: {
            hf14b_config_t c;
            memcpy(&c, packet->data.asBytes, sizeof(hf14b_config_t));
            setHf14bConfig(&c);
            break;
        }
        case CMD_HF_ISO14443B_ST25TB_TEAROFF: {
            ST25TB_TearOff(packet->data.asBytes);
            break;
        }
        case CMD_HF_CRYPTORF_SIM : {
//            simulate_crf_tag();
            break;
        }
#endif

#ifdef WITH_FELICA
        case CMD_HF_FELICA_COMMAND: {
            felica_sendraw(packet);
            break;
        }
        case CMD_HF_FELICA_SIMULATE: {
            felicasim_standard(packet);
            break;
        }
        case CMD_HF_FELICALITE_SIMULATE: {
            struct p {
                uint8_t uid[8];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            felica_sim_lite(payload->uid);
            break;
        }
        case CMD_HF_FELICA_SNIFF: {
            struct p {
                uint32_t samples;
                uint32_t triggers;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            felica_sniff(payload->samples, payload->triggers);
            break;
        }
        case CMD_HF_FELICALITE_DUMP: {
            felica_dump_lite_s();
            break;
        }
#endif

#ifdef WITH_GENERAL_HF
        case CMD_HF_ACQ_RAW_ADC: {
            uint32_t samplesCount = 0;
            memcpy(&samplesCount, packet->data.asBytes, 4);
            HfReadADC(samplesCount, true);
            break;
        }
        case CMD_HF_TEXKOM_SIMULATE: {
            struct p {
                uint8_t data[8];
                uint8_t modulation;
                uint32_t timeout;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            HfSimulateTkm(payload->data, payload->modulation, payload->timeout);
            break;
        }

#endif

#ifdef WITH_ISO14443a
        case CMD_HF_ISO14443A_PRINT_CONFIG: {
            printHf14aConfig();
            break;
        }
        case CMD_HF_ISO14443A_GET_CONFIG: {
            hf14a_config_t *c = getHf14aConfig();
            reply_ng(CMD_HF_ISO14443A_GET_CONFIG, PM3_SUCCESS, (uint8_t *)c, sizeof(hf14a_config_t));
            break;
        }
        case CMD_HF_ISO14443A_SET_CONFIG: {
            hf14a_config_t c;
            memcpy(&c, packet->data.asBytes, sizeof(hf14a_config_t));
            setHf14aConfig(&c);
            break;
        }
        case CMD_HF_ISO14443A_SET_THRESHOLDS: {
            struct p {
                uint8_t threshold;
                uint8_t threshold_high;
                uint8_t legic_threshold;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
            FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, (payload->threshold & 0x3f) | ((payload->threshold_high & 0x3f) << 6));
#ifdef WITH_LEGICRF
            LegicRfSetThreshold((uint32_t)payload->legic_threshold);
#endif
            break;
        }
        case CMD_HF_ISO14443A_SNIFF: {
            reply_ng(CMD_HF_ISO14443A_SNIFF, SniffIso14443a(packet->data.asBytes[0]), NULL, 0);
            break;
        }
        case CMD_HF_HIDCONFIG_SNIFF: {
            SniffHIDConfigCard((const hid_sniff_payload_t *)packet->data.asBytes);
            reply_ng(CMD_HF_HIDCONFIG_SNIFF, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_HF_ISO14443A_READER: {
            ReaderIso14443a(packet);
            break;
        }
#ifdef WITH_SMARTCARD
        case CMD_HF_ISO14443A_EMV_SIMULATE: {
            struct p {
                uint16_t flags;
                uint8_t exitAfter;
                uint8_t uid[7];
                uint16_t atqa;
                uint8_t sak;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            EMVsim(payload->flags, payload->exitAfter, payload->uid, payload->atqa, payload->sak);
            break;
        }
#endif
        case CMD_HF_ISO14443A_SIMULATE: {
            struct p {
                uint8_t tagtype;
                uint16_t flags;
                uint8_t uid[10];
                uint8_t exitAfter;
                uint8_t rats[20];
                uint8_t ulauth_1a1_len;
                uint8_t ulauth_1a2_len;
                uint8_t ulauth_1a1[16];
                uint8_t ulauth_1a2[16];
                bool ulauth_1a2_mirror;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            SimulateIso14443aTagEx(payload->tagtype, payload->flags, payload->uid,
                                   payload->exitAfter, payload->rats, sizeof(payload->rats),
                                   payload->ulauth_1a1, payload->ulauth_1a1_len,
                                   payload->ulauth_1a2, payload->ulauth_1a2_len,
                                   payload->ulauth_1a2_mirror
                                  );  // ## Simulate iso14443a tag - pass tag type & UID
            break;
        }
        case CMD_HF_ISO14443A_SIM_AID: {
            struct p {
                uint8_t tagtype;
                uint16_t flags;
                uint8_t uid[10];
                uint8_t ats[20];
                uint8_t aid[30];
                uint8_t selectaid_response[256];
                uint8_t getdata_response[100];
                uint32_t ats_len;
                uint32_t aid_len;
                uint32_t selectaid_response_len;
                uint32_t getdata_response_len;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            // ## Simulate iso14443a tag - pass tag type, UID, ATS, AID, responses
            SimulateIso14443aTagAID(payload->tagtype, payload->flags, payload->uid,
                                    payload->ats, payload->ats_len, payload->aid, payload->aid_len,
                                    payload->selectaid_response, payload->selectaid_response_len,
                                    payload->getdata_response, payload->getdata_response_len);
            break;
        }
        case CMD_HF_HIDCONFIG_SIM: {
            SimulateHIDConfigCard((const hid_sim_payload_t *) packet->data.asBytes);
            break;
        }
        case CMD_HF_ISO14443A_ANTIFUZZ: {
            struct p {
                uint8_t flag;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            iso14443a_antifuzz(payload->flag);
            break;
        }
        // EPA related
        case CMD_HF_EPA_COLLECT_NONCE: {
            EPA_PACE_Collect_Nonce(packet);
            break;
        }
        case CMD_HF_EPA_REPLAY: {
            EPA_PACE_Replay(packet);
            break;
        }
        case CMD_HF_EPA_PACE_SIMULATE: {
            EPA_PACE_Simulate(packet);
            break;
        }

        case CMD_HF_MIFARE_READER: {
            struct p {
                uint8_t first_run;
                uint8_t blockno;
                uint8_t key_type;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            ReaderMifare(payload->first_run, payload->blockno, payload->key_type);
            break;
        }
        case CMD_HF_MIFARE_READBL: {
            mf_readblock_t *payload = (mf_readblock_t *)packet->data.asBytes;
            uint8_t outbuf[16];
            int16_t retval = mifare_cmd_readblocks(MF_WAKE_WUPA, MIFARE_AUTH_KEYA + payload->keytype, payload->key, ISO14443A_CMD_READBLOCK, payload->blockno, 1, outbuf);
            reply_ng(CMD_HF_MIFARE_READBL, retval, outbuf, sizeof(outbuf));
            break;
        }
        case CMD_HF_MIFARE_READBL_EX: {
            mf_readblock_ex_t *payload = (mf_readblock_ex_t *)packet->data.asBytes;
            uint8_t outbuf[16];
            int16_t retval = mifare_cmd_readblocks(payload->wakeup, payload->auth_cmd, payload->key, payload->read_cmd, payload->block_no, 1, outbuf);
            reply_ng(CMD_HF_MIFARE_READBL_EX, retval, outbuf, sizeof(outbuf));
            break;
        }
        case CMD_HF_MIFAREU_READBL: {
            MifareUReadBlock((mful_readblock_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREU3P_AUTH: {
            MifareU3PassAuth((mful_3passauth_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREU3P_CHKKEY: {
            MifareU3PassChkKeys((mful_3passchk_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREU_READCARD: {
            MifareUReadCard((mful_readblock_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREU_SETKEY: {
            MifareUSetKey((mful_setkey_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_READSC: {
            if (packet->length != sizeof(mf_readsector_t)) {
                reply_ng(CMD_HF_MIFARE_READSC, PM3_EINVARG, NULL, 0);
                break;
            }
            mf_readsector_t *payload = (mf_readsector_t *)packet->data.asBytes;
            MifareReadSector(payload->sectorno, payload->keytype, payload->key);
            break;
        }
        case CMD_HF_MIFARE_WRITEBL_EX: {
            mf_writeblock_ex_t *payload = (mf_writeblock_ex_t *)packet->data.asBytes;
            int16_t retval = mifare_cmd_writeblocks(payload->wakeup, payload->auth_cmd, payload->key, payload->write_cmd, payload->block_no, 1, payload->block_data);
            reply_ng(CMD_HF_MIFARE_WRITEBL_EX, retval, NULL, 0);
            break;
        }
        case CMD_HF_MIFARE_VALUE: {
            if (packet->length != sizeof(mf_value_t)) {
                reply_ng(CMD_HF_MIFARE_VALUE, PM3_EINVARG, NULL, 0);
                break;
            }
            MifareValue((mf_value_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREU_WRITEBL: {
            MifareUWriteBlock((mful_writeblock_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREU_WRITEBL_COMPAT: {
            MifareUWriteBlockCompat((mful_writeblock_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_ACQ_ENCRYPTED_NONCES: {
            if (packet->length != sizeof(mf_acquire_nonces_t)) {
                reply_ng(CMD_HF_MIFARE_ACQ_ENCRYPTED_NONCES, PM3_EINVARG, NULL, 0);
                break;
            }
            MifareAcquireEncryptedNonces((mf_acquire_nonces_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_ACQ_STATIC_ENCRYPTED_NONCES: {
            if (packet->length != sizeof(mf_acquire_nonces_t)) {
                reply_ng(CMD_HF_MIFARE_ACQ_STATIC_ENCRYPTED_NONCES, PM3_EINVARG, NULL, 0);
                break;
            }
            mf_acquire_nonces_t *payload = (mf_acquire_nonces_t *)packet->data.asBytes;
            MifareAcquireStaticEncryptedNonces(payload->flags, payload->key, true, payload->blockno, payload->keytype);
            break;
        }
        case CMD_HF_MIFARE_ACQ_NONCES: {
            if (packet->length != sizeof(mf_acquire_nonces_t)) {
                reply_ng(CMD_HF_MIFARE_ACQ_NONCES, PM3_EINVARG, NULL, 0);
                break;
            }
            MifareAcquireNonces((mf_acquire_nonces_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_NESTED: {
            struct p {
                uint8_t block;
                uint8_t keytype;
                uint8_t target_block;
                uint8_t target_keytype;
                bool calibrate;
                uint8_t key[6];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareNested(payload->block, payload->keytype, payload->target_block, payload->target_keytype, payload->calibrate, payload->key);
            break;
        }
        case CMD_HF_MIFARE_STATIC_NESTED: {
            struct p {
                uint8_t block;
                uint8_t keytype;
                uint8_t target_block;
                uint8_t target_keytype;
                uint8_t force_detect_dist;
                uint8_t key[6];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareStaticNested(payload->block, payload->keytype, payload->target_block, payload->target_keytype, payload->key, payload->force_detect_dist);
            break;
        }
        case CMD_HF_MIFARE_CHKKEYS: {
            MifareChkKeys(packet->data.asBytes, false);
            break;
        }
        case CMD_HF_MIFARE_CHKKEYS_FAST: {
            if (packet->length < sizeof(mf_chkkeys_fast_t)) {
                reply_ng(CMD_HF_MIFARE_CHKKEYS_FAST, PM3_EINVARG, NULL, 0);
                break;
            }
            mf_chkkeys_fast_t *payload = (mf_chkkeys_fast_t *)packet->data.asBytes;
            if ((payload->key_count * 6) > (packet->length - sizeof(mf_chkkeys_fast_t))) {
                reply_ng(CMD_HF_MIFARE_CHKKEYS_FAST, PM3_EINVARG, NULL, 0);
                break;
            }
            MifareChkKeys_fast(payload);
            break;
        }
        case CMD_HF_MIFARE_CHKKEYS_FILE: {
            struct p {
                uint8_t filename[32];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareChkKeys_file(payload->filename);
            break;
        }
        case CMD_HF_MIFARE_SIMULATE: {
            struct p {
                uint16_t flags;
                uint8_t exitAfter;
                uint8_t uid[10];
                uint16_t atqa;
                uint8_t sak;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            Mifare1ksim(payload->flags, payload->exitAfter, payload->uid, payload->atqa, payload->sak);
            break;
        }
        case CMD_HF_MIFARE_EML_MEMCLR: {

            //-----------------------------------------------------------------------------
            // Work with emulator memory
            //
            // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_HF) here although FPGA is not
            // involved in dealing with emulator memory. But if it is called later, it might
            // destroy the Emulator Memory.
            //-----------------------------------------------------------------------------
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

            // Not only clears the emulator memory,
            // also sets default MIFARE values for sector trailers.
            emlClearMem();
            reply_ng(CMD_HF_MIFARE_EML_MEMCLR, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_HF_MIFARE_EML_MEMSET: {
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
            struct p {
                uint16_t blockno;
                uint8_t blockcnt;
                uint8_t blockwidth;
                uint8_t data[];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            // backwards compat... default bytewidth
            if (payload->blockwidth == 0) {
                payload->blockwidth = MIFARE_BLOCK_SIZE;
            }

            emlSetMem_xt(payload->data, payload->blockno, payload->blockcnt, payload->blockwidth);
            break;
        }
        case CMD_HF_MIFARE_EML_MEMGET: {

            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
            struct p {
                uint16_t blockno;
                uint8_t blockcnt;
                uint8_t blockwidth;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            //
            size_t size = payload->blockcnt * payload->blockwidth;
            if (size > PM3_CMD_DATA_SIZE) {
                reply_ng(CMD_HF_MIFARE_EML_MEMGET, PM3_EMALLOC, NULL, 0);
                return;
            }

            uint8_t *buf = BigBuf_calloc(size);

            emlGetMem_xt(buf, payload->blockno, payload->blockcnt, payload->blockwidth); // data, block num, blocks count (max 4)

            LED_B_ON();
            reply_ng(CMD_HF_MIFARE_EML_MEMGET, PM3_SUCCESS, buf, size);
            LED_B_OFF();
            BigBuf_free_keep_EM();
            break;
        }
        case CMD_HF_MIFARE_EML_LOAD: {
            mfc_eload_t *payload = (mfc_eload_t *) packet->data.asBytes;
            MifareECardLoadExt(payload->sectorcnt, payload->keytype, payload->key);
            break;
        }
        // Gen1a / 1b - "magic Chinese" card
        case CMD_HF_MIFARE_CSETBL: {
            if (packet->length < sizeof(mf_chinese_blk_t) + MIFARE_BLOCK_SIZE) {
                reply_ng(CMD_HF_MIFARE_CSETBL, PM3_EINVARG, NULL, 0);
                break;
            }
            mf_chinese_blk_t *payload = (mf_chinese_blk_t *)packet->data.asBytes;
            MifareCSetBlock(payload->params, payload->blockno, payload->data);
            break;
        }
        case CMD_HF_MIFARE_CGETBL: {
            if (packet->length < sizeof(mf_chinese_blk_t)) {
                reply_ng(CMD_HF_MIFARE_CGETBL, PM3_EINVARG, NULL, 0);
                break;
            }
            mf_chinese_blk_t *payload = (mf_chinese_blk_t *)packet->data.asBytes;
            MifareCGetBlock(payload->params, payload->blockno, payload->data);
            break;
        }
        case CMD_HF_MIFARE_CIDENT: {
            struct p {
                uint8_t is_mfc;
                uint8_t keytype;
                uint8_t key[6];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareCIdent(payload->is_mfc, payload->keytype, payload->key);
            break;
        }
        // Gen 3 magic cards
        case CMD_HF_MIFARE_GEN3UID: {
            if (packet->length < sizeof(mf_gen3uid_t)) {
                reply_ng(CMD_HF_MIFARE_GEN3UID, PM3_EINVARG, NULL, 0);
                break;
            }
            mf_gen3uid_t *payload = (mf_gen3uid_t *)packet->data.asBytes;
            if (payload->uidlen > (packet->length - sizeof(mf_gen3uid_t))) {
                reply_ng(CMD_HF_MIFARE_GEN3UID, PM3_EINVARG, NULL, 0);
                break;
            }
            MifareGen3UID(payload->uidlen, payload->uid);
            break;
        }
        case CMD_HF_MIFARE_GEN3BLK: {
            if (packet->length < sizeof(mf_gen3blk_t)) {
                reply_ng(CMD_HF_MIFARE_GEN3BLK, PM3_EINVARG, NULL, 0);
                break;
            }
            mf_gen3blk_t *payload = (mf_gen3blk_t *)packet->data.asBytes;
            if (payload->blocklen > (packet->length - sizeof(mf_gen3blk_t))) {
                reply_ng(CMD_HF_MIFARE_GEN3BLK, PM3_EINVARG, NULL, 0);
                break;
            }
            MifareGen3Blk(payload->blocklen, payload->block);
            break;
        }
        case CMD_HF_MIFARE_GEN3FREEZ: {
            MifareGen3Freez();
            break;
        }
        // Gen 4 GTU magic cards
        case CMD_HF_MIFARE_G4_RDBL: {
            struct p {
                uint8_t blockno;
                uint8_t pwd[4];
                uint8_t workFlags;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareG4ReadBlk(payload->blockno, payload->pwd, payload->workFlags);
            break;
        }
        case CMD_HF_MIFARE_G4_WRBL: {
            struct p {
                uint8_t blockno;
                uint8_t pwd[4];
                uint8_t data[16]; // data to be written
                uint8_t workFlags;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareG4WriteBlk(payload->blockno, payload->pwd, payload->data, payload->workFlags);
            break;
        }
        case CMD_HF_MIFARE_G4_GDM_WRBL: {
            struct p {
                uint8_t blockno;
                uint8_t key[6];
                uint8_t data[16]; // data to be written
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            int16_t retval = mifare_cmd_writeblocks(MF_WAKE_WUPA, MIFARE_MAGIC_GDM_AUTH_KEY, payload->key, MIFARE_MAGIC_GDM_WRITEBLOCK, payload->blockno, 1, payload->data);
            reply_ng(CMD_HF_MIFARE_G4_GDM_WRBL, retval, NULL, 0);
            break;
        }
        case CMD_HF_MIFARE_PERSONALIZE_UID: {
            struct p {
                uint8_t keytype;
                uint8_t pers_option;
                uint8_t key[6];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            uint64_t authkey = bytes_to_num(payload->key, 6);
            MifarePersonalizeUID(payload->keytype, payload->pers_option, authkey);
            break;
        }
        case CMD_HF_MIFARE_SETMOD: {
            MifareSetMod(packet->data.asBytes);
            break;
        }
        //mifare desfire
        case CMD_HF_DESFIRE_READBL: {
            break;
        }
        case CMD_HF_DESFIRE_WRITEBL: {
            break;
        }
        case CMD_HF_DESFIRE_AUTH1: {
            MifareDES_Auth1(packet->data.asBytes);
            break;
        }
        case CMD_HF_DESFIRE_AUTH2: {
            //MifareDES_Auth2(packet->oldarg[0],packet->data.asBytes);
            break;
        }
        case CMD_HF_DESFIRE_READER: {
            //readermifaredes(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_DESFIRE_INFO: {
            MifareDesfireGetInformation();
            break;
        }
        case CMD_HF_DESFIRE_COMMAND: {
            MifareSendCommand(packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_NACK_DETECT: {
            DetectNACKbug();
            break;
        }
        case CMD_HF_MFU_OTP_TEAROFF: {
            if (packet->length < sizeof(mfu_otp_tearoff_t)) {
                reply_ng(CMD_HF_MFU_OTP_TEAROFF, PM3_EINVARG, NULL, 0);
                break;
            }
            mfu_otp_tearoff_t *payload = (mfu_otp_tearoff_t *)packet->data.asBytes;
            MifareU_Otp_Tearoff(payload->blockno, payload->tearoff_time, payload->data);
            break;
        }
        case CMD_HF_MFU_COUNTER_TEAROFF: {
            struct p {
                uint8_t counter;
                uint32_t tearoff_time;
                uint8_t value[4];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareU_Counter_Tearoff(payload->counter, payload->tearoff_time, payload->value);
            break;
        }
        case CMD_HF_MIFARE_STATIC_NONCE: {
            MifareHasStaticNonce();
            break;
        }
        case CMD_HF_MIFARE_STATIC_ENCRYPTED_NONCE: {
            struct p {
                uint8_t block_no;
                uint8_t key_type;
                uint8_t key[6];
                uint8_t block_no_nested;
                uint8_t key_type_nested;
                uint8_t key_nested[6];
                uint8_t nr_nonces;
                uint8_t resets;
                uint8_t addread;
                uint8_t addauth;
                uint8_t incblk2;
                uint8_t corruptnrar;
                uint8_t corruptnrarparity;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            MifareHasStaticEncryptedNonce(payload->block_no, payload->key_type, payload->key, payload->block_no_nested, payload->key_type_nested, payload->key_nested, payload->nr_nonces, payload->resets & 1, (payload->resets >> 1) & 1, payload->addread, payload->addauth, payload->incblk2, payload->corruptnrar, payload->corruptnrarparity);
            break;
        }
#endif

#ifdef WITH_NFCBARCODE
        case CMD_HF_THINFILM_READ: {
            ReadThinFilm();
            break;
        }
        case CMD_HF_THINFILM_SIMULATE: {
            SimulateThinFilm(packet->data.asBytes, packet->length);
            break;
        }
#endif

#ifdef WITH_ICLASS
        // Makes use of ISO14443a FPGA Firmware
        case CMD_HF_ICLASS_SNIFF: {
            struct p {
                uint8_t jam_search_len;
                uint8_t jam_search_string[];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            SniffIClass(payload->jam_search_len, payload->jam_search_string);
            reply_ng(CMD_HF_ICLASS_SNIFF, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_HF_ICLASS_SIMULATE: {
            /*
                        struct p {
                            uint8_t reader[4];
                            uint8_t mac[4];
                        } PACKED;
                        struct p *payload = (struct p *) packet->data.asBytes;
            */

            if (packet->length < sizeof(iclass_sim_t)) {
                reply_ng(CMD_HF_ICLASS_SIMULATE, PM3_EINVARG, NULL, 0);
                break;
            }
            iclass_sim_t *payload = (iclass_sim_t *)packet->data.asBytes;
            iclass_simulate(payload->sim_type, payload->num_csns, payload->send_reply, true, payload->csns, NULL, NULL);
            break;
        }
        case CMD_HF_ICLASS_READER: {
            ReaderIClass(packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_RAW: {
            iClass_Raw(packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_EML_MEMSET: {
            FpgaDownloadAndGo_keep_EM(FPGA_BITSTREAM_HF_15);
            struct p {
                uint16_t offset;
                uint16_t len;
                uint8_t data[];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            emlSet(payload->data, payload->offset, payload->len);
            break;
        }
        case CMD_HF_ICLASS_WRITEBL: {
            iClass_WriteBlock(packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_READBL: {
            iClass_ReadBlock(packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_CHKKEYS: {
            iClass_Authentication_fast((iclass_chk_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_DUMP: {
            iClass_Dump(packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_RESTORE: {
            iClass_Restore((iclass_restore_req_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_RECOVER: {
            iClass_Recover((iclass_recover_req_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_CREDIT_EPURSE: {
            iclass_credit_epurse((iclass_credit_epurse_t *)packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_TEARBL: {
            iClass_TearBlock((iclass_tearblock_req_t *)packet->data.asBytes);
            break;
        }
#endif
#ifdef WITH_SEOS
        case CMD_HF_SEOS_SIMULATE: {
            SimulateSeos((seos_emulate_req_t *)packet->data.asBytes);
            break;
        }
#endif

#ifdef WITH_HFSNIFF
        case CMD_HF_SNIFF: {
            struct p {
                uint32_t samplesToSkip;
                uint32_t triggersToSkip;
                uint8_t skipMode;
                uint8_t skipRatio;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            uint16_t len = 0;
            int res = HfSniff(payload->samplesToSkip, payload->triggersToSkip, &len, payload->skipMode, payload->skipRatio);

            struct {
                uint16_t len;
            } PACKED retval;
            retval.len = len;
            reply_ng(CMD_HF_SNIFF, res, (uint8_t *)&retval, sizeof(retval));
            break;
        }
#endif

#ifdef WITH_HFPLOT
        case CMD_FPGAMEM_DOWNLOAD: {
            HfPlotDownload();
            break;
        }
#endif

#ifdef WITH_SMARTCARD
        case CMD_SMART_ATR: {
            SmartCardAtr();
            break;
        }
        case CMD_SMART_PPS: {
            SmartCardPPS((const smart_card_pps_t *)packet->data.asBytes);
            break;
        }
        case CMD_SMART_SETCLOCK: {
            struct p {
                uint32_t new_clk;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            SmartCardSetClock(payload->new_clk);
            break;
        }
        case CMD_SMART_RAW: {
            SmartCardRaw((smart_card_raw_t *) packet->data.asBytes);
            break;
        }
        case CMD_SMART_UPLOAD: {
            // upload file from client
            struct p {
                uint32_t idx;
                uint32_t bytes_in_packet;
                uint16_t crc;
                uint8_t data[400];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            uint8_t *mem = BigBuf_get_addr();

            // sanity checks
            if (payload->bytes_in_packet > sizeof(payload->data) ||
                    payload->idx > BigBuf_get_size() ||
                    payload->idx + payload->bytes_in_packet > BigBuf_get_size()) {
                reply_ng(CMD_SMART_UPLOAD, PM3_EOVFLOW, NULL, 0);
                break;
            }

            memcpy(mem + payload->idx, payload->data, payload->bytes_in_packet);

            uint8_t a = 0, b = 0;
            compute_crc(CRC_14443_A, mem + payload->idx,  payload->bytes_in_packet, &a, &b);
            int res = PM3_SUCCESS;
            if (payload->crc != (a << 8 | b)) {
                DbpString("CRC Failed");
                res = PM3_ESOFT;
            }
            reply_ng(CMD_SMART_UPLOAD, res, NULL, 0);
            break;
        }
        case CMD_SMART_UPGRADE: {
            struct p {
                uint16_t fw_size;
                uint16_t crc;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            uint8_t *fwdata = BigBuf_get_addr();
            uint8_t a = 0, b = 0;
            compute_crc(CRC_14443_A, fwdata, payload->fw_size, &a, &b);

            if (payload->crc != (a << 8 | b)) {
                Dbprintf("CRC Failed, 0x[%04x] != 0x[%02x%02x]", payload->crc, a, b);
                reply_ng(CMD_SMART_UPGRADE, PM3_ESOFT, NULL, 0);
            } else {
                SmartCardUpgrade(payload->fw_size);
            }
            fwdata = NULL;
            break;
        }

        case CMD_HF_SAM_PICOPASS: {
            sam_picopass_get_pacs(packet);
            break;
        }
        case CMD_HF_SAM_SEOS: {
            sam_seos_get_pacs(packet);
            break;
        }

        case CMD_HF_SAM_MFC: {
//            sam_mfc_get_pacs();
            break;
        }

        case CMD_HF_SAM_SC: {
            sam_sc_handler(packet);
            break;
        }

#endif

#ifdef WITH_FPC_USART
        case CMD_USART_TX: {
            LED_B_ON();
            usart_writebuffer_sync(packet->data.asBytes, packet->length);
            reply_ng(CMD_USART_TX, PM3_SUCCESS, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_USART_RX: {
            LED_B_ON();
            struct p {
                uint32_t waittime;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            uint16_t available;
            uint16_t pre_available = 0;
            uint8_t *dest = BigBuf_calloc(USART_FIFOLEN);
            uint32_t wait = payload->waittime;

            StartTicks();

            uint32_t ti = GetTickCount();

            while (true) {
                WaitMS(50);
                available = usart_rxdata_available();
                if (available > pre_available) {
                    // When receiving data, reset timer and shorten timeout
                    ti = GetTickCount();
                    wait = 50;
                    pre_available = available;
                    continue;
                }
                // We stop either after waittime if no data or 50ms after last data received
                if (GetTickCountDelta(ti) > wait)
                    break;
            }
            if (available > 0) {
                uint16_t len = usart_read_ng(dest, available);
                reply_ng(CMD_USART_RX, PM3_SUCCESS, dest, len);
            } else {
                reply_ng(CMD_USART_RX, PM3_ENODATA, NULL, 0);
            }

            StopTicks();
            BigBuf_free();
            LED_B_OFF();
            break;
        }
        case CMD_USART_TXRX: {
            LED_B_ON();
            struct p {
                uint32_t waittime;
                uint8_t data[];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            usart_writebuffer_sync(payload->data, packet->length - sizeof(payload));

            uint16_t available;
            uint16_t pre_available = 0;
            uint8_t *dest = BigBuf_calloc(USART_FIFOLEN);
            uint32_t wait = payload->waittime;

            StartTicks();

            uint32_t ti = GetTickCount();

            while (true) {
                WaitMS(50);
                available = usart_rxdata_available();
                if (available > pre_available) {
                    // When receiving data, reset timer and shorten timeout
                    ti = GetTickCount();
                    wait = 50;
                    pre_available = available;
                    continue;
                }
                // We stop either after waittime if no data or 50ms after last data received
                if (GetTickCountDelta(ti) > wait)
                    break;
            }

            if (available > 0) {
                uint16_t len = usart_read_ng(dest, available);
                reply_ng(CMD_USART_TXRX, PM3_SUCCESS, dest, len);
            } else {
                reply_ng(CMD_USART_TXRX, PM3_ENODATA, NULL, 0);
            }

            StopTicks();
            BigBuf_free();
            LED_B_OFF();
            break;
        }
        case CMD_USART_CONFIG: {
            struct p {
                uint32_t baudrate;
                uint8_t parity;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            usart_init(payload->baudrate, payload->parity);
            reply_ng(CMD_USART_CONFIG, PM3_SUCCESS, NULL, 0);
            break;
        }
#endif
        case CMD_BUFF_CLEAR: {
            BigBuf_Clear();
            BigBuf_free();
            break;
        }
#ifdef WITH_LF
        case CMD_MEASURE_ANTENNA_TUNING: {
            MeasureAntennaTuning();
            break;
        }
#endif
        case CMD_MEASURE_ANTENNA_TUNING_HF: {
            if (packet->length != 1)
                reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_EINVARG, NULL, 0);

            switch (packet->data.asBytes[0]) {
                case 1: // MEASURE_ANTENNA_TUNING_HF_START
                    // Let the FPGA drive the high-frequency antenna around 13.56 MHz.
                    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER);
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_SUCCESS, NULL, 0);
                    break;
                case 2:
                    if (button_status == BUTTON_SINGLE_CLICK) {
                        reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_EOPABORTED, NULL, 0);
                    }
                    uint32_t volt = AdcRssiAvgToMilliVolt(ADC_RSSI_CH_HF);
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_SUCCESS, (uint8_t *)&volt, sizeof(volt));
                    break;
                case 3:
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_SUCCESS, NULL, 0);
                    break;
                default:
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_HF, PM3_EINVARG, NULL, 0);
                    break;
            }
            break;
        }
#ifndef PM5
        case CMD_HF_DECAY: {
            MeasureAntennaTuningHfDecay((const hf_decay_params_t *)packet->data.asBytes);
            break;
        }
#endif
        case CMD_MEASURE_ANTENNA_TUNING_LF: {
            if (packet->length != 2)
                reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_EINVARG, NULL, 0);

            switch (packet->data.asBytes[0]) {
                case 1: // MEASURE_ANTENNA_TUNING_LF_START
                    // Let the FPGA drive the low-frequency antenna around 125kHz
                    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER | FPGA_LF_ADC_READER_FIELD);
                    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, packet->data.asBytes[1]);
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_SUCCESS, NULL, 0);
                    break;
                case 2:
                    if (button_status == BUTTON_SINGLE_CLICK) {
                        reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_EOPABORTED, NULL, 0);
                    }

                    uint32_t volt = AdcRssiAvgToMilliVolt(ADC_RSSI_CH_LF);
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_SUCCESS, (uint8_t *)&volt, sizeof(volt));
                    break;
                case 3:
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_SUCCESS, NULL, 0);
                    break;
                default:
                    reply_ng(CMD_MEASURE_ANTENNA_TUNING_LF, PM3_EINVARG, NULL, 0);
                    break;
            }
            break;
        }
        case CMD_LISTEN_READER_FIELD: {
            if (packet->length != sizeof(uint8_t))
                break;
            ListenReaderField(packet->data.asBytes[0]);
            reply_ng(CMD_LISTEN_READER_FIELD, PM3_EOPABORTED, NULL, 0);
            break;
        }
        case CMD_FPGA_MAJOR_MODE_OFF: { // ## FPGA Control
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
            FpgaResetBitstream();
            g_hf_field_active = false;
            g_hf_field_timeout_active = false;
            SpinDelay(200);
            LED_D_OFF(); // LED D indicates field ON or OFF
            break;
        }
        case CMD_DOWNLOAD_BIGBUF: {
            LED_B_ON();
            uint8_t *mem = BigBuf_get_addr();
            if (packet->length < sizeof(download_req_t)) {
                break;
            }
            const download_req_t *dreq = (const download_req_t *)packet->data.asBytes;
            uint32_t startidx = dreq->start_index;
            uint32_t numofbytes = dreq->bytes;

            // arg0 = startindex
            // arg1 = length bytes to transfer
            // arg2 = BigBuf tracelen
            //Dbprintf("transfer to client parameters: %" PRIu32 " | %" PRIu32 " | %" PRIu32, startidx, numofbytes, packet->oldarg[2]);

            const size_t dl_chunk = reply_ng_max_data_size() - sizeof(download_chunk_t);
            for (size_t offset = 0; offset < numofbytes; offset += dl_chunk) {
                size_t len = MIN((numofbytes - offset), dl_chunk);
                int result = reply_download_chunk(CMD_DOWNLOADED_BIGBUF, offset, &mem[startidx + offset], len);
                if (result != PM3_SUCCESS)
                    Dbprintf("transfer to client failed ::  | bytes between %d - %d (%d) | result: %d", offset, offset + len, len, result);
            }
            // Trigger a finish downloading signal with an ACK frame
            // arg0 = status of download transfer
            reply_download_done(CMD_DOWNLOAD_BIGBUF, numofbytes, BigBuf_get_traceLen());
            LED_B_OFF();
            break;
        }
#ifdef WITH_LF
        case CMD_LF_UPLOAD_SIM_SAMPLES: {
            // iceman; since changing fpga_bitstreams clears bigbuff, Its better to call it before.
            // to be able to use this one for uploading data to device
            // flag =
            //    b0  0 skip
            //        1 clear bigbuff
            struct p {
                uint8_t flag;
                uint16_t offset;
                uint8_t data[PM3_CMD_DATA_SIZE - sizeof(uint8_t) - sizeof(uint16_t)];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

            if ((payload->flag & 0x1) == 0x1) {
                BigBuf_Clear_ext(false);
                BigBuf_free();
            }

            // offset should not be over buffer
            if (payload->offset >= BigBuf_get_size()) {
                reply_ng(CMD_LF_UPLOAD_SIM_SAMPLES, PM3_EOVFLOW, NULL, 0);
                break;
            }
            // ensure len bytes copied won't go past end of bigbuf
            uint16_t len = MIN(BigBuf_get_size() - payload->offset, sizeof(payload->data));

            uint8_t *mem = BigBuf_get_addr();

            memcpy(mem + payload->offset, &payload->data, len);
            reply_ng(CMD_LF_UPLOAD_SIM_SAMPLES, PM3_SUCCESS, NULL, 0);
            break;
        }
#endif
        case CMD_DOWNLOAD_EML_BIGBUF: {
            LED_B_ON();
            uint8_t *mem = BigBuf_get_EM_addr();
            if (packet->length < sizeof(download_req_t)) {
                break;
            }
            const download_req_t *dreq = (const download_req_t *)packet->data.asBytes;
            uint32_t startidx = dreq->start_index;
            uint32_t numofbytes = dreq->bytes;

            // arg0 = startindex
            // arg1 = length bytes to transfer
            // arg2 = RFU

            const size_t dl_chunk = reply_ng_max_data_size() - sizeof(download_chunk_t);
            for (size_t i = 0; i < numofbytes; i += dl_chunk) {
                size_t len = MIN((numofbytes - i), dl_chunk);
                int result = reply_download_chunk(CMD_DOWNLOADED_EML_BIGBUF, i, mem + startidx + i, len);
                if (result != PM3_SUCCESS)
                    Dbprintf("transfer to client failed ::  | bytes between %d - %d (%d) | result: %d", i, i + len, len, result);
            }
            // Trigger a finish downloading signal with an ACK frame
            reply_download_done(CMD_DOWNLOAD_EML_BIGBUF, numofbytes, 0);
            LED_B_OFF();
            break;
        }
        case CMD_READ_MEM: {
            if (packet->length != sizeof(uint32_t))
                break;
            ReadMem(packet->data.asDwords[0]);
            break;
        }
        case CMD_READ_MEM_DOWNLOAD: {
            LED_B_ON();

            size_t offset = packet->oldarg[0];
            size_t count = packet->oldarg[1];
            uint32_t flags = packet->oldarg[2];

            bool isok = true;
            uint8_t *base = NULL;

            bool raw_address_mode = ((flags & READ_MEM_DOWNLOAD_FLAG_RAW) == READ_MEM_DOWNLOAD_FLAG_RAW);
            if (raw_address_mode == false) {

                base = (uint8_t *) _flash_start;

                size_t flash_size = GetChipFlashSize();

                // Boundary check the offset.
                if (offset > flash_size) {
                    isok = false;
                    Dbprintf("reading mcu flash failed ::  | out of bounds, offset %u count %u", offset, count);
                }

                // Clip the length if it goes past the end of the flash memory.
                count = MIN(count, flash_size - offset);

            } else {
                // Allow reading from any memory address and length in special 'raw' mode.
                base = NULL;
                // Boundary check against end of addressable space.
                if (offset > 0) {
                    count = MIN(count, -offset);
                }
            }

            if (isok) {
                // CMD_READ_MEM_DOWNLOADED is an OLD frame, also served by bootrom.c.
                // Chunk by what reply_old can carry, not by the NG payload size.
                for (size_t pos = 0; pos < count; pos += PM3_CMD_DATA_SIZE_OLD) {
                    size_t len = MIN((count - pos), PM3_CMD_DATA_SIZE_OLD);
                    isok = (reply_old(CMD_READ_MEM_DOWNLOADED, pos, len, 0, &base[offset + pos], len) == PM3_SUCCESS);
                    if (isok == false) {
                        Dbprintf("transfer to client failed ::  | pos %u len %u", pos, len);
                        break;
                    }
                }
            }

            reply_old(CMD_ACK, 1, 0, 0, 0, 0);
            LED_B_OFF();
            break;
        }
#ifdef WITH_FLASH
        case CMD_SPIFFS_TEST: {
            test_spiffs();
            break;
        }
        case CMD_SPIFFS_CHECK: {
            rdv40_spiffs_check();
            break;
        }
        case CMD_SPIFFS_MOUNT: {
            rdv40_spiffs_lazy_mount();
            break;
        }
        case CMD_SPIFFS_UNMOUNT: {
            rdv40_spiffs_lazy_unmount();
            break;
        }
        case CMD_SPIFFS_PRINT_TREE: {
            rdv40_spiffs_safe_print_tree();
            break;
        }
        case CMD_SPIFFS_PRINT_FSINFO: {
            rdv40_spiffs_safe_print_fsinfo();
            break;
        }
        case CMD_SPIFFS_DOWNLOAD: {
            LED_B_ON();
            uint8_t filename[32];
            if (packet->length < sizeof(download_req_t)) {
                reply_ng(CMD_SPIFFS_DOWNLOAD, PM3_EINVARG, NULL, 0);
                break;
            }
            const download_req_t *dreq = (const download_req_t *)packet->data.asBytes;
            uint16_t fnlen = MIN((uint16_t)(packet->length - sizeof(download_req_t)), (uint16_t)SPIFFS_OBJ_NAME_LEN);
            memcpy(filename, dreq->data, fnlen);
            if (g_dbglevel >= DBG_DEBUG) Dbprintf("Filename received for spiffs dump : %s", filename);

            uint32_t size = dreq->bytes;

            uint8_t *buff = BigBuf_calloc(size);
            if (buff == NULL) {
                if (g_dbglevel >= DBG_DEBUG) Dbprintf("Failed to allocate memory");
                // Trigger a finish downloading signal with an PM3_EMALLOC
                reply_ng(CMD_SPIFFS_DOWNLOAD, PM3_EMALLOC, NULL, 0);
            } else {
                rdv40_spiffs_read_as_filetype((char *)filename, (uint8_t *)buff, size, RDV40_SPIFFS_SAFETY_SAFE);
                // arg0 = filename
                // arg1 = size
                // arg2 = RFU

                const size_t dl_chunk = reply_ng_max_data_size() - sizeof(download_chunk_t);
                for (size_t i = 0; i < size; i += dl_chunk) {
                    size_t len = MIN((size - i), dl_chunk);
                    int result = reply_download_chunk(CMD_SPIFFS_DOWNLOADED, i, buff + i, len);
                    if (result != PM3_SUCCESS)
                        Dbprintf("transfer to client failed ::  | bytes between %d - %d (%d) | result: %d", i, i + len, len, result);
                }
                // Trigger a finish downloading signal with an ACK frame
                reply_ng(CMD_SPIFFS_DOWNLOAD, PM3_SUCCESS, NULL, 0);
                BigBuf_free();
            }
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_STAT: {
            LED_B_ON();
            uint8_t filename[32];
            uint8_t *pfilename = packet->data.asBytes;
            memcpy(filename, pfilename, SPIFFS_OBJ_NAME_LEN);
            if (g_dbglevel >= DBG_DEBUG) {
                Dbprintf("Filename received for spiffs STAT : %s", filename);
            }

            int changed = rdv40_spiffs_lazy_mount();
            uint32_t size = size_in_spiffs((char *)filename);
            if (changed) {
                rdv40_spiffs_lazy_unmount();
            }

            reply_ng(CMD_SPIFFS_STAT, PM3_SUCCESS, (uint8_t *)&size, sizeof(uint32_t));
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_REMOVE: {
            LED_B_ON();

            struct p {
                uint8_t len;
                uint8_t fn[32];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            if (g_dbglevel >= DBG_DEBUG) {
                Dbprintf("Filename received for spiffs REMOVE : %s", payload->fn);
            }

            rdv40_spiffs_remove((char *)payload->fn, RDV40_SPIFFS_SAFETY_SAFE);
            reply_ng(CMD_SPIFFS_REMOVE, PM3_SUCCESS, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_RENAME: {
            LED_B_ON();
            struct p {
                uint8_t slen;
                uint8_t src[32];
                uint8_t dlen;
                uint8_t dest[32];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            if (g_dbglevel >= DBG_DEBUG) {
                Dbprintf("SPIFFS RENAME");
                Dbprintf("Source........ %s", payload->src);
                Dbprintf("Destination... %s", payload->dest);
            }
            rdv40_spiffs_rename((char *)payload->src, (char *)payload->dest, RDV40_SPIFFS_SAFETY_SAFE);
            reply_ng(CMD_SPIFFS_RENAME, PM3_SUCCESS, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_COPY: {
            LED_B_ON();
            struct p {
                uint8_t slen;
                uint8_t src[32];
                uint8_t dlen;
                uint8_t dest[32];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            if (g_dbglevel >= DBG_DEBUG) {
                Dbprintf("SPIFFS COPY");
                Dbprintf("Source........ %s", payload->src);
                Dbprintf("Destination... %s", payload->dest);
            }
            rdv40_spiffs_copy((char *)payload->src, (char *)payload->dest, RDV40_SPIFFS_SAFETY_SAFE);
            reply_ng(CMD_SPIFFS_COPY, PM3_SUCCESS, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_WRITE: {
            LED_B_ON();

            flashmem_write_t *payload = (flashmem_write_t *)packet->data.asBytes;

            if (g_dbglevel >= DBG_DEBUG) {
                Dbprintf("SPIFFS WRITE, dest `%s` with APPEND set to: %c", payload->fn, payload->append ? 'Y' : 'N');
            }

            if (payload->append) {
                rdv40_spiffs_append((char *) payload->fn, payload->data, payload->bytes_in_packet, RDV40_SPIFFS_SAFETY_SAFE);
            } else {
                rdv40_spiffs_write((char *) payload->fn, payload->data, payload->bytes_in_packet, RDV40_SPIFFS_SAFETY_SAFE);
            }

            reply_ng(CMD_SPIFFS_WRITE, PM3_SUCCESS, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_WIPE: {
            LED_B_ON();
            rdv40_spiffs_safe_wipe();
            reply_ng(CMD_SPIFFS_WIPE, PM3_SUCCESS, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_SPIFFS_ELOAD: {
            LED_B_ON();

            uint8_t *em = BigBuf_get_EM_addr();
            if (em == NULL) {
                if (g_dbglevel >= DBG_DEBUG) Dbprintf("Failed to allocate memory");
                reply_ng(CMD_SPIFFS_ELOAD, PM3_EMALLOC, NULL, 0);
                LED_B_OFF();
                break;
            }

            char *fn = (char *)packet->data.asBytes;

            uint32_t size = size_in_spiffs(fn);
            if (size == 0) {
                reply_ng(CMD_SPIFFS_ELOAD, PM3_SUCCESS, NULL, 0);
                LED_B_OFF();
                break;
            }

            rdv40_spiffs_read_as_filetype(fn, em, size, RDV40_SPIFFS_SAFETY_SAFE);
            reply_ng(CMD_SPIFFS_ELOAD, PM3_SUCCESS, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_SET_SPIBAUDRATE: {
            if (packet->length != sizeof(uint32_t))
                break;
            Flash_SetSpiBaudrate(packet->data.asDwords[0]);
            break;
        }
        case CMD_FLASHMEM_WRITE: {
            LED_B_ON();

            flashmem_old_write_t *payload = (flashmem_old_write_t *)packet->data.asBytes;

            if (FlashInit() == false) {
                reply_ng(CMD_FLASHMEM_WRITE, PM3_EIO, NULL, 0);
                LED_B_OFF();
                break;
            }

            if (payload->startidx == FLASH_MEM_SIGNATURE_OFFSET_P(spi_flash_pages64k)) {
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(spi_flash_pages64k - 1, 0xF);
            }

            uint16_t res = Flash_Write(payload->startidx, payload->data, payload->len);

            reply_ng(CMD_FLASHMEM_WRITE, (res == payload->len) ? PM3_SUCCESS : PM3_ESOFT, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_WIPE: {
            LED_B_ON();
            if (packet->length != sizeof(flashmem_wipe_t)) {
                reply_ng(CMD_FLASHMEM_WIPE, PM3_EINVARG, NULL, 0);
                LED_B_OFF();
                break;
            }
            flashmem_wipe_t *wpayload = (flashmem_wipe_t *)packet->data.asBytes;
            uint8_t page = wpayload->page;
            uint8_t initialwipe = wpayload->initialwipe;

            bool isok = false;
            if (initialwipe) {
                isok = Flash_WipeMemory();
                reply_ng(CMD_FLASHMEM_WIPE, (isok) ? PM3_SUCCESS : PM3_EFAILED, NULL, 0);
                LED_B_OFF();
                break;
            }

            if (page < spi_flash_pages64k - 1) {
                isok = Flash_WipeMemoryPage(page);
                // let spiffs check and update its info post flash erase
                rdv40_spiffs_check();
            }

            reply_ng(CMD_FLASHMEM_WIPE, (isok) ? PM3_SUCCESS : PM3_EFAILED, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_DOWNLOAD: {

            LED_B_ON();
            uint8_t *mem = BigBuf_calloc(PM3_CMD_DATA_SIZE);
            if (packet->length < sizeof(download_req_t)) {
                break;
            }
            const download_req_t *dreq = (const download_req_t *)packet->data.asBytes;
            uint32_t startidx = dreq->start_index;
            uint32_t numofbytes = dreq->bytes;
            // arg0 = startindex
            // arg1 = length bytes to transfer
            // arg2 = RFU

            if (FlashInit() == false) {
                break;
            }

            const size_t dl_chunk = reply_ng_max_data_size() - sizeof(download_chunk_t);
            for (size_t i = 0; i < numofbytes; i += dl_chunk) {
                size_t len = MIN((numofbytes - i), dl_chunk);
                Flash_CheckBusy(BUSY_TIMEOUT);
                uint16_t isok = Flash_ReadDataCont(startidx + i, mem, len);
                if (isok == false) {
                    Dbprintf("reading flash memory failed with bytes between %d - %d", i, len);
                }
                isok = reply_download_chunk(CMD_FLASHMEM_DOWNLOADED, i, mem, len);

                if (isok != PM3_SUCCESS) {
                    Dbprintf("transfer to client failed with bytes between %d - %d", i, len);
                }
            }
            FlashStop();

            reply_download_done(CMD_FLASHMEM_DOWNLOAD, numofbytes, 0);
            BigBuf_free();
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_GET_SIGNATURE: {

            LED_B_ON();

            rdv40_validation_t *info = (rdv40_validation_t *)BigBuf_calloc(sizeof(rdv40_validation_t));

            // returns 0 when failing
            uint16_t isok = Flash_ReadData(FLASH_MEM_SIGNATURE_OFFSET_P(spi_flash_pages64k), info->signature, FLASH_MEM_SIGNATURE_LEN);

            // re-init since command above calls FlashStop()
            if (isok && FlashInit()) {
                Flash_UniqueID(info->flashid);
                FlashStop();
            }

            reply_ng(CMD_FLASHMEM_GET_SIGNATURE, (isok) ? PM3_SUCCESS : PM3_EFLASH, (uint8_t *)info, sizeof(rdv40_validation_t));
            BigBuf_free();

            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_GET_INFO: {
            LED_B_ON();
            spi_flash_t *spi = flash_get_info();
            reply_ng(CMD_FLASHMEM_GET_INFO, PM3_SUCCESS, (uint8_t *)spi, sizeof(spi_flash_t));
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_PAGES64K: {

            LED_B_ON();

            bool isok = FlashInit();
            if (isok) {
                if (g_dbglevel >= DBG_DEBUG) {
                    Dbprintf("  CMD_FLASHMEM_PAGE64K 0x%02x (%d 64k pages)", spi_flash_pages64k, spi_flash_pages64k);
                }
                FlashStop();
            }
            reply_ng(CMD_FLASHMEM_PAGES64K, (isok) ? PM3_SUCCESS : PM3_EFLASH, &spi_flash_pages64k, sizeof(uint8_t));

            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_GET_ID: {
            uint64_t flash_uniqueID = 0;
            bool isok = FlashInit();
            if (isok) {
                isok = Flash_UniqueID((uint8_t *)(&flash_uniqueID));
                FlashStop();
            }
            reply_ng(CMD_FLASHMEM_GET_ID, (isok) ? PM3_SUCCESS : PM3_EFLASH, (uint8_t *)&flash_uniqueID, sizeof(flash_uniqueID));
            break;
        }
#endif
#ifdef WITH_LF
        case CMD_LF_SET_DIVISOR: {
            FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
            FpgaSendCommand(FPGA_CMD_SET_DIVISOR, packet->data.asBytes[0]);
            break;
        }
#endif
        case CMD_SET_ADC_MUX: {
            switch (packet->data.asBytes[0]) {
                case 0:
                    SetAdcMuxFor(ADC_MUXSEL_LOPKD);
                    break;
                case 2:
                    SetAdcMuxFor(ADC_MUXSEL_HIPKD);
                    break;
#ifndef WITH_FPC_USART
                case 1:
                    SetAdcMuxFor(ADC_MUXSEL_LORAW);
                    break;
                case 3:
                    SetAdcMuxFor(ADC_MUXSEL_HIRAW);
                    break;
#endif
            }
            break;
        }
        case CMD_VERSION: {
            SendVersion();
            break;
        }
        case CMD_STATUS: {
            if (packet->length == 4)
                SendStatus(packet->data.asDwords[0]);
            else
                SendStatus(CONN_SPEED_TEST_MIN_TIME_DEFAULT);
            break;
        }
        case CMD_TIA: {
#ifdef CHIP_AT91SAM7S
            while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
            uint16_t mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;
            Dbprintf("  Slow clock old measured value:.........%d Hz", (16 * MAINCK) / mainf);
            TimingIntervalAcquisition();

            while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
            mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;
            Dbprintf(""); // first message gets lost
            Dbprintf("  Slow clock new measured value:.........%d Hz", (16 * MAINCK) / mainf);
            reply_ng(CMD_TIA, PM3_SUCCESS, NULL, 0);
#else
            Dbprintf("Chip is not AT91SAM7S, TIA is " _RED_("unsupported"));
            reply_ng(CMD_TIA, PM3_EDEVNOTSUPP, NULL, 0);
#endif
            break;
        }
        case CMD_STANDALONE: {

            struct p {
                uint8_t arg;
                uint8_t mlen;
                uint8_t mode[10];
            } PACKED;

            struct p *payload = (struct p *) packet->data.asBytes;

            uint8_t *bb = BigBuf_get_EM_addr();
            if (payload->mlen == 0) {
                bb[0] = payload->arg;
            } else {
                memcpy(bb, payload->mode, payload->mlen);
            }

            RunMod();
            break;
        }
        case CMD_CAPABILITIES: {
            SendCapabilities();
            break;
        }
        case CMD_PING: {
            reply_ng(CMD_PING, PM3_SUCCESS, packet->data.asBytes, packet->length);
            break;
        }
#ifdef WITH_LCD
        case CMD_LCD_RESET: {
            LCDReset();
            break;
        }
        case CMD_LCD: {
            if (packet->length != sizeof(lcd_cmd_t)) {
                break;
            }
            LCDSend(((lcd_cmd_t *)packet->data.asBytes)->cmd);
            break;
        }
#endif
        case CMD_FINISH_WRITE:
        case CMD_HARDWARE_RESET: {
            usb_disable();

            // (iceman) why this wait?
            SpinDelay(1000); // Go wait for the USB to completely go offline on the host side.
            ResetChip();
            // We're going to reset, and the bootrom will take control.
            for (;;) {}
            break;
        }
        case CMD_START_FLASH: {
            if (g_common_area.flags.bootrom_present) {
                g_common_area.command = COMMON_AREA_COMMAND_ENTER_FLASH_MODE;
            }
            usb_disable();
            ResetChip();
            // We're going to flash, and the bootrom will take control.
            for (;;) {}
            break;
        }
        case CMD_DEVICE_INFO: {
            uint32_t dev_info = DEVICE_INFO_FLAG_OSIMAGE_PRESENT | DEVICE_INFO_FLAG_CURRENT_MODE_OS;
            if (g_common_area.flags.bootrom_present) {
                dev_info |= DEVICE_INFO_FLAG_BOOTROM_PRESENT;
            }
            reply_old(CMD_DEVICE_INFO, dev_info, 0, 0, 0, 0);
            break;
        }
        case CMD_FPGA_BITSTREAM_CONFIG_START: // Merge 3 cmds to reuse some code.
        case CMD_FPGA_BITSTREAM_CONFIG_WRITE:
        case CMD_FPGA_BITSTREAM_CONFIG_FINISH: {
            // Dbprintf("Received FPGA config command 0x%04x", packet->cmd);
            int res;
            // Process
            if (packet->cmd == CMD_FPGA_BITSTREAM_CONFIG_START) {
                struct p {
                    uint8_t sram_mode;
                    uint32_t file_length;
                } PACKED;
                struct p *payload = (struct p *) packet->data.asBytes;
                res = FpgaStartConfig(payload->sram_mode, payload->file_length);
            } else if (packet->cmd == CMD_FPGA_BITSTREAM_CONFIG_WRITE) {
                res = FpgaConfigWrite(packet->data.asBytes, packet->length);
            } else {
                res = FpgaStopConfig();
            }
            // Response
            if (res == PM3_EFAILED) {
                uint32_t plat_status = FpgaConfigPlatformStatus(); // Return status code of platform when res is PM3_EFAILED
                reply_ng(packet->cmd, res, (uint8_t *)&plat_status, sizeof(plat_status));
            } else {
                reply_ng(packet->cmd, res, NULL, 0);
            }
            break;
        }
#ifdef PM5
        case CMD_ANT_CONTROL_WRITE: {
            struct p {
                uint8_t data;
                uint8_t reg_type; // 0 is io reg, 1 is map reg.
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            StartTicks();
            I2C_init(true);

            uint8_t addr = 0x51; // TODO DXL define move to header?
            uint8_t cmd = payload->reg_type == 0 ? 0x01 : 0x02;

            bool isok = I2C_BufferWrite(&payload->data, 1, cmd, addr << 1);
            reply_ng(CMD_ANT_CONTROL_WRITE, isok ? PM3_SUCCESS : PM3_EFAILED, NULL, 0);
            break;
        }
        case CMD_ANT_CONTROL_READ: {
            struct p {
                uint8_t reg_type; // 0 is io reg, 1 is map reg.
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            StartTicks();
            I2C_init(true);

            uint8_t addr = 0x51; // TODO DXL define move to header?
            uint8_t cmd = payload->reg_type == 0 ? 0x01 : 0x02;
            uint8_t data;

            bool isok = I2C_BufferReadRaw(&data, 1, cmd, addr << 1);
            reply_ng(CMD_ANT_CONTROL_READ, isok ? PM3_SUCCESS : PM3_EFAILED, &data, sizeof(data));
            break;
        }
        case CMD_EEPROM_FACTORY_INFO_READ: {
            StartTicks();
            I2C_init(true);

            uint8_t addr = 0x50; // TODO DXL define move to header?
            uint8_t data[256]; // 24c02: 256byte
            bool isok = I2C_BufferReadRaw(data, sizeof(data), 0x00, addr << 1);
            reply_ng(CMD_EEPROM_FACTORY_INFO_READ, isok ? PM3_SUCCESS : PM3_EFAILED, data, sizeof(data));
            break;
        }
        case CMD_EEPROM_FACTORY_INFO_WRITE: {
            StartTicks();
            I2C_init(true);

            uint8_t addr = 0x50; // TODO DXL define move to header?
            uint16_t len = packet->length;
            while (len) {
                uint16_t write_len = MIN(len, 16);
                uint16_t write_pos = packet->length - len;
                bool isok = I2C_BufferWrite(packet->data.asBytes + write_pos, write_len, write_pos, addr << 1);
                if (!isok) {
                    reply_ng(CMD_EEPROM_FACTORY_INFO_WRITE, PM3_EFAILED, NULL, 0);
                    return;
                }
                len -= write_len;
                // 24C02 writes to a page write buffer of only 16 bytes.
                // If the write speed is too fast, it may cause data write failure.
                // Therefore, a delay or ACK judgment is required between page writes
                SpinDelay(5); // 24C02 write cycle time is about 5ms
            }
            reply_ng(CMD_EEPROM_FACTORY_INFO_WRITE, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_PM5_FPGA_SET_PWR_PWM_LOW_COUNT: {
            struct p {
                uint8_t is_lf;
                uint16_t count;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            FpgaDownloadAndGo(payload->is_lf ? FPGA_BITSTREAM_LF : FPGA_BITSTREAM_HF);
            FpgaSendCommand(FPGA_CMD_SET_PWR_PWM_LOW_COUNT, payload->count & 0xFFF);
            reply_ng(CMD_PM5_FPGA_SET_PWR_PWM_LOW_COUNT, PM3_SUCCESS, NULL, 0);
            break;
        }
#endif
        case CMD_MAIN_CHIP_UNIQUEID: {
            uint8_t size = 0;
            uint8_t *uid = GetChipUniqueId(&size);
            reply_ng(CMD_MAIN_CHIP_UNIQUEID, PM3_SUCCESS, uid, size);
            break;
        }
#ifdef PM5
        case CMD_PM5_QC_TEST_HW: {
            uint8_t failed_item = 0;
            uint32_t timeout_ms = 0;
            if (packet->length >= sizeof(timeout_ms)) {
                memcpy(&timeout_ms, packet->data.asBytes, sizeof(timeout_ms));
            }
            reply_ng(CMD_PM5_QC_TEST_HW, QCTestPM5(&failed_item, timeout_ms) ? PM3_SUCCESS : PM3_EFAILED, &failed_item, 1);
            break;
        }
        case CMD_PM5_QC_TEST_IO: {
            struct p {
                uint32_t pwd;   // 0xDEADBEEF
                uint16_t index; // index of the IO to test
                uint8_t status; // 0 = low, 1 = high, 2 = float or RESET TO DEFAULT
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            // !!! IMPORTANT !!!
            // This password must not be written in the client software.
            // Users should never use this command without knowing its purpose, otherwise it may damage the device.
            if (payload->pwd != 0xDEADBEEF) {
                reply_ng(CMD_PM5_QC_TEST_IO, PM3_EFAILED, NULL, 0);
                break;
            }
            reply_ng(CMD_PM5_QC_TEST_IO, QCTestPM5IO(payload->index, payload->status), NULL, 0);
            break;
        }
        case CMD_PM5_RGB_SET: {
            // Set the antenna RGB LED colour (used by `hf/lf tune --rgb`).
            struct p {
                uint8_t r;
                uint8_t g;
                uint8_t b;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
            RgbLedSet(payload->r, payload->g, payload->b);
#ifdef WITH_PM5_PWR_LED
            // tune (or any external RGB user) now owns the LED; back the power
            // indicator off. A non-zero colour claims it; all-zero releases it.
            rgb_indicator_set_external(payload->r || payload->g || payload->b);
#endif
            reply_ng(CMD_PM5_RGB_SET, PM3_SUCCESS, NULL, 0);
            break;
        }
#ifdef WITH_BWM_STATUS
        case CMD_PM5_BWM_SET_VCHG: {
            // Set the AW32001E charge-voltage target (REG04 VBAT_REG).
            // Payload: optional uint16 mV (LE); absent -> default.
            uint16_t mv = (packet->length >= 2)
                          ? (uint16_t)(packet->data.asBytes[0] | (packet->data.asBytes[1] << 8))
                          : BWM_DEFAULT_VCHG_MV;
            I2C_init(true);
            uint16_t applied = bwm_charger_set_vchg(mv);
            reply_ng(CMD_PM5_BWM_SET_VCHG, applied ? PM3_SUCCESS : PM3_EFAILED, (uint8_t *)&applied, sizeof(applied));
            break;
        }
        case CMD_PM5_BWM_SET_CAP: {
            // One-time BWM fuel-gauge (BQ27427) Design Capacity provisioning.
            // Payload: optional uint16 mAh (LE); absent -> reference default.
            uint16_t cap = (packet->length >= 2)
                           ? (uint16_t)(packet->data.asBytes[0] | (packet->data.asBytes[1] << 8))
                           : BWM_DEFAULT_DESIGN_CAP_MAH;
            I2C_init(true);
            bool ok = bwm_gauge_provision_capacity(cap);
            reply_ng(CMD_PM5_BWM_SET_CAP, ok ? PM3_SUCCESS : PM3_EFAILED, (uint8_t *)&cap, sizeof(cap));
            break;
        }
        case CMD_PM5_BWM_CHARGE_EN: {
            // Enable/disable battery charging (clear/set AW32001E CEB, REG01[3]).
            // Payload: 1 byte, non-zero = enable (default), zero = disable.
            // One-shot: reverts on the charger watchdog timeout (~160 s).
            bool enable = (packet->length >= 1) ? (packet->data.asBytes[0] != 0) : true;
            I2C_init(true);
            bool ok = bwm_charger_set_charge(enable);
            reply_ng(CMD_PM5_BWM_CHARGE_EN, ok ? PM3_SUCCESS : PM3_EFAILED, NULL, 0);
            break;
        }

        case CMD_PM5_BWM_WIFI: {
#if defined(WITH_BWM_FORWARD)
            uint8_t action = packet->data.asBytes[0];
            uint32_t ip = 0;
            int res;
            if (action == BWM_WIFI_ACTION_STOP) {
                res = bwm_wifi_forward_down();
                reply_ng(CMD_PM5_BWM_WIFI, res, (uint8_t *)&ip, sizeof(ip));
            } else if (action == BWM_WIFI_ACTION_STATUS) {
                uint8_t state = 0;
                res = bwm_wifi_forward_status(&state, &ip);
                uint8_t st[5] = { state,
                                  (uint8_t)(ip & 0xFF), (uint8_t)((ip >> 8) & 0xFF),
                                  (uint8_t)((ip >> 16) & 0xFF), (uint8_t)((ip >> 24) & 0xFF) };
                reply_ng(CMD_PM5_BWM_WIFI, res, st, sizeof(st));
            } else {
                uint16_t port = packet->data.asBytes[1] | (packet->data.asBytes[2] << 8);
                char *ssid = (char *)&packet->data.asBytes[3];
                char *pwd  = ssid + strlen(ssid) + 1;
                char *host = pwd + strlen(pwd) + 1;
                res = bwm_wifi_forward_up(ssid, pwd, host, port, &ip);
                reply_ng(CMD_PM5_BWM_WIFI, res, (uint8_t *)&ip, sizeof(ip));
            }
#else
            reply_ng(CMD_PM5_BWM_WIFI, PM3_ENOTIMPL, NULL, 0);
#endif
            break;
        }
        case CMD_PM5_BWM_ESP_OTA: {
            // ESP32 OTA over the existing BWM app_com link (see bwm_wifi.c).
            // Payload: [action:u8] + action-specific data.
            //   BEGIN: u32 LE total image size
            //   WRITE: firmware chunk
            //   END:   (no payload) finalize + set boot partition
#if defined(WITH_BWM_FORWARD)
            uint8_t action = packet->data.asBytes[0];
            int res = PM3_EINVARG;
            bool replied = false;
            switch (action) {
                case BWM_OTA_ACTION_VERSION: {
                    // Return the running ESP firmware version string so the client
                    // can confirm an update actually took (esp. when the finalize
                    // ack is lost). Replies here with a payload, unlike the others.
                    uint8_t ver[64];
                    uint16_t vlen = sizeof(ver);
                    res = bwm_esp_get_version(ver, &vlen);
                    reply_ng(CMD_PM5_BWM_ESP_OTA, res, ver, (res == PM3_SUCCESS) ? vlen : 0);
                    replied = true;
                    break;
                }
                case BWM_OTA_ACTION_BEGIN: {
                    uint32_t total_size = 0;
                    if (packet->length >= 5) {
                        memcpy(&total_size, packet->data.asBytes + 1, sizeof(total_size));
                    }
                    res = bwm_esp_ota_begin(total_size);
                    break;
                }
                case BWM_OTA_ACTION_WRITE:
                    // Defensive: bwm_esp_ota_write()'s app_com frame buffer caps a
                    // single chunk at BWM_OTA_CHUNK_MAX (see bwm_wifi.c: bwm_cmd()).
                    // The client is expected to respect this, but fail explicitly
                    // here rather than let bwm_cmd() silently overflow/reject.
                    if (packet->length - 1 > BWM_OTA_CHUNK_MAX) {
                        res = PM3_EOVFLOW;
                    } else {
                        res = bwm_esp_ota_write(packet->data.asBytes + 1, packet->length - 1);
                    }
                    break;
                case BWM_OTA_ACTION_END:
                    res = bwm_esp_ota_end();
                    if (res == PM3_SUCCESS) {
                        // Finalize succeeded and the new partition is now marked
                        // bootable; the ESP won't switch to it on its own, so
                        // kick the reboot here (DEV.md 12.8). Best-effort: don't
                        // fail the whole OTA over a lost reboot ack.
                        (void)bwm_esp_reboot();
                    }
                    break;
                case BWM_OTA_ACTION_ABORT:
                    res = bwm_esp_ota_abort();
                    break;
                default:
                    res = PM3_EINVARG;
                    break;
            }
            if (replied == false) {
                reply_ng(CMD_PM5_BWM_ESP_OTA, res, NULL, 0);
            }
#else
            reply_ng(CMD_PM5_BWM_ESP_OTA, PM3_ENOTIMPL, NULL, 0);
#endif
            break;
        }
        case CMD_PM5_BWM_AUTOOFF: {
            // Toggle automatic power-off on USB unplug (runtime, default on).
            // Payload: 1 byte, non-zero = enable (default), zero = disable.
#ifdef WITH_PM5_AUTOOFF
            g_autooff_enabled = (packet->length >= 1) ? (packet->data.asBytes[0] != 0) : true;
            reply_ng(CMD_PM5_BWM_AUTOOFF, PM3_SUCCESS, (uint8_t *)&g_autooff_enabled, 1);
#else
            reply_ng(CMD_PM5_BWM_AUTOOFF, PM3_ENOTIMPL, NULL, 0);
#endif
            break;
        }
#endif
#endif
        default: {
            Dbprintf("%s: 0x%04x", "unknown command:", packet->cmd);
            break;
        }
    }
}

void __attribute__((noreturn)) AppMain(void) {

    SpinDelay(100);
    BigBuf_initialize();

    // Add stack canary
    for (uint32_t *p = _stack_start; p + 0x200 < _stack_end ; ++p) {
        *p = 0xdeadbeef;
    }

    LEDsoff();

    // Setup FPGA clock & Reset COM
    FpgaSetup24MHzClk();
    FpgaResetComInterface();

    // Configure MUX
    SetAdcMuxFor(ADC_MUXSEL_HIPKD);

    // Load the FPGA image, which we have stored in our flash.
    // (the HF version by default)
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    StartTickCount();
    uint32_t last_activity_tick = GetTickCount();
    uint32_t last_activity_label = GetTickCountLabel();

#ifdef WITH_LCD
    LCDInit();
#endif

#ifdef WITH_SMARTCARD
    I2C_init(false);
#endif

#ifdef WITH_FLASH
    if (FlashInit()) {
        uint64_t flash_uniqueID = 0;
        if (!Flash_CheckBusy(BUSY_TIMEOUT)) { // OK because firmware was built for devices with flash
            Flash_UniqueID((uint8_t *)(&flash_uniqueID));
        }
        FlashStop();
        usb_update_serial(flash_uniqueID);
    }
#endif

#ifdef WITH_FLASH
    // If flash is not present, BUSY_TIMEOUT kicks in, let's do it after USB
    loadT55xxConfig();

    // Enforce a spiffs check/garbage collection at boot so we are likely to never
    // fall under the 2 contigous free blocks availables
    // This is a time-consuming process on large flash.
    rdv40_spiffs_check();
#endif

#ifdef WITH_FPC_USART
    usart_init(USART_BAUD_RATE, USART_PARITY);
#endif

    allow_send_wtx = true;

    // This is made as late as possible to ensure enumeration without timeout
    // against device such as http://www.hobbytronics.co.uk/usb-host-board-v2
    // In other words, keep the interval between usb_enable() and the main loop as short as possible.
    // (AT91F_CDC_Enumerate() will be called in the main loop)
    usb_disable();
    usb_enable();
#ifdef WITH_BWM_STATUS
    bwm_detect_and_init();   // probe BWM + apply charge config, off the pre-USB path
#endif

#ifdef WITH_BWM_FORWARD
    bwm_uart_init();         // AT32 UART4 <-> BWM app_com link; AFTER usb_enable()
    // Negotiate the link up from the boot baud; harmless no-op if the ESP is
    // older or the target is unreachable (stays at BWM_UART_BAUD).
    bwm_fwd_negotiate_baud(BWM_UART_BAUD_TARGET);
#endif

#ifdef WITH_BWM_CHARGERKICK
    bwm_charger_kick();
#endif

    for (;;) {
        WDT_HIT();

#ifdef WITH_PM5_PWR_LED
        rgb_indicator_update();
#endif
#ifdef WITH_PM5_AUTOOFF
        bwm_autooff_check();
#endif
#ifdef WITH_BWM_LOWBATT_BEEP
        bwm_lowbatt_check();
#endif

        if (*_stack_start != 0xdeadbeef) {
            Dbprintf("DEBUG: increase stack size, currently " _YELLOW_("%d") " bytes", (uint32_t)_stack_end - (uint32_t)_stack_start);
            Dbprintf("Stack overflow detected");
            Dbprintf("--> Unplug your device now! <--");
            hf_field_off();
            while (1);
        }

        // Check if there is a packet available
        PacketCommandNG rx;
        memset(&rx.data, 0, sizeof(rx.data));

        int ret = receive_ng(&rx);
        if (ret == PM3_SUCCESS) {
            PacketReceived(&rx);
            last_activity_label = GetTickCountLabel();
            last_activity_tick = GetTickCount();
        } else if (ret != PM3_ENODATA) {
            Dbprintf("Error in frame reception: %d %s", ret, (ret == PM3_EIO) ? "PM3_EIO" : "");
            // TODO if error, shall we resync ?
        }

        if (g_hf_field_activity_timeout_ms > 0 && g_hf_field_timeout_active) {
            uint32_t tickcount_label = GetTickCountLabel();
            if (tickcount_label != last_activity_label) {
                last_activity_label = tickcount_label;
                last_activity_tick = GetTickCount();
            } else if (GetTickCountDelta(last_activity_tick) >= g_hf_field_activity_timeout_ms) {
                hf_field_off();
                Dbprintf("HF field auto-off: inactivity timeout (%u ms). To disable, use 'prefs set hf.field.timeout_sec --sec 0'", g_hf_field_activity_timeout_ms);
            }
        }

        // Press button for one second to enter a possible standalone mode
        button_status = BUTTON_HELD(1000);
        if (button_status == BUTTON_HOLD) {
            /*
            * So this is the trigger to execute a standalone mod.  Generic entrypoint by following the standalone/standalone.h headerfile
            * All standalone mod "main loop" should be the RunMod() function.
            */
#ifndef PM5
            allow_send_wtx = false;
            RunMod();
            allow_send_wtx = true;
#else // TODO DXL Test long press to device shutdown, temporarily blocking standalone mod

            /*
            StartTicks();
            I2C_init(true);
            uint8_t addr = 0x51;
            // 125 134 250 375 500 HFLED LFLED Q
            // 1 0 0 0 0 1 1 1
            uint8_t data = 0x87;
            I2C_BufferWrite(&data, 1, 0x02, addr << 1);
            FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
            FpgaSendCommand(FPGA_CMD_SET_PWR_PWM_LOW_COUNT, 4095);

            static bool b = 0;
            if (b) {
                FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                b = 0;
            } else {
                FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
                FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER | FPGA_LF_ADC_READER_FIELD);
                FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125);
                b = 1;
            }
            */

            LEDsoff();
            while (BUTTON_PRESS()) {
                SpinDelay(50);
                LED_A_INV();
                SpinDelay(50);
                LED_B_INV();
                SpinDelay(50);
                LED_C_INV();
                SpinDelay(50);
                LED_D_INV();
            }
            // Release for more than 100ms before truly shutting down, anti shake
            uint8_t idx = 0;
            while (!BUTTON_PRESS()) {
                SpinDelay(10);
                idx += 1;
                if (idx == 10) {
                    break;
                }
            }
            LEDsoff();
            if (idx == 10) {
                SpinDelay(100);
                LED_A_INV();
                SpinDelay(100);
                LED_A_INV();
                SpinDelay(100);
                LED_A_INV();
                Gpio_ARM_Power_ON_Low();
                while (1); // Wait for system power off.
            }

#endif
        }
    }
}
