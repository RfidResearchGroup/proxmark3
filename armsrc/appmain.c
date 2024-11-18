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

#include "clocks.h"
#include "usb_cdc.h"
#include "proxmark3_arm.h"
#include "dbprint.h"
#include "pmflash.h"
#include "fpga.h"
#include "fpgaloader.h"
#include "string.h"
#include "printf.h"
#include "legicrf.h"
#include "BigBuf.h"
#include "iclass_cmd.h"
#include "hfops.h"
#include "iso14443a.h"
#include "iso14443b.h"
#include "iso15693.h"
#include "thinfilm.h"
#include "felica.h"
#include "hitag2.h"
#include "hitag2_crack.h"
#include "hitagS.h"
#include "em4x50.h"
#include "em4x70.h"
#include "iclass.h"
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
#include "ticks.h"
#include "commonutil.h"
#include "crc16.h"
#include "protocols.h"
#include "mifareutil.h"
#include "sam_picopass.h"
#include "sam_seos.h"
#include "sam_mfc.h"

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
extern uint32_t _stack_start[], _stack_end[];
common_area_t g_common_area __attribute__((section(".commonarea")));
static int button_status = BUTTON_NO_CLICK;
static bool allow_send_wtx = false;
uint16_t g_tearoff_delay_us = 0;
bool g_tearoff_enabled = false;

int tearoff_hook(void) {
    if (g_tearoff_enabled) {
        if (g_tearoff_delay_us == 0) {
            Dbprintf(_RED_("No tear-off delay configured!"));
            return PM3_SUCCESS; // SUCCESS = the hook didn't do anything
        }
        SpinDelayUsPrecision(g_tearoff_delay_us);
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        g_tearoff_enabled = false;
        Dbprintf(_YELLOW_("Tear-off triggered!"));
        return PM3_ETEAROFF;
    } else {
        return PM3_SUCCESS;     // SUCCESS = the hook didn't do anything
    }
}

void hf_field_off(void) {
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    g_hf_field_active = false;
}

void send_wtx(uint16_t wtx) {
    if (allow_send_wtx) {
        reply_ng(CMD_WTX, PM3_SUCCESS, (uint8_t *)&wtx, sizeof(wtx));
    }
}

//-----------------------------------------------------------------------------
// Read an ADC channel and block till it completes, then return the result
// in ADC units (0 to 1023). Also a routine to sum up a number of samples and
// return that.
//-----------------------------------------------------------------------------
static uint16_t ReadAdc(uint8_t ch) {

    // Note: ADC_MODE_PRESCALE and ADC_MODE_SAMPLE_HOLD_TIME are set to the maximum allowed value.
    // AMPL_HI is are high impedance (10MOhm || 1MOhm) output, the input capacitance of the ADC is 12pF (typical). This results in a time constant
    // of RC = (0.91MOhm) * 12pF = 10.9us. Even after the maximum configurable sample&hold time of 40us the input capacitor will not be fully charged.
    //
    // The maths are:
    // If there is a voltage v_in at the input, the voltage v_cap at the capacitor (this is what we are measuring) will be
    //
    //       v_cap = v_in * (1 - exp(-SHTIM/RC))  =   v_in * (1 - exp(-40us/10.9us))  =  v_in * 0,97                   (i.e. an error of 3%)

    AT91C_BASE_ADC->ADC_CR = AT91C_ADC_SWRST;
    AT91C_BASE_ADC->ADC_MR =
        ADC_MODE_PRESCALE(63)          // ADC_CLK = MCK / ((63+1) * 2) = 48MHz / 128 = 375kHz
        | ADC_MODE_STARTUP_TIME(1)       // Startup Time = (1+1) * 8 / ADC_CLK = 16 / 375kHz = 42,7us   Note: must be > 20us
        | ADC_MODE_SAMPLE_HOLD_TIME(15); // Sample & Hold Time SHTIM = 15 / ADC_CLK = 15 / 375kHz = 40us

    AT91C_BASE_ADC->ADC_CHER = ADC_CHANNEL(ch);
    AT91C_BASE_ADC->ADC_CR = AT91C_ADC_START;

    while (!(AT91C_BASE_ADC->ADC_SR & ADC_END_OF_CONVERSION(ch))) {};

    return (AT91C_BASE_ADC->ADC_CDR[ch] & 0x3FF);
}

// was static - merlok
uint16_t AvgAdc(uint8_t ch) {
    return SumAdc(ch, 32) >> 5;
}

uint16_t SumAdc(uint8_t ch, uint8_t NbSamples) {
    uint16_t a = 0;
    for (uint8_t i = 0; i < NbSamples; i++)
        a += ReadAdc(ch);
    return (a + (NbSamples >> 1) - 1);
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
        uint32_t adcval = ((MAX_ADC_LF_VOLTAGE * (SumAdc(ADC_CHAN_LF, 32) >> 1)) >> 14);
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

    payload.v_hf = (MAX_ADC_HF_VOLTAGE * SumAdc(ADC_CHAN_HF, 32)) >> 15;

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    reply_ng(CMD_MEASURE_ANTENNA_TUNING, PM3_SUCCESS, (uint8_t *)&payload, sizeof(payload));
    LEDsoff();
}
#endif
// Measure HF in milliVolt
static uint16_t MeasureAntennaTuningHfData(void) {

    return (MAX_ADC_HF_VOLTAGE * SumAdc(ADC_CHAN_HF, 32)) >> 15;

}

// Measure LF in milliVolt
static uint32_t MeasureAntennaTuningLfData(void) {
    return (MAX_ADC_LF_VOLTAGE * (SumAdc(ADC_CHAN_LF, 32) >> 1)) >> 14;
}

void print_stack_usage(void) {
    for (uint32_t *p = _stack_start; ; ++p) {
        if (*p != 0xdeadbeef) {
            Dbprintf("  Max stack usage......... %d / %d bytes", (uint32_t)_stack_end - (uint32_t)p, (uint32_t)_stack_end - (uint32_t)_stack_start);
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
static void SendVersion(void) {
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
        FormatVersionInformation(temp, sizeof(temp), "  bootrom: ", bootrom_version);
        strncat(VersionString, temp, sizeof(VersionString) - strlen(VersionString) - 1);
        strncat(VersionString, "\n", sizeof(VersionString) - strlen(VersionString) - 1);
    }


    FormatVersionInformation(temp, sizeof(temp), "       os: ", &g_version_information);
    strncat(VersionString, temp, sizeof(VersionString) - strlen(VersionString) - 1);
    strncat(VersionString, "\n", sizeof(VersionString) - strlen(VersionString) - 1);

#if defined(__clang__)
    strncat(VersionString, "  compiled with Clang/LLVM "__VERSION__"\n", sizeof(VersionString) - strlen(VersionString) - 1);
#elif defined(__GNUC__) || defined(__GNUG__)
    strncat(VersionString, "  compiled with GCC "__VERSION__"\n", sizeof(VersionString) - strlen(VersionString) - 1);
#endif

    strncat(VersionString, "\n [ "_YELLOW_("FPGA")" ] \n ", sizeof(VersionString) - strlen(VersionString) - 1);

    for (int i = 0; i < g_fpga_bitstream_num; i++) {
        strncat(VersionString, g_fpga_version_information[i].versionString, sizeof(VersionString) - strlen(VersionString) - 1);
        if (i < g_fpga_bitstream_num - 1) {
            strncat(VersionString, "\n ", sizeof(VersionString) - strlen(VersionString) - 1);
        }
    }
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
    payload.id = *(AT91C_DBGU_CIDR);
#ifndef WITH_COMPRESSION
    payload.section_size = (uint32_t)_bootrom_end - (uint32_t)_bootrom_start + (uint32_t)__os_size__;
#else
    payload.section_size = text_and_rodata_section_size + compressed_data_section_size;
#endif
    payload.versionstr_len = strlen(VersionString) + 1;
    memcpy(payload.versionstr, VersionString, payload.versionstr_len);

    reply_ng(CMD_VERSION, PM3_SUCCESS, (uint8_t *)&payload, 12 + payload.versionstr_len);
}

static void TimingIntervalAcquisition(void) {
    // trigger new acquisition by turning main oscillator off and on
    mck_from_pll_to_slck();
    mck_from_slck_to_pll();
    // wait for MCFR and recompute RTMR scaler
    StartTickCount();
}

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
    Dbprintf("  Debug log level......... %d ( " _YELLOW_("%s")" )", g_dbglevel, dbglvlstr);
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

    LED_B_ON();

    while (delta_time < wait) {
        reply_ng(CMD_DOWNLOADED_BIGBUF, PM3_SUCCESS, test_data, PM3_CMD_DATA_SIZE);
        bytes_transferred += PM3_CMD_DATA_SIZE;
        delta_time = GetTickCountDelta(start_time);
    }
    LED_B_OFF();

    Dbprintf("  Time elapsed................... %dms", delta_time);
    Dbprintf("  Bytes transferred.............. %d", bytes_transferred);
    if (delta_time) {
        Dbprintf("  Transfer Speed PM3 -> Client... " _YELLOW_("%llu") " bytes/s", 1000 * (uint64_t)bytes_transferred / delta_time);
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
    printConnSpeed(wait);
    DbpString(_CYAN_("Various"));

    print_stack_usage();
    print_debug_level();

    tosend_t *ts = get_tosend();
    Dbprintf("  ToSendMax............... %d", ts->max);
    Dbprintf("  ToSend BUFFERSIZE....... %d", TOSEND_BUFFER_SIZE);
    while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
    uint16_t mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;       // Get # main clocks within 16 slow clocks
    Dbprintf("  Slow clock.............. %d Hz", (16 * MAINCK) / mainf);
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
    DbpString(_CYAN_("Installed StandAlone Mode"));
    ModInfo();

#ifdef WITH_FLASH
    Flashmem_print_info();
#endif
    DbpString("");
    reply_ng(CMD_STATUS, PM3_SUCCESS, NULL, 0);
}

static void SendCapabilities(void) {
    capabilities_t capabilities;
    capabilities.version = CAPABILITIES_VERSION;
    capabilities.via_fpc = g_reply_via_fpc;
    capabilities.via_usb = g_reply_via_usb;
    capabilities.bigbuf_size = BigBuf_get_size();
    capabilities.baudrate = 0; // no real baudrate for USB-CDC
#ifdef WITH_FPC_USART
    if (g_reply_via_fpc)
        capabilities.baudrate = g_usart_baudrate;
#endif

#ifdef RDV4
    capabilities.is_rdv4 = true;
#else
    capabilities.is_rdv4 = false;
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
    capabilities.hw_available_smartcard = I2C_get_version(&maj, &min) == PM3_SUCCESS;
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
        lf_av = lf_max = (MAX_ADC_LF_VOLTAGE * SumAdc(ADC_CHAN_LF, 32)) >> 15;
        Dbprintf("LF 125/134kHz Baseline: %dmV", lf_av);
        lf_baseline = lf_av;
    }

    if (limit == HF_ONLY || limit == LF_HF_BOTH) {

        // iceman,  useless,  since we are measuring readerfield,  not our field.  My tests shows a max of 20v from a reader.
        hf_av = hf_max = (MAX_ADC_HF_VOLTAGE * SumAdc(ADC_CHAN_HF, 32)) >> 15;
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

            lf_av_new = (MAX_ADC_LF_VOLTAGE * SumAdc(ADC_CHAN_LF, 32)) >> 15;
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

            hf_av_new = (MAX_ADC_HF_VOLTAGE * SumAdc(ADC_CHAN_HF, 32)) >> 15;
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
            struct p {
                uint16_t delay_us;
                bool on;
                bool off;
            } PACKED;
            struct p *payload = (struct p *)packet->data.asBytes;
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
            reply_ng(CMD_SET_TEAROFF, PM3_SUCCESS, NULL, 0);
            break;
        }
        // always available
        case CMD_HF_DROPFIELD: {
            hf_field_off();
            break;
        }
#ifdef WITH_LF
        case CMD_LF_T55XX_SET_CONFIG: {
            setT55xxConfig(packet->oldarg[0], (t55xx_configurations_t *) packet->data.asBytes);
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
                ReadLF_realtime(true);
            } else {
                uint32_t bits = SampleLF(payload->verbose, payload->samples, true);
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
                ReadLF_realtime(false);
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
        case CMD_LF_SIMULATE_BIDIR: {
            SimulateTagLowFrequencyBidir(packet->oldarg[0], packet->oldarg[1]);
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
            WritePCF7931(
                packet->data.asBytes[0], packet->data.asBytes[1], packet->data.asBytes[2], packet->data.asBytes[3],
                packet->data.asBytes[4], packet->data.asBytes[5], packet->data.asBytes[6], packet->data.asBytes[9],
                packet->data.asBytes[7] - 128, packet->data.asBytes[8] - 128,
                packet->oldarg[0],
                packet->oldarg[1],
                packet->oldarg[2],
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
            SniffHitag2(true);
            //hitag_sniff();
            reply_ng(CMD_LF_HITAG_SNIFF, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_LF_HITAG_SIMULATE: { // Simulate Hitag tag, args = memory content
            SimulateHitag2(true);
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
            hts_simulate((bool)packet->oldarg[0], packet->data.asBytes, true);
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
            hts_read_uid(NULL, false, true);
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
            emlSet(packet->data.asBytes, packet->oldarg[0], packet->oldarg[1]);
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
            EmlClearIso15693();
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

            uint8_t *buf = BigBuf_malloc(payload->length);
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
            hf14a_config *hf14aconfig = getHf14aConfig();
            reply_ng(CMD_HF_ISO14443A_GET_CONFIG, PM3_SUCCESS, (uint8_t *)hf14aconfig, sizeof(hf14a_config));
            break;
        }
        case CMD_HF_ISO14443A_SET_CONFIG: {
            hf14a_config c;
            memcpy(&c, packet->data.asBytes, sizeof(hf14a_config));
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
            SniffIso14443a(packet->data.asBytes[0]);
            reply_ng(CMD_HF_ISO14443A_SNIFF, PM3_SUCCESS, NULL, 0);
            break;
        }
        case CMD_HF_ISO14443A_READER: {
            ReaderIso14443a(packet);
            break;
        }
        case 0x0386: {
        //case CMD_HF_ISO14443A_EMV_SIMULATE: {
            struct p {
                uint16_t flags;
                uint8_t exitAfter;
                uint8_t uid[7];
                uint16_t atqa;
                uint8_t sak;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            Dbprintf("We have got hereeee");
            Dbprintf("Flags: %04x, ExitAfter: %02x, UID: %02x %02x %02x %02x %02x %02x %02x, ATQA: %04x, SAK: %02x",
                     payload->flags, payload->exitAfter, payload->uid[0], payload->uid[1], payload->uid[2], payload->uid[3], payload->uid[4], payload->uid[5], payload->uid[6], payload->atqa, payload->sak);
            EMVsim(payload->flags, payload->exitAfter, payload->uid, payload->atqa, payload->sak);
            break;
        }
        case CMD_HF_ISO14443A_SIMULATE: {
            struct p {
                uint8_t tagtype;
                uint16_t flags;
                uint8_t uid[10];
                uint8_t exitAfter;
                uint8_t rats[20];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            SimulateIso14443aTag(payload->tagtype, payload->flags, payload->uid,
                                 payload->exitAfter, payload->rats, sizeof(payload->rats));  // ## Simulate iso14443a tag - pass tag type & UID
            break;
        }
        case CMD_HF_ISO14443A_SIM_AID: {
            struct p {
                uint8_t tagtype;
                uint16_t flags;
                uint8_t uid[10];
                uint8_t rats[20];
                uint8_t aid[30];
                uint8_t response[100];
                uint8_t apdu[100];
                int aid_len;
                int respond_len;
                int apdu_len;
                bool enumerate;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            SimulateIso14443aTagAID(payload->tagtype, payload->flags, payload->uid,
                                    payload->rats, sizeof(payload->rats), payload->aid, payload->response,
                                    payload->apdu, payload->aid_len, payload->respond_len,
                                    payload->apdu_len, payload->enumerate);  // ## Simulate iso14443a tag - pass tag type, UID, rats, aid, resp, apdu
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

            MifareUReadBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREUC_AUTH: {
            MifareUC_Auth(packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREULAES_AUTH: {
            struct p {
                bool turn_off_field;
                uint8_t keyno;
                uint8_t key[18];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareUL_AES_Auth(payload->turn_off_field, payload->keyno, payload->key);
            break;
        }
        case CMD_HF_MIFAREU_READCARD: {
            MifareUReadCard(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREUC_SETPWD: {
            MifareUSetPwd(packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_READSC: {
            MifareReadSector(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_WRITEBL: {
            uint8_t block_no = packet->oldarg[0];
            uint8_t key_type = packet->oldarg[1];
            uint8_t *key = packet->data.asBytes;
            uint8_t *block_data = packet->data.asBytes + 10;

            int16_t retval = mifare_cmd_writeblocks(MF_WAKE_WUPA, MIFARE_AUTH_KEYA + (key_type & 0xF), key, ISO14443A_CMD_WRITEBLOCK, block_no, 1, block_data);

            // convert ng style retval to old status
            if (retval >= 0) {
                retval = 1;
            }

            reply_mix(CMD_ACK, retval, 0, 0, 0, 0);
            break;
        }
        case CMD_HF_MIFARE_WRITEBL_EX: {
            mf_writeblock_ex_t *payload = (mf_writeblock_ex_t *)packet->data.asBytes;
            int16_t retval = mifare_cmd_writeblocks(payload->wakeup, payload->auth_cmd, payload->key, payload->write_cmd, payload->block_no, 1, payload->block_data);
            reply_ng(CMD_HF_MIFARE_WRITEBL_EX, retval, NULL, 0);
            break;
        }
        case CMD_HF_MIFARE_VALUE: {
            MifareValue(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREU_WRITEBL: {
            MifareUWriteBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFAREU_WRITEBL_COMPAT: {
            MifareUWriteBlockCompat(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_ACQ_ENCRYPTED_NONCES: {
            MifareAcquireEncryptedNonces(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_ACQ_STATIC_ENCRYPTED_NONCES: {
            MifareAcquireStaticEncryptedNonces(packet->oldarg[0], packet->data.asBytes, true);
            break;
        }
        case CMD_HF_MIFARE_ACQ_NONCES: {
            MifareAcquireNonces(packet->oldarg[0], packet->oldarg[2]);
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
                uint8_t key[6];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareStaticNested(payload->block, payload->keytype, payload->target_block, payload->target_keytype, payload->key);
            break;
        }
        case CMD_HF_MIFARE_CHKKEYS: {
            MifareChkKeys(packet->data.asBytes, false);
            break;
        }
        case CMD_HF_MIFARE_CHKKEYS_FAST: {
            MifareChkKeys_fast(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
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
            MifareEMemClr();
            reply_ng(CMD_HF_MIFARE_EML_MEMCLR, PM3_SUCCESS, NULL, 0);
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
            break;
        }
        case CMD_HF_MIFARE_EML_MEMSET: {
            struct p {
                uint8_t blockno;
                uint8_t blockcnt;
                uint8_t blockwidth;
                uint8_t data[];
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;

            FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

            // backwards compat... default bytewidth
            if (payload->blockwidth == 0)
                payload->blockwidth = 16;

            emlSetMem_xt(payload->data, payload->blockno, payload->blockcnt, payload->blockwidth);
            break;
        }
        case CMD_HF_MIFARE_EML_MEMGET: {
            struct p {
                uint8_t blockno;
                uint8_t blockcnt;
            } PACKED;
            struct p *payload = (struct p *) packet->data.asBytes;
            MifareEMemGet(payload->blockno, payload->blockcnt);
            break;
        }
        case CMD_HF_MIFARE_EML_LOAD: {
            mfc_eload_t *payload = (mfc_eload_t *) packet->data.asBytes;
            MifareECardLoadExt(payload->sectorcnt, payload->keytype, payload->key);
            break;
        }
        // Gen1a / 1b - "magic Chinese" card
        case CMD_HF_MIFARE_CSETBL: {
            MifareCSetBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_CGETBL: {
            MifareCGetBlock(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
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
            MifareGen3UID(packet->oldarg[0], packet->data.asBytes);
            break;
        }
        case CMD_HF_MIFARE_GEN3BLK: {
            MifareGen3Blk(packet->oldarg[0], packet->data.asBytes);
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
            MifareU_Otp_Tearoff(packet->oldarg[0], packet->oldarg[1], packet->data.asBytes);
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

            SimulateIClass(packet->oldarg[0], packet->oldarg[1], packet->oldarg[2], packet->data.asBytes);
            break;
        }
        case CMD_HF_ICLASS_READER: {
            iclass_card_select_t *payload = (iclass_card_select_t *) packet->data.asBytes;
            ReaderIClass(payload->flags);
            break;
        }
        case CMD_HF_ICLASS_EML_MEMSET: {
            //-----------------------------------------------------------------------------
            // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_HF_15) here although FPGA is not
            // involved in dealing with emulator memory. But if it is called later, it might
            // destroy the Emulator Memory.
            //-----------------------------------------------------------------------------
            FpgaDownloadAndGo(FPGA_BITSTREAM_HF_15);
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
        case CMD_SMART_SETBAUD: {
            SmartCardSetBaud(packet->oldarg[0]);
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
            sam_picopass_get_pacs();
            break;
        }
        case CMD_HF_SAM_SEOS: {
//            sam_seos_get_pacs();
            break;
        }

        case CMD_HF_SAM_MFC: {
//            sam_mfc_get_pacs();
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
            uint8_t *dest = BigBuf_malloc(USART_FIFOLEN);
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
            uint8_t *dest = BigBuf_malloc(USART_FIFOLEN);
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
                    uint16_t volt = MeasureAntennaTuningHfData();
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

                    uint32_t volt = MeasureAntennaTuningLfData();
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
            SpinDelay(200);
            LED_D_OFF(); // LED D indicates field ON or OFF
            break;
        }
        case CMD_DOWNLOAD_BIGBUF: {
            LED_B_ON();
            uint8_t *mem = BigBuf_get_addr();
            uint32_t startidx = packet->oldarg[0];
            uint32_t numofbytes = packet->oldarg[1];

            // arg0 = startindex
            // arg1 = length bytes to transfer
            // arg2 = BigBuf tracelen
            //Dbprintf("transfer to client parameters: %" PRIu32 " | %" PRIu32 " | %" PRIu32, startidx, numofbytes, packet->oldarg[2]);

            for (size_t offset = 0; offset < numofbytes; offset += PM3_CMD_DATA_SIZE) {
                size_t len = MIN((numofbytes - offset), PM3_CMD_DATA_SIZE);
                int result = reply_old(CMD_DOWNLOADED_BIGBUF, offset, len, BigBuf_get_traceLen(), &mem[startidx + offset], len);
                if (result != PM3_SUCCESS)
                    Dbprintf("transfer to client failed ::  | bytes between %d - %d (%d) | result: %d", offset, offset + len, len, result);
            }
            // Trigger a finish downloading signal with an ACK frame
            // arg0 = status of download transfer
            reply_mix(CMD_ACK, 1, 0, BigBuf_get_traceLen(), NULL, 0);
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
            uint32_t startidx = packet->oldarg[0];
            uint32_t numofbytes = packet->oldarg[1];

            // arg0 = startindex
            // arg1 = length bytes to transfer
            // arg2 = RFU

            for (size_t i = 0; i < numofbytes; i += PM3_CMD_DATA_SIZE) {
                size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
                int result = reply_old(CMD_DOWNLOADED_EML_BIGBUF, i, len, 0, mem + startidx + i, len);
                if (result != PM3_SUCCESS)
                    Dbprintf("transfer to client failed ::  | bytes between %d - %d (%d) | result: %d", i, i + len, len, result);
            }
            // Trigger a finish downloading signal with an ACK frame
            reply_mix(CMD_ACK, 1, 0, 0, 0, 0);
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
            if (!raw_address_mode) {

                base = (uint8_t *) _flash_start;

                size_t flash_size = get_flash_size();

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
                if (offset > 0)
                    count = MIN(count, -offset);
            }

            if (isok) {
                for (size_t pos = 0; pos < count; pos += PM3_CMD_DATA_SIZE) {
                    size_t len = MIN((count - pos), PM3_CMD_DATA_SIZE);
                    isok = 0 == reply_old(CMD_READ_MEM_DOWNLOADED, pos, len, 0, &base[offset + pos], len);
                    if (!isok) {
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
            uint8_t *pfilename = packet->data.asBytes;
            memcpy(filename, pfilename, SPIFFS_OBJ_NAME_LEN);
            if (g_dbglevel >= DBG_DEBUG) Dbprintf("Filename received for spiffs dump : %s", filename);

            uint32_t size = packet->oldarg[1];

            uint8_t *buff = BigBuf_malloc(size);
            if (buff == NULL) {
                if (g_dbglevel >= DBG_DEBUG) Dbprintf("Could not allocate buffer");
                // Trigger a finish downloading signal with an PM3_EMALLOC
                reply_ng(CMD_SPIFFS_DOWNLOAD, PM3_EMALLOC, NULL, 0);
            } else {
                rdv40_spiffs_read_as_filetype((char *)filename, (uint8_t *)buff, size, RDV40_SPIFFS_SAFETY_SAFE);
                // arg0 = filename
                // arg1 = size
                // arg2 = RFU

                for (size_t i = 0; i < size; i += PM3_CMD_DATA_SIZE) {
                    size_t len = MIN((size - i), PM3_CMD_DATA_SIZE);
                    int result = reply_old(CMD_SPIFFS_DOWNLOADED, i, len, 0, buff + i, len);
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
            FlashmemSetSpiBaudrate(packet->data.asDwords[0]);
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

            if (payload->startidx == DEFAULT_T55XX_KEYS_OFFSET_P(spi_flash_p64k)) {
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(3, 0xC);
            } else if (payload->startidx ==  DEFAULT_MF_KEYS_OFFSET_P(spi_flash_p64k)) {
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(3, 0x8);
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(3, 0x9);
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(3, 0xA);
            } else if (payload->startidx == DEFAULT_ICLASS_KEYS_OFFSET_P(spi_flash_p64k)) {
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(3, 0xB);
            } else if (payload->startidx == FLASH_MEM_SIGNATURE_OFFSET_P(spi_flash_p64k)) {
                Flash_CheckBusy(BUSY_TIMEOUT);
                Flash_WriteEnable();
                Flash_Erase4k(3, 0xF);
            }

            uint16_t res = Flash_Write(payload->startidx, payload->data, payload->len);

            reply_ng(CMD_FLASHMEM_WRITE, (res == payload->len) ? PM3_SUCCESS : PM3_ESOFT, NULL, 0);
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_WIPE: {
            LED_B_ON();
            uint8_t page = packet->oldarg[0];
            uint8_t initialwipe = packet->oldarg[1];
            bool isok = false;
            if (initialwipe) {
                isok = Flash_WipeMemory();
                reply_mix(CMD_ACK, isok, 0, 0, 0, 0);
                LED_B_OFF();
                break;
            }
            if (page < spi_flash_p64k-1) {
                isok = Flash_WipeMemoryPage(page);
                // let spiffs check and update its info post flash erase
                rdv40_spiffs_check();
            }

            reply_mix(CMD_ACK, isok, 0, 0, 0, 0);
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_DOWNLOAD: {

            LED_B_ON();
            uint8_t *mem = BigBuf_malloc(PM3_CMD_DATA_SIZE);
            uint32_t startidx = packet->oldarg[0];
            uint32_t numofbytes = packet->oldarg[1];
            // arg0 = startindex
            // arg1 = length bytes to transfer
            // arg2 = RFU

            if (FlashInit() == false) {
                break;
            }

            for (size_t i = 0; i < numofbytes; i += PM3_CMD_DATA_SIZE) {
                size_t len = MIN((numofbytes - i), PM3_CMD_DATA_SIZE);
                Flash_CheckBusy(BUSY_TIMEOUT);
                bool isok = Flash_ReadDataCont(startidx + i, mem, len);
                if (isok == false)
                    Dbprintf("reading flash memory failed ::  | bytes between %d - %d", i, len);

                isok = reply_old(CMD_FLASHMEM_DOWNLOADED, i, len, 0, mem, len);
                if (isok != 0)
                    Dbprintf("transfer to client failed ::  | bytes between %d - %d", i, len);
            }
            FlashStop();

            reply_mix(CMD_ACK, 1, 0, 0, 0, 0);
            BigBuf_free();
            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_INFO: {

            LED_B_ON();
            rdv40_validation_t *info = (rdv40_validation_t *)BigBuf_malloc(sizeof(rdv40_validation_t));

            bool isok = Flash_ReadData(FLASH_MEM_SIGNATURE_OFFSET_P(spi_flash_p64k), info->signature, FLASH_MEM_SIGNATURE_LEN);

            if (FlashInit()) {
                Flash_UniqueID(info->flashid);
                FlashStop();
            }
            reply_mix(CMD_ACK, isok, 0, 0, info, sizeof(rdv40_validation_t));
            BigBuf_free();

            LED_B_OFF();
            break;
        }
        case CMD_FLASHMEM_PAGES64K: {

            LED_B_ON();

            bool isok = false;
            if (FlashInit()) {
                isok = true;
                if (g_dbglevel >= DBG_DEBUG) {
                    Dbprintf("  CMD_FLASHMEM_PAGE64K 0x%02x (%d 64k pages)", spi_flash_p64k, spi_flash_p64k);
                }
                FlashStop();
            }
            reply_mix(CMD_ACK, isok, 0, 0, &spi_flash_p64k, sizeof(uint8_t));

            LED_B_OFF();
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
                    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);
                    break;
                case 2:
                    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
                    break;
#ifndef WITH_FPC_USART
                case 1:
                    SetAdcMuxFor(GPIO_MUXSEL_LORAW);
                    break;
                case 3:
                    SetAdcMuxFor(GPIO_MUXSEL_HIRAW);
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

            while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
            uint16_t mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;
            Dbprintf("  Slow clock old measured value:.........%d Hz", (16 * MAINCK) / mainf);
            TimingIntervalAcquisition();

            while ((AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINRDY) == 0);       // Wait for MAINF value to become available...
            mainf = AT91C_BASE_PMC->PMC_MCFR & AT91C_CKGR_MAINF;
            Dbprintf(""); // first message gets lost
            Dbprintf("  Slow clock new measured value:.........%d Hz", (16 * MAINCK) / mainf);
            reply_ng(CMD_TIA, PM3_SUCCESS, NULL, 0);
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
            LCDSend(packet->oldarg[0]);
            break;
        }
#endif
        case CMD_FINISH_WRITE:
        case CMD_HARDWARE_RESET: {
            usb_disable();

            // (iceman) why this wait?
            SpinDelay(1000);
            AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
            // We're going to reset, and the bootrom will take control.
            for (;;) {}
            break;
        }
        case CMD_START_FLASH: {
            if (g_common_area.flags.bootrom_present) {
                g_common_area.command = COMMON_AREA_COMMAND_ENTER_FLASH_MODE;
            }
            usb_disable();
            AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
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
        default: {
            Dbprintf("%s: 0x%04x", "unknown command:", packet->cmd);
            break;
        }
    }
}

void  __attribute__((noreturn)) AppMain(void) {

    SpinDelay(100);
    BigBuf_initialize();

    // Add stack canary
    for (uint32_t *p = _stack_start; p + 0x200 < _stack_end ; ++p) {
        *p = 0xdeadbeef;
    }

    LEDsoff();

    // The FPGA gets its clock from us from PCK0 output, so set that up.
    AT91C_BASE_PIOA->PIO_BSR = GPIO_PCK0;
    AT91C_BASE_PIOA->PIO_PDR = GPIO_PCK0;
    AT91C_BASE_PMC->PMC_SCER |= AT91C_PMC_PCK0;
    // PCK0 is PLL clock / 4 = 96MHz / 4 = 24MHz
    AT91C_BASE_PMC->PMC_PCKR[0] = AT91C_PMC_CSS_PLL_CLK | AT91C_PMC_PRES_CLK_4; //  4 for 24MHz pck0, 2 for 48 MHZ pck0
    AT91C_BASE_PIOA->PIO_OER = GPIO_PCK0;

    // Reset SPI
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SWRST;
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SWRST; // errata says it needs twice to be correctly set.

    // Reset SSC
    AT91C_BASE_SSC->SSC_CR = AT91C_SSC_SWRST;

    // Configure MUX
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

    // Load the FPGA image, which we have stored in our flash.
    // (the HF version by default)
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    StartTickCount();

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

    //
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

    for (;;) {
        WDT_HIT();

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
        } else if (ret != PM3_ENODATA) {

            Dbprintf("Error in frame reception: %d %s", ret, (ret == PM3_EIO) ? "PM3_EIO" : "");
            // TODO if error, shall we resync ?
        }

        // Press button for one second to enter a possible standalone mode
        button_status = BUTTON_HELD(1000);
        if (button_status == BUTTON_HOLD) {
            /*
            * So this is the trigger to execute a standalone mod.  Generic entrypoint by following the standalone/standalone.h headerfile
            * All standalone mod "main loop" should be the RunMod() function.
            */
            allow_send_wtx = false;
            RunMod();
            allow_send_wtx = true;
        }
    }
}
