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
// Low frequency ZX8211 funtions
//-----------------------------------------------------------------------------
#include "lfzx.h"
#include "zx8211.h"

#include "BigBuf.h"
#include "crc.h"        // CRC-8 / Hitag1 / ZX8211
#include "fpgaloader.h"
#include "dbprint.h"
#include "lfops.h"      // turn_read_lf_on / off
#include "lfadc.h"
#include "lfsampling.h" // getSamplingConfig
#include "pm3_cmd.h"    // struct
#include "ticks.h"

/*
ZX8211

RWE to tag
----------
ASK w 100% modulation index
When power field is:
   off, its considered LOW field
   on,  its considered HIGH field


Binary Pulse Length Coding (BPLC)

ZERO = 8 off,  8 on  (14-22)
ONE  = 8 off, 28 on  (26-32)
EOF  = 8 off, 30 on  (38 or more)

Protection
----------
32bit read password
32bit write password

Config bits
-------------

Timings
-------

Tx = 8us = 1fc
*/

#define ZX_START_GAP        170
#define ZX_WAIT_GAP         90
#define ZX_GAP              8    // 4 - 10
#define ZX_T0               18
#define ZX_T0_MIN           14
#define ZX_T0_MAX           22
#define ZX_T1               28
#define ZX_T1_MIN           26
#define ZX_T1_MAX           32
#define ZX_TEOF             38
#define ZX_RESET_GAP        35000 // 35ms
#define ZX_RESPONSE_GAP     208

#define ZX_PROG             716
#define ZX_PROG_CT          4470

// TTF switch to RTF
#define ZX_SWITCH_RTF 350

// ZX commands
#define LF_ZX_GET_UID  0b00110
#define LF_ZX_READ
#define LF_ZX_WRITE


static void zx8211_setup_read(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // Make sure the tag is reset
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    // use lf config settings
    sample_config *sc = getSamplingConfig();
    LFSetupFPGAForADC(sc->divisor, true);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER | FPGA_LF_ADC_READER_FIELD);

    // 50ms for the resonant antenna to settle.
    WaitMS(50);

    // Now set up the SSC to get the ADC samples that are now streaming at us.
    FpgaSetupSsc(FPGA_MAJOR_MODE_LF_READER);

    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125);

    // Connect the A/D to the peak-detected low-frequency path.
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Start the timer
    StartTicks();

    // Watchdog hit
    WDT_HIT();
}

static void zx_send(const uint8_t *cmd, uint8_t clen) {

    if (clen == 0)
        return;

    turn_read_lf_on(ZX_START_GAP);

    // now start writing with bitbanging the antenna.
    while (clen-- > 0) {

        turn_read_lf_off(ZX_GAP * 8);

        if (((*cmd++) & 1) == 1) {
            turn_read_lf_on(ZX_T1 * 8);
        } else {
            turn_read_lf_on(ZX_T0 * 8);
        }
    }

    // send eof
    turn_read_lf_off(ZX_GAP * 8);
    turn_read_lf_on(ZX_TEOF * 8);
}

static void zx_get(bool ledcontrol) {

    while (BUTTON_PRESS() == false) {

        WDT_HIT();

        if (ledcontrol && (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY)) {
            LED_D_ON();
        }

        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            volatile uint8_t sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
            (void)sample;

            // Test point 8 (TP8) can be used to trigger oscilloscope
            if (ledcontrol) LED_D_OFF();

        }
    }
}

int zx8211_read(zx8211_data_t *zxd, bool ledcontrol) {
    zx8211_setup_read();

    // clear buffer now so it does not interfere with timing later
    BigBuf_Clear_ext(false);

    if (ledcontrol) LED_A_ON();

    // send GET_UID
    zx_send(NULL, 0);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER | FPGA_LF_ADC_READER_FIELD);

    zx_get(ledcontrol);

    //uint32_t cs = CRC8Hitag1(uint8_t *buff, size_t size);

    if (ledcontrol) LEDsoff();

    StopTicks();
    lf_finalize(ledcontrol);

    reply_ng(CMD_LF_ZX_READ, PM3_SUCCESS, NULL, 0);
    return PM3_SUCCESS;
}

int zx8211_write(zx8211_data_t *zxd, bool ledcontrol) {
    zx8211_setup_read();

    StopTicks();
    lf_finalize(ledcontrol);
    //reply_ng(CMD_LF_ZX_WRITE, status, tag.data, sizeof(tag.data));
    return PM3_SUCCESS;
}
