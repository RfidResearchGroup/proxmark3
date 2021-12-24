//-----------------------------------------------------------------------------
// Copyright (C) 2021 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency ZX8211 funtions
//-----------------------------------------------------------------------------
#ifndef __LFOPS_H
#define __LFOPS_H

#include "lfzx.h"
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "lfadc.h"
#include "pm3_cmd.h" // struct
#include "zx8211.h"


static void zx8211_setup_read(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);

    // 50ms for the resonant antenna to settle.
    SpinDelay(50);

    // Now set up the SSC to get the ADC samples that are now streaming at us.
    FpgaSetupSsc(FPGA_MAJOR_MODE_LF_READER);

    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125);

    // Connect the A/D to the peak-detected low-frequency path.
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Steal this pin from the SSP (SPI communication channel with fpga) and
    // use it to control the modulation
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;

    // Disable modulation at default, which means enable the field
    LOW(GPIO_SSC_DOUT);

    // Start the timer
    StartTicks();

    // Watchdog hit
    WDT_HIT();
}


int zx8211_read(zx8211_data_t *zxd, bool ledcontrol) {
    zx8211_setup_read();

    StopTicks();
    lf_finalize(ledcontrol);
    //reply_ng(CMD_LF_ZX_READ, status, tag.data, sizeof(tag.data));
    return PM3_SUCCESS;
}

int zx8211_write(zx8211_data_t *zxd, bool ledcontrol) {
    zx8211_setup_read();

    StopTicks();
    lf_finalize(ledcontrol);
    //reply_ng(CMD_LF_ZX_WRITE, status, tag.data, sizeof(tag.data));
    return PM3_SUCCESS;
}

#endif