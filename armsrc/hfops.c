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
// HF general operations
//-----------------------------------------------------------------------------

#include "hfops.h"

#include <string.h>
#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "util.h"
#include "commonutil.h"
#include "lfsampling.h"

int HfReadADC(uint32_t samplesCount, bool ledcontrol) {
    if (ledcontrol) LEDsoff();

    BigBuf_Clear_ext(false);
    // connect Demodulated Signal to ADC:
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    // And put the FPGA in the appropriate mode
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_SUBCARRIER_212_KHZ | FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE);

    // Setup
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);

    if (ledcontrol) LED_A_ON();

    uint32_t sbs = samplesCount;
    initSampleBuffer(&sbs);

    uint32_t wdtcntr = 0;
    for (;;) {
        if (BUTTON_PRESS()) {
            break;
        }

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            volatile uint16_t sample =  AT91C_BASE_SSC->SSC_RHR;

            // FPGA side:
            // corr_i_out <= {2'b00, corr_amplitude[13:8]};
            // corr_q_out <= corr_amplitude[7:0];
            if (sample > 0x1fff)
                sample = 0xff;
            else
                sample = sample >> 5;
            logSample(sample & 0xff, 1, 8, false);
            if (getSampleCounter() >= samplesCount)
                break;

            if (wdtcntr++ > 512) {
                WDT_HIT();
                wdtcntr = 0;
            }
        } else {
            continue;
        }
    }

    FpgaDisableTracing();

    FpgaSetupSsc(FPGA_MAJOR_MODE_OFF);
    // Turn the field off
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    uint32_t scnt = getSampleCounter();
    reply_ng(CMD_HF_ACQ_RAW_ADC, PM3_SUCCESS, (uint8_t*)&scnt, 4);
    if (ledcontrol) LEDsoff();

    return 0;
}


