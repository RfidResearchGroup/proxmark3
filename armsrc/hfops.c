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
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_2SUBCARRIERS_424_484_KHZ | FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE);

    // Setup and start DMA.
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);

    // The DMA buffer, used to stream samples from the FPGA
    dmabuf16_t *dma = get_dma16();
    memset((uint8_t *) dma->buf, 0, DMA_BUFFER_SIZE);

    // Setup and start DMA.
    if (FpgaSetupSscDma((uint8_t *) dma->buf, DMA_BUFFER_SIZE) == false) {
        if (g_dbglevel > DBG_ERROR) Dbprintf("FpgaSetupSscDma failed. Exiting");

        FpgaDisableSscDma();
        FpgaSetupSsc(FPGA_MAJOR_MODE_OFF);
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        return PM3_EINIT;
    }

    if (ledcontrol) LED_A_ON();

    uint16_t *upTo = dma->buf;

    uint32_t sbs = samplesCount;
    initSampleBuffer(&sbs);

    for (;;) {
        if (BUTTON_PRESS()) {
            break;
        }

        volatile uint16_t behindBy = ((uint16_t *)AT91C_BASE_PDC_SSC->PDC_RPR - upTo) & (DMA_BUFFER_SIZE - 1);
        if (behindBy == 0)
            continue;

        // FPGA side:
        // corr_i_out <= {2'b00, corr_amplitude[13:8]};
        // corr_q_out <= corr_amplitude[7:0];
        // ci = upTo >> 8, cq = upTo
        volatile uint16_t sample = *upTo++;
        //if (sample & 0xc000) {
        //    Dbprintf("sample!!!! %d \r\n", getSampleCounter());
        //    break;
        //}

        logSample((sample >> 6) & 0xff, 1, 8, false);

        if (getSampleCounter() >= samplesCount)
            break;

        if (upTo >= dma->buf + DMA_BUFFER_SIZE) {                // we have read all of the DMA buffer content.
            upTo = dma->buf;                                     // start reading the circular buffer from the beginning
        }

        // DMA Counter Register had reached 0, already rotated.
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_ENDRX)) {

            // primary buffer was stopped
            if (AT91C_BASE_PDC_SSC->PDC_RCR == false) {
                AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) dma->buf;
                AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
                Dbprintf("blew\r\n");
            }
            // secondary buffer sets as primary, secondary buffer was stopped
            if (AT91C_BASE_PDC_SSC->PDC_RNCR == false) {
                AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dma->buf;
                AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
            }

            WDT_HIT();
        }
    }

    FpgaDisableSscDma();
    FpgaDisableTracing();

    FpgaSetupSsc(FPGA_MAJOR_MODE_OFF);
    // Turn the field off
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    uint32_t scnt = getSampleCounter();
    reply_ng(CMD_HF_ACQ_RAW_ADC, PM3_SUCCESS, (uint8_t*)&scnt, 4);
    if (ledcontrol) LEDsoff();

    return 0;
}


