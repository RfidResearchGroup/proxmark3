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
// Routines to get sample data from FPGA.
//-----------------------------------------------------------------------------
#include "hfsnoop.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "fpga_loader.h"
#include "ticks_apis.h"
#include "fpga_apis.h"
#include "dbprint.h"
#include "util.h"
#include "fpga.h"
#include "appmain.h"
#include "cmd.h"

static void RAMFUNC optimizedSniff(uint16_t *dest, uint16_t dsize) {
    while (dsize > 0) {
        if (FPGA_SSC_RX_Ready()) {
            *dest = (uint16_t)(FPGA_SSC_RX_Value());
            dest++;
            dsize -= sizeof(dsize);
        }
    }
}

static void RAMFUNC skipSniff(uint8_t *dest, uint16_t dsize, uint8_t skipMode, uint8_t skipRatio) {
    uint32_t accum = (skipMode == HF_SNOOP_SKIP_MIN) ? 0xffffffff : 0;
    uint8_t ratioindx = 0;
    while (dsize > 0) {
        if (FPGA_SSC_RX_Ready()) {
            volatile uint16_t val = (uint16_t)(FPGA_SSC_RX_Value());
            switch (skipMode) {
                case HF_SNOOP_SKIP_MAX:
                    if (accum < (val & 0xff))
                        accum = val & 0xff;
                    if (accum < (val >> 8))
                        accum = val >> 8;
                    break;
                case HF_SNOOP_SKIP_MIN:
                    if (accum > (val & 0xff))
                        accum = val & 0xff;
                    if (accum > (val >> 8))
                        accum = val >> 8;
                    break;
                case HF_SNOOP_SKIP_AVG:
                    accum += (val & 0xff) + (val & 0xff);
                    break;
                default: { // HF_SNOOP_SKIP_DROP and the rest
                    if (ratioindx == 0)
                        accum = val & 0xff;
                }
            }

            ratioindx++;
            if (ratioindx >= skipRatio) {
                if (skipMode == HF_SNOOP_SKIP_AVG && skipRatio > 0) {
                    accum = accum / (skipRatio * 2);
                    if (accum <= 0xff)
                        *dest = accum;
                    else
                        *dest = 0xff;
                } else {
                    *dest = accum;
                }

                dest++;
                dsize --;
                accum = (skipMode == HF_SNOOP_SKIP_MIN) ? 0xffffffff : 0;
                ratioindx = 0;
            }
        }
    }
}

int HfSniff(uint32_t samplesToSkip, uint32_t triggersToSkip, uint16_t *len, uint8_t skipMode, uint8_t skipRatio) {
    BigBuf_free();
    BigBuf_Clear_ext(false);

    Dbprintf("Skipping first %d sample pairs, Skipping %d triggers", samplesToSkip, triggersToSkip);

    LED_D_ON();

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    SetAdcMuxFor(ADC_MUXSEL_HIPKD);

    // Set up the synchronous serial port
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_SNIFF);

    // Setting Frame Mode For better performance on high speed data transfer.
    FpgaUpdateFrameMode(16, false, false);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SNIFF);
    SpinDelay(100);

    *len = BigBuf_max_traceLen();
    uint8_t *mem = BigBuf_calloc(*len);

    uint32_t trigger_cnt = 0;
    uint16_t r = 0, interval = 0;

    bool pressed = false;
    while (pressed == false) {
        WDT_HIT();

        // cancel w usb command.
        if (interval == 2000) {
            if (data_available())
                break;

            interval = 0;
        } else {
            interval++;
        }

        // check if trigger is reached
        if (FPGA_SSC_RX_Ready()) {
            r = (uint16_t)FPGA_SSC_RX_Value();

            r = MAX(r & 0xFF, r >> 8);

            // 180 (0xB4) arbitrary value to see if a strong RF field is near.
            if (r > 180) {

                if (++trigger_cnt > triggersToSkip) {
                    break;
                }
            }
        }

        pressed = BUTTON_PRESS();
    }

    if (pressed == false) {

        // skip samples loop
        while (samplesToSkip != 0) {

            if (FPGA_SSC_RX_Ready()) {
                samplesToSkip--;
            }
        }

        if (skipMode == 0)
            optimizedSniff((uint16_t *)mem, *len);
        else
            skipSniff(mem, *len, skipMode, skipRatio);

        if (g_dbglevel >= DBG_INFO) {
            Dbprintf("Trigger kicked in (%d >= 180)", r);
            Dbprintf("Collected %u samples", *len);
        }
    }

    // Resetting Frame mode (First set in FpgaSetupSsc() function)
    FpgaUpdateFrameMode(8, true, true);
    LED_D_OFF();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    BigBuf_free();
    return (pressed) ? PM3_EOPABORTED : PM3_SUCCESS;
}

void HfPlotDownload(void) {
    // Two chunk buffers laid back to back in the ToSend buffer. Each one is a
    // download_chunk_t header followed by the samples the DMA writes straight
    // into chunk->data, so a filled buffer is already a complete NG payload and
    // can be handed to reply_ng without a copy.
    // get_tosend() has to come after FpgaDownloadAndGo(): the FPGA loader frees
    // BigBuf and reuses this region for its decompression ring buffer.

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    const size_t stride = sizeof(download_chunk_t) + DOWNLOAD_CHUNK_MAX;   // buffer capacity (max)
    const size_t dl_chunk = reply_ng_max_data_size() - sizeof(download_chunk_t);                // per-frame, FPC-aware

    tosend_t *ts = get_tosend();
    if (ts->buf == NULL || (2 * stride) > TOSEND_BUFFER_SIZE) {
        reply_ng(CMD_FPGAMEM_DOWNLOAD, PM3_EMALLOC, NULL, 0);
        return;
    }

    download_chunk_t *chunk[2] = {
        (download_chunk_t *)ts->buf,
        (download_chunk_t *)(ts->buf + stride)
    };
    uint8_t idx = 0;

    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_GET_TRACE);

    // Arm each transfer for exactly what is still coming.
    // FPGA_TRACE_SIZE is not a multiple of DOWNLOAD_CHUNK_MAX,
    // and the FPGA stops after its Block-RAM is out
    FpgaSetupSscRxDmaSingle(chunk[idx]->data, MIN(FPGA_TRACE_SIZE, dl_chunk));

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_GET_TRACE);

    LED_B_ON();
    for (size_t i = 0; i < FPGA_TRACE_SIZE; i += dl_chunk) {

        size_t len = MIN(FPGA_TRACE_SIZE - i, dl_chunk);
        download_chunk_t *this_chunk = chunk[idx];
        idx ^= 1;

        while (!FPGA_SSC_DMA_RX_Done()) {};

        // The main buf has stopped receiving, so arm the other one first
        size_t next = i + dl_chunk;
        if (next < FPGA_TRACE_SIZE) {
            FPGA_SSC_DMA_RX_Refresh_Single(
                chunk[idx]->data,
                MIN(FPGA_TRACE_SIZE - next, dl_chunk)
            );
        }

        this_chunk->offset = i;
        reply_ng(CMD_FPGAMEM_DOWNLOADED, PM3_SUCCESS, (uint8_t *)this_chunk, sizeof(download_chunk_t) + len);
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    download_done_t done = {
        .bytes_sent = FPGA_TRACE_SIZE,
        .extra = 0,
    };
    reply_ng(CMD_FPGAMEM_DOWNLOAD, PM3_SUCCESS, (uint8_t *)&done, sizeof(done));
    LED_B_OFF();
}
