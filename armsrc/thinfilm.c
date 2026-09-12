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
// Routines to support a mangeled ISO 14443 type A for Thinfilm tags by Kovio
//-----------------------------------------------------------------------------

#include "thinfilm.h"

#include "proxmark3_arm.h"
#include "cmd.h"
#include "appmain.h"
#include "BigBuf.h"
#include "iso14443a.h"
#include "fpga_loader.h"
#include "ticks_apis.h"
#include "fpga_apis.h"
#include "rssi_apis.h"
#include "dbprint.h"
#include "util.h"

/**
  * ref
  *   https://www.thinfilmnfc.com/wp-content/uploads/2017/09/Thinfilm-Kovio-NFC-Barcode-Protocol-Tag-Functional-Specification-v3.4-2017-05-26.pdf
  *   https://developer.android.com/reference/android/nfc/tech/NfcBarcode
  *
  */

void ReadThinFilm(void) {

    clear_trace();
    set_tracing(true);

    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

    uint8_t len = 0;
    uint8_t *buf = BigBuf_calloc(36);

    // power on and listen for answer.
    bool status = GetIso14443aAnswerFromTag_Thinfilm(buf, 36, &len);
    reply_ng(CMD_HF_THINFILM_READ, status ? PM3_SUCCESS : PM3_ENODATA, buf, len);

    hf_field_off();
    set_tracing(false);
    BigBuf_free();
}

//-----------------------------------------------------------------------------
// Passively record the frames a Kovio / Thinfilm tag beams at a reader.
// Kovio is tag-talks-first and the reader never sends a command, so only the tag
// side is decoded.  Use `hf 14a sniff` to watch a reader's poll loop.
//-----------------------------------------------------------------------------
int SniffThinFilm(void) {

    LEDsoff();

    iso14443a_setup(FPGA_HF_ISO14443A_SNIFFER);

    BigBuf_free();
    BigBuf_Clear_ext(false);
    clear_trace();
    set_tracing(true);

    // The frames (tag -> reader) that we are receiving.
    uint8_t *resp = BigBuf_calloc(MAX_FRAME_SIZE);
    uint8_t *resp_par = BigBuf_calloc(MAX_PARITY_SIZE);

    if (resp == NULL || resp_par == NULL) {
        if (g_dbglevel >= DBG_ERROR) {
            DbpString("Sniff thinfilm: failed to allocate buffers");
        }
        BigBuf_free();
        return PM3_EMALLOC;
    }

    Demod14aInit(resp, MAX_FRAME_SIZE, resp_par);

    if (g_dbglevel >= DBG_INFO) {
        DbpString("Press " _GREEN_("pm3 button") " to abort sniffing");
    }

    // The DMA buffer, used to stream samples from the FPGA
    dmabuf8_t *dma = get_dma8();
    uint8_t *data = dma->buf;

    if (FpgaSetupSscRxDmaRepeat((uint8_t *)dma->buf, DMA_BUFFER_SIZE) == false) {
        if (g_dbglevel > DBG_ERROR) {
            Dbprintf("FpgaSetupSscRxDmaRepeat failed. Exiting");
        }
        BigBuf_free();
        return PM3_EIO;
    }

    tDemod14a *demod = GetDemod14a();

    uint8_t previous_data = 0;
    uint32_t rx_samples = 0;
    uint32_t overrun_skips = 0;
    uint32_t dma_stalls = 0;
    uint32_t frames = 0;
    uint16_t checker = 12000;
    int dataLen;

    // loop and listen
    while (BUTTON_PRESS() == false) {

        WDT_HIT();
        LED_A_ON();

        if (checker-- == 0) {
            if (data_available()) {
                break;
            }
            checker = 12000;
        }

        register int readBufDataP = data - dma->buf;
        register int dmaBufDataP = DMA_BUFFER_SIZE - FPGA_SSC_DMA_RX_Remaining_Count();
        if (readBufDataP <= dmaBufDataP) {
            dataLen = dmaBufDataP - readBufDataP;
        } else {
            dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP;
        }

        // DMA fully stalled: both buffers exhausted. Re-arm primary + secondary,
        // resync the read pointer, and drop the in-flight frame.
        if (FPGA_SSC_DMA_RX_Primary_Done()) {
            FPGA_SSC_DMA_RX_Refresh_Both(dma->buf, DMA_BUFFER_SIZE);
            data = dma->buf;
            rx_samples += DMA_BUFFER_SIZE;
            Demod14aReset();
            dma_stalls++;
            continue;
        }

        // Fell behind the DMA write pointer; skip to catch up rather than abort.
        if (dataLen > (9 * DMA_BUFFER_SIZE / 10)) {
            data = dma->buf + dmaBufDataP;
            if (data == dma->buf + DMA_BUFFER_SIZE) {
                data = dma->buf;
            }
            rx_samples += dataLen;
            Demod14aReset();
            overrun_skips++;
            continue;
        }

        // The MCU is processing data fast enough that the DMA has not yet received any new data.
        if (dataLen < 1) {
            continue;
        }

        // secondary buffer exhausted, primary still running - refill secondary
        if (FPGA_SSC_DMA_RX_Secondary_Done()) {
            FPGA_SSC_DMA_RX_Refresh_Secondary(dma->buf, DMA_BUFFER_SIZE);
        }

        LED_A_OFF();

        // Need two samples to feed the Manchester decoder
        if (rx_samples & 0x01) {

            uint8_t tagdata = (previous_data << 4) | (*data & 0x0F);

            if (ManchesterDecoding_Thinfilm(tagdata, (rx_samples - 1) * 4)) {

                LED_B_ON();
                frames++;

                if (LogTrace(resp,
                             demod->len,
                             demod->startTime * 16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
                             demod->endTime * 16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
                             NULL,
                             false) == false) {
                    break;
                }

                // ready to receive another frame
                Demod14aReset();
                LED_B_OFF();
            }
        }

        previous_data = *data;
        rx_samples++;
        data++;
        if (data == dma->buf + DMA_BUFFER_SIZE) {
            data = dma->buf;
        }
    } // end main loop

    FpgaDisableTracing();

    if (g_dbglevel >= DBG_ERROR) {
        Dbprintf("Thinfilm sniff, " _YELLOW_("%u") " frames | trace len " _YELLOW_("%d"),
                 frames,
                 BigBuf_get_traceLen()
                );
        if (overrun_skips || dma_stalls) {
            Dbprintf(_RED_("[!] sniffer dropped frames") " | overrun recoveries " _YELLOW_("%u") " | DMA stalls " _YELLOW_("%u"),
                     overrun_skips, dma_stalls);
        }
    }

    switch_off();
    set_tracing(false);
    return PM3_SUCCESS;
}

#define SEC_D 0xf0
#define SEC_E 0x0f
#define SEC_F 0x00

// A genuine Kovio tag repeats its frame every 65536 carrier periods - measured off
// `hf thinfilm sniff`, 2**16 because it clocks a 16 bit counter off the carrier.
// ssp_clk is carrier / 16, so hold 4096 ssp ticks from one frame start to the next.
#define THINFILM_FRAME_PERIOD_SSP 4096

// A 32 sample average costs about 3.8 ms, since every sample pays a 42.7 us ADC
// startup and a 40 us sample & hold.  That is fine once, for the baseline, but in
// the send loop it costs more than the deliberate inter frame delay and nearly
// doubles the frame repeat period.  Poll with far fewer samples.
static uint16_t ReadReaderField(uint8_t samples) {
    return AdcRssiSum(ADC_RSSI_CH_HF, samples) / samples;
}

static void CodeThinfilmAsTag(const uint8_t *cmd, uint16_t len) {

    tosend_reset();

    tosend_t *ts = get_tosend();

    for (uint16_t i = 0; i < len; i++) {
        uint8_t b = cmd[i];
        for (uint8_t j = 0; j < 8; j++) {
            ts->buf[++ts->max] = (b & 0x80) ? SEC_D : SEC_E;
            b <<= 1;
        }
    }

    // Convert from last byte pos to length
    ts->max++;
}

static int EmSendCmdThinfilmRaw(const uint8_t *resp, uint16_t respLen) {

    volatile uint8_t b;
    uint32_t ThisTransferTime ;

    // clear receiving shift register and holding register
    FPGA_SSC_RX_READY_WAIT();
    b = FPGA_SSC_RX_Value();
    (void) b;

    // wait for the FPGA to signal fdt_indicator == 1 (the FPGA is ready to queue new data in its delay line)
    for (uint8_t j = 0; j < 5; j++) {    // allow timeout - better late than never
        FPGA_SSC_RX_READY_WAIT();
        if (FPGA_SSC_RX_Value()) {
            break;
        }
    }
    while ((ThisTransferTime = GetCountSspClk()) & 0x00000007);

    // Clear TXRDY:
    FPGA_SSC_TX_Value(SEC_F);

    uint16_t FpgaSendQueueDelay = 0;

    // send cycle
    size_t i = 0;
    for (; i < respLen;) {
        if (FPGA_SSC_TX_Ready()) {
            FPGA_SSC_TX_Value(resp[i++]);
            FPGA_SSC_RX_READY_WAIT();
            FpgaSendQueueDelay = (uint8_t)FPGA_SSC_RX_Value();
        }

        if (FPGA_SSC_RX_Ready()) {
            b = (uint8_t)(FPGA_SSC_RX_Value());
            (void)b;
        }
        if (BUTTON_PRESS()) break;
    }

    // Ensure that the FPGA Delay Queue is empty
    uint16_t fpga_queued_bits = FpgaSendQueueDelay >> 3;
    fpga_queued_bits >>= 3; // divide by 8 (again?)
    fpga_queued_bits += 1u;
    for (i = 0; i <= fpga_queued_bits;) {
        if (FPGA_SSC_TX_Ready()) {
            FPGA_SSC_TX_Value(SEC_F);
            FPGA_SSC_RX_READY_WAIT();
            FpgaSendQueueDelay = (uint8_t)FPGA_SSC_RX_Value();
            i++;
        }
    }

    return PM3_SUCCESS;
}

void SimulateThinFilm(uint8_t *data, size_t len) {

    switch_off(); // disconnect raw
    SpinDelay(20);

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // allocate command receive buffer
    BigBuf_free();

    clear_trace();
    set_tracing(true);

    Dbprintf("Simulate " _YELLOW_("%i-bit Thinfilm") " tag", len * 8);

    // connect Demodulated Signal to ADC:
    SetAdcMuxFor(ADC_MUXSEL_HIPKD);

    // Set up the synchronous serial port
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_ISO14443A);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_MOD);

    SpinDelay(100);

    // Start the timer
    StartCountSspClk();

    uint16_t hf_baseline = ReadReaderField(32);
    uint16_t hf_peak = hf_baseline;
    uint32_t sends = 0;

    // let the first frame go out without waiting
    uint32_t frame_start = GetCountSspClk() - THINFILM_FRAME_PERIOD_SSP;

    int8_t status = PM3_SUCCESS;
    CodeThinfilmAsTag(data, len);

    tosend_t *ts = get_tosend();

    if (g_dbglevel >= DBG_DEBUG) {
        for (int i = 0; i < ts->max; i += 16) {
            Dbhexdump(MIN(16, ts->max - i), ts->buf + i, false);
        }
        DbpString("------------------------------------------");
    }

    LED_A_ON();

    for (;;) {

        WDT_HIT();

        // Test if the action was cancelled
        if (BUTTON_PRESS() || data_available()) {
            status = PM3_EOPABORTED;
            break;
        }

        uint16_t hf_av = ReadReaderField(4);

        /* TODO DXL: Do not use the ADC value directly, which will result in cross platform failure.
        if (hf_av < hf_baseline) {
            hf_baseline = hf_av;
        }
        if (hf_av > hf_baseline + 10) {
            EmSendCmdThinfilmRaw(ts->buf, ts->max);
            if (len == 16) {
                // wait 3.6ms
                SpinDelayUs(3600);
            } else {
                // wait 2.4ms
                SpinDelayUs(2400);
            }
        }
        */

        if (hf_av < hf_baseline) {
            hf_baseline = hf_av;
        } else if (hf_av > hf_baseline) {
            if (hf_av > hf_peak) {
                hf_peak = hf_av;
            }
            if (AdcRssiDataToMilliVolt(hf_av - hf_baseline, ADC_RSSI_CH_HF) > 1375) {

                // hold the tag's repeat rate.  Waiting on the frame start rather than
                // delaying a fixed amount takes the field poll above out of the gap
                // instead of adding it on top.
                while ((GetCountSspClk() - frame_start) < THINFILM_FRAME_PERIOD_SSP) {
                    WDT_HIT();
                    if (BUTTON_PRESS()) {
                        break;
                    }
                }

                frame_start = GetCountSspClk();
                EmSendCmdThinfilmRaw(ts->buf, ts->max);
                sends++;

                // one tosend byte == one 106 kbit/s bit == 8 ssp clk ticks
                LogTrace(data, len, frame_start * 16, (frame_start + (ts->max * 8)) * 16, NULL, false);
            }
        }

    }

    LED_A_OFF();

    if (g_dbglevel >= DBG_INFO) {
        Dbprintf("Thinfilm sim, sent " _YELLOW_("%u") " frames | field baseline %u, peak %u ( delta %u mV )",
                 sends,
                 hf_baseline,
                 hf_peak,
                 AdcRssiDataToMilliVolt(hf_peak - hf_baseline, ADC_RSSI_CH_HF)
                );
    }

    set_tracing(false);
    reply_ng(CMD_HF_THINFILM_SIMULATE, status, NULL, 0);
}
