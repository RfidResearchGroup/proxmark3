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

#define SEC_D 0xf0
#define SEC_E 0x0f
#define SEC_F 0x00

static uint16_t ReadReaderField(void) {
    return AdcRssiAvg(ADC_RSSI_CH_HF);
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

    Dbprintf("Simulate " _YELLOW_("%i-bit Thinfilm") " tag", len * 8);

    // connect Demodulated Signal to ADC:
    SetAdcMuxFor(ADC_MUXSEL_HIPKD);

    // Set up the synchronous serial port
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_MOD);

    SpinDelay(100);

    // Start the timer
    StartCountSspClk();

    uint16_t hf_baseline = ReadReaderField();

    int8_t status = PM3_SUCCESS;
    CodeThinfilmAsTag(data, len);

    tosend_t *ts = get_tosend();

    for (int i = 0; i < ts->max; i += 16) {
        Dbhexdump(16, ts->buf + i, false);
    }
    DbpString("------------------------------------------");

    LED_A_ON();

    for (;;) {

        WDT_HIT();

        // Test if the action was cancelled
        if (BUTTON_PRESS() || data_available()) {
            status = PM3_EOPABORTED;
            break;
        }

        uint16_t hf_av = ReadReaderField();

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
            if (AdcRssiDataToMilliVolt(hf_av - hf_baseline, ADC_RSSI_CH_HF) > 1375) {
                EmSendCmdThinfilmRaw(ts->buf, ts->max);
                if (len == 16) {
                    // wait 3.6ms
                    SpinDelayUs(3600);
                } else {
                    // wait 2.4ms
                    SpinDelayUs(2400);
                }
            }
        }

    }

    LED_A_OFF();
    reply_ng(CMD_HF_THINFILM_SIMULATE, status, NULL, 0);
}
