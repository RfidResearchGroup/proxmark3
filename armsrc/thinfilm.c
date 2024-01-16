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
#include "fpgaloader.h"
#include "ticks.h"
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
    uint8_t buf[36] = {0x00};

    // power on and listen for answer.
    bool status = GetIso14443aAnswerFromTag_Thinfilm(buf, &len);
    reply_ng(CMD_HF_THINFILM_READ, status ? PM3_SUCCESS : PM3_ENODATA, buf, len);

    hf_field_off();
    set_tracing(false);
}

#define SEC_D 0xf0
#define SEC_E 0x0f
#define SEC_F 0x00
static uint16_t FpgaSendQueueDelay;

static uint16_t ReadReaderField(void) {
    return AvgAdc(ADC_CHAN_HF);
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
    ts->max++;
}

static int EmSendCmdThinfilmRaw(const uint8_t *resp, uint16_t respLen) {
    volatile uint8_t b;
    uint16_t i = 0;
    uint32_t ThisTransferTime;
    // wait for the FPGA to signal fdt_indicator == 1 (the FPGA is ready to queue new data in its delay line)
    for (uint8_t j = 0; j < 5; j++) {    // allow timeout - better late than never
        while (!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY));
        if (AT91C_BASE_SSC->SSC_RHR) break;
    }
    while ((ThisTransferTime = GetCountSspClk()) & 0x00000007);


    // Clear TXRDY:
    AT91C_BASE_SSC->SSC_THR = SEC_F;

    // send cycle
    for (; i < respLen;) {
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = resp[i++];
            FpgaSendQueueDelay = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
        }

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            b = (uint16_t)(AT91C_BASE_SSC->SSC_RHR);
            (void)b;
        }
        if (BUTTON_PRESS()) break;
    }

    // Ensure that the FPGA Delay Queue is empty
    uint8_t fpga_queued_bits = FpgaSendQueueDelay >> 3;
    for (i = 0; i <= fpga_queued_bits / 8 + 1;) {
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = SEC_F;
            FpgaSendQueueDelay = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
            i++;
        }
    }

    return 0;
}

void SimulateThinFilm(uint8_t *data, size_t len) {
    Dbprintf("Simulate %i-bit Thinfilm tag", len * 8);
    Dbhexdump(len, data, true);
    int16_t status = PM3_SUCCESS;
    CodeThinfilmAsTag(data, len);

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // Set up the synchronous serial port
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);

    // connect Demodulated Signal to ADC:
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_MOD);
    SpinDelay(100);

    uint16_t hf_baseline = ReadReaderField();

    tosend_t *ts = get_tosend();

    // Start the timer
    StartCountSspClk();

    bool reader_detected = false;
    LED_A_ON();
    for (;;) {
        WDT_HIT();
        if (BUTTON_PRESS() || data_available()) {
            status = PM3_EOPABORTED;
            break;
        }
        uint16_t hf_av = ReadReaderField();
        if (hf_av < hf_baseline)
            hf_baseline = hf_av;
        if (hf_av > hf_baseline + 10) {

            EmSendCmdThinfilmRaw(ts->buf, ts->max);
            if (!reader_detected) {
                LED_B_ON();
                //Dbprintf("Reader detected, start beaming data");
                reader_detected = true;
            }
        } else {
            if (reader_detected) {
                LED_B_OFF();
                //Dbprintf("Reader gone, stop beaming data");
                reader_detected = false;
            }
        }
    }
    LED_A_OFF();
    reply_ng(CMD_HF_THINFILM_SIMULATE, status, NULL, 0);
}
