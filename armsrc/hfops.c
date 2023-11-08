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
#include "appmain.h"
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
    reply_ng(CMD_HF_ACQ_RAW_ADC, PM3_SUCCESS, (uint8_t *)&scnt, 4);
    if (ledcontrol) LEDsoff();

    return 0;
}

uint8_t encode_acc = 0;
uint8_t encode_acc_bit_count = 0;
uint32_t encode_indx = 0;

static void EncodeInit(void) {
    encode_acc = 0;
    encode_acc_bit_count = 0;
    encode_indx = 0;
}

static void EncodeAddBit(uint8_t *data, uint8_t bit, uint8_t bit_count) {
    for (int i = 0; i < bit_count; i++) {
        encode_acc = (encode_acc << 1) | (bit & 0x01);
        encode_acc_bit_count++;
        if (encode_acc_bit_count > 7) {
            data[encode_indx++] = encode_acc;
            encode_acc = 0;
            encode_acc_bit_count = 0;
        }
    }
}

static uint32_t EncodeFinish(uint8_t *data) {
    if (encode_acc_bit_count > 0) {
        encode_acc = encode_acc << (8 - encode_acc_bit_count);
        data[encode_indx++] = encode_acc;
    }

    return encode_indx;
}

static uint32_t HfEncodeTkm(const uint8_t *uid, uint8_t modulation, uint8_t *data) {
    uint32_t len = 0;
    if (modulation == 0) {
        // TK-13
        // 74ns 1 field cycle,
        // carrier frequency is fc/64 (212kHz), 4.7 mks
        // 100  field cycle = impulse  1.6 ( 1 bit from real tag)
        // 1000 field cycle = `1`     15.6 (17 bit from real tag)
        // 500  field cycle = `0`      7.8 ( 7 bit from real tag)

        EncodeInit();
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                if (((uid[i] << j) & 0x80) != 0) {
                    // `1`
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 17);
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 7);
                } else {
                    // `0`
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 7);
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 17);
                }
            }
        }
        len = EncodeFinish(data);
    } else {
        // TK-17
        // 74ns 1 field cycle,
        // carrier frequency is fc/64 (212kHz), 4.7 mks
        // 0 --- 8 --- 12-15 --- 18-19 --- 26-28 --- 32
        // DO NOT NORMALIZE!!!! it must be with some error like this!!!!
        // `00` -- 1-25-1-5
        // `01` -- 1-12-1-18
        // `10` -- 1-17-1-13
        // `11` -- 1-7-1-23

        EncodeInit();
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j += 2) {
                uint8_t twobit = ((uid[i] >> j) & 0x03);
                if (twobit == 0x00) {
                    // `00`
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 25);
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 5);
                } else if (twobit == 0x01) {
                    // `01`
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 12);
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 18);
                } else if (twobit == 0x02) {
                    // `10`
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 17);
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 13);
                } else { // twobit == 0x03
                    // `11`
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 7);
                    EncodeAddBit(data, 1, 1);
                    EncodeAddBit(data, 0, 23);
                }
            }
        }
        EncodeAddBit(data, 1, 1);
        len = EncodeFinish(data);
    }

    return len;
}

int HfSimulateTkm(const uint8_t *uid, uint8_t modulation, uint32_t timeout) {
    // free eventually allocated BigBuf memory
    BigBuf_free_keep_EM();

    LEDsoff();

    uint8_t *data = BigBuf_calloc(256);
    uint32_t elen = HfEncodeTkm(uid, modulation, data);
    if (elen == 0) {
        DbpString("encode error");
        reply_ng(CMD_HF_TEXKOM_SIMULATE, PM3_EAPDU_ENCODEFAIL, NULL, 0);
        return PM3_EAPDU_ENCODEFAIL;
    }

    LED_C_ON();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_212K);
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_SIMULATOR);

    bool button_pressed = false;
    bool exit_loop = false;
    bool field_on = false;

    uint32_t startTime = GetTickCount();
    while (exit_loop == false) {

        button_pressed = BUTTON_PRESS();
        if (button_pressed || data_available()) {
            break;
        }

        WDT_HIT();

        if (timeout > 0 && startTime + timeout < GetTickCount())
            break;

        // in mV
        int vHf = (MAX_ADC_HF_VOLTAGE * SumAdc(ADC_CHAN_HF, 32)) >> 15;
        if (vHf > MF_MINFIELDV) {
            if (field_on == false) {
                LED_A_ON();
                SpinDelay(50);
            }
            field_on = true;
        } else {
            if (field_on) {
                LED_A_OFF();
            }
            field_on = false;
            continue;
        }

        SpinDelay(3);

        for (int i = 0; i < elen;) {
            if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) {
                AT91C_BASE_SSC->SSC_THR = data[i++];
            }
        }
    }

    switch_off();

    if (button_pressed)
        DbpString("Exit by press button");

    reply_ng(CMD_HF_TEXKOM_SIMULATE, PM3_SUCCESS, NULL, 0);

    return PM3_SUCCESS;
}
