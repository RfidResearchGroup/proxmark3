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
// Hitag shared functionality
//-----------------------------------------------------------------------------

#include "hitag_common.h"

#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "fpga_loader.h"
#include "fpga_apis.h"
#include "ticks_apis.h"
#include "dbprint.h"
#include "util.h"
#include "string.h"
#include "commonutil.h"
#include "hitag2/hitag2_crypto.h"
#include "lfadc.h"
#include "crc.h"
#include "protocols.h"
#include "appmain.h"    // tearoff_hook()

// Initialize FPGA and timer for Hitag operations
void hitag_setup_fpga(uint16_t conf, uint8_t threshold, bool ledcontrol) {
    StopTicks();

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    if (ledcontrol) LED_D_ON();

    // Configure the timers via the HAL: a precision counter (T0 timing), an
    // input capture (tag frame edges) and a timestamp counter (trace timing).
    StartPrecisionCounter();
    StartInputCapture();
    StartTimestamp();

    // Set fpga in edge detect with/without reader field, we can modulate as reader/tag now
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | conf);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125);  //125kHz
    if (threshold != 127) FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, threshold);
    SetAdcMuxFor(ADC_MUXSEL_LOPKD);

    // Configure output and enable pin that is connected to the FPGA (for modulating)
    gpio_fpga_mod_only_setup();

    // Disable modulation at default, which means enable the field
    Gpio_SSC_DOUT_Low();
}

// Clean up and finalize Hitag operations
void hitag_cleanup(bool ledcontrol) {
    StopPrecisionCounter();
    StopInputCapture();
    StopTimestamp();
    set_tracing(false);
    lf_finalize(ledcontrol);
}

// Reader functions
static void hitag_reader_send_bit(int bit, bool ledcontrol) {
    // Reset clock for the next bit
    ResetPrecisionCounter();

    if (ledcontrol) LED_A_ON();

    // Binary puls length modulation (BPLM) is used to encode the data stream
    // This means that a transmission of a one takes longer than that of a zero
    Gpio_SSC_DOUT_High();

    // Wait for 4-10 times the carrier period
    while (GetPrecisionCounter() < T0 * HITAG_T_LOW) {};

    Gpio_SSC_DOUT_Low();

    if (bit == 0) {
        // Zero bit: |_-|
        while (GetPrecisionCounter() < T0 * HITAG_T_0) {};
    } else {
        // One bit: |_--|
        while (GetPrecisionCounter() < T0 * HITAG_T_1) {};
    }

    if (ledcontrol) LED_A_OFF();
}

void hitag_reader_send_frame(const uint8_t *frame, size_t frame_len, bool ledcontrol, bool send_sof) {
    // Send SOF (Start of Frame) for Hitag µ if requested
    if (send_sof) {
        hitag_reader_send_bit(0, ledcontrol);

        // Reset clock for the code violation
        ResetPrecisionCounter();

        if (ledcontrol) LED_A_ON();

        // SOF is HIGH for HITAG_T_LOW
        Gpio_SSC_DOUT_High();
        while (GetPrecisionCounter() < T0 * HITAG_T_LOW) {};

        // Then LOW for HITAG_T_CODE_VIOLATION
        Gpio_SSC_DOUT_Low();
        while (GetPrecisionCounter() < T0 * HITAG_T_CODE_VIOLATION) {};

        if (ledcontrol) LED_A_OFF();
    }

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        hitag_reader_send_bit(TEST_BIT_MSB(frame, i), ledcontrol);
    }

    // Send EOF
    ResetPrecisionCounter();

    Gpio_SSC_DOUT_High();

    // Wait for 4-10 times the carrier period
    while (GetPrecisionCounter() < T0 * HITAG_T_LOW) {};

    Gpio_SSC_DOUT_Low();
}

void hitag_reader_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *resptime, bool ledcontrol,
                                hitag_mod_t modulation, int sof_bits) {
    // Reset values for receiving frames
    memset(rx, 0x00, sizeofrx);
    *rxlen = 0;

    int lastbit = 1;
    bool bSkip = true;
    uint32_t errorCount = 0;
    bool bStarted = false;
    uint16_t next_edge_event = INPUT_CAPTURE_EVT_RB;
    int double_speed = (modulation == AC4K || modulation == MC8K) ? 2 : 1;

    uint32_t rb_i = 0;
    uint8_t edges[160] = {0};

    // Skip SOF bits
    bool sof_received = false;

    // Receive tag frame, watch for at most T0*HITAG_T_PROG_MAX periods
    while (GetPrecisionCounter() < (T0 * HITAG_T_PROG_MAX)) {
        // Check if edge in tag modulation is detected
        if (GetInputCaptureStatus() & next_edge_event) {
            next_edge_event = next_edge_event ^ (INPUT_CAPTURE_EVT_RA | INPUT_CAPTURE_EVT_RB);

            // only use INPUT_CAPTURE_EVT_RB falling edge for now
            if (next_edge_event == INPUT_CAPTURE_EVT_RB) {
                continue;
            }

            // Retrieve the new timing values
            uint32_t rb = GetInputCaptureValue() / T0;

            // For debug, save the edges for decoding manual
            if (rb_i < sizeof(edges)) {
                edges[rb_i++] = rb;
            }

            // Reset timer every frame, we have to capture the last edge for timing
            ResetPrecisionCounter();

            if (ledcontrol) LED_B_INV();

            // Capture tag frame (manchester decoding using only falling edges)
            if (bStarted == false) {
                if (rb >= HITAG_T_WAIT_RESP) {
                    bStarted = true;

                    // Capture tag response timestamp
                    *resptime = TIMESTAMP;

                    // We always receive a 'one' first, which has the falling edge after a half period |-_|
                    rx[0] = 0x80;
                    *rxlen = 1;
                } else {
                    errorCount++;
                }
            } else {
                // Handle different modulation types
                if (modulation == AC2K || modulation == AC4K) {
                    // Anticollision Coding
                    if (rb >= HITAG_T_TAG_CAPTURE_FOUR_HALF / double_speed) {
                        // Anticollision Coding example |--__|--__| (00)
                        lastbit = 0;
                        // CLEAR_BIT_MSB(rx, *rxlen);
                        (*rxlen)++;
                    } else if (rb >= HITAG_T_TAG_CAPTURE_THREE_HALF / double_speed) {
                        // Anticollision Coding example |-_-_|--__| (10) or |--__|-_-_| (01)
                        lastbit = !lastbit;
                        if (lastbit) {
                            SET_BIT_MSB(rx, *rxlen);
                        }
                        (*rxlen)++;

                        bSkip = !!lastbit;
                    } else if (rb >= HITAG_T_TAG_CAPTURE_TWO_HALF / double_speed) {
                        // Anticollision Coding example |-_-_| (1)
                        if (bSkip == false) {
                            lastbit = 1;
                            SET_BIT_MSB(rx, *rxlen);
                            (*rxlen)++;
                        }

                        bSkip = !bSkip;
                    } else {
                        // Ignore weird value, is to small to mean anything
                        errorCount++;
                    }
                } else {
                    // Manchester coding (MC4K, MC8K)
                    if (rb >= HITAG_T_TAG_CAPTURE_FOUR_HALF / double_speed) {
                        // Manchester coding example |-_|_-|-_| (101)
                        // CLEAR_BIT_MSB(rx, *rxlen);
                        (*rxlen)++;

                        SET_BIT_MSB(rx, *rxlen);
                        (*rxlen)++;
                    } else if (rb >= HITAG_T_TAG_CAPTURE_THREE_HALF / double_speed) {
                        // Manchester coding example |_-|...|_-|-_| (0...01)
                        // CLEAR_BIT_MSB(rx, *rxlen);
                        (*rxlen)++;

                        // We have to skip this half period at start and add the 'one' the second time
                        if (bSkip == false) {
                            SET_BIT_MSB(rx, *rxlen);
                            (*rxlen)++;
                        }

                        lastbit = !lastbit;
                        bSkip = !bSkip;
                    } else if (rb >= HITAG_T_TAG_CAPTURE_TWO_HALF / double_speed) {
                        // Manchester coding example |_-|_-| (00) or |-_|-_| (11)
                        // bit is same as last bit
                        if (lastbit) {
                            SET_BIT_MSB(rx, *rxlen);
                        }
                        (*rxlen)++;
                    } else {
                        // Ignore weird value, is to small to mean anything
                        errorCount++;
                    }
                }

                // Handle SOF bits
                if (sof_received == false && *rxlen >= sof_bits) {
                    // Check if SOF is valid (all bits should be 1)
                    if ((rx[0] >> (8 - sof_bits)) != ((1 << sof_bits) - 1)) {
                        if (sof_bits == 4) {
                            sof_bits = 3;
                            // Hitag µ is LSB first 0b110
                            if ((rx[0] & 0xE0) != 0xC0) {
                                DBG Dbprintf("Warning, SOF is invalid rx[0]: 0x%02X", rx[0]);
                            }
                        } else {
                            DBG DbpString("Warning, not all bits of SOF are 1");
                        }
                    }

                    *rxlen -= sof_bits;
                    uint8_t tmp = rx[0];
                    rx[0] = 0x00;
                    for (size_t i = 0; i < *rxlen; i++) {
                        if (TEST_BIT_MSB(&tmp, sof_bits + i)) {
                            SET_BIT_MSB(rx, i);
                        }
                    }
                    // DBG Dbprintf("after sof_bits rxlen: %d rx[0]: 0x%02X", *rxlen, rx[0]);
                    sof_received = true;
                }
            }
        }

        // if we saw over 100 weird values break it probably isn't hitag...
        if (errorCount > 100 || (*rxlen) / 8 >= sizeofrx) {
            break;
        }

        // We can break this loop if we received the last bit from a frame
        // max periods between 2 falling edge
        // RTF AC64 |--__|--__| (00) 64 * T0
        // RTF MC32 |_-|-_|_-| (010) 48 * T0
        if (GetInputCaptureCount() > (T0 * 80)) {
            if (bStarted) {
                break;
            }
        }
    }

    DBG {
        Dbprintf("bStarted:%d bSkip:%d lastbit:%d sof_received:%d", bStarted, bSkip, lastbit, sof_received);
        Dbprintf("RX %i:%02X.. resptime:%i", *rxlen, rx[0], *resptime);
        Dbprintf("Edges count: %d, hex: ", rb_i);
        Dbhexdump(rb_i, edges, false);
    }
}

int hitag_reader_transfer(const uint8_t *tx, size_t txlen, uint8_t *rx, size_t sizeofrx, size_t *rxlen, int t_wait,
                          bool ledcontrol, hitag_mod_t modulation, uint8_t sof_bits, uint8_t send_sof) {
    uint32_t start_time = 0;

    DBG Dbprintf("tx %d bits:", txlen);
    DBG Dbhexdump((txlen + 7) / 8, tx, false);

    // Disable input capture to avoid triggers during our own modulation.
    StopInputCapture();

    // Wait for HITAG_T_WAIT_SC carrier periods after the last tag bit before transmitting,
    // Since the clock counts since the last falling edge, a 'one' means that the
    // falling edge occurred halfway the period. with respect to this falling edge,
    // we need to wait (T_Wait2 + half_tag_period) when the last was a 'one'.
    // All timer values are in terms of T0 units
    while (GetPrecisionCounter() < T0 * t_wait) {};

    start_time = TIMESTAMP;

    // Transmit the reader frame
    hitag_reader_send_frame(tx, txlen, ledcontrol, send_sof);

    // tearoff
    if (g_tearoff_enabled && tearoff_hook() == PM3_ETEAROFF) {
        return PM3_ETEAROFF;
    }

    LogTraceBits(tx, txlen, start_time, TIMESTAMP, true);

    // Enable and reset input capture for capturing the tag response.
    EnableInputCapture();

    hitag_reader_receive_frame(rx, sizeofrx, rxlen, &start_time, ledcontrol, modulation, sof_bits);

    DBG Dbprintf("rx %d bits:", *rxlen);
    DBG Dbhexdump((int)(*rxlen + 7) / 8, rx, false);

    // Check if frame was captured and store it
    if (*rxlen > 0) {
        DBG {
            uint8_t response_bit[sizeofrx * 8];

            for (size_t i = 0; i < *rxlen; i++) {
                response_bit[i] = (rx[i / 8] >> (7 - (i % 8))) & 1;
            }

            Dbprintf("ht?: rxlen...... %zu", *rxlen);
            Dbprintf("ht?: sizeofrx... %zu", sizeofrx);
            DbpString("ht?: response_bit:");
            Dbhexdump((int) *rxlen, response_bit, false);
        }

        LogTraceBits(rx, *rxlen, start_time, TIMESTAMP, false);
    }

    return PM3_SUCCESS;
}

// Tag functions - depends on modulation type
static void hitag_tag_send_bit(int bit, hitag_mod_t modulation, bool ledcontrol) {
    // Reset clock for the next bit
    ResetPrecisionCounter();

    if (ledcontrol) LED_A_ON();

    switch (modulation) {
        case AC2K: {
            if (bit == 0) {
                // AC Coding --__
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 32) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 64) {};
            } else {
                // AC coding -_-_
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 16) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 32) {};

                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 48) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 64) {};
            }
            break;
        }
        case AC4K: {
            if (bit == 0) {
                // AC Coding --__
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * HITAG_T_TAG_HALF_PERIOD) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * HITAG_T_TAG_FULL_PERIOD) {};
            } else {
                // AC coding -_-_
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 8) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 16) {};

                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 24) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 32) {};
            }
            break;
        }
        case MC4K: {
            if (bit == 0) {
                // Manchester: Unloaded, then loaded |__--|
                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 16) {};

                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 32) {};
            } else {
                // Manchester: Loaded, then unloaded |--__|
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 16) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 32) {};
            }
            break;
        }
        case MC8K: {
            if (bit == 0) {
                // Manchester: Unloaded, then loaded |__--|
                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 8) {};

                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 16) {};
            } else {
                // Manchester: Loaded, then unloaded |--__|
                Gpio_SSC_DOUT_High();
                while (GetPrecisionCounter() < T0 * 8) {};

                Gpio_SSC_DOUT_Low();
                while (GetPrecisionCounter() < T0 * 16) {};
            }
            break;
        }
    }

    if (ledcontrol) LED_A_OFF();
}

void hitag_tag_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *start_time, bool ledcontrol, int *overflow) {
    uint16_t next_edge_event = INPUT_CAPTURE_EVT_RB;
    uint8_t edges[160] = {0};
    uint32_t rb_i = 0;

    // Receive frame, watch for at most T0*EOF periods
    while (GetInputCaptureCount() < T0 * HITAG_T_EOF) {

        // Check if edge in modulation is detected
        if (GetInputCaptureStatus() & next_edge_event) {
            next_edge_event = next_edge_event ^ (INPUT_CAPTURE_EVT_RA | INPUT_CAPTURE_EVT_RB);

            // only use INPUT_CAPTURE_EVT_RB falling edge for now
            if (next_edge_event == INPUT_CAPTURE_EVT_RB) continue;

            // Retrieve the new timing values
            uint32_t rb = GetInputCaptureValue() / T0 + *overflow;
            *overflow = 0;

            edges[rb_i++] = rb;

            if (ledcontrol) LED_B_INV();

            // Capture reader cmd start timestamp
            if (*start_time == 0) {
                *start_time = TIMESTAMP - HITAG_T_LOW;
            }

            // Capture reader frame
            if (rb >= HITAG_T_STOP) {
                // Hitag µ SOF
                if (*rxlen != 0 && *rxlen != 1) {
                    // DBG DbpString("weird0?");
                    break;
                }
                *rxlen = 0;
            } else if (rb >= HITAG_T_1_MIN) {
                // '1' bit
                SET_BIT_MSB(rx, *rxlen);
                (*rxlen)++;
            } else if (rb >= HITAG_T_0_MIN) {
                // '0' bit
                // CLEAR_BIT_MSB(rx, *rxlen);
                (*rxlen)++;
            } else {
                // Ignore weird value, is too small to mean anything
            }
        }
    }

    if (ledcontrol) LED_B_OFF();

    DBG if (rb_i) {
        Dbprintf("RX %i bits.. start_time:%i edges:", *rxlen, *start_time);
        Dbhexdump(rb_i, edges, false);
    }
}

void hitag_tag_send_frame(const uint8_t *frame, size_t frame_len, int sof_bits, hitag_mod_t modulation, bool ledcontrol) {
    // The beginning of the frame is hidden in some high level; pause until our bits will have an effect
    ResetPrecisionCounter();
    Gpio_SSC_DOUT_High();

    switch (modulation) {
        case AC4K:
        case MC8K: {
            while (GetPrecisionCounter() < T0 * 40) {}; // FADV
            break;
        }
        case AC2K:
        case MC4K: {
            while (GetPrecisionCounter() < T0 * 20) {}; // STD + ADV
            break;
        }
    }

    // SOF - send start of frame
    for (size_t i = 0; i < sof_bits; i++) {
        if (sof_bits == 4 && i == 3) {
            // Hitag µ SOF is 110
            hitag_tag_send_bit(0, modulation, ledcontrol);
            break;
        } else
            hitag_tag_send_bit(1, modulation, ledcontrol);
    }

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        hitag_tag_send_bit(TEST_BIT_MSB(frame, i), modulation, ledcontrol);
    }

    Gpio_SSC_DOUT_Low();
}
