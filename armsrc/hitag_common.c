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
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "util.h"
#include "string.h"
#include "commonutil.h"
#include "hitag2/hitag2_crypto.h"
#include "lfadc.h"
#include "crc.h"
#include "protocols.h"
#include "appmain.h"    // tearoff_hook()

uint16_t timestamp_high = 0;  // Timer Counter 2 overflow count, combined with TC2 counter for ~47min timing

static void hitag_stop_clock(void) {
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKDIS;
}

static void hitag_init_clock(void) {
    // Enable Peripheral Clock for
    //   Timer Counter 0, used to measure exact timing before answering
    //   Timer Counter 1, used to capture edges of the tag frames
    //   Timer Counter 2, used to log trace time
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0) | (1 << AT91C_ID_TC1) | (1 << AT91C_ID_TC2);

    AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;

    // Disable timer during configuration
    hitag_stop_clock();

    // TC0: Capture mode, default timer source = MCK/32 (TIMER_CLOCK3), no triggers
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK;

    // TC1: Capture mode, default timer source = MCK/32 (TIMER_CLOCK3), TIOA is external trigger,
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK  // use MCK/32 (TIMER_CLOCK3)
                             | AT91C_TC_ABETRG               // TIOA is used as an external trigger
                             | AT91C_TC_ETRGEDG_FALLING      // external trigger on falling edge
                             | AT91C_TC_LDRA_RISING          // load RA on on rising edge of TIOA
                             | AT91C_TC_LDRB_FALLING;        // load RB on on falling edge of TIOA

    // TC2: Capture mode, default timer source = MCK/32 (TIMER_CLOCK3), no triggers
    AT91C_BASE_TC2->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK;

    // Enable and reset counters
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // Assert a sync signal. This sets all timers to 0 on next active clock edge
    AT91C_BASE_TCB->TCB_BCR = 1;

    // synchronized startup procedure
    // In theory, with MCK/32, we shouldn't be waiting longer than 32 instruction statements, right?
    while (AT91C_BASE_TC0->TC_CV != 0) {
    };  // wait until TC0 returned to zero

    // reset timestamp
    timestamp_high = 0;
}

// Initialize FPGA and timer for Hitag operations
void hitag_setup_fpga(uint16_t conf, uint8_t threshold, bool ledcontrol) {
    StopTicks();

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    if (ledcontrol) LED_D_ON();

    hitag_init_clock();

    // Set fpga in edge detect with/without reader field, we can modulate as reader/tag now
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | conf);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125);  //125kHz
    if (threshold != 127) FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, threshold);
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Configure output and enable pin that is connected to the FPGA (for modulating)
    AT91C_BASE_PIOA->PIO_OER |= GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_PER |= GPIO_SSC_DOUT;

    // Disable modulation at default, which means enable the field
    LOW(GPIO_SSC_DOUT);
}

// Clean up and finalize Hitag operations
void hitag_cleanup(bool ledcontrol) {
    hitag_stop_clock();
    set_tracing(false);
    lf_finalize(ledcontrol);
}

// Reader functions
static void hitag_reader_send_bit(int bit, bool ledcontrol) {
    // Reset clock for the next bit
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    while (AT91C_BASE_TC0->TC_CV != 0) {};

    if (ledcontrol) LED_A_ON();

    // Binary puls length modulation (BPLM) is used to encode the data stream
    // This means that a transmission of a one takes longer than that of a zero
    HIGH(GPIO_SSC_DOUT);

    // Wait for 4-10 times the carrier period
    while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_LOW) {};

    LOW(GPIO_SSC_DOUT);

    if (bit == 0) {
        // Zero bit: |_-|
        while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_0) {};
    } else {
        // One bit: |_--|
        while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_1) {};
    }

    if (ledcontrol) LED_A_OFF();
}

void hitag_reader_send_frame(const uint8_t *frame, size_t frame_len, bool ledcontrol, bool send_sof) {
    // Send SOF (Start of Frame) for Hitag µ if requested
    if (send_sof) {
        hitag_reader_send_bit(0, ledcontrol);

        // Reset clock for the code violation
        AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
        while (AT91C_BASE_TC0->TC_CV != 0) {};

        if (ledcontrol) LED_A_ON();

        // SOF is HIGH for HITAG_T_LOW
        HIGH(GPIO_SSC_DOUT);
        while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_LOW) {};

        // Then LOW for HITAG_T_CODE_VIOLATION
        LOW(GPIO_SSC_DOUT);
        while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_CODE_VIOLATION) {};

        if (ledcontrol) LED_A_OFF();
    }

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        hitag_reader_send_bit(TEST_BIT_MSB(frame, i), ledcontrol);
    }

    // Send EOF
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    while (AT91C_BASE_TC0->TC_CV != 0) {};

    HIGH(GPIO_SSC_DOUT);

    // Wait for 4-10 times the carrier period
    while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_LOW) {};

    LOW(GPIO_SSC_DOUT);
}

void hitag_reader_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *resptime, bool ledcontrol,
                                MOD modulation, int sof_bits) {
    // Reset values for receiving frames
    memset(rx, 0x00, sizeofrx);
    *rxlen = 0;

    int lastbit = 1;
    bool bSkip = true;
    uint32_t errorCount = 0;
    bool bStarted = false;
    uint16_t next_edge_event = AT91C_TC_LDRBS;
    int double_speed = (modulation == AC4K || modulation == MC8K) ? 2 : 1;

    uint32_t rb_i = 0;
    uint8_t edges[160] = {0};

    // Skip SOF bits
    bool sof_received = false;

    // Receive tag frame, watch for at most T0*HITAG_T_PROG_MAX periods
    while (AT91C_BASE_TC0->TC_CV < (T0 * HITAG_T_PROG_MAX)) {
        // Check if edge in tag modulation is detected
        if (AT91C_BASE_TC1->TC_SR & next_edge_event) {
            next_edge_event = next_edge_event ^ (AT91C_TC_LDRAS | AT91C_TC_LDRBS);

            // only use AT91C_TC_LDRBS falling edge for now
            if (next_edge_event == AT91C_TC_LDRBS) continue;

            // Retrieve the new timing values
            uint32_t rb = AT91C_BASE_TC1->TC_RB / T0;
            edges[rb_i++] = rb;

            // Reset timer every frame, we have to capture the last edge for timing
            AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

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
                        if (lastbit) SET_BIT_MSB(rx, *rxlen);
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
                        if (lastbit) SET_BIT_MSB(rx, *rxlen);
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
                        if (TEST_BIT_MSB(&tmp, sof_bits + i)) SET_BIT_MSB(rx, i);
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
        if (AT91C_BASE_TC1->TC_CV > (T0 * 80)) {
            if (bStarted) {
                break;
            }
        }
    }

    DBG {
        Dbprintf("RX %i:%02X.. resptime:%i edges:", *rxlen, rx[0], *resptime);
        Dbhexdump(rb_i, edges, false);
    }
}

// Tag functions - depends on modulation type
static void hitag_tag_send_bit(int bit, MOD modulation, bool ledcontrol) {
    // Reset clock for the next bit
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

    if (ledcontrol) LED_A_ON();

    switch (modulation) {
        case AC2K: {
            if (bit == 0) {
                // AC Coding --__
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 64) {};
            } else {
                // AC coding -_-_
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {};

                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 48) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 64) {};
            }
            break;
        }
        case AC4K: {
            if (bit == 0) {
                // AC Coding --__
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_TAG_HALF_PERIOD) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_TAG_FULL_PERIOD) {};
            } else {
                // AC coding -_-_
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 8) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};

                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 24) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {};
            }
            break;
        }
        case MC4K: {
            if (bit == 0) {
                // Manchester: Unloaded, then loaded |__--|
                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};

                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {};
            } else {
                // Manchester: Loaded, then unloaded |--__|
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {};
            }
            break;
        }
        case MC8K: {
            if (bit == 0) {
                // Manchester: Unloaded, then loaded |__--|
                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 8) {};

                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};
            } else {
                // Manchester: Loaded, then unloaded |--__|
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 8) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};
            }
            break;
        }
    }

    if (ledcontrol) LED_A_OFF();
}

void hitag_tag_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *start_time, bool ledcontrol, int *overflow) {
    uint16_t next_edge_event = AT91C_TC_LDRBS;
    uint8_t edges[160] = {0};
    uint32_t rb_i = 0;

    // Receive frame, watch for at most T0*EOF periods
    while (AT91C_BASE_TC1->TC_CV < T0 * HITAG_T_EOF) {

        // Check if edge in modulation is detected
        if (AT91C_BASE_TC1->TC_SR & next_edge_event) {
            next_edge_event = next_edge_event ^ (AT91C_TC_LDRAS | AT91C_TC_LDRBS);

            // only use AT91C_TC_LDRBS falling edge for now
            if (next_edge_event == AT91C_TC_LDRBS) continue;

            // Retrieve the new timing values
            uint32_t rb = AT91C_BASE_TC1->TC_RB / T0 + *overflow;
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

void hitag_tag_send_frame(const uint8_t *frame, size_t frame_len, int sof_bits, MOD modulation, bool ledcontrol) {
    // The beginning of the frame is hidden in some high level; pause until our bits will have an effect
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    HIGH(GPIO_SSC_DOUT);

    switch (modulation) {
        case AC4K:
        case MC8K: {
            while (AT91C_BASE_TC0->TC_CV < T0 * 40) {}; // FADV
            break;
        }
        case AC2K:
        case MC4K: {
            while (AT91C_BASE_TC0->TC_CV < T0 * 20) {}; // STD + ADV
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

    LOW(GPIO_SSC_DOUT);
}
