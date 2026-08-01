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

uint16_t timestamp_high = 0; // Timer Counter 2 overflow count, combined with TC2 counter for ~47min timing

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
    }; // wait until TC0 returned to zero

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

    if (ledcontrol) {
        LED_D_ON();
    }

    hitag_init_clock();

    // Set fpga in edge detect with/without reader field, we can modulate as reader/tag now
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | conf);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125); //125kHz
    if (threshold != 127) FpgaSendCommand(FPGA_CMD_SET_EDGE_DETECT_THRESHOLD, threshold);
    SetAdcMuxFor(ADC_MUXSEL_LOPKD);

    // Configure output and enable pin that is connected to the FPGA (for modulating)
    gpio_fpga_mod_only_setup();

    // Disable modulation at default, which means enable the field
    Gpio_SSC_DOUT_Low();
}

// Clean up and finalize Hitag operations
void hitag_cleanup(bool ledcontrol) {
    hitag_stop_clock();
    set_tracing(false);
    lf_finalize(ledcontrol);
}

/**
 * Send data or condition to TAG
 *
 * This function will modulate a fixed length gap before modulating the data/condition of the specified period,
 * and the number of periods of the data/condition modulated later will subtract the number of gaps.
 *
 * @param periods The numbers of  periods for data/condition modulation
 * @param ledcontrol Show the LED flash
 */
static RAMFUNC void hitag_reader_send_with_gap(int periods, bool ledcontrol) {
    if (ledcontrol)
        LED_A_ON();

    // Binary puls length modulation (BPLM) is used to encode the data stream
    // This means that a transmission of a one takes longer than that of a zero

    // GPIOB->clr = GPIO_PINS_11; // TODO DXL 测试添加

    // Send GAP
    Gpio_SSC_DOUT_High();
    lf_wait_periods(HITAG_T_LOW); // Wait for 4-10 times the carrier period

    // GPIOB->scr = GPIO_PINS_11; // TODO DXL 测试添加

    Gpio_SSC_DOUT_Low();
    lf_wait_periods(periods - HITAG_T_LOW);

    if (ledcontrol)
        LED_A_OFF();
}

void hitag_reader_send_frame(const uint8_t *frame, size_t frame_len, bool ledcontrol, bool send_sof) {
    // Send SOF (Start of Frame) for Hitag µ if requested
    if (send_sof) {
        // The RWD requests in the data exchange mode always a start with a SOF pattern for ease
        // of synchronization. The SOF pattern consists of an encoded data bit ’0’ and a ’code violation’.
        hitag_reader_send_with_gap(HITAG_T_0, ledcontrol);
        // According to the manual description, the TFcv timing includes the TF1 timing,
        // so it is necessary to subtract the TF1 timing(subtract inside the 'hitag_reader_send_with_gap').
        hitag_reader_send_with_gap(HITAG_T_CODE_VIOLATION, ledcontrol);
    }

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        hitag_reader_send_with_gap(TEST_BIT_MSB(frame, i) ? HITAG_T_1 : HITAG_T_0, ledcontrol);
    }

    // 36 + 8 = 44(t0), if you have the wait for 'twresp', the 'twresp' need to subtract HITAG_T_LOW + HITAG_T_STOP
    // twresp include the gap + eof, max = 212(t0).
    // The best way is not to block waiting for a response,
    // Otherwise, there is a possibility of missing the card's response.
    hitag_reader_send_with_gap(HITAG_T_STOP + HITAG_T_LOW, ledcontrol);
}

void hitag_reader_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *resptime, bool ledcontrol,
                                hitag_mod_t modulation, int sof_bits) {
    bool sof_received = false; // Skip SOF bits in header
    bool is_first_edge = true;
    uint8_t lastbit = 1;
    bool skip_next_failing_edge = true;
    uint8_t error_count = 0; // Cannot exceed 255 times.
    uint8_t t_4half, t_3half, t_2half;
    size_t periods_rising_edge = 0; // for save the edge periods if is a rising edge

    // Reset values for receiving frames
    memset(rx, 0x00, sizeofrx);
    *rxlen = 0;

    // For debug, if the development has been completed,
    // please comment out the relevant definitions and calls to reduce resource usage.
    int rb_i = 0;
    uint8_t edges[160] = {0};

    // Precalculate the number of periods at different modulation speeds.
    if (modulation == AC4K || modulation == MC8K) {
        t_4half = HITAG_T_TAG_CAPTURE_FOUR_HALF / 2;
        t_3half = HITAG_T_TAG_CAPTURE_THREE_HALF / 2;
        t_2half = HITAG_T_TAG_CAPTURE_TWO_HALF / 2;
    } else {
        t_4half = HITAG_T_TAG_CAPTURE_FOUR_HALF;
        t_3half = HITAG_T_TAG_CAPTURE_THREE_HALF;
        t_2half = HITAG_T_TAG_CAPTURE_TWO_HALF;
    }

    while (BUTTON_PRESS() == false) {
        // Note: It is necessary to wait for at least N periods after the card is powered on and stabilized.
        //  Otherwise, an incorrect starting edge will be collected, resulting in a deviation in the periods calculation.
        //  So, it's best to wait for about 1000 periods. To wait for first response.
        size_t periods = lf_count_edge_periods(1000);
        if (periods == 0) {
            break;
        }

        // Capture tag frame (manchester decoding using only falling edges)
        if (periods >= HITAG_T_WAIT_RESP - (HITAG_T_EOF + HITAG_T_LOW) && is_first_edge) {
            *resptime = TIMESTAMP; // TODO DXL 待实现计算时间

            // We always receive a 'one' first, which has the falling edge after a half period |-_|
            rx[0] = 0x80;
            *rxlen = 1;

            is_first_edge = false;
            continue;
        }

        // Only use falling edge for now
        if (!lf_get_tag_modulation()) {
            periods_rising_edge = periods;
            continue;
        }

        // We have obtained an effective falling edge, now we can calculate the number of periods.
        periods += periods_rising_edge;
        periods_rising_edge = 0; // reset periods of rising edge for next time detect

        if (rb_i < sizeof(edges)) {
            // For debug, save the edges for decoding manual
            edges[rb_i++] = periods;
        }

        // if we saw over 100 weird values break it probably isn't hitag...
        // Under some decoding conditions, two bits may be obtained,
        // so it is necessary to ensure that the remaining buf space can store at least two bits.
        if (error_count > 100 || (*rxlen + 2) >= sizeofrx * 8) {
            DBG Dbprintf("hitag receive overflow or error!!");
            break;
        }

        if (ledcontrol)
            LED_B_INV();

        if (modulation == AC2K || modulation == AC4K) {
            // Handle different modulation types
            // Anticollision Coding
            if (periods >= t_4half) {
                // Anticollision Coding example |--__|--__| (00)
                lastbit = 0;
                // CLEAR_BIT_MSB(rx, *rxlen);
                (*rxlen)++;
            } else if (periods >= t_3half) {
                // Anticollision Coding example |-_-_|--__| (10) or |--__|-_-_| (01)
                lastbit = !lastbit;
                if (lastbit) {
                    SET_BIT_MSB(rx, *rxlen);
                }
                (*rxlen)++;

                skip_next_failing_edge = !!lastbit;
                // Whether to skip the next falling edge depends on whether the current bit is 1 or not
            } else if (periods >= t_2half) {
                // Anticollision Coding example |-_-_| (1)
                if (skip_next_failing_edge == false) {
                    lastbit = 1;
                    SET_BIT_MSB(rx, *rxlen);
                    (*rxlen)++;
                }

                skip_next_failing_edge = !skip_next_failing_edge;
            } else {
                // Ignore weird value, is to small to mean anything
                error_count++;
            }
        } else {
            // Manchester coding (MC4K, MC8K)
            if (periods >= t_4half) {
                // Manchester coding example |-_|_-|-_| (101)

                // CLEAR_BIT_MSB(rx, *rxlen);
                (*rxlen)++;
                // The function has already been reset to 0 when entering, so there is no need to operate clear

                SET_BIT_MSB(rx, *rxlen);
                (*rxlen)++;
            } else if (periods >= t_3half) {
                // Manchester coding example |_-|...|_-|-_| (0...01)

                // CLEAR_BIT_MSB(rx, *rxlen);
                (*rxlen)++;
                // The function has already been reset to 0 when entering, so there is no need to operate clear

                // We have to skip this half period at start and add the 'one' the second time
                if (skip_next_failing_edge == false) {
                    SET_BIT_MSB(rx, *rxlen);
                    (*rxlen)++;
                }

                lastbit = !lastbit;
                skip_next_failing_edge = !skip_next_failing_edge;
            } else if (periods >= t_2half) {
                // Manchester coding example |_-|_-| (00) or |-_|-_| (11)
                // bit is same as last bit
                if (lastbit) {
                    SET_BIT_MSB(rx, *rxlen);
                }
                (*rxlen)++;
            } else {
                // Ignore weird value, is to small to mean anything
                error_count++;
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
                    DBG Dbprintf("Warning, not all bits of SOF are 1: 0x%02X", rx[0]);
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

    DBG {
        Dbprintf("RX %i:%02X.. resptime:%i, sof_bits: %d", *rxlen, rx[0], *resptime, sof_bits);
        Dbprintf("Edges count: %d, hex: ", rb_i);
        Dbhexdump(rb_i, edges, false);
    }
}

int hitag_reader_transfer(const uint8_t *tx, size_t txlen, uint8_t *rx, size_t sizeofrx, size_t *rxlen, int t_wait,
                          bool ledcontrol, hitag_mod_t modulation, uint8_t sof_bits, uint8_t send_sof) {
    uint32_t start_time = 0;

    DBG Dbprintf("tx %d bits:", txlen);
    DBG Dbhexdump((txlen + 7) / 8, tx, false);

    // Wait for HITAG_T_WAIT_SC carrier periods after the last tag bit before transmitting,
    // Since the clock counts since the last falling edge, a 'one' means that the
    // falling edge occurred halfway the period. with respect to this falling edge,
    // we need to wait (T_Wait2 + half_tag_period) when the last was a 'one'.
    // All timer values are in terms of T0 units
    lf_wait_periods(t_wait);

    // TODO DXL 待实现计算时间
    // start_time = ?

    // Transmit the reader frame
    hitag_reader_send_frame(tx, txlen, ledcontrol, send_sof);

    // tearoff
    if (g_tearoff_enabled && tearoff_hook() == PM3_ETEAROFF) {
        return PM3_ETEAROFF;
    }

    LogTraceBits(tx, txlen, start_time, TIMESTAMP, true);

    hitag_reader_receive_frame(rx, sizeofrx, rxlen, &start_time, ledcontrol, modulation, sof_bits);

    DBG Dbprintf("rx %d bits:", *rxlen);
    DBG Dbhexdump((int) (*rxlen + 7) / 8, rx, false);

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
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

    if (ledcontrol)
        LED_A_ON();

    switch (modulation) {
        case AC2K: {
            if (bit == 0) {
                // AC Coding --__
                Gpio_SSC_DOUT_High();
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {
                };

                Gpio_SSC_DOUT_Low();
                while (AT91C_BASE_TC0->TC_CV < T0 * 64) {
                };
            } else {
                // AC coding -_-_
                Gpio_SSC_DOUT_High();
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {
                };

                Gpio_SSC_DOUT_Low();
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {
                };

                Gpio_SSC_DOUT_High();
                while (AT91C_BASE_TC0->TC_CV < T0 * 48) {
                };

                Gpio_SSC_DOUT_Low();
                while (AT91C_BASE_TC0->TC_CV < T0 * 64) {
                };
            }
            break;
        }
        case AC4K: {
            if (bit == 0) {
                // AC Coding --__
                Gpio_SSC_DOUT_High();
                while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_TAG_HALF_PERIOD) {
                };

                Gpio_SSC_DOUT_Low();
                while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_TAG_FULL_PERIOD) {
                };
            } else {
                // AC coding -_-_
                Gpio_SSC_DOUT_High();
                while (AT91C_BASE_TC0->TC_CV < T0 * 8) {
                };

                Gpio_SSC_DOUT_Low();
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {
                };

                Gpio_SSC_DOUT_High();
                while (AT91C_BASE_TC0->TC_CV < T0 * 24) {
                };

                Gpio_SSC_DOUT_Low();
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {
                };
            }
            break;
        }
        case MC4K: {
            if (bit == 0) {
                // Manchester: Unloaded, then loaded |__--|
                Gpio_SSC_DOUT_Low();
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {
                };

                Gpio_SSC_DOUT_High();
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {
                };
            } else {
                // Manchester: Loaded, then unloaded |--__|
                Gpio_SSC_DOUT_High();
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {
                };

                Gpio_SSC_DOUT_Low();
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {
                };
            }
            break;
        }
        case MC8K: {
            if (bit == 0) {
                // Manchester: Unloaded, then loaded |__--|
                Gpio_SSC_DOUT_Low();
                while (AT91C_BASE_TC0->TC_CV < T0 * 8) {
                };

                Gpio_SSC_DOUT_High();
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {
                };
            } else {
                // Manchester: Loaded, then unloaded |--__|
                Gpio_SSC_DOUT_High();
                while (AT91C_BASE_TC0->TC_CV < T0 * 8) {
                };

                Gpio_SSC_DOUT_Low();
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {
                };
            }
            break;
        }
    }

    if (ledcontrol)
        LED_A_OFF();
}

void hitag_tag_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *start_time, bool ledcontrol,
                             int *overflow) {
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

            if (ledcontrol)
                LED_B_INV();

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

    if (ledcontrol)
        LED_B_OFF();

    DBG
        if (rb_i) {
            Dbprintf("RX %i bits.. start_time:%i edges:", *rxlen, *start_time);
            Dbhexdump(rb_i, edges, false);
        }
}

void hitag_tag_send_frame(const uint8_t *frame, size_t frame_len, int sof_bits, hitag_mod_t modulation,
                          bool ledcontrol) {
    // The beginning of the frame is hidden in some high level; pause until our bits will have an effect
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    Gpio_SSC_DOUT_High();

    switch (modulation) {
        case AC4K:
        case MC8K: {
            while (AT91C_BASE_TC0->TC_CV < T0 * 40) {
            }; // FADV
            break;
        }
        case AC2K:
        case MC4K: {
            while (AT91C_BASE_TC0->TC_CV < T0 * 20) {
            }; // STD + ADV
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
