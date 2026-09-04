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
// LF ADC read/write implementation
//-----------------------------------------------------------------------------

#include "lfadc.h"
#include "lfsampling.h"
#include "fpga_loader.h"
#include "ticks_apis.h"
#include "fpga_apis.h"
#include "dbprint.h"
#include "commonutil.h"   // ARRAYLEN
#include "appmain.h"

// Sam7s has several timers, we will use the source TIMER_CLOCK1 (aka AT91C_TC_CLKS_TIMER_DIV1_CLOCK)
// TIMER_CLOCK1 = MCK/2, MCK is running at 48 MHz, Timer is running at 48/2 = 24 MHz
// Carrier periods (T0) have duration of 8 microseconds (us), which is 1/125000 per second
// T0 = TIMER_CLOCK1 / 125000 = 192
//#define T0 192

// Sam7s has three counters, we will use the first TIMER_COUNTER_0 (aka TC0)
// using TIMER_CLOCK3 (aka AT91C_TC_CLKS_TIMER_DIV3_CLOCK)
// as a counting signal. TIMER_CLOCK3 = MCK/32, MCK is running at 48 MHz, so the timer is running at 48/32 = 1500 kHz
// Carrier period (T0) have duration of 8 microseconds (us), which is 1/125000 per second (125 kHz frequency)
// T0 = timer/carrier = 1500kHz/125kHz = 1500000/125000 = 6
//#define HITAG_T0 3

//////////////////////////////////////////////////////////////////////////////
// Exported global variables
//////////////////////////////////////////////////////////////////////////////

bool g_logging = false; // TODO DXL 在某些情况下，读不到卡的时候，此处可能会造成内存溢出，需要解决

//////////////////////////////////////////////////////////////////////////////
// Global variables
//////////////////////////////////////////////////////////////////////////////

static bool rising_edge = false;
static lf_adc_init_mode_t g_init_mode = LF_ADC_READER;
static lf_adc_edge_mode_t g_edge_mode = LF_ADC_WAV_REVERSED;

//////////////////////////////////////////////////////////////////////////////
// Auxiliary functions
//////////////////////////////////////////////////////////////////////////////

bool lf_test_periods(size_t expected, size_t count) {
    // Compute 10% deviation (integer operation, so rounded down)
    size_t diviation = expected / 10;
    return ((count > (expected - diviation)) && (count < (expected + diviation)));
}

//////////////////////////////////////////////////////////////////////////////
// Low frequency (LF) adc passthrough functionality
//////////////////////////////////////////////////////////////////////////////
static uint8_t previous_adc_val = 0; // 0xFF;
static uint8_t adc_avg = 0;
// The same average, kept as the raw sum of 32 samples (i.e. avg scaled by 32).
// adc_avg alone is truncated to whole ADC counts, so a threshold built from it
// cannot be placed finer than one count - which is why LIMIT_DEV could not be
// lowered without the edge detector chattering on quantisation noise.
static uint32_t adc_avg_q5 = 0;

#define LIMIT_DEV_Q5_REPORT  (20 * 32)
static uint8_t adc_max;
static uint8_t adc_min;

uint8_t lf_get_adc_avg(void) {
    return adc_avg;
}

void lf_sample_mean(void) {
    uint8_t periods = 0;
    uint32_t adc_sum = 0;
    adc_max = 0;
    adc_min = 255;
    while (periods < 32) {
        if (FPGA_SSC_RX_Ready()) {
            const uint8_t adc_val = FPGA_SSC_RX_Value();
            if (adc_val < adc_min) adc_min = adc_val;
            if (adc_val > adc_max) adc_max = adc_val;
            adc_sum += adc_val;
            periods++;
        }
    }
    adc_avg_q5 = adc_sum;   // avg * 32, no rounding thrown away
    adc_avg = adc_sum >> 5; // division by 32
    previous_adc_val = adc_avg;
    DBG Dbprintf("LF ADC average %u, max %u, min %u, diff %u  (threshold is +/-%u counts)",
             adc_avg, adc_max, adc_min, adc_max - adc_min, (unsigned)(LIMIT_DEV_Q5_REPORT / 32));
}

static size_t lf_count_edge_periods_ex(size_t max, bool wait, bool detect_gap) {
// Deviation from the mean that counts as an edge, in 1/32 ADC counts, so the
// threshold is no longer stuck on whole ADC counts the way adc_avg + LIMIT_DEV
// was.  20 counts is the long standing value and is kept here (20 * 32).
//
// Measured, in case it is tempting to lower it: a Proxmark simulating a Hitag 2
// tag modulates only about 2 counts deep, where a genuine fob clears 20 at the
// same position.  Dropping to 6 gained nothing, and 2 only made the detector
// trigger on noise and decode UID FFFFFFFF.  The simulator's dip is the problem,
// not this threshold.
// Measured: lowering this from 20 to 10, to let a simulating Proxmark answer
// shallower and so recover faster, stops the reader reading anything at all -
// 0 of 3 UID reads at every modulation duty.  The existing note below already
// said 6 gained nothing and 2 triggered on noise; 10 is past the edge too.
#define LIMIT_DEV_Q5  (20 * 32)

    // timeout limit to 100 000 w/o
    uint32_t timeout = 100000;
    size_t periods = 0;
    uint32_t avg_peak_q5 = adc_avg_q5 + LIMIT_DEV_Q5;
    uint32_t avg_through_q5 = (adc_avg_q5 > LIMIT_DEV_Q5) ? (adc_avg_q5 - LIMIT_DEV_Q5) : 0;

    while (BUTTON_PRESS() == false) {
        WDT_HIT();

        timeout--;
        if (timeout == 0) {
            DBG Dbprintf("Error, timeout for wait adc value rx");
            return 0;
        }

        if (FPGA_SSC_TX_Ready()) {
            FPGA_SSC_TX_Value(0x00);
            continue;
        }

        if (FPGA_SSC_RX_Ready() == false) {
            continue;
        }

        periods++; // T0 increment, 1(TO) = 8us, same with 125khz clock.
        timeout = 100000; // reset timeout
        volatile uint8_t adc_val = FPGA_SSC_RX_Value(); // Get current adc value.


        if (g_logging) {
            logSampleSimple(adc_val);
        }

        // Only test field changes if state of adc values matter
        if (wait == false) {
            // Test if we are locating a field modulation (100% ASK = complete field drop)
            if (detect_gap) {
                // Only return when the field completely disappeared
                if (adc_val == 0) {
                    return periods;
                }
            } else {
                if (g_edge_mode == LF_ADC_WAV_REVERSED) {
                    if (rising_edge) {
                        if ((((uint32_t)previous_adc_val << 5) > avg_peak_q5) && (adc_val <= previous_adc_val)) {
                            rising_edge = false;
                            return periods;
                        }
                    } else {
                        if ((((uint32_t)previous_adc_val << 5) < avg_through_q5) && (adc_val >= previous_adc_val)) {
                            rising_edge = true;
                            return periods;
                        }
                    }
                } else if (g_edge_mode == LF_ADC_NOT_REVERSED) {
                    if (rising_edge) {
                        if ((((uint32_t)adc_val << 5) <= adc_avg_q5) && (((uint32_t)adc_val << 5) <= avg_through_q5)) {
                            rising_edge = false;
                            return periods;
                        }
                    } else {
                        if (((uint32_t)adc_val << 5) >= avg_peak_q5) {
                            rising_edge = true;
                            return periods;
                        }
                    }
                }
            }
        }

        previous_adc_val = adc_val;

        if (periods >= max) {
            return 0;
        }
    }

    if (g_logging) {
        logSampleSimple(0xFF);
    }

    return 0;
}

size_t lf_count_edge_periods(size_t max) {
    return lf_count_edge_periods_ex(max, false, false);
}

size_t lf_detect_gap(size_t max) {
    return lf_count_edge_periods_ex(max, false, true);
}

void lf_reset_counter(void) {
    // TODO: find out the correct reset settings for tag and reader mode
    //    if (g_init_mode == LF_ADC_READER) {
    // Reset values for reader mode
    rising_edge = false;
    previous_adc_val = 0xFF;

    //    } else {
    // Reset values for tag/transponder mode
    //        rising_edge = false;
    //        previous_adc_val = 0xFF;
    //    }
}

bool lf_get_tag_modulation(void) {
    return (rising_edge == false);
}

bool lf_get_reader_modulation(void) {
    return rising_edge;
}

void lf_wait_periods(size_t periods) {
    // wait for detect gap
    lf_count_edge_periods_ex(periods, true, false);
}

void lf_init(lf_adc_init_mode_t init_mode, lf_adc_edge_mode_t edge_mode, bool ledcontrol) {
    g_init_mode = init_mode;
    g_edge_mode = edge_mode;

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    sample_config *sc = getSamplingConfig();
    sc->decimation = 1;
    sc->averaging = 0;

    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, sc->divisor);

    // Different fpga config for different mode.
    switch (g_init_mode) {
        case LF_ADC_READER:
            FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
            break;
        case LF_ADC_TAG_SIM:
            FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC);
            break;
        case LF_ADC_SNIFF:
            FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC);
            // FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT  | FPGA_LF_EDGE_DETECT_TOGGLE_MODE);
            break;
    }

    // Connect the A/D to the peak-detected low-frequency path.
    SetAdcMuxFor(ADC_MUXSEL_LOPKD);

    // Now set up the SSC to get the ADC samples that are now streaming at us.
    FpgaSetupSsc(FPGA_MAJOR_MODE_LF_READER);

    // When in reader mode, give the field a bit of time to settle.
    // Optimal timing window for LF ADC measurements to be performed:
    // minimum: 313T0 = 313 * 8us = 2504us = 2.50ms - Hitag2 tag internal powerup time
    //          280T0 = 280 * 8us = 2240us = 2.24ms - HitagS minimum time before the first command (powerup time)
    // maximum: 545T0 = 545 * 8us = 4360us = 4.36ms - Hitag2 command waiting time before it starts transmitting in public mode (if configured so)
    //          565T0 = 565 * 8us = 4520us = 4.52ms - HitagS waiting time before entering TTF mode (if configured so)
    // Thus (2.50 ms + 4.36 ms) / 2 ~= 3 ms (rounded down to integer), should be a good timing for both tag models
    SpinDelay(3);

    // Steal this pin from the SSP (SPI communication channel with fpga) and use it to control the modulation
    gpio_fpga_mod_only_setup();
    Gpio_SSC_DOUT_Low();

    // Clear all leds
    if (ledcontrol) LEDsoff();

    // Prepare data trace
    uint32_t bufsize = 10000;

    // use malloc
    if (g_logging) {
        initSampleBufferEx(&bufsize, true);
    }

    lf_sample_mean();
}

void lf_finalize(bool ledcontrol) {

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    if (ledcontrol) LEDsoff();
}

size_t lf_detect_field_drop(size_t max) {
    /*
        size_t periods = 0;
    //    int16_t checked = 0;

        while (BUTTON_PRESS() == false) {

                    // // only every 1000th times, in order to save time when collecting samples.
                    // if (checked == 4000) {
                        // if (data_available()) {
                            // checked = -1;
                            // break;
                        // } else {
                            // checked = 0;
                        // }
                    // }
                    // ++checked;

            WDT_HIT();

            if (FPGA_SSC_RX_Ready()) {
                periods++;
                volatile uint8_t adc_val = FPGA_SSC_RX_Value();

                if (g_logging) logSampleSimple(adc_val);

                if (adc_val == 0) {
                    rising_edge = false;
                    return periods;
                }

                if (periods == max) return 0;
            }
        }
    */
    return 0;
}

void lf_reset_field(size_t periods) {
    // FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    Gpio_SSC_DOUT_High();
    lf_wait_periods(periods);
    Gpio_SSC_DOUT_Low();
    // FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
}

void lf_modulation(bool modulation) {
    if (modulation) {
        Gpio_SSC_DOUT_High();
    } else {
        Gpio_SSC_DOUT_Low();
    }
}

// simulation
static void lf_manchester_send_bit(uint8_t bit) {
    lf_modulation(bit != 0);
    lf_wait_periods(16);
    lf_modulation(bit == 0);
    lf_wait_periods(32);
}

// simulation
bool lf_manchester_send_bytes(const uint8_t *frame, size_t frame_len, bool ledcontrol) {
    if (ledcontrol)
        LED_B_ON();

    lf_manchester_send_bit(1);
    lf_manchester_send_bit(1);
    lf_manchester_send_bit(1);
    lf_manchester_send_bit(1);
    lf_manchester_send_bit(1);

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        lf_manchester_send_bit((frame[i / 8] >> (7 - (i % 8))) & 1);
    }

    if (ledcontrol)
        LED_B_OFF();
    return true;
}
