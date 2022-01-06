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
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
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

bool g_logging = true;

//////////////////////////////////////////////////////////////////////////////
// Global variables
//////////////////////////////////////////////////////////////////////////////

static bool rising_edge = false;
static bool reader_mode = false;

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
static uint8_t previous_adc_val = 0; //0xFF;
static uint8_t adc_avg = 0;

uint8_t get_adc_avg(void) {
    return adc_avg;
}
void lf_sample_mean(void) {
    uint8_t periods = 0;
    uint32_t adc_sum = 0;
    while (periods < 32) {
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            adc_sum += AT91C_BASE_SSC->SSC_RHR;
            periods++;
        }
    }
    // division by 32
    adc_avg = adc_sum >> 5;
    previous_adc_val = adc_avg;

    if (g_dbglevel >= DBG_EXTENDED)
        Dbprintf("LF ADC average %u", adc_avg);
}

static size_t lf_count_edge_periods_ex(size_t max, bool wait, bool detect_gap) {

#define LIMIT_DEV  20

    // timeout limit to 100 000 w/o
    uint32_t timeout = 100000;
    size_t periods = 0;
    uint8_t avg_peak = adc_avg + LIMIT_DEV;
    uint8_t avg_through = adc_avg - LIMIT_DEV;

    while (BUTTON_PRESS() == false) {
        WDT_HIT();

        timeout--;
        if (timeout == 0) {
            return 0;
        }

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = 0x00;
            continue;
        }

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {

            periods++;

            // reset timeout
            timeout = 100000;

            volatile uint8_t adc_val = AT91C_BASE_SSC->SSC_RHR;

            if (g_logging) logSampleSimple(adc_val);

            // Only test field changes if state of adc values matter
            if (wait == false) {
                // Test if we are locating a field modulation (100% ASK = complete field drop)
                if (detect_gap) {
                    // Only return when the field completely disappeared
                    if (adc_val == 0) {
                        return periods;
                    }

                } else {
                    // Trigger on a modulation swap by observing an edge change
                    if (rising_edge) {

                        if ((previous_adc_val > avg_peak) && (adc_val <= previous_adc_val)) {
                            rising_edge = false;
                            return periods;
                        }

                    } else {

                        if ((previous_adc_val < avg_through) && (adc_val >= previous_adc_val)) {
                            rising_edge = true;
                            return periods;
                        }

                    }
                }
            }

            previous_adc_val = adc_val;

            if (periods >= max) {
                return 0;
            }
        }
    }

    if (g_logging) logSampleSimple(0xFF);
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
//    if (reader_mode) {
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
    //       wait  detect gap
    lf_count_edge_periods_ex(periods, true, false);
}

void lf_init(bool reader, bool simulate, bool ledcontrol) {

    StopTicks();

    reader_mode = reader;

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    sample_config *sc = getSamplingConfig();
    sc->decimation = 1;
    sc->averaging = 0;

    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, sc->divisor);
    if (reader) {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
    } else {
        if (simulate)
            FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC);
        else
            // Sniff
            //FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC);
            FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT  | FPGA_LF_EDGE_DETECT_TOGGLE_MODE);

    }

    // Connect the A/D to the peak-detected low-frequency path.
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Now set up the SSC to get the ADC samples that are now streaming at us.
    FpgaSetupSsc(FPGA_MAJOR_MODE_LF_READER);

    // When in reader mode, give the field a bit of time to settle.
    // 313T0 = 313 * 8us = 2504us = 2.5ms  Hitag2 tags needs to be fully powered.
//    if (reader) {
    // 10 ms
    SpinDelay(10);
//    }

    // Steal this pin from the SSP (SPI communication channel with fpga) and use it to control the modulation
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    LOW(GPIO_SSC_DOUT);

    // Enable peripheral Clock for TIMER_CLOCK 0
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC0);
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV4_CLOCK;

    // Enable peripheral Clock for TIMER_CLOCK 1
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC1);
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_TIMER_DIV4_CLOCK;

    // Clear all leds
    if (ledcontrol) LEDsoff();

    // Reset and enable timers
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // Assert a sync signal. This sets all timers to 0 on next active clock edge
    AT91C_BASE_TCB->TCB_BCR = 1;

    // Prepare data trace
    uint32_t bufsize = 10000;

    // use malloc
    if (g_logging) initSampleBufferEx(&bufsize, true);

    lf_sample_mean();
}

void lf_finalize(bool ledcontrol) {
    // Disable timers
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // return stolen pin to SSP
    AT91C_BASE_PIOA->PIO_PDR = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_ASR = GPIO_SSC_DIN | GPIO_SSC_DOUT;

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    if (ledcontrol) LEDsoff();

    StartTicks();
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

            if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
                periods++;
                volatile uint8_t adc_val = AT91C_BASE_SSC->SSC_RHR;

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

void lf_modulation(bool modulation) {
    if (modulation) {
        HIGH(GPIO_SSC_DOUT);
    } else {
        LOW(GPIO_SSC_DOUT);
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

    if (ledcontrol) LED_B_ON();

    lf_manchester_send_bit(1);
    lf_manchester_send_bit(1);
    lf_manchester_send_bit(1);
    lf_manchester_send_bit(1);
    lf_manchester_send_bit(1);

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        lf_manchester_send_bit((frame[i / 8] >> (7 - (i % 8))) & 1);
    }

    if (ledcontrol) LED_B_OFF();
    return true;
}
