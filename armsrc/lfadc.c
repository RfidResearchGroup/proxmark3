//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LF ADC read/write implementation
//-----------------------------------------------------------------------------

#include "lfadc.h"
#include "lfsampling.h"
#include "fpgaloader.h"
#include "ticks.h"

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
#define T0 3

//////////////////////////////////////////////////////////////////////////////
// Global variables
//////////////////////////////////////////////////////////////////////////////

bool rising_edge = false;
bool logging = true;
bool reader_mode = false;

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
uint8_t previous_adc_val = 0;

size_t lf_count_edge_periods_ex(size_t max, bool wait, bool detect_gap) {
    size_t periods = 0;
    volatile uint8_t adc_val;
    //uint8_t avg_peak = 140, avg_through = 96;
    uint8_t avg_peak = 130, avg_through = 106;

    while (!BUTTON_PRESS()) {
        // Watchdog hit
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            adc_val = AT91C_BASE_SSC->SSC_RHR;
            periods++;

            if (logging) logSample(adc_val, 1, 8, 0, 0);

            // Only test field changes if state of adc values matter
            if (!wait) {
                // Test if we are locating a field modulation (100% ASK = complete field drop)
                if (detect_gap) {
                    // Only return when the field completely dissapeared
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
            if (periods == max) return 0;
        }
    }
    if (logging) logSample(255, 1, 8, 0, 0);
    return 0;
}

size_t lf_count_edge_periods(size_t max) {
    return lf_count_edge_periods_ex(max, false, false);
}

size_t lf_detect_gap(size_t max) {
    return lf_count_edge_periods_ex(max, false, true);
}

void lf_reset_counter() {
    // TODO: find out the correct reset settings for tag and reader mode
    if (reader_mode) {
        // Reset values for reader mode
        rising_edge = false;
        previous_adc_val = 0xFF;
    } else {
        // Reset values for tag/transponder mode
        rising_edge = false;
        previous_adc_val = 0xFF;
    }
}

bool lf_get_tag_modulation() {
    return (rising_edge == false);
}

void lf_wait_periods(size_t periods) {
    lf_count_edge_periods_ex(periods, true, false);
}

void lf_init(bool reader) {
    reader_mode = reader;

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
    if (reader) {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
    } else {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC);
    }

    // Connect the A/D to the peak-detected low-frequency path.
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Now set up the SSC to get the ADC samples that are now streaming at us.
    FpgaSetupSsc();

    // When in reader mode, give the field a bit of time to settle.
    if (reader) SpinDelay(50);

    // Steal this pin from the SSP (SPI communication channel with fpga) and use it to control the modulation
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    LOW(GPIO_SSC_DOUT);

    // Enable peripheral Clock for TIMER_CLOCK0
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC0);
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV4_CLOCK;

    // Enable peripheral Clock for TIMER_CLOCK0
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC1);
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_TIMER_DIV4_CLOCK;

    // Clear all leds
    LEDsoff();

    // Reset and enable timers
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // Prepare data trace
    if (logging) initSamplingBuffer();

}

void lf_finalize() {
    // Disable timers
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // return stolen pin to SSP
    AT91C_BASE_PIOA->PIO_PDR = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_ASR = GPIO_SSC_DIN | GPIO_SSC_DOUT;

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    LEDsoff();
}

size_t lf_detect_field_drop(size_t max) {
    size_t periods = 0;
    volatile uint8_t adc_val;

    // usb check?
    while (!BUTTON_PRESS()) {
        // Watchdog hit
        WDT_HIT();

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            periods++;
            adc_val = AT91C_BASE_SSC->SSC_RHR;

            if (logging) logSample(adc_val, 1, 8, 0, 0);

            if (adc_val == 0) {
                rising_edge = false;
                return periods;
            }

            if (periods == max) return 0;
        }
    }
    return 0;
}

inline void lf_modulation(bool modulation) {
    if (modulation) {
        HIGH(GPIO_SSC_DOUT);
    } else {
        LOW(GPIO_SSC_DOUT);
    }
}

inline void lf_manchester_send_bit(uint8_t bit) {
    lf_modulation(bit != 0);
    lf_wait_periods(16);
    lf_modulation(bit == 0);
    lf_wait_periods(16);
}

bool lf_manchester_send_bytes(const uint8_t *frame, size_t frame_len) {

    LED_B_ON();

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        lf_manchester_send_bit((frame[i / 8] >> (7 - (i % 8))) & 1);
    }

    LED_B_OFF();
    return true;
}
