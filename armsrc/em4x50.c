//-----------------------------------------------------------------------------
// Copyright (C) 2020 tharexde
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x50 commands
//-----------------------------------------------------------------------------

#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "lfadc.h"
#include "lfdemod.h"
#include "commonutil.h"
#include "em4x50.h"
#include "flashmem.h"
#include "BigBuf.h"
#include "appmain.h" // tear

// Sam7s has several timers, we will use the source TIMER_CLOCK1 (aka AT91C_TC_CLKS_TIMER_DIV1_CLOCK)
// TIMER_CLOCK1 = MCK/2, MCK is running at 48 MHz, Timer is running at 48/2 = 24 MHz
// EM4x50 units (T0) have duration of 8 microseconds (us), which is 1/125000 per second (carrier)
// T0 = TIMER_CLOCK1 / 125000 = 192

#ifndef T0
#define T0                                  192
#endif

#define EM4X50_T_TAG_QUARTER_PERIOD         16
#define EM4X50_T_TAG_HALF_PERIOD            32
#define EM4X50_T_TAG_THREE_QUARTER_PERIOD   48
#define EM4X50_T_TAG_FULL_PERIOD            64
#define EM4X50_T_TAG_TPP                    64
#define EM4X50_T_TAG_TWA                    64
#define EM4X50_T_TAG_WAITING_FOR_SIGNAL     75
#define EM4X50_T_WAITING_FOR_DBLLIW         1550
#define EM4X50_T_WAITING_FOR_SNGLLIW        140     // this value seems to be
                                                    // critical;
                                                    // if it's too low
                                                    // (e.g. < 120) some cards
                                                    // are no longer readable
                                                    // although they're ok

#define EM4X50_TAG_TOLERANCE                8
#define EM4X50_TAG_WORD                     45

#define EM4X50_COMMAND_LOGIN                0x01
#define EM4X50_COMMAND_RESET                0x80
#define EM4X50_COMMAND_WRITE                0x12
#define EM4X50_COMMAND_WRITE_PASSWORD       0x11
#define EM4X50_COMMAND_SELECTIVE_READ       0x0A

int gHigh = 190;
int gLow = 60;

//==============================================================================
// auxiliary functions
//==============================================================================

static void wait_timer(uint32_t period) {

    // do nothing for <period> using timer0

    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    while (AT91C_BASE_TC0->TC_CV < period);
}

static bool extract_parities(uint64_t word, uint32_t *data) {
    
    // extract and check parities
    // return result of parity check and extracted plain data
    
    uint8_t row_parities = 0x0, col_parities = 0x0;
    uint8_t row_parities_calculated = 0x0, col_parities_calculated = 0x0;
    
    *data = 0x0;
    
    // extract plain data (32 bits) from raw word (45 bits)
    for (int i = 0; i < 4; i++) {
        *data <<= 8;
        *data |= (word >> ((4 - i) * 9 + 1)) & 0xFF;
    }
    
    // extract row parities (4 bits + stop bit) from raw word (45 bits)
    for (int i = 0; i < 5; i++) {
        row_parities <<= 1;
        row_parities |= (word >> ((4 - i) * 9)) & 0x1;
    }

    // extract col_parities (8 bits, no stop bit) from raw word (45 bits)
    col_parities = (word >> 1) & 0xFF;

    // check extracted parities against extracted data

    // calculate row parities from data
    for (int i = 0; i < 4; i++) {
        row_parities_calculated <<= 1;
        for (int j = 0; j < 8; j++) {
            row_parities_calculated ^= (*data >> ((3 - i) * 8 + (7 - j))) & 0x1;
        }
    }

    // add stop bit (always zero)
    row_parities_calculated <<= 1;

    // calculate column parities from data
    for (int i = 0; i < 8; i++) {
        col_parities_calculated <<= 1;
        for (int j = 0; j < 4; j++) {
            col_parities_calculated ^= (*data >> ((3 - j) * 8 + (7 - i))) & 0x1;
        }
    }
    
    if ((row_parities == row_parities_calculated) && (col_parities == col_parities_calculated))
        return true;

    return false;
}

static void em4x50_setup_read(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);

    // 50ms for the resonant antenna to settle.
    SpinDelay(50);

    // Now set up the SSC to get the ADC samples that are now streaming at us.
    FpgaSetupSsc(FPGA_MAJOR_MODE_LF_READER);

    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125);

    // Connect the A/D to the peak-detected low-frequency path.
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Steal this pin from the SSP (SPI communication channel with fpga) and
    // use it to control the modulation
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;

    // Disable modulation at default, which means enable the field
    LOW(GPIO_SSC_DOUT);

    // Enable Peripheral Clock for
    //   TIMER_CLOCK0, used to measure exact timing before answering
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0);// | (1 << AT91C_ID_TC1);
    AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;

    // Disable timer during configuration
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;

    // TC0: Capture mode, default timer source = MCK/2 (TIMER_CLOCK1), no triggers
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV1_CLOCK;

    // TC1: Capture mode, default timer source = MCK/2 (TIMER_CLOCK1), no triggers

    // Enable and reset counters
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // synchronized startup procedure
    while (AT91C_BASE_TC0->TC_CV > 0) {}; // wait until TC1 returned to zero

    // Watchdog hit
    WDT_HIT();
}

static void em4x50_setup_sim(void) {
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125);

    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT | GPIO_SSC_CLK;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_CLK;
}

//==============================================================================
// functions for "reader" use case
//==============================================================================

static bool get_signalproperties(void) {

    // calculate signal properties (mean amplitudes) from measured data:
    // 32 amplitudes (maximum values) -> mean amplitude value -> gHigh -> gLow

    bool signal_found = false;
    int no_periods = 32, pct = 75, noise = 140;
    uint8_t sample_ref = 127;
    uint8_t sample_max_mean = 0;
    uint8_t sample_max[no_periods];
    uint32_t sample_max_sum = 0;
    memcpy(sample_max, 0x00, sizeof(sample_max));

    LED_A_ON();

    // wait until signal/noise > 1 (max. 32 periods)
    for (int i = 0; i < EM4X50_T_TAG_WAITING_FOR_SIGNAL; i++) {

        if (BUTTON_PRESS()) return false;

        // about 2 samples per bit period
        wait_timer(T0 * EM4X50_T_TAG_HALF_PERIOD);
      
        // ignore first samples
        if ((i > SIGNAL_IGNORE_FIRST_SAMPLES) && (AT91C_BASE_SSC->SSC_RHR > noise)) {
            signal_found = true;
            break;
        }
    }

    if (signal_found == false) {
        LED_A_OFF();
        return false;
    }

    // calculate mean maximum value of 32 periods, each period has a length of
    // 3 single "full periods" to eliminate the influence of a listen window
    for (int i = 0; i < no_periods; i++) {

        AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
        while (AT91C_BASE_TC0->TC_CV < T0 * 3 * EM4X50_T_TAG_FULL_PERIOD) {

            if (BUTTON_PRESS()) return false;

            volatile uint8_t sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
            if (sample > sample_max[i])
                sample_max[i] = sample;

        }

        sample_max_sum += sample_max[i];
    }

    sample_max_mean = sample_max_sum / no_periods;

    // set global envelope variables
    gHigh = sample_ref + pct * (sample_max_mean - sample_ref) / 100;
    gLow = sample_ref - pct * (sample_max_mean - sample_ref) / 100;

    LED_A_OFF();
    
    return true;
}

static bool invalid_bit(void) {

    // returns true if bit is undefined by evaluating a single sample within
    // a bit period (given there is no LIW, ACK or NAK)
    // This function is used for identifying a listen window in functions
    // "find_double_listen_window" and "check_ack"

    // get sample at 3/4 of bit period
    wait_timer(T0 * EM4X50_T_TAG_THREE_QUARTER_PERIOD);

    uint8_t sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    // wait until end of bit period
    wait_timer(T0 * EM4X50_T_TAG_QUARTER_PERIOD);

    // bit in "undefined" state?
    if (sample <= gHigh && sample >= gLow)
        return true;

    return false;
}

static uint32_t get_pulse_length(void) {

    int32_t timeout = (T0 * 3 * EM4X50_T_TAG_FULL_PERIOD);

    // iterates pulse length (low -> high -> low)

    volatile uint8_t sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    while (sample > gLow && (timeout--))
        sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    if (timeout == 0)
        return 0;

    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    timeout = (T0 * 3 * EM4X50_T_TAG_FULL_PERIOD);

    while (sample < gHigh && (timeout--))
        sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    if (timeout == 0)
        return 0;

    timeout = (T0 * 3 * EM4X50_T_TAG_FULL_PERIOD);
    while (sample > gLow && (timeout--))
        sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    if (timeout == 0)
        return 0;

    return (uint32_t)AT91C_BASE_TC0->TC_CV;

}

static bool check_pulse_length(uint32_t pl, int length) {
    
    // check if pulse length <pl> corresponds to given length <length>
    return ((pl >= T0 * (length - EM4X50_TAG_TOLERANCE)) && (pl <= T0 * (length + EM4X50_TAG_TOLERANCE)));
    
}

static void em4x50_reader_send_bit(int bit) {

    // send single bit according to EM4x50 application note and datasheet

    // reset clock for the next bit
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

    if (bit == 0) {

        // disable modulation (drops the field) for 7 cycles of carrier
        // period (Opt64)
        LOW(GPIO_SSC_DOUT);
        while (AT91C_BASE_TC0->TC_CV < T0 * 7);

        // enable modulation (activates the field) for remaining first
        // half of bit period
        HIGH(GPIO_SSC_DOUT);
        while (AT91C_BASE_TC0->TC_CV < T0 * EM4X50_T_TAG_HALF_PERIOD);

        // disable modulation for second half of bit period
        LOW(GPIO_SSC_DOUT);
        while (AT91C_BASE_TC0->TC_CV < T0 * EM4X50_T_TAG_FULL_PERIOD);

    } else {

        // bit = "1" means disable modulation for full bit period
        LOW(GPIO_SSC_DOUT);
        while (AT91C_BASE_TC0->TC_CV < T0 * EM4X50_T_TAG_FULL_PERIOD);
    }
}

static void em4x50_reader_send_byte(uint8_t byte) {

    // send byte (without parity)

    for (int i = 0; i < 8; i++)
        em4x50_reader_send_bit((byte >> (7 - i)) & 1);

}

static void em4x50_reader_send_byte_with_parity(uint8_t byte) {

    // send byte followed by its (equal) parity bit

    int parity = 0, bit = 0;

    for (int i = 0; i < 8; i++) {
        bit = (byte >> (7 - i)) & 1;
        em4x50_reader_send_bit(bit);
        parity ^= bit;
    }

    em4x50_reader_send_bit(parity);
}

static void em4x50_reader_send_word(const uint32_t word) {

    // send 32 bit word with parity bits according to EM4x50 datasheet
    // word hast be sent in msb notation

    uint8_t bytes[4] = {0x0, 0x0, 0x0, 0x0};
    
    for (int i = 0; i < 4; i++) {
        bytes[i] = (word >> (24 - (8 * i))) & 0xFF;
        em4x50_reader_send_byte_with_parity(bytes[i]);
    }
    
    // send column parities
    em4x50_reader_send_byte(bytes[0] ^ bytes[1] ^ bytes[2] ^ bytes[3]);

    // send final stop bit (always "0")
    em4x50_reader_send_bit(0);
}

static bool find_single_listen_window(void) {

    // find single listen window

    int cnt_pulses = 0;
    
    LED_B_ON();

    while (cnt_pulses < EM4X50_T_WAITING_FOR_SNGLLIW) {

        // identification of listen window is done via evaluation of
        // pulse lengths
        if (check_pulse_length(get_pulse_length(), 3 * EM4X50_T_TAG_FULL_PERIOD)) {

            if (check_pulse_length(get_pulse_length(), 2 * EM4X50_T_TAG_FULL_PERIOD)) {

                // found listen window
                LED_B_OFF();
                return true;
            }
        }
        cnt_pulses++;
    }

    LED_B_OFF();
    
    return false;
}

static int find_double_listen_window(bool bcommand) {

    // find two successive listen windows that indicate the beginning of
    // data transmission
    // double listen window to be detected within 1600 pulses -> worst case
    // reason: first detectable double listen window after 34 words
    // -> 34 words + 34 single listen windows -> about 1600 pulses

    int cnt_pulses = 0;
    
    LED_B_ON();

    while (cnt_pulses < EM4X50_T_WAITING_FOR_DBLLIW) {

        if (BUTTON_PRESS())
            return BUTTON_SINGLE_CLICK;

        // identification of listen window is done via evaluation of
        // pulse lengths
        if (check_pulse_length(get_pulse_length(), 3 * EM4X50_T_TAG_FULL_PERIOD)) {

            //if (BUTTON_PRESS())
            //    return BUTTON_SINGLE_CLICK;
            
            if (check_pulse_length(get_pulse_length(), 2 * EM4X50_T_TAG_FULL_PERIOD)) {

                // first listen window found

                if (bcommand) {

//                    SpinDelay(10);

                    // data transmission from card has to be stopped, because
                    // a commamd shall be issued

                    // unfortunately the position in listen window (where
                    // command request has to be sent) has gone, so if a
                    // second window follows - sync on this to issue a command

                    // skip the next bit...
                    wait_timer(T0 * EM4X50_T_TAG_FULL_PERIOD);

                    // ...and check if the following bit does make sense
                    // (if not it is the correct position within the second
                    // listen window)
                    if (invalid_bit()) {

                        // send RM for request mode
                        em4x50_reader_send_bit(0);
                        em4x50_reader_send_bit(0);

                        LED_B_OFF();

                        return PM3_SUCCESS;
                    }

                }

                if (check_pulse_length(get_pulse_length(), 3 * EM4X50_T_TAG_FULL_PERIOD)) {

                    LED_B_OFF();

                    // return although second listen window consists of one
                    // more bit period but this period is necessary for
                    // evaluating further pulse lengths
                    return PM3_SUCCESS;
                }
            }
        }
        cnt_pulses++;
    }

    LED_B_OFF();
    
    return PM3_EFAILED;
}

static bool find_em4x50_tag(void) {

    // function is used to check wether a tag on the proxmark is an
    // EM4x50 tag or not -> speed up "lf search" process
    return find_single_listen_window();
}

static int request_receive_mode(void) {

    // To issue a command we have to find a listen window first.
    // Because identification and synchronization at the same time is not
    // possible when using pulse lengths a double listen window is used.
    return find_double_listen_window(true);
}

static bool check_ack(bool bliw) {

    // returns true if signal structue corresponds to ACK, anything else is
    // counted as NAK (-> false)
    // Only relevant for pasword writing function:
    // If <bliw> is true then within the single listen window right after the
    // ack signal a RM request has to be sent.

    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    while (AT91C_BASE_TC0->TC_CV < T0 * 4 * EM4X50_T_TAG_FULL_PERIOD) {

        if (BUTTON_PRESS())
            return false;
        
        if (check_pulse_length(get_pulse_length(), 2 * EM4X50_T_TAG_FULL_PERIOD)) {

            // The received signal is either ACK or NAK.

            if (check_pulse_length(get_pulse_length(), 2 * EM4X50_T_TAG_FULL_PERIOD)) {

                // Now the signal must be ACK.

                if (!bliw) {

                    return true;

                } else {

                    // send RM request after ack signal

                    // wait for 2 bits (remaining "bit" of ACK signal + first
                    // "bit" of listen window)
                    wait_timer(T0 * 2 * EM4X50_T_TAG_FULL_PERIOD);

                    // check for listen window (if first bit cannot be interpreted
                    // as a valid bit it must belong to a listen window)
                    if (invalid_bit()) {

                        // send RM for request mode
                        em4x50_reader_send_bit(0);
                        em4x50_reader_send_bit(0);

                        return true;
                    }
                }
            } else {

                // It's NAK -> stop searching
                break;
            }
        }
    }

    return false;
}

static int get_word_from_bitstream(uint32_t *data) {

    // decodes one word by evaluating pulse lengths and previous bit;
    // word must have 45 bits in total:
    // 32 data bits + 4 row parity bits + 8 column parity bits + 1 stop bit

    bool bitchange = false;
    int cnt = 0;
    uint32_t pl = 0;
    uint64_t word = 0x0;
    
    LED_C_ON();
    
    *data = 0x0;

    // initial bit value depends on last pulse length of listen window
    pl = get_pulse_length();
    if (check_pulse_length(pl, 3 * EM4X50_T_TAG_HALF_PERIOD)) {

        // pulse length = 1.5
        word = 0x1;

    } else if (check_pulse_length(pl, 2 * EM4X50_T_TAG_FULL_PERIOD)) {

        // pulse length = 2
        bitchange = true;

    } else {

        // pulse length = 2.5
        word = 0x1;
        cnt++;
    }

    // identify remaining bits based on pulse lengths
    // between two listen windows only pulse lengths of 1, 1.5 and 2 are possible
    while (BUTTON_PRESS() == false) {

        cnt++;
        word <<= 1;
        
        pl = get_pulse_length();

        if (check_pulse_length(pl, EM4X50_T_TAG_FULL_PERIOD)) {

            // pulse length = 1 -> keep former bit value
            word |= (word >> 1) & 0x1;

        } else if (check_pulse_length(pl, 3 * EM4X50_T_TAG_HALF_PERIOD)) {

            // pulse length = 1.5 -> decision on bit change

            if (bitchange) {

                // if number of pulse lengths with 1.5 periods is even -> add bit
                word |= (word >> 1) & 0x1;
                word <<= 1;

                // pulse length of 1.5 changes bit value
                word |= ((word >> 1) & 0x1) ^ 0x1;
                cnt++;

                // next time add only one bit
                bitchange = false;

            } else {

                word |= ((word >> 1) & 0x1) ^ 0x1;

                // next time two bits have to be added
                bitchange = true;
            }

        } else if (check_pulse_length(pl, 2 * EM4X50_T_TAG_FULL_PERIOD)) {

            // pulse length of 2 means: adding 2 bits "01"
            cnt++;

            word <<= 1;
            word |= 0x1;

        } else if (check_pulse_length(pl, 3 * EM4X50_T_TAG_FULL_PERIOD)) {

            LED_C_OFF();

            // pulse length of 3 indicates listen window -> clear last
            // bit (= 0) and return (without parities)
            word >>= 2;
            return (extract_parities(word, data)) ? --cnt : 0;
        }
    }
    
    LED_C_OFF();
    
    return BUTTON_SINGLE_CLICK;
}

//==============================================================================
// functions for "simulating" use case
//==============================================================================

static bool em4x50_sim_send_bit(uint8_t bit) {

    uint16_t check = 0;

    for (int t = 0; t < EM4X50_T_TAG_FULL_PERIOD; t++) {

        // wait until SSC_CLK goes HIGH
        // used as a simple detection of a reader field?
        while (!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK)) {
            WDT_HIT();
            if (check == 1000) {
                if (BUTTON_PRESS())
                    return false;
                check = 0;
            }
            ++check;
        }

        if (bit)
            OPEN_COIL();
        else
            SHORT_COIL();

        check = 0;

        //wait until SSC_CLK goes LOW
        while (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK) {
            WDT_HIT();
            if (check == 1000) {
                if (BUTTON_PRESS())
                    return false;
                check = 0;
            }
            ++check;
        }

        if (t == EM4X50_T_TAG_HALF_PERIOD)
            bit ^= 1;

    }

    return true;
}

static bool em4x50_sim_send_byte(uint8_t byte) {

    // send byte
    for (int i = 0; i < 8; i++)
        if (!em4x50_sim_send_bit((byte >> (7 - i)) & 1))
            return false;

    return true;

}

static bool em4x50_sim_send_byte_with_parity(uint8_t byte) {

    uint8_t parity = 0x0;

    // send byte with parity (even)
    for (int i = 0; i < 8; i++)
        parity ^= (byte >> i) & 1;

    if (!em4x50_sim_send_byte(byte))
        return false;;

    if (!em4x50_sim_send_bit(parity))
        return false;

    return true;
}

bool em4x50_sim_send_word(uint32_t word) {

    uint8_t cparity = 0x00;

    // word has tobe sent in msb, not lsb
    word = reflect32(word);
    
    // 4 bytes each with even row parity bit
    for (int i = 0; i < 4; i++)
        if (!em4x50_sim_send_byte_with_parity((word >> ((3 - i) * 8)) & 0xFF))
            return false;

    // column parity
    for (int i = 0; i < 8; i++) {
        cparity <<= 1;
        for (int j = 0; j < 4; j++) {
            cparity ^= (((word >> ((3 - j) * 8)) & 0xFF) >> (7 - i)) & 1;
        }
    }
    if (!em4x50_sim_send_byte(cparity))
        return false;

    // stop bit
    if (!em4x50_sim_send_bit(0))
        return false;

    return true;
}

bool em4x50_sim_send_listen_window(void) {

    uint16_t check = 0;

    for (int t = 0; t < 5 * EM4X50_T_TAG_FULL_PERIOD; t++) {

        // wait until SSC_CLK goes HIGH
        while (!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK)) {
            WDT_HIT();
            if (check == 1000) {
                if (BUTTON_PRESS())
                    return false;
                check = 0;
            }
            ++check;
        }

        if (t >= 4 * EM4X50_T_TAG_FULL_PERIOD)
            SHORT_COIL();
        else if (t >= 3 * EM4X50_T_TAG_FULL_PERIOD)
            OPEN_COIL();
        else if (t >= EM4X50_T_TAG_FULL_PERIOD)
            SHORT_COIL();
        else if (t >= EM4X50_T_TAG_HALF_PERIOD)
            OPEN_COIL();
        else
            SHORT_COIL();

        check = 0;

        // wait until SSC_CLK goes LOW
        while (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK) {
            WDT_HIT();
            if (check == 1000) {
                if (BUTTON_PRESS())
                    return false;
                check = 0;
            }
            ++check;
        }
    }

    return true;
}

//==============================================================================
// login functions
//==============================================================================

static bool login(uint32_t password) {

    // simple login to EM4x50,
    // used in operations that require authentication

    if (request_receive_mode() == PM3_SUCCESS) {

        // send login command
        em4x50_reader_send_byte_with_parity(EM4X50_COMMAND_LOGIN);

        // send password
        em4x50_reader_send_word(password);
        
        wait_timer(T0 * EM4X50_T_TAG_TPP);

        // check if ACK is returned
        if (check_ack(false))
            return PM3_SUCCESS;

    } else {
        if (DBGLEVEL >= DBG_DEBUG)
            Dbprintf("error in command request");
    }

    return PM3_EFAILED;
}

static bool brute(uint32_t start, uint32_t stop, uint32_t *pwd) {

    // searching for password in given range

    bool pwd_found = false;
    int cnt = 0;

    for (*pwd = start; *pwd <= stop; (*pwd)++) {

        if (login(*pwd) == PM3_SUCCESS) {
            
            pwd_found = true;

            // to be safe login 5 more times
            for (int i = 0; i < 5; i++) {
                if (login(*pwd) != PM3_SUCCESS) {
                    pwd_found = false;
                    break;
                }
            }
            
            if (pwd_found)
                break;
        }
        
        // print password every 500 iterations
        if ((++cnt % 500) == 0) {

            // print header
            if (cnt == 500) {
                Dbprintf("|---------+------------+------------|");
                Dbprintf("|   no.   | pwd (msb)  | pwd (lsb)  |");
                Dbprintf("|---------+------------+------------|");
            }

            // print data
            Dbprintf("|%8i | 0x%08x | 0x%08x |", cnt, reflect32(*pwd), *pwd);
        }
        
        if (BUTTON_PRESS())
            break;
 
    }

    // print footer
    if (cnt >= 500)
        Dbprintf("|---------+------------+------------|");

    return pwd_found;
}

void em4x50_login(uint32_t *password) {

    // login into EM4x50

    uint8_t status = PM3_EFAILED;

    em4x50_setup_read();

    // set gHigh and gLow
    if (get_signalproperties() && find_em4x50_tag())
        status = login(*password);

    lf_finalize();
    reply_ng(CMD_LF_EM4X50_LOGIN, status, 0, 0);
}

void em4x50_brute(em4x50_data_t *etd) {

    // envoke password search

    bool bsuccess = false;
    uint32_t pwd = 0x0;
    
    em4x50_setup_read();

    if (get_signalproperties() && find_em4x50_tag())
        bsuccess = brute(etd->password1, etd->password2, &pwd);

    lf_finalize();
    reply_ng(CMD_LF_EM4X50_BRUTE, bsuccess, (uint8_t *)(&pwd), 32);
}

void em4x50_chk(uint32_t *offset) {

    // check passwords from dictionary content in flash memory

    int status = PM3_EFAILED;
    uint8_t counter[2] = {0x00, 0x00};
    uint16_t isok = 0;
    uint16_t pwd_count = 0;
    uint16_t pwd_size_available = 0;
    uint32_t pwd = 0x0;
    uint8_t *pwds = BigBuf_get_EM_addr();

    //-----------------------------------------------------------------------------
    // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_LF) here although FPGA is not
    // involved in dealing with emulator memory. But if it is called later, it will
    // destroy the Emulator Memory.
    //-----------------------------------------------------------------------------
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    BigBuf_Clear_EM();

    // initialize passwords and get number of passwords
    if (Flash_ReadData(*offset, counter, sizeof(counter)) != sizeof(counter))
        goto OUT;

    pwd_count = (uint16_t)(counter[1] << 8 | counter[0]);
    if (pwd_count == 0)
        goto OUT;

    pwd_size_available = 4 * pwd_count;
    
    isok = Flash_ReadData(*offset + 2, pwds, pwd_size_available);
    if (isok != pwd_size_available)
        goto OUT;
    
    em4x50_setup_read();

    // set gHigh and gLow
    if (get_signalproperties() && find_em4x50_tag()) {

        // try to login with current password
        for (int i = 0; i < pwd_count; i++) {

            // manual interruption
            if (BUTTON_PRESS()) {
                status = BUTTON_SINGLE_CLICK;
                break;
            }

            // get next password
            pwd = 0x0;
            for (int j = 0; j < 4; j++)
                pwd |= (*(pwds + 4 * i + j)) << ((3 - j) * 8);
                        
            if ((status = login(pwd)) == PM3_SUCCESS)
                break;
        }
    }

OUT:
    
    lf_finalize();
    reply_ng(CMD_LF_EM4X50_CHK, status, (uint8_t *)&pwd, 32);
}

//==============================================================================
// reset functions
//==============================================================================

static int reset(void) {

    // resets EM4x50 tag (used by write function)

    if (request_receive_mode() == PM3_SUCCESS) {

        // send reset command
        em4x50_reader_send_byte_with_parity(EM4X50_COMMAND_RESET);

        if (check_ack(false))
            return PM3_SUCCESS;

    } else {
        if (DBGLEVEL >= DBG_DEBUG)
            Dbprintf("error in command request");
    }

    return PM3_EFAILED;
}

void em4x50_reset(void) {

    // reset EM4x50

    uint8_t status = PM3_EFAILED;

    em4x50_setup_read();

    // set gHigh and gLow
    if (get_signalproperties() && find_em4x50_tag())
        status = reset();

    lf_finalize();
    reply_ng(CMD_LF_EM4X50_RESET, status, 0, 0);
}

//==============================================================================
// read functions
//==============================================================================

static int standard_read(int *now, uint32_t *words) {

    // reads data that tag transmits when exposed to reader field
    // (standard read mode); number of read words is saved in <now>

    int fwr = *now, res = PM3_EFAILED;

    // start with the identification of two successive listening windows
    if ((res = find_double_listen_window(false)) == PM3_SUCCESS) {

        // read and save words until following double listen window is detected
        while ((res = get_word_from_bitstream(&words[*now])) == EM4X50_TAG_WORD)
            (*now)++;

        // number of detected words
        *now -= fwr;

    } else {
        if (DBGLEVEL >= DBG_DEBUG)
            Dbprintf("didn't find a listen window");
    }

    return res;
}

static int selective_read(uint32_t addresses, uint32_t *words) {

    // reads from "first word read" (fwr) to "last word read" (lwr)
    // result is verified by "standard read mode"

    int status = PM3_EFAILED;
    uint8_t fwr = addresses & 0xFF;         // first word read (first byte)
    uint8_t lwr = (addresses >> 8) & 0xFF;  // last word read (second byte)
    int now = fwr;                          // number of words

    if (request_receive_mode() == PM3_SUCCESS) {

        // send selective read command
        em4x50_reader_send_byte_with_parity(EM4X50_COMMAND_SELECTIVE_READ);

        // send address data
        em4x50_reader_send_word(addresses);

        // look for ACK sequence
        if (check_ack(false))

            // save and verify via standard read mode (compare number of words)
            if ((status = standard_read(&now, words)) == PM3_SUCCESS)
                if (now == (lwr - fwr + 1))
                    return status;

    } else {
        if (DBGLEVEL >= DBG_DEBUG)
            Dbprintf("error in command request");
    }

    return status;
}

void em4x50_read(em4x50_data_t *etd) {

    // reads by using "selective read mode" -> bidirectional communication

    bool blogin = true;
    int status = PM3_EFAILED;
    uint32_t words[EM4X50_NO_WORDS] = {0x0};

    em4x50_setup_read();

    // set gHigh and gLow
    if (get_signalproperties() && find_em4x50_tag()) {

        // try to login with given password
        if (etd->pwd_given)
            blogin = (login(etd->password1) == PM3_SUCCESS);

        // only one word has to be read -> first word read = last word read
        if (blogin)
            status = selective_read(etd->addresses, words);
    }

    LOW(GPIO_SSC_DOUT);
    lf_finalize();
    reply_ng(CMD_LF_EM4X50_READ, status, (uint8_t *)words, 136);
}

void em4x50_stdread(void) {

    // reads data that tag transmits "voluntarily" -> standard read mode

    int now = 0;
    uint32_t words[EM4X50_NO_WORDS] = {0x0};

    em4x50_setup_read();

    // set gHigh and gLow
    if (get_signalproperties() && find_em4x50_tag())
        standard_read(&now, words);

    LOW(GPIO_SSC_DOUT);
    lf_finalize();
    reply_ng(CMD_LF_EM4X50_STDREAD, now, (uint8_t *)words, 4 * now);
}

void em4x50_info(em4x50_data_t *etd) {

    // collects as much information as possible via selective read mode

    bool blogin = true;
    int status = PM3_EFAILED;
    uint32_t addresses = 0x00002100; // read from fwr = 0 to lwr = 33 (0x21)
    uint32_t words[EM4X50_NO_WORDS] = {0x0};

    em4x50_setup_read();

    // set gHigh and gLow
    if (get_signalproperties() && find_em4x50_tag()) {

        // login with given password
        if (etd->pwd_given)
            blogin = (login(etd->password1) == PM3_SUCCESS);

        if (blogin)
            status = selective_read(addresses, words);
    }

    lf_finalize();
    reply_ng(CMD_LF_EM4X50_INFO, status, (uint8_t *)words, 136);
}

void em4x50_watch() {

    // read continuously and display standard reads of tag

    int now = 0;
    uint32_t words[EM4X50_NO_WORDS] = {0x0};
    
    em4x50_setup_read();

    while (BUTTON_PRESS() == false) {

        WDT_HIT();
        memset(words, 0, sizeof(words));
        now = 0;

        if (get_signalproperties() && find_em4x50_tag()) {

            if (standard_read(&now, words) == BUTTON_SINGLE_CLICK)
                break;
            
            if (now > 0) {

                Dbprintf("");
                for (int i = 0; i < now; i++)
                    Dbprintf("EM4x50 tag data: "
                             _GREEN_("%08x") " (msb) - " _GREEN_("%08x") " (lsb)",
                             words[i], reflect32(words[i]));
            }
        }
    }

    LOW(GPIO_SSC_DOUT);
    lf_finalize();
    reply_ng(CMD_LF_EM4X50_WATCH, 1, 0, 0);
}

//==============================================================================
// write functions
//==============================================================================

static int write(uint32_t word, uint32_t addresses) {

    // writes <word> to specified <addresses>
    
    if (request_receive_mode() == PM3_SUCCESS) {

        // send write command
        em4x50_reader_send_byte_with_parity(EM4X50_COMMAND_WRITE);

        // send address data
        em4x50_reader_send_byte_with_parity(addresses & 0xFF);

        // send data
        em4x50_reader_send_word(word);

        if (tearoff_hook() == PM3_ETEAROFF) { // tearoff occurred
            reply_ng(CMD_LF_EM4X50_WRITE, PM3_ETEAROFF, NULL, 0);
            return PM3_ETEAROFF;
        } else {
        
            // wait for T0 * EM4X50_T_TAG_TWA (write access time)
            wait_timer(T0 * EM4X50_T_TAG_TWA);

            // look for ACK sequence
            if (check_ack(false)) {

                // now EM4x50 needs T0 * EM4X50_T_TAG_TWEE (EEPROM write time)
                // for saving data and should return with ACK
                if (check_ack(false))
                    return PM3_SUCCESS;
            }
        }
    } else {
        if (DBGLEVEL >= DBG_DEBUG)
            Dbprintf("error in command request");
    }

    return PM3_EFAILED;
}

static int write_password(uint32_t password, uint32_t new_password) {

    // changes password from <password> to <new_password>

    if (request_receive_mode() == PM3_SUCCESS) {

        // send write password command
        em4x50_reader_send_byte_with_parity(EM4X50_COMMAND_WRITE_PASSWORD);

        // send address data
        em4x50_reader_send_word(password);

        if (tearoff_hook() == PM3_ETEAROFF) { // tearoff occurred
            reply_ng(CMD_LF_EM4X50_WRITE, PM3_ETEAROFF, NULL, 0);
            return PM3_ETEAROFF;
        } else {

            // wait for T0 * EM4x50_T_TAG_TPP (processing pause time)
            wait_timer(T0 * EM4X50_T_TAG_TPP);

            // look for ACK sequence and send rm request
            // during following listen window
            if (check_ack(true)) {

                // send new password
                em4x50_reader_send_word(new_password);

                // wait for T0 * EM4X50_T_TAG_TWA (write access time)
                wait_timer(T0 * EM4X50_T_TAG_TWA);

                if (check_ack(false))
                    if (check_ack(false))
                        return PM3_SUCCESS;
            }
        }
    } else {
        if (DBGLEVEL >= DBG_DEBUG)
            Dbprintf("error in command request");
    }

    return PM3_EFAILED;
}

void em4x50_write(em4x50_data_t *etd) {

    // write operation process for EM4x50 tag,
    // single word is written to given address, verified by selective read operation
    // wrong password -> return with PM3_EFAILED

    int status = PM3_EFAILED;
    uint32_t words[EM4X50_NO_WORDS] = {0x0};

    em4x50_setup_read();

    // set gHigh and gLow
    if (get_signalproperties() && find_em4x50_tag()) {

        // if password is given try to login first
        status = PM3_SUCCESS;
        if (etd->pwd_given)
            status = login(etd->password1);

        if (status == PM3_SUCCESS) {

            // write word to given address
            status = write(etd->word, etd->addresses);
            if (status == PM3_ETEAROFF) {
                lf_finalize();
                return;
            }

            if (status == PM3_SUCCESS) {

                // to verify result reset EM4x50
                status = reset();
                if (status == PM3_SUCCESS) {

                    // if password is given renew login after reset
                    if (etd->pwd_given)
                        status = login(etd->password1);
                            
                    if (status == PM3_SUCCESS) {

                        // call a selective read
                        status = selective_read(etd->addresses, words);
                        if (status == PM3_SUCCESS) {

                            // compare result with given word
                            if (words[etd->addresses & 0xFF] != reflect32(etd->word))
                                status = PM3_EFAILED;
                        }
                    }
                }
            }
        }
    }

    lf_finalize();
    reply_ng(CMD_LF_EM4X50_WRITE, status, (uint8_t *)words, 136);
}

void em4x50_writepwd(em4x50_data_t *etd) {

    // simple change of password
    
    int status = PM3_EFAILED;

    em4x50_setup_read();

    // set gHigh and gLow
    if (get_signalproperties() && find_em4x50_tag()) {

        // login and change password
        if (login(etd->password1) == PM3_SUCCESS) {

            status = write_password(etd->password1, etd->password2);
            if (status == PM3_ETEAROFF) {
                lf_finalize();
                return;
            }
        }
    }

    lf_finalize();
    reply_ng(CMD_LF_EM4X50_WRITEPWD, status, 0, 0);
}

void em4x50_restore(em4x50_data_t *etd) {

    // restore em4x50 dump file to tag

    bool bsuccess = false;
    int status = PM3_EFAILED;
    int start_word = 3; // first block/address with user data
    uint8_t em4x50_mem[DUMP_FILESIZE] = {0x0};
    uint32_t addresses = 0x00001F01; // from fwr = 1 to lwr = 31 (0x1F)
    uint32_t words_client[EM4X50_NO_WORDS] = {0x0};
    uint32_t words_read[EM4X50_NO_WORDS] = {0x0};

    //-----------------------------------------------------------------------------
    // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_LF) here although FPGA is not
    // involved in dealing with emulator memory. But if it is called later, it will
    // destroy the Emulator Memory.
    //-----------------------------------------------------------------------------
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // read data from flash memory
    Flash_ReadData(0, em4x50_mem, 4 * EM4X50_NO_WORDS);
    for (int i = 0; i < EM4X50_NO_WORDS; i++)
        words_client[i] = reflect32(bytes_to_num(em4x50_mem + (i * 4), 4));

    em4x50_setup_read();

    // set gHigh and gLow
    if (get_signalproperties() && find_em4x50_tag()) {

        // login first if password is available
        if (etd->pwd_given) {
            if (login(etd->password1) == PM3_SUCCESS) {

                // successful login allows words 1 and 2 to be written
                start_word = 1;
            }
        }

        // write data to each address but ignore addresses
        // 0 -> password, 32 -> serial, 33 -> uid
        for (int i = start_word; i < EM4X50_NO_WORDS - 2; i++) {
            status = write(words_client[i], i);
            if (status == PM3_ETEAROFF) {
                lf_finalize();
                return;
            }
        }

        // to verify result -> reset EM4x50
        if (reset() == PM3_SUCCESS) {

            // login not necessary because protected word has been set to 0
            // -> no read protected words
            // -> selective read can be called immediately
            if (selective_read(addresses, words_read) == PM3_SUCCESS) {

                // check if everything is zero
                bsuccess = true;
                for (int i = start_word; i < EM4X50_NO_WORDS - 2; i++)
                    bsuccess &= (reflect32(words_read[i]) == words_client[i]);
            }
        }
    }

    if (bsuccess)
        status = PM3_SUCCESS;

    lf_finalize();
    reply_ng(CMD_LF_EM4X50_RESTORE, status, 0, 0);
}

//==============================================================================
// simulate functions
//==============================================================================

void em4x50_sim(void) {

    // simulate uploaded data in flash memory
    // (currently only a one-way communication is possible)

    int status = PM3_SUCCESS;
    uint8_t em4x50_mem[DUMP_FILESIZE] = {0x0};
    uint32_t words[EM4X50_NO_WORDS] = {0x0};

    //-----------------------------------------------------------------------------
    // Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_LF) here although FPGA is not
    // involved in dealing with emulator memory. But if it is called later, it will
    // destroy the Emulator Memory.
    //-----------------------------------------------------------------------------
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // read data from flash memory
    Flash_ReadData(0, em4x50_mem, 4 * EM4X50_NO_WORDS);
    for (int i = 0; i < EM4X50_NO_WORDS; i++)
        words[i] = reflect32(bytes_to_num(em4x50_mem + (i * 4), 4));

    em4x50_setup_sim();

    // only if valid em4x50 data (e.g. uid == serial)
    if (words[EM4X50_DEVICE_SERIAL] != words[EM4X50_DEVICE_ID]) {

        // extract control data
        int fwr = words[CONFIG_BLOCK] & 0xFF;           // first word read
        int lwr = (words[CONFIG_BLOCK] >> 8) & 0xFF;    // last word read
        // extract protection data
        int fwrp = words[EM4X50_PROTECTION] & 0xFF;         // first word read protected
        int lwrp = (words[EM4X50_PROTECTION] >> 8) & 0xFF;  // last word read protected

        while (!BUTTON_PRESS()) {
            
            WDT_HIT();
            em4x50_sim_send_listen_window();
            for (int i = fwr; i <= lwr; i++) {

                em4x50_sim_send_listen_window();

                if ((i >= fwrp) && (i <= lwrp))
                    em4x50_sim_send_word(0x00);
                else
                    em4x50_sim_send_word(words[i]);
            }
        }
    } else {
        status = PM3_ENODATA;
    }
    
    BigBuf_free();
    lf_finalize();
    reply_ng(CMD_LF_EM4X50_SIM, status, 0, 0);
}

//==============================================================================
// standalone mode functions
//==============================================================================

int em4x50_standalone_brute(uint32_t start, uint32_t stop, uint32_t *pwd) {

    // envoke password search in standalone mode

    int status = false;

    em4x50_setup_read();

    if (get_signalproperties() && find_em4x50_tag())
        status = brute(start, stop, pwd);
    else
        status = PM3_ETIMEOUT;

    lf_finalize();

    return status;
}

int em4x50_standalone_read(uint32_t *words) {

    int now = 0;

    em4x50_setup_read();

    if (get_signalproperties() && find_em4x50_tag())
        if (find_double_listen_window(false) == PM3_SUCCESS)
            while (get_word_from_bitstream(&words[now]) == EM4X50_TAG_WORD)
                now++;

    return now;
}
