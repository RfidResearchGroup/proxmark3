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
// Low frequency EM4x50 commands
//-----------------------------------------------------------------------------

#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "lfsampling.h"
#include "lfadc.h"
#include "lfdemod.h"
#include "commonutil.h"
#include "em4x50.h"
#include "BigBuf.h"
#include "spiffs.h"
#include "appmain.h" // tear
#include "bruteforce.h"

// Sam7s has several timers, we will use the source TIMER_CLOCK1 (aka AT91C_TC_CLKS_TIMER_DIV1_CLOCK)
// TIMER_CLOCK1 = MCK/2, MCK is running at 48 MHz, Timer is running at 48/2 = 24 MHz
// EM4x50 units (T0) have duration of 8 microseconds (us), which is 1/125000 per second (carrier)
// T0 = TIMER_CLOCK1 / 125000 = 192
#ifndef T0
#define T0                                  192
#endif

// conversions (carrier frequency 125 kHz):
// 1 us = 1.5 ticks
// 1 cycle = 1 period = 8 us = 12 ticks
// 1 bit = 64 cycles = 768 ticks = 512 us (for Opt64)
#define CYCLES2TICKS                        12
#define CYCLES2MUSEC                        8

// given in cycles/periods
#define EM4X50_T_TAG_QUARTER_PERIOD         16
#define EM4X50_T_TAG_HALF_PERIOD            32
#define EM4X50_T_TAG_THREE_QUARTER_PERIOD   48
#define EM4X50_T_TAG_FULL_PERIOD            64
#define EM4X50_T_TAG_TPP                    64
#define EM4X50_T_TAG_TWA                    64
#define EM4X50_T_TAG_TINIT                  2112
#define EM4X50_T_TAG_TWEE                   3200
#define EM4X50_T_TAG_WAITING_FOR_SIGNAL     75
#define EM4X50_T_WAITING_FOR_DBLLIW         1550
#define EM4X50_T_WAITING_FOR_ACK            4
#define EM4X50_T_TOLERANCE                  8
#define EM4X50_T_ZERO_DETECTION             3

// timeout values (empirical) for simulation mode (may vary with regard to reader)
#define EM4X50_T_SIMULATION_TIMEOUT_READ    600
#define EM4X50_T_SIMULATION_TIMEOUT_WAIT    50

// the following value (pulses) seems to be critical; if it's too low
//(e.g. < 120) some cards are no longer readable although they're ok
#define EM4X50_T_WAITING_FOR_SNGLLIW        140

// div
#define EM4X50_TAG_WORD                     45
#define EM4X50_TAG_MAX_NO_BYTES             136
#define EM4X50_TIMEOUT_PULSE_EVAL           2500

uint8_t g_High = 190;
uint8_t g_Low = 60;

// indication whether a previous login has been successful, so operations
// that require authentication can be handled
bool g_Login = false;
// WritePassword process in simulation mode is handled in a different way
// compared to operations like read, write, login, so it is necessary to
// to be able to identfiy it
bool g_WritePasswordProcess = false;
// if reader sends a different password than "expected" -> save it
uint32_t g_Password = 0;

// extract and check parities
// return result of parity check and extracted plain data
static bool extract_parities(uint64_t word, uint32_t *data) {

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

void em4x50_setup_read(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);

    StartTicks();

    // 50ms for the resonant antenna to settle.
    WaitMS(50);

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

    // Watchdog hit
    WDT_HIT();
}

void em4x50_setup_sim(void) {
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125);

    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT | GPIO_SSC_CLK;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_CLK;

    StartTicks();

    // Watchdog hit
    WDT_HIT();
}

// calculate signal properties (mean amplitudes) from measured data:
// 32 amplitudes (maximum values) -> mean amplitude value -> g_High -> g_Low
static bool get_signalproperties(void) {

    bool signal_found = false;
    int no_periods = 32, pct = 75, noise = 140;
    uint8_t sample_ref = 127;
    uint8_t sample_max_mean = 0;
    uint8_t sample_max[no_periods];
    uint32_t sample_max_sum = 0;
    memset(sample_max, 0x00, sizeof(sample_max));

    // wait until signal/noise > 1 (max. 32 periods)
    for (int i = 0; i < EM4X50_T_TAG_WAITING_FOR_SIGNAL; i++) {

        if (BUTTON_PRESS()) return false;

        // about 2 samples per bit period
        WaitUS(EM4X50_T_TAG_HALF_PERIOD * CYCLES2MUSEC);

        // ignore first samples
        if ((i > SIGNAL_IGNORE_FIRST_SAMPLES) && (AT91C_BASE_SSC->SSC_RHR > noise)) {
            signal_found = true;
            break;
        }
    }

    if (signal_found == false) {
        return false;
    }

    // calculate mean maximum value of 32 periods, each period has a length of
    // 3 single "full periods" to eliminate the influence of a listen window
    for (int i = 0; i < no_periods; i++) {

        uint32_t tval = GetTicks();
        while (GetTicks() - tval < 12 * 3 * EM4X50_T_TAG_FULL_PERIOD) {

            if (BUTTON_PRESS()) return false;

            volatile uint8_t sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
            if (sample > sample_max[i])
                sample_max[i] = sample;

        }

        sample_max_sum += sample_max[i];
    }

    sample_max_mean = sample_max_sum / no_periods;

    // set global envelope variables
    g_High = sample_ref + pct * (sample_max_mean - sample_ref) / 100;
    g_Low = sample_ref - pct * (sample_max_mean - sample_ref) / 100;

    return true;
}

// returns true if bit is undefined by evaluating a single sample within
// a bit period (given there is no LIW, ACK or NAK)
// This function is used for identifying a listen window in functions
// "find_double_listen_window" and "check_ack"
static bool invalid_bit(void) {

    // get sample at 3/4 of bit period
    WaitUS(EM4X50_T_TAG_THREE_QUARTER_PERIOD * CYCLES2MUSEC);

    uint8_t sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    // wait until end of bit period
    WaitUS(EM4X50_T_TAG_QUARTER_PERIOD * CYCLES2MUSEC);

    // bit in "undefined" state?
    if (sample <= g_High && sample >= g_Low)
        return true;

    return false;
}

static uint32_t get_pulse_length(void) {

    int32_t timeout = EM4X50_TIMEOUT_PULSE_EVAL, tval = 0;

    // iterates pulse lengths (low -> high -> low)

    volatile uint8_t sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    while (sample > g_Low && (timeout--))
        sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    if (timeout <= 0)
        return 0;

    tval = GetTicks();
    timeout = EM4X50_TIMEOUT_PULSE_EVAL;

    while (sample < g_High && (timeout--))
        sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    if (timeout <= 0)
        return 0;

    timeout = EM4X50_TIMEOUT_PULSE_EVAL;
    while (sample > g_Low && (timeout--))
        sample = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    if (timeout <= 0)
        return 0;

    return GetTicks() - tval;

}

// check if pulse length <pl> corresponds to given length <length>
static bool check_pulse_length(uint32_t pl, int length) {
    return ((pl >= (length - EM4X50_T_TOLERANCE) * CYCLES2TICKS) &&
            (pl <= (length + EM4X50_T_TOLERANCE) * CYCLES2TICKS));
}

// send single bit according to EM4x50 application note and datasheet
static void em4x50_reader_send_bit(int bit) {

    // reset clock for the next bit
    uint32_t tval = GetTicks();

    if (bit == 0) {

        // disable modulation (activate the field) for 7 cycles of carrier
        // period (Opt64)
        LOW(GPIO_SSC_DOUT);
        while (GetTicks() - tval < 7 * CYCLES2TICKS);

        // enable modulation (drop the field) for remaining first
        // half of bit period
        HIGH(GPIO_SSC_DOUT);
        while (GetTicks() - tval < EM4X50_T_TAG_HALF_PERIOD * CYCLES2TICKS);

        // disable modulation for second half of bit period
        LOW(GPIO_SSC_DOUT);
        while (GetTicks() - tval < EM4X50_T_TAG_FULL_PERIOD * CYCLES2TICKS);

    } else {

        // bit = "1" means disable modulation for full bit period
        LOW(GPIO_SSC_DOUT);
        while (GetTicks() - tval < EM4X50_T_TAG_FULL_PERIOD * CYCLES2TICKS);
    }
}

// send byte (without parity)
static void em4x50_reader_send_byte(uint8_t byte) {
    for (int i = 0; i < 8; i++) {
        em4x50_reader_send_bit((byte >> (7 - i)) & 1);
    }
}

// send byte followed by its (even) parity bit
static void em4x50_reader_send_byte_with_parity(uint8_t byte) {
    int parity = 0;

    for (int i = 0; i < 8; i++) {
        int bit = (byte >> (7 - i)) & 1;
        em4x50_reader_send_bit(bit);
        parity ^= bit;
    }

    em4x50_reader_send_bit(parity);
}

// send 32 bit word with parity bits according to EM4x50 datasheet
// word hast be sent in msb notation
static void em4x50_reader_send_word(const uint32_t word) {
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

// find single listen window
static bool find_single_listen_window(void) {
    int cnt_pulses = 0;

    while (cnt_pulses < EM4X50_T_WAITING_FOR_SNGLLIW) {

        // identification of listen window is done via evaluation of
        // pulse lengths
        if (check_pulse_length(get_pulse_length(), 3 * EM4X50_T_TAG_FULL_PERIOD)) {

            if (check_pulse_length(get_pulse_length(), 2 * EM4X50_T_TAG_FULL_PERIOD)) {

                // found listen window
                return true;
            }
        }
        cnt_pulses++;
    }

    return false;
}

// find two successive listen windows that indicate the beginning of
// data transmission
// double listen window to be detected within 1600 pulses -> worst case
// reason: first detectable double listen window after 34 words
// -> 34 words + 34 single listen windows -> about 1600 pulses
static int find_double_listen_window(bool bcommand) {
    int cnt_pulses = 0;

    while (cnt_pulses < EM4X50_T_WAITING_FOR_DBLLIW) {

        if (BUTTON_PRESS()) {
            return PM3_EOPABORTED;
        }

        // identification of listen window is done via evaluation of
        // pulse lengths
        if (check_pulse_length(get_pulse_length(), 3 * EM4X50_T_TAG_FULL_PERIOD)) {

            if (check_pulse_length(get_pulse_length(), 2 * EM4X50_T_TAG_FULL_PERIOD)) {

                // first listen window found

                if (bcommand) {

                    // data transmission from card has to be stopped, because
                    // a commamd shall be issued

                    // unfortunately the position in listen window (where
                    // command request has to be sent) has gone, so if a
                    // second window follows - sync on this to issue a command

                    // skip the next bit...
                    WaitUS(EM4X50_T_TAG_FULL_PERIOD * CYCLES2MUSEC);

                    // ...and check if the following bit does make sense
                    // (if not it is the correct position within the second
                    // listen window)
                    if (invalid_bit()) {

                        // send RM for request mode
                        em4x50_reader_send_bit(0);
                        em4x50_reader_send_bit(0);

                        return PM3_SUCCESS;
                    }

                }

                if (check_pulse_length(get_pulse_length(), 3 * EM4X50_T_TAG_FULL_PERIOD)) {

                    // return although second listen window consists of one
                    // more bit period but this period is necessary for
                    // evaluating further pulse lengths
                    return PM3_SUCCESS;
                }
            }
        }
        cnt_pulses++;
    }

    return PM3_EFAILED;
}

// function is used to check whether a tag on the proxmark is an
// EM4x50 tag or not -> speed up "lf search" process
static bool find_em4x50_tag(void) {
    return find_single_listen_window();
}

// To issue a command we have to find a listen window first.
// Because identification and synchronization at the same time is not
// possible when using pulse lengths a double listen window is used.
static int request_receive_mode(void) {
    return find_double_listen_window(true);
}

// returns true if signal structue corresponds to ACK, anything else is
// counted as NAK (-> false)
// Only relevant for password writing function:
// If <bliw> is true then within the single listen window right after the
// ack signal a RM request has to be sent.
static bool check_ack(bool bliw) {
    int count_cycles = 0;
    while (count_cycles < EM4X50_T_WAITING_FOR_ACK) {
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
                    WaitUS(2 * EM4X50_T_TAG_FULL_PERIOD * CYCLES2MUSEC);

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
        count_cycles++;
    }

    return false;
}

// decodes one word by evaluating pulse lengths and previous bit;
// word must have 45 bits in total:
// 32 data bits + 4 row parity bits + 8 column parity bits + 1 stop bit
static int get_word_from_bitstream(uint32_t *data) {
    bool bitchange = false;
    int cnt = 0;
    uint32_t pl = 0;
    uint64_t word = 0x0;

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

            // pulse length of 3 indicates listen window -> clear last
            // bit (= 0) and return (without parities)
            word >>= 2;
            return (extract_parities(word, data)) ? --cnt : 0;
        }
    }

    return PM3_EOPABORTED;
}

// simple login to EM4x50,
// used in operations that require authentication
static int login(uint32_t password) {
    if (request_receive_mode() == PM3_SUCCESS) {

        // send login command
        em4x50_reader_send_byte_with_parity(EM4X50_COMMAND_LOGIN);

        // send password
        em4x50_reader_send_word(password);

        WaitUS(EM4X50_T_TAG_TPP * CYCLES2MUSEC);

        // check if ACK is returned
        if (check_ack(false))
            return PM3_SUCCESS;

    } else {
        if (g_dbglevel >= DBG_DEBUG)
            Dbprintf("error in command request");
    }

    return PM3_EFAILED;
}

// searching for password using chosen bruteforce algorithm
static bool brute(const em4x50_data_t *etd, uint32_t *pwd) {

    generator_context_t ctx;
    bool pwd_found = false;
    int generator_ret = 0;
    int cnt = 0;

    bf_generator_init(&ctx, etd->bruteforce_mode);

    if (etd->bruteforce_mode == BRUTEFORCE_MODE_CHARSET)
        bf_generator_set_charset(&ctx, etd->bruteforce_charset);

    while ((generator_ret = bf_generate32(&ctx)) == GENERATOR_NEXT) {
        *pwd = ctx.current_key32;

        WDT_HIT();

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

// login into EM4x50
void em4x50_login(const uint32_t *password, bool ledcontrol) {
    em4x50_setup_read();

    int status = PM3_EFAILED;
    if (ledcontrol) LED_C_ON();
    if (get_signalproperties() && find_em4x50_tag()) {
        if (ledcontrol) {
            LED_C_OFF();
            LED_D_ON();
        }
        status = login(*password);
    }

    if (ledcontrol) LEDsoff();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X50_LOGIN, status, NULL, 0);
}

// invoke password search
void em4x50_brute(const em4x50_data_t *etd, bool ledcontrol) {
    em4x50_setup_read();

    bool bsuccess = false;
    uint32_t pwd = 0x0;
    if (ledcontrol) LED_C_ON();
    if (get_signalproperties() && find_em4x50_tag()) {
        if (ledcontrol) {
            LED_C_OFF();
            LED_D_ON();
        }
        bsuccess = brute(etd, &pwd);
    }

    if (ledcontrol) LEDsoff();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X50_BRUTE, bsuccess ? PM3_SUCCESS : PM3_EFAILED, (uint8_t *)(&pwd), sizeof(pwd));
}

// check passwords from dictionary content in flash memory
void em4x50_chk(const char *filename, bool ledcontrol) {
    int status = PM3_EFAILED;
    uint32_t pwd = 0x0;

#ifdef WITH_FLASH

    BigBuf_free();

    int changed = rdv40_spiffs_lazy_mount();
    uint16_t pwd_count = 0;
    uint32_t size = size_in_spiffs(filename);
    pwd_count = size / 4;
    uint8_t *pwds = BigBuf_malloc(size);

    rdv40_spiffs_read_as_filetype(filename, pwds, size, RDV40_SPIFFS_SAFETY_SAFE);

    if (changed)
        rdv40_spiffs_lazy_unmount();

    em4x50_setup_read();

    // set g_High and g_Low
    if (ledcontrol) LED_C_ON();
    if (get_signalproperties() && find_em4x50_tag()) {

        if (ledcontrol) {
            LED_C_OFF();
            LED_D_ON();
        }

        // try to login with current password
        for (int i = 0; i < pwd_count; i++) {

            // manual interruption
            if (BUTTON_PRESS()) {
                status = PM3_EOPABORTED;
                break;
            }

            // get next password
            pwd = 0x0;
            for (int j = 0; j < 4; j++)
                pwd |= (*(pwds + 4 * i + j)) << ((3 - j) * 8);

            if ((status = login(pwd)) == PM3_SUCCESS) {
                SpinUp(50);
                SpinDown(50);
                break;
            }
        }
    }

    BigBuf_free();

#endif

    if (ledcontrol) LEDsoff();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X50_CHK, status, (uint8_t *)&pwd, sizeof(pwd));
}

// resets EM4x50 tag (used by write function)
static int reset(void) {
    if (request_receive_mode() == PM3_SUCCESS) {

        // send reset command
        em4x50_reader_send_byte_with_parity(EM4X50_COMMAND_RESET);

        if (check_ack(false))
            return PM3_SUCCESS;

    } else {
        if (g_dbglevel >= DBG_DEBUG)
            Dbprintf("error in command request");
    }

    return PM3_EFAILED;
}

// reads data that tag transmits when exposed to reader field
// (standard read mode); number of read words is saved in <now>
int standard_read(int *now, uint32_t *words) {

    int fwr = *now, res = PM3_EFAILED;

    // start with the identification of two successive listening windows
    if ((res = find_double_listen_window(false)) == PM3_SUCCESS) {

        // read and save words until following double listen window is detected
        res = get_word_from_bitstream(&words[*now]);
        while (res == EM4X50_TAG_WORD) {
            (*now)++;
            res = get_word_from_bitstream(&words[*now]);
        }

        // number of detected words
        *now -= fwr;

    } else {
        if (g_dbglevel >= DBG_DEBUG)
            Dbprintf("didn't find a listen window");
    }

    return res;
}

// reads from "first word read" (fwr) to "last word read" (lwr)
// result is verified by "standard read mode"
static int selective_read(uint32_t addresses, uint32_t *words) {

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
        if (g_dbglevel >= DBG_DEBUG)
            Dbprintf("error in command request");
    }

    return status;
}

// reads by using "selective read mode" -> bidirectional communication
void em4x50_read(const em4x50_data_t *etd, bool ledcontrol) {
    int status = PM3_EFAILED;
    uint32_t words[EM4X50_NO_WORDS] = {0x0};

    em4x50_setup_read();

    // set g_High and g_Low
    if (ledcontrol) LED_C_ON();
    if (get_signalproperties() && find_em4x50_tag()) {

        if (ledcontrol) {
            LED_C_OFF();
            LED_D_ON();
        }

        bool blogin = true;

        // try to login with given password
        if (etd->pwd_given)
            blogin = (login(etd->password1) == PM3_SUCCESS);

        // only one word has to be read -> first word read = last word read
        if (blogin)
            status = selective_read(etd->addresses, words);
    }

    if (ledcontrol) LEDsoff();
    LOW(GPIO_SSC_DOUT);
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X50_READ, status, (uint8_t *)words, EM4X50_TAG_MAX_NO_BYTES);
}

// collects as much information as possible via selective read mode
void em4x50_info(const em4x50_data_t *etd, bool ledcontrol) {
    int status = PM3_EFAILED;
    uint32_t words[EM4X50_NO_WORDS] = {0x0};

    em4x50_setup_read();

    if (ledcontrol) LED_C_ON();
    if (get_signalproperties() && find_em4x50_tag()) {
        if (ledcontrol) {
            LED_C_OFF();
            LED_D_ON();
        }

        bool blogin = true;
        // login with given password
        if (etd->pwd_given)
            blogin = (login(etd->password1) == PM3_SUCCESS);

        if (blogin) {
            // read addresses from fwr = 0 to lwr = 33 (0x21)
            status = selective_read(0x00002100, words);
        }
    }

    if (ledcontrol) LEDsoff();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X50_INFO, status, (uint8_t *)words, EM4X50_TAG_MAX_NO_BYTES);
}

// reads data that tag transmits "voluntarily" -> standard read mode
void em4x50_reader(bool ledcontrol) {

    int now = 0;
    uint32_t words[EM4X50_NO_WORDS] = {0x0};

    em4x50_setup_read();

    if (ledcontrol) LED_C_ON();
    if (get_signalproperties() && find_em4x50_tag()) {
        if (ledcontrol) {
            LED_C_OFF();
            LED_D_ON();
        }
        standard_read(&now, words);
    }

    if (ledcontrol) LEDsoff();
    LOW(GPIO_SSC_DOUT);
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X50_READER, now, (uint8_t *)words, 4 * now);
}

// writes <word> to specified <addresses>
static int write(uint32_t word, uint32_t addresses) {

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
            WaitUS(EM4X50_T_TAG_TWA * CYCLES2MUSEC);

            // look for ACK sequence
            if (check_ack(false)) {

                // now EM4x50 needs T0 * EM4X50_T_TAG_TWEE (EEPROM write time = 3.2ms = 50 * 64 periods)
                // for saving data and should return with ACK
                for (int i = 0; i < 50; i++) {
                    WaitUS(EM4X50_T_TAG_FULL_PERIOD * CYCLES2MUSEC);
                }

                if (check_ack(false))
                    return PM3_SUCCESS;
            }
        }
    } else {
        if (g_dbglevel >= DBG_DEBUG)
            Dbprintf("error in command request");
    }

    return PM3_EFAILED;
}

// changes password from <password> to <new_password>
static int write_password(uint32_t password, uint32_t new_password) {
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
            WaitUS(EM4X50_T_TAG_TPP * CYCLES2MUSEC);

            // look for ACK sequence and send rm request
            // during following listen window
            if (check_ack(true)) {

                // send new password
                em4x50_reader_send_word(new_password);

                // wait for T0 * EM4X50_T_TAG_TWA (write access time)
                WaitUS(EM4X50_T_TAG_TWA * CYCLES2MUSEC);

                if (check_ack(false)) {

                    // now EM4x50 needs T0 * EM4X50_T_TAG_TWEE (EEPROM write time = 3.2ms = 50 * 64 periods)
                    // for saving data and should return with ACK
                    for (int i = 0; i < 50; i++) {
                        WaitUS(EM4X50_T_TAG_FULL_PERIOD * CYCLES2MUSEC);
                    }

                    if (check_ack(false))
                        return PM3_SUCCESS;
                }
            }
        }
    } else {
        if (g_dbglevel >= DBG_DEBUG)
            Dbprintf("error in command request");
    }

    return PM3_EFAILED;
}

// write operation process for EM4x50 tag,
// single word is written to given address, verified by selective read operation
// wrong password -> return with PM3_EFAILED
void em4x50_write(const em4x50_data_t *etd, bool ledcontrol) {
    int status = PM3_EFAILED;
    uint32_t words[EM4X50_NO_WORDS] = {0x0};

    em4x50_setup_read();

    if (ledcontrol) LED_C_ON();
    if (get_signalproperties() && find_em4x50_tag()) {

        if (ledcontrol) {
            LED_C_OFF();
            LED_D_ON();
        }

        // if password is given try to login first
        status = PM3_SUCCESS;
        if (etd->pwd_given)
            status = login(etd->password1);

        if (status == PM3_SUCCESS) {

            // write word to given address
            status = write(etd->word, etd->addresses);
            if (status == PM3_ETEAROFF) {
                lf_finalize(ledcontrol);
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

    if (ledcontrol) LEDsoff();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X50_WRITE, status, (uint8_t *)words, EM4X50_TAG_MAX_NO_BYTES);
}

// simple change of password
void em4x50_writepwd(const em4x50_data_t *etd, bool ledcontrol) {
    int status = PM3_EFAILED;

    em4x50_setup_read();

    if (ledcontrol) LED_C_ON();
    if (get_signalproperties() && find_em4x50_tag()) {

        if (ledcontrol) {
            LED_C_OFF();
            LED_D_ON();
        }

        // login and change password
        if (login(etd->password1) == PM3_SUCCESS) {

            status = write_password(etd->password1, etd->password2);
            if (status == PM3_ETEAROFF) {
                lf_finalize(ledcontrol);
                return;
            }
        }
    }

    if (ledcontrol) LEDsoff();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X50_WRITEPWD, status, NULL, 0);
}

// send bit in receive mode by counting carrier cycles
static void em4x50_sim_send_bit(uint8_t bit) {

    uint16_t timeout = EM4X50_T_SIMULATION_TIMEOUT_READ;

    for (int t = 0; t < EM4X50_T_TAG_FULL_PERIOD; t++) {

        // wait until SSC_CLK goes HIGH
        // used as a simple detection of a reader field?
        while ((timeout--) && !(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK));

        if (timeout == 0) {
            return;
        }
        timeout = EM4X50_T_SIMULATION_TIMEOUT_READ;

        if (bit)
            OPEN_COIL();
        else
            SHORT_COIL();

        //wait until SSC_CLK goes LOW
        while ((timeout--) && (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK));
        if (timeout == 0) {
            return;
        }
        timeout = EM4X50_T_SIMULATION_TIMEOUT_READ;

        if (t == EM4X50_T_TAG_HALF_PERIOD)
            bit ^= 1;

    }
}

// send byte in receive mode either with or without parity check (even)
static void em4x50_sim_send_byte(uint8_t byte, bool paritycheck) {

    // send byte
    for (int i = 0; i < 8; i++) {
        em4x50_sim_send_bit((byte >> (7 - i)) & 1);
    }

    if (paritycheck) {

        uint8_t parity = 0x0;

        for (int i = 0; i < 8; i++) {
            parity ^= (byte >> i) & 1;
        }

        em4x50_sim_send_bit(parity);
    }
}

// send complete word in receive mode (including all parity checks)
static void em4x50_sim_send_word(uint32_t word) {

    uint8_t cparity = 0x00;

    // word has tobe sent in msb, not lsb
    word = reflect32(word);

    // 4 bytes each with even row parity bit
    for (int i = 0; i < 4; i++) {
        em4x50_sim_send_byte((word >> ((3 - i) * 8)) & 0xFF, true);
    }

    // column parity
    for (int i = 0; i < 8; i++) {
        cparity <<= 1;
        for (int j = 0; j < 4; j++) {
            cparity ^= (((word >> ((3 - j) * 8)) & 0xFF) >> (7 - i)) & 1;
        }
    }
    em4x50_sim_send_byte(cparity, false);

    // stop bit
    em4x50_sim_send_bit(0);
}

// wait for <maxperiods> pulses of carrier frequency
static void wait_cycles(int maxperiods) {

    int period = 0, timeout = EM4X50_T_SIMULATION_TIMEOUT_WAIT;

    while (period < maxperiods) {

        while ((timeout--) && !(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK));
        if (timeout <= 0) {
            return;
        }
        timeout = EM4X50_T_SIMULATION_TIMEOUT_WAIT;

        while ((timeout--) && (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK));
        if (timeout <= 0) {
            return;
        }
        timeout = EM4X50_T_SIMULATION_TIMEOUT_WAIT;

        period++;
    }
}

// read single bit in simulation mode
static int em4x50_sim_read_bit(void) {

    int cycles = 0;
    int timeout = EM4X50_T_SIMULATION_TIMEOUT_READ;

    while (cycles < EM4X50_T_TAG_FULL_PERIOD) {

        // wait until reader field disappears
        while ((timeout--) && !(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK));
        if (timeout <= 0) {
            return PM3_ETIMEOUT;
        }
        timeout = EM4X50_T_SIMULATION_TIMEOUT_READ;

        // now check until reader switches on carrier field
        uint32_t tval = GetTicks();
        while ((timeout--) && (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK)) {

            if (timeout <= 0) {
                return PM3_ETIMEOUT;
            }

            // check if current cycle takes longer than "usual""
            if (GetTicks() - tval > EM4X50_T_ZERO_DETECTION * CYCLES2TICKS) {

                // gap detected; wait until reader field is switched on again
                while ((timeout--) && (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK));

                if (timeout <= 0) {
                    return PM3_ETIMEOUT;
                }

                // now we have a reference "position", from here it will take
                // slightly less than 32 cycles until the end of the bit period
                wait_cycles(28);

                // end of bit period is reached; return with bit value "0"
                // (cf. datasheet)
                return 0;
            }
        }
        timeout = EM4X50_T_SIMULATION_TIMEOUT_READ;

        // no gap detected, i.e. reader field is still up;
        // continue with counting cycles
        cycles++;
    }

    // reached 64 cycles (= EM4X50_T_TAG_FULL_PERIOD) -> return bit value "1"
    return 1;
}

// read byte in simulation mode either with or without parity check (even)
static bool em4x50_sim_read_byte(uint8_t *byte, bool paritycheck) {

    for (int i = 0; i < 8; i++) {
        *byte <<= 1;
        *byte |= em4x50_sim_read_bit();
    }

    if (paritycheck) {

        int pval = em4x50_sim_read_bit();
        uint8_t parity = 0;

        for (int i = 0; i < 8; i++) {
            parity ^= ((*byte) >> i) & 1;
        }

        if (parity != pval) {
            return false;
        }
    }

    return true;
}

// read complete word in simulation mode
static bool em4x50_sim_read_word(uint32_t *word) {

    uint8_t stop_bit = 0;
    uint8_t parities = 0, parities_calculated = 0;
    uint8_t bytes[4] = {0};

    // read plain data
    for (int i = 0; i < 4; i++) {
        em4x50_sim_read_byte(&bytes[i], true);
    }

    // read column parities and stop bit
    em4x50_sim_read_byte(&parities, false);
    stop_bit = em4x50_sim_read_bit();

    // calculate column parities from data
    for (int i = 0; i < 8; i++) {
        parities_calculated <<= 1;
        for (int j = 0; j < 4; j++) {
            parities_calculated ^= (bytes[j] >> (7 - i)) & 1;
        }
    }

    *word = BYTES2UINT32_BE(bytes);

    // check parities
    if ((parities == parities_calculated) && (stop_bit == 0)) {
        return true;
    }

    return false;
}

// check if reader requests receive mode (rm) by sending two zeros
static int check_rm_request(const uint32_t *tag, bool ledcontrol) {

    // look for first zero
    int bit = em4x50_sim_read_bit();
    if (bit == 0) {

        // look for second zero
        bit = em4x50_sim_read_bit();
        if (bit == 0) {

            if (ledcontrol) LED_C_ON();

            // if command before was EM4X50_COMMAND_WRITE_PASSWORD
            // switch to separate process
            if (g_WritePasswordProcess) {
                return EM4X50_COMMAND_WRITE_PASSWORD;
            } else {
                // read mode request detected, get command from reader
                uint8_t command = 0;
                em4x50_sim_read_byte(&command, true);
                return command;
            }
        }
    }

    return (bit != PM3_ETIMEOUT) ? PM3_SUCCESS : PM3_ETIMEOUT;
}

// send single listen window in simulation mode
static int em4x50_sim_send_listen_window(const uint32_t *tag, bool ledcontrol) {

    SHORT_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);

    OPEN_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);

    SHORT_COIL();
    wait_cycles(2 * EM4X50_T_TAG_FULL_PERIOD);

    OPEN_COIL();
    int command = check_rm_request(tag, ledcontrol);
    if (command != PM3_SUCCESS) {
        return command;
    }

    SHORT_COIL();
    wait_cycles(EM4X50_T_TAG_FULL_PERIOD);

    return PM3_SUCCESS;
}

// send ack
static void em4x50_sim_send_ack(void) {

    SHORT_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);

    OPEN_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);

    SHORT_COIL();
    wait_cycles(3 * EM4X50_T_TAG_HALF_PERIOD);

    OPEN_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);

    SHORT_COIL();
    wait_cycles(3 * EM4X50_T_TAG_HALF_PERIOD);

    OPEN_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);

    SHORT_COIL();
}

// send nak
static void em4x50_sim_send_nak(void) {

    SHORT_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);

    OPEN_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);

    SHORT_COIL();
    wait_cycles(3 * EM4X50_T_TAG_HALF_PERIOD);

    OPEN_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);

    SHORT_COIL();
    wait_cycles(EM4X50_T_TAG_FULL_PERIOD);

    OPEN_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);

    SHORT_COIL();
    wait_cycles(EM4X50_T_TAG_HALF_PERIOD);
}

// standard read mode process (simulation mode)
static int em4x50_sim_handle_standard_read_command(const uint32_t *tag, bool ledcontrol) {

    // extract control data
    int fwr = reflect32(tag[EM4X50_CONTROL]) & 0xFF;        // first word read
    int lwr = (reflect32(tag[EM4X50_CONTROL]) >> 8) & 0xFF; // last word read
    // extract protection data:
    // first word read protected
    int fwrp = reflect32(tag[EM4X50_PROTECTION]) & 0xFF;
    // last word read protected
    int lwrp = (reflect32(tag[EM4X50_PROTECTION]) >> 8) & 0xFF;

    while ((BUTTON_PRESS() == false) && (data_available() == false)) {

        WDT_HIT();

        int res = em4x50_sim_send_listen_window(tag, ledcontrol);

        if (res != PM3_SUCCESS) {
            return res;
        }

        for (int i = fwr; i <= lwr; i++) {

            res = em4x50_sim_send_listen_window(tag, ledcontrol);
            if (res != PM3_SUCCESS) {
                return res;
            }

            if ((g_Login == false) && (i >= fwrp) && (i <= lwrp)) {
                em4x50_sim_send_word(0x00);
            } else {
                em4x50_sim_send_word(reflect32(tag[i]));
            }
        }
    }

    return PM3_EOPABORTED;
}

// selective read mode process (simulation mode)
static int em4x50_sim_handle_selective_read_command(const uint32_t *tag, bool ledcontrol) {

    // read password
    uint32_t address = 0;
    bool addr = em4x50_sim_read_word(&address);

    // processing pause time (corresponds to a "1" bit)
    em4x50_sim_send_bit(1);

    if (addr) {
        em4x50_sim_send_ack();
    } else {
        em4x50_sim_send_nak();
        return EM4X50_COMMAND_STANDARD_READ;
    }

    // extract control data
    int fwr = address & 0xFF;           // first word read
    int lwr = (address >> 8) & 0xFF;    // last word read

    // extract protection data:
    // first word read protected
    int fwrp = reflect32(tag[EM4X50_PROTECTION]) & 0xFF;
    // last word read protected
    int lwrp = (reflect32(tag[EM4X50_PROTECTION]) >> 8) & 0xFF;

    while ((BUTTON_PRESS() == false) && (data_available() == false)) {

        WDT_HIT();

        int command = em4x50_sim_send_listen_window(tag, ledcontrol);
        if (command != PM3_SUCCESS) {
            return command;
        }

        for (int i = fwr; i <= lwr; i++) {

            command = em4x50_sim_send_listen_window(tag, ledcontrol);
            if (command != PM3_SUCCESS) {
                return command;
            }

            // if not authenticated do not send read protected words
            if ((g_Login == false) && (i >= fwrp) && (i <= lwrp)) {
                em4x50_sim_send_word(0x00);
            } else {
                em4x50_sim_send_word(reflect32(tag[i]));
            }
        }
    }

    return PM3_EOPABORTED;
}

// login process (simulation mode)
static int em4x50_sim_handle_login_command(const uint32_t *tag, bool ledcontrol) {

    // read password
    uint32_t password = 0;
    bool pwd = em4x50_sim_read_word(&password);

    // processing pause time (corresponds to a "1" bit)
    em4x50_sim_send_bit(1);

    if (pwd && (password == reflect32(tag[EM4X50_DEVICE_PASSWORD]))) {
        em4x50_sim_send_ack();
        g_Login = true;
        if (ledcontrol) LED_D_ON();
    } else {
        em4x50_sim_send_nak();
        g_Login = false;
        if (ledcontrol) LED_D_OFF();

        // save transmitted password (to be used in standalone mode)
        g_Password = password;
    }
    // continue with standard read mode
    return EM4X50_COMMAND_STANDARD_READ;
}

// reset process (simulation mode)
static int em4x50_sim_handle_reset_command(const uint32_t *tag, bool ledcontrol) {

    // processing pause time (corresponds to a "1" bit)
    em4x50_sim_send_bit(1);

    // send ACK
    em4x50_sim_send_ack();
    g_Login = false;
    if (ledcontrol) LED_D_OFF();

    // wait for initialization (tinit)
    wait_cycles(EM4X50_T_TAG_TINIT);

    // continue with standard read mode
    return EM4X50_COMMAND_STANDARD_READ;
}

// write process (simulation mode)
static int em4x50_sim_handle_write_command(uint32_t *tag, bool ledcontrol) {

    // read address
    uint8_t address = 0;
    bool addr = em4x50_sim_read_byte(&address, true);
    // read data
    uint32_t data = 0;
    bool word = em4x50_sim_read_word(&data);

    // write access time
    wait_cycles(EM4X50_T_TAG_TWA);

    if ((addr == false) || (word == false)) {
        em4x50_sim_send_nak();
        return EM4X50_COMMAND_STANDARD_READ;
    }

    // extract necessary control data
    bool raw = (tag[EM4X50_CONTROL] >> CONFIG_BLOCK) & READ_AFTER_WRITE;
    // extract protection data:
    // first word write protected
    int fwwp = reflect8((tag[EM4X50_PROTECTION] >> 24) & 0xFF);
    // last word write protected
    int lwwp = reflect8((tag[EM4X50_PROTECTION] >> 16) & 0xFF);

    switch (address) {

        case EM4X50_DEVICE_PASSWORD:
            em4x50_sim_send_nak();
            return EM4X50_COMMAND_STANDARD_READ;
            break;

        case EM4X50_PROTECTION:
            if (g_Login) {
                tag[address] = reflect32(data);
                em4x50_sim_send_ack();
            } else {
                em4x50_sim_send_nak();
                return EM4X50_COMMAND_STANDARD_READ;
            }
            break;

        case EM4X50_CONTROL:
            if (g_Login) {
                tag[address] = reflect32(data);
                em4x50_sim_send_ack();
            } else {
                em4x50_sim_send_nak();
                return EM4X50_COMMAND_STANDARD_READ;
            }
            break;

        case EM4X50_DEVICE_SERIAL:
            em4x50_sim_send_nak();
            return EM4X50_COMMAND_STANDARD_READ;
            break;

        case EM4X50_DEVICE_ID:
            em4x50_sim_send_nak();
            return EM4X50_COMMAND_STANDARD_READ;
            break;

        default:
            if ((address >= fwwp) && (address <= lwwp)) {
                if (g_Login) {
                    tag[address] = reflect32(data);
                    em4x50_sim_send_ack();
                } else {
                    em4x50_sim_send_nak();
                    return EM4X50_COMMAND_STANDARD_READ;
                }
            } else {
                tag[address] = reflect32(data);
                em4x50_sim_send_ack();
            }
            break;
    }

    // EEPROM write time
    // strange: need some sort of 'waveform correction', otherwise ack signal
    // will not be detected; sending a single "1" as last "bit" of Twee
    // seems to solve the problem
    wait_cycles(EM4X50_T_TAG_TWEE - EM4X50_T_TAG_FULL_PERIOD);
    em4x50_sim_send_bit(1);
    em4x50_sim_send_ack();

    // if "read after write" (raw) bit is set, send written data once
    if (raw) {
        int command = em4x50_sim_send_listen_window(tag, ledcontrol);
        if (command != PM3_SUCCESS) {
            return command;
        }

        command = em4x50_sim_send_listen_window(tag, ledcontrol);
        if (command != PM3_SUCCESS) {
            return command;
        }

        em4x50_sim_send_word(tag[address]);
    }

    // continue with standard read mode
    return EM4X50_COMMAND_STANDARD_READ;
}

// write password process (simulation mode)
static int em4x50_sim_handle_writepwd_command(uint32_t *tag, bool ledcontrol) {

    bool pwd = false;

    g_WritePasswordProcess = true;

    // read password
    uint32_t act_password = 0;
    pwd = em4x50_sim_read_word(&act_password);

    // processing pause time tpp (corresponds to a "1" bit)
    em4x50_sim_send_bit(1);

    if (pwd && (act_password == reflect32(tag[EM4X50_DEVICE_PASSWORD]))) {
        em4x50_sim_send_ack();
        g_Login = true;
    } else {
        em4x50_sim_send_nak();
        g_Login = false;
        g_WritePasswordProcess = false;

        // save transmitted password (to be used in standalone mode)
        g_Password = act_password;

        return EM4X50_COMMAND_STANDARD_READ;
    }

    int command = em4x50_sim_send_listen_window(tag, ledcontrol);
    g_WritePasswordProcess = false;
    if (command != EM4X50_COMMAND_WRITE_PASSWORD) {
        return command;
    }

    // read new password
    uint32_t new_password = 0;
    pwd = em4x50_sim_read_word(&new_password);

    // write access time twa
    wait_cycles(EM4X50_T_TAG_TWA);

    if (pwd) {
        em4x50_sim_send_ack();
        tag[EM4X50_DEVICE_PASSWORD] = reflect32(new_password);
        g_Password = new_password;
    } else {
        em4x50_sim_send_nak();
        return EM4X50_COMMAND_STANDARD_READ;
    }

    // EEPROM write time
    // strange: need some sort of 'waveform correction', otherwise ack signal
    // will not be detected; sending a single "1" as last part of Twee
    // seems to solve the problem
    wait_cycles(EM4X50_T_TAG_TWEE - EM4X50_T_TAG_FULL_PERIOD);
    em4x50_sim_send_bit(1);
    em4x50_sim_send_ack();

    // continue with standard read mode
    return EM4X50_COMMAND_STANDARD_READ;
}

void em4x50_handle_commands(int *command, uint32_t *tag, bool ledcontrol) {

    switch (*command) {

        case EM4X50_COMMAND_LOGIN:
            *command = em4x50_sim_handle_login_command(tag, ledcontrol);
            break;

        case EM4X50_COMMAND_RESET:
            *command = em4x50_sim_handle_reset_command(tag, ledcontrol);
            break;

        case EM4X50_COMMAND_WRITE:
            *command = em4x50_sim_handle_write_command(tag, ledcontrol);
            break;

        case EM4X50_COMMAND_WRITE_PASSWORD:
            *command = em4x50_sim_handle_writepwd_command(tag, ledcontrol);
            break;

        case EM4X50_COMMAND_SELECTIVE_READ:
            *command = em4x50_sim_handle_selective_read_command(tag, ledcontrol);
            break;

        case EM4X50_COMMAND_STANDARD_READ:
            if (ledcontrol) LED_C_OFF();
            *command = em4x50_sim_handle_standard_read_command(tag, ledcontrol);
            break;

        // bit errors during reading may lead to unknown commands
        // -> continue with standard read mode
        default:
            *command = EM4X50_COMMAND_STANDARD_READ;
            break;
    }
}

// simulate uploaded data in emulator memory
// LED C -> reader command has been detected
// LED D -> operations that require authentication are possible
void em4x50_sim(const uint32_t *password, bool ledcontrol) {

    int command = PM3_ENODATA;

    uint8_t *em4x50_mem = BigBuf_get_EM_addr();
    uint32_t tag[EM4X50_NO_WORDS] = {0x0};

    for (int i = 0; i < EM4X50_NO_WORDS; i++)
        tag[i] = bytes_to_num(em4x50_mem + (i * 4), 4);

    // via eload uploaded dump usually does not contain a password
    if (tag[EM4X50_DEVICE_PASSWORD] == 0) {
        tag[EM4X50_DEVICE_PASSWORD] = reflect32(*password);
    }

    // only if valid em4x50 data (e.g. uid == serial)
    if (tag[EM4X50_DEVICE_SERIAL] != tag[EM4X50_DEVICE_ID]) {

        // init
        if (ledcontrol) LEDsoff();
        em4x50_setup_sim();
        g_Login = false;
        g_WritePasswordProcess = false;

        // start with initial command = standard read mode
        command = EM4X50_COMMAND_STANDARD_READ;

        for (;;) {

            em4x50_handle_commands(&command, tag, ledcontrol);

            // stop if key (pm3 button or enter key) has been pressed
            if (command == PM3_EOPABORTED) {
                break;
            }

            // if timeout (e.g. no reader field) continue with standard read
            // mode and reset former authentication
            if (command == PM3_ETIMEOUT) {
                command = EM4X50_COMMAND_STANDARD_READ;
                g_Login = false;
                if (ledcontrol) LED_D_OFF();
            }
        }
    }

    BigBuf_free();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X50_SIM, command, NULL, 0);
}
