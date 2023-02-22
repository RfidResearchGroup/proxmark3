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
// Low frequency EM4x70 commands
//-----------------------------------------------------------------------------

#include "inttypes.h"
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "printf.h"
#include "lfadc.h"
#include "commonutil.h"
#include "optimized_cipherutils.h"
#include "em4x70.h"
#include "appmain.h" // tear

static em4x70_tag_t tag = { 0 };

// EM4170 requires a parity bit on commands, other variants do not.
static bool command_parity = true;

// Conversion from Ticks to RF periods
// 1 us = 1.5 ticks
// 1RF Period = 8us = 12 Ticks
#define TICKS_PER_FC                        12

// Chip timing from datasheet
// Converted into Ticks for timing functions
#define EM4X70_T_TAG_QUARTER_PERIOD          (8 * TICKS_PER_FC)
#define EM4X70_T_TAG_HALF_PERIOD            (16 * TICKS_PER_FC)
#define EM4X70_T_TAG_THREE_QUARTER_PERIOD   (24 * TICKS_PER_FC)
#define EM4X70_T_TAG_FULL_PERIOD            (32 * TICKS_PER_FC) // 1 Bit Period
#define EM4X70_T_TAG_TWA                   (128 * TICKS_PER_FC) // Write Access Time
#define EM4X70_T_TAG_DIV                   (224 * TICKS_PER_FC) // Divergency Time
#define EM4X70_T_TAG_AUTH                 (4224 * TICKS_PER_FC) // Authentication Time
#define EM4X70_T_TAG_WEE                  (3072 * TICKS_PER_FC) // EEPROM write Time
#define EM4X70_T_TAG_TWALB                 (672 * TICKS_PER_FC) // Write Access Time of Lock Bits
#define EM4X70_T_TAG_BITMOD                  (4 * TICKS_PER_FC) // Initial time to stop modulation when sending 0
#define EM4X70_T_TAG_TOLERANCE               (8 * TICKS_PER_FC) // Tolerance in RF periods for receive/LIW

#define EM4X70_T_TAG_TIMEOUT                 (4 * EM4X70_T_TAG_FULL_PERIOD) // Timeout if we ever get a pulse longer than this
#define EM4X70_T_WAITING_FOR_LIW             50 // Pulses to wait for listen window
#define EM4X70_T_READ_HEADER_LEN             16 // Read header length (16 bit periods)

#define EM4X70_COMMAND_RETRIES               5 // Attempts to send/read command
#define EM4X70_MAX_RECEIVE_LENGTH           96 // Maximum bits to expect from any command

/**
 * These IDs are from the EM4170 datasheet
 * Some versions of the chip require a
 * (even) parity bit, others do not
 */
#define EM4X70_COMMAND_ID                   0x01
#define EM4X70_COMMAND_UM1                  0x02
#define EM4X70_COMMAND_AUTH                 0x03
#define EM4X70_COMMAND_PIN                  0x04
#define EM4X70_COMMAND_WRITE                0x05
#define EM4X70_COMMAND_UM2                  0x07

// Constants used to determine high/low state of signal
#define EM4X70_NOISE_THRESHOLD  13  // May depend on noise in environment
#define HIGH_SIGNAL_THRESHOLD  (127 + EM4X70_NOISE_THRESHOLD)
#define LOW_SIGNAL_THRESHOLD   (127 - EM4X70_NOISE_THRESHOLD)

#define IS_HIGH(sample) (sample > LOW_SIGNAL_THRESHOLD ? true : false)
#define IS_LOW(sample) (sample < HIGH_SIGNAL_THRESHOLD ? true : false)

// Timing related macros
#define IS_TIMEOUT(timeout_ticks) (GetTicks() > timeout_ticks)
#define TICKS_ELAPSED(start_ticks) (GetTicks() - start_ticks)

static uint8_t bits2byte(const uint8_t *bits, int length);
static void bits2bytes(const uint8_t *bits, int length, uint8_t *out);
static int em4x70_receive(uint8_t *bits, size_t length);
static bool find_listen_window(bool command);

// For any 32-bit value, returns the index of the highest bit set to one.
// for input of zero, this returns -1.  range of returned results: [-1 .. 31 ]
static int8_t highest_set_bit_index(uint32_t v);
static void propagate_set_bits(uint32_t *v);
static void propagate_set_bits(uint32_t *v) {
    *v |= *v >> 1;
    *v |= *v >> 2;
    *v |= *v >> 4;
    *v |= *v >> 8;
    *v |= *v >> 16;
}
static int8_t highest_set_bit_index(uint32_t v)
{
    // DeBruijn's Sequence
    static const uint32_t deBruijnValue = (uint32_t) 0x07C4ACDD;
    static const int reverse_lookup[32] = {
        0,  9,  1, 10, 13, 21,  2, 29,   11, 14, 16, 18, 22, 25,  3, 30,
        8, 12, 20, 28, 15, 17, 24,  7,   19, 27, 23,  6, 26,  5,  4, 31,
    };
    if (!v) { return -1; }
    propagate_set_bits(&v);
    return reverse_lookup[(v * deBruijnValue) >> 27];
}



static void init_tag(void) {
    memset(tag.data, 0x00, sizeof(tag.data));
}

static void em4x70_setup_read(void) {

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

    // Start the timer
    StartTicks();

    // Watchdog hit
    WDT_HIT();
}

static bool get_signalproperties(void) {

    // Simple check to ensure we see a signal above the noise threshold
    uint32_t no_periods = 32;

    // wait until signal/noise > 1 (max. 32 periods)
    for (int i = 0; i < EM4X70_T_TAG_FULL_PERIOD * no_periods; i++) {

        // about 2 samples per bit period
        WaitTicks(EM4X70_T_TAG_HALF_PERIOD);

        if (AT91C_BASE_SSC->SSC_RHR > HIGH_SIGNAL_THRESHOLD) {
            return true;
        }
    }
    return false;
}

/**
 *  get_falling_pulse_length
 *
 *      Returns time between falling edge pulse in ticks
 */
static uint32_t get_falling_pulse_length(void) {

    uint32_t timeout = GetTicks() + EM4X70_T_TAG_TIMEOUT;

    while (IS_HIGH(AT91C_BASE_SSC->SSC_RHR) && !IS_TIMEOUT(timeout));

    if (IS_TIMEOUT(timeout))
        return 0;

    uint32_t start_ticks = GetTicks();

    while (IS_LOW(AT91C_BASE_SSC->SSC_RHR) && !IS_TIMEOUT(timeout));

    if (IS_TIMEOUT(timeout))
        return 0;

    while (IS_HIGH(AT91C_BASE_SSC->SSC_RHR) && !IS_TIMEOUT(timeout));

    if (IS_TIMEOUT(timeout))
        return 0;

    return TICKS_ELAPSED(start_ticks);
}

/**
 *  get_rising_pulse_length
 *
 *      Returns time between rising edge pulse in ticks
 */
static uint32_t get_rising_pulse_length(void) {

    uint32_t timeout = GetTicks() + EM4X70_T_TAG_TIMEOUT;

    while (IS_LOW(AT91C_BASE_SSC->SSC_RHR) && !IS_TIMEOUT(timeout));

    if (IS_TIMEOUT(timeout))
        return 0;

    uint32_t start_ticks = GetTicks();

    while (IS_HIGH(AT91C_BASE_SSC->SSC_RHR) && !IS_TIMEOUT(timeout));

    if (IS_TIMEOUT(timeout))
        return 0;

    while (IS_LOW(AT91C_BASE_SSC->SSC_RHR) && !IS_TIMEOUT(timeout));

    if (IS_TIMEOUT(timeout))
        return 0;

    return TICKS_ELAPSED(start_ticks);

}

static uint32_t get_pulse_length(edge_detection_t edge) {

    if (edge == RISING_EDGE)
        return get_rising_pulse_length();
    else if (edge == FALLING_EDGE)
        return get_falling_pulse_length();

    return 0;
}

static bool check_pulse_length(uint32_t pl, uint32_t length) {
    // check if pulse length <pl> corresponds to given length <length>
    return ((pl >= (length - EM4X70_T_TAG_TOLERANCE)) && (pl <= (length + EM4X70_T_TAG_TOLERANCE)));
}

static void em4x70_send_bit(bool bit) {

    // send single bit according to EM4170 application note and datasheet
    uint32_t start_ticks = GetTicks();

    if (bit == 0) {

        // disable modulation (drop the field) n cycles of carrier
        LOW(GPIO_SSC_DOUT);
        while (TICKS_ELAPSED(start_ticks) <= EM4X70_T_TAG_BITMOD);

        // enable modulation (activates the field) for remaining first
        // half of bit period
        HIGH(GPIO_SSC_DOUT);
        while (TICKS_ELAPSED(start_ticks) <= EM4X70_T_TAG_HALF_PERIOD);

        // disable modulation for second half of bit period
        LOW(GPIO_SSC_DOUT);
        while (TICKS_ELAPSED(start_ticks) <= EM4X70_T_TAG_FULL_PERIOD);

    } else {

        // bit = "1" means disable modulation for full bit period
        LOW(GPIO_SSC_DOUT);
        while (TICKS_ELAPSED(start_ticks) <= EM4X70_T_TAG_FULL_PERIOD);
    }
}

/**
 * em4x70_send_nibble
 *
 *  sends 4 bits of data + 1 bit of parity (with_parity)
 *
 */
static void em4x70_send_nibble(uint8_t nibble, bool with_parity) {
    int parity = 0;
    int msb_bit = 0;

    // Non automotive EM4x70 based tags are 3 bits + 1 parity.
    // So drop the MSB and send a parity bit instead after the command
    if (command_parity)
        msb_bit = 1;

    for (int i = msb_bit; i < 4; i++) {
        int bit = (nibble >> (3 - i)) & 1;
        em4x70_send_bit(bit);
        parity ^= bit;
    }

    if (with_parity)
        em4x70_send_bit(parity);
}

static void em4x70_send_byte(uint8_t byte) {
    // Send byte msb first
    for (int i = 0; i < 8; i++)
        em4x70_send_bit((byte >> (7 - i)) & 1);
}

// NOTE: Takes native byte order for word to be sent.
static void em4x70_send_word(const uint16_t word) {

    // Split into nibbles
    uint8_t nibbles[4];
    // prior loop unrolled for clarity
    // input  is native uint16_t
    // output starts with most significant bits of the least significant byte (!!!)
    nibbles[0] = (word >>  4) & 0xf;
    nibbles[1] = (word >>  0) & 0xf;
    nibbles[2] = (word >> 12) & 0xf;
    nibbles[3] = (word >>  8) & 0xf;

    // send 16 bit word with parity bits according to EM4x70 datasheet
    // sent as 4 x nibbles (4 bits + parity)
    for (int i = 0; i < 4; i++) {
        em4x70_send_nibble(nibbles[i], true);
    }

    // send column parities (4 bit)
    em4x70_send_nibble(nibbles[0] ^ nibbles[1] ^ nibbles[2] ^ nibbles[3], false);

    // send final stop bit (always "0")
    em4x70_send_bit(0);
}

static bool check_ack(void) {
    // returns true if signal structue corresponds to ACK, anything else is
    // counted as NAK (-> false)
    // ACK  64 + 64
    // NAK 64 + 48
    if (check_pulse_length(get_pulse_length(FALLING_EDGE), 2 * EM4X70_T_TAG_FULL_PERIOD) &&
            check_pulse_length(get_pulse_length(FALLING_EDGE), 2 * EM4X70_T_TAG_FULL_PERIOD)) {
        // ACK
        return true;
    }

    // Otherwise it was a NAK or Listen Window
    return false;
}

static int authenticate(const uint8_t *rnd, const uint8_t *frnd, uint8_t *response) {

    if (find_listen_window(true)) {

        em4x70_send_nibble(EM4X70_COMMAND_AUTH, true);

        // Send 56-bit Random number
        for (int i = 0; i < 7; i++) {
            em4x70_send_byte(rnd[i]);
        }

        // Send 7 x 0's (Diversity bits)
        for (int i = 0; i < 7; i++) {
            em4x70_send_bit(0);
        }

        // Send 28-bit f(RN)

        // Send first 24 bits
        for (int i = 0; i < 3; i++) {
            em4x70_send_byte(frnd[i]);
        }

        // Send last 4 bits (no parity)
        em4x70_send_nibble((frnd[3] >> 4) & 0xf, false);

        // Receive header, 20-bit g(RN), LIW
        uint8_t grnd[EM4X70_MAX_RECEIVE_LENGTH] = {0};
        int num = em4x70_receive(grnd, 20);
        if (num < 20) {
            if (g_dbglevel >= DBG_EXTENDED) Dbprintf("Auth failed");
            return PM3_ESOFT;
        }
        bits2bytes(grnd, 24, response);
        return PM3_SUCCESS;
    }

    return PM3_ESOFT;
}

static int set_byte(uint8_t *target, int value) {
    int c = value > 0xFF;
    *target = reflect8(value);
    return c;
}

static int bruteforce(const uint8_t address, const uint8_t *rnd, const uint8_t *frnd, uint16_t start_key, uint8_t *response) {

    uint8_t auth_resp[3] = {0};
    uint8_t rev_rnd[7];
    uint8_t temp_rnd[7];

    reverse_arraycopy((uint8_t *)rnd, rev_rnd, sizeof(rev_rnd));
    memcpy(temp_rnd, rnd, sizeof(temp_rnd));

    for (int k = start_key; k <= 0xFFFF; ++k) {
        int c = 0;

        WDT_HIT();

        uint16_t rev_k = reflect16(k);
        switch (address) {
            case 9:
                c = set_byte(&temp_rnd[0], rev_rnd[0] + (rev_k & 0xFF));
                c = set_byte(&temp_rnd[1], rev_rnd[1] + c + ((rev_k >> 8) & 0xFF));
                c = set_byte(&temp_rnd[2], rev_rnd[2] + c);
                c = set_byte(&temp_rnd[3], rev_rnd[3] + c);
                c = set_byte(&temp_rnd[4], rev_rnd[4] + c);
                c = set_byte(&temp_rnd[5], rev_rnd[5] + c);
                set_byte(&temp_rnd[6], rev_rnd[6] + c);
                break;

            case 8:
                c = set_byte(&temp_rnd[2], rev_rnd[2] + (rev_k & 0xFF));
                c = set_byte(&temp_rnd[3], rev_rnd[3] + c + ((rev_k >> 8) & 0xFF));
                c = set_byte(&temp_rnd[4], rev_rnd[4] + c);
                c = set_byte(&temp_rnd[5], rev_rnd[5] + c);
                set_byte(&temp_rnd[6], rev_rnd[6] + c);
                break;

            case 7:
                c = set_byte(&temp_rnd[4], rev_rnd[4] + (rev_k & 0xFF));
                c = set_byte(&temp_rnd[5], rev_rnd[5] + c + ((rev_k >> 8) & 0xFF));
                set_byte(&temp_rnd[6], rev_rnd[6] + c);
                break;

            default:
                Dbprintf("Bad block number given: %d", address);
                return PM3_ESOFT;
        }

        // Report progress every 256 attempts
        if ((k % 0x100) == 0) {
            Dbprintf("Trying: %04X", k);
        }

        // Due to performance reason, we only try it once. Therefore you need a very stable RFID communcation.
        if (authenticate(temp_rnd, frnd, auth_resp) == PM3_SUCCESS) {
            if (g_dbglevel >= DBG_INFO)
                Dbprintf("Authentication success with rnd: %02X%02X%02X%02X%02X%02X%02X", temp_rnd[0], temp_rnd[1], temp_rnd[2], temp_rnd[3], temp_rnd[4], temp_rnd[5], temp_rnd[6]);
            response[0] = (k >> 8) & 0xFF;
            response[1] = k & 0xFF;
            return PM3_SUCCESS;
        }

        if (BUTTON_PRESS() || data_available()) {
            Dbprintf("EM4x70 Bruteforce Interrupted");
            return PM3_EOPABORTED;
        }
    }

    return PM3_ESOFT;
}

static int send_pin(const uint32_t pin) {

    // sends pin code for unlocking
    if (find_listen_window(true)) {

        // send PIN command
        em4x70_send_nibble(EM4X70_COMMAND_PIN, true);

        // --> Send TAG ID (bytes 4-7)
        for (int i = 0; i < 4; i++) {
            em4x70_send_byte(tag.data[7 - i]);
        }

        // --> Send PIN
        for (int i = 0; i < 4 ; i++) {
            em4x70_send_byte((pin >> (i * 8)) & 0xff);
        }

        // Wait TWALB (write access lock bits)
        WaitTicks(EM4X70_T_TAG_TWALB);

        // <-- Receive ACK
        if (check_ack()) {

            // <w> Writes Lock Bits
            WaitTicks(EM4X70_T_TAG_WEE);
            // <-- Receive header + ID
            uint8_t tag_id[EM4X70_MAX_RECEIVE_LENGTH];
            int num  = em4x70_receive(tag_id, 32);
            if (num < 32) {
                Dbprintf("Invalid ID Received");
                return PM3_ESOFT;
            }
            bits2bytes(tag_id, num, &tag.data[4]);
            return PM3_SUCCESS;
        }
    }

    return PM3_ESOFT;
}

static int write(const uint16_t word, const uint8_t address) {

    // writes <word> to specified <address>
    if (find_listen_window(true)) {

        // send write command
        em4x70_send_nibble(EM4X70_COMMAND_WRITE, true);

        // send address data with parity bit
        em4x70_send_nibble(address, true);

        // send data word
        em4x70_send_word(word);

        // Wait TWA
        WaitTicks(EM4X70_T_TAG_TWA);

        // look for ACK sequence
        if (check_ack()) {

            // now EM4x70 needs EM4X70_T_TAG_TWEE (EEPROM write time)
            // for saving data and should return with ACK
            WaitTicks(EM4X70_T_TAG_WEE);
            if (check_ack()) {

                return PM3_SUCCESS;
            }
        }
    }
    return PM3_ESOFT;
}


static bool find_listen_window(bool command) {

    int cnt = 0;
    while (cnt < EM4X70_T_WAITING_FOR_LIW) {
        /*
        80 ( 64 + 16 )
        80 ( 64 + 16 )
        Flip Polarity
        96 ( 64 + 32 )
        64 ( 32 + 16 +16 )*/

        if (check_pulse_length(get_pulse_length(RISING_EDGE), (2 * EM4X70_T_TAG_FULL_PERIOD) + EM4X70_T_TAG_HALF_PERIOD) &&
                check_pulse_length(get_pulse_length(RISING_EDGE), (2 * EM4X70_T_TAG_FULL_PERIOD) + EM4X70_T_TAG_HALF_PERIOD) &&
                check_pulse_length(get_pulse_length(FALLING_EDGE), (2 * EM4X70_T_TAG_FULL_PERIOD) + EM4X70_T_TAG_FULL_PERIOD) &&
                check_pulse_length(get_pulse_length(FALLING_EDGE),         EM4X70_T_TAG_FULL_PERIOD + (2 * EM4X70_T_TAG_HALF_PERIOD))) {

            if (command) {
                /* Here we are after the 64 duration edge.
                    *   em4170 says we need to wait about 48 RF clock cycles.
                    *   depends on the delay between tag and us
                    *
                    *   I've found between 4-5 quarter periods (32-40) works best
                    */
                WaitTicks(4 * EM4X70_T_TAG_QUARTER_PERIOD);
                // Send RM Command
                em4x70_send_bit(0);
                em4x70_send_bit(0);
            }
            return true;
        }
        cnt++;
    }

    return false;
}

static void bits2bytes(const uint8_t *bits, int length, uint8_t *out) {

    if (length % 8 != 0) {
        Dbprintf("Should have a multiple of 8 bits, was sent %d", length);
    }

    int num_bytes = length / 8; // We should have a multiple of 8 here

    for (int i = 1; i <= num_bytes; i++) {
        out[num_bytes - i] = bits2byte(bits, 8);
        bits += 8;
    }
}

static uint8_t bits2byte(const uint8_t *bits, int length) {

    // converts <length> separate bits into a single "byte"
    uint8_t byte = 0;
    for (int i = 0; i < length; i++) {

        byte |= bits[i];

        if (i != length - 1)
            byte <<= 1;
    }

    return byte;
}

static bool send_command_and_read(uint8_t command, uint8_t *bytes, size_t length) {

    int retries = EM4X70_COMMAND_RETRIES;
    while (retries) {
        retries--;

        if (find_listen_window(true)) {
            uint8_t bits[EM4X70_MAX_RECEIVE_LENGTH] = {0};
            size_t out_length_bits = length * 8;
            em4x70_send_nibble(command, command_parity);
            int len = em4x70_receive(bits, out_length_bits);
            if (len < out_length_bits) {
                Dbprintf("Invalid data received length: %d, expected %d", len, out_length_bits);
                return false;
            }
            bits2bytes(bits, len, bytes);
            return true;
        }
    }
    return false;
}



/**
 * em4x70_read_id
 *
 *  read pre-programmed ID (4 bytes)
 */
static bool em4x70_read_id(void) {

    return send_command_and_read(EM4X70_COMMAND_ID, &tag.data[4], 4);

}

/**
 *  em4x70_read_um1
 *
 *  read user memory 1 (4 bytes including lock bits)
 */
static bool em4x70_read_um1(void) {

    return send_command_and_read(EM4X70_COMMAND_UM1, &tag.data[0], 4);

}


/**
 *  em4x70_read_um2
 *
 *  read user memory 2 (8 bytes)
 */
static bool em4x70_read_um2(void) {

    return send_command_and_read(EM4X70_COMMAND_UM2, &tag.data[24], 8);

}

static bool find_em4x70_tag(void) {
    // function is used to check whether a tag on the proxmark is an
    // EM4170 tag or not -> speed up "lf search" process
    return find_listen_window(false);
}

static int em4x70_receive(uint8_t *bits, size_t length) {

    uint32_t pl;
    int bit_pos = 0;
    edge_detection_t edge = RISING_EDGE;
    bool foundheader = false;

    // Read out the header
    //   12 Manchester 1's (may miss some during settle period)
    //    4 Manchester 0's

    // Skip a few leading 1's as it could be noisy
    WaitTicks(6 * EM4X70_T_TAG_FULL_PERIOD);

    // wait until we get the transition from 1's to 0's which is 1.5 full windows
    for (int i = 0; i < EM4X70_T_READ_HEADER_LEN; i++) {
        pl = get_pulse_length(edge);
        if (check_pulse_length(pl, 3 * EM4X70_T_TAG_HALF_PERIOD)) {
            foundheader = true;
            break;
        }
    }

    if (!foundheader) {
        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("Failed to find read header");
        return 0;
    }

    // Skip next 3 0's, header check consumes the first 0
    for (int i = 0; i < 3; i++) {
        // If pulse length is not 1 bit, then abort early
        if (!check_pulse_length(get_pulse_length(edge), EM4X70_T_TAG_FULL_PERIOD)) {
            return 0;
        }
    }

    // identify remaining bits based on pulse lengths
    // between listen windows only pulse lengths of 1, 1.5 and 2 are possible
    while (bit_pos < length) {

        pl = get_pulse_length(edge);

        if (check_pulse_length(pl, EM4X70_T_TAG_FULL_PERIOD)) {

            // pulse length 1 -> assign bit
            bits[bit_pos++] = edge == FALLING_EDGE ? 1 : 0;

        } else if (check_pulse_length(pl, 3 * EM4X70_T_TAG_HALF_PERIOD)) {

            // pulse length 1.5 -> 2 bits + flip edge detection
            if (edge == FALLING_EDGE) {
                bits[bit_pos++] = 0;
                bits[bit_pos++] = 0;
                edge = RISING_EDGE;
            } else {
                bits[bit_pos++] = 1;
                bits[bit_pos++] = 1;
                edge = FALLING_EDGE;
            }

        } else if (check_pulse_length(pl, 2 * EM4X70_T_TAG_FULL_PERIOD)) {

            // pulse length of 2 -> two bits
            if (edge == FALLING_EDGE) {
                bits[bit_pos++] = 0;
                bits[bit_pos++] = 1;
            } else {
                bits[bit_pos++] = 1;
                bits[bit_pos++] = 0;
            }

        } else {
            // Listen Window, or invalid bit
            break;
        }
    }

    return bit_pos;
}

void em4x70_info(em4x70_data_t *etd, bool ledcontrol) {

    uint8_t status = 0;

    // Support tags with and without command parity bits
    command_parity = etd->parity;

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {
        // Read ID, UM1 and UM2
        status = em4x70_read_id() && em4x70_read_um1() && em4x70_read_um2();
    }

    StopTicks();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X70_INFO, status, tag.data, sizeof(tag.data));
}

void em4x70_write(em4x70_data_t *etd, bool ledcontrol) {

    uint8_t status = 0;

    command_parity = etd->parity;

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Write
        status = write(etd->word, etd->address) == PM3_SUCCESS;

        if (status) {
            // Read Tag after writing
            if (em4x70_read_id()) {
                em4x70_read_um1();
                em4x70_read_um2();
            }
        }

    }

    StopTicks();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X70_WRITE, status, tag.data, sizeof(tag.data));
}

void em4x70_unlock(em4x70_data_t *etd, bool ledcontrol) {

    uint8_t status = 0;

    command_parity = etd->parity;

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Read ID (required for send_pin command)
        if (em4x70_read_id()) {

            // Send PIN
            status = send_pin(etd->pin) == PM3_SUCCESS;

            // If the write succeeded, read the rest of the tag
            if (status) {
                // Read Tag
                // ID doesn't change
                em4x70_read_um1();
                em4x70_read_um2();
            }
        }
    }

    StopTicks();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X70_UNLOCK, status, tag.data, sizeof(tag.data));
}

void em4x70_auth(em4x70_data_t *etd, bool ledcontrol) {

    uint8_t status = 0;
    uint8_t response[3] = {0};

    command_parity = etd->parity;

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Authenticate and get tag response
        status = authenticate(etd->rnd, etd->frnd, response) == PM3_SUCCESS;
    }

    StopTicks();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X70_AUTH, status, response, sizeof(response));
}

void em4x70_brute(em4x70_data_t *etd, bool ledcontrol) {
    uint8_t status = 0;
    uint8_t response[2] = {0};

    command_parity = etd->parity;

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Bruteforce partial key
        status = bruteforce(etd->address, etd->rnd, etd->frnd, etd->start_key, response) == PM3_SUCCESS;
    }

    StopTicks();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X70_BRUTE, status, response, sizeof(response));
}

void em4x70_write_pin(em4x70_data_t *etd, bool ledcontrol) {

    uint8_t status = 0;

    command_parity = etd->parity;

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Read ID (required for send_pin command)
        if (em4x70_read_id()) {

            // Write new PIN
            if ((write(etd->pin & 0xFFFF,        EM4X70_PIN_WORD_UPPER) == PM3_SUCCESS) &&
                    (write((etd->pin >> 16) & 0xFFFF, EM4X70_PIN_WORD_LOWER) == PM3_SUCCESS)) {

                // Now Try to authenticate using the new PIN

                // Send PIN
                status = send_pin(etd->pin) == PM3_SUCCESS;

                // If the write succeeded, read the rest of the tag
                if (status) {
                    // Read Tag
                    // ID doesn't change
                    em4x70_read_um1();
                    em4x70_read_um2();
                }
            }
        }
    }

    StopTicks();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X70_WRITEPIN, status, tag.data, sizeof(tag.data));
}

void em4x70_write_key(em4x70_data_t *etd, bool ledcontrol) {

    uint8_t status = 0;

    command_parity = etd->parity;

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Read ID to ensure we can write to card
        if (em4x70_read_id()) {
            status = 1;

            // Write each crypto block
            for (int i = 0; i < 6; i++) {

                uint16_t key_word = (etd->crypt_key[(i * 2) + 1] << 8) + etd->crypt_key[i * 2];
                // Write each word, abort if any failure occurs
                if (write(key_word, 9 - i) != PM3_SUCCESS) {
                    status = 0;
                    break;
                }
            }
            // TODO: Ideally here we would perform a test authentication
            //       to ensure the new key was written correctly. This is
            //       what the datasheet suggests. We can't do that until
            //       we have the crypto algorithm implemented.
        }
    }

    StopTicks();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X70_WRITEKEY, status, tag.data, sizeof(tag.data));
}

// TODO: Check known output filter bits to reduce attempts needed.
// PROBLEM: Requires two (modifiable) 128k bit tables to store two
//          bits for each of the 2^20 possibilities.  Won't fit in
//          current ProxMark3 hardware.
//          Flash has hard-coded (assumed) size of 512k.
//          However, actual chips may be larger.
//


bool g_Extensive_EM4x70_AuthBranch_Debug = false;

void em4x70_authbranch(em4x70_authbranch_t *abd, bool ledcontrol) {
    int status_code = PM3_SUCCESS;

    init_tag();
    em4x70_setup_read();


    // expect incoming phase to be ..._REQUESTED_...
    em4x70_authbranch_phase_t phase = MemBeToUint4byte(&(abd->be_phase[0]));
    em4x70_authbranch_t results; memcpy(&results, abd, sizeof(em4x70_authbranch_t));

    command_parity = abd->phase1_input.useParity ? true : false;

    if (phase == EM4X70_AUTHBRANCH_PHASE1_REQUESTED_VERIFY_STARTING_VALUES) {
        WDT_HIT();
        Uint4byteToMemBe(&(results.be_phase[0]), EM4X70_AUTHBRANCH_PHASE1_COMPLETED_VERIFY_STARTING_VALUES);
        // Note: there are no outputs to this phase, so simply modifying the phase is sufficient

        // 1. find the tag
        if (status_code == PM3_SUCCESS) {
            WDT_HIT();
            if (g_Extensive_EM4x70_AuthBranch_Debug) {
                Dbprintf("1. Finding tag...");
            }
            if (!get_signalproperties()) {
                Dbprintf(_RED_("Failed to get signal properties."));
                status_code = PM3_EFAILED;
            }
        }
        if (status_code == PM3_SUCCESS) {
            WDT_HIT();
            if (!find_em4x70_tag()) {
                Dbprintf(_RED_("Failed to find tag."));
                status_code = PM3_EFAILED;
            }
        }
        // 2. write original key to transponder
        if (status_code == PM3_SUCCESS) {
            WDT_HIT();
            if (g_Extensive_EM4x70_AuthBranch_Debug) {
                Dbprintf("2. Writing original key to transponder...");
            }
            for (int i = 0; (status_code == PM3_SUCCESS) && (i < 6); i++) {
                // Yes, this treats the key array as though it were an array of LE 16-bit values ...
                // That's because the write() function ends up swapping each pair of bytes back. <sigh>
                uint16_t key_word = (abd->phase1_input.be_key[(i * 2) + 1] << 8) + abd->phase1_input.be_key[i * 2];
                // Write each word, abort if any failure occurs
                status_code = write(key_word, 9 - i);
                if (status_code != PM3_SUCCESS) {
                    Dbprintf(_RED_("Failed to write orig key to block %d, status %d"), 9-i, status_code);
                }
            }
        }
        // 3. verify authentication with provided rnd/frnd works
        if (status_code == PM3_SUCCESS) {
            WDT_HIT();
            uint8_t auth_response[4] = {0u};
            if (g_Extensive_EM4x70_AuthBranch_Debug) {
                Dbprintf("3. Verifying auth with provided rnd/frnd");
            }
            status_code = authenticate(&(abd->phase1_input.be_rnd[0]), &(abd->phase1_input.be_frn[0]), &(auth_response[0]));
            if (status_code != PM3_SUCCESS) {
                Dbprintf(_RED_("Failed to verify original key/rnd/frnd, status %d"), status_code);
            } else if (g_Extensive_EM4x70_AuthBranch_Debug) {
                Dbprintf("Original Tag Auth Response: %02X%02X%02X", auth_response[0], auth_response[1], auth_response[2]);
            }
        }

    } else if (phase == EM4X70_AUTHBRANCH_PHASE2_REQUESTED_WRITE_BRANCHED_KEY) {
        WDT_HIT();
        Uint4byteToMemBe(&(results.be_phase[0]), EM4X70_AUTHBRANCH_PHASE2_COMPLETED_WRITE_BRANCHED_KEY);

        // Generate the new key
        memcpy(results.phase2_output.be_key, abd->phase1_input.be_key, sizeof(results.phase2_output.be_key));
        uint32_t xormask = MemBeToUint4byte(&(abd->phase1_input.be_xormask[0]));
        uint32_t key_lsb = MemBeToUint4byte(&(abd->phase1_input.be_key[8]));
        uint32_t new_key_lsb = key_lsb ^ xormask;
        Uint4byteToMemBe(&(results.phase2_output.be_key[8]), new_key_lsb);

        // The highest set bit of xormask defines the maximum number of iterations required.
        int8_t highest_key_xormask_bit_index = highest_set_bit_index(xormask); // range [-1..31]
        if (highest_key_xormask_bit_index < 5) {
            // values less than 0x20 don't change the frn
            Uint4byteToMemBe(&(results.phase2_output.be_max_iterations[0]), UINT32_C(1));
            memcpy(&(results.phase2_output.be_min_frn[0]), &(results.phase1_input.be_frn[0]), sizeof(results.phase1_input.be_frn));
            memcpy(&(results.phase2_output.be_max_frn[0]), &(results.phase1_input.be_frn[0]), sizeof(results.phase1_input.be_frn));
            // that's all for these trivial cases!
        } else {
            // highest_key_xormask_bit_index range now [5..31]
            enum {
                // 28-bit FRN bit index is the middle-ground, converts to either key index or uint32_t frn
                // when going from the 28-bit FRN, must add 5 to the index, because least significant 5 bits of key have no influence on FRN
                // when going from the 28-bit FRN to the one stored in uint32_t, have to add 4 to the index,
                FRN_28BIT_BIT_INDEX_TO_KEY_INDEX    =  5,
                FRN_28BIT_BIT_INDEX_TO_FRN_UINT32_INDEX =  4,
                // Now list the inverse operations of the two operations above
                KEY_BIT_INDEX_TO_FRN_28BIT_INDEX        = -FRN_28BIT_BIT_INDEX_TO_KEY_INDEX,        // aka -5
                FRN_UINT32_BIT_INDEX_TO_FRN_28BIT_INDEX = -FRN_28BIT_BIT_INDEX_TO_FRN_UINT32_INDEX, // aka -4

                // For convenience, also add for converting from key bit directly to uint32_t frn and vice versa
                FRM_UINT32_BIT_INDEX_TO_KEY_INDEX = FRN_UINT32_BIT_INDEX_TO_FRN_28BIT_INDEX + FRN_28BIT_BIT_INDEX_TO_KEY_INDEX, // aka -4 + 5 = +1
                KEY_BIT_INDEX_TO_FRN_UINT32_INDEX = -FRM_UINT32_BIT_INDEX_TO_KEY_INDEX, // aka -1
            };

            // have to manuall deal with the wierdness of having a 28-bit value
            // with four zero bits shifted as least significant bits.
            // This includes special-casing otherwise simple bitmasks / bitshifts.
            // CHOSEN METHOD:
            // bit index :== index of the bit, as stored in the uint32_t (e.g., +4 to the index)
            //               of course, relative to the keybit index, the frn index would be -5.

            // Most of these are constexpr...
            int8_t frn_in_uint32_bit_index  = highest_key_xormask_bit_index + KEY_BIT_INDEX_TO_FRN_UINT32_INDEX; // range: 4..30,   if ==4          if ==30
            int8_t frn_28bit_bit_index      = highest_key_xormask_bit_index + KEY_BIT_INDEX_TO_FRN_28BIT_INDEX;  // range: 0..26,      ==0             ==26
            uint32_t original_frn_in_uint32 = MemBeToUint4byte(&(abd->phase1_input.be_frn[0]));
            uint32_t frn_in_uint32_clear_mask = ~((UINT32_C(1) << (frn_in_uint32_bit_index+1)) - 1); // before negation, all the lowest bits were set
            // uint32_t frn_in_uint32_set_mask = (~frn_in_uint32_clear_mask) & UINT32_C(0xFFFFFFF0);    // negate the clear mask, but exclude low nibble

            uint32_t max_iterations    = UINT32_C(1) << (frn_28bit_bit_index+1);
            uint32_t frn_min_in_uint32 = original_frn_in_uint32 & frn_in_uint32_clear_mask;
            uint32_t frn_max_in_uint32 = frn_min_in_uint32 + ((max_iterations-1) << 4);
            uint32_t calculated_max_iterations = ((frn_max_in_uint32 - frn_min_in_uint32)/0x10)+1;
            if (calculated_max_iterations != max_iterations) {
                if (g_Extensive_EM4x70_AuthBranch_Debug) {
                    Dbprintf(_BRIGHT_RED_("My maths appear to be incorrect...."));
                    //                              ....-....1....-....2....-            
                    Dbprintf("  %25s: %02" PRId8 , "frn_in_uint32_bit_index",    frn_in_uint32_bit_index   );
                    Dbprintf("  %25s: %02" PRId8 , "frn_28bit_bit_index",        frn_28bit_bit_index       );
                    Dbprintf("  %25s: %08" PRIX32, "original_frn_in_uint32",     original_frn_in_uint32    );
                    Dbprintf("  %25s: %08" PRIX32, "frn_in_uint32_clear_mask",   frn_in_uint32_clear_mask  );
                    Dbprintf("  %25s: %08" PRIX32, "max_iterations",             max_iterations            );
                    Dbprintf("  %25s: %08" PRIX32, "frn_min_in_uint32",          frn_min_in_uint32         );
                    Dbprintf("  %25s: %08" PRIX32, "frn_max_in_uint32",          frn_max_in_uint32         );
                    Dbprintf("  %25s: %08" PRIX32, "calculated_max_iterations",  calculated_max_iterations );
                }
                status_code = PM3_ESOFT;
            }

            // store the results in the output fields...
            Uint4byteToMemBe(&(results.phase2_output.be_min_frn[0]),        frn_min_in_uint32);
            Uint4byteToMemBe(&(results.phase2_output.be_max_frn[0]),        frn_max_in_uint32);
            Uint4byteToMemBe(&(results.phase2_output.be_max_iterations[0]), max_iterations   );
        }
        // 4. write the new branched key
        // TODO - only write the 1-2 words that have changed from phase1? (meaningless optimization)
        if (status_code == PM3_SUCCESS) {
            if (g_Extensive_EM4x70_AuthBranch_Debug) {
                Dbprintf("4. Writing branched key to transponder...");
            }
            for (int i = 0; (status_code == PM3_SUCCESS) && (i < 6); i++) {
                WDT_HIT();
                // Yes, this treats the key array as though it were an array of LE 16-bit values ...
                // That's because the write() function ends up swapping each pair of bytes back. <sigh>
                uint16_t key_word = (results.phase2_output.be_key[(i * 2) + 1] << 8) + results.phase2_output.be_key[i * 2];
                // Write each word, abort if any failure occurs
                status_code = write(key_word, 9 - i);
                if (status_code != PM3_SUCCESS) {
                    Dbprintf(_RED_("Failed to write orig key to block %d, status %d"), 9-i, status_code);
                }
            }
        }
    } else if (phase == EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE) {
        WDT_HIT();
        Uint4byteToMemBe(&(results.be_phase[0]), EM4X70_AUTHBRANCH_PHASE3_COMPLETED_BRUTE_FORCE);
        results.phase3_output.found_working_value = 0;

        // In phase 3, going to be repeatedly attempting authorization with the transponder.
        // INPUTS:
        //     phase1_input.be_rnd[7]
        //     phase3_input.be_starting_frn[4]
        //     phase3_input.be_max_iterations[4]
        //
        // If none of the frn in this set worked, still return PM3_SUCCESS.
        // This helps to differentiate vs. other types of error conditions in the client.
        //
        // OUTPUTS:
        //     be_next_start_frn[4]
        //     found_working_value
        //     be_successful_ac[3]
        //     be_successful_frn[4]
        //

        // TODO: validate inputs?
        uint32_t start_frn      = MemBeToUint4byte(&(abd->phase3_input.be_starting_frn[0]));
        uint32_t max_iterations = MemBeToUint4byte(&(abd->phase3_input.be_max_iterations[0]));
        uint32_t current_frn    = start_frn;
        if (g_Extensive_EM4x70_AuthBranch_Debug) {
            Dbprintf(_BRIGHT_RED_("Start == %08" PRIX32 ", max_iterations == %08" PRIX32), start_frn, max_iterations);
        }

        if (max_iterations == UINT32_C(0xFFFFFFFF)) {
            // would cause infinite loop
            Dbprintf(_BRIGHT_RED_("max_iterations cannot be -1"));
            status_code = PM3_EINVARG;
        }

        for (uint32_t i = 0; (status_code == PM3_SUCCESS) && (i < max_iterations); ++i, current_frn += 0x10) {
            WDT_HIT();
            if (g_Extensive_EM4x70_AuthBranch_Debug) {
                Dbprintf("Attempting FRN %08" PRIX32, current_frn);
            }

            // rnd can be used directly
            // keep output's next_start_frn updated (in case of early exit)
            Uint4byteToMemBe(&(results.phase3_output.be_next_start_frn[0]), current_frn);

            uint8_t response_data[3] = {0};
            int16_t tmp_status = authenticate(
                &(abd->phase1_input.be_rnd[0]),
                &(results.phase3_output.be_next_start_frn[0]),
                &(response_data[0])
                );

            if (tmp_status == PM3_SUCCESS) {
                if (g_Extensive_EM4x70_AuthBranch_Debug) {
                    Dbprintf(_BRIGHT_GREEN_("Found @ FRN == %08" PRIX32), current_frn);
                }
                results.phase3_output.found_working_value = 0x5A;
                Uint4byteToMemBe(&(results.phase3_output.be_successful_frn[0]), current_frn);
                memcpy(&(results.phase3_output.be_successful_ac[0]), &(response_data[0]), 3);
                break; // out of for-loop
            }
            // only tried once ... keep perfect positioning (e.g., use blue tack to hold transponder)

            if (BUTTON_PRESS() || data_available()) {
                if (g_Extensive_EM4x70_AuthBranch_Debug) {
                    Dbprintf(_BRIGHT_YELLOW_("EM4x70 Auth_Branch Interrupted;  Last FRN tested == %08" PRIX32), current_frn);
                }
                status_code = PM3_EOPABORTED;
                break; // out of for-loop
            }
        }
        // whether broke out early or not, save the next start frn
        Uint4byteToMemBe(&(results.phase3_output.be_next_start_frn[0]), current_frn);
        // if ((!results.phase3_output.found_working_value) && (status_code == PM3_SUCCESS)) {
        //     status
        // }

    } else {
        // unsupported phase ... exit!
        status_code = PM3_ESOFT;
    }

    StopTicks();
    lf_finalize(ledcontrol);

    reply_ng(CMD_LF_EM4X70_AUTHBRANCH, status_code, (uint8_t *)&results, sizeof(em4x70_authbranch_t));
    return;
}


