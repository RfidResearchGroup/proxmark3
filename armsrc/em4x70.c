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

#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
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

static void em4x70_send_word(const uint16_t word) {

    // Split into nibbles
    uint8_t nibbles[4];
    uint8_t j = 0;
    for (int i = 0; i < 2; i++) {
        uint8_t byte = (word >> (8 * i)) & 0xff;
        nibbles[j++] = (byte >> 4) & 0xf;
        nibbles[j++] = byte & 0xf;
    }

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

// TODO: define and use structs for rnd, frnd, response
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

// Sets one (reflected) byte and returns carry bit
// (1 if `value` parameter was greater than 0xFF)
static int set_byte(uint8_t *target, uint16_t value) {
    int c = value > 0xFF ? 1 : 0; // be explicit about carry bit values
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
                c = set_byte(&temp_rnd[0], rev_rnd[0]     + ((rev_k) & 0xFFu));
                c = set_byte(&temp_rnd[1], rev_rnd[1] + c + ((rev_k >> 8) & 0xFFu));
                c = set_byte(&temp_rnd[2], rev_rnd[2] + c);
                c = set_byte(&temp_rnd[3], rev_rnd[3] + c);
                c = set_byte(&temp_rnd[4], rev_rnd[4] + c);
                c = set_byte(&temp_rnd[5], rev_rnd[5] + c);
                set_byte(&temp_rnd[6], rev_rnd[6] + c);
                break;

            case 8:
                c = set_byte(&temp_rnd[2], rev_rnd[2]     + ((rev_k) & 0xFFu));
                c = set_byte(&temp_rnd[3], rev_rnd[3] + c + ((rev_k >> 8) & 0xFFu));
                c = set_byte(&temp_rnd[4], rev_rnd[4] + c);
                c = set_byte(&temp_rnd[5], rev_rnd[5] + c);
                set_byte(&temp_rnd[6], rev_rnd[6] + c);
                break;

            case 7:
                c = set_byte(&temp_rnd[4], rev_rnd[4]     + ((rev_k) & 0xFFu));
                c = set_byte(&temp_rnd[5], rev_rnd[5] + c + ((rev_k >> 8) & 0xFFu));
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

void em4x70_info(const em4x70_data_t *etd, bool ledcontrol) {

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

void em4x70_write(const em4x70_data_t *etd, bool ledcontrol) {

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

void em4x70_unlock(const em4x70_data_t *etd, bool ledcontrol) {

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

void em4x70_auth(const em4x70_data_t *etd, bool ledcontrol) {

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

void em4x70_brute(const em4x70_data_t *etd, bool ledcontrol) {
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

void em4x70_write_pin(const em4x70_data_t *etd, bool ledcontrol) {

    uint8_t status = 0;

    command_parity = etd->parity;

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Read ID (required for send_pin command)
        if (em4x70_read_id()) {

            // Write new PIN
            if ((write((etd->pin) & 0xFFFF, EM4X70_PIN_WORD_UPPER) == PM3_SUCCESS) &&
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

void em4x70_write_key(const em4x70_data_t *etd, bool ledcontrol) {

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
