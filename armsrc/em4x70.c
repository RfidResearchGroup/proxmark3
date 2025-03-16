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

// Set debug level via client, e.g.: `hw dbg -4`
// For development, can force all the logging at compilation time by setting this to `true`
#define FORCE_ENABLE_LOGGING (false)

// Define debug macros that efficiently avoid formatting the strings
// if the debug level is not high enough.  Avoids rewriting the same
// checks like `if (g_dbglevel >= DBG_ERROR)` throughout the code,
// improving readability.  On the downside, it does require double-parentheses
// because of the limitations of the C preprocessor (until C23).
//
// Example usage:
//     DPRINTF_ERROR(("Error: %d", error_code));
//     DPRINTF_EXTENDED(("Bitstream: %s", bitstream_as_string));
#define DPRINTF_ALWAYS(x)   do { Dbprintf x ; } while (0);
#define DPRINTF_ERROR(x)    do { if ((FORCE_ENABLE_LOGGING) || (g_dbglevel >= DBG_ERROR   )) { Dbprintf x ; } } while (0);
#define DPRINTF_INFO(x)     do { if ((FORCE_ENABLE_LOGGING) || (g_dbglevel >= DBG_INFO    )) { Dbprintf x ; } } while (0);
#define DPRINTF_DEBUG(x)    do { if ((FORCE_ENABLE_LOGGING) || (g_dbglevel >= DBG_DEBUG   )) { Dbprintf x ; } } while (0);
#define DPRINTF_EXTENDED(x) do { if ((FORCE_ENABLE_LOGGING) || (g_dbglevel >= DBG_EXTENDED)) { Dbprintf x ; } } while (0);
#define DPRINTF_PROLIX(x)   do { if ((FORCE_ENABLE_LOGGING) || (g_dbglevel >  DBG_EXTENDED)) { Dbprintf x ; } } while (0);
static em4x70_tag_t tag = { 0 };

// EM4170 requires a parity bit on commands, other variants do not.
static bool command_parity = true;


#if 1 // Calculation of ticks for timing functions
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
#define EM4X70_MAX_SEND_BITCOUNT            96u // Authentication == CMD(4) + NONCE(56) + DIVERGENCY(7) + FRND(28) == 6 + 56 + 35 == 56 + 41 == 95 bits (NOTE: RM(2) is handled as part of LIW detection)
#define EM4X70_MAX_RECEIVE_BITCOUNT         64u // Maximum bits to receive in response to any command (NOTE: This is EXCLUDING the 16-bit header of 0b1111'1111'1111'0000)
#endif // Calculation of ticks for timing functions

#if 1 // EM4x70 Command IDs and notes
/**
 * These IDs are from the EM4170 datasheet.
 * Some versions of the chip require a
 * (even) parity bit, others do not.
 * The command is thus stored only in the
 * three least significant bits (mask 0x07).
 */
//                                               // w/o parity      with parity
#define EM4X70_COMMAND_ID                   0x01 // 0b0001      --> 0b001'1
#define EM4X70_COMMAND_UM1                  0x02 // 0b0010      --> 0b010'1
#define EM4X70_COMMAND_AUTH                 0x03 // 0b0011      --> 0b011'0
#define EM4X70_COMMAND_PIN                  0x04 // 0b0100      --> 0b100'1
#define EM4X70_COMMAND_WRITE                0x05 // 0b0101      --> 0b101'0
#define EM4X70_COMMAND_UM2                  0x07 // 0b0111      --> 0b111'1

// Command behaviors and bit counts for each direction:
//
// The command IDs and behaviors are the same for both EM4170 and V4070/EM4070,
// However, V4070/EM4070 does not support sending a PIN, reading UM2, and WRITE
// is limited to block 0..9 (other blocks don't exist).
// NOTE: It's possible that original V4070/EM4070 tags may have been manufactured
//       with all ten blocks being OTP (one-time-programmable)?
//
// There are only 6 commands in total.
// Each of the six commands has two variants (i.e., with and w/o command parity).
//
// Four of the commands send a predetermined bitstream, immediately synchronize
// on the tag sending the header, and then receive a number of bits from the tag:
// 
// #define EM4X70_COMMAND_ID                   0x01 // 0b0001      --> 0b001'1
//    Tag:  [LIW]           [Header][ID₃₁..ID₀][LIW]
// Reader:     [RM][Command]
//  Bits Sent: RM     +  4 bits
//  Bits Recv: Header + 32 bits
// 
// #define EM4X70_COMMAND_UM1                  0x02 // 0b0010      --> 0b010'1
//    Tag:  [LIW]           [Header][LB₁, LB₀, UM1₂₉..UM1₀][LIW]
// Reader:     [RM][Command]
//  Bits Sent: RM     +  4 bits
//  Bits Recv: Header + 32 bits
//
// #define EM4X70_COMMAND_UM2                  0x07 // 0b0111      --> 0b111'1
//    Tag:  [LIW]           [Header][UM2₆₃..UM2₀][LIW]
// Reader:     [RM][Command]
//  Bits Sent: RM     +  4 bits
//  Bits Recv: Header + 64 bits
//
// #define EM4X70_COMMAND_AUTH                 0x03 // 0b0011      --> 0b011'0
//    Tag:  [LIW]                                              [Header][g(RN)₁₉..RN₀][LIW]
// Reader:     [RM][Command][N₅₅..N₀][0000000][f(RN)₂₇..f(RN)₀]
//  Bits Sent: RM     + 95 bits
//  Bits Recv: Header + 20 bits
//
// The SEND_PIN command requires the tag ID to be retrieved first,
// then can sends a predetermined bitstream.  Unlike the above, there
// is then a wait time before the tag sends a first ACK.  Then a second
// wait time before synchronizing on the tag sending the header, and
// receive a number of bits from the tag:
//
// #define EM4X70_COMMAND_PIN                  0x04 // 0b0100      --> 0b100'1
//    Tag:  [LIW]                                    ..  [ACK]  ..  [Header][ID₃₁..ID₀][LIW]
// Reader:     [RM][Command][ID₃₁..ID₀][Pin₃₁..Pin₀] ..         ..
//  Bits Sent: RM     + 68 bits
//  Bits Recv: Header + 32 bits
//
// The WRITE command, given an address to write (A) and 16 bits of data (D),
// sends a predetermined bitstream.  Unlike the four basic commands, there
// is then a wait time before the tag sends a first ACK, and then a second
// wait time before the tag sends a second ACK.  No data is received from
// the tag ... just the two ACKs.
//
// #define EM4X70_COMMAND_WRITE                0x05 // 0b0101      --> 0b101'0
//    Tag:  [LIW]                                    ..  [ACK]  ..  [ACK][LIW]
// Reader:     [RM][Command][A₃..A₀,Ap][Data5x5]     ..         ..
//  Bits Sent: RM     + 34 bits
//  Bits Recv: !!!!!!!! NONE !!!!!!!!
//
// Thus, only need to define three sequences of interaction with the tag.
// Moreover, the reader can pre-generate its entire bitstream before any bits are sent.

// Validation of newly-written data depends on the block(s) written:
// * UM1 -- Read UM1 from the tag
// * ID  -- Read ID  from the tag
// * UM2 -- Read UM2 from the tag
// * KEY -- attempt authentication with the new key
// * PIN -- unlock the tag using the new PIN
//   TODO: Determine if sending PIN will report success, even if the tag is already unlocked?

// Auto-detect tag variant and command parity?
// EM4070/V4070 does not contain UM2 or PIN, and UM1 may be OTP (one-time programmable)
// EM4170 added Pin and UM2, and UM1
// 
// Thus, to check for overlap, need only check the first three commands with parity:
// | CMD   |  P? | Bits     | Safe? | Overlaps With    | Notes
// |-------|-----|----------|-------|------------------|------------
// | ID    | No  | `0b0001` | Yes   | None!            | Safe ... indicates no parity if successful
// | UM1   | No  | `0b0010` | Yes   | None!            | Safe ... indicates no parity if successful
// | AUTH  | No  | `0b0011` | Yes   | ID w/parity      | cannot test for no-parity, but safe to try ID w/parity
// | WRITE | No  | `0b0101` | NO    |                  | DO NOT USE ... just in case
// | PIN   | No  | `0b0100` | N/A   |                  | DO NOT USE ... just in case
// | UM2   | No  | `0b0111` | Yes   | None!            | Safe ... indicates no parity AND EM4170 tag type
// | ID    | Yes | `0b0011` | Yes   | Auth w/o Parity  | Safe to try ... indicates parity if successful
// | UM1   | Yes | `0b0101` | Yes   | Write w/o Parity | 
// | AUTH  | Yes | `0b0110` | Yes   | None!            | Not testable
// | WRITE | Yes | `0b1010` | NO    | None!            | DO NOT USE ... just in case
// | PIN   | Yes | `0b1001` | N/A   | None!            | DO NOT USE ... just in case
// | UM2   | Yes | `0b1111` | Yes   | None!            | Safe ... indicates parity AND EM4170 tag type
//
// Thus, the following sequence of commands should auto-detect both the type of tag,
// as well as whether it requires command parity or not:
// 1. If   UM2 w/o  parity -- If successful, command parity is NOT required, Type is EM4170
// 2. Elif UM2 with parity -- If successful, command parity IS     required, Type is EM4170
// 3. Elif ID  w/o  parity -- If successful, command parity is NOT required, Type is EM4070/V4070
// 4. Elif ID  with parity -- If successful, command parity IS     required, Type is EM4070/V4070
// 5. Else                 -- Error ... no tag or other error?
#endif // EM4x70 Command IDs

// Constants used to determine high/low state of signal
#define EM4X70_NOISE_THRESHOLD  13  // May depend on noise in environment
#define HIGH_SIGNAL_THRESHOLD  (127 + EM4X70_NOISE_THRESHOLD)
#define LOW_SIGNAL_THRESHOLD   (127 - EM4X70_NOISE_THRESHOLD)

#define IS_HIGH(sample) (sample > LOW_SIGNAL_THRESHOLD ? true : false)
#define IS_LOW(sample) (sample < HIGH_SIGNAL_THRESHOLD ? true : false)

// Timing related macros
#define IS_TIMEOUT(timeout_ticks) (GetTicks() > timeout_ticks)
#define TICKS_ELAPSED(start_ticks) (GetTicks() - start_ticks)

static uint8_t encoded_bit_array_to_byte(const uint8_t *bits, int count_of_bits);
static void encoded_bit_array_to_bytes(const uint8_t *bits, int count_of_bits, uint8_t *out);
static int em4x70_receive(uint8_t *bits, size_t maximum_bits_to_read);
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

static bool check_pulse_length(uint32_t pulse_tick_length, uint32_t target_tick_length) {
    // check if pulse tick length corresponds to target length (+/- tolerance)
    return ((pulse_tick_length >= (target_tick_length - EM4X70_T_TAG_TOLERANCE)) &&
            (pulse_tick_length <= (target_tick_length + EM4X70_T_TAG_TOLERANCE)));
}

#if 1 // brute force logging of sent buffer

// e.g., authenticate sends 93 bits (2x RM, 56x rnd, 7x div, 28x frnd) == 2+56+35 = 58+35 = 93
// NOTE: unlike the bitstream functions, the logs include sending of the two `RM` bits
#define EM4X70_MAX_LOG_BITS MAX(2u + EM4X70_MAX_SEND_BITCOUNT, 16u + EM4X70_MAX_RECEIVE_BITCOUNT)

typedef struct _em4x70_log_t {
    uint32_t start_tick;
    uint32_t end_tick;
    uint32_t bits_used;
    uint8_t  bit[EM4X70_MAX_LOG_BITS]; // one bit per byte
} em4x70_sublog_t;
typedef struct _em4x70_transmit_log_t {
    em4x70_sublog_t transmit;
    em4x70_sublog_t receive;
} em4x70_transmitted_data_log_t;
em4x70_transmitted_data_log_t g_not_used_directly; // change to bigbuff allocation?
em4x70_transmitted_data_log_t* g_Log = &g_not_used_directly;
static void log_reset(void) {
    if (g_Log != NULL) {
        memset(g_Log, 0, sizeof(em4x70_transmitted_data_log_t));
    }
}
static void log_dump_helper(em4x70_sublog_t * part, bool is_transmit) {
    if (g_dbglevel >= DBG_INFO || FORCE_ENABLE_LOGGING) {
        char const * const  direction = is_transmit ? "sent >>>" : "recv <<<";
        if (part->bits_used == 0) {
            DPRINTF_EXTENDED(("%s: no data", direction));
        } else {
            char bitstring[EM4X70_MAX_LOG_BITS + 1];
            memset(bitstring, 0, sizeof(bitstring));
            for (int i = 0; i < part->bits_used; i++) {
                bitstring[i] = part->bit[i] ? '1' : '0';
            }
            DPRINTF_EXTENDED((
                "%s: [ %8d .. %8d ] ( %6d ) %2d bits: %s",
                direction,
                part->start_tick, part->end_tick,
                part->end_tick - part->start_tick,
                part->bits_used, bitstring
                ));
        }
    }
}
static void log_dump(void) {
    if (g_dbglevel >= DBG_INFO || FORCE_ENABLE_LOGGING) {
        bool hasContent = false;
        if (g_Log != NULL) {
            uint8_t * check_for_data = (uint8_t *)g_Log;
            for (size_t i = 0; i < sizeof(em4x70_transmitted_data_log_t); ++i) {
                if (check_for_data[i] != 0) {
                    hasContent = true;
                    break;
                }
            }
        }
        if (hasContent) {
            log_dump_helper(&g_Log->transmit, true);
            log_dump_helper(&g_Log->receive, false);
        }
    }
}
static void log_sent_bit(uint32_t start_tick, bool bit) {
    if (g_Log != NULL) {
        if (g_Log->transmit.bits_used == 0) {
            g_Log->transmit.start_tick = start_tick;
        }
        g_Log->transmit.bit[g_Log->transmit.bits_used] = bit;
        g_Log->transmit.bits_used++;
    }
}
static void log_sent_bit_end(uint32_t end_tick) {
    if (g_Log != NULL) {
        g_Log->transmit.end_tick = end_tick;
    }
}
static void log_received_bit_start(uint32_t start_tick) {
    if (g_Log != NULL && g_Log->receive.start_tick == 0) {        
        g_Log->receive.start_tick = start_tick;
    }
}
static void log_received_bit_end(uint32_t end_tick) {
    if (g_Log != NULL) {
        g_Log->receive.end_tick = end_tick;
    }
}
static void log_received_bits(uint8_t *byte_per_bit_array, size_t array_element_count) {
    if (g_Log != NULL) {
        memcpy(&g_Log->receive.bit[g_Log->receive.bits_used], byte_per_bit_array, array_element_count);
        g_Log->receive.bits_used += array_element_count;
    }
}
#endif // brute force logging of sent buffer

// This is the only function that actually toggles modulation for sending bits
static void em4x70_send_bit(bool bit) {

    // send single bit according to EM4170 application note and datasheet
    uint32_t start_ticks = GetTicks();
    log_sent_bit(start_ticks, bit);

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
    log_sent_bit_end(GetTicks());
}

// TODO: Add similar function that will wait for an ACK/NAK up to a given timeout.
//       This will allow for more flexibile handling of tag timing in the response.
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

#if  1 // #pragma region    // Bitstream structures / enumerations
#define EM4X70_MAX_BITSTREAM_BITS MAX(EM4X70_MAX_SEND_BITCOUNT, EM4X70_MAX_RECEIVE_BITCOUNT)

// _Static_assert(EM4X70_MAX_SEND_BITCOUNT    <= 255, "EM4X70_MAX_SEND_BITCOUNT    must fit in uint8_t");
// _Static_assert(EM4X70_MAX_RECEIVE_BITCOUNT <= 255, "EM4X70_MAX_RECEIVE_BITCOUNT must fit in uint8_t");

typedef struct _em4x70_bitstream_t {
    // For sending, this is the number of bits to send
    // For receiving, this is the number of bits expected from tag
    uint8_t bitcount;
    // each bit is stored as a uint8_t, storing a single bit as 0 or 1
    // this avoids bit-shifting in potentially timing-sensitive code,
    // and ensures the simplest possible code for sending and receiving.
    uint8_t one_bit_per_byte[EM4X70_MAX_BITSTREAM_BITS];
} em4x70_bitstream_t;
typedef struct _em4x70_command_bitstream {
    uint8_t command; // three-bit value that is encoded as the command ... used to select function to handle sending/receiving data
    em4x70_bitstream_t to_send;
    em4x70_bitstream_t to_receive;
    // Note: Bits are stored in reverse order from transmission
    //       As a result, the first bit from one_bit_per_byte[0]
    //       ends up as the least significant bit of the LAST
    //       byte written.  E.g., if receiving 20 bit g(rn),
    //       converted_to_bytes[0] will have bits: GRN03..GRN00 0 0 0 0
    //       converted_to_bytes[1] will have bits: GRN11..GRN04
    //       converted_to_bytes[2] will have bits: GRN19..GRN12
    //       Which when treated as a 24-bit value stored little-endian, is:
    //           g(rn) << 8u
    //       This is based on how the existing code worked.
    uint8_t received_data_converted_to_bytes[(EM4X70_MAX_BITSTREAM_BITS / 8) + (EM4X70_MAX_BITSTREAM_BITS % 8 ? 1 : 0)];
} em4x70_command_bitstream_t;

typedef bool (*bitstream_command_generator_id_t)(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity);
typedef bool (*bitstream_command_generator_um1_t)(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity);
typedef bool (*bitstream_command_generator_um2_t)(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity);
typedef bool (*bitstream_command_generator_auth_t)(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity, const uint8_t * rnd, const uint8_t * frnd);
typedef bool (*bitstream_command_generator_pin_t)(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity, const uint8_t * tag_id, const uint32_t pin_little_endian);
typedef bool (*bitstream_command_generator_write_t)(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity, uint16_t data_little_endian, uint8_t address);

typedef struct _em4x70_command_generators_t {
    bitstream_command_generator_id_t    id;
    bitstream_command_generator_um1_t   um1;
    bitstream_command_generator_um2_t   um2;
    bitstream_command_generator_auth_t  auth;
    bitstream_command_generator_pin_t   pin;
    bitstream_command_generator_write_t write;
} em4x70_command_generators_t;

#endif // #pragma endregion // Bitstream structures / enumerations
#if  1 // #pragma region    // Functions to dump bitstreams to debug output
static void bitstream_dump_helper(const em4x70_bitstream_t * bitstream, bool is_transmit) {
    // mimic the log's output format to make comparisons easier
    char const * const  direction = is_transmit ? "sent >>>" : "recv <<<";
    if (bitstream->bitcount == 0) {
        if (g_dbglevel >= DBG_INFO || true) {
            DPRINTF_EXTENDED(("%s: no data", direction));
        }
    } else if (bitstream->bitcount > 0xFEu) {
        DPRINTF_ERROR(("INTERNAL ERROR: Too many bits to dump: %d", bitstream->bitcount));
    } else {
        char bitstring[EM4X70_MAX_BITSTREAM_BITS + 1];
        memset(bitstring, 0, sizeof(bitstring));
        for (uint16_t i = 0; i < bitstream->bitcount; ++i) {
            bitstring[i] = bitstream->one_bit_per_byte[i] ? '1' : '0';
        }
        DPRINTF_EXTENDED((
            "%s: [ %8d .. %8d ] ( %6d ) %2d bits: %s%s",
            direction,
            0, 0, 0,
            bitstream->bitcount + (is_transmit ? 2u : 0u), // add the two RM bits to transmitted data
            is_transmit ? "00" : "", // add the two RM bits to transmitted data
            bitstring
            ));
    }
}
static void bitstream_dump(const em4x70_command_bitstream_t * cmd_bitstream) {
    bitstream_dump_helper(&cmd_bitstream->to_send,    true );
    bitstream_dump_helper(&cmd_bitstream->to_receive, false);
}
#endif // #pragma region    // Functions to dump bitstreams to debug output
#if  1 // #pragma region    // Functions to send bitstreams, with options to receive data

/// @brief Internal function to send a bitstream to the tag.
/// @details This function presumes a validated structure, and sends the bitstream without delays, to support timing-sensitive operations.
/// @param send The details on the bitstream to send to the tag.
/// @return 
static bool send_bitstream_internal(const em4x70_bitstream_t * send) {
    // similar to original send_command_and_read, but using provided bitstream
    int retries = EM4X70_COMMAND_RETRIES;

    // TIMING SENSITIVE FUNCTION ... Minimize delays after finding the listen window
    while (retries) {
        const uint8_t * s = send->one_bit_per_byte;
        uint8_t sent = 0;
        retries--;
        if (find_listen_window(true)) { // `true` will automatically send the two `RM` zero bits
            // TIMING SENSITIVE SECTION
            do {
                em4x70_send_bit(*s);
                s++;
                sent++;
            } while (sent < send->bitcount);
            return true;
            // TIMING SENSITIVE SECTION
        }
    }
    return false;
}
/// @brief Internal function to send a bitstream to the tag, and immediately read response data.
/// @param send Bitstream to be sent to the tag
/// @param recv Buffer to store received data from the tag.
///             `recv->expected_bitcount` must be initialized to indicate expected bits to receive from the tag.
/// @return true only if the bitstream was sent and the expected count of bits were received from the tag.
static bool send_bitstream_and_read(em4x70_command_bitstream_t * command_bitstream) {
    const em4x70_bitstream_t * send = &command_bitstream->to_send;
    em4x70_bitstream_t * recv = &command_bitstream->to_receive;

    // Validate the parameters before proceeding
    bool parameters_valid = true;
    uint8_t bits_to_decode;
    do {
        if (command_bitstream->command == 0) {
            DPRINTF_ERROR(("No command specified -- coding error?"));
            parameters_valid = false;
            bits_to_decode = 0;
        } else if (
            (command_bitstream->command == EM4X70_COMMAND_ID)  ||
            (command_bitstream->command == EM4X70_COMMAND_UM1) ||
            (command_bitstream->command == EM4X70_COMMAND_UM2) ||
            (command_bitstream->command == EM4X70_COMMAND_AUTH)
            ) {
            // These are the four commands that are supported by this function.
            // Allow these to proceed.
        } else {
            DPRINTF_ERROR(("Unknown command: 0x%x (%d)", command_bitstream->command, command_bitstream->command));
            parameters_valid = false;
            bits_to_decode = 0;
        }

        if (send->bitcount == 0) {
            DPRINTF_ERROR(("No bits to send -- coding error?"));
            parameters_valid = false;
            bits_to_decode = 0;
        } else if (send->bitcount > EM4X70_MAX_SEND_BITCOUNT) {
            DPRINTF_ERROR(("Too many bits to send -- coding error? %d", send->bitcount));
            parameters_valid = false;
            bits_to_decode = 0;
        }
        if (recv->bitcount == 0) {
            DPRINTF_ERROR(("No bits to receive -- coding error?"));
            parameters_valid = false;
            bits_to_decode = 0;
        } else if (recv->bitcount > EM4X70_MAX_RECEIVE_BITCOUNT) {
            DPRINTF_ERROR(("Too many bits to receive -- coding error? %d", recv->bitcount));
            parameters_valid = false;
            bits_to_decode = 0;
        } else if (recv->bitcount % 8u != 0u) {
            // AUTH command receives 20 bits.  Existing code treated this "as if" tag sent 24 bits.
            // Keep this behavior to minimize the changes to both ARM and client code bases.
            bits_to_decode = ((recv->bitcount / 8u) + 1u) * 8u;  // round up to nearest byte multiple
            // _Static_assert(EM4X70_MAX_RECEIVE_BITCOUNT <= (UINT8_MAX - (UINT8_MAX % 8u)), "EM4X70_MAX_RECEIVE_BITCOUNT too large to safely round up within a uint8_t?");
            // No static assertion, so do this at runtime
            if (bits_to_decode > EM4X70_MAX_RECEIVE_BITCOUNT) {
                DPRINTF_ERROR(("Too many bits to decode after adjusting to nearest byte multiple -- coding error? %d --> %d (max %d)", recv->bitcount, bits_to_decode, EM4X70_MAX_RECEIVE_BITCOUNT));
                parameters_valid = false;
            } else {
                DPRINTF_PROLIX(("Note: will receive %d bits, but decode as %d bits", recv->bitcount));
            }
        } else {
            // Valid number of bits expected, and an integral multiple of 8 bits ... so decode exactly what was received
            bits_to_decode = recv->bitcount;
        }
    } while (0);
    // early return when parameter validation fails
    if (!parameters_valid) {
        return false;
    }


    // similar to original send_command_and_read, but using provided bitstream
    int bits_received = 0;
    
    // NOTE: reset of log does not track the time first bit is sent.  That occurs
    //       when the first sent bit is recorded in the log.
    log_reset();

    // TIMING SENSITIVE SECTION
    if (send_bitstream_internal(send)) {
        bits_received = em4x70_receive(recv->one_bit_per_byte, recv->bitcount);
    }
    // END OF TIMING SENSITIVE SECTION

    // Convert the received bits into byte array (bits are received in reverse order ... this simplifies reasoning / debugging)
    bool result = (bits_received == recv->bitcount);

    // output errors via debug prints and dump log as appropriate
    encoded_bit_array_to_bytes(recv->one_bit_per_byte, bits_to_decode, command_bitstream->received_data_converted_to_bytes);
    log_dump();
    bitstream_dump(command_bitstream);
    if (bits_received == 0) {
        DPRINTF_INFO(("No bits received -- tag may not be present?"));
    } else if (bits_received < recv->bitcount) {
        DPRINTF_INFO(("Invalid data received length: %d, expected %d", bits_received, recv->bitcount));
    } else if (bits_received != recv->bitcount) {
        DPRINTF_INFO(("INTERNAL ERROR: Expected %d bits, received %d bits (more than maximum allowed)", recv->bitcount, bits_received));
    }

    // finally return the result of the operation
    return result;
}
static bool send_bitstream_wait_ack_wait_read(em4x70_command_bitstream_t * command_bitstream) {
    const em4x70_bitstream_t * send = &command_bitstream->to_send;
    em4x70_bitstream_t * recv = &command_bitstream->to_receive;

    // Validate the parameters before proceeding
    bool parameters_valid = true;
    do {
        if (command_bitstream->command == 0) {
            DPRINTF_ERROR(("No command specified -- coding error?"));
            parameters_valid = false;
        } else if (command_bitstream->command != EM4X70_COMMAND_PIN) {
            DPRINTF_ERROR(("Unexpected command (only supports PIN): 0x%x (%d)", command_bitstream->command, command_bitstream->command));
            parameters_valid = false;
        }

        if (send->bitcount == 0) {
            DPRINTF_ERROR(("No bits to send -- coding error?"));
            parameters_valid = false;
        } else if (send->bitcount > EM4X70_MAX_SEND_BITCOUNT) {
            DPRINTF_ERROR(("Too many bits to send -- coding error? %d", send->bitcount));
            parameters_valid = false;
        }
        if (recv->bitcount == 0) {
            DPRINTF_ERROR(("No bits to receive -- coding error?"));
            parameters_valid = false;
        } else if (recv->bitcount > EM4X70_MAX_RECEIVE_BITCOUNT) {
            DPRINTF_ERROR(("Too many bits to receive -- coding error? %d", recv->bitcount));
            parameters_valid = false;
        } else if (recv->bitcount % 8u != 0u) {
            DPRINTF_ERROR(("PIN must transmit multiple of 8 bits -- coding error?", recv->bitcount));
            parameters_valid = false;
        }
    } while (0);
    // early return when parameter validation fails
    if (!parameters_valid) {
        return false;
    }

    log_reset();

    int bits_received = 0;
    // TIMING SENSITIVE SECTION -- only debug output on unrecoverable errors
    if (send_bitstream_internal(send)) {

        // Wait TWALB (write access lock bits)
        WaitTicks(EM4X70_T_TAG_TWALB);

        // <-- Receive ACK
        if (check_ack()) {

            // <w> Writes Lock Bits
            WaitTicks(EM4X70_T_TAG_WEE);

            bits_received  = em4x70_receive(recv->one_bit_per_byte, recv->bitcount);
            if (bits_received != recv->bitcount) {
                DPRINTF_INFO(("Invalid data received length: %d, expected %d", bits_received, recv->bitcount));
            }
        } else {
            DPRINTF_INFO(("No ACK received after sending command"));
        }
    } else {
        DPRINTF_INFO(("Failed to send command"));
    }
    // END TIMING SENSITIVE SECTION

    // Convert the received bits into byte array (bits are received in reverse order ... this simplifies reasoning / debugging)
    bool result = (bits_received == recv->bitcount);

    // output errors via debug prints and dump log as appropriate
    encoded_bit_array_to_bytes(recv->one_bit_per_byte, bits_received, command_bitstream->received_data_converted_to_bytes);
    log_dump();
    bitstream_dump(command_bitstream);

    return result;
}
static bool send_bitstream_wait_ack_wait_ack(em4x70_command_bitstream_t * command_bitstream) {

    const em4x70_bitstream_t * send = &command_bitstream->to_send;
    em4x70_bitstream_t * recv = &command_bitstream->to_receive;

    // Validate the parameters before proceeding
    bool parameters_valid = true;
    do {
        if (command_bitstream->command == 0) {
            DPRINTF_ERROR(("No command specified -- coding error?"));
            parameters_valid = false;
        } else if (command_bitstream->command != EM4X70_COMMAND_WRITE) {
            DPRINTF_ERROR(("Unexpected command (only supports WRITE): 0x%x (%d)", command_bitstream->command, command_bitstream->command));
            parameters_valid = false;
        }

        if (send->bitcount == 0) {
            DPRINTF_ERROR(("No bits to send -- coding error?"));
            parameters_valid = false;
        } else if (send->bitcount > EM4X70_MAX_SEND_BITCOUNT) {
            DPRINTF_ERROR(("Too many bits to send -- coding error? %d", send->bitcount));
            parameters_valid = false;
        }
        if (recv->bitcount != 0) {
            DPRINTF_ERROR(("Expecting to receive data (%d bits) -- coding error?", recv->bitcount));
            parameters_valid = false;
        }
    } while (0);
    // early return when parameter validation fails
    if (!parameters_valid) {
        DPRINTF_ERROR(("Parameter validation failed"));
        return false;
    }

    bool result = false;
    log_reset();

    // TIMING SENSITIVE SECTION -- only debug output on unrecoverable errors
    if (send_bitstream_internal(send)) {
        // Wait TWA
        WaitTicks(EM4X70_T_TAG_TWA);
        // look for ACK sequence
        if (check_ack()) {
            // now EM4x70 needs EM4X70_T_TAG_TWEE (EEPROM write time)
            // for saving data and should return with ACK
            WaitTicks(EM4X70_T_TAG_WEE);
            if (check_ack()) {
                result = true;
            } else {
                DPRINTF_INFO(("No second ACK received after sending command"));
            }
        } else {
            DPRINTF_INFO(("No ACK received after sending command"));
        }
    } else {
        DPRINTF_INFO(("Failed to send command"));
    }
    // END TIMING SENSITIVE SECTION

    log_dump();
    bitstream_dump(command_bitstream);
    return result;
}
#endif // #pragma region    // Functions to send bitstreams, with options to receive data
#if  1 // #pragma region    // Create bitstreams for each type of EM4x70 command

static bool add_bit_to_bitstream(em4x70_bitstream_t * s, bool b) {
    uint8_t i = s->bitcount;
    uint8_t bits_to_add = 1u;

    if (i > EM4X70_MAX_BITSTREAM_BITS - bits_to_add) {
        DPRINTF_ERROR(("Too many bits to add to bitstream: %d, %d", i, bits_to_add));
        return false;
    }

    s->one_bit_per_byte[i] = b ? 1 : 0;
    s->bitcount++;
    return true;
}
static bool add_nibble_to_bitstream(em4x70_bitstream_t * s, uint8_t nibble, bool add_fifth_parity_bit) {
    uint8_t i = s->bitcount;
    uint8_t bits_to_add = add_fifth_parity_bit ? 5u : 4u;
    
    if (i > EM4X70_MAX_BITSTREAM_BITS - bits_to_add) {
        DPRINTF_ERROR(("Too many bits to add to bitstream: %d, %d", i, bits_to_add));
        return false;
    }
    if ((nibble & 0xFu) != nibble) {
        DPRINTF_ERROR(("Invalid nibble value: 0x%x", nibble));
        return false;
    }

    // transmit the most significant bit first
    s->one_bit_per_byte[i + 0] = nibble & 0x08u ? 1 : 0;
    s->one_bit_per_byte[i + 1] = nibble & 0x04u ? 1 : 0;
    s->one_bit_per_byte[i + 2] = nibble & 0x02u ? 1 : 0;
    s->one_bit_per_byte[i + 3] = nibble & 0x01u ? 1 : 0;

    // add parity if requested
    if (add_fifth_parity_bit) {
        static const uint16_t parity = 0x6996u; // 0b0110'1001'1001'0110 -- value at bit index defines parity bit for that nibble value
        s->one_bit_per_byte[i + 4] = (parity & (1u << nibble)) == 0 ? 0 : 1;
    }
    s->bitcount += bits_to_add;
    return true;
}
static bool add_byte_to_bitstream(em4x70_bitstream_t * s, uint8_t b) {
    uint8_t i = s->bitcount;
    uint8_t bits_to_add = 8u;

    if (i > EM4X70_MAX_BITSTREAM_BITS - bits_to_add) {
        DPRINTF_ERROR(("Too many bits to add to bitstream: %d, %d", i, bits_to_add));
        return false;
    }
    // transmit the most significant bit first
    s->one_bit_per_byte[i + 0] = b & 0x80u ? 1 : 0;
    s->one_bit_per_byte[i + 1] = b & 0x40u ? 1 : 0;
    s->one_bit_per_byte[i + 2] = b & 0x20u ? 1 : 0;
    s->one_bit_per_byte[i + 3] = b & 0x10u ? 1 : 0;
    s->one_bit_per_byte[i + 4] = b & 0x08u ? 1 : 0;
    s->one_bit_per_byte[i + 5] = b & 0x04u ? 1 : 0;
    s->one_bit_per_byte[i + 6] = b & 0x02u ? 1 : 0;
    s->one_bit_per_byte[i + 7] = b & 0x01u ? 1 : 0;
    s->bitcount += bits_to_add;
    return true;
}


static bool create_legacy_em4x70_bitstream_for_cmd_id(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity) {
    const uint8_t expected_bits_to_send = 4u;
    bool result = true;
    memset(out_cmd_bitstream, 0, sizeof(em4x70_command_bitstream_t));
    out_cmd_bitstream->command = EM4X70_COMMAND_ID;
    uint8_t cmd = with_command_parity ? 0x3u : 0x1u;
    result = result && add_nibble_to_bitstream(&out_cmd_bitstream->to_send, cmd, false);
    out_cmd_bitstream->to_receive.bitcount = 32;
    if (out_cmd_bitstream->to_send.bitcount != expected_bits_to_send) {
        DPRINTF_ERROR(("INTERNAL ERROR: Expected %d bits to be added to send buffer, but only %d bits were added", expected_bits_to_send, out_cmd_bitstream->to_send.bitcount));
        result = false;
    }
    return result;
}
static bool create_legacy_em4x70_bitstream_for_cmd_um1(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity) {
    const uint8_t expected_bits_to_send = 4u;
    bool result = true;
    memset(out_cmd_bitstream, 0, sizeof(em4x70_command_bitstream_t));
    out_cmd_bitstream->command = EM4X70_COMMAND_UM1;
    uint8_t cmd = with_command_parity ? 0x5u : 0x2u;
    result = result && add_nibble_to_bitstream(&out_cmd_bitstream->to_send, cmd, false);
    out_cmd_bitstream->to_receive.bitcount = 32;
    if (out_cmd_bitstream->to_send.bitcount != expected_bits_to_send) {
        DPRINTF_ERROR(("INTERNAL ERROR: Expected %d bits to be added to send buffer, but only %d bits were added", expected_bits_to_send, out_cmd_bitstream->to_send.bitcount));
        result = false;
    }
    return result;
}
static bool create_legacy_em4x70_bitstream_for_cmd_um2(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity) {
    const uint8_t expected_bits_to_send = 4u;
    bool result = true;
    memset(out_cmd_bitstream, 0, sizeof(em4x70_command_bitstream_t));
    out_cmd_bitstream->command = EM4X70_COMMAND_UM2;
    uint8_t cmd = with_command_parity ? 0xFu : 0x7u;
    result = result && add_nibble_to_bitstream(&out_cmd_bitstream->to_send, cmd, false);
    out_cmd_bitstream->to_receive.bitcount = 64;
    if (out_cmd_bitstream->to_send.bitcount != expected_bits_to_send) {
        DPRINTF_ERROR(("INTERNAL ERROR: Expected %d bits to be added to send buffer, but only %d bits were added", expected_bits_to_send, out_cmd_bitstream->to_send.bitcount));
        result = false;
    }
    return true;
}
static bool create_legacy_em4x70_bitstream_for_cmd_auth(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity, const uint8_t *rnd, const uint8_t *frnd) {
    const uint8_t expected_bits_to_send = 96u;
    bool result = true;
    
    memset(out_cmd_bitstream, 0, sizeof(em4x70_command_bitstream_t));
    out_cmd_bitstream->command = EM4X70_COMMAND_AUTH;

    em4x70_bitstream_t * s = &out_cmd_bitstream->to_send;

    // *********************************************************************************
    // HACK -- Insert an extra zero bit to match legacy behavior
    // *********************************************************************************
    result = result && add_bit_to_bitstream(s, 0);

    // uint8_t cmd = with_command_parity ? 0x6u : 0x3u;
    uint8_t cmd = 0x6u; // HACK - always sent with cmd parity
    result = result && add_nibble_to_bitstream(s, cmd, false);

    // Reader:     [RM][0][Command][N₅₅..N₀][0000000][f(RN)₂₇..f(RN)₀]
    //
    // ----> HACK <----- : [ 0 ] == extra bit of zero (!?)
    // Command is 4 bits : [ 1 ..  4 ]  <---- HACK: Always sent with command parity
    // N is 56 bits      : [ 5 .. 60 ]
    // 7 bits of 0       : [61 .. 67 ]
    // f(RN) is 28 bits  : [68 .. 95 ]
    // Total bits to send: 96 bits (not the 95 bits that are actually expected)

    // Fills in bits at indexes 5 .. 60
    for (uint_fast8_t i = 0; i < 7; ++i) {
        result = result && add_byte_to_bitstream(s, rnd[i]);
    }

    // Send seven diversity bits ... indexes 61 .. 67
    for (uint_fast8_t i = 0; i < 7; ++i) {
        result = result && add_bit_to_bitstream(s, 0);
    }

    // Send first 24 bit of f(RN) ... indexes 68 .. 91
    for (uint_fast8_t i = 0; i < 3; ++i) {
        result = result && add_byte_to_bitstream(s, frnd[i]);
    }
    // and send the final 4 bits of f(RN) ... indexes 92 .. 95
    do {
        uint8_t nibble = (frnd[3] >> 4u) & 0xFu;
        result = result && add_nibble_to_bitstream(s, nibble, false);
    } while (0);

    out_cmd_bitstream->to_receive.bitcount = 20;
    if (out_cmd_bitstream->to_send.bitcount != expected_bits_to_send) {
        DPRINTF_ERROR(("INTERNAL ERROR: Expected %d bits to be added to send buffer, but only %d bits were added", expected_bits_to_send, out_cmd_bitstream->to_send.bitcount));
        result = false;
    }

    return result;
}
static bool create_legacy_em4x70_bitstream_for_cmd_pin(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity, const uint8_t *tag_id, const uint32_t pin) {
    const uint8_t expected_bits_to_send = 69; // normally 68 bits, but legacy hack inserts an extra RM bit, and always adds a command parity bit
    bool result = true;
    memset(out_cmd_bitstream, 0, sizeof(em4x70_command_bitstream_t));

    em4x70_bitstream_t * s = &out_cmd_bitstream->to_send;

    out_cmd_bitstream->command = EM4X70_COMMAND_PIN;

    // *********************************************************************************
    // HACK -- Insert an extra zero bit to match legacy behavior
    // *********************************************************************************
    result = result && add_bit_to_bitstream(s, 0);

    //uint8_t cmd = with_command_parity ? 0x9u : 0x4u;
    uint8_t cmd = 0x9u; // HACK - always sent with cmd parity, with extra zero bit in RM?
    result = result && add_nibble_to_bitstream(s, cmd, false);

    // Send tag's ID ... indexes 4 .. 35
    // e.g., tag_id points to &tag.data[4] ... &tag.data[7]
    for (uint_fast8_t i = 0; i < 4; i++) {
        uint8_t b = tag_id[3-i];
        result = result && add_byte_to_bitstream(s, b);
    }

    // Send the PIN ... indexes 36 .. 67
    for (uint_fast8_t i = 0; i < 4 ; i++) {
        // BUGBUG ... Non-portable ... likely depends on little-endian vs. big-endian (presumes little-endian)
        uint8_t b = (pin >> (i * 8u)) & 0xFFu;
        result = result && add_byte_to_bitstream(s, b);
    }

    out_cmd_bitstream->to_receive.bitcount = 32;
    if (out_cmd_bitstream->to_send.bitcount != expected_bits_to_send) {
        DPRINTF_ERROR(("INTERNAL ERROR: Expected %d bits to be added to send buffer, but only %d bits were added", expected_bits_to_send, out_cmd_bitstream->to_send.bitcount));
        result = false;
    }
    return result;
}
static bool create_legacy_em4x70_bitstream_for_cmd_write(em4x70_command_bitstream_t * out_cmd_bitstream, bool with_command_parity, uint16_t new_data, uint8_t address) {
    const uint8_t expected_bits_to_send = 35u; // normally 34 bits, but legacy hack inserts an extra RM bit, and always adds a command parity bit
    bool result = true;
    memset(out_cmd_bitstream, 0, sizeof(em4x70_command_bitstream_t));
    out_cmd_bitstream->command = EM4X70_COMMAND_WRITE;

    em4x70_bitstream_t * s = &out_cmd_bitstream->to_send;

    // *********************************************************************************
    // HACK -- Insert an extra zero bit to match legacy behavior
    // *********************************************************************************
    result = result && add_bit_to_bitstream(s, 0);

    //uint8_t cmd = with_command_parity ? 0xAu : 0x5u;
    uint8_t cmd = 0xAu; // HACK - always sent with cmd parity, with extra zero bit in RM?
    result = result && add_nibble_to_bitstream(s, cmd, false);

    if ((address & 0x0Fu) != address) {
        // only lower 4 bits are valid for address
        DPRINTF_ERROR(("Invalid address value: 0x%x", address));
        result = false;
    }
    // Send address data with its even parity bit ... indexes 4 .. 8
    result = result && add_nibble_to_bitstream(s, address, true);

    // Split into nibbles ... Being explicit here because
    // the client sent a uint16_t, but the order of the bytes
    // is reversed relative to what is going to be sent.
    // Thus, must swap the bytes before splitting into nibbles.
    // TODO: Fix client and arm code to only use byte arrays.....
    uint8_t nibbles[4] = {
        (new_data >>  4) & 0xFu,
        (new_data >>  0) & 0xFu,
        (new_data >> 12) & 0xFu,
        (new_data >>  8) & 0xFu,
    };

    // Send each of the four nibbles of data with their respective parity ... indexes 9 .. 28
    uint8_t column_parity = 0;
    for (uint_fast8_t i = 0; i < 4; ++i) {
        uint8_t nibble = nibbles[i];
        column_parity ^= nibble;
        result = result && add_nibble_to_bitstream(s, nibble, true);
    }

    // add the column parity ... indexes 29 .. 32 ... but manually add zero as fifth bit (it's not a parity)
    result = result && add_nibble_to_bitstream(s, column_parity, false);
    result = result && add_bit_to_bitstream(s, 0);

    out_cmd_bitstream->to_receive.bitcount = 0;
    if (out_cmd_bitstream->to_send.bitcount != expected_bits_to_send) {
        DPRINTF_ERROR(("INTERNAL ERROR: Expected %d bits to be added to send buffer, but only %d bits were added", expected_bits_to_send, out_cmd_bitstream->to_send.bitcount));
        result = false;
    }
    return result;
}
const em4x70_command_generators_t legacy_em4x70_command_generators = {
    .id    = create_legacy_em4x70_bitstream_for_cmd_id,
    .um1   = create_legacy_em4x70_bitstream_for_cmd_um1,
    .um2   = create_legacy_em4x70_bitstream_for_cmd_um2,
    .auth  = create_legacy_em4x70_bitstream_for_cmd_auth,
    .pin   = create_legacy_em4x70_bitstream_for_cmd_pin,
    .write = create_legacy_em4x70_bitstream_for_cmd_write
};
#endif // #pragma endregion // Create bitstreams for each type of EM4x70 command

// TODO: define and use structs for rnd, frnd, response
//       Or, just use the structs defined by IDLIB48?
// log entry/exit point
static int authenticate(const uint8_t *rnd, const uint8_t *frnd, uint8_t *response) {
    em4x70_command_bitstream_t auth_cmd;

    const em4x70_command_generators_t * generator = &legacy_em4x70_command_generators;
    generator->auth(&auth_cmd, command_parity, rnd, frnd);

    bool result = send_bitstream_and_read(&auth_cmd);
    if (result) {
        encoded_bit_array_to_bytes(auth_cmd.to_receive.one_bit_per_byte, 24, response);
    }
    return result ? PM3_SUCCESS : PM3_ESOFT;
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

    reverse_arraybytes_copy((uint8_t *)rnd, rev_rnd, sizeof(rev_rnd));
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
                DPRINTF_ERROR(("Bad block number given: %d", address));
                return PM3_ESOFT;
        }

        // Report progress every 256 attempts
        if ((k % 0x100) == 0) {
            DPRINTF_ALWAYS(("Trying: %04X", k));
        }

        // Due to performance reason, we only try it once. Therefore you need a very stable RFID communcation.
        if (authenticate(temp_rnd, frnd, auth_resp) == PM3_SUCCESS) {
            DPRINTF_INFO(("Authentication success with rnd: %02X%02X%02X%02X%02X%02X%02X", temp_rnd[0], temp_rnd[1], temp_rnd[2], temp_rnd[3], temp_rnd[4], temp_rnd[5], temp_rnd[6]));
            response[0] = (k >> 8) & 0xFF;
            response[1] = k & 0xFF;
            return PM3_SUCCESS;
        }

        if (BUTTON_PRESS() || data_available()) {
            DPRINTF_ALWAYS(("EM4x70 Bruteforce Interrupted at key %04X", k));
            return PM3_EOPABORTED;
        }
    }

    return PM3_ESOFT;
}

// log entry/exit point
static int send_pin(const uint32_t pin) {
    em4x70_command_bitstream_t send_pin_cmd;
    const em4x70_command_generators_t * generator = &legacy_em4x70_command_generators;
    generator->pin(&send_pin_cmd, command_parity, &tag.data[4], pin);

    bool result = send_bitstream_wait_ack_wait_read(&send_pin_cmd);
    return result ? PM3_SUCCESS : PM3_ESOFT;
}

// log entry/exit point
static int write(const uint16_t word, const uint8_t address) {
    em4x70_command_bitstream_t write_cmd;

    const em4x70_command_generators_t * generator = &legacy_em4x70_command_generators;
    generator->write(&write_cmd, command_parity, word, address);

    bool result = send_bitstream_wait_ack_wait_ack(&write_cmd);
    if (!result) {
        DPRINTF_INFO(("Failed to write data"));
    }
    return result ? PM3_SUCCESS : PM3_ESOFT;
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

        if (check_pulse_length(get_pulse_length(RISING_EDGE),  (2 * EM4X70_T_TAG_FULL_PERIOD) + EM4X70_T_TAG_HALF_PERIOD) &&
            check_pulse_length(get_pulse_length(RISING_EDGE),  (2 * EM4X70_T_TAG_FULL_PERIOD) + EM4X70_T_TAG_HALF_PERIOD) &&
            check_pulse_length(get_pulse_length(FALLING_EDGE), (2 * EM4X70_T_TAG_FULL_PERIOD) + EM4X70_T_TAG_FULL_PERIOD) &&
            check_pulse_length(get_pulse_length(FALLING_EDGE), (1 * EM4X70_T_TAG_FULL_PERIOD) + EM4X70_T_TAG_FULL_PERIOD)) {

            if (command) {
                /* Here we are after the 64 duration edge.
                 *   em4170 says we need to wait about 48 RF clock cycles.
                 *   depends on the delay between tag and us
                 *
                 *   I've found 32-40 field cycles works best
                 *   Allow user adjustment in range: 24-48 field cycles?
                 *   On PM3Easy I've seen success at 24..40 field 
                 */
                WaitTicks(40 * TICKS_PER_FC);
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

// *bits == array of bytes, each byte storing a single bit.
// *out  == array of bytes, storing converted bits --> bytes.
//
// [in,  bcount(count_of_bits)  ] const uint8_t *bits
// [out, bcount(count_of_bits/8)] uint8_t *out
static void encoded_bit_array_to_bytes(const uint8_t *bits, int count_of_bits, uint8_t *out) {

    if (count_of_bits % 8 != 0) {
        DPRINTF_ERROR(("Should have a multiple of 8 bits, was sent %d", count_of_bits));
    }

    int num_bytes = count_of_bits / 8; // We should have a multiple of 8 here

    for (int i = 1; i <= num_bytes; i++) {
        out[num_bytes - i] = encoded_bit_array_to_byte(bits, 8);
        bits += 8;
    }
}

static uint8_t encoded_bit_array_to_byte(const uint8_t *bits, int count_of_bits) {

    // converts <count_of_bits> separate bits into a single "byte"
    uint8_t byte = 0;
    for (int i = 0; i < count_of_bits; i++) {
        byte <<= 1;
        byte |= bits[i];
    }

    return byte;
}

/**
 * em4x70_read_id
 *
 *  read pre-programmed ID (4 bytes)
 */
static bool em4x70_read_id(void) {
    em4x70_command_bitstream_t read_id_cmd;
    const em4x70_command_generators_t * generator = &legacy_em4x70_command_generators;
    generator->id(&read_id_cmd, command_parity);

    bool result = send_bitstream_and_read(&read_id_cmd);
    if (result) {
        encoded_bit_array_to_bytes(read_id_cmd.to_receive.one_bit_per_byte, read_id_cmd.to_receive.bitcount, &tag.data[4]);
    }
    return result;
}

/**
 *  em4x70_read_um1
 *
 *  read user memory 1 (4 bytes including lock bits)
 */
static bool em4x70_read_um1(void) {
    em4x70_command_bitstream_t read_um1_cmd;
    const em4x70_command_generators_t * generator = &legacy_em4x70_command_generators;
    generator->um1(&read_um1_cmd, command_parity);

    bool result = send_bitstream_and_read(&read_um1_cmd);
    if (result) {
        encoded_bit_array_to_bytes(read_um1_cmd.to_receive.one_bit_per_byte, read_um1_cmd.to_receive.bitcount, &tag.data[0]);
    }

    bitstream_dump(&read_um1_cmd);
    return result;
}

/**
 *  em4x70_read_um2
 *
 *  read user memory 2 (8 bytes)
 */
static bool em4x70_read_um2(void) {
    em4x70_command_bitstream_t read_um2_cmd;
    const em4x70_command_generators_t * generator = &legacy_em4x70_command_generators;
    generator->um2(&read_um2_cmd, command_parity);

    bool result = send_bitstream_and_read(&read_um2_cmd);
    if (result) {
        encoded_bit_array_to_bytes(read_um2_cmd.to_receive.one_bit_per_byte, read_um2_cmd.to_receive.bitcount, &tag.data[24]);
    }


    bitstream_dump(&read_um2_cmd);
    return result;
}
static bool find_em4x70_tag(void) {
    // function is used to check whether a tag on the proxmark is an
    // EM4x70 tag or not -> speed up "lf search" process
    return find_listen_window(false);
}

// This is the ONLY function that receives data from the tag
static int em4x70_receive(uint8_t *bits, size_t maximum_bits_to_read) {

    uint32_t pl;
    int bit_pos = 0;
    edge_detection_t edge = RISING_EDGE;
    bool foundheader = false;

    // Read out the header
    //   12 Manchester 1's (may miss some during settle period)
    //    4 Manchester 0's

    // Skip about half of the leading 1's as signal could start off noisy
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

    // Skip next 3 0's, (the header check above consumed the first 0)
    for (int i = 0; i < 3; i++) {
        // If pulse length is not 1 bit, then abort early
        if (!check_pulse_length(get_pulse_length(edge), EM4X70_T_TAG_FULL_PERIOD)) {
            return 0;
        }
    }
    log_received_bit_start(GetTicks());

    // identify remaining bits based on pulse lengths
    // between listen windows only pulse lengths of 1, 1.5 and 2 are possible
    while (bit_pos < maximum_bits_to_read) {

        pl = get_pulse_length(edge);

        if (check_pulse_length(pl, EM4X70_T_TAG_FULL_PERIOD)) {

            // pulse length 1 -> assign bit
            bits[bit_pos++] = edge == FALLING_EDGE ? 1 : 0;

        } else if (check_pulse_length(pl, 3 * EM4X70_T_TAG_HALF_PERIOD)) {

            // pulse length 1.5 -> 2 bits + flip edge detection
            if (edge == FALLING_EDGE) {
                bits[bit_pos++] = 0;
                if (bit_pos < maximum_bits_to_read) {
                    bits[bit_pos++] = 0;
                }
                edge = RISING_EDGE;
            } else {
                bits[bit_pos++] = 1;
                if (bit_pos < maximum_bits_to_read) {
                    bits[bit_pos++] = 1;
                }
                edge = FALLING_EDGE;
            }

        } else if (check_pulse_length(pl, 2 * EM4X70_T_TAG_FULL_PERIOD)) {

            // pulse length of 2 -> two bits
            if (edge == FALLING_EDGE) {
                bits[bit_pos++] = 0;
                if (bit_pos < maximum_bits_to_read) {
                    bits[bit_pos++] = 1;
                }
            } else {
                bits[bit_pos++] = 1;
                if (bit_pos < maximum_bits_to_read) {
                    bits[bit_pos++] = 0;
                }
            }

        } else {
            // Listen Window, or invalid bit
            break;
        }
    }
    log_received_bit_end(GetTicks());
    log_received_bits(bits, bit_pos);

    return bit_pos;
}

// CLIENT ENTRY POINTS
void em4x70_info(const em4x70_data_t *etd, bool ledcontrol) {

    bool success = false;
    bool success_with_UM2 = false;

    // Support tags with and without command parity bits
    command_parity = etd->parity;

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {
        // Read ID and UM1 (both em4070 and em4170)
        success = em4x70_read_id() && em4x70_read_um1();
        // em4170 also has UM2, V4070 does not (e.g., 1998 Porsche Boxster)
        success_with_UM2 = em4x70_read_um2();
    }

    StopTicks();
    lf_finalize(ledcontrol);
    int status = success ? PM3_SUCCESS : PM3_ESOFT;
    size_t data_size =
        success && success_with_UM2 ? 32 :
        success ? 20 :
        0;

    // not returning the data to the client about actual length read?
    reply_ng(CMD_LF_EM4X70_INFO, status, tag.data, data_size);
}

void em4x70_write(const em4x70_data_t *etd, bool ledcontrol) {
    int status = PM3_ESOFT;

    command_parity = etd->parity;

    // Disable to prevent sending corrupted data to the tag.
    if (command_parity) {
        DPRINTF_ALWAYS(("Use of `--par` option with `lf em 4x70 write` is  non-functional and may corrupt data on the tag."));
        // reply_ng(CMD_LF_EM4X70_WRITE, PM3_ENOTIMPL, NULL, 0);
        // return;
    }

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Write
        status = write(etd->word, etd->address);

        if (status == PM3_SUCCESS) {
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

    int status = PM3_ESOFT;

    command_parity = etd->parity;

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Read ID (required for send_pin command)
        if (em4x70_read_id()) {

            // Send PIN
            status = send_pin(etd->pin);

            // If the write succeeded, read the rest of the tag
            if (status == PM3_SUCCESS) {
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

    int status = PM3_ESOFT;

    uint8_t response[3] = {0};

    command_parity = etd->parity;

    // Disable to prevent sending corrupted data to the tag.
    if (command_parity) {
        DPRINTF_ALWAYS(("Use of `--par` option with `lf em 4x70 auth` is  non-functional."));
        // reply_ng(CMD_LF_EM4X70_WRITE, PM3_ENOTIMPL, NULL, 0);
        // return;
    }

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Authenticate and get tag response
        status = authenticate(etd->rnd, etd->frnd, response);
    }

    StopTicks();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X70_AUTH, status, response, sizeof(response));
}

void em4x70_brute(const em4x70_data_t *etd, bool ledcontrol) {
    int status = PM3_ESOFT;
    uint8_t response[2] = {0};

    command_parity = etd->parity;

    // Disable to prevent sending corrupted data to the tag.
    if (command_parity) {
        DPRINTF_ALWAYS(("Use of `--par` option with `lf em 4x70 brute` is  non-functional and may corrupt data on the tag."));
        // reply_ng(CMD_LF_EM4X70_WRITE, PM3_ENOTIMPL, NULL, 0);
        // return;
    }

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Bruteforce partial key
        status = bruteforce(etd->address, etd->rnd, etd->frnd, etd->start_key, response);
    }

    StopTicks();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X70_BRUTE, status, response, sizeof(response));
}

void em4x70_write_pin(const em4x70_data_t *etd, bool ledcontrol) {

    int status = PM3_ESOFT;

    command_parity = etd->parity;

    // Disable to prevent sending corrupted data to the tag.
    if (command_parity) {
        DPRINTF_ALWAYS(("Use of `--par` option with `lf em 4x70 setpin` is non-functional and may corrupt data on the tag."));
        // reply_ng(CMD_LF_EM4X70_WRITE, PM3_ENOTIMPL, NULL, 0);
        // return;
    }

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Read ID (required for send_pin command)
        if (em4x70_read_id()) {

            // Write the pin
            status = write((etd->pin) & 0xFFFF, EM4X70_PIN_WORD_UPPER);
            if (status == PM3_SUCCESS) {
                status = write((etd->pin >> 16) & 0xFFFF, EM4X70_PIN_WORD_LOWER);
            }
            if (status == PM3_SUCCESS) {
                // Now Try to authenticate using the new PIN

                // Send PIN
                status = send_pin(etd->pin);

                // If the write succeeded, read the rest of the tag
                if (status == PM3_SUCCESS) {
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
    reply_ng(CMD_LF_EM4X70_SETPIN, status, tag.data, sizeof(tag.data));
}

void em4x70_write_key(const em4x70_data_t *etd, bool ledcontrol) {

    int status = PM3_ESOFT;

    command_parity = etd->parity;

    // Disable to prevent sending corrupted data to the tag.
    if (command_parity) {
        DPRINTF_ALWAYS(("Use of `--par` option with `lf em 4x70 setkey` is non-functional and may corrupt data on the tag."));
        // reply_ng(CMD_LF_EM4X70_WRITE, PM3_ENOTIMPL, NULL, 0);
        // return;
    }

    init_tag();
    em4x70_setup_read();

    // Find the Tag
    if (get_signalproperties() && find_em4x70_tag()) {

        // Read ID to ensure we can write to card
        if (em4x70_read_id()) {
            status = PM3_SUCCESS;

            // Write each crypto block
            for (int i = 0; i < 6; i++) {

                uint16_t key_word = (etd->crypt_key[(i * 2) + 1] << 8) + etd->crypt_key[i * 2];
                // Write each word, abort if any failure occurs
                status = write(key_word, 9 - i);
                if (status != PM3_SUCCESS) {
                    break;
                }
            }
            // The client now has support for test authentication after
            // writing a new key, thus allowing to verify that the new
            // key was written correctly.  This is what the datasheet
            // suggests.   Not currently implemented in the firmware.
            // ID48LIB has no dependencies that would prevent this from
            // being implemented directly within the firmware layer...
        }
    }

    StopTicks();
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_EM4X70_SETKEY, status, tag.data, sizeof(tag.data));
}
