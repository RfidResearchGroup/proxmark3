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

#include "hitag2.h"
#include "hitag2/hitag2_crypto.h"
#include "string.h"
#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "util.h"
#include "lfadc.h"
#include "lfsampling.h"
#include "lfdemod.h"
#include "commonutil.h"
#include "appmain.h"
#include "protocols.h"

#define test_bit(data, i)  (*(data + (i/8)) >> (7-(i % 8))) & 1
#define set_bit(data, i)   *(data + (i/8)) |= (1 << (7-(i % 8)))
#define clear_bit(data, i) *(data + (i/8)) &= ~(1 << (7-(i % 8)))
#define flip_bit(data, i)  *(data + (i/8)) ^= (1 << (7-(i % 8)))

// Successful crypto auth
static bool bCrypto;
// Is in auth stage
static bool bAuthenticating;
// Successful password auth
static bool bSelecting;
static bool bCollision;
static bool bPwd;
static bool bSuccessful;

/*
Password Mode : 0x06 - 0000 0110
Crypto Mode   : 0x0E - 0000 1110
Public Mode A : 0x02 - 0000 0010
Public Mode B : 0x00 - 0000 0000
Public Mode C : 0x04 - 0000 0100
*/

static hitag2_t tag = {
    .state = TAG_STATE_RESET,
    .sectors = {                          // Password mode:               | Crypto mode:
        [0]  = { 0x02, 0x4e, 0x02, 0x20}, // UID                          | UID
        [1]  = { 0x4d, 0x49, 0x4b, 0x52}, // Password RWD                 | 32 bit LSB key
        [2]  = { 0x20, 0xf0, 0x4f, 0x4e}, // Reserved                     | 16 bit MSB key, 16 bit reserved
        [3]  = { 0x06, 0xaa, 0x48, 0x54}, // Configuration, password TAG  | Configuration, password TAG
        [4]  = { 0x46, 0x5f, 0x4f, 0x4b}, // Data: F_OK
        [5]  = { 0x55, 0x55, 0x55, 0x55}, // Data: UUUU
        [6]  = { 0xaa, 0xaa, 0xaa, 0xaa}, // Data: ....
        [7]  = { 0x55, 0x55, 0x55, 0x55}, // Data: UUUU
        [8]  = { 0x00, 0x00, 0x00, 0x00}, // RSK Low
        [9]  = { 0x00, 0x00, 0x00, 0x00}, // RSK High
        [10] = { 0x00, 0x00, 0x00, 0x00}, // RCF
        [11] = { 0x00, 0x00, 0x00, 0x00}, // SYNC
        // up to index 15 reserved for HITAG 1/HITAG S public data
    },
};

static enum {
    WRITE_STATE_START = 0x0,
    WRITE_STATE_PAGENUM_WRITTEN,
    WRITE_STATE_PROG
} writestate;

// ToDo: define a meaningful maximum size for auth_table. The bigger this is, the lower will be the available memory for traces.
// Historically it used to be FREE_BUFFER_SIZE, which was 2744.
#define AUTH_TABLE_LENGTH 2744
static uint8_t *auth_table;
static size_t auth_table_pos = 0;
static size_t auth_table_len = AUTH_TABLE_LENGTH;

static uint8_t password[4];
static uint8_t NrAr[8];
static uint8_t key[8];
static uint8_t writedata[4];
static uint8_t logdata_0[4], logdata_1[4];
static uint8_t nonce[4];
static uint8_t key_no;
static uint64_t cipher_state;

static int16_t blocknr;
static size_t flipped_bit = 0;
static uint32_t byte_value = 0;

static void hitag2_reset(void) {
    tag.state = TAG_STATE_RESET;
    tag.crypto_active = 0;
}

static void hitag2_init(void) {
    hitag2_reset();
}

// Sam7s has several timers, we will use the source TIMER_CLOCK1 (aka AT91C_TC_CLKS_TIMER_DIV1_CLOCK)
// TIMER_CLOCK1 = MCK/2, MCK is running at 48 MHz, Timer is running at 48/2 = 24 MHz
// Hitag units (T0) have duration of 8 microseconds (us), which is 1/125000 per second (carrier)
// T0 = TIMER_CLOCK1 / 125000 = 192
#ifndef HITAG_T0
#define HITAG_T0               192
#endif

#define HITAG_FRAME_LEN  20
#define HITAG_FRAME_BIT_COUNT   (8 * HITAG_FRAME_LEN)
#define HITAG_T_STOP     36 /* T_EOF should be > 36 */
#define HITAG_T_LOW      6  /* T_LOW should be 4..10 */
#define HITAG_T_0_MIN    15 /* T[0] should be 18..22 */
#define HITAG_T_0        20 /* T[0] should be 18..22 */
#define HITAG_T_1_MIN    25 /* T[1] should be 26..30 */
#define HITAG_T_1        30 /* T[1] should be 26..30 */
#define HITAG_T_EOF      80 /* T_EOF should be > 36    and must be larger than HITAG_T_TAG_CAPTURE_FOUR_HALF */
#define HITAG_T_WAIT_1_MIN   199 /* T_wresp should be 199..206 */
#define HITAG_T_WAIT_2_MIN   90 /* T_wait2 should be at least 90 */
#define HITAG_T_WAIT_MAX 300 /* bit more than HITAG_T_WAIT_1 + HITAG_T_WAIT_2 */
#define HITAG_T_PROG     614
#define HITAG_T_WAIT_POWERUP   313 /* transponder internal powerup time is 312.5 */
#define HITAG_T_WAIT_START_AUTH_MAX   232 /* transponder waiting time to receive the START_AUTH command is 232.5, then it enters public mode */

#define HITAG_T_TAG_ONE_HALF_PERIOD     10
#define HITAG_T_TAG_TWO_HALF_PERIOD     25
#define HITAG_T_TAG_THREE_HALF_PERIOD   41
#define HITAG_T_TAG_FOUR_HALF_PERIOD    57

#define HITAG_T_TAG_HALF_PERIOD         16
#define HITAG_T_TAG_FULL_PERIOD         32

#define HITAG_T_TAG_CAPTURE_ONE_HALF    13
#define HITAG_T_TAG_CAPTURE_TWO_HALF    25
#define HITAG_T_TAG_CAPTURE_THREE_HALF  41
#define HITAG_T_TAG_CAPTURE_FOUR_HALF   57

#define HT2_MAX_NRSZ  ((8 * HITAG_FRAME_LEN + 5) * 2)

/*
// sim
static void hitag_send_bit(int bit, bool ledcontrol) {
    if (ledcontrol) LED_A_ON();

    // Reset clock for the next bit
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

    // Fixed modulation, earlier proxmark version used inverted signal
    // check datasheet if reader uses BiPhase?
    if (bit == 0) {
        // Manchester: Unloaded, then loaded |__--|
        LOW(GPIO_SSC_DOUT);
        while (AT91C_BASE_TC0->TC_CV < HITAG_T0 * HITAG_T_TAG_HALF_PERIOD);
        HIGH(GPIO_SSC_DOUT);
        while (AT91C_BASE_TC0->TC_CV < HITAG_T0 * HITAG_T_TAG_FULL_PERIOD);
    } else {
        // Manchester: Loaded, then unloaded |--__|
        HIGH(GPIO_SSC_DOUT);
        while (AT91C_BASE_TC0->TC_CV < HITAG_T0 * HITAG_T_TAG_HALF_PERIOD);
        LOW(GPIO_SSC_DOUT);
        while (AT91C_BASE_TC0->TC_CV < HITAG_T0 * HITAG_T_TAG_FULL_PERIOD);
    }
    if (ledcontrol) LED_A_OFF();
}

// sim
static void hitag_send_frame(const uint8_t *frame, size_t frame_len) {
    // SOF - send start of frame
    hitag_send_bit(1);
    hitag_send_bit(1);
    hitag_send_bit(1);
    hitag_send_bit(1);
    hitag_send_bit(1);

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        hitag_send_bit((frame[i / 8] >> (7 - (i % 8))) & 1);
    }

    // Drop the modulation
    LOW(GPIO_SSC_DOUT);
}
*/

// sim
static void hitag2_handle_reader_command(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen) {
    uint8_t rx_air[HITAG_FRAME_LEN];

    // Copy the (original) received frame how it is send over the air
    memcpy(rx_air, rx, nbytes(rxlen));

    if (tag.crypto_active) {
        ht2_hitag2_cipher_transcrypt(&(tag.cs), rx, rxlen / 8, rxlen % 8);
    }

    // Reset the transmission frame length
    *txlen = 0;

    // Try to find out which command was send by selecting on length (in bits)
    switch (rxlen) {
        // Received 11000 from the reader, request for UID, send UID
        case 5: {
            // Always send over the air in the clear plaintext mode
            if (rx_air[0] != HITAG2_START_AUTH) {
                // Unknown frame ?
                return;
            }
            *txlen = 32;
            memcpy(tx, tag.sectors[0], 4);
            tag.crypto_active = 0;
        }
        break;

        // Read/Write command: ..xx x..y  yy with yyy == ~xxx, xxx is sector number
        case 10: {
            uint16_t sector = (~(((rx[0] << 2) & 0x04) | ((rx[1] >> 6) & 0x03)) & 0x07);

            // Verify complement of sector index
            if (sector != ((rx[0] >> 3) & 0x07)) {
                DBG DbpString("Transmission error (read/write)");
                return;
            }

            switch (rx[0] & 0xC6) {
                // Read command: 11xx x00y
                case HITAG2_READ_PAGE: {
                    memcpy(tx, tag.sectors[sector], 4);
                    *txlen = 32;
                    break;
                }
                // Inverted Read command: 01xx x10y
                case HITAG2_READ_PAGE_INVERTED: {
                    for (size_t i = 0; i < 4; i++) {
                        tx[i] = tag.sectors[sector][i] ^ 0xff;
                    }
                    *txlen = 32;
                    break;
                }
                // Write command: 10xx x01y
                case HITAG2_WRITE_PAGE: {
                    // Prepare write, acknowledge by repeating command
                    memcpy(tx, rx, nbytes(rxlen));
                    *txlen = rxlen;
                    tag.active_sector = sector;
                    tag.state = TAG_STATE_WRITING;
                    break;
                }
                // Unknown command
                default: {
                    DBG Dbprintf("Unknown command: %02x %02x", rx[0], rx[1]);
                    return;
                }
            }
        }
        break;

        // Writing data or Reader password
        case 32: {
            if (tag.state == TAG_STATE_WRITING) {
                // These are the sector contents to be written. We don't have to do anything else.
                memcpy(tag.sectors[tag.active_sector], rx, nbytes(rxlen));
                tag.state = TAG_STATE_RESET;
                return;
            } else {
                // Received RWD password, respond with configuration and our password
                if (memcmp(rx, tag.sectors[1], 4) != 0) {
                    DBG DbpString("Reader password is wrong");
                    return;
                }
                *txlen = 32;
                memcpy(tx, tag.sectors[3], 4);
            }
        }
        break;

        // Received RWD authentication challenge and response
        case 64: {
            // Store the authentication attempt
            if (auth_table_len < (AUTH_TABLE_LENGTH - 8)) {
                memcpy(auth_table + auth_table_len, rx, 8);
                auth_table_len += 8;
            }

            // Reset the cipher state
            ht2_hitag2_cipher_reset(&tag, rx);

            // Check if the authentication was correct
            if (!ht2_hitag2_cipher_authenticate(&(tag.cs), rx + 4)) {
                // The reader failed to authenticate, do nothing
                DBG Dbprintf("auth: %02x%02x%02x%02x%02x%02x%02x%02x Failed!", rx[0], rx[1], rx[2], rx[3], rx[4], rx[5], rx[6], rx[7]);
                return;
            }
            // Activate encryption algorithm for all further communication
            tag.crypto_active = 1;

            // Use the tag password as response
            memcpy(tx, tag.sectors[3], 4);
            *txlen = 32;
        }
        break;
    }

    // LogTraceBits(rx, rxlen, 0, 0, false);
    // LogTraceBits(tx, txlen, 0, 0, true);

    if (tag.crypto_active) {
        ht2_hitag2_cipher_transcrypt(&(tag.cs), tx, *txlen / 8, *txlen % 8);
    }
}

// reader/writer
// returns how long it took
static uint32_t hitag_reader_send_bit(int bit) {
    // Binary pulse length modulation (BPLM) is used to encode the data stream
    // This means that a transmission of a one takes longer than that of a zero

    // Enable modulation, which means, drop the field
    lf_modulation(true);

    // Wait for 4-10 times the carrier period
    lf_wait_periods(HITAG_T_LOW); // wait for 4-10 times the carrier period
    uint32_t wait = HITAG_T_LOW;

    // Disable modulation, just activates the field again
    lf_modulation(false);

    if (bit == 0) {
        // Zero bit: |_-|
        lf_wait_periods(HITAG_T_0 - HITAG_T_LOW); // wait for 18-22 times the carrier period
        wait += HITAG_T_0 - HITAG_T_LOW;
    } else {
        // One bit: |_--|
        lf_wait_periods(HITAG_T_1 - HITAG_T_LOW); // wait for 26-32 times the carrier period
        wait += HITAG_T_1 - HITAG_T_LOW;
    }

    return wait;
}

// reader / writer commands
// frame_len is in number of bits?
static uint32_t hitag_reader_send_frame(const uint8_t *frame, size_t frame_len) {
    WDT_HIT();

    uint32_t wait = 0;
    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        wait += hitag_reader_send_bit((frame[i / 8] >> (7 - (i % 8))) & 1);
    }

    // Send EOF
    // Enable modulation, which means, drop the field
    lf_modulation(true);

    // Wait for 4-10 times the carrier period
    lf_wait_periods(HITAG_T_LOW);
    wait += HITAG_T_LOW;

    // Disable modulation, just activates the field again
    lf_modulation(false);

    // t_stop, high field for stop condition (> 36)
    lf_wait_periods(HITAG_T_STOP);
    wait += HITAG_T_STOP;
    WDT_HIT();
    return wait;
}

// reader / writer commands
// frame_len is in number of bits?
static uint32_t hitag_reader_send_framebits(const uint8_t *frame, size_t frame_len) {

    WDT_HIT();

    uint32_t wait = 0;
    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        wait += hitag_reader_send_bit(frame[i]);
    }

    // Send EOF
    // Enable modulation, which means, drop the field
    // set GPIO_SSC_DOUT to HIGH
    lf_modulation(true);

    // Wait for 4-10 times the carrier period
    lf_wait_periods(HITAG_T_LOW);
    wait += HITAG_T_LOW;

    // Disable modulation, just activates the field again
    // set GPIO_SSC_DOUT to LOW
    lf_modulation(false);

    // t_stop, high field for stop condition (> 36)
    lf_wait_periods(HITAG_T_STOP);
    wait += HITAG_T_STOP;

    WDT_HIT();
    return wait;
}

static uint8_t hitag_crc(uint8_t *data, size_t n) {
    uint8_t crc = 0xFF;
    for (size_t i = 0; i < ((n + 7) / 8); i++) {
        crc ^= *(data + i);
        uint8_t bit = n < (8 * (i + 1)) ? (n % 8) : 8;
        while (bit--) {
            if (crc & 0x80) {
                crc <<= 1;
                crc ^= 0x1D;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

/*
void fix_ac_decoding(uint8_t *input, size_t len) {
    // Reader routine tries to decode AC data after Manchester decoding
    // AC has double the bitrate, extract data from bit-pairs
    uint8_t temp[len / 16];
    memset(temp, 0, sizeof(temp));

    for (size_t i = 1; i < len; i += 2) {
        if (test_bit(input, i) && test_bit(input, (i + 1))) {
            set_bit(temp, (i / 2));
        }
    }
    memcpy(input, temp, sizeof(temp));
}
*/


// looks at number of received bits.
// 0 = collision?
// 32 =  good response
static bool hitag1_plain(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen, bool hitag_s) {
    *txlen = 0;
    switch (rxlen) {
        case 0: {
            // retry waking up card
            /*tx[0] = 0xb0; // Rev 3.0*/
            tx[0] = HITAG1_SET_CC; // Rev 2.0
            *txlen = 5;
            if (!bCollision) blocknr--;
            if (blocknr < 0) {
                blocknr = 0;
            }
            if (!hitag_s) {
                if (blocknr > 1 && blocknr < 31) {
                    blocknr = 31;
                }
            }
            bCollision = true;
            return true;
        }
        case 32: {
            uint8_t crc;
            if (bCollision) {
                // Select card by serial from response
                tx[0] = HITAG1_SELECT | rx[0] >> 5;
                tx[1] = rx[0] << 3 | rx[1] >> 5;
                tx[2] = rx[1] << 3 | rx[2] >> 5;
                tx[3] = rx[2] << 3 | rx[3] >> 5;
                tx[4] = rx[3] << 3;
                crc = hitag_crc(tx, 37);
                tx[4] |= crc >> 5;
                tx[5] = crc << 3;
                *txlen = 45;
                bCollision = false;
            } else {
                memcpy(tag.sectors[blocknr], rx, 4);
                blocknr++;
                if (!hitag_s) {
                    if (blocknr > 1 && blocknr < 31) {
                        blocknr = 31;
                    }
                }
                if (blocknr > 63) {
                    DbpString("Read successful!");
                    *txlen = 0;
                    bSuccessful = true;
                    return false;
                }
                // read next page of card until done
                Dbprintf("Reading page %02u", blocknr);
                tx[0] = HITAG1_RDPPAGE | blocknr >> 4; // RDPPAGE
                tx[1] = blocknr << 4;
                crc = hitag_crc(tx, 12);
                tx[1] |= crc >> 4;
                tx[2] = crc << 4;
                *txlen = 20;
            }
        }
        break;
        default: {
            Dbprintf("Unknown frame length: %d", rxlen);
            return false;
        }
        break;
    }
    return true;
}


static bool hitag1_authenticate(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen) {
    uint8_t crc;
    *txlen = 0;
    switch (rxlen) {
        case 0: {
            // retry waking up card
            /*tx[0] = 0xb0; // Rev 3.0*/
            tx[0] = HITAG1_SELECT; // Rev 2.0
            *txlen = 5;
            if (bCrypto && byte_value <= 0xff) {
                // to retry
                bCrypto = false;
            }
            if (!bCollision) blocknr--;
            if (blocknr < 0) {
                blocknr = 0;
            }
            bCollision = true;
            // will receive 32-bit UID
        }
        break;
        case 2: {
            if (bAuthenticating) {
                // received Auth init ACK, send nonce
                // TODO Roel, bit-manipulation goes here
                /*nonce[0] = 0x2d;*/
                /*nonce[1] = 0x74;*/
                /*nonce[2] = 0x80;*/
                /*nonce[3] = 0xa5;*/
                nonce[0] = byte_value;
                byte_value++;
                /*set_bit(nonce,flipped_bit);*/
                memcpy(tx, nonce, 4);
                *txlen = 32;
                // will receive 32 bit encrypted Logdata
            } else if (bCrypto) {
                // authed, start reading
                tx[0] = HITAG1_RDCPAGE | blocknr >> 4; // RDCPAGE
                tx[1] = blocknr << 4;
                crc = hitag_crc(tx, 12);
                tx[1] |= crc >> 4;
                tx[2] = crc << 4;
                *txlen = 20;
                // will receive 32-bit encrypted page
            }
        }
        break;
        case 32: {
            if (bCollision) {
                // Select card by serial from response
                tx[0] = HITAG1_SELECT | rx[0] >> 5;
                tx[1] = rx[0] << 3 | rx[1] >> 5;
                tx[2] = rx[1] << 3 | rx[2] >> 5;
                tx[3] = rx[2] << 3 | rx[3] >> 5;
                tx[4] = rx[3] << 3;
                crc = hitag_crc(tx, 37);
                tx[4] |= crc >> 5;
                tx[5] = crc << 3;
                *txlen = 45;
                bCollision = false;
                bSelecting = true;
                // will receive 32-bit configuration page
            } else if (bSelecting) {
                // Initiate auth
                tx[0] = HITAG1_WRCPAGE | (key_no); // WRCPAGE
                tx[1] = blocknr << 4;
                crc = hitag_crc(tx, 12);
                tx[1] |= crc >> 4;
                tx[2] = crc << 4;
                *txlen = 20;
                bSelecting = false;
                bAuthenticating = true;
                // will receive 2-bit ACK
            } else if (bAuthenticating) {
                // received 32-bit logdata 0
                // TODO decrypt logdata 0, verify against logdata_0
                memcpy(tag.sectors[0], rx, 4);
                memcpy(tag.sectors[1], tx, 4);
                Dbprintf("%02x%02x%02x%02x %02x%02x%02x%02x", rx[0], rx[1], rx[2], rx[3], tx[0], tx[1], tx[2], tx[3]);
                // TODO replace with secret data stream
                // TODO encrypt logdata_1
                memcpy(tx, logdata_1, 4);
                *txlen = 32;
                bAuthenticating = false;
                bCrypto = true;
                // will receive 2-bit ACK
            } else if (bCrypto) {
                // received 32-bit encrypted page
                // TODO decrypt rx
                memcpy(tag.sectors[blocknr], rx, 4);
                blocknr++;
                if (blocknr > 63) {
                    DbpString("Read successful!");
                    bSuccessful = true;
                    return false;
                }

                // TEST
                Dbprintf("Successfully authenticated with logdata:");
                Dbhexdump(4, logdata_1, false);
                bSuccessful = true;
                return false;
                /*
                                // read next page of card until done
                                tx[0] = HITAG1_RDCPAGE | blocknr >> 4; // RDCPAGE
                                tx[1] = blocknr << 4;
                                crc = hitag_crc(tx, 12);
                                tx[1] |= crc >> 4;
                                tx[2] = crc << 4;
                                *txlen = 20;
                */
            }
        }
        break;
        default: {
            Dbprintf("Unknown frame length: %d", rxlen);
            return false;
        }
        break;
    }

    return true;
}

//-----------------------------------------------------------------------------
// Hitag 2 operations
//-----------------------------------------------------------------------------

static bool hitag2_write_page(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen) {
    switch (writestate) {
        case WRITE_STATE_START: {
            *txlen = 10;
            tx[0] = HITAG2_WRITE_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2);
            tx[1] = ((blocknr ^ 7) << 6);
            writestate = WRITE_STATE_PAGENUM_WRITTEN;
            break;
        }
        case WRITE_STATE_PAGENUM_WRITTEN: {
            // Check if page number was received correctly
            if ((rxlen == 10)
                    && (rx[0] == (HITAG2_WRITE_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2)))
                    && (rx[1] == (((blocknr & 0x3) ^ 0x3) << 6))) {

                *txlen = 32;
                memset(tx, 0, HITAG_FRAME_LEN);
                memcpy(tx, writedata, 4);
                writestate = WRITE_STATE_PROG;
            } else {
                Dbprintf("hitag2_write_page: Page number was not received correctly: rxlen %d rx %02x%02x%02x%02x"
                         , rxlen
                         , rx[0], rx[1], rx[2], rx[3]
                        );
                bSuccessful = false;
                return false;
            }
            break;
        }
        case WRITE_STATE_PROG: {
            if (rxlen == 0) {
                bSuccessful = true;
            } else {
                bSuccessful = false;
                Dbprintf("hitag2_write_page: unexpected rx data (%d) after page write", rxlen);
            }
            return false;
        }
        default: {
            Dbprintf("hitag2_write_page: Unknown state " _RED_("%d"), writestate);
            bSuccessful = false;
            return false;
        }
    }
    return true;
}

static bool hitag2_password(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen, bool write) {
    // Reset the transmission frame length
    *txlen = 0;

    if (bPwd && (bAuthenticating == false) && write) {

        SpinDelay(2);
        if (hitag2_write_page(rx, rxlen, tx, txlen) == false) {
            return false;
        }

    } else {
        // Try to find out which command was send by selecting on length (in bits)
        switch (rxlen) {
            // No answer, try to resurrect
            case 0: {
                // Stop if there is no answer (after sending password)
                if (bPwd) {
                    DBG DbpString("Password failed!");
                    return false;
                }
                *txlen = 5;
                memcpy(tx, "\xC0", nbytes(*txlen));
            }
            break;

            // Received UID, tag password
            case 32: {
                // stage 1, got UID
                if (bPwd == false) {
                    bPwd = true;
                    bAuthenticating = true;
                    memcpy(tx, password, 4);
                    *txlen = 32;
                } else {
                    // stage 2, got config byte+password TAG, discard as will read later
                    if (bAuthenticating) {
                        bAuthenticating = false;
                        if (write) {
                            if (!hitag2_write_page(rx, rxlen, tx, txlen)) {
                                return false;
                            }
                            break;
                        }
                    }
                    // stage 2+, got data block
                    else {
                        memcpy(tag.sectors[blocknr], rx, 4);
                        blocknr++;
                    }

                    if (blocknr > 7) {
                        bSuccessful = true;
                        return false;
                    }

                    *txlen = 10;
                    tx[0] = HITAG2_READ_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2);
                    tx[1] = ((blocknr ^ 7) << 6);
                }
            }
            break;

            // Unexpected response
            default: {
                DBG Dbprintf("Unknown frame length: " _RED_("%d"), rxlen);
                return false;
            }
            break;
        }
    }

    return true;
}

static bool hitag2_crypto(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen, bool write) {
    // Reset the transmission frame length
    *txlen = 0;

    if (bCrypto) {
        ht2_hitag2_cipher_transcrypt(&cipher_state, rx, rxlen / 8, rxlen % 8);
    }

    if (bCrypto && (bAuthenticating == false) && write) {

        SpinDelay(2);
        if (hitag2_write_page(rx, rxlen, tx, txlen) == false) {
            return false;
        }

    } else {

        // Try to find out which command was send by selecting on length (in bits)
        switch (rxlen) {
            // No answer, try to resurrect
            case 0: {
                // Stop if there is no answer while we are in crypto mode (after sending NrAr)
                if (bCrypto) {
                    // Failed during authentication
                    if (bAuthenticating) {
                        DBG DbpString("Authentication failed!");
                        return false;
                    } else {
                        // Failed reading a block, could be (read/write) locked, skip block and re-authenticate
                        if (blocknr == 1) {
                            // Write the low part of the key in memory
                            memcpy(tag.sectors[1], key + 2, 4);
                        } else if (blocknr == 2) {
                            // Write the high part of the key in memory
                            tag.sectors[2][0] = 0x00;
                            tag.sectors[2][1] = 0x00;
                            tag.sectors[2][2] = key[0];
                            tag.sectors[2][3] = key[1];
                        } else {
                            // Just put zero's in the memory (of the unreadable block)
                            memset(tag.sectors[blocknr], 0x00, 4);
                        }
                        blocknr++;
                        bCrypto = false;
                    }
                } else {
                    *txlen = 5;
                    memcpy(tx, "\xc0", nbytes(*txlen));
                }
                break;
            }
            // Received UID, crypto tag answer
            case 32: {
                // stage 1, got UID
                if (bCrypto == false) {

                    DBG Dbprintf("hitag2_crypto: key array ");
                    DBG Dbhexdump(6, key, false);

                    uint64_t ui64key = key[0] | ((uint64_t)key[1]) << 8 | ((uint64_t)key[2]) << 16 | ((uint64_t)key[3]) << 24 | ((uint64_t)key[4]) << 32 | ((uint64_t)key[5]) << 40;

                    uint32_t ui32uid = rx[0] | ((uint32_t)rx[1]) << 8 | ((uint32_t)rx[2]) << 16 | ((uint32_t)rx[3]) << 24;
                    DBG Dbprintf("hitag2_crypto: key=0x%x%x uid=0x%x"
                                 , (uint32_t)((REV64(ui64key)) >> 32)
                                 , (uint32_t)((REV64(ui64key)) & 0xffffffff)
                                 , REV32(ui32uid)
                                );

                    cipher_state = ht2_hitag2_init(REV64(ui64key), REV32(ui32uid), 0);

                    // PRN  00 00 00 00
                    memset(tx, 0x00, 4);
                    // Secret data FF FF FF FF
                    memset(tx + 4, 0xff, 4);
                    ht2_hitag2_cipher_transcrypt(&cipher_state, tx + 4, 4, 0);
                    *txlen = 64;
                    bCrypto = true;
                    bAuthenticating = true;
                } else {

                    // stage 2, got config byte+password TAG, discard as will read later
                    if (bAuthenticating) {

                        bAuthenticating = false;

                        if (write) {
                            if (hitag2_write_page(rx, rxlen, tx, txlen) == false) {
                                return false;
                            }
                            break;
                        }

                    } else { // stage 2+, got data block

                        // Store the received block
                        memcpy(tag.sectors[blocknr], rx, 4);
                        blocknr++;
                    }

                    if (blocknr > 7) {
                        DBG DbpString("Read successful!");
                        bSuccessful = true;
                        return false;
                    } else {
                        *txlen = 10;
                        tx[0] = HITAG2_READ_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2);
                        tx[1] = ((blocknr ^ 7) << 6);
                    }
                }
                break;
            }
            default: {
                DBG Dbprintf("Unknown frame length: " _RED_("%d"), rxlen);
                return false;
            }
        }
    }

    // try to avoid double encryption calls
    if (bCrypto && bAuthenticating == false) {
        ht2_hitag2_cipher_transcrypt(&cipher_state, tx, *txlen / 8, *txlen % 8);
    }

    return true;
}

static bool hitag2_authenticate(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen, bool write) {
    // Reset the transmission frame length
    *txlen = 0;

    // Try to find out which command was send by selecting on length (in bits)
    switch (rxlen) {
        case 0: {
            // No answer, try to resurrect
            // Stop if there is no answer while we are in crypto mode (after sending NrAr)
            if (bCrypto) {
                DBG DbpString("No answer after sending NrAr!");
                return false;
            } else {

                // Failed during authentication
                if (bAuthenticating) {
                    DBG DbpString("Authentication - failed!");
                    return false;
                }

                DBG DbpString("Authenticating - send 0xC0");
                *txlen = 5;
                memcpy(tx, "\xC0", nbytes(*txlen));
            }
            break;
        }
        case 32: {
            // Received UID or crypto tag answer
            if (bCrypto == false) {
                *txlen = 64;
                memcpy(tx, NrAr, sizeof(NrAr));
                bCrypto = true;
                bAuthenticating = true;
                DBG DbpString("Authenticating sending NrAr");
            } else {
                DBG DbpString("Authentication successful!");

                // stage 2, got config byte+password TAG, discard as will read later
                if (bAuthenticating) {

                    bAuthenticating = false;

                    if (write) {
                        if (hitag2_write_page(rx, rxlen, tx, txlen) == false) {
                            return false;
                        }
                        break;
                    }

                } else { // stage 2+, got data block

                    // Store the received block
                    memcpy(tag.sectors[blocknr], rx, 4);
                    blocknr++;
                }

                if (blocknr > 7) {
                    DBG DbpString("Read successful!");
                    bSuccessful = true;
                    return false;
                } else {

                    DBG Dbprintf("Sending read block %u", blocknr);

                    *txlen = 10;
                    tx[0] = HITAG2_READ_PAGE | (blocknr << 3) | ((blocknr ^ 7) >> 2);
                    tx[1] = ((blocknr ^ 7) << 6);
                }
            }
            break;
        }
        default: {
            DBG Dbprintf("Unknown frame length: " _RED_("%d"), rxlen);
            return false;
        }
    }
    return true;
}

static bool hitag2_test_auth_attempts(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen) {

    // Reset the transmission frame length
    *txlen = 0;

    // Try to find out which command was send by selecting on length (in bits)
    switch (rxlen) {
        // No answer, try to resurrect
        case 0: {
            // Stop if there is no answer while we are in crypto mode (after sending NrAr)
            if (bCrypto) {
                Dbprintf("auth: %02x%02x%02x%02x%02x%02x%02x%02x Failed, removed entry!", NrAr[0], NrAr[1], NrAr[2], NrAr[3], NrAr[4], NrAr[5], NrAr[6], NrAr[7]);

                // Removing failed entry from authentications table
                memcpy(auth_table + auth_table_pos, auth_table + auth_table_pos + 8, 8);
                auth_table_len -= 8;

                // Return if we reached the end of the authentications table
                bCrypto = false;
                if (auth_table_pos == auth_table_len) {
                    return false;
                }

                // Copy the next authentication attempt in row (at the same position, b/c we removed last failed entry)
                memcpy(NrAr, auth_table + auth_table_pos, 8);
            }
            *txlen = 5;
            memcpy(tx, "\xc0", nbytes(*txlen));
        }
        break;

        // Received UID, crypto tag answer, or read block response
        case 32: {
            if (bCrypto == false) {
                *txlen = 64;
                memcpy(tx, NrAr, 8);
                bCrypto = true;
            } else {
                Dbprintf("auth: %02x%02x%02x%02x%02x%02x%02x%02x ( " _GREEN_("ok") " )", NrAr[0], NrAr[1], NrAr[2], NrAr[3], NrAr[4], NrAr[5], NrAr[6], NrAr[7]);
                bCrypto = false;
                if ((auth_table_pos + 8) == auth_table_len) {
                    return false;
                }
                auth_table_pos += 8;
                memcpy(NrAr, auth_table + auth_table_pos, 8);
            }
        }
        break;

        default: {
            Dbprintf("Unknown frame length: " _RED_("%d"), rxlen);
            return false;
        }
        break;
    }

    return true;
}

// Hitag 2 Sniffing
void hitag_sniff(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    BigBuf_free();
    BigBuf_Clear_ext(false);
    clear_trace();
    set_tracing(true);

    // Set up eavesdropping mode, frequency divisor which will drive the FPGA
    // and analog mux selection.
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT  | FPGA_LF_EDGE_DETECT_TOGGLE_MODE);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); // 125Khz
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);
    RELAY_OFF();

}


// T0     18-22 fc  (total time ZERO)
// T1     26-32 fc  (total time ONE)
// Tstop  36 >  fc  (high field stop limit)
// Tlow   4-10  fc  (reader field low time)
void SniffHitag2(bool ledcontrol) {

    if (ledcontrol) LED_D_ON();

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    BigBuf_free();
    BigBuf_Clear_ext(false);
    clear_trace();
    set_tracing(true);

    /*
        lf_init(false, false, ledcontrol);

        // no logging of the raw signal
    g_logging = true;
        uint32_t total_count = 0;

    uint8_t rx[HITAG_FRAME_BIT_COUNT * 2];

        while (BUTTON_PRESS() == false) {

            lf_reset_counter();

            WDT_HIT();

            size_t periods = 0;
            uint16_t rxlen = 0;
            memset(rx, 0x00, sizeof(rx));

            // Use the current modulation state as starting point
            uint8_t mod_state = lf_get_reader_modulation();

            while (rxlen < sizeof(rx)) {
                periods = lf_count_edge_periods(64);
                // Evaluate the number of periods before the next edge
                if (periods >= 24 && periods < 64) {
                    // Detected two sequential equal bits and a modulation switch
                    // NRZ modulation: (11 => --|) or (11 __|)
                    rx[rxlen++] = mod_state;
                    if (rxlen < sizeof(rx)) {
                    rx[rxlen++] = mod_state;
                    }
                    // toggle tag modulation state
                    mod_state ^= 1;

                } else if (periods > 0 && periods < 24) {
                    // Detected one bit and a modulation switch
                    // NRZ modulation: (1 => -|) or (0 _|)
                    rx[rxlen++] = mod_state;
                    mod_state ^= 1;
                } else {
                    mod_state ^= 1;
                // The function lf_count_edge_periods() returns > 64 periods, this is not a valid number periods
                Dbprintf("Detected unexpected period count... " _YELLOW_("%zu"), periods);
                    break;
                }

            }

            if (rxlen < 10) {
                continue;
            }

            // tag sends 11111 + uid,
        bool got_tag = (memcmp(rx, "\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00", 10) == 0);

        Dbprintf("periods... %zu   rxlen... %u", periods, rxlen);
        Dbhexdump(rxlen, rx, false);

            if (got_tag) {

                bool bad_man = false;
                uint16_t bitnum = 0;
                // mqnchester decode
                for (uint16_t i = 0; i < rxlen; i += 2) {

                    if (rx[i] == 1 && (rx[i + 1] == 0)) {
                        rx[bitnum++] = 0;
                    } else if ((rx[i] == 0) && rx[i + 1] == 1) {
                        rx[bitnum++] = 1;
                    } else {
                        bad_man = true;
                        break;
                    }
                }
    //                Dbprintf(_YELLOW_("TAG") " rxlen... %u  bitnum... %u", rxlen, bitnum);
                if (bad_man) {
                Dbprintf("bad manchester  ( bitnum %u )", bitnum);
                    continue;;
                }

                if (bitnum < 5) {
                    DbpString("too few bits");
                    continue;
                }

            // Pack the response into a byte array,
            // and skip header 11111  (start at idx 5)
                rxlen = 0;

                for (uint16_t i = 5; i < bitnum; i++) {
                    uint8_t b = rx[i];
                    rx[rxlen >> 3] |= b << (7 - (rxlen % 8));
                    rxlen++;
                }

                // skip spurious bit
                if (rxlen % 8 == 1) {
                    rxlen--;
                }

                // nothing to log
                if (rxlen == 0) {
                    if (ledcontrol) LED_A_INV();
                    continue;
                }

            LogTraceBits(rx, rxlen, 0, periods, false);
                total_count += nbytes(rxlen);

            } else {

                // nothing to log
                if (rxlen < 3) {
                    if (ledcontrol) LED_A_INV();
                    continue;
                }

                uint16_t n = 0;
                for (uint16_t i = 0; i < rxlen; i++) {
                    uint8_t b = rx[i];
                    rx[n >> 3] |= b << (7 - (n % 8));
                    n++;
                }

                // decode reader comms
            LogTraceBits(rx, n, 0, periods, true);
                total_count += nbytes(n);
            }
            if (ledcontrol) LED_A_INV();
        }

        lf_finalize(ledcontrol);
        Dbprintf("Collected %u bytes", total_count);
    switch_off();
    BigBuf_free();
    }
        */

    // Set up eavesdropping mode, frequency divisor which will drive the FPGA
    // and analog mux selection.
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT  | FPGA_LF_EDGE_DETECT_TOGGLE_MODE);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); // 125Khz
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);
    RELAY_OFF();

    // Configure output pin that is connected to the FPGA (for modulating)
//    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
//    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;

    // Disable modulation, we are going to eavesdrop, not modulate ;)
//    LOW(GPIO_SSC_DOUT);

    // Enable Peripheral Clock for TIMER_CLOCK1, used to capture edges of the reader frames
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC1);
    AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;

    // Disable timer during configuration
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // Capture mode, default timer source = MCK/2 (TIMER_CLOCK1), TIOA is external trigger,
    // external trigger rising edge, load RA on rising edge of TIOA.
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_TIMER_DIV1_CLOCK | AT91C_TC_ETRGEDG_BOTH | AT91C_TC_ABETRG | AT91C_TC_LDRA_BOTH;

    // Enable and reset counter
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // Assert a sync signal. This sets all timers to 0 on next active clock edge
    AT91C_BASE_TCB->TCB_BCR = 1;

    int frame_count = 0, response = 0, lastbit = 1, tag_sof = 4;
    int overflow = 0;
    bool rising_edge, reader_frame = false, bSkip = true;

//    bool exit_due_to_overflow;
    // HACK -- add one byte to avoid rewriting manchester decoder for edge case
    uint8_t rx[HITAG_FRAME_LEN + 1];
    size_t rxlen = 0;

    auth_table_len = 0;
    auth_table_pos = 0;

    auth_table = (uint8_t *)BigBuf_calloc(AUTH_TABLE_LENGTH);

    while (BUTTON_PRESS() == false) {

        WDT_HIT();

//        bool exit_due_to_overflow = false;

        // Receive frame, watch for at most T0 * EOF periods
        while (AT91C_BASE_TC1->TC_CV < (HITAG_T0 * HITAG_T_EOF)) {

            // Check if rising edge in modulation is detected
            if (AT91C_BASE_TC1->TC_SR & AT91C_TC_LDRAS) {

                // Retrieve the new timing values
                int ra = (AT91C_BASE_TC1->TC_RA / HITAG_T0) + overflow;
                overflow = 0;

                // Find out if we are dealing with a rising or falling edge
                rising_edge = (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_FRAME) > 0;

                // Shorter periods will only happen with reader frames
                if (reader_frame == false && rising_edge && ra < HITAG_T_TAG_CAPTURE_ONE_HALF) {
                    // Switch from tag to reader capture
                    if (ledcontrol) LED_C_OFF();
                    reader_frame = true;
                    rxlen = 0;
                }

                // Only handle if reader frame and rising edge, or tag frame and falling edge
                if (reader_frame != rising_edge) {
                    overflow += ra;
                    continue;
                }

                // Add the buffered timing values of earlier captured edges which were skipped
                ra += overflow;
                overflow = 0;

                if (reader_frame) {

                    if (ledcontrol) LED_B_ON();
                    // Capture reader frame
                    if (ra >= HITAG_T_STOP) {
//                      if (rxlen != 0) {
                        //DbpString("wierd0?");
//                      }
                        // Capture the T0 periods that have passed since last communication or field drop (reset)
                        response = (ra - HITAG_T_LOW);
                        if (rxlen != 0) { Dbprintf("ra - HITAG_T_LOW... %i", response); }

                    } else if (ra >= HITAG_T_1_MIN) {
                        // '1' bit
                        rx[rxlen / 8] |= 1 << (7 - (rxlen % 8));
                        rxlen++;

                    } else if (ra >= HITAG_T_0_MIN) {
                        // '0' bit
                        rx[rxlen / 8] |= 0 << (7 - (rxlen % 8));
                        rxlen++;
                    }

                } else {
                    if (ledcontrol) LED_C_ON();
                    // Capture tag frame (manchester decoding using only falling edges)
                    if (ra >= HITAG_T_EOF) {
//                      if (rxlen != 0) {
                        //DbpString("wierd1?");
//                      }
                        // Capture the T0 periods that have passed since last communication or field drop (reset)
                        // We always receive a 'one' first, which has the falling edge after a half period |-_|
                        response = ra - HITAG_T_TAG_HALF_PERIOD;

                    } else if (ra >= HITAG_T_TAG_CAPTURE_FOUR_HALF) {
                        // Manchester coding example |-_|_-|-_| (101)
                        rx[rxlen / 8] |= 0 << (7 - (rxlen % 8));
                        rxlen++;
                        rx[rxlen / 8] |= 1 << (7 - (rxlen % 8));
                        rxlen++;

                    } else if (ra >= HITAG_T_TAG_CAPTURE_THREE_HALF) {
                        // Manchester coding example |_-|...|_-|-_| (0...01)
                        rx[rxlen / 8] |= 0 << (7 - (rxlen % 8));
                        rxlen++;
                        // We have to skip this half period at start and add the 'one' the second time
                        if (bSkip == false) {
                            rx[rxlen / 8] |= 1 << (7 - (rxlen % 8));
                            rxlen++;
                        }
                        lastbit = !lastbit;
                        bSkip = !bSkip;

                    } else if (ra >= HITAG_T_TAG_CAPTURE_TWO_HALF) {
                        // Manchester coding example |_-|_-| (00) or |-_|-_| (11)
                        if (tag_sof) {
                            // Ignore bits that are transmitted during SOF
                            tag_sof--;
                        } else {
                            // bit is same as last bit
                            rx[rxlen / 8] |= lastbit << (7 - (rxlen % 8));
                            rxlen++;
                        }
                    }
                }
            }
        }  // end while

        // Check if frame was captured
        if (rxlen) {

            frame_count++;
            LogTraceBits(rx, rxlen, response, 0, reader_frame);

            // Check if we recognize a valid authentication attempt
            if (rxlen == 64) {
                // Store the authentication attempt
                if (auth_table_len < (AUTH_TABLE_LENGTH - 8)) {
                    memcpy(auth_table + auth_table_len, rx, 8);
                    auth_table_len += 8;
                }
            }

            if (ledcontrol) {
                LED_B_OFF();
                LED_C_OFF();
            }

            response = 0;
            reader_frame = false;
            lastbit = 1;
            bSkip = true;
            tag_sof = 4;
            overflow = 0;

            if (ledcontrol) {
                LED_B_OFF();
                LED_C_OFF();
            }

        } else {
            // Save the timer overflow, will be 0 when frame was received
            overflow += (AT91C_BASE_TC1->TC_CV / HITAG_T0);
        }

        // Reset the frame length
        rxlen = 0;

        // Reset the timer to restart while-loop that receives frames
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_SWTRG;

        // Assert a sync signal. This sets all timers to 0 on next active clock edge
        AT91C_BASE_TCB->TCB_BCR = 1;
    }

    if (ledcontrol) LEDsoff();

    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;

    DBG Dbprintf("frames.......... %d", frame_count);
    Dbprintf("Auth attempts... %d", (auth_table_len / 8));

    switch_off();
    BigBuf_free();
}


// Hitag 2 simulation
void SimulateHitag2(bool ledcontrol) {

    BigBuf_free();
    BigBuf_Clear_ext(false);
    clear_trace();
    set_tracing(true);

    // empties bigbuff etc
    lf_init(false, true, ledcontrol);

    int response = 0;
    uint8_t rx[HITAG_FRAME_LEN] = {0};
    uint8_t tx[HITAG_FRAME_LEN] = {0};

    auth_table_len = 0;
    auth_table_pos = 0;
//    auth_table = BigBuf_calloc(AUTH_TABLE_LENGTH);

    DbpString("Starting Hitag 2 simulation");

    // hitag2 state machine?
    hitag2_init();

    // printing
    uint32_t block = 0;
    for (size_t i = 0; i < 12; i++) {

        // num2bytes?
        for (size_t j = 0; j < 4; j++) {
            block <<= 8;
            block |= tag.sectors[i][j];
        }
        Dbprintf("| %d | %08x |", i, block);
    }

    size_t max_nrzs = 8 * HITAG_FRAME_LEN + 5;
    uint8_t nrz_samples[max_nrzs];

//    uint32_t command_start = 0, command_duration = 0;
    //  int16_t checked = 0;

// SIMULATE
    uint32_t signal_size = 10000;
    while (BUTTON_PRESS() == false) {

        // use malloc
        initSampleBufferEx(&signal_size, true);

        if (ledcontrol) {
            LED_D_ON();
            LED_A_OFF();
        }

//        lf_reset_counter();
        WDT_HIT();

        /*
                // only every 1000th times, in order to save time when collecting samples.
                if (checked == 100) {
                    if (data_available()) {
                        checked = -1;
                        break;
                    } else {
                        checked = 0;
                    }
                }
                ++checked;
        */
        size_t rxlen = 0, txlen = 0;

        // Keep administration of the first edge detection
        bool waiting_for_first_edge = true;

        // Did we detected any modulaiton at all
        bool detected_modulation = false;

        // Use the current modulation state as starting point
        uint8_t reader_modulation = lf_get_reader_modulation();

        // Receive frame, watch for at most max_nrzs periods
        // Reset the number of NRZ samples and use edge detection to detect them
        size_t nrzs = 0;
        while (nrzs < max_nrzs) {
            // Get the timing of the next edge in number of wave periods
            size_t periods = lf_count_edge_periods(128);

            // Just break out of loop after an initial time-out (tag is probably not available)
            // The function lf_count_edge_periods() returns 0 when a time-out occurs
            if (periods == 0) {
                break;
            }

            if (ledcontrol) LED_A_ON();

            // Are we dealing with the first incoming edge
            if (waiting_for_first_edge) {

                // Register the number of periods that have passed
                response = periods;

                // Indicate that we have dealt with the first edge
                waiting_for_first_edge = false;

                // The first edge is always a single NRZ bit, force periods on 16
                periods = 16;

                // We have received more than 0 periods, so we have detected a tag response
                detected_modulation = true;
            }

            // Evaluate the number of periods before the next edge
            if (periods > 24 && periods <= 64) {
                // Detected two sequential equal bits and a modulation switch
                // NRZ modulation: (11 => --|) or (11 __|)
                nrz_samples[nrzs++] = reader_modulation;
                if (nrzs < max_nrzs) {
                    nrz_samples[nrzs++] = reader_modulation;
                }
                // Invert tag modulation state
                reader_modulation ^= 1;
            } else if (periods > 0 && periods <= 24) {
                // Detected one bit and a modulation switch
                // NRZ modulation: (1 => -|) or (0 _|)
                nrz_samples[nrzs++] = reader_modulation;
                reader_modulation ^= 1;
            } else {
                reader_modulation ^= 1;
                // The function lf_count_edge_periods() returns > 64 periods, this is not a valid number periods
                Dbprintf("Detected unexpected period count: %zu", periods);
                break;
            }
        }

        if (ledcontrol) LED_D_OFF();

        // If there is no response, just repeat the loop
        if (!detected_modulation) continue;

        if (ledcontrol) LED_A_OFF();

        // Make sure we always have an even number of samples. This fixes the problem
        // of ending the manchester decoding with a zero. See the example below where
        // the '|' character is end of modulation
        //  One at the end: ..._-|_____...
        // Zero at the end: ...-_|_____...
        // The last modulation change of a zero is not detected, but we should take
        // the half period in account, otherwise the demodulator will fail.
        if ((nrzs % 2) != 0) {
            if (nrzs >= max_nrzs) {
                Dbprintf("max_nrzs (%d) is odd?  Must be even!", max_nrzs); // should be a static assert above
                continue;
            }
            nrz_samples[nrzs++] = reader_modulation;
        }

        if (ledcontrol) LED_B_ON();

        // decode bitstream
        manrawdecode((uint8_t *)nrz_samples, &nrzs, true, 0);

        // Verify if the header consists of five consecutive ones
        if (nrzs < 5) {
            Dbprintf("Detected unexpected number of manchester decoded samples [%d]", nrzs);
            continue;
        } else {
            for (size_t i = 0; i < 5; i++) {
                if (nrz_samples[i] != 1) {
                    Dbprintf("Detected incorrect header, the bit [%d] is zero instead of one", i);
                }
            }
        }

        // Pack the response into a byte array
        for (size_t i = 5; i < 37; i++) {
            uint8_t bit = nrz_samples[i];
            rx[rxlen / 8] |= bit << (7 - (rxlen % 8));
            rxlen++;
        }

        // Check if frame was captured
        if (rxlen > 4) {

            LogTraceBits(rx, rxlen, response, response, true);

            // Process the incoming frame (rx) and prepare the outgoing frame (tx)
            hitag2_handle_reader_command(rx, rxlen, tx, &txlen);

            // Wait for HITAG_T_WAIT_1 carrier periods after the last reader bit,
            // not that since the clock counts since the rising edge, but T_Wait1 is
            // with respect to the falling edge, we need to wait actually (T_Wait1 - T_Low)
            // periods. The gap time T_Low varies (4..10). All timer values are in
            // terms of T0 units (HITAG_T_WAIT_1_MIN - HITAG_T_LOW )
            lf_wait_periods(HITAG_T_WAIT_1_MIN);

            // Send and store the tag answer (if there is any)
            if (txlen) {
                // Transmit the tag frame
                //hitag_send_frame(tx, txlen);
                lf_manchester_send_bytes(tx, txlen, ledcontrol);

                // Store the frame in the trace
                LogTraceBits(tx, txlen, 0, 0, false);
            }

            // Reset the received frame and response timing info
            memset(rx, 0x00, sizeof(rx));
            response = 0;

            if (ledcontrol) LED_B_OFF();
        }
    }

    lf_finalize(ledcontrol);

    // release allocated memory from BigBuff.
    BigBuf_free();

    DbpString("Sim stopped");

//    reply_ng(CMD_LF_HITAG_SIMULATE, (checked == -1) ? PM3_EOPABORTED : PM3_SUCCESS, (uint8_t *)tag.sectors, tag_size);
}

void ReaderHitag(const lf_hitag_data_t *payload, bool ledcontrol) {

    uint32_t command_start = 0, command_duration = 0;
    uint32_t response_start = 0, response_duration = 0;

    uint8_t rx[HITAG_FRAME_LEN] = {0};
    size_t rxlen = 0;
    uint8_t txbuf[HITAG_FRAME_LEN] = {0};
    uint8_t *tx = txbuf;
    size_t txlen = 0;

    int t_wait_1 = 204;
    int t_wait_1_guard = 8;
    int t_wait_2 = 128;
    size_t tag_size = 48;
    bool bStop = false;

    // Raw demodulation/decoding by sampling edge periods
    size_t periods = 0;

    // Reset the return status
    bSuccessful = false;
    bCrypto = false;

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    // Check configuration
    switch (payload->cmd) {
        case HT1F_PLAIN: {
            DBG Dbprintf("Read public blocks in plain mode");
            // this part will be unreadable
            memset(tag.sectors + 2, 0x0, 30);
            blocknr = 0;
            break;
        }
        case HT1F_AUTHENTICATE: {
            DBG Dbprintf("Read all blocks in authed mode");

            memcpy(nonce, payload->nonce, 4);
            memcpy(key, payload->key, 4);
            memcpy(logdata_0, payload->logdata_0, 4);
            memcpy(logdata_1, payload->logdata_1, 4);

            // TEST
            memset(nonce, 0x0, 4);
            memset(logdata_1, 0x00, 4);

            byte_value = 0;
            key_no = payload->key_no;

            DBG Dbprintf("Authenticating using key #%u :", key_no);
            DBG Dbhexdump(4, key, false);
            DBG DbpString("Nonce:");
            DBG Dbhexdump(4, nonce, false);
            DBG DbpString("Logdata_0:");
            DBG Dbhexdump(4, logdata_0, false);
            DBG DbpString("Logdata_1:");
            DBG Dbhexdump(4, logdata_1, false);
            blocknr = 0;
            break;
        }
        case HT2F_PASSWORD: {
            DBG Dbprintf("List identifier in password mode");
            if (memcmp(payload->pwd, "\x00\x00\x00\x00", 4) == 0) {
                memcpy(password, tag.sectors[1], sizeof(password));
            } else {
                memcpy(password, payload->pwd, sizeof(password));
            }
            blocknr = 0;
            bPwd = false;
            bAuthenticating = false;
            break;
        }
        case HT2F_AUTHENTICATE: {
            DBG DbpString("Authenticating using NrAr pair:");
            memcpy(NrAr, payload->NrAr, 8);
            DBG Dbhexdump(8, NrAr, false);
            // We can't read block 0, 1, 2..
            blocknr = 3;
            bCrypto = false;
            bPwd = false;
            bAuthenticating = false;
            break;
        }
        case HT2F_CRYPTO: {
            DBG DbpString("Authenticating using key:");
            memcpy(key, payload->key, 6);  //HACK; 4 or 6??  I read both in the code.
            DBG Dbhexdump(6, key, false);
            DBG DbpString("Nonce:");
            DBG Dbhexdump(4, nonce, false);
            memcpy(nonce, payload->data, 4);
            blocknr = 0;
            bCrypto = false;
            bAuthenticating = false;
            break;
        }
        case HT2F_TEST_AUTH_ATTEMPTS: {
            DBG Dbprintf("Testing " _YELLOW_("%d") " authentication attempts", (auth_table_len / 8));
            auth_table_pos = 0;
            memcpy(NrAr, auth_table, 8);
            bCrypto = false;
            break;
        }
        default: {
            DBG Dbprintf("Error, unknown function: " _RED_("%d"), payload->cmd);
            set_tracing(false);
            reply_ng(CMD_LF_HITAG_READER, PM3_ESOFT, NULL, 0);
            return;
        }
    }

    if (ledcontrol) LED_D_ON();

    // hitag 2 state machine?
    hitag2_init();

    // Tag specific configuration settings (sof, timings, etc.)
// TODO HTS
    /*  if (payload->cmd <= HTS_LAST_CMD) {
            // hitag S settings
            t_wait_1 = 204;
            t_wait_2 = 128;
            flipped_bit = 0;
            tag_size = 8;
            DBG DbpString("Configured for " _YELLOW_("Hitag S") " reader");
        } else */
    if (payload->cmd <= HT1_LAST_CMD) {
        // hitag 1 settings
        t_wait_1 = 204;
        t_wait_2 = 128;
        tag_size = 256;
        flipped_bit = 0;
        DBG DbpString("Configured for " _YELLOW_("Hitag 1") " reader");
    } else if (payload->cmd <= HT2_LAST_CMD) {
        // hitag 2 settings
        t_wait_1 = HITAG_T_WAIT_1_MIN;
        t_wait_2 = HITAG_T_WAIT_2_MIN;
        tag_size = 48;
        DBG DbpString("Configured for " _YELLOW_("Hitag 2") " reader");
    }

    // init as reader
    lf_init(true, false, ledcontrol);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    uint8_t tag_modulation;
    size_t max_nrzs = (8 * HITAG_FRAME_LEN + 5) * 2; // up to 2 nrzs per bit
    uint8_t nrz_samples[max_nrzs];
    bool turn_on = true;
    size_t nrzs = 0;
    int16_t checked = 0;
    uint32_t signal_size = 10000;

    while (bStop == false && BUTTON_PRESS() == false) {

        // use malloc
        initSampleBufferEx(&signal_size, true);

        WDT_HIT();

        // only every 1000th times, in order to save time when collecting samples.
        if (checked == 4000) {
            if (data_available()) {
                checked = -1;
                break;
            } else {
                checked = 0;
            }
        }
        ++checked;

        // By default reset the transmission buffer
        tx = txbuf;
        switch (payload->cmd) {
            case HT1F_PLAIN: {
                bStop = !hitag1_plain(rx, rxlen, tx, &txlen, false);
                break;
            }
            case HT1F_AUTHENTICATE: {
                bStop = !hitag1_authenticate(rx, rxlen, tx, &txlen);
                break;
            }
            case HT2F_PASSWORD: {
                bStop = !hitag2_password(rx, rxlen, tx, &txlen, false);
                break;
            }
            case HT2F_AUTHENTICATE: {
                bStop = !hitag2_authenticate(rx, rxlen, tx, &txlen, false);
                break;
            }
            case HT2F_CRYPTO: {
                bStop = !hitag2_crypto(rx, rxlen, tx, &txlen, false);
                break;
            }
            case HT2F_TEST_AUTH_ATTEMPTS: {
                bStop = !hitag2_test_auth_attempts(rx, rxlen, tx, &txlen);
                break;
            }
            default: {
                DBG Dbprintf("Error, unknown function: " _RED_("%d"), payload->cmd);
                goto out;
            }
        }

        if (bStop) {
            break;
        }

        if (turn_on) {
            // Wait 50ms with field off to be sure the transponder gets reset
            SpinDelay(50);
            FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
            turn_on = false;
            // Wait with field on to be in "Wait for START_AUTH" timeframe
            lf_wait_periods(HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4);
            command_start += HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4;
        } else {
            // Wait for t_wait_2 carrier periods after the last tag bit before transmitting,
            lf_wait_periods(t_wait_2);
            command_start += t_wait_2;
        }

        // Transmit the reader frame
        command_duration = hitag_reader_send_frame(tx, txlen);
        response_start = command_start + command_duration;

        // Let the antenna and ADC values settle
        // And find the position where edge sampling should start
        lf_wait_periods(t_wait_1 - t_wait_1_guard);

        response_start += t_wait_1 - t_wait_1_guard;

        // Keep administration of the first edge detection
        bool waiting_for_first_edge = true;

        // Did we detected any modulaiton at all
        bool detected_tag_modulation = false;

        // Use the current modulation state as starting point
        tag_modulation = lf_get_tag_modulation();

        // Reset the number of NRZ samples and use edge detection to detect them

        nrzs = 0;
        while (nrzs < max_nrzs) {
            // Get the timing of the next edge in number of wave periods
            periods = lf_count_edge_periods(128);

            // Are we dealing with the first incoming edge
            if (waiting_for_first_edge) {
                // Just break out of loop after an initial time-out (tag is probably not available)
                if (periods == 0) {
                    break;
                }

                if (tag_modulation == 0) {
                    // hitag replies always start with 11111 == 1010101010, if we see 0
                    // it means we missed the first period, e.g. if the signal never crossed 0 since reader signal
                    // so let's add it:
                    nrz_samples[nrzs++] = tag_modulation ^ 1;
                    // Register the number of periods that have passed
                    // we missed the begin of response but we know it happened one period of 16 earlier
                    response_start += periods - 16;
                    response_duration = response_start;
                } else {
                    // Register the number of periods that have passed
                    response_start += periods;
                    response_duration = response_start;
                }
                // Indicate that we have dealt with the first edge
                waiting_for_first_edge = false;
                // The first edge is always a single NRZ bit, force periods on 16
                periods = 16;
                // We have received more than 0 periods, so we have detected a tag response
                detected_tag_modulation = true;
            } else {
                // The function lf_count_edge_periods() returns 0 when a time-out occurs
                if (periods == 0) {
                    DBG Dbprintf("Detected timeout after [" _YELLOW_("%zu") "] nrz samples", nrzs);
                    break;
                }
            }
            // Evaluate the number of periods before the next edge
            if (periods > 24 && periods <= 64) {
                // Detected two sequential equal bits and a modulation switch
                // NRZ modulation: (11 => --|) or (11 __|)
                nrz_samples[nrzs++] = tag_modulation;
                if (nrzs < max_nrzs) {
                    nrz_samples[nrzs++] = tag_modulation;
                }
                response_duration += periods;
                // Invert tag modulation state
                tag_modulation ^= 1;
            } else if (periods > 0 && periods <= 24) {
                // Detected one bit and a modulation switch
                // NRZ modulation: (1 => -|) or (0 _|)
                nrz_samples[nrzs++] = tag_modulation;
                response_duration += periods;
                tag_modulation ^= 1;
            } else {
                // The function lf_count_edge_periods() returns > 64 periods, this is not a valid number periods
                DBG Dbprintf("Detected unexpected period count: " _RED_("%zu"), periods);
                break;
            }
        }

        // Store the TX frame, we do this now at this point, to avoid delay in processing
        // and to be able to overwrite the first samples with the trace (since they currently
        // still use the same memory space)
        LogTraceBits(tx, txlen, command_start, command_start + command_duration, true);

        // Reset values for receiving frames
        memset(rx, 0x00, sizeof(rx));
        rxlen = 0;

        // If there is no response
        if (detected_tag_modulation == false) {
            checked = -1;
            goto out;
        }

        // Make sure we always have an even number of samples. This fixes the problem
        // of ending the manchester decoding with a zero. See the example below where
        // the '|' character is end of modulation
        //  One at the end: ..._-|_____...
        // Zero at the end: ...-_|_____...
        // The last modulation change of a zero is not detected, but we should take
        // the half period in account, otherwise the demodulator will fail.
        if ((nrzs % 2) != 0) {

            if (nrzs >= max_nrzs) {
                DBG Dbprintf("max_nrzs ( " _YELLOW_("%zu") " ) is odd?  Must be even!", max_nrzs);
                continue;
            }
            nrz_samples[nrzs++] = tag_modulation;
        }

        if (ledcontrol) LED_B_ON();

        // decode bitstream
        manrawdecode((uint8_t *)nrz_samples, &nrzs, true, 0);

        // decode frame

        // Verify if the header consists of five consecutive ones
        if (nrzs < 5) {
            DBG Dbprintf("Detected unexpected number of manchester decoded samples [%zu]", nrzs);
            break;
        } else {

            size_t i;
            for (i = 0; i < 5; i++) {
                if (nrz_samples[i] != 1) {
                    DBG Dbprintf("Detected incorrect header, the bit [%zu] is zero instead of one, abort", i);
                    break;
                }
            }
            if (i < 5) {
                break;
            }
        }

        // Pack the response into a byte array
        for (size_t i = 5; i < nrzs && rxlen < (sizeof(rx) << 3); i++) {

            uint8_t bit = nrz_samples[i];
            if (bit > 1) { // When Manchester detects impossible symbol it writes "7"
                DBG Dbprintf("Error in Manchester decoding, abort");
                break;
            }

            rx[rxlen >> 3] |= bit << (7 - (rxlen % 8));
            rxlen++;
        }

        // skip spurious bit
        if (rxlen % 8 == 1) {
            rxlen--;
        }

        // Check if frame was captured and store it
        LogTraceBits(rx, rxlen, response_start, response_start + response_duration, false);

// TODO when using cumulative time for command_start, pm3 doesn't reply anymore, e.g. on lf hitag reader --23 -k 4F4E4D494B52
// Use delta time?
//            command_start = response_start + response_duration;
        command_start = 0;
        nrzs = 0;
    }

out:
    lf_finalize(ledcontrol);

    // release allocated memory from BigBuff.
    BigBuf_free();

    if (checked == -1) {
        reply_ng(CMD_LF_HITAG_READER, PM3_ESOFT, NULL, 0);
    }

    reply_ng(CMD_LF_HITAG_READER
             , (bSuccessful) ? PM3_SUCCESS : PM3_EFAILED
             , (uint8_t *)tag.sectors
             , tag_size
            );
}

void WriterHitag(const lf_hitag_data_t *payload, bool ledcontrol) {

    uint32_t command_start = 0;
    uint32_t command_duration = 0;
    uint32_t response_start = 0;
    uint32_t response_duration = 0;

    uint8_t rx[HITAG_FRAME_LEN];
    size_t rxlen = 0;

    uint8_t txbuf[HITAG_FRAME_LEN];
    uint8_t *tx = txbuf;
    size_t txlen = 0;

    int t_wait_1 = 204;
    int t_wait_1_guard = 8;
    int t_wait_2 = 128;
    size_t tag_size = 48;

    bool bStop = false;

    // Raw demodulation/decoding by sampling edge periods
    size_t periods = 0;

    // iceman:   Hitag2 is filled with static global vars.
    // these following are globals status indicator  :-|
    // Reset the return status
    bSuccessful = false;

    writestate = WRITE_STATE_START;
    blocknr = 0;

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    // Check configuration
    switch (payload->cmd) {
        case HT2F_CRYPTO: {
            DBG DbpString("Authenticating using key:");
            memcpy(key, payload->key, 6); //HACK; 4 or 6??  I read both in the code.
            memcpy(writedata, payload->data, 4);
            Dbhexdump(6, key, false);
            blocknr = payload->page;
            bCrypto = false;
            bAuthenticating = false;
        }
        break;
        case HT2F_PASSWORD: {
            DBG DbpString("Authenticating using password:");
            if (memcmp(payload->pwd, "\x00\x00\x00\x00", 4) == 0) {
                memcpy(password, tag.sectors[1], sizeof(password));
            } else {
                memcpy(password, payload->pwd, sizeof(password));
            }
            memcpy(writedata, payload->data, 4);
            DBG Dbhexdump(4, password, false);
            blocknr = payload->page;
            bPwd = false;
            bAuthenticating = false;
        }
        break;
        default: {
            DBG Dbprintf("Error, unknown function: " _RED_("%d"), payload->cmd);
            reply_ng(CMD_LF_HITAG2_WRITE, PM3_ESOFT, NULL, 0);
            return;
        }
        break;
    }

    if (ledcontrol) LED_D_ON();

    hitag2_init();

    // init as reader
    lf_init(true, false, ledcontrol);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    // Tag specific configuration settings (sof, timings, etc.)
// TODO HTS
    /*    if (payload->cmd <= HTS_LAST_CMD) {
            // hitag S settings
            t_wait_1 = 204;
            t_wait_2 = 128;
            //tag_size = 256;
            flipped_bit = 0;
            tag_size = 8;
            DBG DbpString("Configured for " _YELLOW_("Hitag S") " writer");
        } else
    */
    if (payload->cmd <= HT1_LAST_CMD) {
        // hitag 1 settings
        t_wait_1 = 204;
        t_wait_2 = 128;
        tag_size = 256;
        flipped_bit = 0;
        DBG DbpString("Configured for " _YELLOW_("Hitag 1") " writer");
    } else if (payload->cmd <= HT2_LAST_CMD) {
        // hitag 2 settings
        t_wait_1 = HITAG_T_WAIT_1_MIN;
        t_wait_2 = HITAG_T_WAIT_2_MIN;
        tag_size = 48;
        DBG DbpString("Configured for " _YELLOW_("Hitag 2") " writer");
    }

    uint8_t tag_modulation;
    size_t max_nrzs = (8 * HITAG_FRAME_LEN + 5) * 2; // up to 2 nrzs per bit
    uint8_t nrz_samples[max_nrzs];
    size_t nrzs = 0;
    int16_t checked = 0;
    uint32_t signal_size = 10000;
    bool turn_on = true;

    while (bStop == false && BUTTON_PRESS() == false) {

        // use malloc
        initSampleBufferEx(&signal_size, true);

        // only every 4000th times, in order to save time when collecting samples.
        if (checked == 4000) {
            if (data_available()) {
                checked = -1;
                break;
            } else {
                checked = 0;
            }
        }
        ++checked;

        WDT_HIT();

        // By default reset the transmission buffer
        tx = txbuf;

        switch (payload->cmd) {
            case HT2F_CRYPTO: {
                bStop = !hitag2_crypto(rx, rxlen, tx, &txlen, true);
                break;
            }
            case HT2F_PASSWORD: {
                bStop = !hitag2_password(rx, rxlen, tx, &txlen, true);
                break;
            }
            default: {
                goto out;
            }
        }

        if (bStop) {
            break;
        }

        if (turn_on) {
            // Wait 50ms with field off to be sure the transponder gets reset
            SpinDelay(50);
            FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
            turn_on = false;
            // Wait with field on to be in "Wait for START_AUTH" timeframe
            lf_wait_periods(HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4);
            command_start += HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4;
        } else {
            // Wait for t_wait_2 carrier periods after the last tag bit before transmitting,
            lf_wait_periods(t_wait_2);
            command_start += t_wait_2;
        }

        // Transmit the reader frame
        command_duration = hitag_reader_send_frame(tx, txlen);

        // global write state variable used
        // tearoff occurred
        if ((writestate == WRITE_STATE_PROG) && (tearoff_hook() == PM3_ETEAROFF)) {
            reply_ng(CMD_LF_HITAG2_WRITE, PM3_ETEAROFF, NULL, 0);
            lf_finalize(ledcontrol);
            BigBuf_free();
            return;
        }

        response_start = command_start + command_duration;

        // Let the antenna and ADC values settle
        // And find the position where edge sampling should start
        lf_wait_periods(t_wait_1 - t_wait_1_guard);

        response_start += t_wait_1 - t_wait_1_guard;

        // Keep administration of the first edge detection
        bool waiting_for_first_edge = true;

        // Did we detected any modulaiton at all
        bool detected_tag_modulation = false;

        // Use the current modulation state as starting point
        tag_modulation = lf_get_tag_modulation();

        // Reset the number of NRZ samples and use edge detection to detect them
        nrzs = 0;
        while (nrzs < max_nrzs) {
            // Get the timing of the next edge in number of wave periods
            periods = lf_count_edge_periods(128);

            // Are we dealing with the first incoming edge
            if (waiting_for_first_edge) {
                // Just break out of loop after an initial time-out (tag is probably not available)
                if (periods == 0) {
                    break;
                }

                if (tag_modulation == 0) {
                    // hitag replies always start with 11111 == 1010101010, if we see 0
                    // it means we missed the first period, e.g. if the signal never crossed 0 since reader signal
                    // so let's add it:
                    nrz_samples[nrzs++] = tag_modulation ^ 1;
                    // Register the number of periods that have passed
                    // we missed the begin of response but we know it happened one period of 16 earlier
                    response_start += periods - 16;
                    response_duration = response_start;
                } else {
                    // Register the number of periods that have passed
                    response_start += periods;
                    response_duration = response_start;
                }
                // Indicate that we have dealt with the first edge
                waiting_for_first_edge = false;
                // The first edge is always a single NRZ bit, force periods on 16
                periods = 16;
                // We have received more than 0 periods, so we have detected a tag response
                detected_tag_modulation = true;
            } else {
                // The function lf_count_edge_periods() returns 0 when a time-out occurs
                if (periods == 0) {
                    DBG Dbprintf("Detected timeout after [" _YELLOW_("%zu") "] nrz samples", nrzs);
                    break;
                }
            }
            // Evaluate the number of periods before the next edge
            if (periods > 24 && periods <= 64) {
                // Detected two sequential equal bits and a modulation switch
                // NRZ modulation: (11 => --|) or (11 __|)
                nrz_samples[nrzs++] = tag_modulation;
                if (nrzs < max_nrzs) {
                    nrz_samples[nrzs++] = tag_modulation;
                }
                response_duration += periods;
                // Invert tag modulation state
                tag_modulation ^= 1;
            } else if (periods > 0 && periods <= 24) {
                // Detected one bit and a modulation switch
                // NRZ modulation: (1 => -|) or (0 _|)
                nrz_samples[nrzs++] = tag_modulation;
                response_duration += periods;
                tag_modulation ^= 1;
            } else {
                // The function lf_count_edge_periods() returns > 64 periods, this is not a valid number periods
                DBG Dbprintf("Detected unexpected period count: " _RED_("%zu"), periods);
                break;
            }
        }

        // Wait some extra time for flash to be programmed

        // Store the TX frame, we do this now at this point, to avoid delay in processing
        // and to be able to overwrite the first samples with the trace (since they currently
        // still use the same memory space)
        LogTraceBits(tx, txlen, command_start, command_start + command_duration, true);

        // Reset values for receiving frames
        memset(rx, 0x00, sizeof(rx));
        rxlen = 0;

        // If there is no response, just repeat the loop
        if (detected_tag_modulation == false) {
            continue;
        }

        // Make sure we always have an even number of samples. This fixes the problem
        // of ending the manchester decoding with a zero. See the example below where
        // the '|' character is end of modulation
        //  One at the end: ..._-|_____...
        // Zero at the end: ...-_|_____...
        // The last modulation change of a zero is not detected, but we should take
        // the half period in account, otherwise the demodulator will fail.
        if ((nrzs % 2) != 0) {

            if (nrzs >= max_nrzs) {
                Dbprintf("max_nrzs ( " _YELLOW_("%zu") " ) is odd?  Must be even!", max_nrzs);
                continue;
            } else {
                nrz_samples[nrzs++] = tag_modulation;
            }
        }

        if (ledcontrol) LED_B_ON();

        // decode bitstream
        manrawdecode((uint8_t *)nrz_samples, &nrzs, true, 0);

        // decode frame

        // Verify if the header consists of five consecutive ones
        if (nrzs < 5) {
            DBG Dbprintf("Detected unexpected number of manchester decoded samples [%zu]", nrzs);
            break;
        } else {

            size_t i;
            for (i = 0; i < 5; i++) {
                if (nrz_samples[i] != 1) {
                    DBG Dbprintf("Detected incorrect header, the bit " _YELLOW_("%zu") " is zero instead of one, abort", i);
                    break;
                }
            }

            if (i < 5) {
                break;
            }
        }

        // Pack the response into a byte array
        for (size_t i = 5; i < nrzs && rxlen < (sizeof(rx) << 3); i++) {

            uint8_t bit = nrz_samples[i];

            // When Manchester detects impossible symbol it writes "7"
            if (bit > 1) {
                DBG Dbprintf("Error in Manchester decoding, abort");
                break;
            }

            // >> 3 instead of div by 8
            rx[rxlen >> 3] |= bit << (7 - (rxlen % 8));
            rxlen++;
        }

        // skip spurious bit
        if (rxlen % 8 == 1) {
            rxlen--;
        }

        // Check if frame was captured and store it
        LogTraceBits(rx, rxlen, response_start, response_start + response_duration, false);
        command_start = 0;
        nrzs = 0;
    }

out:
    lf_finalize(ledcontrol);

    // release allocated memory from BigBuff.
    BigBuf_free();

    if (checked == -1) {
        reply_ng(CMD_LF_HITAG2_WRITE, PM3_ESOFT, NULL, 0);
    }

    reply_ng(CMD_LF_HITAG2_WRITE
             , (bSuccessful) ? PM3_SUCCESS : PM3_EFAILED
             , (uint8_t *)tag.sectors
             , tag_size
            );
}


static void ht2_send(bool turn_on, uint32_t *cmd_start
                     , uint32_t *cmd_duration, uint32_t *resp_start
                     , uint8_t *tx, size_t txlen, bool send_bits) {

    // Tag specific configuration settings (sof, timings, etc.)  HITAG2 Settings
#define T_WAIT_1_GUARD  7

    if (turn_on) {
        // Wait 50ms with field off to be sure the transponder gets reset
        SpinDelay(50);
        FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);

        // Wait with field on to be in "Wait for START_AUTH" timeframe
        lf_wait_periods(HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4);
        *cmd_start += HITAG_T_WAIT_POWERUP + HITAG_T_WAIT_START_AUTH_MAX / 4;

    } else {
        // Wait for t_wait_2 carrier periods after the last tag bit before transmitting,
        lf_wait_periods(HITAG_T_WAIT_2_MIN + HITAG_T_WAIT_2_MIN);
        *cmd_start += (HITAG_T_WAIT_2_MIN + HITAG_T_WAIT_2_MIN);
    }

    // Transmit the reader frame
    if (send_bits) {
        *cmd_duration = hitag_reader_send_framebits(tx, txlen);
    } else {
        *cmd_duration = hitag_reader_send_frame(tx, txlen);
    }

    *resp_start = (*cmd_start + *cmd_duration);

    *resp_start += (HITAG_T_WAIT_1_MIN - T_WAIT_1_GUARD);
    // Let the antenna and ADC values settle
    // And find the position where edge sampling should start
    lf_wait_periods(HITAG_T_WAIT_1_MIN - T_WAIT_1_GUARD);
}

static bool ht2_receive(uint32_t *resp_start, uint32_t *resp_duration, uint8_t *nrz_samples, size_t *samples) {

    // Keep administration of the first edge detection
    bool waiting_for_first_edge = true;

    // Did we detected any modulaiton at all
    bool detected_tag_modulation = false;

    // Reset the number of NRZ samples and use edge detection to detect them
    size_t nrzs = 0;

    // Use the current modulation state as starting point
    uint8_t tag_modulation = lf_get_tag_modulation();

    // Raw demodulation/decoding by sampling edge periods

    while (nrzs < HT2_MAX_NRSZ) {

        // Get the timing of the next edge in number of wave periods
        size_t periods = lf_count_edge_periods(128);

        // Are we dealing with the first incoming edge
        if (waiting_for_first_edge) {

            // Just break out of loop after an initial time-out (tag is probably not available)
            if (periods == 0) {
                break;
            }

            if (tag_modulation == 0) {
                // hitag replies always start with 11111 == 1010101010, if we see 0
                // it means we missed the first period, e.g. if the signal never crossed 0 since reader signal
                // so let's add it:
                nrz_samples[nrzs++] = tag_modulation ^ 1;
                // Register the number of periods that have passed
                // we missed the begin of response but we know it happened one period of 16 earlier
                resp_start += (periods - 16);
                resp_duration = resp_start;

            } else {
                // Register the number of periods that have passed
                resp_start += periods;
                resp_duration = resp_start;
            }

            // Indicate that we have dealt with the first edge
            waiting_for_first_edge = false;
            // The first edge is always a single NRZ bit, force periods on 16
            periods = 16;
            // We have received more than 0 periods, so we have detected a tag response
            detected_tag_modulation = true;

        } else {
            // The function lf_count_edge_periods() returns 0 when a time-out occurs
            if (periods == 0) {
                break;
            }
        }
        // Evaluate the number of periods before the next edge
        if (periods > 24 && periods <= 64) {
            // Detected two sequential equal bits and a modulation switch
            // NRZ modulation: (11 => --|) or (11 __|)
            nrz_samples[nrzs++] = tag_modulation;

            if (nrzs < HT2_MAX_NRSZ) {
                nrz_samples[nrzs++] = tag_modulation;
            }

            resp_duration += periods;
            // Invert tag modulation state
            tag_modulation ^= 1;

        } else if (periods > 0 && periods <= 24) {
            // Detected one bit and a modulation switch
            // NRZ modulation: (1 => -|) or (0 _|)
            nrz_samples[nrzs++] = tag_modulation;

            resp_duration += periods;

            tag_modulation ^= 1;

        } else {
            // The function lf_count_edge_periods() returns > 64 periods, this is not a valid number periods
            break;
        }
    }

    // Make sure we always have an even number of samples. This fixes the problem
    // of ending the manchester decoding with a zero. See the example below where
    // the '|' character is end of modulation
    //  One at the end: ..._-|_____...
    // Zero at the end: ...-_|_____...
    // The last modulation change of a zero is not detected, but we should take
    // the half period in account, otherwise the demodulator will fail.
    if ((nrzs % 2) != 0) {

        if (nrzs >= HT2_MAX_NRSZ) {
            return false;
        }

        nrz_samples[nrzs++] = tag_modulation;
    }

    *samples = nrzs;

    return detected_tag_modulation;
}

bool ht2_packbits(uint8_t *nrz_samples, size_t nrzs, uint8_t *rx, size_t *rxlen) {
    // Verify if the header consists of five consecutive ones
    if (nrzs < 5) {
        return false;
    }

    // detect hitag 2 header
    if (memcmp(nrz_samples, "\x01\x01\x01\x01\x01", 5)) {
        return false;
    }

    // Pack the response into a byte array
    for (size_t i = 5; i < nrzs && *rxlen < (HITAG_FRAME_LEN << 3); i++) {

        uint8_t bit = nrz_samples[i];

        // When Manchester detects impossible symbol it writes "7"
        if (bit > 1) {
            break;
        }

        rx[*rxlen >> 3] |= bit << (7 - (*rxlen % 8));
        *rxlen = *rxlen + 1;
    }

    // skip spurious bit
    if (*rxlen % 8 == 1) {
        *rxlen = *rxlen - 1;
    }
    return true;
}
int ht2_read_uid(uint8_t *uid, bool ledcontrol, bool send_answer, bool keep_field_up) {

    g_logging = false;

    // keep field up indicates there are more traffic to be done.
    if (keep_field_up == false) {
        clear_trace();
    }


    // hitag 2 state machine?
    hitag2_init();

    // init as reader
    lf_init(true, false, true);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    uint8_t rx[HITAG_FRAME_LEN] = {0};
    size_t rxlen = 0;  // In number of bits

    uint8_t nrz_samples[HT2_MAX_NRSZ];

    uint8_t attempt_count = 3;

    int res = PM3_EFAILED;
    bool turn_on = true;

    while (attempt_count && BUTTON_PRESS() == false) {

        attempt_count--;

        WDT_HIT();

        uint32_t command_start = 0, command_duration = 0;
        uint32_t response_start = 0, response_duration = 0;

        // start AUTH command
        size_t txlen = 5;
        uint8_t tx[] = {HITAG2_START_AUTH};

        // Transmit as reader
        ht2_send(turn_on, &command_start, &command_duration, &response_start, tx, txlen, false);

        turn_on = false;

        // Reset the number of NRZ samples and use edge detection to detect them
        size_t nrzs = 0;

        // receive raw samples
        if (ht2_receive(&response_start, &response_duration, nrz_samples, &nrzs) == false) {
            continue;;
        }

        // Store the transmit frame ( TX ), we do this now at this point, to avoid delay in processing
        // and to be able to overwrite the first samples with the trace (since they currently
        // still use the same memory space)
        LogTraceBits(tx, txlen, command_start, command_start + command_duration, true);

        // decode raw samples from Manchester Encoded to bits
        manrawdecode(nrz_samples, &nrzs, true, 0);

        // pack bits to bytes
        if (ht2_packbits(nrz_samples, nrzs, rx, &rxlen) == false) {
            continue;
        }

        // log Receive data
        LogTraceBits(rx, rxlen, response_start, response_start + response_duration, false);

        if (rxlen != 32)  {
            continue;
        }

        // Store received UID
        memcpy(tag.sectors[0], rx, 4);
        if (uid) {
            memcpy(uid, rx, 4);
        }
        res = PM3_SUCCESS;
        break;
    }

    if (keep_field_up == false) {
        lf_finalize(false);
        BigBuf_free_keep_EM();
    }

    if (send_answer) {
        reply_ng(CMD_LF_HITAG_READER, res, (uint8_t *)tag.sectors, 4);
    }

    return res;
}

// This function assumes you have called hitag2_read_uid before to turn on the field :)
// tx = expects bin arrays 0,1 i
// txlen = number of bits to send
// rx =  return bin arrys
// rxlen = number of bits returned
int ht2_tx_rx(uint8_t *tx, size_t txlen, uint8_t *rx, size_t *rxlen, bool ledcontrol, bool keep_field_up) {

    int res = PM3_EFAILED;
    size_t nrzs = 0;
    uint8_t samples[HT2_MAX_NRSZ] = {0};

    uint32_t command_start = 0, command_duration = 0;
    uint32_t response_start = 0, response_duration = 0;

    // Transmit as reader
    ht2_send(false, &command_start, &command_duration, &response_start, tx, txlen, true);

    // receive raw samples
    if (ht2_receive(&response_start, &response_duration, samples, &nrzs) == false) {
        goto out;
    }

    // decode raw samples from Manchester Encoded to bits
    if (manrawdecode(samples, &nrzs, true, 0)) {
        goto out;
    }

    // pack bits to bytes
    if (rx && (ht2_packbits(samples, nrzs, rx, rxlen) == false)) {
        goto out;
    }

    res = PM3_SUCCESS;

out:
    if (keep_field_up == false) {
        lf_finalize(false);
    }
    return res;
}
