//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/Proxmark/proxmark3/pull/167/files
// Copyright (C) 2016 Oguzhan Cicek, Hendrik Schwartke, Ralf Spenneberg
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
// Hitag S emulation (preliminary test version)
//-----------------------------------------------------------------------------

#include "hitagS.h"

#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "util.h"
#include "string.h"
#include "commonutil.h"
#include "hitag2/hitag2_crypto.h"
#include "lfadc.h"
#include "crc.h"
#include "protocols.h"
#include "hitag.h"
#include "appmain.h"    // tearoff_hook()

#define CRC_PRESET 0xFF
#define CRC_POLYNOM 0x1D

static struct hitagS_tag tag = {
    .data.pages = {
                                               // Plain mode:               | Authentication mode:
            [0] = {0x5F, 0xC2, 0x11, 0x84},    // UID                       | UID
            // HITAG S 2048
            [1] = {0xCA, 0x00, 0x00, 0xAA},    // CON0 CON1 CON2 Reserved   | CON0 CON1 CON2 PWDH0
            [2] = {0x48, 0x54, 0x4F, 0x4E},    // Data                      | PWDL0 PWDL1 KEYH0 KEYH1
            [3] = {0x4D, 0x49, 0x4B, 0x52},    // Data                      | KEYL0 KEYL1 KEYL2 KEYL3
            [4] = {0xFF, 0x80, 0x00, 0x00},    // Data
            [5] = {0x00, 0x00, 0x00, 0x00},    // Data
            [6] = {0x00, 0x00, 0x00, 0x00},    // Data
            [7] = {0x57, 0x5F, 0x4F, 0x48},    // Data
            // up to index 63 for HITAG S2048 public data
        },
};
static uint8_t page_to_be_written = 0;
static int block_data_left = 0;
static bool enable_page_tearoff = false;

typedef enum modulation {
    AC2K = 0,
    AC4K,
    MC4K,
    MC8K
} MOD;

static MOD m = AC2K;                                // used modulation
static uint32_t reader_selected_uid;
static int rotate_uid = 0;
static int sof_bits;                                // number of start-of-frame bits
static uint8_t pwdh0, pwdl0, pwdl1;                 // password bytes
static uint8_t rnd[] = {0x74, 0x12, 0x44, 0x85};    // random number
//#define SENDBIT_TEST

/* array index 3 2 1 0 // bytes in sim.bin file are 0 1 2 3
UID is 0 1 2 3 // tag.data.s.uid_le is 3210
datasheet HitagS_V11.pdf bytes in tables printed 3 2 1 0

#db# UID: 5F C2 11 84
#db# conf0: C9 conf1: 00 conf2: 00
                3  2  1  0
#db# Page[ 0]: 84 11 C2 5F uid
#db# Page[ 1]: AA 00 00 C9 conf, HITAG S 256
#db# Page[ 2]: 4E 4F 54 48
#db# Page[ 3]: 52 4B 49 4D
#db# Page[ 4]: 00 00 00 00
#db# Page[ 5]: 00 00 00 00
#db# Page[ 6]: 00 00 00 00
#db# Page[ 7]: 4B 4F 5F 57 */

#define ht2bs_4a(a,b,c,d)   (~(((a|b)&c)^(a|d)^b))
#define ht2bs_4b(a,b,c,d)   (~(((d|c)&(a^b))^(d|a|b)))
#define ht2bs_5c(a,b,c,d,e) (~((((((c^e)|d)&a)^b)&(c^b))^(((d^e)|a)&((d^b)|c))))

// Sam7s has several timers, we will use the source TIMER_CLOCK3 (aka AT91C_TC_CLKS_TIMER_DIV3_CLOCK)
// TIMER_CLOCK3 = MCK/32, MCK is running at 48 MHz, Timer is running at 48MHz/32 = 1500 KHz
// Hitag units (T0) have duration of 8 microseconds (us), which is 1/125000 per second (carrier)
// T0 = TIMER_CLOCK3 / 125000 = 12

#define T0                             12

#define HITAG_FRAME_LEN                20

// TC0 and TC1 are 16-bit counters and will overflow after 5461 * T0
// Ensure not to set these timings above 5461 (~43ms) when comparing without considering overflow, as they will never reach that value.

#define HITAG_T_STOP                   36  /* T_EOF should be > 36 */
#define HITAG_T_LOW                    8   /* T_LOW should be 4..10 */
#define HITAG_T_0_MIN                  15  /* T[0] should be 18..22 */
#define HITAG_T_1_MIN                  25  /* T[1] should be 26..30 */
#define HITAG_T_0                      20  /* T[0] should be 18..22 */
#define HITAG_T_1                      28  /* T[1] should be 26..30 */
// #define HITAG_T_EOF   40 /* T_EOF should be > 36 */
#define HITAG_T_EOF                    80   /* T_EOF should be > 36 */
#define HITAG_T_WAIT_RESP              200  /* T_wresp should be 204..212 */
#define HITAG_T_WAIT_SC                200   /* T_wsc should be 90..5000 */
#define HITAG_T_WAIT_FIRST             300  /* T_wfc should be 280..565 (T_ttf) */
#define HITAG_T_PROG_MAX               750  /* T_prog should be 716..726 */

#define HITAG_T_TAG_ONE_HALF_PERIOD    10
#define HITAG_T_TAG_TWO_HALF_PERIOD    25
#define HITAG_T_TAG_THREE_HALF_PERIOD  41
#define HITAG_T_TAG_FOUR_HALF_PERIOD   57

#define HITAG_T_TAG_HALF_PERIOD        16
#define HITAG_T_TAG_FULL_PERIOD        32

#define HITAG_T_TAG_CAPTURE_ONE_HALF   13
#define HITAG_T_TAG_CAPTURE_TWO_HALF   25
#define HITAG_T_TAG_CAPTURE_THREE_HALF 41
#define HITAG_T_TAG_CAPTURE_FOUR_HALF  57

/*
 * Implementation of the crc8 calculation from Hitag S
 * from http://www.proxmark.org/files/Documents/125%20kHz%20-%20Hitag/HitagS.V11.pdf
 */
static void calc_crc(unsigned char *crc, unsigned char data, unsigned char Bitcount) {
    *crc ^= data; // crc = crc (exor) data
    do {
        if (*crc & 0x80) { // if (MSB-CRC == 1)
            *crc <<= 1; // CRC = CRC Bit-shift left
            *crc ^= CRC_POLYNOM; // CRC = CRC (exor) CRC_POLYNOM
        } else {
            *crc <<= 1; // CRC = CRC Bit-shift left
        }
    } while (--Bitcount);
}

static void update_tag_max_page(void) {
    //check which memorysize this tag has
    if ((tag.data.s.CON0 & 0x3) == 0x00) {
        tag.max_page = 32 / (HITAGS_PAGE_SIZE * 8) - 1;
    } else if ((tag.data.s.CON0 & 0x3) == 0x1) {
        tag.max_page = 256 / (HITAGS_PAGE_SIZE * 8) - 1;
    } else if ((tag.data.s.CON0 & 0x3) == 0x2) {
        tag.max_page = 2048 / (HITAGS_PAGE_SIZE * 8) - 1;
    } else {
        tag.max_page = HITAGS_MAX_PAGES - 1;
    }
}

static void hitag_send_bit(int bit, bool ledcontrol) {

    if (ledcontrol) LED_A_ON();
    // Reset clock for the next bit
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

    switch (m) {
        case AC2K: {
            if (bit == 0) {
                // AC Coding --__
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 64)  {};

            } else {
                // AC coding -_-_
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {};

                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 48) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 64) {};

            }
            if (ledcontrol) LED_A_OFF();
            break;
        }
        case AC4K: {
            if (bit == 0) {
                // AC Coding --__
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_TAG_HALF_PERIOD) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_TAG_FULL_PERIOD) {};

            } else {
                // AC coding -_-_
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 8) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};

                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 24) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {};
            }
            if (ledcontrol) LED_A_OFF();
            break;
        }
        case MC4K: {
            if (bit == 0) {
                // Manchester: Unloaded, then loaded |__--|
                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};

                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {};

            } else {
                // Manchester: Loaded, then unloaded |--__|
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 32) {};

            }
            if (ledcontrol) LED_A_OFF();
            break;
        }
        case MC8K: {
            if (bit == 0) {
                // Manchester: Unloaded, then loaded |__--|
                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 8) {};

                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};

            } else {
                // Manchester: Loaded, then unloaded |--__|
                HIGH(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 8) {};

                LOW(GPIO_SSC_DOUT);
                while (AT91C_BASE_TC0->TC_CV < T0 * 16) {};

            }
            if (ledcontrol) LED_A_OFF();
            break;
        }
        default: {
            break;
        }
    }
}

static void hitag_send_frame(const uint8_t *frame, size_t frame_len, bool ledcontrol) {

    DBG Dbprintf("hitag_send_frame: (%i) %02X %02X %02X %02X", frame_len, frame[0], frame[1], frame[2], frame[3]);

    // The beginning of the frame is hidden in some high level; pause until our bits will have an effect
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    HIGH(GPIO_SSC_DOUT);
    switch (m) {
        case AC4K:
        case MC8K: {
            while (AT91C_BASE_TC0->TC_CV < T0 * 40) {}; //FADV
            break;
        }
        case AC2K:
        case MC4K: {
            while (AT91C_BASE_TC0->TC_CV < T0 * 20) {}; //STD + ADV
            break;
        }
    }

    // SOF - send start of frame
    for (size_t i = 0; i < sof_bits; i++) {
        hitag_send_bit(1, ledcontrol);
    }

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        hitag_send_bit((frame[i / 8] >> (7 - (i % 8))) & 1, ledcontrol);
    }

    LOW(GPIO_SSC_DOUT);
}

static void hitag_reader_send_bit(int bit, bool ledcontrol) {

    if (ledcontrol) LED_A_ON();
    // Reset clock for the next bit
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    while (AT91C_BASE_TC0->TC_CV != 0);

    // Binary puls length modulation (BPLM) is used to encode the data stream
    // This means that a transmission of a one takes longer than that of a zero

    HIGH(GPIO_SSC_DOUT);

#ifdef SENDBIT_TEST
    // Wait for 4-10 times the carrier period
    while (AT91C_BASE_TC0->TC_CV < T0 * 6) {};

    LOW(GPIO_SSC_DOUT);

    if (bit == 0) {
        // Zero bit: |_-|
        while (AT91C_BASE_TC0->TC_CV < T0 * 11) {};
    } else {
        // One bit: |_--|
        while (AT91C_BASE_TC0->TC_CV < T0 * 14) {};
    }
#else
    // Wait for 4-10 times the carrier period
    while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_LOW) {};

    LOW(GPIO_SSC_DOUT);

    if (bit == 0) {
        // Zero bit: |_-|
        while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_0) {};
    } else {
        // One bit: |_--|
        while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_1) {};
    }
#endif

    if (ledcontrol) LED_A_OFF();
}

static void hitag_reader_send_frame(const uint8_t *frame, size_t frame_len, bool ledcontrol) {
    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        hitag_reader_send_bit((frame[i / 8] >> (7 - (i % 8))) & 1, ledcontrol);
    }
    // send EOF
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;
    while (AT91C_BASE_TC0->TC_CV != 0);
    HIGH(GPIO_SSC_DOUT);

    // Wait for 4-10 times the carrier period
    while (AT91C_BASE_TC0->TC_CV < T0 * HITAG_T_LOW) {};

    LOW(GPIO_SSC_DOUT);
}

static void hts_init_clock(void) {

    // Enable Peripheral Clock for
    //   Timer Counter 0, used to measure exact timing before answering
    //   Timer Counter 1, used to capture edges of the tag frames
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0) | (1 << AT91C_ID_TC1);

    AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;

    // Disable timer during configuration
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // TC0: Capture mode, clock source = MCK/32 (TIMER_CLOCK3), no triggers
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK;

    // TC1: Capture mode, clock source = MCK/32 (TIMER_CLOCK3), TIOA is external trigger,
    // external trigger falling edge, set RA on falling edge of TIOA.
    AT91C_BASE_TC1->TC_CMR =
        AT91C_TC_CLKS_TIMER_DIV3_CLOCK |    // MCK/32 (TIMER_CLOCK3)
        AT91C_TC_ETRGEDG_FALLING |          // external trigger on falling edge
        AT91C_TC_ABETRG |                   // TIOA is used as an external trigger
        AT91C_TC_LDRA_FALLING;              // load RA on on falling edge

    // Enable and reset counters
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // synchronized startup procedure
    // In theory, with MCK/32, we shouldn't be waiting longer than 32 instruction statements, right?
    while (AT91C_BASE_TC0->TC_CV != 0) {}; // wait until TC0 returned to zero

}

static void hts_stop_clock(void) {
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
}

/*
 * to check if the right uid was selected
 */
static int check_select(const uint8_t *rx, uint32_t uid) {

    // global var?
    concatbits((uint8_t *)&reader_selected_uid, 0, rx, 5, 32);
    reader_selected_uid = BSWAP_32(reader_selected_uid);

    if (reader_selected_uid == uid) {
        return 1;
    }

    return 0;
}

static void hts_set_frame_modulation(void) {
    switch (tag.mode) {
        case HT_STANDARD: {
            sof_bits = 1;
            m = MC4K;
            break;
        }
        case HT_ADVANCED: {
            sof_bits = 6;
            m = MC4K;
            break;
        }
        case HT_FAST_ADVANCED: {
            sof_bits = 6;
            m = MC8K;
            break;
        }
        default: {
            break;
        }
    }
}

/*
 * handles all commands from a reader
 */
static void hts_handle_reader_command(uint8_t *rx, const size_t rxlen,
                                      uint8_t *tx, size_t *txlen) {
    uint64_t state;
    unsigned char crc;

    // Reset the transmission frame length
    *txlen = 0;
    // Reset the frame modulation
    hts_set_frame_modulation();

    // Try to find out which command was send by selecting on length (in bits)
    switch (rxlen) {
        case 5: {
            //UID request with a selected response protocol mode
            DBG Dbprintf("UID request: length: %i first byte: %02x", rxlen, rx[0]);
            tag.pstate = HT_READY;
            tag.tstate = HT_NO_OP;

            if (rx[0] == HITAGS_UID_REQ_STD) {
                DBG Dbprintf("HT_STANDARD");
                tag.mode = HT_STANDARD;
                sof_bits = 1;
                m = AC2K;
            }

            if (rx[0] == HITAGS_UID_REQ_ADV) {
                DBG Dbprintf("HT_ADVANCED");
                tag.mode = HT_ADVANCED;
                sof_bits = 3;
                m = AC2K;
            }

            if (rx[0] == HITAGS_UID_REQ_FADV) {
                DBG Dbprintf("HT_FAST_ADVANCED");
                tag.mode = HT_FAST_ADVANCED;
                sof_bits = 3;
                m = AC4K;
            }
            //send uid as a response
            *txlen = 32;
            memcpy(tx, tag.data.pages[HITAGS_UID_PADR], HITAGS_PAGE_SIZE);
            break;
        }
        // case 14 to 44 AC SEQUENCE
        case 45: {
            //select command from reader received
            DBG DbpString("SELECT");

            if ((rx[0] & 0xf8) == HITAGS_SELECT && check_select(rx, BSWAP_32(tag.data.s.uid_le)) == 1) {

                DBG DbpString("SELECT match");

                //if the right tag was selected
                *txlen = 32;

                //send configuration
                memcpy(tx, tag.data.pages[HITAGS_CONFIG_PADR], HITAGS_PAGE_SIZE - 1);

                tx[3] = 0xff;

                if (tag.mode != HT_STANDARD) {
                    //add crc8
                    *txlen += 8;
                    crc = CRC_PRESET;

                    for (int i = 0; i < 4; i++) {
                        calc_crc(&crc, tx[i], 8);
                    }

                    tx[4] = crc;
                }
            }
            break;
        }
        case 64: {
            //challenge message received
            DBG Dbprintf("Challenge for UID: %X", reader_selected_uid);

            rotate_uid++;
            *txlen = 32;
            // init crypt engine
            state = ht2_hitag2_init(reflect48(tag.data.s.key), reflect32(tag.data.s.uid_le), reflect32(*(uint32_t *)rx));
            DBG Dbhexdump(8, tx, false);

            for (int i = 0; i < 4; i++) {
                ht2_hitag2_byte(&state);
            }

            //send con2, pwdh0, pwdl0, pwdl1 encrypted as a response
            tx[0] = ht2_hitag2_byte(&state) ^ tag.data.pages[HITAGS_CONFIG_PADR][2];
            tx[1] = ht2_hitag2_byte(&state) ^ tag.data.s.pwdh0;
            tx[2] = ht2_hitag2_byte(&state) ^ tag.data.s.pwdl0;
            tx[3] = ht2_hitag2_byte(&state) ^ tag.data.s.pwdl1;

            if (tag.mode != HT_STANDARD) {
                //add crc8
                *txlen += 8;
                crc = CRC_PRESET;
                calc_crc(&crc, tag.data.pages[HITAGS_CONFIG_PADR][2], 8);
                calc_crc(&crc, tag.data.s.pwdh0, 8);
                calc_crc(&crc, tag.data.s.pwdl0, 8);
                calc_crc(&crc, tag.data.s.pwdl1, 8);
                tx[4] = (crc ^ ht2_hitag2_byte(&state));
            }
            /*
             * some readers do not allow to authenticate multiple times in a row with the same tag.
             * use this to change the uid between authentications.

             if (rotate_uid % 2 == 0) {
                 tag.data.s.uid_le = 0x44332211;
             } else {
                 tag.data.s.uid_le = 0x88776655;
             }
             */
            break;
        }
        case 40: {
            DBG Dbprintf("WRITE DATA");

            //data received to be written
            if (tag.tstate == HT_WRITING_PAGE_DATA) {
                tag.tstate = HT_NO_OP;
                memcpy(tag.data.pages[page_to_be_written], rx, HITAGS_PAGE_SIZE);
                //send ack
                *txlen = 2;
                tx[0] = 0x40;
                page_to_be_written = 0;

            } else if (tag.tstate == HT_WRITING_BLOCK_DATA) {
                memcpy(tag.data.pages[page_to_be_written], rx, HITAGS_PAGE_SIZE);
                //send ack
                *txlen = 2;
                tx[0] = 0x40;
                page_to_be_written++;
                block_data_left--;

                if (block_data_left == 0) {
                    tag.tstate = HT_NO_OP;
                    page_to_be_written = 0;
                }
            }
            break;
        }
        case 20: {
            //write page, write block, read page or read block command received
            uint8_t page = ((rx[0] & 0x0f) << 4) + ((rx[1] & 0xf0) >> 4);
            // TODO: handle over max_page readonly to 00000000. 82xx mode
            if (page > tag.max_page) {
                *txlen = 0;
                break;
            }

            if ((rx[0] & 0xf0) == HITAGS_READ_PAGE) { //read page
                //send page data
                *txlen = 32;
                memcpy(tx, tag.data.pages[page], HITAGS_PAGE_SIZE);

                if (tag.data.s.auth && page == HITAGS_CONFIG_PADR) {
                    tx[3] = 0xFF;
                }

                if (tag.mode != HT_STANDARD) {
                    //add crc8
                    *txlen += 8;
                    crc = CRC_PRESET;
                    for (int i = 0; i < 4; i++) {
                        calc_crc(&crc, tx[i], 8);
                    }
                    tx[4] = crc;
                }

                if (tag.data.s.auth && tag.data.s.LKP && (page == 2 || page == 3)) {
                    //if reader asks for key or password and the LKP-mark is set do not respond
                    *txlen = 0;
                }

            } else if ((rx[0] & 0xf0) == HITAGS_READ_BLOCK) { //read block
                // TODO: handle auth LKP
                *txlen = (HITAGS_BLOCK_SIZE - (page % 4) * HITAGS_PAGE_SIZE) * 8;

                //send page,...,page+3 data
                memcpy(tx, tag.data.pages[page], *txlen / 8);

                if (tag.mode != HT_STANDARD) {
                    //add crc8
                    crc = CRC_PRESET;
                    for (int i = 0; i < *txlen / 8; i++) {
                        calc_crc(&crc, tx[i], 8);
                    }
                    *txlen += 8;
                    tx[16] = crc;
                }

            } else if ((rx[0] & 0xf0) == HITAGS_WRITE_PAGE) { //write page
                // TODO: handle con2 LCK*
                if ((tag.data.s.LCON && page == 1)
                        || (tag.data.s.LKP && (page == 2 || page == 3))) {
                    //deny
                    *txlen = 0;
                } else {
                    //allow
                    *txlen = 2;
                    tx[0] = 0x40;
                    page_to_be_written = page;
                    tag.tstate = HT_WRITING_PAGE_DATA;
                }

            } else if ((rx[0] & 0xf0) == HITAGS_WRITE_BLOCK) { //write block
                // TODO: handle LCON con2 LCK*
                if ((tag.data.s.LCON && page == 1)
                        || (tag.data.s.LKP && (page == 2 || page == 3))) {
                    //deny
                    *txlen = 0;
                } else {
                    //allow
                    *txlen = 2;
                    tx[0] = 0x40;
                    page_to_be_written = page;
                    block_data_left = 4 - (page % 4);
                    tag.tstate = HT_WRITING_BLOCK_DATA;
                }
            }
            break;
        }
        default: {
            DBG Dbprintf("unknown rxlen: (%i) %02X %02X %02X %02X ...", rxlen, rx[0], rx[1], rx[2], rx[3]);
            break;
        }
    }
}

/*
 * Emulates a Hitag S Tag with the given data from the .hts file
 */
void hts_simulate(bool tag_mem_supplied, const uint8_t *data, bool ledcontrol) {

    StopTicks();

    int response = 0, overflow = 0;
    uint8_t rx[HITAG_FRAME_LEN];
    size_t rxlen = 0;
    uint8_t tx[HITAG_FRAME_LEN];
    size_t txlen = 0;

    // Reset the received frame, frame count and timing info
    memset(rx, 0x00, sizeof(rx));

    // free eventually allocated BigBuf memory
    BigBuf_free();
    BigBuf_Clear_ext(false);

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    DbpString("Starting Hitag S simulation");

    tag.pstate = HT_READY;
    tag.tstate = HT_NO_OP;

    // read tag data into memory
    if (tag_mem_supplied) {
        DbpString("Loading hitag S memory...");
        memcpy(tag.data.pages, data, HITAGS_MAX_BYTE_SIZE);
    } else {
        // use the last read tag
    }

    // max_page
    update_tag_max_page();

    for (int i = 0; i < tag.max_page; i++) {
        DBG Dbprintf("Page[%2d]: %02X %02X %02X %02X",
                     i,
                     tag.data.pages[i][3],
                     tag.data.pages[i][2],
                     tag.data.pages[i][1],
                     tag.data.pages[i][0]
                    );
    }


    // Set up simulator mode, frequency divisor which will drive the FPGA
    // and analog mux selection.
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125); //125kHz
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Configure output pin that is connected to the FPGA (for modulating)
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;

    // Disable modulation at default, which means release resistance
    LOW(GPIO_SSC_DOUT);

    // Enable Peripheral Clock for
    //   Timer Counter 0, used to measure exact timing before answering
    //   Timer Counter 1, used to capture edges of the tag frames
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0) | (1 << AT91C_ID_TC1);

    AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;

    // Disable timer during configuration
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // TC0: Capture mode, default timer source = MCK/32 (TIMER_CLOCK3), no triggers
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK;

    // TC1: Capture mode, default timer source = MCK/32 (TIMER_CLOCK3), TIOA is external trigger,
    // external trigger rising edge, load RA on rising edge of TIOA.
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK
                             | AT91C_TC_ETRGEDG_RISING | AT91C_TC_ABETRG | AT91C_TC_LDRA_RISING;

    // Enable and reset counter
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // synchronized startup procedure
    while (AT91C_BASE_TC0->TC_CV != 0); // wait until TC0 returned to zero

    if (ledcontrol) LED_D_ON();

    while ((BUTTON_PRESS() == false) && (data_available() == false)) {

        WDT_HIT();

        // Receive frame, watch for at most T0*EOF periods
        while (AT91C_BASE_TC1->TC_CV < T0 * HITAG_T_EOF) {

            // Check if rising edge in modulation is detected
            if (AT91C_BASE_TC1->TC_SR & AT91C_TC_LDRAS) {

                // Retrieve the new timing values
                int ra = (AT91C_BASE_TC1->TC_RA / T0) + overflow;
                overflow = 0;

                // Reset timer every frame, we have to capture the last edge for timing
                AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

                if (ledcontrol) LED_B_ON();

                // Capture reader frame
                if (ra >= HITAG_T_STOP) {
                    if (rxlen != 0) {
                        //DbpString("weird0?");
                    }
                    // Capture the T0 periods that have passed since last communication or field drop (reset)
                    response = (ra - HITAG_T_LOW);
                } else if (ra >= HITAG_T_1_MIN) {
                    // '1' bit
                    rx[rxlen / 8] |= 1 << (7 - (rxlen % 8));
                    rxlen++;
                } else if (ra >= HITAG_T_0_MIN) {
                    // '0' bit
                    rx[rxlen / 8] |= 0 << (7 - (rxlen % 8));
                    rxlen++;
                } else {
                    // Ignore weird value, is to small to mean anything
                }
            }
        }

        // Check if frame was captured
        if (rxlen > 0) {
            LogTraceBits(rx, rxlen, response, response, true);

            // Disable timer 1 with external trigger to avoid triggers during our own modulation
            AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

            // Process the incoming frame (rx) and prepare the outgoing frame (tx)
            hts_handle_reader_command(rx, rxlen, tx, &txlen);

            // Wait for HITAG_T_WAIT_RESP carrier periods after the last reader bit,
            // not that since the clock counts since the rising edge, but T_Wait1 is
            // with respect to the falling edge, we need to wait actually (T_Wait1 - T_Low)
            // periods. The gap time T_Low varies (4..10). All timer values are in
            // terms of T0 units
            while (AT91C_BASE_TC0->TC_CV < T0 * (HITAG_T_WAIT_RESP - HITAG_T_LOW)) {};

            // Send and store the tag answer (if there is any)
            if (txlen > 0) {
                // Transmit the tag frame
                hitag_send_frame(tx, txlen, ledcontrol);
                LogTraceBits(tx, txlen, 0, 0, false);
            }

            // Enable and reset external trigger in timer for capturing future frames
            AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

            // Reset the received frame and response timing info
            memset(rx, 0x00, sizeof(rx));
            response = 0;

            if (ledcontrol) LED_B_OFF();
        }
        // Reset the frame length
        rxlen = 0;
        // Save the timer overflow, will be 0 when frame was received
        overflow += (AT91C_BASE_TC1->TC_CV / T0);
        // Reset the timer to restart while-loop that receives frames
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_SWTRG;

    }

    set_tracing(false);
    lf_finalize(ledcontrol);
    // release allocated memory from BigBuff.
    BigBuf_free();

    DbpString("Sim stopped");
}

static void hts_receive_frame(uint8_t *rx, size_t sizeofrx, size_t *rxlen, uint32_t *resptime, bool ledcontrol) {

    // Reset values for receiving frames
    memset(rx, 0x00, sizeofrx);
    *rxlen = 0;

    int lastbit = 1;
    bool bSkip = true;
    *resptime = 0;
    uint32_t errorCount = 0;
    bool bStarted = false;

    uint32_t ra_i = 0, h2 = 0, h3 = 0, h4 = 0;
    uint8_t edges[160] = {0};

    // Dbprintf("TC0_CV:%i TC1_CV:%i TC1_RA:%i", AT91C_BASE_TC0->TC_CV, AT91C_BASE_TC1->TC_CV ,AT91C_BASE_TC1->TC_RA);

    // Receive tag frame, watch for at most T0*HITAG_T_PROG_MAX periods
    while (AT91C_BASE_TC0->TC_CV < (T0 * HITAG_T_PROG_MAX)) {

        // Check if falling edge in tag modulation is detected
        if (AT91C_BASE_TC1->TC_SR & AT91C_TC_LDRAS) {

            // Retrieve the new timing values
            uint32_t ra = AT91C_BASE_TC1->TC_RA / T0;
            edges[ra_i++] = ra;
            // Reset timer every frame, we have to capture the last edge for timing
            AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

            if (ledcontrol) LED_B_ON();

            // Capture tag frame (manchester decoding using only falling edges)

            if (bStarted == false) {

                // Capture the T0 periods that have passed since last communication or field drop (reset)
                *resptime = ra - HITAG_T_TAG_HALF_PERIOD;

                if (ra >= HITAG_T_WAIT_RESP) {
                    bStarted = true;

                    // We always receive a 'one' first, which has the falling edge after a half period |-_|
                    rx[0] = 0x80;
                    (*rxlen)++;
                } else {
                    errorCount++;
                }

            } else if (ra >= HITAG_T_TAG_CAPTURE_FOUR_HALF) {

                // Manchester coding example |-_|_-|-_| (101)
                rx[(*rxlen) / 8] |= 0 << (7 - ((*rxlen) % 8));
                (*rxlen)++;

                rx[(*rxlen) / 8] |= 1 << (7 - ((*rxlen) % 8));
                (*rxlen)++;
                h4++;
            } else if (ra >= HITAG_T_TAG_CAPTURE_THREE_HALF) {

                // Manchester coding example |_-|...|_-|-_| (0...01)
                rx[(*rxlen) / 8] |= 0 << (7 - ((*rxlen) % 8));
                (*rxlen)++;

                // We have to skip this half period at start and add the 'one' the second time
                if (bSkip == false) {
                    rx[(*rxlen) / 8] |= 1 << (7 - ((*rxlen) % 8));
                    (*rxlen)++;
                }

                lastbit = !lastbit;
                bSkip = !bSkip;
                h3++;
            } else if (ra >= HITAG_T_TAG_CAPTURE_TWO_HALF) {
                // Manchester coding example |_-|_-| (00) or |-_|-_| (11)
                // bit is same as last bit
                rx[(*rxlen) / 8] |= lastbit << (7 - ((*rxlen) % 8));
                (*rxlen)++;
                h2++;
            } else {
                // Ignore weird value, is to small to mean anything
                errorCount++;
            }
        }

        // if we saw over 100 weird values break it probably isn't hitag...
        if (errorCount > 100 || (*rxlen) / 8 >= sizeofrx) {
            break;
        }

        // We can break this loop if we received the last bit from a frame
        // max periods between 2 falling edge
        // RTF AC64 |--__|--__| (00) 64 * T0
        // RTF MC32 |_-|-_|_-| (010) 48 * T0
        if (AT91C_BASE_TC1->TC_CV > (T0 * 80)) {
            if ((*rxlen)) {
                break;
            }
        }
    }

    DBG Dbprintf("RX0 %i:%02X.. err:%i resptime:%i h2:%i h3:%i h4:%i edges:", *rxlen, rx[0], errorCount, *resptime, h2, h3, h4);
    DBG Dbhexdump(ra_i, edges, false);
}

static int hts_send_receive(const uint8_t *tx, size_t txlen, uint8_t *rx, size_t sizeofrx, size_t *prxbits, int t_wait, bool ledcontrol, bool ac_seq) {

    LogTraceBits(tx, txlen, HITAG_T_WAIT_SC, HITAG_T_WAIT_SC, true);

    // Send and store the reader command
    // Disable timer 1 with external trigger to avoid triggers during our own modulation
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // Wait for HITAG_T_WAIT_SC carrier periods after the last tag bit before transmitting,
    // Since the clock counts since the last falling edge, a 'one' means that the
    // falling edge occurred halfway the period. with respect to this falling edge,
    // we need to wait (T_Wait2 + half_tag_period) when the last was a 'one'.
    // All timer values are in terms of T0 units
    while (AT91C_BASE_TC0->TC_CV < T0 * t_wait) {};

    // Transmit the reader frame
    hitag_reader_send_frame(tx, txlen, ledcontrol);

    if (enable_page_tearoff && tearoff_hook() == PM3_ETEAROFF) {
        return PM3_ETEAROFF;
    }

    // Enable and reset external trigger in timer for capturing future frames
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    uint32_t resptime = 0;
    size_t rxlen = 0;
    hts_receive_frame(rx, sizeofrx, &rxlen, &resptime, ledcontrol);
    int k = 0;

    // Check if frame was captured and store it
    if (rxlen > 0) {

        uint8_t response_bit[sizeofrx * 8];

        for (size_t i = 0; i < rxlen; i++) {
            response_bit[i] = (rx[i / 8] >> (7 - (i % 8))) & 1;
        }

        DBG Dbprintf("htS: rxlen...... %zu", rxlen);
        DBG Dbprintf("htS: sizeofrx... %zu", sizeofrx);
        DBG DbpString("htS: response_bit:");
        DBG Dbhexdump(rxlen, response_bit, false);

        memset(rx, 0x00, sizeofrx);

        if (ac_seq) {

            // Tag Response is AC encoded
            // We used UID Request Advanced,  meaning AC SEQ SOF is  111.
            for (int i = 7; i < rxlen; i += 2) {

                rx[k / 8] |= response_bit[i] << (7 - (k % 8));

                k++;

                if (k > 8 * sizeofrx) {
                    break;
                }
            }

            // TODO: It's very confusing to reinterpreter the MC to AC; we should implement a more straightforward approach.
            // add the lost bit zero, when AC64 last bit is zero
            if (k % 8 == 7) {
                k++;
            }

            if (g_dbglevel >= DBG_EXTENDED) {
                DbpString("htS: ac sequence compress");
                Dbhexdump(k / 8, rx, false);
            }

        } else {

            if (g_dbglevel >= DBG_EXTENDED) {
                DbpString("htS: skipping 6 bit header");
            }

            // ignore first 6 bits: SOF (actually 1 or 6 depending on response protocol)
            // or rather a header.
            for (size_t i = 6; i < rxlen; i++) {

                rx[k / 8] |= response_bit[i] << (7 - (k % 8));
                k++;

                if (k > 8 * sizeofrx) {
                    break;
                }
            }
        }
        LogTraceBits(rx, k, resptime, resptime, false);
    }
    *prxbits = k;

    return PM3_SUCCESS;
}

static int hts_select_tag(const lf_hitag_data_t *packet, uint8_t *tx, size_t sizeoftx, uint8_t *rx, size_t sizeofrx, int t_wait, bool ledcontrol) {

    StopTicks();

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    if (ledcontrol) LED_D_ON();

    hts_init_clock();

    // Set fpga in edge detect with reader field, we can modulate as reader now
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | FPGA_LF_EDGE_DETECT_READER_FIELD);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125); //125kHz
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Configure output and enable pin that is connected to the FPGA (for modulating)
    AT91C_BASE_PIOA->PIO_OER |= GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_PER |= GPIO_SSC_DOUT;

    // Disable modulation at default, which means enable the field
    LOW(GPIO_SSC_DOUT);

    // UID request standard   00110
    // UID request Advanced   1100x
    // UID request FAdvanced  11010
    size_t txlen = 0;
    size_t rxlen = 0;
    uint8_t cmd = HITAGS_UID_REQ_ADV;
    txlen = concatbits(tx, txlen, &cmd, 0, 5);
    hts_send_receive(tx, txlen, rx, sizeofrx, &rxlen, t_wait, ledcontrol, true);

    if (rxlen != 32) {
        DbpString("UID Request failed!");
        return -1;
    }

    memcpy(tag.data.pages[HITAGS_UID_PADR], rx, HITAGS_PAGE_SIZE);

    DBG Dbprintf("UID... %02X%02X%02X%02X", rx[0], rx[1], rx[2], rx[3]);

    // select uid
    txlen = 0;
    cmd = HITAGS_SELECT;
    txlen = concatbits(tx, txlen, &cmd, 0, 5);
    txlen = concatbits(tx, txlen, rx, 0, 32);
    uint8_t crc = CRC8Hitag1Bits(tx, txlen);
    txlen = concatbits(tx, txlen, &crc, 0, 8);

    hts_send_receive(tx, txlen, rx, sizeofrx, &rxlen, HITAG_T_WAIT_SC, ledcontrol, false);

    if (rxlen != 40) {
        Dbprintf("Select UID failed! %i", rxlen);
        return -1;
    }

    memcpy(tag.data.pages[HITAGS_CONFIG_PADR], rx, HITAGS_PAGE_SIZE - 1);

    update_tag_max_page();

    DBG Dbprintf("conf 0: %02X conf 1: %02X conf 2: %02X", tag.data.pages[HITAGS_CONFIG_PADR][0], tag.data.pages[HITAGS_CONFIG_PADR][1], tag.data.pages[HITAGS_CONFIG_PADR][2]);

    if (tag.data.s.auth == 1) {

        uint64_t key_le = 0;
        // if the tag is in authentication mode try the key or challenge
        if (packet->cmd == HTSF_KEY) {

            DBG DbpString("Authenticating using key:");
            DBG Dbhexdump(6, packet->key, false);

            key_le = *(uint64_t *)packet->key;

            uint64_t state = ht2_hitag2_init(reflect48(key_le), reflect32(tag.data.s.uid_le), reflect32(*(uint32_t*)rnd));

            uint8_t auth_ks[4];
            for (int i = 0; i < 4; i++) {
                auth_ks[i] = ht2_hitag2_byte(&state) ^ 0xff;
            }

            txlen = 0;
            txlen = concatbits(tx, txlen, rnd, 0, 32);
            txlen = concatbits(tx, txlen, auth_ks, 0, 32);

            DBG Dbprintf("%02X %02X %02X %02X %02X %02X %02X %02X", tx[0], tx[1], tx[2], tx[3], tx[4], tx[5], tx[6], tx[7]);

        } else if (packet->cmd == HTSF_CHALLENGE) {

            DBG DbpString("Authenticating using nr,ar pair:");
            DBG Dbhexdump(8, packet->NrAr, false);

            uint64_t NrAr = 0;
            NrAr = ((uint64_t)packet->NrAr[7]) <<  0 |
                   ((uint64_t)packet->NrAr[6]) <<  8 |
                   ((uint64_t)packet->NrAr[5]) << 16 |
                   ((uint64_t)packet->NrAr[4]) << 24 |
                   ((uint64_t)packet->NrAr[3]) << 32 |
                   ((uint64_t)packet->NrAr[2]) << 40 |
                   ((uint64_t)packet->NrAr[1]) << 48 |
                   ((uint64_t)packet->NrAr[0]) << 56;

            txlen = 64;
            for (int i = 0; i < 8; i++) {
                tx[i] = ((NrAr >> (56 - (i * 8))) & 0xFF);
            }

        } else if (packet->cmd == HTSF_82xx) {
            // 8268/8310 Authentication by writing password to block 64

            // send write page request
            txlen = 0;
            cmd = HITAGS_WRITE_PAGE;
            txlen = concatbits(tx, txlen, &cmd, 0, 4);

            uint8_t addr = 64;
            txlen = concatbits(tx, txlen, &addr, 0, 8);

            crc = CRC8Hitag1Bits(tx, txlen);
            txlen = concatbits(tx, txlen, &crc, 0, 8);

            hts_send_receive(tx, txlen, rx, sizeofrx, &rxlen, HITAG_T_WAIT_SC, ledcontrol, false);

            if ((rxlen != 2) || (rx[0] >> (8 - 2) != 0x01)) {
                Dbprintf("no write access on page " _YELLOW_("64") ". not 82xx?");
                return -1;
            }

            txlen = 0;
            txlen = concatbits(tx, txlen, packet->pwd, 0, 32);
            crc = CRC8Hitag1Bits(tx, txlen);
            txlen = concatbits(tx, txlen, &crc, 0, 8);

            hts_send_receive(tx, txlen, rx, sizeofrx, &rxlen, HITAG_T_WAIT_SC, ledcontrol, false);

            if ((rxlen != 2) || (rx[0] >> (8 - 2) != 0x01)) {
                Dbprintf("write to page " _YELLOW_("64") " failed! wrong password?");
                return -1;
            }

            return 0;
        } else if (packet->cmd == HTSF_PLAIN) {
            Dbprintf("Error, " _YELLOW_("AUT=1") " This tag is configured in Authentication Mode");
            return -1;
        } else {
            Dbprintf("Error, unknown function: " _RED_("%d"), packet->cmd);
            return -1;
        }

        hts_send_receive(tx, txlen, rx, sizeofrx, &rxlen, HITAG_T_WAIT_SC, ledcontrol, false);

        if (rxlen != 40) {
            Dbprintf("Authenticate failed! " _RED_("%i"), rxlen);
            return -1;
        }

        //encrypted con2,password received.
        DBG Dbprintf("UID... %08X", BSWAP_32(tag.data.s.uid_le));
        DBG Dbprintf("RND... %02X%02X%02X%02X", rnd[0], rnd[1], rnd[2], rnd[3]);

        //decrypt password
        pwdh0 = 0;
        pwdl0 = 0;
        pwdl1 = 0;
        if (packet->cmd == HTSF_KEY) {

            uint64_t state = ht2_hitag2_init(reflect48(key_le), reflect32(tag.data.s.uid_le), reflect32(*(uint32_t *)rnd));
            for (int i = 0; i < 4; i++) {
                ht2_hitag2_byte(&state);
            }

            uint8_t con2 = rx[0] ^ ht2_hitag2_byte(&state);
            pwdh0 = rx[1] ^ ht2_hitag2_byte(&state);
            pwdl0 = rx[2] ^ ht2_hitag2_byte(&state);
            pwdl1 = rx[3] ^ ht2_hitag2_byte(&state);

            DBG Dbprintf("con2 %02X pwdh0 %02X pwdl0 %02X pwdl1 %02X", con2, pwdh0, pwdl0, pwdl1);
        }
    }
    return 0;
}

/*
 * Authenticates to the Tag with the given key or challenge.
 * If the key was given the password will be decrypted.
 * Reads every page of a hitag S transpoder.
 */
void hts_read(const lf_hitag_data_t *payload, bool ledcontrol) {

    uint8_t rx[HITAG_FRAME_LEN] = { 0x00 };
    uint8_t tx[HITAG_FRAME_LEN] = { 0x00 };

    int status = PM3_SUCCESS;
    if (hts_select_tag(payload, tx, ARRAYLEN(tx), rx, ARRAYLEN(rx), HITAG_T_WAIT_FIRST, ledcontrol) == -1) {
        status = PM3_ERFTRANS;
        goto read_end;
    }

    int pageNum = 0;

    while ((BUTTON_PRESS() == false) && (data_available() == false)) {

        WDT_HIT();

        size_t rxlen = 0;

        //send read request
        size_t txlen = 0;
        uint8_t cmd = HITAGS_READ_PAGE;
        txlen = concatbits(tx, txlen, &cmd, 0, 4);
        uint8_t addr = pageNum;
        txlen = concatbits(tx, txlen, &addr, 0, 8);
        uint8_t crc = CRC8Hitag1Bits(tx, txlen);
        txlen = concatbits(tx, txlen, &crc, 0, 8);

        hts_send_receive(tx, txlen, rx, ARRAYLEN(rx), &rxlen, HITAG_T_WAIT_SC, ledcontrol, false);

        if (rxlen != 40) {
            DBG Dbprintf("Read page failed!");
            status = PM3_ERFTRANS;
            goto read_end;
        }

        //save received data - 40 bits
        for (int i = 0; i < 4 && i < rxlen; i++) {   // set page bytes from received bits
            tag.data.pages[pageNum][i] = rx[i];
        }

        if (g_dbglevel >= DBG_EXTENDED) {
            if (tag.data.s.auth && tag.data.s.LKP && pageNum == 1) {
                DBG Dbprintf("Page[%2d]: %02X %02X %02X %02X", pageNum, pwdh0,
                             tag.data.pages[pageNum][2],
                             tag.data.pages[pageNum][1],
                             tag.data.pages[pageNum][0]);
            } else {
                DBG Dbprintf("Page[%2d]: %02X %02X %02X %02X", pageNum,
                             tag.data.pages[pageNum][3],
                             tag.data.pages[pageNum][2],
                             tag.data.pages[pageNum][1],
                             tag.data.pages[pageNum][0]);
            }
        }

        pageNum++;
        //display key and password if possible
        if (pageNum == 2 && tag.data.s.auth == 1 && tag.data.s.LKP) {
            if (payload->cmd == HTSF_KEY) {
                DBG Dbprintf("Page[ 2]: %02X %02X %02X %02X",
                             payload->key[1],
                             payload->key[0],
                             pwdl1,
                             pwdl0
                            );
                DBG Dbprintf("Page[ 3]: %02X %02X %02X %02X",
                             payload->key[5],
                             payload->key[4],
                             payload->key[3],
                             payload->key[2]
                            );
            } else {
                //if the authentication is done with a challenge the key and password are unknown
                DBG Dbprintf("Page[ 2]: __ __ __ __");
                DBG Dbprintf("Page[ 3]: __ __ __ __");
            }
            // since page 2+3 are not accessible when LKP == 1 and AUT == 1 fastforward to next readable page
            pageNum = 4;
        }

        if (pageNum >= tag.max_page) {
            break;
        }
    }

read_end:
    hts_stop_clock();
    set_tracing(false);
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_HITAGS_READ, status, (uint8_t *)tag.data.pages, sizeof(tag.data.pages));
}

/*
 * Authenticates to the Tag with the given Key or Challenge.
 * Writes the given 32Bit data into page_
 */
void hts_write_page(const lf_hitag_data_t *payload, bool ledcontrol) {

    //check for valid input
    if (payload->page == 0) {
        DBG Dbprintf("Warning, write page 0");
    }

    uint8_t rx[HITAG_FRAME_LEN];
    size_t rxlen = 0;

    uint8_t tx[HITAG_FRAME_LEN];
    size_t txlen = 0;

    int res = PM3_ESOFT;

    if (hts_select_tag(payload, tx, ARRAYLEN(tx), rx, ARRAYLEN(rx), HITAG_T_WAIT_FIRST, ledcontrol) == -1) {
        res = PM3_ERFTRANS;
        goto write_end;
    }

    //check if the given page exists
    if (payload->page > tag.max_page) {
        DBG Dbprintf("Warning, page number too large");
        // 82xx CON0 is fully modifiable
    }

    //send write page request
    txlen = 0;

    uint8_t cmd = HITAGS_WRITE_PAGE;
    txlen = concatbits(tx, txlen, &cmd, 0, 4);

    uint8_t addr = payload->page;
    txlen = concatbits(tx, txlen, &addr, 0, 8);

    uint8_t crc = CRC8Hitag1Bits(tx, txlen);
    txlen = concatbits(tx, txlen, &crc, 0, 8);

    hts_send_receive(tx, txlen, rx, ARRAYLEN(rx), &rxlen, HITAG_T_WAIT_SC, ledcontrol, false);

    if ((rxlen != 2) || (rx[0] >> (8 - 2) != 0x01)) {
        DBG Dbprintf("no write access on page " _YELLOW_("%d"), payload->page);
        res = PM3_ESOFT;
        goto write_end;
    }

    // //ACK received to write the page. send data
    // uint8_t data[4] = {0, 0, 0, 0};
    // switch (payload->cmd) {
    //     case HTSF_PLAIN:
    //     case HTSF_CHALLENGE:
    //     case HTSF_KEY:
    //         data[0] = payload->data[3];
    //         data[1] = payload->data[2];
    //         data[2] = payload->data[1];
    //         data[3] = payload->data[0];
    //         break;
    //     default: {
    //         res = PM3_EINVARG;
    //         goto write_end;
    //     }
    // }

    txlen = 0;
    txlen = concatbits(tx, txlen, payload->data, 0, 32);
    crc = CRC8Hitag1Bits(tx, txlen);
    txlen = concatbits(tx, txlen, &crc, 0, 8);

    enable_page_tearoff = g_tearoff_enabled;

    if (hts_send_receive(tx, txlen, rx, ARRAYLEN(rx), &rxlen, HITAG_T_WAIT_SC, ledcontrol, false) == PM3_ETEAROFF) {
        res = PM3_ETEAROFF;
        enable_page_tearoff = false;
        goto write_end;
    }

    if ((rxlen != 2) || (rx[0] >> (8 - 2) != 0x01)) {
        res = PM3_ESOFT; //  write failed
    } else {
        res = PM3_SUCCESS;
    }

write_end:
    hts_stop_clock();
    set_tracing(false);
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_HITAGS_WRITE, res, NULL, 0);
}

int hts_read_uid(uint32_t *uid, bool ledcontrol, bool send_answer) {

    StopTicks();

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    if (ledcontrol) LED_D_ON();

    hts_init_clock();

    // Set fpga in edge detect with reader field, we can modulate as reader now
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | FPGA_LF_EDGE_DETECT_READER_FIELD);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125); //125kHz
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Configure output and enable pin that is connected to the FPGA (for modulating)
    AT91C_BASE_PIOA->PIO_OER |= GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_PER |= GPIO_SSC_DOUT;

    // Disable modulation at default, which means enable the field
    LOW(GPIO_SSC_DOUT);

    // UID request standard   00110
    // UID request Advanced   1100x
    // UID request FAdvanced  11010
    uint8_t cmd = HITAGS_UID_REQ_ADV;

    size_t rxlen = 0;
    uint8_t rx[HITAG_FRAME_LEN] = { 0x00 };

    size_t txlen = 0;
    uint8_t tx[HITAG_FRAME_LEN] = { 0x00 };

    txlen = concatbits(tx, txlen, &cmd, 0, 5);

    hts_send_receive(tx, txlen, rx, ARRAYLEN(rx), &rxlen, HITAG_T_WAIT_FIRST, ledcontrol, true);

    int status = PM3_SUCCESS;
    if (rxlen == 32) {

        memcpy(tag.data.pages[0], rx, HITAGS_PAGE_SIZE);

        if (uid) {
            *uid = BSWAP_32(tag.data.s.uid_le);
        }

    } else {
        DBG DbpString("UID Request failed!");
        status = PM3_ERFTRANS;
    }

    hts_stop_clock();
    set_tracing(false);
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_HITAGS_UID, status, (uint8_t *)tag.data.pages, sizeof(tag.data.pages));
    return status;
}

/*
 * Tries to authenticate to a Hitag S Transponder with the given challenges from a .cc file.
 * Displays all Challenges that failed.
 * When collecting Challenges to break the key it is possible that some data
 * is not received correctly due to Antenna problems. This function
 * detects these challenges.
 */
void hts_check_challenges(const uint8_t *data, uint32_t datalen, bool ledcontrol) {

    //check for valid input
    if (datalen < 8) {
        DBG Dbprintf("Error, missing challenges");
        reply_ng(CMD_LF_HITAGS_TEST_TRACES, PM3_EINVARG, NULL, 0);
        return;
    }
    uint32_t dataoffset = 0;

    uint8_t rx[HITAG_FRAME_LEN];
    uint8_t tx[HITAG_FRAME_LEN];

    while ((BUTTON_PRESS() == false) && (data_available() == false)) {
        // Watchdog hit
        WDT_HIT();

        lf_hitag_data_t payload;
        memset(&payload, 0, sizeof(payload));
        payload.cmd = HTSF_CHALLENGE;

        memcpy(payload.NrAr, data + dataoffset, 8);

        int res = hts_select_tag(&payload, tx, ARRAYLEN(tx), rx, ARRAYLEN(rx), HITAG_T_WAIT_FIRST, ledcontrol);

        DBG  Dbprintf("Challenge %s: %02X %02X %02X %02X %02X %02X %02X %02X",
                      res == -1 ? "failed " : "success",
                      payload.NrAr[0], payload.NrAr[1],
                      payload.NrAr[2], payload.NrAr[3],
                      payload.NrAr[4], payload.NrAr[5],
                      payload.NrAr[6], payload.NrAr[7]
                     );

        if (res == -1) {
            // Need to do a dummy UID select that will fail
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
            SpinDelay(2);
            hts_select_tag(&payload, tx, ARRAYLEN(tx), rx, ARRAYLEN(rx), HITAG_T_WAIT_FIRST, ledcontrol);
        }

        dataoffset += 8;
        if (dataoffset >= datalen - 8) {
            break;
        }
        // reset field
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

        // min t_reset = 2ms
        SpinDelay(2);
    }

    hts_stop_clock();
    set_tracing(false);
    lf_finalize(ledcontrol);
    reply_ng(CMD_LF_HITAGS_TEST_TRACES, PM3_SUCCESS, NULL, 0);
    return;
}
