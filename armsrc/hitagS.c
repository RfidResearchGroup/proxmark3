//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// HitagS emulation (preliminary test version)
//
// (c) 2016 Oguzhan Cicek, Hendrik Schwartke, Ralf Spenneberg
//     <info@os-s.de>
//-----------------------------------------------------------------------------
// Some code was copied from Hitag2.c
//-----------------------------------------------------------------------------

#include "hitagS.h"

#define CRC_PRESET 0xFF
#define CRC_POLYNOM 0x1D

static bool bQuiet;
static bool bSuccessful;
static struct hitagS_tag tag;
static uint8_t page_to_be_written = 0;
static int block_data_left = 0;

typedef enum modulation {
    AC2K = 0,
    AC4K,
    MC4K,
    MC8K
} MOD;

static MOD m = AC2K;               // used modulation
static uint32_t temp_uid;
static int temp2 = 0;
static int sof_bits;               // number of start-of-frame bits
static uint8_t pwdh0, pwdl0, pwdl1; // password bytes
static uint32_t rnd = 0x74124485;  // randomnumber
size_t blocknr;
bool end = false;
//#define SENDBIT_TEST

#define ht2bs_4a(a,b,c,d)   (~(((a|b)&c)^(a|d)^b))
#define ht2bs_4b(a,b,c,d)   (~(((d|c)&(a^b))^(d|a|b)))
#define ht2bs_5c(a,b,c,d,e) (~((((((c^e)|d)&a)^b)&(c^b))^(((d^e)|a)&((d^b)|c))))

// Sam7s has several timers, we will use the source TIMER_CLOCK1 (aka AT91C_TC_CLKS_TIMER_DIV1_CLOCK)
// TIMER_CLOCK1 = MCK/2, MCK is running at 48 MHz, Timer is running at 48/2 = 24 MHz
// Hitag units (T0) have duration of 8 microseconds (us), which is 1/125000 per second (carrier)
// T0 = TIMER_CLOCK1 / 125000 = 192
#ifndef T0
#define T0                             192
#endif

#define HITAG_FRAME_LEN                20
#define HITAG_T_STOP                   36  /* T_EOF should be > 36 */
#define HITAG_T_LOW                    8   /* T_LOW should be 4..10 */
#define HITAG_T_0_MIN                  15  /* T[0] should be 18..22 */
#define HITAG_T_1_MIN                  25  /* T[1] should be 26..30 */
//#define HITAG_T_EOF   40 /* T_EOF should be > 36 */
#define HITAG_T_EOF                    80   /* T_EOF should be > 36 */
#define HITAG_T_WAIT_1                 200  /* T_wresp should be 199..206 */
#define HITAG_T_WAIT_2                 90   /* T_wresp should be 199..206 */
#define HITAG_T_WAIT_MAX               300  /* bit more than HITAG_T_WAIT_1 + HITAG_T_WAIT_2 */

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

#define DEBUG 0

/*
 * Implementation of the crc8 calculation from Hitag S
 * from http://www.proxmark.org/files/Documents/125%20kHz%20-%20Hitag/HitagS.V11.pdf
 */
void calc_crc(unsigned char *crc, unsigned char data, unsigned char Bitcount) {
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

static void hitag_send_bit(int bit) {
    LED_A_ON();
    // Reset clock for the next bit
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

    switch (m) {
        case AC2K:
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
            LED_A_OFF();
            break;
        case AC4K:
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
            LED_A_OFF();
            break;
        case MC4K:
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
            LED_A_OFF();
            break;
        case MC8K:
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
            LED_A_OFF();
            break;
        default:
            break;
    }
}

static void hitag_send_frame(const uint8_t *frame, size_t frame_len) {
    // SOF - send start of frame
    for (size_t i = 0; i < sof_bits; i++) {
        hitag_send_bit(1);
    }

    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
        hitag_send_bit((frame[i / 8] >> (7 - (i % 8))) & 1);
    }

    LOW(GPIO_SSC_DOUT);
}

static void hitag_reader_send_bit(int bit) {

    LED_A_ON();
    // Reset clock for the next bit
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

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
    while (AT91C_BASE_TC0->TC_CV < T0 * 6) {};

    LOW(GPIO_SSC_DOUT);

    if (bit == 0) {
        // Zero bit: |_-|
        while (AT91C_BASE_TC0->TC_CV < T0 * 22) {};
    } else {
        // One bit: |_--|
        while (AT91C_BASE_TC0->TC_CV < T0 * 28) {};
    }
#endif

    LED_A_OFF();
}

static void hitag_reader_send_frame(const uint8_t *frame, size_t frame_len) {
    // Send the content of the frame
    for (size_t i = 0; i < frame_len; i++) {
//        if (frame[0] == 0xf8) {
        //Dbprintf("BIT: %d",(frame[i / 8] >> (7 - (i % 8))) & 1);
//        }
        hitag_reader_send_bit((frame[i / 8] >> (7 - (i % 8))) & 1);
    }
    // send EOF
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

    HIGH(GPIO_SSC_DOUT);

    // Wait for 4-10 times the carrier period
    while (AT91C_BASE_TC0->TC_CV < T0 * 6) {};

    LOW(GPIO_SSC_DOUT);
}

/*
 * to check if the right uid was selected
 */
static int check_select(uint8_t *rx, uint32_t uid) {
    unsigned char resp[48];
    uint32_t ans = 0x0;
    for (int i = 0; i < 48; i++)
        resp[i] = (rx[i / 8] >> (7 - (i % 8))) & 0x1;
    for (int i = 0; i < 32; i++)
        ans += resp[5 + i] << (31 - i);

    temp_uid = ans;
    if (ans == tag.uid)
        return 1;

    return 0;
}

/*
 * handles all commands from a reader
 */
static void hitagS_handle_reader_command(uint8_t *rx, const size_t rxlen,
                                         uint8_t *tx, size_t *txlen) {
    uint8_t rx_air[HITAG_FRAME_LEN];
    uint64_t state;
    unsigned char crc;

    // Copy the (original) received frame how it is send over the air
    memcpy(rx_air, rx, nbytes(rxlen));

    // Reset the transmission frame length
    *txlen = 0;

    // Try to find out which command was send by selecting on length (in bits)
    switch (rxlen) {
        case 5: {
            //UID request with a selected response protocol mode
            tag.pstate = HT_READY;
            tag.tstate = HT_NO_OP;
            if ((rx[0] & 0xf0) == 0x30) {
                tag.mode = HT_STANDARD;
                sof_bits = 1;
                m = AC2K;
            }
            if ((rx[0] & 0xf0) == 0xc0) {
                tag.mode = HT_ADVANCED;
                sof_bits = 3;
                m = AC2K;
            }

            if ((rx[0] & 0xf0) == 0xd0) {
                tag.mode = HT_FAST_ADVANCED;
                sof_bits = 3;
                m = AC4K;
            }
            //send uid as a response
            *txlen = 32;
            for (int i = 0; i < 4; i++)
                tx[i] = (tag.uid >> (24 - (i * 8))) & 0xff;
        }
        break;
        case 45: {
            //select command from reader received
            if (check_select(rx, tag.uid) == 1) {
                //if the right tag was selected
                *txlen = 32;
                switch (tag.mode) {
                    case HT_STANDARD:
                        sof_bits = 1;
                        m = MC4K;
                        break;
                    case HT_ADVANCED:
                        sof_bits = 6;
                        m = MC4K;
                        break;
                    case HT_FAST_ADVANCED:
                        sof_bits = 6;
                        m = MC8K;
                        break;
                    default:
                        break;
                }

                //send configuration
                for (int i = 0; i < 4; i++)
                    tx[i] = (tag.pages[0][1] >> (i * 8)) & 0xff;
                tx[3] = 0xff;
                if (tag.mode != HT_STANDARD) {
                    *txlen = 40;
                    crc = CRC_PRESET;
                    for (int i = 0; i < 4; i++)
                        calc_crc(&crc, tx[i], 8);
                    tx[4] = crc;
                }
            }
        }
        break;
        case 64: {
            //challenge message received
            Dbprintf("Challenge for UID: %X", temp_uid);
            temp2++;
            *txlen = 32;
            state = _hitag2_init(REV64(tag.key),
                                 REV32(tag.pages[0][0]),
                                 REV32(((rx[3] << 24) + (rx[2] << 16) + (rx[1] << 8) + rx[0]))
                                );
            Dbprintf(",{0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X}",
                     rx[0], rx[1], rx[2], rx[3], rx[4], rx[5], rx[6], rx[7]);

            switch (tag.mode) {
                case HT_STANDARD:
                    sof_bits = 1;
                    m = MC4K;
                    break;
                case HT_ADVANCED:
                    sof_bits = 6;
                    m = MC4K;
                    break;
                case HT_FAST_ADVANCED:
                    sof_bits = 6;
                    m = MC8K;
                    break;
                default:
                    break;
            }

            for (int i = 0; i < 4; i++)
                _hitag2_byte(&state);

            //send con2, pwdh0, pwdl0, pwdl1 encrypted as a response
            tx[0] = _hitag2_byte(&state) ^ ((tag.pages[0][1] >> 16) & 0xff);
            tx[1] = _hitag2_byte(&state) ^ tag.pwdh0;
            tx[2] = _hitag2_byte(&state) ^ tag.pwdl0;
            tx[3] = _hitag2_byte(&state) ^ tag.pwdl1;
            if (tag.mode != HT_STANDARD) {
                //add crc8
                *txlen = 40;
                crc = CRC_PRESET;
                calc_crc(&crc, ((tag.pages[0][1] >> 16) & 0xff), 8);
                calc_crc(&crc, tag.pwdh0, 8);
                calc_crc(&crc, tag.pwdl0, 8);
                calc_crc(&crc, tag.pwdl1, 8);
                tx[4] = (crc ^ _hitag2_byte(&state));
            }
            /*
             * some readers do not allow to authenticate multiple times in a row with the same tag.
             * use this to change the uid between authentications.

             if (temp2 % 2 == 0) {
             tag.uid = 0x11223344;
             tag.pages[0][0] = 0x44332211;
             } else {
             tag.uid = 0x55667788;
             tag.pages[0][0] = 0x88776655;
             }
             */
        }
        case 40:
            //data received to be written
            if (tag.tstate == HT_WRITING_PAGE_DATA) {
                tag.tstate = HT_NO_OP;
                tag.pages[page_to_be_written / 4][page_to_be_written % 4] = (rx[0]
                                                                            << 0) + (rx[1] << 8) + (rx[2] << 16) + (rx[3] << 24);
                //send ack
                *txlen = 2;
                tx[0] = 0x40;
                page_to_be_written = 0;
                switch (tag.mode) {
                    case HT_STANDARD:
                        sof_bits = 1;
                        m = MC4K;
                        break;
                    case HT_ADVANCED:
                        sof_bits = 6;
                        m = MC4K;
                        break;
                    case HT_FAST_ADVANCED:
                        sof_bits = 6;
                        m = MC8K;
                        break;
                    default:
                        break;
                }
            } else if (tag.tstate == HT_WRITING_BLOCK_DATA) {
                tag.pages[page_to_be_written / 4][page_to_be_written % 4] = (rx[0]
                                                                            << 24) + (rx[1] << 16) + (rx[2] << 8) + rx[3];
                //send ack
                *txlen = 2;
                tx[0] = 0x40;
                switch (tag.mode) {
                    case HT_STANDARD:
                        sof_bits = 1;
                        m = MC4K;
                        break;
                    case HT_ADVANCED:
                        sof_bits = 6;
                        m = MC4K;
                        break;
                    case HT_FAST_ADVANCED:
                        sof_bits = 6;
                        m = MC8K;
                        break;
                    default:
                        break;
                }
                page_to_be_written++;
                block_data_left--;
                if (block_data_left == 0) {
                    tag.tstate = HT_NO_OP;
                    page_to_be_written = 0;
                }
            }
            break;
        case 20: {
            //write page, write block, read page or read block command received
            if ((rx[0] & 0xf0) == 0xc0) { //read page
                //send page data
                uint8_t page = ((rx[0] & 0x0f) * 16) + ((rx[1] & 0xf0) / 16);
                *txlen = 32;
                tx[0] = (tag.pages[page / 4][page % 4]) & 0xff;
                tx[1] = (tag.pages[page / 4][page % 4] >> 8) & 0xff;
                tx[2] = (tag.pages[page / 4][page % 4] >> 16) & 0xff;
                tx[3] = (tag.pages[page / 4][page % 4] >> 24) & 0xff;
                if (tag.LKP && page == 1)
                    tx[3] = 0xff;

                switch (tag.mode) {
                    case HT_STANDARD:
                        sof_bits = 1;
                        m = MC4K;
                        break;
                    case HT_ADVANCED:
                        sof_bits = 6;
                        m = MC4K;
                        break;
                    case HT_FAST_ADVANCED:
                        sof_bits = 6;
                        m = MC8K;
                        break;
                    default:
                        break;
                }

                if (tag.mode != HT_STANDARD) {
                    //add crc8
                    *txlen = 40;
                    crc = CRC_PRESET;
                    for (int i = 0; i < 4; i++)
                        calc_crc(&crc, tx[i], 8);
                    tx[4] = crc;
                }

                if (tag.LKP && (page == 2 || page == 3)) {
                    //if reader asks for key or password and the LKP-mark is set do not respond
                    sof_bits = 0;
                    *txlen = 0;
                }
            } else if ((rx[0] & 0xf0) == 0xd0) { //read block
                uint8_t page = ((rx[0] & 0x0f) * 16) + ((rx[1] & 0xf0) / 16);
                *txlen = 32 * 4;
                //send page,...,page+3 data
                for (int i = 0; i < 4; i++) {
                    tx[0 + i * 4] = (tag.pages[page / 4][page % 4]) & 0xff;
                    tx[1 + i * 4] = (tag.pages[page / 4][page % 4] >> 8) & 0xff;
                    tx[2 + i * 4] = (tag.pages[page / 4][page % 4] >> 16) & 0xff;
                    tx[3 + i * 4] = (tag.pages[page / 4][page % 4] >> 24) & 0xff;
                    page++;
                }

                switch (tag.mode) {
                    case HT_STANDARD:
                        sof_bits = 1;
                        m = MC4K;
                        break;
                    case HT_ADVANCED:
                        sof_bits = 6;
                        m = MC4K;
                        break;
                    case HT_FAST_ADVANCED:
                        sof_bits = 6;
                        m = MC8K;
                        break;
                    default:
                        break;
                }

                if (tag.mode != HT_STANDARD) {
                    //add crc8
                    *txlen = 32 * 4 + 8;
                    crc = CRC_PRESET;
                    for (int i = 0; i < 16; i++)
                        calc_crc(&crc, tx[i], 8);
                    tx[16] = crc;
                }

                if ((page - 4) % 4 != 0 || (tag.LKP && (page - 4) == 0)) {
                    sof_bits = 0;
                    *txlen = 0;
                }
            } else if ((rx[0] & 0xf0) == 0x80) { //write page
                uint8_t page = ((rx[0] & 0x0f) * 16) + ((rx[1] & 0xf0) / 16);

                switch (tag.mode) {
                    case HT_STANDARD:
                        sof_bits = 1;
                        m = MC4K;
                        break;
                    case HT_ADVANCED:
                        sof_bits = 6;
                        m = MC4K;
                        break;
                    case HT_FAST_ADVANCED:
                        sof_bits = 6;
                        m = MC8K;
                        break;
                    default:
                        break;
                }
                if ((tag.LCON && page == 1)
                        || (tag.LKP && (page == 2 || page == 3))) {
                    //deny
                    *txlen = 0;
                } else {
                    //allow
                    *txlen = 2;
                    tx[0] = 0x40;
                    page_to_be_written = page;
                    tag.tstate = HT_WRITING_PAGE_DATA;
                }

            } else if ((rx[0] & 0xf0) == 0x90) { //write block
                uint8_t page = ((rx[0] & 0x0f) * 6) + ((rx[1] & 0xf0) / 16);
                switch (tag.mode) {
                    case HT_STANDARD:
                        sof_bits = 1;
                        m = MC4K;
                        break;
                    case HT_ADVANCED:
                        sof_bits = 6;
                        m = MC4K;
                        break;
                    case HT_FAST_ADVANCED:
                        sof_bits = 6;
                        m = MC8K;
                        break;
                    default:
                        break;
                }
                if (page % 4 != 0 || page == 0) {
                    //deny
                    *txlen = 0;
                } else {
                    //allow
                    *txlen = 2;
                    tx[0] = 0x40;
                    page_to_be_written = page;
                    block_data_left = 4;
                    tag.tstate = HT_WRITING_BLOCK_DATA;
                }
            }
        }
        break;
        default:

            break;
    }
}

/*
 * to autenticate to a tag with the given key or challenge
 */
static int hitagS_handle_tag_auth(hitag_function htf, uint64_t key, uint64_t NrAr, uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen) {
    uint8_t rx_air[HITAG_FRAME_LEN];
    int response_bit[200];
    unsigned char mask = 1;
    unsigned char uid[32];
    unsigned char crc;
    uint64_t state;
    uint8_t auth_ks[4];
    uint8_t conf_pages[3];
    memcpy(rx_air, rx, nbytes(rxlen));
    *txlen = 0;

    if (tag.pstate == HT_READY && rxlen >= 67) {
        //received uid
        if (end == true) {
            Dbprintf("authentication failed!");
            return -1;
        }
        int z = 0;
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 8; j++) {
                response_bit[z] = 0;
                if ((rx[i] & ((mask << 7) >> j)) != 0)
                    response_bit[z] = 1;
                z++;
            }
        }
        uint16_t k = 0;
        for (int i = 5; i < z; i += 2) {
            uid[k] = response_bit[i];
            k++;
            if (k > 31)
                break;
        }
        uint8_t uid1 = (uid[0] << 7)
                       | (uid[1] << 6)
                       | (uid[2] << 5)
                       | (uid[3] << 4)
                       | (uid[4] << 3)
                       | (uid[5] << 2)
                       | (uid[6] << 1)
                       | uid[7];

        uint8_t uid2 = (uid[8] << 7)
                       | (uid[9] << 6)
                       | (uid[10] << 5)
                       | (uid[11] << 4)
                       | (uid[12] << 3)
                       | (uid[13] << 2)
                       | (uid[14] << 1)
                       | uid[15];

        uint8_t uid3 = (uid[16] << 7)
                       | (uid[17] << 6)
                       | (uid[18] << 5)
                       | (uid[19] << 4)
                       | (uid[20] << 3)
                       | (uid[21] << 2)
                       | (uid[22] << 1)
                       | uid[23];

        uint8_t uid4 = (uid[24] << 7)
                       | (uid[25] << 6)
                       | (uid[26] << 5)
                       | (uid[27] << 4)
                       | (uid[28] << 3)
                       | (uid[29] << 2)
                       | (uid[30] << 1)
                       | uid[31];

        if (DEBUG)
            Dbprintf("UID: %02X %02X %02X %02X", uid1, uid2, uid3, uid4);

        tag.uid = (uid4 << 24 | uid3 << 16 | uid2 << 8 | uid1);

        //select uid
        *txlen = 45;
        crc = CRC_PRESET;
        calc_crc(&crc, 0x00, 5);
        calc_crc(&crc, uid1, 8);
        calc_crc(&crc, uid2, 8);
        calc_crc(&crc, uid3, 8);
        calc_crc(&crc, uid4, 8);

        for (int i = 0; i < 100; i++) {
            response_bit[i] = 0;
        }

        for (int i = 0; i < 5; i++) {
            response_bit[i] = 0;
        }
        {
            int i = 5;
            for (; i < 37; i++) {
                response_bit[i] = uid[i - 5];
            }

            for (int j = 0; j < 8; j++) {
                response_bit[i] = 0;
                if ((crc & ((mask << 7) >> j)) != 0)
                    response_bit[i] = 1;
                i++;
            }
        }
        k = 0;
        for (int i = 0; i < 6; i++) {
            tx[i] = (response_bit[k] << 7)
                    | (response_bit[k + 1] << 6)
                    | (response_bit[k + 2] << 5)
                    | (response_bit[k + 3] << 4)
                    | (response_bit[k + 4] << 3)
                    | (response_bit[k + 5] << 2)
                    | (response_bit[k + 6] << 1)
                    | response_bit[k + 7];

            k += 8;
        }

        tag.pstate = HT_INIT;
    } else if (tag.pstate == HT_INIT && rxlen == 44) {
        // received configuration after select command
        int z = 0;
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 8; j++) {
                response_bit[z] = 0;
                if ((rx[i] & ((mask << 7) >> j)) != 0)
                    response_bit[z] = 1;
                z++;
            }
        }
        conf_pages[0] = ((response_bit[4] << 7) | (response_bit[5] << 6)
                         | (response_bit[6] << 5) | (response_bit[7] << 4)
                         | (response_bit[8] << 3) | (response_bit[9] << 2)
                         | (response_bit[10] << 1) | response_bit[11]);
        //check wich memorysize this tag has
        if (response_bit[10] == 0 && response_bit[11] == 0)
            tag.max_page = 32 / 32;
        if (response_bit[10] == 0 && response_bit[11] == 1)
            tag.max_page = 256 / 32;
        if (response_bit[10] == 1 && response_bit[11] == 0)
            tag.max_page = 2048 / 32;
        conf_pages[1] = ((response_bit[12] << 7) | (response_bit[13] << 6)
                         | (response_bit[14] << 5) | (response_bit[15] << 4)
                         | (response_bit[16] << 3) | (response_bit[17] << 2)
                         | (response_bit[18] << 1) | response_bit[19]);
        tag.auth = response_bit[12];
        tag.TTFC = response_bit[13];
        //tag.TTFDR in response_bit[14] and response_bit[15]
        //tag.TTFM in response_bit[16] and response_bit[17]
        tag.LCON = response_bit[18];
        tag.LKP = response_bit[19];
        conf_pages[2] = ((response_bit[20] << 7) | (response_bit[21] << 6)
                         | (response_bit[22] << 5) | (response_bit[23] << 4)
                         | (response_bit[24] << 3) | (response_bit[25] << 2)
                         | (response_bit[26] << 1) | response_bit[27]);
        tag.LCK7 = response_bit[20];
        tag.LCK6 = response_bit[21];
        tag.LCK5 = response_bit[22];
        tag.LCK4 = response_bit[23];
        tag.LCK3 = response_bit[24];
        tag.LCK2 = response_bit[25];
        tag.LCK1 = response_bit[26];
        tag.LCK0 = response_bit[27];

        if (DEBUG)
            Dbprintf("conf0: %02X conf1: %02X conf2: %02X", conf_pages[0], conf_pages[1], conf_pages[2]);

        if (tag.auth == 1) {
            //if the tag is in authentication mode try the key or challenge
            *txlen = 64;
            if (end != true) {
                if (htf == 02 || htf == 04) { //RHTS_KEY //WHTS_KEY
                    state = _hitag2_init(REV64(key), REV32(tag.uid), REV32(rnd));

                    for (int i = 0; i < 4; i++) {
                        auth_ks[i] = _hitag2_byte(&state) ^ 0xff;
                    }
                    *txlen = 64;
                    tx[0] = rnd & 0xff;
                    tx[1] = (rnd >> 8) & 0xff;
                    tx[2] = (rnd >> 16) & 0xff;
                    tx[3] = (rnd >> 24) & 0xff;

                    tx[4] = auth_ks[0];
                    tx[5] = auth_ks[1];
                    tx[6] = auth_ks[2];
                    tx[7] = auth_ks[3];
                    if (DEBUG)
                        Dbprintf("%02X %02X %02X %02X %02X %02X %02X %02X", tx[0],
                                 tx[1], tx[2], tx[3], tx[4], tx[5], tx[6], tx[7]);
                } else if (htf == 01 || htf == 03) { //RHTS_CHALLENGE //WHTS_CHALLENGE
                    for (int i = 0; i < 8; i++)
                        tx[i] = ((NrAr >> (56 - (i * 8))) & 0xff);
                }
                end = true;
                tag.pstate = HT_AUTHENTICATE;
            } else {
                Dbprintf("authentication failed!");
                return -1;
            }
        } else if (tag.auth == 0) {
            tag.pstate = HT_SELECTED;
        }

    } else if (tag.pstate == HT_AUTHENTICATE && rxlen == 44) {
        //encrypted con2,password received.
        crc = CRC_PRESET;
        calc_crc(&crc, 0x80, 1);
        calc_crc(&crc, ((rx[0] & 0x0f) * 16 + ((rx[1] & 0xf0) / 16)), 8);
        calc_crc(&crc, ((rx[1] & 0x0f) * 16 + ((rx[2] & 0xf0) / 16)), 8);
        calc_crc(&crc, ((rx[2] & 0x0f) * 16 + ((rx[3] & 0xf0) / 16)), 8);
        calc_crc(&crc, ((rx[3] & 0x0f) * 16 + ((rx[4] & 0xf0) / 16)), 8);
        if (DEBUG) {
            Dbprintf("UID:::%X", tag.uid);
            Dbprintf("RND:::%X", rnd);
        }

        //decrypt password
        pwdh0 = 0;
        pwdl0 = 0;
        pwdl1 = 0;
        if (htf == 02 || htf == 04) { //RHTS_KEY //WHTS_KEY
            {
                state = _hitag2_init(REV64(key), REV32(tag.uid), REV32(rnd));
                for (int i = 0; i < 5; i++)
                    _hitag2_byte(&state);

                pwdh0 = ((rx[1] & 0x0f) * 16 + ((rx[2] & 0xf0) / 16)) ^ _hitag2_byte(&state);
                pwdl0 = ((rx[2] & 0x0f) * 16 + ((rx[3] & 0xf0) / 16)) ^ _hitag2_byte(&state);
                pwdl1 = ((rx[3] & 0x0f) * 16 + ((rx[4] & 0xf0) / 16)) ^ _hitag2_byte(&state);
            }

            if (DEBUG)
                Dbprintf("pwdh0 %02X pwdl0 %02X pwdl1 %02X", pwdh0, pwdl0, pwdl1);

            //Dbprintf("%X %02X", rnd, ((rx[4] & 0x0f) * 16) + ((rx[5] & 0xf0) / 16));
            //rnd += 1;
        }
        tag.pstate = HT_SELECTED; //tag is now ready for read/write commands
    }
    return 0;

}

/*
 * Emulates a Hitag S Tag with the given data from the .hts file
 */
void SimulateHitagSTag(bool tag_mem_supplied, uint8_t *data) {

    StopTicks();

//    int frame_count = 0;
    int response = 0, overflow = 0;
    int i, j;
    uint8_t rx[HITAG_FRAME_LEN];
    size_t rxlen = 0;
    bQuiet = false;
    uint8_t txbuf[HITAG_FRAME_LEN];
    uint8_t *tx = txbuf;
    size_t txlen = 0;

    // Reset the received frame, frame count and timing info
    memset(rx, 0x00, sizeof(rx));

    // free eventually allocated BigBuf memory
    BigBuf_free();
    BigBuf_Clear_ext(false);

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    DbpString("Starting HitagS simulation");
    LED_D_ON();

    tag.pstate = HT_READY;
    tag.tstate = HT_NO_OP;

    for (i = 0; i < 16; i++)
        for (j = 0; j < 4; j++)
            tag.pages[i][j] = 0x0;

    // read tag data into memory
    if (tag_mem_supplied) {
        DbpString("Loading hitagS memory...");
        memcpy((uint8_t *)tag.pages, data, 4 * 64);
    }

    tag.uid = (uint32_t)tag.pages[0];
    tag.key = (intptr_t)tag.pages[3];
    tag.key <<= 16;
    tag.key += ((tag.pages[2][0]) << 8) + tag.pages[2][1];
    tag.pwdl0 = tag.pages[2][3];
    tag.pwdl1 = tag.pages[2][2];
    tag.pwdh0 = tag.pages[1][0];
    //con0
    tag.max_page = 64;
    if ((tag.pages[1][3] & 0x2) == 0 && (tag.pages[1][3] & 0x1) == 1)
        tag.max_page = 8;
    if ((tag.pages[1][3] & 0x2) == 0 && (tag.pages[1][3] & 0x1) == 0)
        tag.max_page = 0;
    //con1
    tag.auth = 0;
    if ((tag.pages[1][2] & 0x80) == 0x80)
        tag.auth = 1;
    tag.LCON = 0;
    if ((tag.pages[1][2] & 0x2) == 0x02)
        tag.LCON = 1;
    tag.LKP = 0;
    if ((tag.pages[1][2] & 0x1) == 0x01)
        tag.LKP = 1;
    //con2
    //0=read write 1=read only
    tag.LCK7 = 0;
    if ((tag.pages[1][1] & 0x80) == 0x80)
        tag.LCK7 = 1;
    tag.LCK6 = 0;
    if ((tag.pages[1][1] & 0x40) == 0x040)
        tag.LCK6 = 1;
    tag.LCK5 = 0;
    if ((tag.pages[1][1] & 0x20) == 0x20)
        tag.LCK5 = 1;
    tag.LCK4 = 0;
    if ((tag.pages[1][1] & 0x10) == 0x10)
        tag.LCK4 = 1;
    tag.LCK3 = 0;
    if ((tag.pages[1][1] & 0x8) == 0x08)
        tag.LCK3 = 1;
    tag.LCK2 = 0;
    if ((tag.pages[1][1] & 0x4) == 0x04)
        tag.LCK2 = 1;
    tag.LCK1 = 0;
    if ((tag.pages[1][1] & 0x2) == 0x02)
        tag.LCK1 = 1;
    tag.LCK0 = 0;
    if ((tag.pages[1][1] & 0x1) == 0x01)
        tag.LCK0 = 1;

    // Set up simulator mode, frequency divisor which will drive the FPGA
    // and analog mux selection.
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Configure output pin that is connected to the FPGA (for modulating)
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;

    // Disable modulation at default, which means release resistance
    LOW(GPIO_SSC_DOUT);

    // Enable Peripheral Clock for
    //   TIMER_CLOCK0, used to measure exact timing before answering
    //   TIMER_CLOCK1, used to capture edges of the tag frames
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0) | (1 << AT91C_ID_TC1);

    AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;

    // Disable timer during configuration
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // TC0: Capture mode, default timer source = MCK/2 (TIMER_CLOCK1), no triggers
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV1_CLOCK;

    // TC1: Capture mode, default timer source = MCK/2 (TIMER_CLOCK1), TIOA is external trigger,
    // external trigger rising edge, load RA on rising edge of TIOA.
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_TIMER_DIV1_CLOCK
                             | AT91C_TC_ETRGEDG_RISING | AT91C_TC_ABETRG | AT91C_TC_LDRA_RISING;

    // Enable and reset counter
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // synchronized startup procedure
    while (AT91C_BASE_TC0->TC_CV > 0); // wait until TC0 returned to zero

    while (!BUTTON_PRESS() && !data_available()) {

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

                LED_B_ON();

                // Capture reader frame
                if (ra >= HITAG_T_STOP) {
                    if (rxlen != 0) {
                        //DbpString("wierd0?");
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
                    // Ignore wierd value, is to small to mean anything
                }
            }
        }

        // Check if frame was captured
        if (rxlen > 0) {
//            frame_count++;
            LogTrace(rx, nbytes(rxlen), response, 0, NULL, true);

            // Disable timer 1 with external trigger to avoid triggers during our own modulation
            AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

            // Process the incoming frame (rx) and prepare the outgoing frame (tx)
            hitagS_handle_reader_command(rx, rxlen, tx, &txlen);

            // Wait for HITAG_T_WAIT_1 carrier periods after the last reader bit,
            // not that since the clock counts since the rising edge, but T_Wait1 is
            // with respect to the falling edge, we need to wait actually (T_Wait1 - T_Low)
            // periods. The gap time T_Low varies (4..10). All timer values are in
            // terms of T0 units
            while (AT91C_BASE_TC0->TC_CV < T0 * (HITAG_T_WAIT_1 - HITAG_T_LOW)) {};

            // Send and store the tag answer (if there is any)
            if (txlen > 0) {
                // Transmit the tag frame
                hitag_send_frame(tx, txlen);
                LogTrace(tx, nbytes(txlen), 0, 0, NULL, false);
            }

            // Reset the received frame and response timing info
            memset(rx, 0x00, sizeof(rx));
            response = 0;

            // Enable and reset external trigger in timer for capturing future frames
            AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
            LED_B_OFF();
        }
        // Reset the frame length
        rxlen = 0;
        // Save the timer overflow, will be 0 when frame was received
        overflow += (AT91C_BASE_TC1->TC_CV / T0);
        // Reset the timer to restart while-loop that receives frames
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_SWTRG;
    }

    LEDsoff();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    set_tracing(false);
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;

    // release allocated memory from BigBuff.
    BigBuf_free();

    StartTicks();

    DbpString("Sim Stopped");
}

/*
 * Authenticates to the Tag with the given key or challenge.
 * If the key was given the password will be decrypted.
 * Reads every page of a hitag S transpoder.
 */
void ReadHitagS(hitag_function htf, hitag_data *htd) {

    StopTicks();

    int i, j, z, k;
//    int frame_count = 0;
    int response = 0;
    int response_bit[200];
    uint8_t rx[HITAG_FRAME_LEN];
    size_t rxlen = 0;
    uint8_t txbuf[HITAG_FRAME_LEN];
    uint8_t *tx = txbuf;
    size_t txlen = 0;
    int lastbit = 1;
    int reset_sof = 1;
    int t_wait = HITAG_T_WAIT_MAX;
    bool bStop = false;
    int sendNum = 0;
    unsigned char mask = 1;
    unsigned char crc;
    unsigned char pageData[32];
    page_to_be_written = 0;

    //read given key/challenge
    uint8_t NrAr_[8];
    uint64_t key = 0;
    uint64_t NrAr = 0;
    uint8_t key_[6];

    switch (htf) {
        case RHTSF_CHALLENGE: {
            DbpString("Authenticating using nr,ar pair:");
            memcpy(NrAr_, htd->auth.NrAr, 8);
            Dbhexdump(8, NrAr_, false);
            NrAr = NrAr_[7] | ((uint64_t)NrAr_[6]) << 8 | ((uint64_t)NrAr_[5]) << 16 | ((uint64_t)NrAr_[4]) << 24 | ((uint64_t)NrAr_[3]) << 32 |
                   ((uint64_t)NrAr_[2]) << 40 | ((uint64_t)NrAr_[1]) << 48 | ((uint64_t)NrAr_[0]) << 56;
            break;
        }
        case RHTSF_KEY: {
            DbpString("Authenticating using key:");
            memcpy(key_, htd->crypto.key, 6);
            Dbhexdump(6, key_, false);
            key = key_[5] | ((uint64_t)key_[4]) << 8 | ((uint64_t)key_[3]) << 16 | ((uint64_t)key_[2]) << 24 | ((uint64_t)key_[1]) << 32 | ((uint64_t)key_[0]) << 40;
            break;
        }
        default: {
            Dbprintf("Error , unknown function: %d", htf);
            return;
        }
    }

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    // Reset the return status
    bSuccessful = false;

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    bQuiet = false;

    LED_D_ON();

    // Set fpga in edge detect with reader field, we can modulate as reader now
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | FPGA_LF_EDGE_DETECT_READER_FIELD);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Configure output and enable pin that is connected to the FPGA (for modulating)
    AT91C_BASE_PIOA->PIO_OER |= GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_PER |= GPIO_SSC_DOUT;

    // Disable modulation at default, which means enable the field
    LOW(GPIO_SSC_DOUT);

    // Enable Peripheral Clock for
    //   TIMER_CLOCK0, used to measure exact timing before answering
    //   TIMER_CLOCK1, used to capture edges of the tag frames
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0) | (1 << AT91C_ID_TC1);

    AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;

    // Disable timer during configuration
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // TC0: Capture mode, default timer source = MCK/2 (TIMER_CLOCK1), no triggers
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV1_CLOCK;

    // TC1: Capture mode, defaul timer source = MCK/2 (TIMER_CLOCK1), TIOA is external trigger,
    // external trigger rising edge, load RA on falling edge of TIOA.
    AT91C_BASE_TC1->TC_CMR =
        AT91C_TC_CLKS_TIMER_DIV1_CLOCK  |
        AT91C_TC_ETRGEDG_FALLING        |
        AT91C_TC_ABETRG                 |
        AT91C_TC_LDRA_FALLING;

    // Enable and reset counters
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // synchronized startup procedure
    while (AT91C_BASE_TC0->TC_CV > 0); // wait until TC0 returned to zero

    // Reset the received frame, frame count and timing info
    t_wait = 200;

    while (!bStop && !BUTTON_PRESS() && !data_available())  {

        WDT_HIT();

        // Check if frame was captured and store it
        if (rxlen > 0) {
//            frame_count++;
            LogTrace(rx, nbytes(rxlen), response, 0, NULL, false);
        }

        // By default reset the transmission buffer
        tx = txbuf;
        txlen = 0;

        if (rxlen == 0) {
            //start authentication
            txlen = 5;
            memcpy(tx, "\xC0", nbytes(txlen));
            tag.pstate = HT_READY;
            tag.tstate = HT_NO_OP;
        } else if (tag.pstate != HT_SELECTED) {
            if (hitagS_handle_tag_auth(htf, key, NrAr, rx, rxlen, tx, &txlen) == -1)
                bStop = !false;
        }

        if (tag.pstate == HT_SELECTED && tag.tstate == HT_NO_OP && rxlen > 0) {
            //send read request
            tag.tstate = HT_READING_PAGE;
            txlen = 20;
            crc = CRC_PRESET;
            tx[0] = 0xc0 + (sendNum / 16);
            calc_crc(&crc, tx[0], 8);
            calc_crc(&crc, 0x00 + ((sendNum % 16) * 16), 4);
            tx[1] = 0x00 + ((sendNum % 16) * 16) + (crc / 16);
            tx[2] = 0x00 + (crc % 16) * 16;
        } else if (tag.pstate == HT_SELECTED
                   && tag.tstate == HT_READING_PAGE
                   && rxlen > 0) {
            //save received data
            z = 0;
            for (i = 0; i < 5; i++) {
                for (j = 0; j < 8; j++) {
                    response_bit[z] = 0;
                    if ((rx[i] & ((mask << 7) >> j)) != 0)
                        response_bit[z] = 1;
                    z++;
                }
            }
            k = 0;
            for (i = 4; i < 36; i++) {
                pageData[k] = response_bit[i];
                k++;
            }
            for (i = 0; i < 4; i++)
                tag.pages[sendNum / 4][sendNum % 4] = 0x0;
            for (i = 0; i < 4; i++) {
                tag.pages[sendNum / 4][sendNum % 4] += ((pageData[i * 8] << 7)
                                                        | (pageData[1 + (i * 8)] << 6)
                                                        | (pageData[2 + (i * 8)] << 5)
                                                        | (pageData[3 + (i * 8)] << 4)
                                                        | (pageData[4 + (i * 8)] << 3)
                                                        | (pageData[5 + (i * 8)] << 2)
                                                        | (pageData[6 + (i * 8)] << 1) | pageData[7 + (i * 8)])
                                                       << (i * 8);
            }
            if (tag.auth && tag.LKP && sendNum == 1) {
                Dbprintf("Page[%2d]: %02X %02X %02X %02X", sendNum, pwdh0,
                         (tag.pages[sendNum / 4][sendNum % 4] >> 16) & 0xff,
                         (tag.pages[sendNum / 4][sendNum % 4] >> 8) & 0xff,
                         tag.pages[sendNum / 4][sendNum % 4] & 0xff);
            } else {
                Dbprintf("Page[%2d]: %02X %02X %02X %02X", sendNum,
                         (tag.pages[sendNum / 4][sendNum % 4] >> 24) & 0xff,
                         (tag.pages[sendNum / 4][sendNum % 4] >> 16) & 0xff,
                         (tag.pages[sendNum / 4][sendNum % 4] >> 8) & 0xff,
                         tag.pages[sendNum / 4][sendNum % 4] & 0xff);
            }

            sendNum++;
            //display key and password if possible
            if (sendNum == 2 && tag.auth == 1 && tag.LKP) {
                if (htf == RHTSF_KEY) {
                    Dbprintf("Page[ 2]: %02X %02X %02X %02X",
                             (uint8_t)(key >> 8) & 0xff,
                             (uint8_t) key & 0xff,
                             pwdl1,
                             pwdl0
                            );
                    Dbprintf("Page[ 3]: %02X %02X %02X %02X",
                             (uint8_t)(key >> 40) & 0xff,
                             (uint8_t)(key >> 32) & 0xff,
                             (uint8_t)(key >> 24) & 0xff,
                             (uint8_t)(key >> 16) & 0xff
                            );
                } else {
                    //if the authentication is done with a challenge the key and password are unknown
                    Dbprintf("Page[ 2]: __ __ __ __");
                    Dbprintf("Page[ 3]: __ __ __ __");
                }
            }

            txlen = 20;
            crc = CRC_PRESET;
            tx[0] = 0xc0 + (sendNum / 16);
            calc_crc(&crc, tx[0], 8);
            calc_crc(&crc, 0x00 + ((sendNum % 16) * 16), 4);
            tx[1] = 0x00 + ((sendNum % 16) * 16) + (crc / 16);
            tx[2] = 0x00 + (crc % 16) * 16;
            if (sendNum >= tag.max_page) {
                bStop = !false;
            }
        }

        // Send and store the reader command
        // Disable timer 1 with external trigger to avoid triggers during our own modulation
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

        // Wait for HITAG_T_WAIT_2 carrier periods after the last tag bit before transmitting,
        // Since the clock counts since the last falling edge, a 'one' means that the
        // falling edge occured halfway the period. with respect to this falling edge,
        // we need to wait (T_Wait2 + half_tag_period) when the last was a 'one'.
        // All timer values are in terms of T0 units

        while (AT91C_BASE_TC0->TC_CV < T0 * (t_wait + (HITAG_T_TAG_HALF_PERIOD * lastbit))) {};

        // Transmit the reader frame
        hitag_reader_send_frame(tx, txlen);

        // Enable and reset external trigger in timer for capturing future frames
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

        // Add transmitted frame to total count
        if (txlen > 0) {
//            frame_count++;
            LogTrace(tx, nbytes(txlen), HITAG_T_WAIT_2, 0, NULL, true);
        }

        // Reset values for receiving frames
        memset(rx, 0x00, sizeof(rx));
        rxlen = 0;
        lastbit = 1;
        bool bSkip = true;
        int tag_sof = reset_sof;
        response = 0;

        // Receive frame, watch for at most T0*EOF periods
        while (AT91C_BASE_TC1->TC_CV < T0 * HITAG_T_WAIT_MAX) {
            // Check if falling edge in tag modulation is detected
            if (AT91C_BASE_TC1->TC_SR & AT91C_TC_LDRAS) {
                // Retrieve the new timing values
                int ra = (AT91C_BASE_TC1->TC_RA / T0);

                // Reset timer every frame, we have to capture the last edge for timing
                AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

                LED_B_ON();

                // Capture tag frame (manchester decoding using only falling edges)
                if (ra >= HITAG_T_EOF) {
                    if (rxlen != 0) {
                        //DbpString("wierd1?");
                    }
                    // Capture the T0 periods that have passed since last communication or field drop (reset)
                    // We always recieve a 'one' first, which has the falling edge after a half period |-_|
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
                    if (!bSkip) {
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
                } else {
                    // Ignore wierd value, is to small to mean anything
                }
            }

            // We can break this loop if we received the last bit from a frame
            if (AT91C_BASE_TC1->TC_CV > T0 * HITAG_T_EOF) {
                if (rxlen > 0)
                    break;
            }
        }
    }
    end = false;

    LEDsoff();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    set_tracing(false);

    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    StartTicks();

    reply_old(CMD_ACK, bSuccessful, 0, 0, 0, 0);
}

/*
 * Authenticates to the Tag with the given Key or Challenge.
 * Writes the given 32Bit data into page_
 */
void WritePageHitagS(hitag_function htf, hitag_data *htd, int page) {

    StopTicks();

//    int frame_count = 0;
    int response = 0;
    uint8_t rx[HITAG_FRAME_LEN];
    size_t rxlen = 0;
    uint8_t txbuf[HITAG_FRAME_LEN];
    uint8_t *tx = txbuf;
    size_t txlen = 0;
    int lastbit;
    int reset_sof;
    int t_wait = HITAG_T_WAIT_MAX;
    bool bStop;
    unsigned char crc;
    uint8_t data[4] = {0, 0, 0, 0};

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    bSuccessful = false;

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    //read given key/challenge, the page and the data
    uint8_t NrAr_[8];
    uint64_t key = 0;
    uint64_t NrAr = 0;
    uint8_t key_[6];
    switch (htf) {
        case WHTSF_CHALLENGE: {
            memcpy(data, htd->auth.data, 4);
            DbpString("Authenticating using nr,ar pair:");
            memcpy(NrAr_, htd->auth.NrAr, 8);
            Dbhexdump(8, NrAr_, false);
            NrAr = NrAr_[7] | ((uint64_t)NrAr_[6]) << 8 | ((uint64_t)NrAr_[5]) << 16 | ((uint64_t)NrAr_[4]) << 24 | ((uint64_t)NrAr_[3]) << 32 |
                   ((uint64_t)NrAr_[2]) << 40 | ((uint64_t)NrAr_[1]) << 48 | ((uint64_t)NrAr_[0]) << 56;
            break;
        }

        case WHTSF_KEY: {
            memcpy(data, htd->crypto.data, 4);
            DbpString("Authenticating using key:");
            memcpy(key_, htd->crypto.key, 6);
            Dbhexdump(6, key_, false);
            key = key_[5] | ((uint64_t)key_[4]) << 8 | ((uint64_t)key_[3]) << 16 | ((uint64_t)key_[2]) << 24 | ((uint64_t)key_[1]) << 32 | ((uint64_t)key_[0]) << 40;
            break;
        }
        default: {
            Dbprintf("Error , unknown function: %d", htf);
            return;
        }
    }

    Dbprintf("Page: %d", page);
    Dbprintf("DATA: %02X %02X %02X %02X", data[0], data[1], data[2], data[3]);

    tag.pstate = HT_READY;
    tag.tstate = HT_NO_OP;

    LED_D_ON();

    // Configure output and enable pin that is connected to the FPGA (for modulating)
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;

    // Set fpga in edge detect with reader field, we can modulate as reader now
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | FPGA_LF_EDGE_DETECT_READER_FIELD);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Disable modulation at default, which means enable the field
    LOW(GPIO_SSC_DOUT);

    // Enable Peripheral Clock for
    //   TIMER_CLOCK0, used to measure exact timing before answering
    //   TIMER_CLOCK1, used to capture edges of the tag frames
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0) | (1 << AT91C_ID_TC1);

    AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;

    // Disable timer during configuration
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // Capture mode, defaul timer source = MCK/2 (TIMER_CLOCK1), TIOA is external trigger,
    // external trigger rising edge, load RA on falling edge of TIOA.
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_TIMER_DIV1_CLOCK
                             | AT91C_TC_ETRGEDG_FALLING
                             | AT91C_TC_ABETRG
                             | AT91C_TC_LDRA_FALLING;

    // Enable and reset counters
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    while (AT91C_BASE_TC0->TC_CV > 0);

    // Reset the received frame, frame count and timing info
    lastbit = 1;
    bStop = false;
    reset_sof = 1;
    t_wait = 200;

    while (!bStop && !BUTTON_PRESS() && !data_available()) {

        WDT_HIT();

        // Check if frame was captured and store it
        if (rxlen > 0) {
//            frame_count++;
            LogTrace(rx, nbytes(rxlen), response, 0, NULL, false);
        }

        //check for valid input
        if (page == 0) {
            Dbprintf(
                "usage: lf hitag writer [03 | 04] [CHALLENGE | KEY] [page] [byte0] [byte1] [byte2] [byte3]");
            bStop = !false;
        }

        // By default reset the transmission buffer
        tx = txbuf;
        txlen = 0;

        if (rxlen == 0 && tag.tstate == HT_WRITING_PAGE_ACK) {
            //no write access on this page
            Dbprintf("no write access on page %d", page);
            bStop = !false;
        } else if (rxlen == 0 && tag.tstate != HT_WRITING_PAGE_DATA) {
            //start the authetication
            txlen = 5;
            memcpy(tx, "\xc0", nbytes(txlen));
            tag.pstate = HT_READY;
            tag.tstate = HT_NO_OP;
        } else if (tag.pstate != HT_SELECTED) {
            //try to authenticate with the given key or challenge
            if (hitagS_handle_tag_auth(htf, key, NrAr, rx, rxlen, tx, &txlen) == -1)
                bStop = !false;
        }
        if (tag.pstate == HT_SELECTED && tag.tstate == HT_NO_OP && rxlen > 0) {
            //check if the given page exists
            if (page > tag.max_page) {
                Dbprintf("page number too big");
                bStop = !false;
            }
            //ask Tag for write permission
            tag.tstate = HT_WRITING_PAGE_ACK;
            txlen = 20;
            crc = CRC_PRESET;
            tx[0] = 0x90 + (page / 16);
            calc_crc(&crc, tx[0], 8);
            calc_crc(&crc, 0x00 + ((page % 16) * 16), 4);
            tx[1] = 0x00 + ((page % 16) * 16) + (crc / 16);
            tx[2] = 0x00 + (crc % 16) * 16;
        } else if (tag.pstate == HT_SELECTED && tag.tstate == HT_WRITING_PAGE_ACK
                   && rxlen == 6 && rx[0] == 0xf4) {
            //ACK recieved to write the page. send data
            tag.tstate = HT_WRITING_PAGE_DATA;
            txlen = 40;
            crc = CRC_PRESET;
            calc_crc(&crc, data[3], 8);
            calc_crc(&crc, data[2], 8);
            calc_crc(&crc, data[1], 8);
            calc_crc(&crc, data[0], 8);
            tx[0] = data[3];
            tx[1] = data[2];
            tx[2] = data[1];
            tx[3] = data[0];
            tx[4] = crc;
        } else if (tag.pstate == HT_SELECTED && tag.tstate == HT_WRITING_PAGE_DATA
                   && rxlen == 6 && rx[0] == 0xf4) {
            //received ACK
            Dbprintf("Successful!");
            bStop = !false;
        }

        // Send and store the reader command
        // Disable timer 1 with external trigger to avoid triggers during our own modulation
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

        // Wait for HITAG_T_WAIT_2 carrier periods after the last tag bit before transmitting,
        // Since the clock counts since the last falling edge, a 'one' means that the
        // falling edge occured halfway the period. with respect to this falling edge,
        // we need to wait (T_Wait2 + half_tag_period) when the last was a 'one'.
        // All timer values are in terms of T0 units

        while (AT91C_BASE_TC0->TC_CV < T0 * (t_wait + (HITAG_T_TAG_HALF_PERIOD * lastbit))) {};

        // Transmit the reader frame
        hitag_reader_send_frame(tx, txlen);

        // Enable and reset external trigger in timer for capturing future frames
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

        // Add transmitted frame to total count
        if (txlen > 0) {
//            frame_count++;
            LogTrace(tx, nbytes(txlen), HITAG_T_WAIT_2, 0, NULL, true);
        }

        // Reset values for receiving frames
        memset(rx, 0x00, sizeof(rx));
        rxlen = 0;
        lastbit = 1;
        bool bSkip = true;
        int tag_sof = reset_sof;
        response = 0;
        uint32_t errorCount = 0;

        // Receive frame, watch for at most T0*EOF periods
        while (AT91C_BASE_TC1->TC_CV < T0 * HITAG_T_WAIT_MAX) {
            // Check if falling edge in tag modulation is detected
            if (AT91C_BASE_TC1->TC_SR & AT91C_TC_LDRAS) {
                // Retrieve the new timing values
                int ra = (AT91C_BASE_TC1->TC_RA / T0);

                // Reset timer every frame, we have to capture the last edge for timing
                AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

                LED_B_ON();

                // Capture tag frame (manchester decoding using only falling edges)
                if (ra >= HITAG_T_EOF) {
                    if (rxlen != 0) {
                        //DbpString("wierd1?");
                    }
                    // Capture the T0 periods that have passed since last communication or field drop (reset)
                    // We always recieve a 'one' first, which has the falling edge after a half period |-_|
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
                    if (!bSkip) {
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
                } else {
                    // Ignore wierd value, is to small to mean anything
                    errorCount++;
                }
            }

            // if we saw over 100 wierd values break it probably isn't hitag...
            if (errorCount > 100) break;

            // We can break this loop if we received the last bit from a frame
            if (AT91C_BASE_TC1->TC_CV > T0 * HITAG_T_EOF) {
                if (rxlen > 0)
                    break;
            }
        }
    }
    end = false;
    LEDsoff();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    set_tracing(false);

    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;

    StartTicks();

    reply_old(CMD_ACK, bSuccessful, 0, 0, 0, 0);
}

/*
 * Tries to authenticate to a Hitag S Transponder with the given challenges from a .cc file.
 * Displays all Challenges that failed.
 * When collecting Challenges to break the key it is possible that some data
 * is not received correctly due to Antenna problems. This function
 * detects these challenges.
 */
void check_challenges(bool file_given, uint8_t *data) {
    int i, j, z, k;
//    int frame_count = 0;
    int response = 0;
    uint8_t uid_byte[4];
    uint8_t rx[HITAG_FRAME_LEN];
    uint8_t unlocker[60][8];
    int u1 = 0;
    size_t rxlen = 0;
    uint8_t txbuf[HITAG_FRAME_LEN];
    int t_wait = HITAG_T_WAIT_MAX;
    int lastbit, reset_sof, STATE = 0;;
    bool bStop;
    int response_bit[200];
    unsigned char mask = 1;
    unsigned char uid[32];
    unsigned char crc;

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    // Reset the return status
    bSuccessful = false;

    // Clean up trace and prepare it for storing frames
    set_tracing(true);
    clear_trace();

    bQuiet = false;

    LED_D_ON();

    // Configure output and enable pin that is connected to the FPGA (for modulating)
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;

    // Set fpga in edge detect with reader field, we can modulate as reader now
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | FPGA_LF_EDGE_DETECT_READER_FIELD);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
    SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

    // Disable modulation at default, which means enable the field
    LOW(GPIO_SSC_DOUT);

    // Enable Peripheral Clock for
    //   TIMER_CLOCK0, used to measure exact timing before answering
    //   TIMER_CLOCK1, used to capture edges of the tag frames
    AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC0) | (1 << AT91C_ID_TC1);

    AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;

    // Disable timer during configuration
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    // TC0: Capture mode, default timer source = MCK/2 (TIMER_CLOCK1), no triggers
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV1_CLOCK;

    // TC1:  Capture mode, defaul timer source = MCK/2 (TIMER_CLOCK1), TIOA is external trigger,
    // external trigger rising edge, load RA on falling edge of TIOA.
    AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_TIMER_DIV1_CLOCK
                             | AT91C_TC_ETRGEDG_FALLING
                             | AT91C_TC_ABETRG
                             | AT91C_TC_LDRA_FALLING;

    // Enable and reset counters
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    while (AT91C_BASE_TC0->TC_CV > 0) {};

    // Reset the received frame, frame count and timing info
    lastbit = 1;
    bStop = false;
    reset_sof = 1;
    t_wait = 200;

    if (file_given) {
        DbpString("Loading challenges...");
        memcpy((uint8_t *)unlocker, data, 60 * 8);
    }

    while (file_given && !bStop && !BUTTON_PRESS()) {
        // Watchdog hit
        WDT_HIT();

        // Check if frame was captured and store it
        if (rxlen > 0) {
//            frame_count++;
            LogTrace(rx, nbytes(rxlen), response, 0, NULL, false);
        }

        uint8_t *tx = txbuf;
        size_t txlen = 0;
        if (rxlen == 0) {
            if (STATE == 2)
                // challenge failed
                Dbprintf("Challenge failed: %02X %02X %02X %02X %02X %02X %02X %02X",
                         unlocker[u1 - 1][0], unlocker[u1 - 1][1],
                         unlocker[u1 - 1][2], unlocker[u1 - 1][3],
                         unlocker[u1 - 1][4], unlocker[u1 - 1][5],
                         unlocker[u1 - 1][6], unlocker[u1 - 1][7]);
            STATE = 0;
            txlen = 5;
            //start new authentication
            memcpy(tx, "\xC0", nbytes(txlen));
        } else if (rxlen >= 67 && STATE == 0) {
            //received uid
            z = 0;
            for (i = 0; i < 10; i++) {
                for (j = 0; j < 8; j++) {
                    response_bit[z] = 0;
                    if ((rx[i] & ((mask << 7) >> j)) != 0)
                        response_bit[z] = 1;
                    z++;
                }
            }
            k = 0;
            for (i = 5; i < z; i += 2) {
                uid[k] = response_bit[i];
                k++;
                if (k > 31)
                    break;
            }
            uid_byte[0] = (uid[0] << 7) | (uid[1] << 6) | (uid[2] << 5)
                          | (uid[3] << 4) | (uid[4] << 3) | (uid[5] << 2)
                          | (uid[6] << 1) | uid[7];
            uid_byte[1] = (uid[8] << 7) | (uid[9] << 6) | (uid[10] << 5)
                          | (uid[11] << 4) | (uid[12] << 3) | (uid[13] << 2)
                          | (uid[14] << 1) | uid[15];
            uid_byte[2] = (uid[16] << 7) | (uid[17] << 6) | (uid[18] << 5)
                          | (uid[19] << 4) | (uid[20] << 3) | (uid[21] << 2)
                          | (uid[22] << 1) | uid[23];
            uid_byte[3] = (uid[24] << 7) | (uid[25] << 6) | (uid[26] << 5)
                          | (uid[27] << 4) | (uid[28] << 3) | (uid[29] << 2)
                          | (uid[30] << 1) | uid[31];
            //Dbhexdump(10, rx, rxlen);
            STATE = 1;
            txlen = 45;
            crc = CRC_PRESET;
            calc_crc(&crc, 0x00, 5);
            calc_crc(&crc, uid_byte[0], 8);
            calc_crc(&crc, uid_byte[1], 8);
            calc_crc(&crc, uid_byte[2], 8);
            calc_crc(&crc, uid_byte[3], 8);
            for (i = 0; i < 100; i++) {
                response_bit[i] = 0;
            }
            for (i = 0; i < 5; i++) {
                response_bit[i] = 0;
            }
            for (i = 5; i < 37; i++) {
                response_bit[i] = uid[i - 5];
            }
            for (j = 0; j < 8; j++) {
                response_bit[i] = 0;
                if ((crc & ((mask << 7) >> j)) != 0)
                    response_bit[i] = 1;
                i++;
            }
            k = 0;
            for (i = 0; i < 6; i++) {
                tx[i] = (response_bit[k] << 7) | (response_bit[k + 1] << 6)
                        | (response_bit[k + 2] << 5)
                        | (response_bit[k + 3] << 4)
                        | (response_bit[k + 4] << 3)
                        | (response_bit[k + 5] << 2)
                        | (response_bit[k + 6] << 1) | response_bit[k + 7];
                k += 8;
            }

        } else if (STATE == 1 && rxlen == 44) {
            //received configuration
            STATE = 2;
            z = 0;
            for (i = 0; i < 6; i++) {
                for (j = 0; j < 8; j++) {
                    response_bit[z] = 0;
                    if ((rx[i] & ((mask << 7) >> j)) != 0)
                        response_bit[z] = 1;
                    z++;
                }
            }
            txlen = 64;

            if (u1 >= ARRAYLEN(unlocker))
                bStop = !false;
            for (i = 0; i < 8; i++)
                tx[i] = unlocker[u1][i];
            u1++;

        } else if (STATE == 2 && rxlen >= 44) {
            STATE = 0;
        }

        // Send and store the reader command
        // Disable timer 1 with external trigger to avoid triggers during our own modulation
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

        // Wait for HITAG_T_WAIT_2 carrier periods after the last tag bit before transmitting,
        // Since the clock counts since the last falling edge, a 'one' means that the
        // falling edge occured halfway the period. with respect to this falling edge,
        // we need to wait (T_Wait2 + half_tag_period) when the last was a 'one'.
        // All timer values are in terms of T0 units

        while (AT91C_BASE_TC0->TC_CV < T0 * (t_wait + (HITAG_T_TAG_HALF_PERIOD * lastbit))) {};

        // Transmit the reader frame
        hitag_reader_send_frame(tx, txlen);

        // Enable and reset external trigger in timer for capturing future frames
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

        // Add transmitted frame to total count
        if (txlen > 0) {
//            frame_count++;
            LogTrace(tx, nbytes(txlen), HITAG_T_WAIT_2, 0, NULL, true);
        }

        // Reset values for receiving frames
        memset(rx, 0x00, sizeof(rx));
        rxlen = 0;
        lastbit = 1;
        bool bSkip = true;
        int tag_sof = reset_sof;
        response = 0;

        // Receive frame, watch for at most T0*EOF periods
        while (AT91C_BASE_TC1->TC_CV < T0 * HITAG_T_WAIT_MAX) {
            // Check if falling edge in tag modulation is detected
            if (AT91C_BASE_TC1->TC_SR & AT91C_TC_LDRAS) {
                // Retrieve the new timing values
                int ra = (AT91C_BASE_TC1->TC_RA / T0);

                // Reset timer every frame, we have to capture the last edge for timing
                AT91C_BASE_TC0->TC_CCR = AT91C_TC_SWTRG;

                LED_B_ON();

                // Capture tag frame (manchester decoding using only falling edges)
                if (ra >= HITAG_T_EOF) {
                    if (rxlen != 0) {
                        //DbpString("wierd1?");
                    }
                    // Capture the T0 periods that have passed since last communication or field drop (reset)
                    // We always recieve a 'one' first, which has the falling edge after a half period |-_|
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
                    if (!bSkip) {
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
                } else {
                    // Ignore wierd value, is to small to mean anything
                }
            }

            // We can break this loop if we received the last bit from a frame
            if (AT91C_BASE_TC1->TC_CV > T0 * HITAG_T_EOF) {
                if (rxlen > 0)
                    break;
            }
        }
    }

    LEDsoff();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    set_tracing(false);

    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;

    StartTicks();

    reply_old(CMD_ACK, bSuccessful, 0, 0, 0, 0);
}



