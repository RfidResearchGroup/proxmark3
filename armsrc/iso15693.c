//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Nov 2006
// Copyright (C) Greg Jones, Jan 2009
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
// Routines to support ISO 15693. This includes both the reader software and
// the `fake tag' modes.
//-----------------------------------------------------------------------------

// The ISO 15693 describes two transmission modes from reader to tag, and four
// transmission modes from tag to reader. As of Oct 2018 this code supports
// both reader modes and the high speed variant with one subcarrier from card to reader.
// As long as the card fully support ISO 15693 this is no problem, since the
// reader chooses both data rates, but some non-standard tags do not.
// For card simulation, the code supports both high and low speed modes with one subcarrier.
//
// VCD (reader) -> VICC (tag)
// 1 out of 256:
//  data rate: 1,66 kbit/s (fc/8192)
//  used for long range
// 1 out of 4:
//  data rate: 26,48 kbit/s (fc/512)
//  used for short range, high speed
//
// VICC (tag) -> VCD (reader)
// Modulation:
//    ASK / one subcarrier (423,75 kHz)
//    FSK / two subcarriers (423,75 kHz && 484,28 kHz)
// Data Rates / Modes:
//  low ASK: 6,62 kbit/s
//  low FSK: 6.67 kbit/s
//  high ASK: 26,48 kbit/s
//  high FSK: 26,69 kbit/s
//-----------------------------------------------------------------------------
// added "1 out of 256" mode (for VCD->PICC) - atrox 20100911


// Random Remarks:
// *) UID is always used "transmission order" (LSB), which is reverse to display order

// TODO / BUGS / ISSUES:
// *) signal decoding is unable to detect collisions.
// *) add anti-collision support for inventory-commands
// *) read security status of a block
// *) sniffing and simulation do not support two subcarrier modes.
// *) remove or refactor code under "deprecated"
// *) document all the functions

#include "iso15693.h"

#include "proxmark3_arm.h"
#include "util.h"
#include "string.h"
#include "iso15693tools.h"
#include "protocols.h"
#include "cmd.h"
#include "appmain.h"
#include "dbprint.h"
#include "fpgaloader.h"
#include "commonutil.h"
#include "ticks.h"
#include "BigBuf.h"
#include "crc16.h"

// Delays in SSP_CLK ticks.
// SSP_CLK runs at 13,56MHz / 32 = 423.75kHz when simulating a tag
#define DELAY_READER_TO_ARM               8
#define DELAY_ARM_TO_READER               0

//SSP_CLK runs at 13.56MHz / 4 = 3,39MHz when acting as reader. All values should be multiples of 16
#define DELAY_ARM_TO_TAG                 16
#define DELAY_TAG_TO_ARM                 32

//SSP_CLK runs at 13.56MHz / 4 = 3,39MHz when sniffing. All values should be multiples of 16
#define DELAY_TAG_TO_ARM_SNIFF           32
#define DELAY_READER_TO_ARM_SNIFF        32

// times in samples @ 212kHz when acting as reader
#define ISO15693_READER_TIMEOUT            330  // 330/212kHz = 1558us
#define ISO15693_READER_TIMEOUT_WRITE      4700 // 4700/212kHz = 22ms, nominal 20ms

// iceman: This defines below exists in the header file,  just here for my easy reading
// Delays in SSP_CLK ticks.
// SSP_CLK runs at 13,56MHz / 32 = 423.75kHz when simulating a tag
//#define DELAY_ISO15693_VCD_TO_VICC_SIM     132  // 132/423.75kHz = 311.5us from end of command EOF to start of tag response

//SSP_CLK runs at 13.56MHz / 4 = 3,39MHz when acting as reader. All values should be multiples of 16
//#define DELAY_ISO15693_VCD_TO_VICC_READER 1056 // 1056/3,39MHz = 311.5us from end of command EOF to start of tag response
//#define DELAY_ISO15693_VICC_TO_VCD_READER 1024 // 1024/3.39MHz = 302.1us between end of tag response and next reader command


///////////////////////////////////////////////////////////////////////
// ISO 15693 Part 2 - Air Interface
// This section basically contains transmission and receiving of bits
///////////////////////////////////////////////////////////////////////

// buffers
#define ISO15693_MAX_RESPONSE_LENGTH     36 // allows read single block with the maximum block size of 256bits. Read multiple blocks not supported yet
#define ISO15693_MAX_COMMAND_LENGTH      45 // allows write single block with the maximum block size of 256bits. Write multiple blocks not supported yet

// 32 + 2 crc + 1
#define ISO15_MAX_FRAME     35
#define CMD_ID_RESP         5
#define CMD_READ_RESP       13
#define CMD_INV_RESP        12
#define CMD_SYSINFO_RESP    17
#define CMD_READBLOCK_RESP  7

//#define Crc(data, len)        Crc(CRC_15693, (data), (len))
#define CheckCrc15(data, len)   check_crc(CRC_15693, (data), (len))
#define AddCrc15(data, len)     compute_crc(CRC_15693, (data), (len), (data)+(len), (data)+(len)+1)

static void BuildIdentifyRequest(uint8_t *cmd);

// ---------------------------

// Signal Processing
// ---------------------------

// prepare data using "1 out of 4" code for later transmission
// resulting data rate is 26.48 kbit/s (fc/512)
// cmd ... data
// n ... length of data
static uint8_t encode15_lut[] = {
    0x40, // 01000000
    0x10, // 00010000
    0x04, // 00000100
    0x01  // 00000001
};

void CodeIso15693AsReader(const uint8_t *cmd, int n) {

    tosend_reset();
    tosend_t *ts = get_tosend();

    // SOF for 1of4
    ts->buf[++ts->max] = 0x84; //10000100

    // data
    for (int i = 0; i < n; i++) {

        volatile uint8_t b = (cmd[i] >> 0) & 0x03;
        ts->buf[++ts->max] = encode15_lut[b];

        b = (cmd[i] >> 2) & 0x03;
        ts->buf[++ts->max] = encode15_lut[b];

        b = (cmd[i] >> 4) & 0x03;
        ts->buf[++ts->max] = encode15_lut[b];

        b = (cmd[i] >> 6) & 0x03;
        ts->buf[++ts->max] = encode15_lut[b];
    }

    // EOF
    ts->buf[++ts->max] = 0x20; //0010 + 0000 padding
    ts->max++;
}

// Encode EOF only
static void CodeIso15693AsReaderEOF(void) {
    tosend_reset();
    tosend_t *ts = get_tosend();
    ts->buf[++ts->max] = 0x20;
    ts->max++;
}


// encode data using "1 out of 256" scheme
// data rate is 1,66 kbit/s (fc/8192)
// is designed for more robust communication over longer distances
static void CodeIso15693AsReader256(const uint8_t *cmd, int n) {

    tosend_reset();
    tosend_t *ts = get_tosend();

    // SOF for 1of256
    ts->buf[++ts->max] = 0x81; //10000001

    // data
    for (int i = 0; i < n; i++) {
        for (int j = 0; j <= 255; j++) {
            if (cmd[i] == j) {
                tosend_stuffbit(0);
                tosend_stuffbit(1);
            } else {
                tosend_stuffbit(0);
                tosend_stuffbit(0);
            }
        }
    }

    // EOF
    ts->buf[++ts->max] = 0x20; //0010 + 0000 padding
    ts->max++;
}

static const uint8_t encode_4bits[16] = {
//  0     1     2     3
    0xaa, 0x6a, 0x9a, 0x5a,
//  4     5     6     7
    0xa6, 0x66, 0x96, 0x56,
//  8     9     A     B
    0xa9, 0x69, 0x99, 0x59,
//  C    D      E     F
    0xa5, 0x65, 0x95, 0x55
};

void CodeIso15693AsTag(const uint8_t *cmd, size_t len) {
    /*
     * SOF comprises 3 parts;
     * * An unmodulated time of 56.64 us
     * * 24 pulses of 423.75 kHz (fc/32)
     * * A logic 1, which starts with an unmodulated time of 18.88us
     *   followed by 8 pulses of 423.75kHz (fc/32)
     *
     * EOF comprises 3 parts:
     * - A logic 0 (which starts with 8 pulses of fc/32 followed by an unmodulated
     *   time of 18.88us.
     * - 24 pulses of fc/32
     * - An unmodulated time of 56.64 us
     *
     * A logic 0 starts with 8 pulses of fc/32
     * followed by an unmodulated time of 256/fc (~18,88us).
     *
     * A logic 0 starts with unmodulated time of 256/fc (~18,88us) followed by
     * 8 pulses of fc/32 (also 18.88us)
     *
     * A bit here becomes 8 pulses of fc/32. Therefore:
     * The SOF can be written as 00011101 = 0x1D
     * The EOF can be written as 10111000 = 0xb8
     * A logic 1 is 01
     * A logic 0 is 10
     *
     * */
    tosend_reset();
    tosend_t *ts = get_tosend();

    // SOF
    ts->buf[++ts->max] = 0x1D;  // 00011101

    // data
    for (size_t i = 0; i < len; i += 2) {
        ts->buf[++ts->max] = encode_4bits[cmd[i] & 0xF];
        ts->buf[++ts->max] = encode_4bits[cmd[i] >> 4];
        ts->buf[++ts->max] = encode_4bits[cmd[i + 1] & 0xF];
        ts->buf[++ts->max] = encode_4bits[cmd[i + 1] >> 4];
    }

    // EOF
    ts->buf[++ts->max] = 0xB8; // 10111000
    ts->max++;
}

// Transmit the command (to the tag) that was placed in cmd[].
void TransmitTo15693Tag(const uint8_t *cmd, int len, uint32_t *start_time) {

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SEND_FULL_MOD);

    if (*start_time < DELAY_ARM_TO_TAG) {
        *start_time = DELAY_ARM_TO_TAG;
    }

    *start_time = (*start_time - DELAY_ARM_TO_TAG) & 0xfffffff0;

    if (GetCountSspClk() > *start_time) { // we may miss the intended time
        *start_time = (GetCountSspClk() + 16) & 0xfffffff0; // next possible time
    }

    // wait
    while (GetCountSspClk() < *start_time) ;

    LED_B_ON();
    for (int c = 0; c < len; c++) {
        volatile uint8_t data = cmd[c];

        for (uint8_t i = 0; i < 8; i++) {
            uint16_t send_word = (data & 0x80) ? 0xffff : 0x0000;
            while (!(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))) ;
            AT91C_BASE_SSC->SSC_THR = send_word;
            while (!(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))) ;
            AT91C_BASE_SSC->SSC_THR = send_word;
            data <<= 1;
        }
        WDT_HIT();
    }
    LED_B_OFF();

    *start_time = *start_time + DELAY_ARM_TO_TAG;
    FpgaDisableTracing();
}

//-----------------------------------------------------------------------------
// Transmit the tag response (to the reader) that was placed in cmd[].
//-----------------------------------------------------------------------------
void TransmitTo15693Reader(const uint8_t *cmd, size_t len, uint32_t *start_time, uint32_t slot_time, bool slow) {

    // don't use the FPGA_HF_SIMULATOR_MODULATE_424K_8BIT minor mode. It would spoil GetCountSspClk()
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_424K);

    uint32_t modulation_start_time = *start_time - DELAY_ARM_TO_READER + 3 * 8;  // no need to transfer the unmodulated start of SOF

    while (GetCountSspClk() > (modulation_start_time & 0xfffffff8) + 3) { // we will miss the intended time
        if (slot_time) {
            modulation_start_time += slot_time; // use next available slot
        } else {
            modulation_start_time = (modulation_start_time & 0xfffffff8) + 8; // next possible time
        }
    }

    // wait
    while (GetCountSspClk() < (modulation_start_time & 0xfffffff8)) ;

    uint8_t shift_delay = modulation_start_time & 0x00000007;

    *start_time = modulation_start_time + DELAY_ARM_TO_READER - 3 * 8;

    LED_C_ON();
    uint8_t bits_to_shift = 0x00;
    uint8_t bits_to_send = 0x00;

    for (size_t c = 0; c < len; c++) {
        for (int i = (c == 0 ? 4 : 7); i >= 0; i--) {

            uint8_t cmd_bits = ((cmd[c] >> i) & 0x01) ? 0xff : 0x00;

            for (int j = 0; j < (slow ? 4 : 1);) {
                if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) {
                    bits_to_send = bits_to_shift << (8 - shift_delay) | cmd_bits >> shift_delay;
                    AT91C_BASE_SSC->SSC_THR = bits_to_send;
                    bits_to_shift = cmd_bits;
                    j++;
                }
            }
        }
        WDT_HIT();
    }

    // send the remaining bits, padded with 0:
    bits_to_send = bits_to_shift << (8 - shift_delay);
    if (bits_to_send) {
        for (; ;) {
            if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) {
                AT91C_BASE_SSC->SSC_THR = bits_to_send;
                break;
            }
        }
    }
    LED_C_OFF();
}

//=============================================================================
// An ISO 15693 decoder for tag responses (one subcarrier only).
// Uses cross correlation to identify each bit and EOF.
// This function is called 8 times per bit (every 2 subcarrier cycles).
// Subcarrier frequency fs is 424kHz, 1/fs = 2,36us,
// i.e. function is called every 4,72us
// LED handling:
//    LED C -> ON once we have received the SOF and are expecting the rest.
//    LED C -> OFF once we have received EOF or are unsynced
//
// Returns: true if we received a EOF
//          false if we are still waiting for some more
//=============================================================================

#define NOISE_THRESHOLD          80                   // don't try to correlate noise
#define MAX_PREVIOUS_AMPLITUDE   (-1 - NOISE_THRESHOLD)

typedef struct {
    enum {
        STATE_TAG_SOF_LOW,
        STATE_TAG_SOF_RISING_EDGE,
        STATE_TAG_SOF_HIGH,
        STATE_TAG_SOF_HIGH_END,
        STATE_TAG_RECEIVING_DATA,
        STATE_TAG_EOF,
        STATE_TAG_EOF_TAIL
    } state;
    int bitCount;
    int posCount;
    enum {
        LOGIC0,
        LOGIC1,
        SOF_PART1,
        SOF_PART2
    } lastBit;
    uint16_t shiftReg;
    uint16_t max_len;
    uint8_t *output;
    int len;
    int sum1;
    int sum2;
    int threshold_sof;
    int threshold_half;
    uint16_t  previous_amplitude;
} DecodeTag_t;

//-----------------------------------------------------------------------------
// DEMODULATE tag answer
//-----------------------------------------------------------------------------
static RAMFUNC int Handle15693SamplesFromTag(uint16_t amplitude, DecodeTag_t *tag) {

    switch (tag->state) {

        case STATE_TAG_SOF_LOW: {
            // waiting for a rising edge
            if (amplitude > NOISE_THRESHOLD + tag->previous_amplitude) {
                if (tag->posCount > 10) {
                    tag->threshold_sof = amplitude - tag->previous_amplitude; // to be divided by 2
                    tag->threshold_half = 0;
                    tag->state = STATE_TAG_SOF_RISING_EDGE;
                } else {
                    tag->posCount = 0;
                }
            } else {
                tag->posCount++;
                tag->previous_amplitude = amplitude;
            }
            break;
        }

        case STATE_TAG_SOF_RISING_EDGE: {
            if (amplitude > tag->threshold_sof + tag->previous_amplitude) { // edge still rising
                if (amplitude > tag->threshold_sof + tag->threshold_sof) { // steeper edge, take this as time reference
                    tag->posCount = 1;
                } else {
                    tag->posCount = 2;
                }
                tag->threshold_sof = (amplitude - tag->previous_amplitude) / 2;
            } else {
                tag->posCount = 2;
                tag->threshold_sof = tag->threshold_sof / 2;
            }
            tag->state = STATE_TAG_SOF_HIGH;
            break;
        }

        case STATE_TAG_SOF_HIGH: {
            // waiting for 10 times high. Take average over the last 8
            if (amplitude > tag->threshold_sof) {
                tag->posCount++;
                if (tag->posCount > 2) {
                    tag->threshold_half += amplitude; // keep track of average high value
                }
                if (tag->posCount == 10) {
                    tag->threshold_half >>= 2; // (4 times 1/2 average)
                    tag->state = STATE_TAG_SOF_HIGH_END;
                }
            } else { // high phase was too short
                tag->posCount = 1;
                tag->previous_amplitude = amplitude;
                tag->state = STATE_TAG_SOF_LOW;
            }
            break;
        }

        case STATE_TAG_SOF_HIGH_END: {
            // check for falling edge
            if (tag->posCount == 13 && amplitude < tag->threshold_sof) {
                tag->lastBit = SOF_PART1;  // detected 1st part of SOF (12 samples low and 12 samples high)
                tag->shiftReg = 0;
                tag->bitCount = 0;
                tag->len = 0;
                tag->sum1 = amplitude;
                tag->sum2 = 0;
                tag->posCount = 2;
                tag->state = STATE_TAG_RECEIVING_DATA;
                LED_C_ON();
            } else {
                tag->posCount++;
                if (tag->posCount > 13) { // high phase too long
                    tag->posCount = 0;
                    tag->previous_amplitude = amplitude;
                    tag->state = STATE_TAG_SOF_LOW;
                    LED_C_OFF();
                }
            }
            break;
        }

        case STATE_TAG_RECEIVING_DATA: {
            if (tag->posCount == 1) {
                tag->sum1 = 0;
                tag->sum2 = 0;
            }

            if (tag->posCount <= 4) {
                tag->sum1 += amplitude;
            } else {
                tag->sum2 += amplitude;
            }

            if (tag->posCount == 8) {
                if (tag->sum1 > tag->threshold_half && tag->sum2 > tag->threshold_half) { // modulation in both halves
                    if (tag->lastBit == LOGIC0) {  // this was already part of EOF
                        tag->state = STATE_TAG_EOF;
                    } else {
                        tag->posCount = 0;
                        tag->previous_amplitude = amplitude;
                        tag->state = STATE_TAG_SOF_LOW;
                        LED_C_OFF();
                    }
                } else if (tag->sum1 < tag->threshold_half && tag->sum2 > tag->threshold_half) { // modulation in second half
                    // logic 1
                    if (tag->lastBit == SOF_PART1) { // still part of SOF
                        tag->lastBit = SOF_PART2;    // SOF completed
                    } else {
                        tag->lastBit = LOGIC1;
                        tag->shiftReg >>= 1;
                        tag->shiftReg |= 0x80;
                        tag->bitCount++;
                        if (tag->bitCount == 8) {
                            tag->output[tag->len] = tag->shiftReg & 0xFF;
                            tag->len++;

                            if (tag->len > tag->max_len) {
                                // buffer overflow, give up
                                LED_C_OFF();
                                return true;
                            }
                            tag->bitCount = 0;
                            tag->shiftReg = 0;
                        }
                    }
                } else if (tag->sum1 > tag->threshold_half && tag->sum2 < tag->threshold_half) { // modulation in first half
                    // logic 0
                    if (tag->lastBit == SOF_PART1) { // incomplete SOF
                        tag->posCount = 0;
                        tag->previous_amplitude = amplitude;
                        tag->state = STATE_TAG_SOF_LOW;
                        LED_C_OFF();
                    } else {
                        tag->lastBit = LOGIC0;
                        tag->shiftReg >>= 1;
                        tag->bitCount++;

                        if (tag->bitCount == 8) {
                            tag->output[tag->len] = (tag->shiftReg & 0xFF);
                            tag->len++;

                            if (tag->len > tag->max_len) {
                                // buffer overflow, give up
                                tag->posCount = 0;
                                tag->previous_amplitude = amplitude;
                                tag->state = STATE_TAG_SOF_LOW;
                                LED_C_OFF();
                            }
                            tag->bitCount = 0;
                            tag->shiftReg = 0;
                        }
                    }
                } else { // no modulation
                    if (tag->lastBit == SOF_PART2) { // only SOF (this is OK for iClass)
                        LED_C_OFF();
                        return true;
                    } else {
                        tag->posCount = 0;
                        tag->state = STATE_TAG_SOF_LOW;
                        LED_C_OFF();
                    }
                }
                tag->posCount = 0;
            }
            tag->posCount++;
            break;
        }

        case STATE_TAG_EOF: {
            if (tag->posCount == 1) {
                tag->sum1 = 0;
                tag->sum2 = 0;
            }

            if (tag->posCount <= 4) {
                tag->sum1 += amplitude;
            } else {
                tag->sum2 += amplitude;
            }

            if (tag->posCount == 8) {
                if (tag->sum1 > tag->threshold_half && tag->sum2 < tag->threshold_half) { // modulation in first half
                    tag->posCount = 0;
                    tag->state = STATE_TAG_EOF_TAIL;
                } else {
                    tag->posCount = 0;
                    tag->previous_amplitude = amplitude;
                    tag->state = STATE_TAG_SOF_LOW;
                    LED_C_OFF();
                }
            }
            tag->posCount++;
            break;
        }

        case STATE_TAG_EOF_TAIL: {
            if (tag->posCount == 1) {
                tag->sum1 = 0;
                tag->sum2 = 0;
            }

            if (tag->posCount <= 4) {
                tag->sum1 += amplitude;
            } else {
                tag->sum2 += amplitude;
            }

            if (tag->posCount == 8) {
                if (tag->sum1 < tag->threshold_half && tag->sum2 < tag->threshold_half) { // no modulation in both halves
                    LED_C_OFF();
                    return true;
                } else {
                    tag->posCount = 0;
                    tag->previous_amplitude = amplitude;
                    tag->state = STATE_TAG_SOF_LOW;
                    LED_C_OFF();
                }
            }
            tag->posCount++;
            break;
        }
    }

    return false;
}

static void DecodeTagReset(DecodeTag_t *tag) {
    tag->posCount = 0;
    tag->state = STATE_TAG_SOF_LOW;
    tag->previous_amplitude = MAX_PREVIOUS_AMPLITUDE;
}

static void DecodeTagInit(DecodeTag_t *tag, uint8_t *data, uint16_t max_len) {
    tag->output = data;
    tag->max_len = max_len;
    DecodeTagReset(tag);
}

/*
 *  Receive and decode the tag response, also log to tracebuffer
 */
int GetIso15693AnswerFromTag(uint8_t *response, uint16_t max_len, uint16_t timeout, uint32_t *eof_time) {

    int samples = 0, ret = 0;

    // the Decoder data structure
    DecodeTag_t dtm = { 0 };
    DecodeTag_t *dt = &dtm;
    DecodeTagInit(dt, response, max_len);

    // wait for last transfer to complete
    while (!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXEMPTY));

    // And put the FPGA in the appropriate mode
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_SUBCARRIER_424_KHZ | FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE);

    // Setup and start DMA.
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);

    // The DMA buffer, used to stream samples from the FPGA
    dmabuf16_t *dma = get_dma16();

    // Setup and start DMA.
    if (FpgaSetupSscDma((uint8_t *) dma->buf, DMA_BUFFER_SIZE) == false) {
        if (g_dbglevel > DBG_ERROR) Dbprintf("FpgaSetupSscDma failed. Exiting");
        return -4;
    }

    uint32_t dma_start_time = 0;
    uint16_t *upTo = dma->buf;

    for (;;) {

        volatile uint16_t behindBy = ((uint16_t *)AT91C_BASE_PDC_SSC->PDC_RPR - upTo) & (DMA_BUFFER_SIZE - 1);
        if (behindBy == 0)
            continue;

        samples++;
        if (samples == 1) {
            // DMA has transferred the very first data
            dma_start_time = GetCountSspClk() & 0xfffffff0;
        }

        volatile uint16_t tagdata = *upTo++;

        if (upTo >= dma->buf + DMA_BUFFER_SIZE) {                // we have read all of the DMA buffer content.
            upTo = dma->buf;                                     // start reading the circular buffer from the beginning

            // DMA Counter Register had reached 0, already rotated.
            if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_ENDRX)) {

                // primary buffer was stopped
                if (AT91C_BASE_PDC_SSC->PDC_RCR == false) {
                    AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) dma->buf;
                    AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
                }
                // secondary buffer sets as primary, secondary buffer was stopped
                if (AT91C_BASE_PDC_SSC->PDC_RNCR == false) {
                    AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dma->buf;
                    AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
                }

                WDT_HIT();
                if (BUTTON_PRESS()) {
                    DbpString("stopped");
                    break;
                }
            }
        }

        if (Handle15693SamplesFromTag(tagdata, dt)) {

            *eof_time = dma_start_time + (samples * 16) - DELAY_TAG_TO_ARM; // end of EOF

            if (dt->lastBit == SOF_PART2) {
                *eof_time -= (8 * 16); // needed 8 additional samples to confirm single SOF (iCLASS)
            }
            if (dt->len > dt->max_len) {
                ret = -2; // buffer overflow
                Dbprintf("overflow (%d > %d", dt->len, dt->max_len);
            }
            break;
        }

        // timeout
        if (samples > timeout && dt->state < STATE_TAG_RECEIVING_DATA) {
            ret = -3;
            break;
        }

    }

    FpgaDisableSscDma();
    FpgaDisableTracing();

    uint32_t sof_time = *eof_time
                        - (dt->len * 8 * 8 * 16) // time for byte transfers
                        - (32 * 16)  // time for SOF transfer
                        - (dt->lastBit != SOF_PART2 ? (32 * 16) : 0); // time for EOF transfer

    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("samples = %d, ret = %d, Decoder: state = %d, lastBit = %d, len = %d, bitCount = %d, posCount = %d, maxlen = %u",
                 samples,
                 ret,
                 dt->state,
                 dt->lastBit,
                 dt->len,
                 dt->bitCount,
                 dt->posCount,
                 dt->max_len
                );
        Dbprintf("timing: sof_time = %d, eof_time = %d", (sof_time * 4), (*eof_time * 4));
    }

    if (ret < 0) {
        return ret;
    }

    LogTrace_ISO15693(dt->output, dt->len, (sof_time * 4), (*eof_time * 4), NULL, false);
    return dt->len;
}


//=============================================================================
// An ISO15693 decoder for reader commands.
//
// This function is called 4 times per bit (every 2 subcarrier cycles).
// Subcarrier frequency fs is 848kHz, 1/fs = 1,18us, i.e. function is called every 2,36us
// LED handling:
//    LED B -> ON once we have received the SOF and are expecting the rest.
//    LED B -> OFF once we have received EOF or are in error state or unsynced
//
// Returns: true  if we received a EOF
//          false if we are still waiting for some more
//=============================================================================

typedef struct {
    enum {
        STATE_READER_UNSYNCD,
        STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF,
        STATE_READER_AWAIT_1ST_RISING_EDGE_OF_SOF,
        STATE_READER_AWAIT_2ND_FALLING_EDGE_OF_SOF,
        STATE_READER_AWAIT_2ND_RISING_EDGE_OF_SOF,
        STATE_READER_AWAIT_END_OF_SOF_1_OUT_OF_4,
        STATE_READER_RECEIVE_DATA_1_OUT_OF_4,
        STATE_READER_RECEIVE_DATA_1_OUT_OF_256,
        STATE_READER_RECEIVE_JAMMING
    }           state;
    enum {
        CODING_1_OUT_OF_4,
        CODING_1_OUT_OF_256
    }           Coding;
    uint8_t     shiftReg;
    uint8_t     bitCount;
    int         byteCount;
    int         byteCountMax;
    int         posCount;
    int         sum1, sum2;
    uint8_t     *output;
    uint8_t     jam_search_len;
    uint8_t     *jam_search_string;
} DecodeReader_t;

static void DecodeReaderInit(DecodeReader_t *reader, uint8_t *data, uint16_t max_len, uint8_t jam_search_len, uint8_t *jam_search_string) {
    reader->output = data;
    reader->byteCountMax = max_len;
    reader->state = STATE_READER_UNSYNCD;
    reader->byteCount = 0;
    reader->bitCount = 0;
    reader->posCount = 1;
    reader->shiftReg = 0;
    reader->jam_search_len = jam_search_len;
    reader->jam_search_string = jam_search_string;
}

static void DecodeReaderReset(DecodeReader_t *reader) {
    reader->state = STATE_READER_UNSYNCD;
}

//static inline __attribute__((always_inline))
static int RAMFUNC Handle15693SampleFromReader(bool bit, DecodeReader_t *reader) {
    switch (reader->state) {
        case STATE_READER_UNSYNCD:
            // wait for unmodulated carrier
            if (bit) {
                reader->state = STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF;
            }
            break;

        case STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF:
            if (!bit) {
                // we went low, so this could be the beginning of a SOF
                reader->posCount = 1;
                reader->state = STATE_READER_AWAIT_1ST_RISING_EDGE_OF_SOF;
            }
            break;

        case STATE_READER_AWAIT_1ST_RISING_EDGE_OF_SOF:
            reader->posCount++;
            if (bit) { // detected rising edge
                if (reader->posCount < 4) { // rising edge too early (nominally expected at 5)
                    reader->state = STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF;
                } else { // SOF
                    reader->state = STATE_READER_AWAIT_2ND_FALLING_EDGE_OF_SOF;
                }
            } else {
                if (reader->posCount > 5) { // stayed low for too long
                    DecodeReaderReset(reader);
                } else {
                    // do nothing, keep waiting
                }
            }
            break;

        case STATE_READER_AWAIT_2ND_FALLING_EDGE_OF_SOF:

            reader->posCount++;

            if (bit == false) { // detected a falling edge

                if (reader->posCount < 20) {         // falling edge too early (nominally expected at 21 earliest)
                    DecodeReaderReset(reader);
                } else if (reader->posCount < 23) {  // SOF for 1 out of 4 coding
                    reader->Coding = CODING_1_OUT_OF_4;
                    reader->state = STATE_READER_AWAIT_2ND_RISING_EDGE_OF_SOF;
                } else if (reader->posCount < 28) {  // falling edge too early (nominally expected at 29 latest)
                    DecodeReaderReset(reader);
                } else {                                   // SOF for 1 out of 256 coding
                    reader->Coding = CODING_1_OUT_OF_256;
                    reader->state = STATE_READER_AWAIT_2ND_RISING_EDGE_OF_SOF;
                }

            } else {
                if (reader->posCount > 29) { // stayed high for too long
                    reader->state = STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF;
                } else {
                    // do nothing, keep waiting
                }
            }
            break;

        case STATE_READER_AWAIT_2ND_RISING_EDGE_OF_SOF:

            reader->posCount++;

            if (bit) { // detected rising edge
                if (reader->Coding == CODING_1_OUT_OF_256) {
                    if (reader->posCount < 32) { // rising edge too early (nominally expected at 33)
                        reader->state = STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF;
                    } else {
                        reader->posCount = 1;
                        reader->bitCount = 0;
                        reader->byteCount = 0;
                        reader->sum1 = 1;
                        reader->state = STATE_READER_RECEIVE_DATA_1_OUT_OF_256;
                        LED_B_ON();
                    }
                } else { // CODING_1_OUT_OF_4
                    if (reader->posCount < 24) { // rising edge too early (nominally expected at 25)
                        reader->state = STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF;
                    } else {
                        reader->posCount = 1;
                        reader->state = STATE_READER_AWAIT_END_OF_SOF_1_OUT_OF_4;
                    }
                }
            } else {
                if (reader->Coding == CODING_1_OUT_OF_256) {
                    if (reader->posCount > 34) { // signal stayed low for too long
                        DecodeReaderReset(reader);
                    } else {
                        // do nothing, keep waiting
                    }
                } else { // CODING_1_OUT_OF_4
                    if (reader->posCount > 26) { // signal stayed low for too long
                        DecodeReaderReset(reader);
                    } else {
                        // do nothing, keep waiting
                    }
                }
            }
            break;

        case STATE_READER_AWAIT_END_OF_SOF_1_OUT_OF_4:

            reader->posCount++;

            if (bit) {
                if (reader->posCount == 9) {
                    reader->posCount = 1;
                    reader->bitCount = 0;
                    reader->byteCount = 0;
                    reader->sum1 = 1;
                    reader->state = STATE_READER_RECEIVE_DATA_1_OUT_OF_4;
                    LED_B_ON();
                } else {
                    // do nothing, keep waiting
                }
            } else { // unexpected falling edge
                DecodeReaderReset(reader);
            }
            break;

        case STATE_READER_RECEIVE_DATA_1_OUT_OF_4:

            reader->posCount++;

            if (reader->posCount == 1) {

                reader->sum1 = bit ? 1 : 0;

            } else if (reader->posCount <= 4) {

                if (bit)
                    reader->sum1++;

            } else if (reader->posCount == 5) {

                reader->sum2 = bit ? 1 : 0;

            } else {
                if (bit)
                    reader->sum2++;
            }

            if (reader->posCount == 8) {
                reader->posCount = 0;
                if (reader->sum1 <= 1 && reader->sum2 >= 3) { // EOF
                    LED_B_OFF(); // Finished receiving
                    DecodeReaderReset(reader);
                    if (reader->byteCount != 0) {
                        return true;
                    }

                } else if (reader->sum1 >= 3 && reader->sum2 <= 1) { // detected a 2bit position
                    reader->shiftReg >>= 2;
                    reader->shiftReg |= (reader->bitCount << 6);
                }

                if (reader->bitCount == 15) { // we have a full byte

                    reader->output[reader->byteCount++] = reader->shiftReg;
                    if (reader->byteCount > reader->byteCountMax) {
                        // buffer overflow, give up
                        LED_B_OFF();
                        DecodeReaderReset(reader);
                    }

                    reader->bitCount = 0;
                    reader->shiftReg = 0;
                    if (reader->byteCount == reader->jam_search_len) {
                        if (!memcmp(reader->output, reader->jam_search_string, reader->jam_search_len)) {
                            LED_D_ON();
                            FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SEND_JAM);
                            reader->state = STATE_READER_RECEIVE_JAMMING;
                        }
                    }

                } else {
                    reader->bitCount++;
                }
            }
            break;

        case STATE_READER_RECEIVE_DATA_1_OUT_OF_256:

            reader->posCount++;

            if (reader->posCount == 1) {
                reader->sum1 = bit ? 1 : 0;
            } else if (reader->posCount <= 4) {
                if (bit) reader->sum1++;
            } else if (reader->posCount == 5) {
                reader->sum2 = bit ? 1 : 0;
            } else if (bit) {
                reader->sum2++;
            }

            if (reader->posCount == 8) {
                reader->posCount = 0;
                if (reader->sum1 <= 1 && reader->sum2 >= 3) { // EOF
                    LED_B_OFF(); // Finished receiving
                    DecodeReaderReset(reader);
                    if (reader->byteCount != 0) {
                        return true;
                    }

                } else if (reader->sum1 >= 3 && reader->sum2 <= 1) { // detected the bit position
                    reader->shiftReg = reader->bitCount;
                }

                if (reader->bitCount == 255) { // we have a full byte
                    reader->output[reader->byteCount++] = reader->shiftReg;
                    if (reader->byteCount > reader->byteCountMax) {
                        // buffer overflow, give up
                        LED_B_OFF();
                        DecodeReaderReset(reader);
                    }

                    if (reader->byteCount == reader->jam_search_len) {
                        if (!memcmp(reader->output, reader->jam_search_string, reader->jam_search_len)) {
                            LED_D_ON();
                            FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SEND_JAM);
                            reader->state = STATE_READER_RECEIVE_JAMMING;
                        }
                    }
                }
                reader->bitCount++;
            }
            break;

        case STATE_READER_RECEIVE_JAMMING:

            reader->posCount++;

            if (reader->Coding == CODING_1_OUT_OF_4) {
                if (reader->posCount == 7 * 16) { // 7 bits jammed
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SNIFF_AMPLITUDE); // stop jamming
                    // FpgaDisableTracing();
                    LED_D_OFF();
                } else if (reader->posCount == 8 * 16) {
                    reader->posCount = 0;
                    reader->output[reader->byteCount++] = 0x00;
                    reader->state = STATE_READER_RECEIVE_DATA_1_OUT_OF_4;
                }
            } else {
                if (reader->posCount == 7 * 256) { // 7 bits jammend
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SNIFF_AMPLITUDE); // stop jamming
                    LED_D_OFF();
                } else if (reader->posCount == 8 * 256) {
                    reader->posCount = 0;
                    reader->output[reader->byteCount++] = 0x00;
                    reader->state = STATE_READER_RECEIVE_DATA_1_OUT_OF_256;
                }
            }
            break;

        default:
            LED_B_OFF();
            DecodeReaderReset(reader);
            break;
    }

    return false;
}

//-----------------------------------------------------------------------------
// Receive a command (from the reader to us, where we are the simulated tag),
// and store it in the given buffer, up to the given maximum length. Keeps
// spinning, waiting for a well-framed command, until either we get one
// (returns len) or someone presses the pushbutton on the board (returns -1).
//
// Assume that we're called with the SSC (to the FPGA) and ADC path set
// correctly.
//-----------------------------------------------------------------------------

int GetIso15693CommandFromReader(uint8_t *received, size_t max_len, uint32_t *eof_time) {
    int samples = 0;
    bool gotFrame = false;

    // the decoder data structure
    DecodeReader_t *dr = (DecodeReader_t *)BigBuf_malloc(sizeof(DecodeReader_t));
    DecodeReaderInit(dr, received, max_len, 0, NULL);

    // wait for last transfer to complete
    while (!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXEMPTY));

    LED_D_OFF();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_NO_MODULATION);

    // clear receive register and wait for next transfer
    uint32_t temp = AT91C_BASE_SSC->SSC_RHR;
    (void) temp;
    while (!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY)) ;

    // Setup and start DMA.
    dmabuf8_t *dma = get_dma8();
    if (FpgaSetupSscDma(dma->buf, DMA_BUFFER_SIZE) == false) {
        if (g_dbglevel > DBG_ERROR) Dbprintf("FpgaSetupSscDma failed. Exiting");
        return -4;
    }
    uint8_t *upTo = dma->buf;

    uint32_t dma_start_time = GetCountSspClk() & 0xfffffff8;

    for (;;) {
        volatile uint16_t behindBy = ((uint8_t *)AT91C_BASE_PDC_SSC->PDC_RPR - upTo) & (DMA_BUFFER_SIZE - 1);
        if (behindBy == 0) continue;

        if (samples == 0) {
            // DMA has transferred the very first data
            dma_start_time = GetCountSspClk() & 0xfffffff0;
        }

        volatile uint8_t b = *upTo++;
        if (upTo >= dma->buf + DMA_BUFFER_SIZE) {               // we have read all of the DMA buffer content.
            upTo = dma->buf;                                    // start reading the circular buffer from the beginning
            if (behindBy > (9 * DMA_BUFFER_SIZE / 10)) {
                Dbprintf("About to blow circular buffer - aborted! behindBy %d", behindBy);
                break;
            }
        }
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_ENDRX)) {       // DMA Counter Register had reached 0, already rotated.
            AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dma->buf; // refresh the DMA Next Buffer and
            AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;     // DMA Next Counter registers
        }

        for (int i = 7; i >= 0; i--) {
            if (Handle15693SampleFromReader((b >> i) & 0x01, dr)) {
                *eof_time = dma_start_time + samples - DELAY_READER_TO_ARM; // end of EOF
                gotFrame = true;
                break;
            }
            samples++;
        }

        if (gotFrame) {
            break;
        }

        if (BUTTON_PRESS()) {
            dr->byteCount = -1;
            break;
        }

        WDT_HIT();
    }

    FpgaDisableSscDma();

    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("samples = %d, gotFrame = %d, Decoder: state = %d, len = %d, bitCount = %d, posCount = %d",
                 samples, gotFrame, dr->state, dr->byteCount,
                 dr->bitCount, dr->posCount);
    }

    if (dr->byteCount >= 0) {
        uint32_t sof_time = *eof_time
                            - dr->byteCount * (dr->Coding == CODING_1_OUT_OF_4 ? 128 : 2048) // time for byte transfers
                            - 32  // time for SOF transfer
                            - 16; // time for EOF transfer
        LogTrace_ISO15693(dr->output, dr->byteCount, (sof_time * 32), (*eof_time * 32), NULL, true);
    }

    return dr->byteCount;
}

//-----------------------------------------------------------------------------
// Start to read an ISO 15693 tag. We send an identify request, then wait
// for the response. The response is not demodulated, just left in the buffer
// so that it can be downloaded to a PC and processed there.
//-----------------------------------------------------------------------------
void AcquireRawAdcSamplesIso15693(void) {

    LEDsoff();
    DbpString("Starting to acquire data...");
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    BigBuf_free();
    clear_trace();

    // Start from off (no field generated)
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    SpinDelay(10);


    uint8_t cmd[5];
    BuildIdentifyRequest(cmd);
    CodeIso15693AsReader(cmd, sizeof(cmd));

    LED_A_ON();

    uint8_t *dest = BigBuf_malloc(4000);

    // switch field on
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER);
    LED_D_ON();

    // initialize SSC and select proper AD input
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

    StartCountSspClk();

    // Give the tags time to energize
    SpinDelay(250);

    // Now send the command
    tosend_t *ts = get_tosend();

    uint32_t start_time = 0;
    TransmitTo15693Tag(ts->buf, ts->max, &start_time);

    // wait for last transfer to complete
    while (!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXEMPTY)) ;

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_SUBCARRIER_424_KHZ | FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE);

    for (int c = 0; c < 4000;) {
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            uint16_t r = AT91C_BASE_SSC->SSC_RHR;
            dest[c++] = r >> 5;
        }
    }


    FpgaDisableSscDma();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
}

void SniffIso15693(uint8_t jam_search_len, uint8_t *jam_search_string) {

    LEDsoff();
    LED_A_ON();

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    DbpString("Starting to sniff. Press PM3 Button to stop.");

    BigBuf_free();
    clear_trace();
    set_tracing(true);

    DecodeTag_t dtag = {0};
    uint8_t response[ISO15693_MAX_RESPONSE_LENGTH] = {0};
    DecodeTagInit(&dtag, response, sizeof(response));

    DecodeReader_t dreader = {0};
    uint8_t cmd[ISO15693_MAX_COMMAND_LENGTH] = {0};
    DecodeReaderInit(&dreader, cmd, sizeof(cmd), jam_search_len, jam_search_string);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SNIFF_AMPLITUDE);
    LED_D_OFF();

    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);

    StartCountSspClk();

    // The DMA buffer, used to stream samples from the FPGA
    dmabuf16_t *dma = get_dma16();

    // Setup and start DMA.
    if (FpgaSetupSscDma((uint8_t *) dma->buf, DMA_BUFFER_SIZE) == false) {
        if (g_dbglevel > DBG_ERROR) DbpString("FpgaSetupSscDma failed. Exiting");
        switch_off();
        return;
    }

    bool tag_is_active = false;
    bool reader_is_active = false;
    bool expect_tag_answer = false;
    int dma_start_time = 0;

    // Count of samples received so far, so that we can include timing
    int samples = 0;

    uint16_t *upTo = dma->buf;

    for (;;) {

        volatile int behind_by = ((uint16_t *)AT91C_BASE_PDC_SSC->PDC_RPR - upTo) & (DMA_BUFFER_SIZE - 1);
        if (behind_by < 1) continue;

        samples++;
        if (samples == 1) {
            // DMA has transferred the very first data
            dma_start_time = GetCountSspClk() & 0xfffffff0;
        }

        volatile uint16_t sniffdata = *upTo++;

        // we have read all of the DMA buffer content
        if (upTo >= dma->buf + DMA_BUFFER_SIZE) {

            // start reading the circular buffer from the beginning
            upTo = dma->buf;

            // DMA Counter Register had reached 0, already rotated.
            if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_ENDRX)) {

                // primary buffer was stopped
                if (AT91C_BASE_PDC_SSC->PDC_RCR == false) {
                    AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) dma->buf;
                    AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
                }
                // secondary buffer sets as primary, secondary buffer was stopped
                if (AT91C_BASE_PDC_SSC->PDC_RNCR == false) {
                    AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dma->buf;
                    AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
                }

                WDT_HIT();
                if (BUTTON_PRESS()) {
                    DbpString("Sniff stopped");
                    break;
                }
            }
        }

        // no need to try decoding reader data if the tag is sending
        if (tag_is_active == false) {

            if (Handle15693SampleFromReader((sniffdata & 0x02) >> 1, &dreader)) {

                uint32_t eof_time = dma_start_time + (samples * 16) + 8 - DELAY_READER_TO_ARM_SNIFF; // end of EOF
                if (dreader.byteCount > 0) {
                    uint32_t sof_time = eof_time
                                        - dreader.byteCount * (dreader.Coding == CODING_1_OUT_OF_4 ? 128 * 16 : 2048 * 16) // time for byte transfers
                                        - 32 * 16  // time for SOF transfer
                                        - 16 * 16; // time for EOF transfer
                    LogTrace_ISO15693(dreader.output, dreader.byteCount, (sof_time * 4), (eof_time * 4), NULL, true);
                }
                // And ready to receive another command.
                DecodeReaderReset(&dreader);
                DecodeTagReset(&dtag);
                reader_is_active = false;
                expect_tag_answer = true;

            } else if (Handle15693SampleFromReader(sniffdata & 0x01, &dreader)) {

                uint32_t eof_time = dma_start_time + (samples * 16) + 16 - DELAY_READER_TO_ARM_SNIFF; // end of EOF
                if (dreader.byteCount > 0) {
                    uint32_t sof_time = eof_time
                                        - dreader.byteCount * (dreader.Coding == CODING_1_OUT_OF_4 ? 128 * 16 : 2048 * 16) // time for byte transfers
                                        - 32 * 16  // time for SOF transfer
                                        - 16 * 16; // time for EOF transfer
                    LogTrace_ISO15693(dreader.output, dreader.byteCount, (sof_time * 4), (eof_time * 4), NULL, true);
                }
                // And ready to receive another command
                DecodeReaderReset(&dreader);
                DecodeTagReset(&dtag);
                reader_is_active = false;
                expect_tag_answer = true;

            } else {
                reader_is_active = (dreader.state >= STATE_READER_RECEIVE_DATA_1_OUT_OF_4);
            }
        }

        if (reader_is_active == false && expect_tag_answer) {                       // no need to try decoding tag data if the reader is currently sending or no answer expected yet

            if (Handle15693SamplesFromTag(sniffdata >> 2, &dtag)) {

                uint32_t eof_time = dma_start_time + (samples * 16) - DELAY_TAG_TO_ARM_SNIFF; // end of EOF
                if (dtag.lastBit == SOF_PART2) {
                    eof_time -= (8 * 16); // needed 8 additional samples to confirm single SOF (iCLASS)
                }
                uint32_t sof_time = eof_time
                                    - dtag.len * 8 * 8 * 16 // time for byte transfers
                                    - (32 * 16)  // time for SOF transfer
                                    - (dtag.lastBit != SOF_PART2 ? (32 * 16) : 0); // time for EOF transfer

                LogTrace_ISO15693(dtag.output, dtag.len, (sof_time * 4), (eof_time * 4), NULL, false);
                // And ready to receive another response.
                DecodeTagReset(&dtag);
                DecodeReaderReset(&dreader);
                expect_tag_answer = false;
                tag_is_active = false;
            } else {
                tag_is_active = (dtag.state >= STATE_TAG_RECEIVING_DATA);
            }
        }

    }

    FpgaDisableTracing();
    switch_off();

    DbpString("");
    DbpString(_CYAN_("Sniff statistics"));
    DbpString("=================================");
    Dbprintf("  DecodeTag State........%d", dtag.state);
    Dbprintf("  DecodeTag byteCnt......%d", dtag.len);
    Dbprintf("  DecodeTag posCount.....%d", dtag.posCount);
    Dbprintf("  DecodeReader State.....%d", dreader.state);
    Dbprintf("  DecodeReader byteCnt...%d", dreader.byteCount);
    Dbprintf("  DecodeReader posCount..%d", dreader.posCount);
    Dbprintf("  Trace length..........." _YELLOW_("%d"), BigBuf_get_traceLen());
    DbpString("");

}

// Initialize Proxmark3 as ISO15693 reader
void Iso15693InitReader(void) {

    LEDsoff();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // Start from off (no field generated)
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    SpinDelay(10);

    // switch field on
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER);
    LED_D_ON();

    // initialize SSC and select proper AD input
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

    set_tracing(true);

    // give tags some time to energize
    SpinDelay(250);

    StartCountSspClk();
}

///////////////////////////////////////////////////////////////////////
// ISO 15693 Part 3 - Air Interface
// This section basically contains transmission and receiving of bits
///////////////////////////////////////////////////////////////////////

// Encode an identify request, which is the first
// thing that you must send to a tag to get a response.
// It expects "cmdout" to be at least CMD_ID_RESP large
// When READER:
static void BuildIdentifyRequest(uint8_t *cmd) {
    // flags
    cmd[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
    // inventory command code
    cmd[1] = ISO15693_INVENTORY;
    // no mask
    cmd[2] = 0x00;
    // CRC
    AddCrc15(cmd, 3);
}

// Universal Method for sending to and recv bytes from a tag
//  init ... should we initialize the reader?
//  speed ... 0 low speed, 1 hi speed
//  **recv will return you a pointer to the received data
//  If you do not need the answer use NULL for *recv[]
//  return: length of received data
// logging enabled
int SendDataTag(uint8_t *send, int sendlen, bool init, bool speed_fast, uint8_t *recv,
                uint16_t max_recv_len, uint32_t start_time, uint16_t timeout, uint32_t *eof_time) {

    if (init) {
        Iso15693InitReader();
        start_time = GetCountSspClk();
    }

    if (speed_fast) {
        // high speed (1 out of 4)
        CodeIso15693AsReader(send, sendlen);
    } else {
        // low speed (1 out of 256)
        CodeIso15693AsReader256(send, sendlen);
    }
    int res = 0;
    tosend_t *ts = get_tosend();
    TransmitTo15693Tag(ts->buf, ts->max, &start_time);

    if (tearoff_hook() == PM3_ETEAROFF) { // tearoff occurred

        res = PM3_ETEAROFF;

    } else {

        *eof_time = start_time + 32 * ((8 * ts->max) - 4); // subtract the 4 padding bits after EOF
        LogTrace_ISO15693(send, sendlen, (start_time * 4), (*eof_time * 4), NULL, true);
        if (recv != NULL) {
            res = GetIso15693AnswerFromTag(recv, max_recv_len, timeout, eof_time);
        }
    }
    return res;
}

int SendDataTagEOF(uint8_t *recv, uint16_t max_recv_len, uint32_t start_time, uint16_t timeout, uint32_t *eof_time) {

    CodeIso15693AsReaderEOF();
    tosend_t *ts = get_tosend();
    TransmitTo15693Tag(ts->buf, ts->max, &start_time);
    uint32_t end_time = start_time + 32 * (8 * ts->max - 4); // subtract the 4 padding bits after EOF
    LogTrace_ISO15693(NULL, 0, (start_time * 4), (end_time * 4), NULL, true);

    int res = 0;
    if (recv != NULL) {
        res = GetIso15693AnswerFromTag(recv, max_recv_len, timeout, eof_time);
    }
    return res;
}

// --------------------------------------------------------------------
// Debug Functions
// --------------------------------------------------------------------

// Decodes a message from a tag and displays its metadata and content
#define DBD15STATLEN 48
static void DbdecodeIso15693Answer(int len, uint8_t *d) {

    if (len > 3) {

        char status[DBD15STATLEN + 1] = {0};

        if (d[0] & ISO15_RES_EXT)
            strncat(status, "ProtExt ", DBD15STATLEN - strlen(status));

        if (d[0] & ISO15_RES_ERROR) {
            // error
            strncat(status, "Error ", DBD15STATLEN - strlen(status));
            switch (d[1]) {
                case 0x01:
                    strncat(status, "01: not supported", DBD15STATLEN - strlen(status));
                    break;
                case 0x02:
                    strncat(status, "02: not recognized", DBD15STATLEN - strlen(status));
                    break;
                case 0x03:
                    strncat(status, "03: opt not supported", DBD15STATLEN - strlen(status));
                    break;
                case 0x0f:
                    strncat(status, "0F: no info", DBD15STATLEN - strlen(status));
                    break;
                case 0x10:
                    strncat(status, "10: don't exist", DBD15STATLEN - strlen(status));
                    break;
                case 0x11:
                    strncat(status, "11: lock again", DBD15STATLEN - strlen(status));
                    break;
                case 0x12:
                    strncat(status, "12: locked", DBD15STATLEN - strlen(status));
                    break;
                case 0x13:
                    strncat(status, "13: program error", DBD15STATLEN - strlen(status));
                    break;
                case 0x14:
                    strncat(status, "14: lock error", DBD15STATLEN - strlen(status));
                    break;
                default:
                    strncat(status, "unknown error", DBD15STATLEN - strlen(status));
            }
            strncat(status, " ", DBD15STATLEN - strlen(status));
        } else {
            strncat(status, "No error ", DBD15STATLEN - strlen(status));
        }

        if (CheckCrc15(d, len))
            strncat(status, "[+] crc (" _GREEN_("OK") ")", DBD15STATLEN - strlen(status));
        else
            strncat(status, "[!] crc (" _RED_("fail") ")", DBD15STATLEN - strlen(status));

        if (g_dbglevel >= DBG_ERROR) Dbprintf("%s", status);
    }
}

///////////////////////////////////////////////////////////////////////
// Functions called via USB/Client
///////////////////////////////////////////////////////////////////////

//-----------------------------------------------------------------------------
// Act as ISO15693 reader, perform anti-collision and then attempt to read a sector
// all demodulation performed in arm rather than host. - greg
//-----------------------------------------------------------------------------
// ok
// parameter is unused !?!
void ReaderIso15693(uint32_t parameter, iso15_card_select_t *p_card) {

    LED_A_ON();
    set_tracing(true);

    uint8_t *answer = BigBuf_malloc(ISO15693_MAX_RESPONSE_LENGTH);
    memset(answer, 0x00, ISO15693_MAX_RESPONSE_LENGTH);

    // FIRST WE RUN AN INVENTORY TO GET THE TAG UID
    // THIS MEANS WE CAN PRE-BUILD REQUESTS TO SAVE CPU TIME

    // Send the IDENTIFY command
    uint8_t cmd[5] = {0};
    BuildIdentifyRequest(cmd);
    uint32_t start_time = 0;
    uint32_t eof_time;
    int recvlen = SendDataTag(cmd, sizeof(cmd), true, true, answer, ISO15693_MAX_RESPONSE_LENGTH, start_time, ISO15693_READER_TIMEOUT, &eof_time);

    if (recvlen == PM3_ETEAROFF) { // tearoff occurred
        reply_mix(CMD_ACK, recvlen, 0, 0, NULL, 0);
    } else {

        //start_time = eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;

        // we should do a better check than this
        if (recvlen >= 12) {
            uint8_t uid[8];
            uid[0] = answer[9]; // always E0
            uid[1] = answer[8]; // IC Manufacturer code
            uid[2] = answer[7];
            uid[3] = answer[6];
            uid[4] = answer[5];
            uid[5] = answer[4];
            uid[6] = answer[3];
            uid[7] = answer[2];

            if (p_card != NULL) {
                memcpy(p_card->uid, uid, 8);
                p_card->uidlen = 8;
            }

            if (g_dbglevel >= DBG_EXTENDED) {
                Dbprintf("[+] UID = %02X%02X%02X%02X%02X%02X%02X%02X",
                         uid[0], uid[1], uid[2], uid[3],
                         uid[4], uid[5], uid[5], uid[6]
                        );
            }
            // send UID back to client.
            // arg0 = 1 = OK
            // arg1 = len of response (12 bytes)
            // arg2 = rtf
            // asbytes = uid.
            reply_mix(CMD_ACK, 1, sizeof(uid), 0, uid, sizeof(uid));

            if (g_dbglevel >= DBG_EXTENDED) {
                Dbprintf("[+] %d octets read from IDENTIFY request:", recvlen);
                DbdecodeIso15693Answer(recvlen, answer);
                Dbhexdump(recvlen, answer, true);
            }
        } else {
            p_card->uidlen = 0;
            DbpString("Failed to select card");
            reply_mix(CMD_ACK, 0, 0, 0, NULL, 0);
        }
    }
    switch_off();
    BigBuf_free();
}

// When SIM: initialize the Proxmark3 as ISO15693 tag
void Iso15693InitTag(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // Start from off (no field generated)
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    SpinDelay(10);

    // switch simulation FPGA
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_NO_MODULATION);

    // initialize SSC and select proper AD input
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_SIMULATOR);
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

    clear_trace();
    set_tracing(true);

    StartCountSspClk();
}

// Simulate an ISO15693 TAG, perform anti-collision and then print any reader commands
// all demodulation performed in arm rather than host. - greg
void SimTagIso15693(uint8_t *uid) {

    // free eventually allocated BigBuf memory
    BigBuf_free_keep_EM();

    Iso15693InitTag();

    LED_A_ON();

    Dbprintf("ISO-15963 Simulating uid: %02X%02X%02X%02X%02X%02X%02X%02X", uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7]);

    LED_C_ON();



    enum { NO_FIELD, IDLE, ACTIVATED, SELECTED, HALTED } chip_state = NO_FIELD;

    bool button_pressed = false;
    int vHf; // in mV

    bool exit_loop = false;
    while (exit_loop == false) {

        button_pressed = BUTTON_PRESS();
        if (button_pressed || data_available())
            break;

        WDT_HIT();

        // find reader field
        if (chip_state == NO_FIELD) {

            vHf = (MAX_ADC_HF_VOLTAGE * SumAdc(ADC_CHAN_HF, 32)) >> 15;
            if (vHf > MF_MINFIELDV) {
                chip_state = IDLE;
                LED_A_ON();
            } else {
                continue;
            }
        }

        // Listen to reader
        uint8_t cmd[ISO15693_MAX_COMMAND_LENGTH];
        uint32_t reader_eof_time = 0;
        int cmd_len = GetIso15693CommandFromReader(cmd, sizeof(cmd), &reader_eof_time);
        if (cmd_len < 0) {
            button_pressed = true;
            break;
        }

        // TODO: check more flags
        if ((cmd_len >= 5) && (cmd[0] & ISO15_REQ_INVENTORY) && (cmd[1] == ISO15693_INVENTORY)) {
            bool slow = !(cmd[0] & ISO15_REQ_DATARATE_HIGH);
            uint32_t response_time = reader_eof_time + DELAY_ISO15693_VCD_TO_VICC_SIM;

            // Build INVENTORY command
            uint8_t resp_inv[CMD_INV_RESP] = {0};

            resp_inv[0] = 0; // No error, no protocol format extension
            resp_inv[1] = 0; // DSFID (data storage format identifier).  0x00 = not supported

            // 64-bit UID
            resp_inv[2] = uid[7];
            resp_inv[3] = uid[6];
            resp_inv[4] = uid[5];
            resp_inv[5] = uid[4];
            resp_inv[6] = uid[3];
            resp_inv[7] = uid[2];
            resp_inv[8] = uid[1];
            resp_inv[9] = uid[0];

            // CRC
            AddCrc15(resp_inv, 10);
            CodeIso15693AsTag(resp_inv, CMD_INV_RESP);

            tosend_t *ts = get_tosend();

            TransmitTo15693Reader(ts->buf, ts->max, &response_time, 0, slow);
            LogTrace_ISO15693(resp_inv, CMD_INV_RESP, response_time * 32, (response_time * 32) + (ts->max * 32 * 64), NULL, false);

            chip_state = SELECTED;
        }

        // GET_SYSTEM_INFO
        if ((cmd[1] == ISO15693_GET_SYSTEM_INFO)) {
            bool slow = !(cmd[0] & ISO15_REQ_DATARATE_HIGH);
            uint32_t response_time = reader_eof_time + DELAY_ISO15693_VCD_TO_VICC_SIM;

            // Build GET_SYSTEM_INFO command
            uint8_t resp_sysinfo[CMD_SYSINFO_RESP] = {0};

            resp_sysinfo[0] = 0;    // Response flags.
            resp_sysinfo[1] = 0x0F; // Information flags (0x0F - DSFID, AFI, Mem size, IC)

            // 64-bit UID
            resp_sysinfo[2] = uid[7];
            resp_sysinfo[3] = uid[6];
            resp_sysinfo[4] = uid[5];
            resp_sysinfo[5] = uid[4];
            resp_sysinfo[6] = uid[3];
            resp_sysinfo[7] = uid[2];
            resp_sysinfo[8] = uid[1];
            resp_sysinfo[9] = uid[0];

            resp_sysinfo[10] = 0;    // DSFID
            resp_sysinfo[11] = 0;    // AFI

            resp_sysinfo[12] = 0x1B; // Memory size.
            resp_sysinfo[13] = 0x03; // Memory size.
            resp_sysinfo[14] = 0x01; // IC reference.

            // CRC
            AddCrc15(resp_sysinfo, 15);
            CodeIso15693AsTag(resp_sysinfo, CMD_SYSINFO_RESP);

            tosend_t *ts = get_tosend();

            TransmitTo15693Reader(ts->buf, ts->max, &response_time, 0, slow);
            LogTrace_ISO15693(resp_sysinfo, CMD_SYSINFO_RESP, response_time * 32, (response_time * 32) + (ts->max * 32 * 64), NULL, false);
        }

        // READ_BLOCK
        if ((cmd[1] == ISO15693_READBLOCK)) {
            bool slow = !(cmd[0] & ISO15_REQ_DATARATE_HIGH);
            uint32_t response_time = reader_eof_time + DELAY_ISO15693_VCD_TO_VICC_SIM;

            // Build GET_SYSTEM_INFO command
            uint8_t resp_readblock[CMD_READBLOCK_RESP] = {0};

            resp_readblock[0] = 0;    // Response flags.
            resp_readblock[1] = 0;    // Block data.
            resp_readblock[2] = 0;    // Block data.
            resp_readblock[3] = 0;    // Block data.
            resp_readblock[4] = 0;    // Block data.

            // CRC
            AddCrc15(resp_readblock, 5);
            CodeIso15693AsTag(resp_readblock, CMD_READBLOCK_RESP);

            tosend_t *ts = get_tosend();

            TransmitTo15693Reader(ts->buf, ts->max, &response_time, 0, slow);
            LogTrace_ISO15693(resp_readblock, CMD_READBLOCK_RESP, response_time * 32, (response_time * 32) + (ts->max * 32 * 64), NULL, false);
        }
    }

    switch_off();

    if (button_pressed)
        DbpString("button pressed");

    reply_ng(CMD_HF_ISO15693_SIMULATE, PM3_SUCCESS, NULL, 0);
}

// Since there is no standardized way of reading the AFI out of a tag, we will brute force it
// (some manufactures offer a way to read the AFI, though)
void BruteforceIso15693Afi(uint32_t speed) {

    uint8_t data[7] = {0};
    uint8_t recv[ISO15693_MAX_RESPONSE_LENGTH];
    Iso15693InitReader();

    // first without AFI
    // Tags should respond without AFI and with AFI=0 even when AFI is active

    data[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
    data[1] = ISO15693_INVENTORY;
    data[2] = 0; // AFI
    AddCrc15(data, 3);

    int datalen = 5;
    uint32_t eof_time = 0;
    int recvlen = SendDataTag(data, datalen, true, speed, recv, sizeof(recv), 0, ISO15693_READER_TIMEOUT, &eof_time);
    uint32_t start_time = eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;

    WDT_HIT();

    if (recvlen >= 12) {
        Dbprintf("NoAFI UID = %s", iso15693_sprintUID(NULL, recv + 2));
    } else {
        DbpString("Failed to select card");
        reply_ng(CMD_HF_ISO15693_FINDAFI, PM3_ESOFT, NULL, 0);
        switch_off();
        return;
    }

    // now with AFI
    data[0] |= ISO15_REQINV_AFI;
    data[2] = 0; // AFI
    data[3] = 0; // mask length

    // 4 + 2crc
    datalen = 6;

    bool aborted = false;
    for (uint16_t i = 0; i < 256; i++) {

        data[2] = i & 0xFF;
        AddCrc15(data, 4);

        recvlen = SendDataTag(data, datalen, false, speed, recv, sizeof(recv), start_time, ISO15693_READER_TIMEOUT, &eof_time);
        start_time = eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;

        WDT_HIT();

        if (recvlen >= 12) {
            Dbprintf("AFI = %i  UID = %s", i, iso15693_sprintUID(NULL, recv + 2));
        }

        aborted = BUTTON_PRESS() && data_available();
        if (aborted) {
            break;
        }
    }

    DbpString("AFI Bruteforcing done.");
    switch_off();

    if (aborted) {
        reply_ng(CMD_HF_ISO15693_FINDAFI, PM3_EOPABORTED, NULL, 0);
    } else {
        reply_ng(CMD_HF_ISO15693_FINDAFI, PM3_SUCCESS, NULL, 0);
    }
}

// Allows to directly send commands to the tag via the client
// OBS:  doesn't turn off rf field afterwards.
void DirectTag15693Command(uint32_t datalen, uint32_t speed, uint32_t recv, uint8_t *data) {

    LED_A_ON();

    uint8_t recvbuf[ISO15693_MAX_RESPONSE_LENGTH];
    uint16_t timeout;
    uint32_t eof_time = 0;
    bool request_answer = false;

    switch (data[1]) {
        case ISO15693_WRITEBLOCK:
        case ISO15693_LOCKBLOCK:
        case ISO15693_WRITE_MULTI_BLOCK:
        case ISO15693_WRITE_AFI:
        case ISO15693_LOCK_AFI:
        case ISO15693_WRITE_DSFID:
        case ISO15693_LOCK_DSFID:
            timeout = ISO15693_READER_TIMEOUT_WRITE;
            request_answer = data[0] & ISO15_REQ_OPTION;
            break;
        default:
            timeout = ISO15693_READER_TIMEOUT;
    }

    uint32_t start_time = 0;
    int recvlen = SendDataTag(data, datalen, true, speed, (recv ? recvbuf : NULL), sizeof(recvbuf), start_time, timeout, &eof_time);

    if (recvlen == PM3_ETEAROFF) { // tearoff occurred
        reply_mix(CMD_ACK, recvlen, 0, 0, NULL, 0);
    } else {

        // send a single EOF to get the tag response
        if (request_answer) {
            start_time = eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;
            recvlen = SendDataTagEOF((recv ? recvbuf : NULL), sizeof(recvbuf), start_time, ISO15693_READER_TIMEOUT, &eof_time);
        }

        if (recv) {
            recvlen = MIN(recvlen, ISO15693_MAX_RESPONSE_LENGTH);
            reply_mix(CMD_ACK, recvlen, 0, 0, recvbuf, recvlen);
        } else {
            reply_mix(CMD_ACK, 1, 0, 0, NULL, 0);
        }
    }
    // note: this prevents using hf 15 cmd with s option - which isn't implemented yet anyway
    // also prevents hf 15 raw -k  keep_field on ...
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LED_D_OFF();
}

/*
SLIx functions from official master forks.

void LockPassSlixIso15693(uint32_t pass_id, uint32_t password) {

    LED_A_ON();

    uint8_t cmd_inventory[]  = {ISO15693_REQ_DATARATE_HIGH | ISO15693_REQ_INVENTORY | ISO15693_REQINV_SLOT1, 0x01, 0x00, 0x00, 0x00 };
    uint8_t cmd_get_rnd[]    = {ISO15693_REQ_DATARATE_HIGH, 0xB2, 0x04, 0x00, 0x00 };
    uint8_t cmd_set_pass[]   = {ISO15693_REQ_DATARATE_HIGH, 0xB3, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    //uint8_t cmd_write_pass[] = {ISO15693_REQ_DATARATE_HIGH | ISO15693_REQ_ADDRESS, 0xB4, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t cmd_lock_pass[] = {ISO15693_REQ_DATARATE_HIGH | ISO15693_REQ_ADDRESS, 0xB5, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00 };
    uint16_t crc;
    int recvlen = 0;
    uint8_t recvbuf[ISO15693_MAX_RESPONSE_LENGTH];
    uint32_t start_time = 0;
    bool done = false;

    // setup 'get random number' command
    crc = Iso15693Crc(cmd_get_rnd, 3);
    cmd_get_rnd[3] = crc & 0xff;
    cmd_get_rnd[4] = crc >> 8;

    Dbprintf("LockPass: Press button lock password, long-press to terminate.");

    while (!done) {

        LED_D_ON();
        switch(BUTTON_HELD(1000)) {
            case BUTTON_SINGLE_CLICK:
                Dbprintf("LockPass: Reset 'DONE'-LED (A)");
                LED_A_OFF();
                LED_B_OFF();
                LED_C_OFF();
                break;
            case BUTTON_HOLD:
                Dbprintf("LockPass: Terminating");
                done = true;
                break;
            default:
                SpinDelay(50);
                continue;
        }

        if (done) [
            break;
        }

        recvlen = SendDataTag(cmd_get_rnd, sizeof(cmd_get_rnd), true, true, recvbuf, sizeof(recvbuf), start_time);
        if (recvlen != 5) {
            LED_C_ON();
        } else {
            Dbprintf("LockPass: Received random 0x%02X%02X (%d)", recvbuf[1], recvbuf[2], recvlen);

            // setup 'set password' command
            cmd_set_pass[4] = ((password>>0) &0xFF) ^ recvbuf[1];
            cmd_set_pass[5] = ((password>>8) &0xFF) ^ recvbuf[2];
            cmd_set_pass[6] = ((password>>16) &0xFF) ^ recvbuf[1];
            cmd_set_pass[7] = ((password>>24) &0xFF) ^ recvbuf[2];

            crc = Iso15693Crc(cmd_set_pass, 8);
            cmd_set_pass[8] = crc & 0xff;
            cmd_set_pass[9] = crc >> 8;

            Dbprintf("LockPass: Sending old password to end privacy mode", cmd_set_pass[4], cmd_set_pass[5], cmd_set_pass[6], cmd_set_pass[7]);
            recvlen = SendDataTag(cmd_set_pass, sizeof(cmd_set_pass), false, true, recvbuf, sizeof(recvbuf), start_time);
            if (recvlen != 3) {
                Dbprintf("LockPass: Failed to set password (%d)", recvlen);
                LED_B_ON();
            } else {
                crc = Iso15693Crc(cmd_inventory, 3);
                cmd_inventory[3] = crc & 0xff;
                cmd_inventory[4] = crc >> 8;

                Dbprintf("LockPass: Searching for tag...");
                recvlen = SendDataTag(cmd_inventory, sizeof(cmd_inventory), false, true, recvbuf, sizeof(recvbuf), start_time);
                if (recvlen != 12) {
                    Dbprintf("LockPass: Failed to read inventory (%d)", recvlen);
                    LED_B_ON();
                    LED_C_ON();
                } else {

                    Dbprintf("LockPass: Answer from %02X%02X%02X%02X%02X%02X%02X%02X", recvbuf[9], recvbuf[8], recvbuf[7], recvbuf[6], recvbuf[5], recvbuf[4], recvbuf[3], recvbuf[2]);

                    memcpy(&cmd_lock_pass[3], &recvbuf[2], 8);

                    cmd_lock_pass[8+3] = pass_id;

                    crc = Iso15693Crc(cmd_lock_pass, 8+4);
                    cmd_lock_pass[8+4] = crc & 0xff;
                    cmd_lock_pass[8+5] = crc >> 8;

                    Dbprintf("LockPass: locking to password 0x%02X%02X%02X%02X for ID %02X", cmd_set_pass[4], cmd_set_pass[5], cmd_set_pass[6], cmd_set_pass[7], pass_id);

                    recvlen = SendDataTag(cmd_lock_pass, sizeof(cmd_lock_pass), false, true, recvbuf, sizeof(recvbuf), start_time);
                    if (recvlen != 3) {
                        Dbprintf("LockPass: Failed to lock password (%d)", recvlen);
                    } else {
                        Dbprintf("LockPass: Successful (%d)", recvlen);
                    }
                    LED_A_ON();
                }
            }       }
    }

    Dbprintf("LockPass: Finishing");
    cmd_send(CMD_ACK, recvlen, 0, 0, recvbuf, recvlen);
}
*/

//-----------------------------------------------------------------------------
// Work with "magic Chinese" card.
//
//-----------------------------------------------------------------------------

// Set the UID on Magic ISO15693 tag (based on Iceman's LUA-script).
void SetTag15693Uid(const uint8_t *uid) {

    LED_A_ON();

    uint8_t cmd[4][9] = {
        {ISO15_REQ_DATARATE_HIGH, ISO15693_WRITEBLOCK, 0x3e, 0x00, 0x00, 0x00, 0x00},
        {ISO15_REQ_DATARATE_HIGH, ISO15693_WRITEBLOCK, 0x3f, 0x69, 0x96, 0x00, 0x00},
        {ISO15_REQ_DATARATE_HIGH, ISO15693_WRITEBLOCK, 0x38},
        {ISO15_REQ_DATARATE_HIGH, ISO15693_WRITEBLOCK, 0x39}
    };

    // Command 3 : 02 21 38 u8u7u6u5 (where uX = uid byte X)
    cmd[2][3] = uid[7];
    cmd[2][4] = uid[6];
    cmd[2][5] = uid[5];
    cmd[2][6] = uid[4];

    // Command 4 : 02 21 39 u4u3u2u1 (where uX = uid byte X)
    cmd[3][3] = uid[3];
    cmd[3][4] = uid[2];
    cmd[3][5] = uid[1];
    cmd[3][6] = uid[0];

    AddCrc15(cmd[0], 7);
    AddCrc15(cmd[1], 7);
    AddCrc15(cmd[2], 7);
    AddCrc15(cmd[3], 7);

    uint8_t recvbuf[ISO15693_MAX_RESPONSE_LENGTH];

    uint32_t start_time = 0;
    uint32_t eof_time = 0;
    for (int i = 0; i < 4; i++) {
        SendDataTag(cmd[i], sizeof(cmd[i]), i == 0 ? true : false, true, recvbuf, sizeof(recvbuf), start_time, ISO15693_READER_TIMEOUT_WRITE, &eof_time);
        start_time = eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;
    }

    reply_ng(CMD_HF_ISO15693_CSETUID, PM3_SUCCESS, NULL, 0);
    switch_off();
}

static void init_password_15693_slixl(uint8_t *buffer, uint8_t *pwd, const uint8_t *rnd) {
    memcpy(buffer, pwd, 4);
    if (rnd) {
        buffer[0] ^= rnd[0];
        buffer[1] ^= rnd[1];
        buffer[2] ^= rnd[0];
        buffer[3] ^= rnd[1];
    }
}

static bool get_rnd_15693_slixl(uint32_t start_time, uint32_t *eof_time, uint8_t *rnd) {
    // 0x04, == NXP from manufacture id list.
    uint8_t c[] = {ISO15_REQ_DATARATE_HIGH, ISO15693_GET_RANDOM_NUMBER, 0x04, 0x00, 0x00 };
    AddCrc15(c, 3);

    uint8_t recvbuf[ISO15693_MAX_RESPONSE_LENGTH];
    int recvlen = SendDataTag(c, sizeof(c), false, true, recvbuf, sizeof(recvbuf), start_time, ISO15693_READER_TIMEOUT_WRITE, eof_time);
    if (recvlen != 5) {
        return false;
    }

    if (rnd) {
        memcpy(rnd, &recvbuf[1], 2);
    }
    return true;
}

static uint32_t set_pass_15693_slixl(uint32_t start_time, uint32_t *eof_time, uint8_t pass_id, uint8_t *password) {
    uint8_t rnd[2];
    if (get_rnd_15693_slixl(start_time, eof_time, rnd) == false) {
        return PM3_ETIMEOUT;
    }

    // 0x04, == NXP from manufacture id list.
    uint8_t c[] = {ISO15_REQ_DATARATE_HIGH, ISO15693_SET_PASSWORD, 0x04, pass_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    init_password_15693_slixl(&c[4], password, rnd);
    AddCrc15(c, 8);

    start_time = *eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;
    uint8_t recvbuf[ISO15693_MAX_RESPONSE_LENGTH];
    int recvlen = SendDataTag(c, sizeof(c), false, true, recvbuf, sizeof(recvbuf), start_time, ISO15693_READER_TIMEOUT_WRITE, eof_time);
    if (recvlen != 3) {
        return PM3_EWRONGANSWER;
    }

    return PM3_SUCCESS;
}

/*
static uint32_t enable_privacy_15693_slixl(uint32_t start_time, uint32_t *eof_time, uint8_t *uid, uint8_t pass_id, uint8_t *password) {
    uint8_t rnd[2];
    if (get_rnd_15693_slixl(start_time, eof_time, rnd) == false) {
        return PM3_ETIMEOUT;
    }

    uint8_t c[] = {ISO15_REQ_DATARATE_HIGH | ISO15_REQ_ADDRESS, ISO15693_ENABLE_PRIVACY, pass_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memcpy(&c[3], uid, 8);
    init_password_15693_slixl(&c[11], password, rnd);
    AddCrc15(c, 15);

    start_time = *eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;
    uint8_t recvbuf[ISO15693_MAX_RESPONSE_LENGTH];
    int recvlen = SendDataTag(c, sizeof(c), false, true, recvbuf, sizeof(recvbuf), start_time, ISO15693_READER_TIMEOUT_WRITE, eof_time);
    if (recvlen != 3) {
        return PM3_EWRONGANSWER;
    }
    return PM3_SUCCESS;
}

static uint32_t write_password_15693_slixl(uint32_t start_time, uint32_t *eof_time, uint8_t *uid, uint8_t pass_id, uint8_t *password) {
    uint8_t rnd[2];
    if (get_rnd_15693_slixl(start_time, eof_time, rnd) == false) {
        return PM3_ETIMEOUT;
    }

    uint8_t c[] = {ISO15_REQ_DATARATE_HIGH | ISO15_REQ_ADDRESS, ISO15693_WRITE_PASSWORD, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memcpy(&c[3], uid, 8);
    c[11] = pass_id;
    init_password_15693_slixl(&c[12], password, NULL);
    AddCrc15(c, 16);

    start_time = *eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;

    uint8_t recvbuf[ISO15693_MAX_RESPONSE_LENGTH];
    int recvlen = SendDataTag(c, sizeof(c), false, true, recvbuf, sizeof(recvbuf), start_time, ISO15693_READER_TIMEOUT_WRITE, eof_time);
    if (recvlen != 3) {
        return PM3_EWRONGANSWER;
    }
    return PM3_SUCCESS;
}

static uint32_t destroy_15693_slixl(uint32_t start_time, uint32_t *eof_time, uint8_t *uid, uint8_t *password) {

    uint8_t rnd[2];
    if (get_rnd_15693_slixl(start_time, eof_time, rnd) == false) {
        return PM3_ETIMEOUT;
    }

    uint8_t c[] = {ISO15_REQ_DATARATE_HIGH | ISO15_REQ_ADDRESS, ISO15693_DESTROY, ISO15693_ENABLE_PRIVACY, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memcpy(&c[3], uid, 8);
    init_password_15693_slixl(&c[11], password, rnd);
    AddCrc15(c, 15);

    start_time = *eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;
    uint8_t recvbuf[ISO15693_MAX_RESPONSE_LENGTH];
    int recvlen = SendDataTag(c, sizeof(c), false, true, recvbuf, sizeof(recvbuf), start_time, ISO15693_READER_TIMEOUT_WRITE, eof_time);
    if (recvlen != 3) {
        return PM3_EWRONGANSWER;
    }
    return PM3_SUCCESS;
}

*/
void DisablePrivacySlixLIso15693(uint8_t *password) {
    LED_D_ON();
    Iso15693InitReader();
    StartCountSspClk();
    uint32_t start_time = 0, eof_time = 0;
    // 4 == pass id.
    int res = set_pass_15693_slixl(start_time, &eof_time, 0x10, password);
    reply_ng(CMD_HF_ISO15693_SLIX_L_DISABLE_PRIVACY, res, NULL, 0);
    switch_off();
}


