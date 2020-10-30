/*****************************************************************************
 * WARNING
 *
 * THIS CODE IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY.
 *
 * USAGE OF THIS CODE IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL
 * PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL,
 * AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES.
 *
 * THIS CODE SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS.
 *
 *****************************************************************************
 *
 * This file is part of loclass. It is a reconstructon of the cipher engine
 * used in iClass, and RFID techology.
 *
 * The implementation is based on the work performed by
 * Flavio D. Garcia, Gerhard de Koning Gans, Roel Verdult and
 * Milosch Meriac in the paper "Dismantling IClass".
 *
 * Copyright (C) 2014 Martin Holst Swende
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, or, at your option, any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with loclass.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 ****************************************************************************/
#include "cipherutils.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "util.h" // sprint_hex
#include "commonutil.h"  // ARRAYLEN

#include "fileutils.h"
/**
 *
 * @brief Return and remove the first bit (x0) in the stream : <x0 x1 x2 x3 ... xn >
 * @param stream
 * @return
 */
bool headBit(BitstreamIn *stream) {
    int bytepos = stream->position >> 3; // divide by 8
    int bitpos = (stream->position++) & 7; // mask out 00000111
    return (*(stream->buffer + bytepos) >> (7 - bitpos)) & 1;
}
/**
 * @brief Return and remove the last bit (xn) in the stream: <x0 x1 x2 ... xn>
 * @param stream
 * @return
 */
bool tailBit(BitstreamIn *stream) {
    int bitpos = stream->numbits - 1 - (stream->position++);

    int bytepos = bitpos >> 3;
    bitpos &= 7;
    return (*(stream->buffer + bytepos) >> (7 - bitpos)) & 1;
}
/**
 * @brief Pushes bit onto the stream
 * @param stream
 * @param bit
 */
void pushBit(BitstreamOut *stream, bool bit) {
    int bytepos = stream->position >> 3; // divide by 8
    int bitpos = stream->position & 7;
    *(stream->buffer + bytepos) |= (bit) << (7 - bitpos);
    stream->position++;
    stream->numbits++;
}

/**
 * @brief Pushes the lower six bits onto the stream
 * as b0 b1 b2 b3 b4 b5 b6
 * @param stream
 * @param bits
 */
void push6bits(BitstreamOut *stream, uint8_t bits) {
    pushBit(stream, bits & 0x20);
    pushBit(stream, bits & 0x10);
    pushBit(stream, bits & 0x08);
    pushBit(stream, bits & 0x04);
    pushBit(stream, bits & 0x02);
    pushBit(stream, bits & 0x01);
}

/**
 * @brief bitsLeft
 * @param stream
 * @return number of bits left in stream
 */
int bitsLeft(BitstreamIn *stream) {
    return stream->numbits - stream->position;
}
/**
 * @brief numBits
 * @param stream
 * @return Number of bits stored in stream
 */
/*
static int numBits(BitstreamOut *stream) {
    return stream->numbits;
}
*/
void x_num_to_bytes(uint64_t n, size_t len, uint8_t *dest) {
    while (len--) {
        dest[len] = (uint8_t) n;
        n >>= 8;
    }
}

uint64_t x_bytes_to_num(uint8_t *src, size_t len) {
    uint64_t num = 0;
    while (len--) {
        num = (num << 8) | (*src);
        src++;
    }
    return num;
}

void reverse_arraybytes(uint8_t *arr, size_t len) {
    uint8_t i;
    for (i = 0; i < len ; i++) {
        arr[i] = reflect8(arr[i]);
    }
}

void reverse_arraycopy(uint8_t *arr, uint8_t *dest, size_t len) {
    uint8_t i;
    for (i = 0; i < len ; i++) {
        dest[i] = reflect8(arr[i]);
    }
}

void printarr(const char *name, uint8_t *arr, int len) {
    if (name == NULL || arr == NULL) return;

    int cx, i;
    size_t outsize = 40 + strlen(name) + len * 5;
    char *output = calloc(outsize, sizeof(char));
    cx = snprintf(output, outsize, "uint8_t %s[] = {", name);
    for (i = 0; i < len; i++) {
        cx += snprintf(output + cx, outsize - cx, "0x%02x,", *(arr + i)); //5 bytes per byte
    }
    snprintf(output + cx, outsize - cx, "};");
    PrintAndLogEx(INFO, output);
    free(output);
}

void printarr_human_readable(const char *title, uint8_t *arr, int len) {

    if (arr == NULL) return;

    int cx = 0, i;
    size_t outsize = 100 + strlen(title) + (len * 4);
    char *output = calloc(outsize, sizeof(char));
    PrintAndLogEx(INFO, "%s", title);
    for (i = 0;  i < len; i++) {
        if (i % 16 == 0) {

            if (i == 0)
                cx += snprintf(output + cx, outsize - cx, "%02x| ", i);
            else
                cx += snprintf(output + cx, outsize - cx, "\n%02x| ", i);
        }
        cx += snprintf(output + cx, outsize - cx, "%02x ", *(arr + i));
    }
    PrintAndLogEx(INFO, output);
    free(output);
}

//-----------------------------
// Code for testing below
//-----------------------------

#ifndef ON_DEVICE
static int testBitStream(void) {
    uint8_t input [] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t output [] = {0, 0, 0, 0, 0, 0, 0, 0};
    BitstreamIn in = { input, sizeof(input) * 8, 0};
    BitstreamOut out = { output, 0, 0}
                       ;
    while (bitsLeft(&in) > 0) {
        pushBit(&out, headBit(&in));
        //printf("Bits left: %d\n", bitsLeft(&in));
        //printf("Bits out: %d\n", numBits(&out));
    }

    if (memcmp(input, output, sizeof(input)) == 0) {
        PrintAndLogEx(SUCCESS, "    Bitstream test 1 (%s)", _GREEN_("ok"));
    } else {
        PrintAndLogEx(FAILED, "    Bitstream test 1 (%s)", _RED_("failed"));
        uint8_t i;
        for (i = 0 ; i < ARRAYLEN(input) ; i++) {
            PrintAndLogEx(NORMAL, "    IN %02x, OUT %02x", input[i], output[i]);
        }
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int testReversedBitstream(void) {
    uint8_t input [] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t reverse [] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t output [] = {0, 0, 0, 0, 0, 0, 0, 0};
    BitstreamIn in = { input, sizeof(input) * 8, 0};
    BitstreamOut out = { output, 0, 0};
    BitstreamIn reversed_in = { reverse, sizeof(input) * 8, 0};
    BitstreamOut reversed_out = { reverse, 0, 0};

    while (bitsLeft(&in) > 0) {
        pushBit(&reversed_out, tailBit(&in));
    }

    while (bitsLeft(&reversed_in) > 0) {
        pushBit(&out, tailBit(&reversed_in));
    }

    if (memcmp(input, output, sizeof(input)) == 0) {
        PrintAndLogEx(SUCCESS, "    Bitstream test 2 (%s)", _GREEN_("ok"));
    } else {
        PrintAndLogEx(FAILED, "    Bitstream test 2 (%s)", _RED_("failed"));
        uint8_t i;
        for (i = 0 ; i < ARRAYLEN(input) ; i++) {
            PrintAndLogEx(NORMAL, "    IN %02x, MIDDLE: %02x, OUT %02x", input[i], reverse[i], output[i]);
        }
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

int testCipherUtils(void) {
    PrintAndLogEx(INFO, "Testing some internals...");
    int retval = testBitStream();
    if (retval == PM3_SUCCESS)
        retval = testReversedBitstream();

    return retval;
}
#endif
