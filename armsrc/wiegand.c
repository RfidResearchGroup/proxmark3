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
// Generic Wiegand Calculation code
//-----------------------------------------------------------------------------

#include "wiegand.h"

/*
* @brief getParity
* @param bits     pointer to the source bitstream of binary values 0|1
* @param len      how long shall parity be calculated
* @param type     use the defined values  EVEN|ODD
* @return parity bit required to match type
*/
uint8_t getParity(const uint8_t *bits, uint8_t len, uint8_t type) {
    uint8_t x = 0;
    for (; len > 0; --len)
        x += bits[len - 1];

    return (x & 1) ^ type;
}

// by marshmellow
/* pass bits to be tested in bits, length bits passed in bitLen, and parity type EVEN|ODD in type
* @brief checkParity
* @param bits     pointer to the source bitstream of binary values 0|1
* @param len      number of bits to be checked
* @param type     use the defined values  EVEN|ODD
* @return 1 if passed
*/
uint8_t checkParity(uint32_t bits, uint8_t len, uint8_t type);

// by marshmellow
// takes a array of binary values, start position, length of bits per parity (includes parity bit),
// Parity Type (1 for odd; 0 for even; 2 for Always 1's; 3 for Always 0's), and binary Length (length to run)
size_t removeParity(uint8_t *bits, size_t startIdx, uint8_t pLen, uint8_t pType, size_t bLen) {
    uint32_t parityWd = 0;
    size_t j = 0, bitcount = 0;
    for (int word = 0; word < (bLen); word += pLen) {
        for (int bit = 0; bit < pLen; ++bit) {
            parityWd = (parityWd << 1) | bits[startIdx + word + bit];
            bits[j++] = (bits[startIdx + word + bit]);
        }
        j--; // overwrite parity with next data
        // if parity fails then return 0
        switch (pType) {
            case 3:
                if (bits[j] == 1) return 0;
                break; //should be 0 spacer bit
            case 2:
                if (bits[j] == 0) return 0;
                break; //should be 1 spacer bit
            default: //test parity
                if (parityTest(parityWd, pLen, pType) == 0) return 0;
                break;
        }
        bitcount += (pLen - 1);
        parityWd = 0;
    }
    // if we got here then all the parities passed
    //return ID start index and size
    return bitcount;
}


// by marshmellow
// takes a array of binary values, length of bits per parity (includes parity bit),
// Parity Type (1 for odd; 0 for even; 2 Always 1's; 3 Always 0's), and binary Length (length to run)
// Make sure *dest is long enough to store original sourceLen + #_of_parities_to_be_added
/*
* @brief addParity
* @param src        pointer to the source bitstream of binary values
* @param dest       pointer to the destination where parities together with bits are added.
* @param sourceLen  number of
* @param pLen       length bits to be checked
* @param pType      EVEN|ODD|2 (always 1's)|3 (always 0's)
* @return
*/
size_t addParity(const uint8_t *src, uint8_t *dest, uint8_t sourceLen, uint8_t pLen, uint8_t pType) {
    uint32_t parityWd = 0;
    size_t j = 0, bitCnt = 0;
    for (int word = 0; word < sourceLen; word += pLen - 1) {
        for (int bit = 0; bit < pLen - 1; ++bit) {
            parityWd = (parityWd << 1) | src[word + bit];
            dest[j++] = (src[word + bit]);
        }

        // if parity fails then return 0
        switch (pType) {
            case 3:
                dest[j++] = 0;
                break; // marker bit which should be a 0
            case 2:
                dest[j++] = 1;
                break; // marker bit which should be a 1
            default:
                dest[j++] = parityTest(parityWd, pLen - 1, pType) ^ 1;
                break;
        }
        bitCnt += pLen;
        parityWd = 0;
    }
    // if we got here then all the parities passed
    //return ID start index and size
    return bitCnt;
}

// by marshmellow
/*
*  add HID parity to binary array: EVEN prefix for 1st half of ID, ODD suffix for 2nd half
* @brief wiegand_add_parity
* @param source  pointer to source of binary data
* @param dest    pointer to the destination where wiegandparity has been appended
* @param len     number of bits which wiegand parity shall be calculated over. This number is without parities, so a wiegand 26 has 24 bits of data
*/
void wiegand_add_parity(uint8_t *source, uint8_t *dest, uint8_t len) {

    // Copy to destination, shifted one step to make room for EVEN parity
    memcpy(dest + 1, source, length);

    // half length, Even and Odd is calculated to the middle.
    uint8_t len_h2 = length >> 1;

    // add EVEN parity at the beginning
    *(dest) = GetParity(source, EVEN, len_h2);

    dest += length + 1;

    // add ODD parity at the very end
    *(dest) = GetParity(source + len_h2, ODD, len_h2);
}

//uint32_t bytebits_to_byte(uint8_t* src, size_t numbits);
#define MAX_BITS_TXX55 6*4*8
#define MAX_BYTES_TXX55 6*4
/*
* @brief num_to_wiegand_bytes
* @param oem       Sometimes call FF Fixfield, SiteCode. Used in a few formats
* @param fc        Facility code
* @param cn        Card number
* @param dest      pointer to the destination where wiegand bytes will be stored
* @param formatlen
*/
void num_to_wiegand_bytes(uint64_t oem, uint64_t fc, uint64_t cn, uint8_t *dest, uint8_t formatlen) {

    uint8_t data[MAX_BITS_TXX55] = {0};
    memset(data, 0, sizeof(data));

    num_to_wiegand_bits(oem, fc, cn, data, formatlen);

    // loop
    // (formatlen / 32 ) + 1
    // (formatlen >> 5) + 1
    for (int i = 0; i < formatlen ; ++i) {
        uint32_t value  = bytebits_to_byte(data + (i * 32), 32);
        num_to_bytes(value, 32, dest + (i * 4));
    }

}
/*
* @brief num_to_wiegand_bits
* @param oem       Sometimes call FF Fixfield, SiteCode. Used in a few formats
* @param fc        Facility code
* @param cn        Card number
* @param dest      pointer to the destination where wiegand bits will be stored
* @param formatlen
*/
void num_to_wiegand_bits(uint64_t oem, uint64_t fc, uint64_t cn, uint8_t *dest, uint8_t formatlen) {

    uint8_t bits[MAX_BITS_TXX55] = {0};
    memset(bits, 0, sizeof(bits));
    uint8_t *temp = bits;
    uint64_t value = 0;

    switch (formatlen) {
        case 26 :               // 26bit HID H10301
            fc &= 0xFF;         // 8bits
            cn &= 0xFFFF;       // 16bits
            value = fc << 16 | cn;
            num_to_bytebits(value, 24, temp);
            wiegand_add_parity(temp, dest, 24);
            break;
        case 261:               // 26bit Indala
            fc &= 0xFFF;        // 12bits
            cn &= 0xFFF;        // 12bits
            value = fc << 12 | cn;
            num_to_bytebits(value, 24, temp);
            wiegand_add_parity(temp, dest, 24);
            break;
        case 34 :               // 34bits HID
            fc &= 0xFFFF;       // 16bits
            cn &= 0xFFFF;       // 16bits
            value = fc << 16 | cn;
            num_to_bytebits(value, 32, temp);
            wiegand_add_parity(temp, dest, 32);
            break;
        case 35 :               // 35bits HID
            fc &= 0xFFF;        // 12bits
            cn &= 0xFFFFFF;     // 20bits
            value = fc << 20 | cn;
            num_to_bytebits(value, 32, temp);
            wiegand_add_parity(temp, dest, 32);
            break;
        case 37 :               // H10304
            fc &= 0xFFFF;       // 16bits
            cn &= 0x7FFFF;      // 19bits
            value = fc << 19 | cn;
            num_to_bytebits(value, 35, temp);
            wiegand_add_parity(temp, dest, 35);
            break;
        case 39 :               // 39bit KERI System Pyramid
            fc &= 0x1FFFF;      // 17bits
            cn &= 0xFFFFFFFF;   // 20bits
            value = fc << 20 | cn;
            num_to_bytebits(value, 37, temp);
            wiegand_add_parity(temp, dest, 37);
            break;
        case 44 :               // 44bit KERI system Pyramid
            oem &= 0xFF;        // 8bits
            fc &= 0xFFF;        // 12bits
            cn &= 0xFFFFFFFF;   // 21bits
            value = oem << 20 | fc << 12 | cn;
            num_to_bytebits(value, 42, temp);
            wiegand_add_parity(temp, dest, 42);
            break;
        case 50 :               // AWID 50 RBH
            fc &= 0xFFFF;       // 16bits
            cn &= 0xFFFFFFFF;   // 32bits
            value = fc << 32 | cn;
            num_to_bytebits(value, 48, temp);
            wiegand_add_parity(temp, dest, 48);  // verify!
            break;
        default:
            break;
    }
}
