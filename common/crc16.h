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
// CRC16
//-----------------------------------------------------------------------------
#ifndef __CRC16_H
#define __CRC16_H

#include "common.h"

#define CRC16_POLY_CCITT     0x1021
#define CRC16_POLY_KERMIT    0x8408
#define CRC16_POLY_LEGIC     0xc6c6 //0x6363
#define CRC16_POLY_LEGIC_16  0x002d
#define CRC16_POLY_DNP       0x3d65

#define X25_CRC_CHECK     ((uint16_t)(~0xF0B8 & 0xFFFF)) // use this for checking of a correct crc

typedef enum {
    CRC_NONE,
    CRC_11784,
    CRC_14443_A,
    CRC_14443_B,
    CRC_15693,
    CRC_ICLASS,
    CRC_FELICA,
    CRC_LEGIC,
    CRC_LEGIC_16,
    CRC_CCITT,
    CRC_KERMIT,
    CRC_XMODEM,
    CRC_CRYPTORF,
    CRC_PHILIPS,
} CrcType_t;

uint16_t update_crc16_ex(uint16_t crc, uint8_t c, uint16_t polynomial);
uint16_t update_crc16(uint16_t crc, uint8_t c);
uint16_t Crc16(uint8_t const *d, size_t length, uint16_t remainder, uint16_t polynomial, bool refin, bool refout);

uint16_t Crc16ex(CrcType_t ct, const uint8_t *d, size_t n);
void compute_crc(CrcType_t ct, const uint8_t *d, size_t n, uint8_t *first, uint8_t *second);
bool check_crc(CrcType_t ct, const uint8_t *d, size_t n);

// Calculate CRC-16/CCITT-FALSE
uint16_t crc16_ccitt(uint8_t const *d, size_t n);

// Calculate CRC-16/KERMIT (FDX-B ISO11784/85)  LF
uint16_t crc16_fdxb(uint8_t const *d, size_t n);

// Calculate CRC-16/KERMIT
uint16_t crc16_kermit(uint8_t const *d, size_t n);

// Calculate CRC-16/XMODEM (FeliCa)
uint16_t crc16_xmodem(uint8_t const *d, size_t n);

// Calculate CRC-16/X25 (ISO15693, ISO14443 CRC-B,ISO/IEC 13239)
uint16_t crc16_x25(uint8_t const *d, size_t n);

// Calculate CRC-16/CRC-A (ISO14443 CRC-A)
uint16_t crc16_a(uint8_t const *d, size_t n);

// Calculate CRC-16/iCLASS
uint16_t crc16_iclass(uint8_t const *d, size_t n);

// Calculate CRC-16/Legic
// the initial_value is based on the previous legic_Crc8 of the UID.
// ie:  uidcrc = 0x78  then initial_value == 0x7878
uint16_t crc16_legic(uint8_t const *d, size_t n, uint8_t uidcrc);

// Calculate CRC-16/ Philips.
uint16_t crc16_philips(uint8_t const *d, size_t n);

// table implementation
void init_table(CrcType_t crctype);
void reset_table(void);
void generate_table(uint16_t polynomial, bool refin);
uint16_t crc16_fast(uint8_t const *d, size_t n, uint16_t initval, bool refin, bool refout);

#endif
