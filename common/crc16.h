//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CRC16
//-----------------------------------------------------------------------------
#ifndef __CRC16_H
#define __CRC16_H

#include <stdint.h>
#include "util.h"   // SwapBits

#define CRC16_POLY_CCITT 0x1021
#define CRC16_POLY 0x8408


uint16_t update_crc16_ex( uint16_t crc, uint8_t c, uint16_t polynomial );
uint16_t update_crc16(uint16_t crc, uint8_t c);
uint16_t crc16(uint8_t const *message, int length, uint16_t remainder, uint16_t polynomial, bool refin, bool refout);
uint16_t crc16_ccitt(uint8_t const *message, int length);

uint16_t crc16_ccitt_kermit(uint8_t const *message, int length);
uint16_t crc16_kermit(uint8_t const *message, int length);
uint16_t crc16_xmodem(uint8_t const *d, int n);

uint16_t crc16_x25(uint8_t const *d, int n);
uint16_t crc16_a(uint8_t const *d, int n);

bool check_crc16_ccitt(uint8_t const *d, int n);

//felica imp
void felica_test();
void init_crcccitt_tab( void );
uint16_t update_crc_ccitt( uint16_t crc,uint8_t c );
#endif
