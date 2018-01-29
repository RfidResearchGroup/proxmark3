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
#include <stdio.h>
#include "util.h"

#define CRC16_POLY_CCITT  0x1021
#define CRC16_POLY_LEGIC  0xc6c6 //0x6363
#define CRC16_POLY_DNP	  0x3d65

typedef enum {
	CRC_NONE,
	CRC_14A,
	CRC_14B,
	CRC_15,
	CRC_15_ICLASS,
	CRC_FELICA,
	CRC_LEGIC,
	CRC_DNP,
	CRC_CCITT,
} CrcType_t;

uint16_t update_crc16_ex( uint16_t crc, uint8_t c, uint16_t polynomial );
uint16_t update_crc16(uint16_t crc, uint8_t c);
uint16_t crc16(uint8_t const *message, size_t length, uint16_t remainder, uint16_t polynomial, bool refin, bool refout);

// Calculate CRC-16/CCITT-FALSE checksum
uint16_t crc16_ccitt(uint8_t const *d, size_t n);

// Calculate CRC-16/KERMIT checksum
uint16_t crc16_kermit(uint8_t const *d, size_t n);

// Calculate CRC-16/XMODEM (FeliCa) checksum
uint16_t crc16_xmodem(uint8_t const *d, size_t n);

// Calculate CRC-16/X25 (ISO15693, ISO14443 CRC-B,ISO/IEC 13239) checksum 
uint16_t crc16_x25(uint8_t const *d, size_t n);

// Calculate CRC-16/CRC-A (ISO14443 CRC-A) checksum
uint16_t crc16_a(uint8_t const *d, size_t n);

// Calculate CRC-16/iCLASS checksum
uint16_t crc16_iclass(uint8_t const *d, size_t n);

// Calculate CRC-16/DNP checksum
uint16_t crc16_dnp(uint8_t const *d, size_t n);

// Calculate CRC-16/Legic checksum
// the initial_value is based on the previous legic_Crc8 of the UID.
// ie:  uidcrc = 0x78  then initial_value == 0x7878
uint16_t crc16_legic(uint8_t const *d, size_t n, uint8_t uidcrc);

// table implementation
void init_table(CrcType_t crctype);
void reset_table(void);
void generate_table(uint16_t polynomial, bool refin);
uint16_t crc16_fast(uint8_t const *d, size_t n, uint16_t initval, bool refin, bool refout);

//checks
bool check_crc16_ccitt(uint8_t const *d, size_t n);

//felica imp
void felica_test();
void init_crcccitt_tab( void );
uint16_t update_crc_ccitt( uint16_t crc,uint8_t c );
#endif
