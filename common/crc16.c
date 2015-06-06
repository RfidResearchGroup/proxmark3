//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CRC16
//-----------------------------------------------------------------------------

#include "crc16.h"

unsigned short update_crc16( unsigned short crc, unsigned char c )
{
	unsigned short i, v, tcrc = 0;

	v = (crc ^ c) & 0xff;
	for (i = 0; i < 8; i++) {
		tcrc = ( (tcrc ^ v) & 1 ) ? ( tcrc >> 1 ) ^ 0x8408 : tcrc >> 1;
		v >>= 1;
	}

	return ((crc >> 8) ^ tcrc)&0xffff;
}

uint16_t crc16(uint8_t const *message, int length, uint16_t remainder, uint16_t polynomial) {

	if (length == 0) return (~remainder);

	for (int byte = 0; byte < length; ++byte) {
		remainder ^= (message[byte] << 8);
		for (uint8_t bit = 8; bit > 0; --bit) {
			if (remainder & 0x8000) {
				remainder = (remainder << 1) ^ polynomial;
			} else {
				remainder = (remainder << 1);
			}
		}
	}
	return remainder;
}

uint16_t crc16_ccitt(uint8_t const *message, int length) {
	return crc16(message, length, 0xffff, 0x1021);
}

uint16_t crc16_ccitt_kermit(uint8_t const *message, int length) {
	return bit_reverse_uint16(crc16(message, length, 0x0000, 0x1021));
}

uint16_t bit_reverse_uint16 (uint16_t value) {
	const uint16_t mask0 = 0x5555;
	const uint16_t mask1 = 0x3333;
	const uint16_t mask2 = 0x0F0F;
	const uint16_t mask3 = 0x00FF;

	value = (((~mask0) & value) >> 1) | ((mask0 & value) << 1);
	value = (((~mask1) & value) >> 2) | ((mask1 & value) << 2);
	value = (((~mask2) & value) >> 4) | ((mask2 & value) << 4);
	value = (((~mask3) & value) >> 8) | ((mask3 & value) << 8);

	return value;
}
