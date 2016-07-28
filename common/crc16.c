//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CRC16
//-----------------------------------------------------------------------------

#include "crc16.h"
#define CRC16_POLY_CCITT 0x1021
#define CRC16_POLY 0x8408

uint16_t update_crc16( uint16_t crc, unsigned char c ) {
  uint16_t i, v, tcrc = 0;

  v = (crc ^ c) & 0xff;
  for (i = 0; i < 8; i++) {
      tcrc = ( (tcrc ^ v) & 1 ) ? ( tcrc >> 1 ) ^ CRC16_POLY : tcrc >> 1;
      v >>= 1;
  }

  return ((crc >> 8) ^ tcrc) & 0xffff;
}

uint16_t crc16(uint8_t const *message, int length, uint16_t remainder, uint16_t polynomial) {
    
	if (length == 0)
        return (~remainder);
			
    for (uint32_t i = 0; i < length; ++i) {
        remainder ^= (message[i] << 8);
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
    return crc16(message, length, 0xffff, CRC16_POLY_CCITT);
}

uint16_t crc16_ccitt_kermit(uint8_t const *message, int length) {
	uint16_t val = crc16(message, length, 0x0000, CRC16_POLY_CCITT);
    return SwapBits(val, 16);
}
