//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CRC16
//-----------------------------------------------------------------------------

#include "crc16.h"
uint16_t update_crc16_ex( uint16_t crc, uint8_t c, uint16_t polynomial ) {
	uint16_t i, v, tmp = 0;

	v = (crc ^ c) & 0xff;
	
	for (i = 0; i < 8; i++) {
		
		if ( (tmp ^ v) & 1 )
			tmp = ( tmp >> 1 ) ^ polynomial;
		else
			tmp >>= 1;
		
		v >>= 1;
	}
	return ((crc >> 8) ^ tmp) & 0xffff;
}
uint16_t update_crc16( uint16_t crc, uint8_t c ) {
	return update_crc16_ex( crc, c, CRC16_POLY_CCITT);
}

// two ways.
// msb or lsb loop.
//
uint16_t crc16(uint8_t const *d, size_t length, uint16_t remainder, uint16_t polynomial, bool refin, bool refout) {
    
	if (length == 0)
        return (~remainder);

	uint8_t c;
    for (uint32_t i = 0; i < length; ++i) {
		c = d[i];
		if (refin) c = reflect8(c);

		// xor in at msb
        remainder ^= (c << 8);
		
		// 8 iteration loop		
        for (uint8_t j = 8; j; --j) {
            if (remainder & 0x8000) {
                remainder = (remainder << 1) ^ polynomial;
            } else {
                remainder <<=  1;
            }
        }		

		/*
	    c = (c ^ (uint8_t)(remainder & 0x00FF));
		c = (c ^ (c << 4));
		remainder = (remainder >> 8) ^ ((uint16_t) c << 8) ^ ((uint16_t) c << 3) ^ ((uint16_t) c >> 4);
		*/
    }
	if (refout) 
		remainder = reflect16(remainder);
	
    return remainder;
}
uint16_t crc16_ccitt(uint8_t const *d, size_t n) {
    return crc16(d, n, 0xffff, CRC16_POLY_CCITT, false, false);
}
//poly=0x1021  init=0x0000  refin=true  refout=true  xorout=0x0000 name="KERMIT"
uint16_t crc16_ccitt_kermit(uint8_t const *d, size_t n){
	return crc16_kermit(d, n);
}
uint16_t crc16_kermit(uint8_t const *d, size_t n) {
	return crc16(d, n, 0x0000, CRC16_POLY_CCITT, true, true);
}
//FeliCa uses XMODEM
//poly=0x1021  init=0x0000  refin=false  refout=false  xorout=0x0000 name="XMODEM"
uint16_t crc16_xmodem(uint8_t const *d, size_t n) {
	return crc16(d, n, 0x0000, CRC16_POLY_CCITT, false, false); 
}
//ISO 15693 uses X-25, CRC_B  (or 14443-3 )
//poly=0x1021  init=0xffff  refin=true  refout=true  xorout=0xffff name="X-25"
uint16_t crc16_x25(uint8_t const *d, size_t n) {	
	uint16_t crc = crc16(d, n, 0xffff, CRC16_POLY_CCITT, true, true);
	crc ^= 0xFFFF;
	return crc;
}
//CRC-A  (14443-3)
//poly=0x1021 init=0xc6c6 refin=true refout=true xorout=0x0000 name="CRC-A"
uint16_t crc16_a(uint8_t const *d, size_t n) {	
	return crc16(d, n, 0xc6c6, 0x1021, true, true);
}

//width=16  poly=0x8408  init=0xffff  refin=true  refout=true  xorout=0x0BC3  check=0xF0B8  name="CRC-16/ICLASS"
uint16_t crc16_iclass(uint8_t const *d, size_t n) {
	uint16_t crc = crc16(d, n, 0xffff, CRC16_POLY_CCITT, true, true);
	crc ^= 0x0BC3;
	return crc;
}


// CHECK functions.
bool check_crc16_ccitt(uint8_t const *d, size_t n) {
	if (n < 3) return false;

	uint16_t crc = crc16_ccitt(d, n - 2);	
	if ((( crc & 0xff ) == d[n-2]) && (( crc >> 8 ) == d[n-1]))
		return true;
	return false;
}