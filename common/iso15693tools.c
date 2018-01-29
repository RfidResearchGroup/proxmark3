//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ISO15693 CRC & other commons
//-----------------------------------------------------------------------------

#include "iso15693tools.h"

// The CRC as described in ISO 15693-Part 3-Annex C
uint16_t Iso15693Crc(uint8_t *d, size_t n){
	init_table(CRC_15);
	return crc16_x25(d, n);
}

// adds a CRC to a dataframe
// 	d[]   iso15963 frame without crc
//	n     length without crc
// returns the new length of the dataframe.
int Iso15693AddCrc(uint8_t *d, size_t n) {
	uint16_t crc = Iso15693Crc(d, n);
	d[n] = crc & 0xff;
	d[n+1] = crc >> 8;
	return n + 2;
}

// check the CRC as described in ISO 15693-Part 3-Annex C
// 	v	buffer with data
//	n	length (including crc)
// If calculated with crc bytes,  the residue should be 0xF0B8
bool Iso15693CheckCrc(uint8_t *d, size_t n) {
	return (Iso15693Crc(d, n) == ISO15_CRC_CHECK );
}

int sprintf(char *str, const char *format, ...);

// returns a string representation of the UID
// UID is transmitted and stored LSB first, displayed MSB first
//		target    char* buffer, where to put the UID, if NULL a static buffer is returned
//		uid[]		the UID in transmission order
//	return: ptr to string
char* Iso15693sprintUID(char *target, uint8_t *uid) {

	static char tempbuf[2*8+1] = {0};
	if (target == NULL) 
		target = tempbuf;
	sprintf(target, "%02X %02X %02X %02X %02X %02X %02X %02X",
				uid[7], uid[6], uid[5], uid[4],
				uid[3], uid[2], uid[1], uid[0]
	);
	return target;
}

uint16_t iclass_crc16(uint8_t *d, uint16_t n) {

	unsigned int data;
	uint16_t crc = 0xffff;

	
	if (n == 0)
		return (~crc);

	do {
		for (uint8_t i=0, data = *d++; i < 8;  i++, data >>= 1) {
			if ((crc & 0x0001) ^ (data & 0x0001))
				crc = (crc >> 1) ^ ISO15_CRC_POLY;
			else  
				crc >>= 1;
		}
	} while (--n);

	crc = ~crc;
	data = crc;
	crc = (crc << 8) | (data >> 8 & 0xff);
	crc = crc ^ 0xBC3;
	return crc;
}