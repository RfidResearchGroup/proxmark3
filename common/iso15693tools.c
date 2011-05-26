//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ISO15693 CRC & other commons
//-----------------------------------------------------------------------------


#include "proxmark3.h"
#include <stdint.h>
#include <stdlib.h>
//#include "iso15693tools.h"

// The CRC as described in ISO 15693-Part 3-Annex C
// 	v	buffer with data
//		n	length
//	returns crc as 16bit value
uint16_t Iso15693Crc(uint8_t *v, int n)
{
	uint32_t reg;
	int i, j;

	reg = 0xffff;
	for(i = 0; i < n; i++) {
		reg = reg ^ ((uint32_t)v[i]);
		for (j = 0; j < 8; j++) {
			if (reg & 0x0001) {
				reg = (reg >> 1) ^ 0x8408;
			} else {
				reg = (reg >> 1);
			}
		}
	}

	return ~(uint16_t)(reg & 0xffff);
}

// adds a CRC to a dataframe
// 	req[]   iso15963 frame without crc
//		n       length without crc
// returns the new length of the dataframe.
int Iso15693AddCrc(uint8_t *req, int n) {
	uint16_t crc=Iso15693Crc(req,n);
	req[n] = crc & 0xff;
	req[n+1] = crc >> 8;
	return n+2;
}


int sprintf(char *str, const char *format, ...);

// returns a string representation of the UID
// UID is transmitted and stored LSB first, displayed MSB first
//		target    char* buffer, where to put the UID, if NULL a static buffer is returned
//		uid[]		the UID in transmission order
//	return: ptr to string
char* Iso15693sprintUID(char *target,uint8_t *uid) {
  static char tempbuf[2*8+1]="";
  if (target==NULL) target=tempbuf;
  sprintf(target,"%02hX%02hX%02hX%02hX%02hX%02hX%02hX%02hX",
  				uid[7],uid[6],uid[5],uid[4],uid[3],uid[2],uid[1],uid[0]);
  return target;
}



