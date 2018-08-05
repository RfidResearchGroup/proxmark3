//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ISO14443 CRC calculation code.
//-----------------------------------------------------------------------------

#include "iso14443crc.h"


uint16_t UpdateCrc14443(uint8_t b, uint16_t *crc) {
    b = (b ^ (uint8_t)((*crc) & 0x00FF));
    b = (b ^ (b << 4));
    *crc = (*crc >> 8) ^ ((uint16_t) b << 8) ^ ((uint16_t) b << 3) ^ ((uint16_t) b >> 4);
    return (*crc);
}

void ComputeCrc14443(uint16_t CrcType, const uint8_t *data, int length,
                     uint8_t *TransmitFirst, uint8_t *TransmitSecond)
{
    uint8_t b;
    uint16_t crc = CrcType;

	do {
        b = *data++;
        UpdateCrc14443(b, &crc);
    } while (--length);

    if (CrcType == CRC_14443_B)
        crc = ~crc;                /* ISO/IEC 13239 (formerly ISO/IEC 3309) */

    *TransmitFirst = (uint8_t) (crc & 0xFF);
    *TransmitSecond = (uint8_t)((crc >> 8) & 0xFF);
    return;
}

bool CheckCrc14443(uint16_t CrcType, const uint8_t *data, int length) {
	if (length < 3) return false;
	uint8_t b1, b2;
	ComputeCrc14443(CrcType, data, length - 2, &b1, &b2);
	if ((b1 == data[length - 2]) && (b2 == data[length - 1])) 
		return true;
	return false;
}
