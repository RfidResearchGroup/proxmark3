//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ISO14443 CRC calculation code.
//-----------------------------------------------------------------------------

#ifndef __ISO14443CRC_H
#define __ISO14443CRC_H
#include "common.h"

//-----------------------------------------------------------------------------
// Routines to compute the CRCs (two different flavours, just for confusion)
// required for ISO 14443, swiped directly from the spec.
//-----------------------------------------------------------------------------
#define	CRC_14443_A	0x6363	/* ITU-V.41 */
#define	CRC_14443_B	0xFFFF  /* ISO/IEC 13239 (formerly ISO/IEC 3309) */
#define CRC_ICLASS	0xE012  /* ICLASS PREFIX */

uint16_t UpdateCrc14443(uint8_t b, uint16_t *crc);
void ComputeCrc14443(uint16_t CrcType, const uint8_t *data, int length,
                     uint8_t *TransmitFirst, uint8_t *TransmitSecond);
bool CheckCrc14443(uint16_t CrcType, const uint8_t *data, int length);

#endif
