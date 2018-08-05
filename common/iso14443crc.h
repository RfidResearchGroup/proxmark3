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

uint16_t UpdateCrc14443(uint8_t b, uint16_t *crc);

#endif
