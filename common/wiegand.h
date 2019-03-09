//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Generic Wiegand Calculation code
//-----------------------------------------------------------------------------

#ifndef __WIEGAND_H
#define __WIEGAND_H

#include "common.h"
#include "util.h"

uint8_t getParity(uint8_t *bits, uint8_t length, uint8_t type);
uint8_t checkParity(uint32_t bits, uint8_t bitlen, uint8_t type);

void num_to_wiegand_bytes(uint64_t oem, uint64_t fc, uint64_t cn, uint8_t *dest, uint8_t formatlen);
void num_to_wiegand_bits(uint64_t oem, uint64_t fc, uint64_t cn, uint8_t *dest, uint8_t formatlen);

#endif /* __WIEGAND_H */
