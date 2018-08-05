//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CRC32
//-----------------------------------------------------------------------------

#ifndef __CRC32_H
#define __CRC32_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void crc32_ex(const uint8_t *data, const size_t len, uint8_t *crc);
void crc32_append (uint8_t *data, const size_t len);

#ifdef __cplusplus
}
#endif

#endif
