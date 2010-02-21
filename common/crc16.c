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
