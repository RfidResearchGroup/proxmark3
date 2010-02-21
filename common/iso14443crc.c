//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ISO14443 CRC calculation code.
//-----------------------------------------------------------------------------

#include "iso14443crc.h"

static unsigned short UpdateCrc14443(unsigned char ch, unsigned short *lpwCrc)
{
    ch = (ch ^ (unsigned char) ((*lpwCrc) & 0x00FF));
    ch = (ch ^ (ch << 4));
    *lpwCrc = (*lpwCrc >> 8) ^ ((unsigned short) ch << 8) ^
              ((unsigned short) ch << 3) ^ ((unsigned short) ch >> 4);
    return (*lpwCrc);
}

void ComputeCrc14443(int CrcType,
                     unsigned char *Data, int Length,
                     unsigned char *TransmitFirst,
                     unsigned char *TransmitSecond)
{
    unsigned char chBlock;
    unsigned short wCrc=CrcType;

  do {
        chBlock = *Data++;
        UpdateCrc14443(chBlock, &wCrc);
    } while (--Length);

    if (CrcType == CRC_14443_B)
        wCrc = ~wCrc;                /* ISO/IEC 13239 (formerly ISO/IEC 3309) */

    *TransmitFirst = (unsigned char) (wCrc & 0xFF);
    *TransmitSecond = (unsigned char) ((wCrc >> 8) & 0xFF);
    return;
}
