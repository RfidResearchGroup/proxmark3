//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ISO14443 CRC calculation code.
//-----------------------------------------------------------------------------

#include "iso14443crc.h"

static unsigned short UpdateCrc14443(unsigned char ch, unsigned short *lpwCrc) {
    ch = (ch ^ (unsigned char)((*lpwCrc) & 0x00FF));
    ch = (ch ^ (ch << 4));
    *lpwCrc = (*lpwCrc >> 8) ^ ((unsigned short) ch << 8) ^
              ((unsigned short) ch << 3) ^ ((unsigned short) ch >> 4);
    return (*lpwCrc);
}

void ComputeCrc14443(int CrcType,
                     const unsigned char *Data, int Length,
                     unsigned char *TransmitFirst,
                     unsigned char *TransmitSecond) {
    unsigned short wCrc = CrcType;

    do {
        unsigned char chBlock = *Data++;
        UpdateCrc14443(chBlock, &wCrc);
    } while (--Length);

    if (CrcType == CRC_14443_B)
        wCrc = ~wCrc;                /* ISO/IEC 13239 (formerly ISO/IEC 3309) */

    *TransmitFirst = (unsigned char)(wCrc & 0xFF);
    *TransmitSecond = (unsigned char)((wCrc >> 8) & 0xFF);
    return;
}

int CheckCrc14443(int CrcType, const unsigned char *Data, int Length) {
    unsigned char b1;
    unsigned char b2;
    if (Length < 3) return 0;
    ComputeCrc14443(CrcType, Data, Length - 2, &b1, &b2);
    if ((b1 == Data[Length - 2]) && (b2 == Data[Length - 1])) return 1;
    return 0;
}
