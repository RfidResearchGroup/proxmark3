//-----------------------------------------------------------------------------
// Routines to compute the CRCs (two different flavours, just for confusion)
// required for ISO 14443, swiped directly from the spec.
//-----------------------------------------------------------------------------

#define	CRC_14443_A	0x6363	/* ITU-V.41 */
#define	CRC_14443_B 0xFFFF  /* ISO/IEC 13239 (formerly ISO/IEC 3309) */

static unsigned short UpdateCrc14443(unsigned char ch, unsigned short *lpwCrc)
{
    ch = (ch ^ (unsigned char) ((*lpwCrc) & 0x00FF));
    ch = (ch ^ (ch << 4));
    *lpwCrc =	(*lpwCrc >> 8) ^ ((unsigned short) ch << 8) ^
            	((unsigned short) ch << 3) ^ ((unsigned short) ch >> 4);
    return (*lpwCrc);
}

static void ComputeCrc14443(int CrcType, BYTE *Data, int Length,
           BYTE *TransmitFirst, BYTE *TransmitSecond)
{
    unsigned char chBlock;
    unsigned short wCrc=CrcType;

	do {
        chBlock = *Data++;
        UpdateCrc14443(chBlock, &wCrc);
    } while (--Length);

    if (CrcType == CRC_14443_B)
        wCrc = ~wCrc;                /* ISO/IEC 13239 (formerly ISO/IEC 3309) */

    *TransmitFirst = (BYTE) (wCrc & 0xFF);
    *TransmitSecond = (BYTE) ((wCrc >> 8) & 0xFF);
    return;
}
