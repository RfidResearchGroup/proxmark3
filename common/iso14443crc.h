#ifndef ISO14443CRC_H__
#define ISO14443CRC_H__

//-----------------------------------------------------------------------------
// Routines to compute the CRCs (two different flavours, just for confusion)
// required for ISO 14443, swiped directly from the spec.
//-----------------------------------------------------------------------------
#define	CRC_14443_A	0x6363	/* ITU-V.41 */
#define	CRC_14443_B	0xFFFF  /* ISO/IEC 13239 (formerly ISO/IEC 3309) */

void ComputeCrc14443(int CrcType,
                     unsigned char *Data, int Length,
                     unsigned char *TransmitFirst,
                     unsigned char *TransmitSecond);

#endif
