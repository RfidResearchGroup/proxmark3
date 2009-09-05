//-----------------------------------------------------------------------------
// Routines to support ISO 15693. This includes both the reader software and
// the `fake tag' modes, but at the moment I've implemented only the reader
// stuff, and that barely.
// Jonathan Westhues, split Nov 2006

// Modified by Greg Jones, Jan 2009 to perform modulation onboard in arm rather than on PC
// Also added additional reader commands (SELECT, READ etc.)

//-----------------------------------------------------------------------------
#include <proxmark3.h>
#include "apps.h"
#include <stdio.h>
#include <stdlib.h>

// FROM winsrc\prox.h //////////////////////////////////
#define arraylen(x) (sizeof(x)/sizeof((x)[0]))

//-----------------------------------------------------------------------------
// Map a sequence of octets (~layer 2 command) into the set of bits to feed
// to the FPGA, to transmit that command to the tag.
//-----------------------------------------------------------------------------

	// The sampling rate is 106.353 ksps/s, for T = 18.8 us

	// SOF defined as
	// 1) Unmodulated time of 56.64us
	// 2) 24 pulses of 423.75khz
	// 3) logic '1' (unmodulated for 18.88us followed by 8 pulses of 423.75khz)

	static const int FrameSOF[] = {
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		-1, -1, -1, -1,
		-1, -1, -1, -1,
		 1,  1,  1,  1,
		 1,  1,  1,  1
	};
	static const int Logic0[] = {
		 1,  1,  1,  1,
		 1,  1,  1,  1,
		-1, -1, -1, -1,
		-1, -1, -1, -1
	};
	static const int Logic1[] = {
		-1, -1, -1, -1,
		-1, -1, -1, -1,
		 1,  1,  1,  1,
		 1,  1,  1,  1
	};

	// EOF defined as
	// 1) logic '0' (8 pulses of 423.75khz followed by unmodulated for 18.88us)
	// 2) 24 pulses of 423.75khz
	// 3) Unmodulated time of 56.64us

	static const int FrameEOF[] = {
		 1,  1,  1,  1,
		 1,  1,  1,  1,
		-1, -1, -1, -1,
		-1, -1, -1, -1,
		 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
	};

static void CodeIso15693AsReader(BYTE *cmd, int n)
{
	int i, j;

	ToSendReset();

	// Give it a bit of slack at the beginning
	for(i = 0; i < 24; i++) {
		ToSendStuffBit(1);
	}

	ToSendStuffBit(0);
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(0);
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	for(i = 0; i < n; i++) {
		for(j = 0; j < 8; j += 2) {
			int these = (cmd[i] >> j) & 3;
			switch(these) {
				case 0:
					ToSendStuffBit(1);
					ToSendStuffBit(0);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					break;
				case 1:
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(0);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					break;
				case 2:
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(0);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					break;
				case 3:
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(1);
					ToSendStuffBit(0);
					break;
			}
		}
	}
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(0);
	ToSendStuffBit(1);

	// And slack at the end, too.
	for(i = 0; i < 24; i++) {
		ToSendStuffBit(1);
	}
}

//-----------------------------------------------------------------------------
// The CRC used by ISO 15693.
//-----------------------------------------------------------------------------
static WORD Crc(BYTE *v, int n)
{
	DWORD reg;
	int i, j;

	reg = 0xffff;
	for(i = 0; i < n; i++) {
		reg = reg ^ ((DWORD)v[i]);
		for (j = 0; j < 8; j++) {
			if (reg & 0x0001) {
				reg = (reg >> 1) ^ 0x8408;
			} else {
				reg = (reg >> 1);
			}
		}
	}

	return ~reg;
}

char *strcat(char *dest, const char *src)
{
	size_t dest_len = strlen(dest);
	size_t i;
 
	for (i = 0 ; src[i] != '\0' ; i++)
	        dest[dest_len + i] = src[i];
	dest[dest_len + i] = '\0';
 
	return dest;
}

////////////////////////////////////////// code to do 'itoa'

/* reverse:  reverse string s in place */
void reverse(char s[])
{
    int c, i, j;

    for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

/* itoa:  convert n to characters in s */
void itoa(int n, char s[])
{
    int i, sign;

    if ((sign = n) < 0)  /* record sign */
        n = -n;          /* make n positive */
    i = 0;
    do {       /* generate digits in reverse order */
        s[i++] = n % 10 + '0';   /* get next digit */
    } while ((n /= 10) > 0);     /* delete it */
    if (sign < 0)
        s[i++] = '-';
    s[i] = '\0';
    reverse(s);
}

//////////////////////////////////////// END 'itoa' CODE

//-----------------------------------------------------------------------------
// Encode (into the ToSend buffers) an identify request, which is the first
// thing that you must send to a tag to get a response.
//-----------------------------------------------------------------------------
static void BuildIdentifyRequest(void)
{
	BYTE cmd[5];

	WORD crc;
	// one sub-carrier, inventory, 1 slot, fast rate
	// AFI is at bit 5 (1<<4) when doing an INVENTORY
	cmd[0] = (1 << 2) | (1 << 5) | (1 << 1);
	// inventory command code
	cmd[1] = 0x01;
	// no mask
	cmd[2] = 0x00;
	//Now the CRC
	crc = Crc(cmd, 3);
	cmd[3] = crc & 0xff;
	cmd[4] = crc >> 8;

	CodeIso15693AsReader(cmd, sizeof(cmd));
}

static void __attribute__((unused)) BuildSysInfoRequest(BYTE *uid)
{
	BYTE cmd[12];

	WORD crc;
	// If we set the Option_Flag in this request, the VICC will respond with the secuirty status of the block
	// followed by teh block data
	// one sub-carrier, inventory, 1 slot, fast rate
	cmd[0] =  (1 << 5) | (1 << 1); // no SELECT bit
	// System Information command code
	cmd[1] = 0x2B;
	// UID may be optionally specified here
	// 64-bit UID
	cmd[2] = 0x32;
	cmd[3]= 0x4b;
	cmd[4] = 0x03;
	cmd[5] = 0x01;
	cmd[6] = 0x00;
	cmd[7] = 0x10;
	cmd[8] = 0x05;
	cmd[9]= 0xe0; // always e0 (not exactly unique)
	//Now the CRC
	crc = Crc(cmd, 10); // the crc needs to be calculated over 2 bytes
	cmd[10] = crc & 0xff;
	cmd[11] = crc >> 8;

	CodeIso15693AsReader(cmd, sizeof(cmd));
}

static void BuildSelectRequest( BYTE uid[])
{

//	uid[6]=0x31;  // this is getting ignored - the uid array is not happening...
	BYTE cmd[12];

	WORD crc;
	// one sub-carrier, inventory, 1 slot, fast rate
	//cmd[0] = (1 << 2) | (1 << 5) | (1 << 1);	// INVENTROY FLAGS
	cmd[0] = (1 << 4) | (1 << 5) | (1 << 1);	// Select and addressed FLAGS
	// SELECT command code
	cmd[1] = 0x25;
	// 64-bit UID
//	cmd[2] = uid[0];//0x32;
//	cmd[3]= uid[1];//0x4b;
//	cmd[4] = uid[2];//0x03;
//	cmd[5] = uid[3];//0x01;
//	cmd[6] = uid[4];//0x00;
//	cmd[7] = uid[5];//0x10;
//	cmd[8] = uid[6];//0x05;
	cmd[2] = 0x32;//
	cmd[3] = 0x4b;
	cmd[4] = 0x03;
	cmd[5] = 0x01;
	cmd[6] = 0x00;
	cmd[7] = 0x10;
	cmd[8] = 0x05; // infineon?

	cmd[9]= 0xe0; // always e0 (not exactly unique)

//	DbpIntegers(cmd[8],cmd[7],cmd[6]);
	// Now the CRC
	crc = Crc(cmd, 10); // the crc needs to be calculated over 10 bytes
	cmd[10] = crc & 0xff;
	cmd[11] = crc >> 8;

	CodeIso15693AsReader(cmd, sizeof(cmd));
}

static void __attribute__((unused)) BuildReadBlockRequest(BYTE *uid, BYTE blockNumber )
{
	BYTE cmd[13];

	WORD crc;
	// If we set the Option_Flag in this request, the VICC will respond with the secuirty status of the block
	// followed by teh block data
	// one sub-carrier, inventory, 1 slot, fast rate
	cmd[0] = (1 << 6)| (1 << 5) | (1 << 1); // no SELECT bit
	// READ BLOCK command code
	cmd[1] = 0x20;
	// UID may be optionally specified here
	// 64-bit UID
	cmd[2] = 0x32;
	cmd[3]= 0x4b;
	cmd[4] = 0x03;
	cmd[5] = 0x01;
	cmd[6] = 0x00;
	cmd[7] = 0x10;
	cmd[8] = 0x05;
	cmd[9]= 0xe0; // always e0 (not exactly unique)
	// Block number to read
	cmd[10] = blockNumber;//0x00;
	//Now the CRC
	crc = Crc(cmd, 11); // the crc needs to be calculated over 2 bytes
	cmd[11] = crc & 0xff;
	cmd[12] = crc >> 8;

	CodeIso15693AsReader(cmd, sizeof(cmd));
}

static void __attribute__((unused)) BuildReadMultiBlockRequest(BYTE *uid)
{
	BYTE cmd[14];

	WORD crc;
	// If we set the Option_Flag in this request, the VICC will respond with the secuirty status of the block
	// followed by teh block data
	// one sub-carrier, inventory, 1 slot, fast rate
	cmd[0] =  (1 << 5) | (1 << 1); // no SELECT bit
	// READ Multi BLOCK command code
	cmd[1] = 0x23;
	// UID may be optionally specified here
	// 64-bit UID
	cmd[2] = 0x32;
	cmd[3]= 0x4b;
	cmd[4] = 0x03;
	cmd[5] = 0x01;
	cmd[6] = 0x00;
	cmd[7] = 0x10;
	cmd[8] = 0x05;
	cmd[9]= 0xe0; // always e0 (not exactly unique)
	// First Block number to read
	cmd[10] = 0x00;
	// Number of Blocks to read
	cmd[11] = 0x2f; // read quite a few
	//Now the CRC
	crc = Crc(cmd, 12); // the crc needs to be calculated over 2 bytes
	cmd[12] = crc & 0xff;
	cmd[13] = crc >> 8;

	CodeIso15693AsReader(cmd, sizeof(cmd));
}

static void __attribute__((unused)) BuildArbitraryRequest(BYTE *uid,BYTE CmdCode)
{
	BYTE cmd[14];

	WORD crc;
	// If we set the Option_Flag in this request, the VICC will respond with the secuirty status of the block
	// followed by teh block data
	// one sub-carrier, inventory, 1 slot, fast rate
	cmd[0] =   (1 << 5) | (1 << 1); // no SELECT bit
	// READ BLOCK command code
	cmd[1] = CmdCode;
	// UID may be optionally specified here
	// 64-bit UID
	cmd[2] = 0x32;
	cmd[3]= 0x4b;
	cmd[4] = 0x03;
	cmd[5] = 0x01;
	cmd[6] = 0x00;
	cmd[7] = 0x10;
	cmd[8] = 0x05;
	cmd[9]= 0xe0; // always e0 (not exactly unique)
	// Parameter
	cmd[10] = 0x00;
	cmd[11] = 0x0a;

//	cmd[12] = 0x00;
//	cmd[13] = 0x00;	//Now the CRC
	crc = Crc(cmd, 12); // the crc needs to be calculated over 2 bytes
	cmd[12] = crc & 0xff;
	cmd[13] = crc >> 8;

	CodeIso15693AsReader(cmd, sizeof(cmd));
}

static void __attribute__((unused)) BuildArbitraryCustomRequest(BYTE uid[], BYTE CmdCode)
{
	BYTE cmd[14];

	WORD crc;
	// If we set the Option_Flag in this request, the VICC will respond with the secuirty status of the block
	// followed by teh block data
	// one sub-carrier, inventory, 1 slot, fast rate
	cmd[0] =   (1 << 5) | (1 << 1); // no SELECT bit
	// READ BLOCK command code
	cmd[1] = CmdCode;
	// UID may be optionally specified here
	// 64-bit UID
	cmd[2] = 0x32;
	cmd[3]= 0x4b;
	cmd[4] = 0x03;
	cmd[5] = 0x01;
	cmd[6] = 0x00;
	cmd[7] = 0x10;
	cmd[8] = 0x05;
	cmd[9]= 0xe0; // always e0 (not exactly unique)
	// Parameter
	cmd[10] = 0x05; // for custom codes this must be manufcturer code
	cmd[11] = 0x00;

//	cmd[12] = 0x00;
//	cmd[13] = 0x00;	//Now the CRC
	crc = Crc(cmd, 12); // the crc needs to be calculated over 2 bytes
	cmd[12] = crc & 0xff;
	cmd[13] = crc >> 8;

	CodeIso15693AsReader(cmd, sizeof(cmd));
}

/////////////////////////////////////////////////////////////////////////
// Now the VICC>VCD responses when we are simulating a tag
////////////////////////////////////////////////////////////////////

 static void BuildInventoryResponse(void)
{
	BYTE cmd[12];

	WORD crc;
	// one sub-carrier, inventory, 1 slot, fast rate
	// AFI is at bit 5 (1<<4) when doing an INVENTORY
	cmd[0] = 0; //(1 << 2) | (1 << 5) | (1 << 1);
	cmd[1] = 0;
	// 64-bit UID
	cmd[2] = 0x32;
	cmd[3]= 0x4b;
	cmd[4] = 0x03;
	cmd[5] = 0x01;
	cmd[6] = 0x00;
	cmd[7] = 0x10;
	cmd[8] = 0x05;
	cmd[9]= 0xe0;
	//Now the CRC
	crc = Crc(cmd, 10);
	cmd[10] = crc & 0xff;
	cmd[11] = crc >> 8;

	CodeIso15693AsReader(cmd, sizeof(cmd));
}

//-----------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitTo15693Tag(const BYTE *cmd, int len, int *samples, int *wait)
{
    int c;

//    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX);
	if(*wait < 10) { *wait = 10; }

//    for(c = 0; c < *wait;) {
//        if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
//            SSC_TRANSMIT_HOLDING = 0x00;		// For exact timing!
//            c++;
//        }
//        if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
//            volatile DWORD r = SSC_RECEIVE_HOLDING;
//            (void)r;
//        }
//        WDT_HIT();
//    }

    c = 0;
    for(;;) {
        if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
            SSC_TRANSMIT_HOLDING = cmd[c];
            c++;
            if(c >= len) {
                break;
            }
        }
        if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
            volatile DWORD r = SSC_RECEIVE_HOLDING;
            (void)r;
        }
        WDT_HIT();
    }
	*samples = (c + *wait) << 3;
}

//-----------------------------------------------------------------------------
// Transmit the command (to the reader) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitTo15693Reader(const BYTE *cmd, int len, int *samples, int *wait)
{
    int c;

//	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR);	// No requirement to energise my coils
	if(*wait < 10) { *wait = 10; }

    c = 0;
    for(;;) {
        if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
            SSC_TRANSMIT_HOLDING = cmd[c];
            c++;
            if(c >= len) {
                break;
            }
        }
        if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
            volatile DWORD r = SSC_RECEIVE_HOLDING;
            (void)r;
        }
        WDT_HIT();
    }
	*samples = (c + *wait) << 3;
}

static int GetIso15693AnswerFromTag(BYTE *receivedResponse, int maxLen, int *samples, int *elapsed)
{
	int c = 0;
	BYTE *dest = (BYTE *)BigBuf;
	int getNext = 0;

	SBYTE prev = 0;

// NOW READ RESPONSE
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	//spindelay(60);	// greg - experiment to get rid of some of the 0 byte/failed reads
	c = 0;
	getNext = FALSE;
	for(;;) {
		if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
			SSC_TRANSMIT_HOLDING = 0x43;
		}
		if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
			SBYTE b;
			b = (SBYTE)SSC_RECEIVE_HOLDING;

			// The samples are correlations against I and Q versions of the
			// tone that the tag AM-modulates, so every other sample is I,
			// every other is Q. We just want power, so abs(I) + abs(Q) is
			// close to what we want.
			if(getNext) {
				SBYTE r;

				if(b < 0) {
					r = -b;
				} else {
					r = b;
				}
				if(prev < 0) {
					r -= prev;
				} else {
					r += prev;
				}

				dest[c++] = (BYTE)r;

				if(c >= 2000) {
					break;
				}
			} else {
				prev = b;
			}

			getNext = !getNext;
		}
	}

//////////////////////////////////////////
/////////// DEMODULATE ///////////////////
//////////////////////////////////////////

	int i, j;
	int max = 0, maxPos=0;

	int skip = 4;

//	if(GraphTraceLen < 1000) return;	// THIS CHECKS FOR A BUFFER TO SMALL

	// First, correlate for SOF
	for(i = 0; i < 100; i++) {
		int corr = 0;
		for(j = 0; j < arraylen(FrameSOF); j += skip) {
			corr += FrameSOF[j]*dest[i+(j/skip)];
		}
		if(corr > max) {
			max = corr;
			maxPos = i;
		}
	}
//	DbpString("SOF at %d, correlation %d", maxPos,max/(arraylen(FrameSOF)/skip));

	int k = 0; // this will be our return value

	// greg - If correlation is less than 1 then there's little point in continuing
	if ((max/(arraylen(FrameSOF)/skip)) >= 1)
	{

	i = maxPos + arraylen(FrameSOF)/skip;

	BYTE outBuf[20];
	memset(outBuf, 0, sizeof(outBuf));
	BYTE mask = 0x01;
	for(;;) {
		int corr0 = 0, corr1 = 0, corrEOF = 0;
		for(j = 0; j < arraylen(Logic0); j += skip) {
			corr0 += Logic0[j]*dest[i+(j/skip)];
		}
		for(j = 0; j < arraylen(Logic1); j += skip) {
			corr1 += Logic1[j]*dest[i+(j/skip)];
		}
		for(j = 0; j < arraylen(FrameEOF); j += skip) {
			corrEOF += FrameEOF[j]*dest[i+(j/skip)];
		}
		// Even things out by the length of the target waveform.
		corr0 *= 4;
		corr1 *= 4;

		if(corrEOF > corr1 && corrEOF > corr0) {
//			DbpString("EOF at %d", i);
			break;
		} else if(corr1 > corr0) {
			i += arraylen(Logic1)/skip;
			outBuf[k] |= mask;
		} else {
			i += arraylen(Logic0)/skip;
		}
		mask <<= 1;
		if(mask == 0) {
			k++;
			mask = 0x01;
		}
		if((i+(int)arraylen(FrameEOF)) >= 2000) {
			DbpString("ran off end!");
			break;
		}
	}
	if(mask != 0x01) {
		DbpString("error, uneven octet! (discard extra bits!)");
///		DbpString("   mask=%02x", mask);
	}
//	BYTE str1 [8];
//	itoa(k,str1);
//	strcat(str1," octets read");

//	DbpString(  str1);    // DbpString("%d octets", k);

//	for(i = 0; i < k; i+=3) {
//		//DbpString("# %2d: %02x ", i, outBuf[i]);
//		DbpIntegers(outBuf[i],outBuf[i+1],outBuf[i+2]);
//	}

	for(i = 0; i < k; i++) {
		receivedResponse[i] = outBuf[i];
	}
	} // "end if correlation > 0" 	(max/(arraylen(FrameSOF)/skip))
	return k; // return the number of bytes demodulated

///	DbpString("CRC=%04x", Iso15693Crc(outBuf, k-2));

}

// Now the GetISO15693 message from sniffing command
static int GetIso15693AnswerFromSniff(BYTE *receivedResponse, int maxLen, int *samples, int *elapsed)
{
	int c = 0;
	BYTE *dest = (BYTE *)BigBuf;
	int getNext = 0;

	SBYTE prev = 0;

// NOW READ RESPONSE
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	//spindelay(60);	// greg - experiment to get rid of some of the 0 byte/failed reads
	c = 0;
	getNext = FALSE;
	for(;;) {
		if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
			SSC_TRANSMIT_HOLDING = 0x43;
		}
		if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
			SBYTE b;
			b = (SBYTE)SSC_RECEIVE_HOLDING;

			// The samples are correlations against I and Q versions of the
			// tone that the tag AM-modulates, so every other sample is I,
			// every other is Q. We just want power, so abs(I) + abs(Q) is
			// close to what we want.
			if(getNext) {
				SBYTE r;

				if(b < 0) {
					r = -b;
				} else {
					r = b;
				}
				if(prev < 0) {
					r -= prev;
				} else {
					r += prev;
				}

				dest[c++] = (BYTE)r;

				if(c >= 20000) {
					break;
				}
			} else {
				prev = b;
			}

			getNext = !getNext;
		}
	}

//////////////////////////////////////////
/////////// DEMODULATE ///////////////////
//////////////////////////////////////////

	int i, j;
	int max = 0, maxPos=0;

	int skip = 4;

//	if(GraphTraceLen < 1000) return;	// THIS CHECKS FOR A BUFFER TO SMALL

	// First, correlate for SOF
	for(i = 0; i < 19000; i++) {
		int corr = 0;
		for(j = 0; j < arraylen(FrameSOF); j += skip) {
			corr += FrameSOF[j]*dest[i+(j/skip)];
		}
		if(corr > max) {
			max = corr;
			maxPos = i;
		}
	}
//	DbpString("SOF at %d, correlation %d", maxPos,max/(arraylen(FrameSOF)/skip));

	int k = 0; // this will be our return value

	// greg - If correlation is less than 1 then there's little point in continuing
	if ((max/(arraylen(FrameSOF)/skip)) >= 1)	// THIS SHOULD BE 1
	{

	i = maxPos + arraylen(FrameSOF)/skip;

	BYTE outBuf[20];
	memset(outBuf, 0, sizeof(outBuf));
	BYTE mask = 0x01;
	for(;;) {
		int corr0 = 0, corr1 = 0, corrEOF = 0;
		for(j = 0; j < arraylen(Logic0); j += skip) {
			corr0 += Logic0[j]*dest[i+(j/skip)];
		}
		for(j = 0; j < arraylen(Logic1); j += skip) {
			corr1 += Logic1[j]*dest[i+(j/skip)];
		}
		for(j = 0; j < arraylen(FrameEOF); j += skip) {
			corrEOF += FrameEOF[j]*dest[i+(j/skip)];
		}
		// Even things out by the length of the target waveform.
		corr0 *= 4;
		corr1 *= 4;

		if(corrEOF > corr1 && corrEOF > corr0) {
//			DbpString("EOF at %d", i);
			break;
		} else if(corr1 > corr0) {
			i += arraylen(Logic1)/skip;
			outBuf[k] |= mask;
		} else {
			i += arraylen(Logic0)/skip;
		}
		mask <<= 1;
		if(mask == 0) {
			k++;
			mask = 0x01;
		}
		if((i+(int)arraylen(FrameEOF)) >= 2000) {
			DbpString("ran off end!");
			break;
		}
	}
	if(mask != 0x01) {
		DbpString("error, uneven octet! (discard extra bits!)");
///		DbpString("   mask=%02x", mask);
	}
//	BYTE str1 [8];
//	itoa(k,str1);
//	strcat(str1," octets read");

//	DbpString(  str1);    // DbpString("%d octets", k);

//	for(i = 0; i < k; i+=3) {
//		//DbpString("# %2d: %02x ", i, outBuf[i]);
//		DbpIntegers(outBuf[i],outBuf[i+1],outBuf[i+2]);
//	}

	for(i = 0; i < k; i++) {
		receivedResponse[i] = outBuf[i];
	}
	} // "end if correlation > 0" 	(max/(arraylen(FrameSOF)/skip))
	return k; // return the number of bytes demodulated

///	DbpString("CRC=%04x", Iso15693Crc(outBuf, k-2));
}

//-----------------------------------------------------------------------------
// Start to read an ISO 15693 tag. We send an identify request, then wait
// for the response. The response is not demodulated, just left in the buffer
// so that it can be downloaded to a PC and processed there.
//-----------------------------------------------------------------------------
void AcquireRawAdcSamplesIso15693(void)
{
	int c = 0;
	BYTE *dest = (BYTE *)BigBuf;
	int getNext = 0;

	SBYTE prev = 0;

	BuildIdentifyRequest();

	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Give the tags time to energize
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	SpinDelay(100);

	// Now send the command
	FpgaSetupSsc();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX);

	c = 0;
	for(;;) {
		if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
			SSC_TRANSMIT_HOLDING = ToSend[c];
			c++;
			if(c == ToSendMax+3) {
				break;
			}
		}
		if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
			volatile DWORD r = SSC_RECEIVE_HOLDING;
			(void)r;
		}
		WDT_HIT();
	}

	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);

	c = 0;
	getNext = FALSE;
	for(;;) {
		if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
			SSC_TRANSMIT_HOLDING = 0x43;
		}
		if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
			SBYTE b;
			b = (SBYTE)SSC_RECEIVE_HOLDING;

			// The samples are correlations against I and Q versions of the
			// tone that the tag AM-modulates, so every other sample is I,
			// every other is Q. We just want power, so abs(I) + abs(Q) is
			// close to what we want.
			if(getNext) {
				SBYTE r;

				if(b < 0) {
					r = -b;
				} else {
					r = b;
				}
				if(prev < 0) {
					r -= prev;
				} else {
					r += prev;
				}

				dest[c++] = (BYTE)r;

				if(c >= 2000) {
					break;
				}
			} else {
				prev = b;
			}

			getNext = !getNext;
		}
	}
}

//-----------------------------------------------------------------------------
// Simulate an ISO15693 reader, perform anti-collision and then attempt to read a sector
// all demodulation performed in arm rather than host. - greg
//-----------------------------------------------------------------------------
void ReaderIso15693(DWORD parameter)
{
	LED_A_ON();
	LED_B_ON();
	LED_C_OFF();
	LED_D_OFF();

//DbpString(parameter);

	BYTE *receivedAnswer0 = (((BYTE *)BigBuf) + 3560); // allow 100 bytes per reponse (way too much)
	BYTE *receivedAnswer1 = (((BYTE *)BigBuf) + 3660); //
	BYTE *receivedAnswer2 = (((BYTE *)BigBuf) + 3760);
	BYTE *receivedAnswer3 = (((BYTE *)BigBuf) + 3860);
	//BYTE *TagUID= (((BYTE *)BigBuf) + 3960);		// where we hold the uid for hi15reader
//	int responseLen0 = 0;
	int responseLen1 = 0;
	int responseLen2 = 0;
	int responseLen3 = 0;

	// Blank arrays
	int j;
	for(j = 0; j < 100; j++) {
		receivedAnswer3[j] = 0;
		receivedAnswer2[j] =0;
		receivedAnswer1[j] = 0;
		receivedAnswer0[j] = 0;
	}

	// Setup SSC
	FpgaSetupSsc();

	// Start from off (no field generated)
    	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    	SpinDelay(200);

	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

	// Give the tags time to energize
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	SpinDelay(200);

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();
	LED_D_OFF();

	int samples = 0;
	int tsamples = 0;
	int wait = 0;
	int elapsed = 0;

	// FIRST WE RUN AN INVENTORY TO GET THE TAG UID
	// THIS MEANS WE CAN PRE-BUILD REQUESTS TO SAVE CPU TIME
 BYTE TagUID[7];		// where we hold the uid for hi15reader

//	BuildIdentifyRequest();
//	//TransmitTo15693Tag(ToSend,ToSendMax+3,&tsamples, &wait);
//	TransmitTo15693Tag(ToSend,ToSendMax,&tsamples, &wait);	// No longer ToSendMax+3
//	// Now wait for a response
//	responseLen0 = GetIso15693AnswerFromTag(receivedAnswer0, 100, &samples, &elapsed) ;
//	if (responseLen0 >=12) // we should do a better check than this
//	{
//		// really we should check it is a valid mesg
//		// but for now just grab what we think is the uid
//		TagUID[0] = receivedAnswer0[2];
//		TagUID[1] = receivedAnswer0[3];
//		TagUID[2] = receivedAnswer0[4];
//		TagUID[3] = receivedAnswer0[5];
//		TagUID[4] = receivedAnswer0[6];
//		TagUID[5] = receivedAnswer0[7];
//		TagUID[6] = receivedAnswer0[8]; // IC Manufacturer code
//	DbpIntegers(TagUID[6],TagUID[5],TagUID[4]);
//}

	// Now send the IDENTIFY command
	BuildIdentifyRequest();
	//TransmitTo15693Tag(ToSend,ToSendMax+3,&tsamples, &wait);
	TransmitTo15693Tag(ToSend,ToSendMax,&tsamples, &wait);	// No longer ToSendMax+3
	// Now wait for a response
	responseLen1 = GetIso15693AnswerFromTag(receivedAnswer1, 100, &samples, &elapsed) ;

	if (responseLen1 >=12) // we should do a better check than this
	{

		TagUID[0] = receivedAnswer1[2];
		TagUID[1] = receivedAnswer1[3];
		TagUID[2] = receivedAnswer1[4];
		TagUID[3] = receivedAnswer1[5];
		TagUID[4] = receivedAnswer1[6];
		TagUID[5] = receivedAnswer1[7];
		TagUID[6] = receivedAnswer1[8]; // IC Manufacturer code

		// Now send the SELECT command
		BuildSelectRequest(TagUID);
		TransmitTo15693Tag(ToSend,ToSendMax,&tsamples, &wait);	// No longer ToSendMax+3
		// Now wait for a response
		responseLen2 = GetIso15693AnswerFromTag(receivedAnswer2, 100, &samples, &elapsed);

		// Now send the MULTI READ command
//		BuildArbitraryRequest(*TagUID,parameter);
		BuildArbitraryCustomRequest(TagUID,parameter);
//		BuildReadBlockRequest(*TagUID,parameter);
//		BuildSysInfoRequest(*TagUID);
		//TransmitTo15693Tag(ToSend,ToSendMax+3,&tsamples, &wait);
		TransmitTo15693Tag(ToSend,ToSendMax,&tsamples, &wait);	// No longer ToSendMax+3
		// Now wait for a response
		responseLen3 = GetIso15693AnswerFromTag(receivedAnswer3, 100, &samples, &elapsed) ;

	}

	char str1 [4];
	//char str2 [200];
	int i;

	itoa(responseLen1,str1);
	strcat(str1," octets read from IDENTIFY request");
	DbpString(str1);
	for(i = 0; i < responseLen1; i+=3) {
		DbpIntegers(receivedAnswer1[i],receivedAnswer1[i+1],receivedAnswer1[i+2]);
	}

	itoa(responseLen2,str1);
	strcat(str1," octets read from SELECT request");
	DbpString(str1);
	for(i = 0; i < responseLen2; i+=3) {
		DbpIntegers(receivedAnswer2[i],receivedAnswer2[i+1],receivedAnswer2[i+2]);
	}

	itoa(responseLen3,str1);
	strcat(str1," octets read from XXX request");
	DbpString(str1);
	for(i = 0; i < responseLen3; i+=3) {
		DbpIntegers(receivedAnswer3[i],receivedAnswer3[i+1],receivedAnswer3[i+2]);
	}

//	str2[0]=0;
//	for(i = 0; i < responseLen3; i++) {
//		itoa(str1,receivedAnswer3[i]);
//		strcat(str2,str1);
//	}
//	DbpString(str2);

	LED_A_OFF();
	LED_B_OFF();
	LED_C_OFF();
	LED_D_OFF();
}

//-----------------------------------------------------------------------------
// Simulate an ISO15693 TAG, perform anti-collision and then print any reader commands
// all demodulation performed in arm rather than host. - greg
//-----------------------------------------------------------------------------
void SimTagIso15693(DWORD parameter)
{
	LED_A_ON();
	LED_B_ON();
	LED_C_OFF();
	LED_D_OFF();

//DbpString(parameter);

	BYTE *receivedAnswer0 = (((BYTE *)BigBuf) + 3560); // allow 100 bytes per reponse (way too much)
	BYTE *receivedAnswer1 = (((BYTE *)BigBuf) + 3660); //
	BYTE *receivedAnswer2 = (((BYTE *)BigBuf) + 3760);
	BYTE *receivedAnswer3 = (((BYTE *)BigBuf) + 3860);
	//BYTE *TagUID= (((BYTE *)BigBuf) + 3960);		// where we hold the uid for hi15reader
//	int responseLen0 = 0;
	int responseLen1 = 0;
//	int responseLen2 = 0;
//	int responseLen3 = 0;

	// Blank arrays
	int j;
	for(j = 0; j < 100; j++) {
		receivedAnswer3[j] = 0;
		receivedAnswer2[j] =0;
		receivedAnswer1[j] = 0;
		receivedAnswer0[j] = 0;
	}

	// Setup SSC
	FpgaSetupSsc();

	// Start from off (no field generated)
    	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    	SpinDelay(200);

	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

	// Give the tags time to energize
//	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);	// NO GOOD FOR SIM TAG!!!!
	SpinDelay(200);

	LED_A_OFF();
	LED_B_OFF();
	LED_C_ON();
	LED_D_OFF();

	int samples = 0;
	int tsamples = 0;
	int wait = 0;
	int elapsed = 0;

	// FIRST WE RUN AN INVENTORY TO GET THE TAG UID
	// THIS MEANS WE CAN PRE-BUILD REQUESTS TO SAVE CPU TIME
	// BYTE TagUID[7];		// where we hold the uid for hi15reader

	// Now send the IDENTIFY command
	//	BuildIdentifyRequest();
	//	TransmitTo15693Tag(ToSend,ToSendMax,&tsamples, &wait);	// No longer ToSendMax+3

	// Now wait for a command from the reader
	responseLen1=0;
	//	while(responseLen1=0) {
	//		if(BUTTON_PRESS()) break;
		responseLen1 = GetIso15693AnswerFromSniff(receivedAnswer1, 100, &samples, &elapsed) ;
	//		}

	if (responseLen1 >=1) // we should do a better check than this
	{
		// Build a suitable reponse to the reader INVENTORY cocmmand
		BuildInventoryResponse();
		TransmitTo15693Reader(ToSend,ToSendMax,&tsamples, &wait);

		// Now wait for a command from the reader
//		responseLen2 = GetIso15693AnswerFromTag(receivedAnswer2, 100, &samples, &elapsed);

		// Now wait for a command from the reader
//		responseLen3 = GetIso15693AnswerFromTag(receivedAnswer3, 100, &samples, &elapsed) ;

	}

	char str1 [4];
	//char str2 [200];
	int i;

	itoa(responseLen1,str1);
	strcat(str1," octets read from reader command");
	DbpString(str1);
	for(i = 0; i < responseLen1; i+=3) {
		DbpIntegers(receivedAnswer1[i],receivedAnswer1[i+1],receivedAnswer1[i+2]);
	}

//	itoa(responseLen2,str1);
//	strcat(str1," octets read from SELECT request");
//	DbpString(str1);
//	for(i = 0; i < responseLen2; i+=3) {
//		DbpIntegers(receivedAnswer2[i],receivedAnswer2[i+1],receivedAnswer2[i+2]);
//	}
//
//	itoa(responseLen3,str1);
//	strcat(str1," octets read from XXX request");
//	DbpString(str1);
//	for(i = 0; i < responseLen3; i+=3) {
//		DbpIntegers(receivedAnswer3[i],receivedAnswer3[i+1],receivedAnswer3[i+2]);
//	}

//	str2[0]=0;
//	for(i = 0; i < responseLen3; i++) {
//		itoa(str1,receivedAnswer3[i]);
//		strcat(str2,str1);
//	}
//	DbpString(str2);

	LED_A_OFF();
	LED_B_OFF();
	LED_C_OFF();
	LED_D_OFF();
}
