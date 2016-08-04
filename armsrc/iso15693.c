//-----------------------------------------------------------------------------
// Jonathan Westhues, split Nov 2006
// Modified by Greg Jones, Jan 2009
// Modified by Adrian Dabrowski "atrox", Mar-Sept 2010,Oct 2011
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 15693. This includes both the reader software and
// the `fake tag' modes, but at the moment I've implemented only the reader
// stuff, and that barely.
// Modified to perform modulation onboard in arm rather than on PC
// Also added additional reader commands (SELECT, READ etc.)
//-----------------------------------------------------------------------------
// The ISO 15693 describes two transmission modes from reader to tag, and 4 
// transmission modes from tag to reader. As of Mar 2010 this code only 
// supports one of each: "1of4" mode from reader to tag, and the highspeed 
// variant with one subcarrier from card to reader.
// As long, as the card fully support ISO 15693 this is no problem, since the 
// reader chooses both data rates, but some non-standard tags do not. Further for 
// the simulation to work, we will need to support all data rates.
//
// VCD (reader) -> VICC (tag)
// 1 out of 256:
// 	data rate: 1,66 kbit/s (fc/8192) 
// 	used for long range
// 1 out of 4:
// 	data rate: 26,48 kbit/s (fc/512)
//	used for short range, high speed
// 
// VICC (tag) -> VCD (reader)
// Modulation:
//		ASK / one subcarrier (423,75 khz)
//		FSK / two subcarriers (423,75 khz && 484,28 khz)
// Data Rates / Modes:
// 	low ASK: 6,62 kbit/s
// 	low FSK: 6.67 kbit/s
// 	high ASK: 26,48 kbit/s
// 	high FSK: 26,69 kbit/s
//-----------------------------------------------------------------------------
// added "1 out of 256" mode (for VCD->PICC) - atrox 20100911


// Random Remarks:
// *) UID is always used "transmission order" (LSB), which is reverse to display order

// TODO / BUGS / ISSUES:
// *) writing to tags takes longer: we miss the answer from the tag in most cases
//    -> tweak the read-timeout times
// *) signal decoding from the card is still a bit shaky. 
// *) signal decoding is unable to detect collissions.
// *) add anti-collission support for inventory-commands 
// *) read security status of a block
// *) sniffing and simulation do only support one transmission mode. need to support 
//		all 8 transmission combinations
//	*) remove or refactor code under "depricated"
// *) document all the functions


#include "proxmark3.h"
#include "util.h"
#include "apps.h"
#include "string.h"
#include "iso15693tools.h"
#include "cmd.h"

///////////////////////////////////////////////////////////////////////
// ISO 15693 Part 2 - Air Interface
// This section basicly contains transmission and receiving of bits
///////////////////////////////////////////////////////////////////////

#define FrameSOF              Iso15693FrameSOF
#define Logic0                Iso15693Logic0
#define Logic1                Iso15693Logic1
#define FrameEOF              Iso15693FrameEOF

#define Crc(data,datalen)     Iso15693Crc(data,datalen)
#define AddCrc(data,datalen)  Iso15693AddCrc(data,datalen)
#define sprintUID(target,uid)	Iso15693sprintUID(target,uid)

int DEBUG = 0;


// ---------------------------
// Signal Processing 
// ---------------------------

// prepare data using "1 out of 4" code for later transmission
// resulting data rate is 26,48 kbit/s (fc/512)
// cmd ... data
// n ... length of data
static void CodeIso15693AsReader(uint8_t *cmd, int n)
{
	int i, j;

	ToSendReset();

	// Give it a bit of slack at the beginning
	for(i = 0; i < 24; i++)
		ToSendStuffBit(1);

	// SOF for 1of4
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
	// EOF
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(0);
	ToSendStuffBit(1);

	// And slack at the end, too.
	for(i = 0; i < 24; i++)
		ToSendStuffBit(1);
}

// encode data using "1 out of 256" sheme
// data rate is 1,66 kbit/s (fc/8192) 
// is designed for more robust communication over longer distances
static void CodeIso15693AsReader256(uint8_t *cmd, int n)
{
	int i, j;

	ToSendReset();

	// Give it a bit of slack at the beginning
	for(i = 0; i < 24; i++)
		ToSendStuffBit(1);

	// SOF for 1of256
	ToSendStuffBit(0);
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(0);
	
	for(i = 0; i < n; i++) {
		for (j = 0; j <= 255; j++) {
			if (cmd[i] == j) {
				ToSendStuffBit(1);
				ToSendStuffBit(0);
			} else {
				ToSendStuffBit(1);
				ToSendStuffBit(1);
			}			
		}	
	}
	// EOF
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(0);
	ToSendStuffBit(1);

	// And slack at the end, too.
	for(i = 0; i < 24; i++)
		ToSendStuffBit(1);
}


// Transmit the command (to the tag) that was placed in ToSend[].
static void TransmitTo15693Tag(const uint8_t *cmd, int len, int *samples, int *wait)
{
    int c;
	volatile uint32_t r;
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX);
	if(*wait < 10) { *wait = 10; }

//    for(c = 0; c < *wait;) {
//        if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
//            AT91C_BASE_SSC->SSC_THR = 0x00;		// For exact timing!
//            ++c;
//        }
//        if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
//            r = AT91C_BASE_SSC->SSC_RHR;
//            (void)r;
//        }
//        WDT_HIT();
//    }

    c = 0;
    for(;;) {
        if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = cmd[c];
            if( ++c >= len) break;
        }
        if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            r = AT91C_BASE_SSC->SSC_RHR;
            (void)r;
        }
        WDT_HIT();
    }
	*samples = (c + *wait) << 3;
}

//-----------------------------------------------------------------------------
// Transmit the command (to the reader) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitTo15693Reader(const uint8_t *cmd, int len, int *samples, int *wait)
{
    int c = 0;
	volatile uint32_t r;
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR|FPGA_HF_SIMULATOR_MODULATE_424K);
	if(*wait < 10) { *wait = 10; }

    for(;;) {
        if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = cmd[c];
            if( ++c >= len) break;
        }
        if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            r = AT91C_BASE_SSC->SSC_RHR;
            (void)r;
        }
        WDT_HIT();
    }
	*samples = (c + *wait) << 3;
}


// Read from Tag
// Parameters:
//		receivedResponse
//		maxLen
//		samples
//		elapsed
// returns: 
//		number of decoded bytes
static int GetIso15693AnswerFromTag(uint8_t *receivedResponse, int maxLen, int *samples, int *elapsed)
{
	uint8_t *dest = BigBuf_get_addr();

	int c = 0, getNext = FALSE;
	int8_t prev = 0;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	SpinDelay(100);	// greg - experiment to get rid of some of the 0 byte/failed reads

	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))
			AT91C_BASE_SSC->SSC_THR = 0x43;

		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			int8_t b;
			b = (int8_t)AT91C_BASE_SSC->SSC_RHR;

			// The samples are correlations against I and Q versions of the
			// tone that the tag AM-modulates, so every other sample is I,
			// every other is Q. We just want power, so abs(I) + abs(Q) is
			// close to what we want.
			// iceman 2016, amplitude sqrt(abs(i) + abs(q))
			if(getNext) {
				dest[c++] = (uint8_t)ABS(b) + ABS(prev);

				if(c >= 2000)
					break;
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
	int max = 0, maxPos=0, skip = 4;
	int k = 0; // this will be our return value
	
	//	if(GraphTraceLen < 1000) return;	// THIS CHECKS FOR A BUFFER TO SMALL

	// First, correlate for SOF
	for(i = 0; i < 100; i++) {
		int corr = 0;
		for(j = 0; j < ARRAYLEN(FrameSOF); j += skip) {
			corr += FrameSOF[j] * dest[i+(j/skip)];
		}
		if(corr > max) {
			max = corr;
			maxPos = i;
		}
	}
	//	DbpString("SOF at %d, correlation %d", maxPos,max/(ARRAYLEN(FrameSOF)/skip));

	// greg - If correlation is less than 1 then there's little point in continuing
	if ((max/(ARRAYLEN(FrameSOF)/skip)) >= 1)
	{
		i = maxPos + ARRAYLEN(FrameSOF) / skip;
	
		uint8_t outBuf[20];
		memset(outBuf, 0, sizeof(outBuf));
		uint8_t mask = 0x01;
		for(;;) {
			int corr0 = 0, corr1 = 0, corrEOF = 0;
			for(j = 0; j < ARRAYLEN(Logic0); j += skip) {
				corr0 += Logic0[j] * dest[i+(j/skip)];
			}
			for(j = 0; j < ARRAYLEN(Logic1); j += skip) {
				corr1 += Logic1[j] * dest[i+(j/skip)];
			}
			for(j = 0; j < ARRAYLEN(FrameEOF); j += skip) {
				corrEOF += FrameEOF[j] * dest[i+(j/skip)];
			}
			// Even things out by the length of the target waveform.
			corr0 *= 4;
			corr1 *= 4;
	
			if(corrEOF > corr1 && corrEOF > corr0) {
	//			DbpString("EOF at %d", i);
				break;
			} else if(corr1 > corr0) {
				i += ARRAYLEN(Logic1)/skip;
				outBuf[k] |= mask;
			} else {
				i += ARRAYLEN(Logic0)/skip;
			}
			mask <<= 1;
			if(mask == 0) {
				k++;
				mask = 0x01;
			}
			if( ( i + (int)ARRAYLEN(FrameEOF)) >= 2000) {
				DbpString("ran off end!");
				break;
			}
		}
		if(mask != 0x01) { // this happens, when we miss the EOF
			// TODO: for some reason this happens quite often
			if (DEBUG) Dbprintf("error, uneven octet! (extra bits!) mask=%02x", mask);
			if (mask < 0x08) k--; // discard the last uneven octet;
			// 0x08 is an assumption - but works quite often
		}
	//	uint8_t str1 [8];
	//	itoa(k,str1);
	//	strncat(str1," octets read",8);
	
	//	DbpString(  str1);    // DbpString("%d octets", k);
	
	//	for(i = 0; i < k; i+=3) {
	//		//DbpString("# %2d: %02x ", i, outBuf[i]);
	//		DbpIntegers(outBuf[i],outBuf[i+1],outBuf[i+2]);
	//	}
	
		for(i = 0; i < k; i++) {
			receivedResponse[i] = outBuf[i];
		}
	} // "end if correlation > 0" 	(max/(ARRAYLEN(FrameSOF)/skip))
	return k; // return the number of bytes demodulated
}


// Now the GetISO15693 message from sniffing command
static int GetIso15693AnswerFromSniff(uint8_t *receivedResponse, int maxLen, int *samples, int *elapsed)
{
	uint8_t *dest = BigBuf_get_addr();

	int c = 0, getNext = FALSE;
	int8_t prev = 0;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	SpinDelay(100);	// greg - experiment to get rid of some of the 0 byte/failed reads

	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))
			AT91C_BASE_SSC->SSC_THR = 0x43;

		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			int8_t b = (int8_t)AT91C_BASE_SSC->SSC_RHR;

			// The samples are correlations against I and Q versions of the
			// tone that the tag AM-modulates, so every other sample is I,
			// every other is Q. We just want power, so abs(I) + abs(Q) is
			// close to what we want.
			if(getNext) {
				dest[c++] = (uint8_t)ABS(b) + ABS(prev);

				if(c >= 20000)
					break;
			} else {
				prev = b;
			}
			getNext = !getNext;
		}
	}

	//////////////////////////////////////////
	/////////// DEMODULATE ///////////////////
	//////////////////////////////////////////

	int i, j, max = 0, maxPos=0, skip = 4;

	// First, correlate for SOF
	for(i = 0; i < 19000; i++) {
		int corr = 0;
		for(j = 0; j < ARRAYLEN(FrameSOF); j += skip) {
			corr += FrameSOF[j]*dest[i+(j/skip)];
		}
		if(corr > max) {
			max = corr;
			maxPos = i;
		}
	}
//	DbpString("SOF at %d, correlation %d", maxPos,max/(ARRAYLEN(FrameSOF)/skip));

	int k = 0; // this will be our return value

	// greg - If correlation is less than 1 then there's little point in continuing
	if ((max/(ARRAYLEN(FrameSOF)/skip)) >= 1)	// THIS SHOULD BE 1
	{
	
		i = maxPos + ARRAYLEN(FrameSOF)/skip;
	
		uint8_t outBuf[20];
		memset(outBuf, 0, sizeof(outBuf));
		uint8_t mask = 0x01;
		for(;;) {
			int corr0 = 0, corr1 = 0, corrEOF = 0;
			for(j = 0; j < ARRAYLEN(Logic0); j += skip) {
				corr0 += Logic0[j]*dest[i+(j/skip)];
			}
			for(j = 0; j < ARRAYLEN(Logic1); j += skip) {
				corr1 += Logic1[j]*dest[i+(j/skip)];
			}
			for(j = 0; j < ARRAYLEN(FrameEOF); j += skip) {
				corrEOF += FrameEOF[j]*dest[i+(j/skip)];
			}
			// Even things out by the length of the target waveform.
			corr0 *= 4;
			corr1 *= 4;
	
			if(corrEOF > corr1 && corrEOF > corr0) {
	//			DbpString("EOF at %d", i);
				break;
			} else if(corr1 > corr0) {
				i += ARRAYLEN(Logic1)/skip;
				outBuf[k] |= mask;
			} else {
				i += ARRAYLEN(Logic0)/skip;
			}
			mask <<= 1;
			if(mask == 0) {
				k++;
				mask = 0x01;
			}
			if((i+(int)ARRAYLEN(FrameEOF)) >= 2000) {
				DbpString("ran off end!");
				break;
			}
		}
		if(mask != 0x01) {
			DbpString("sniff: error, uneven octet! (discard extra bits!)");
	//		DbpString("   mask=%02x", mask);
		}
	//	uint8_t str1 [8];
	//	itoa(k,str1);
	//	strncat(str1," octets read",8);
	
	//	DbpString(  str1);    // DbpString("%d octets", k);
	
	//	for(i = 0; i < k; i+=3) {
	//		//DbpString("# %2d: %02x ", i, outBuf[i]);
	//		DbpIntegers(outBuf[i],outBuf[i+1],outBuf[i+2]);
	//	}
	
		for(i = 0; i < k; i++) {
			receivedResponse[i] = outBuf[i];
		}
	} // "end if correlation > 0" 	(max/(ARRAYLEN(FrameSOF)/skip))
	return k; // return the number of bytes demodulated
}


static void BuildIdentifyRequest(void);
//-----------------------------------------------------------------------------
// Start to read an ISO 15693 tag. We send an identify request, then wait
// for the response. The response is not demodulated, just left in the buffer
// so that it can be downloaded to a PC and processed there.
//-----------------------------------------------------------------------------
void AcquireRawAdcSamplesIso15693(void)
{
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

	int c = 0, getNext = FALSE;
	int8_t prev = 0;
	volatile uint32_t r;

	uint8_t *dest = BigBuf_get_addr();
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
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = ToSend[c];
			if( ++c == ToSendMax+3) break;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			r = AT91C_BASE_SSC->SSC_RHR;
			(void)r;
		}
		WDT_HIT();
	}

	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);

	c = 0;
	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))
			AT91C_BASE_SSC->SSC_THR = 0x43;
		
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {

			int8_t b = (int8_t)AT91C_BASE_SSC->SSC_RHR;

			// The samples are correlations against I and Q versions of the
			// tone that the tag AM-modulates, so every other sample is I,
			// every other is Q. We just want power, so abs(I) + abs(Q) is
			// close to what we want.
			if(getNext) {
				
				dest[c++] = (uint8_t)(ABS(b) + ABS(prev));

				if(c >= 2000) break;
				
			} else {
				prev = b;
			}
			getNext = !getNext;
		}
	}
}


void RecordRawAdcSamplesIso15693(void)
{
	uint8_t *dest = BigBuf_get_addr();

	int c = 0, getNext = FALSE;
	int8_t prev = 0;

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	// Setup SSC
	FpgaSetupSsc();

	// Start from off (no field generated)
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelay(200);

	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	SpinDelay(100);

	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);

	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0x43;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			int8_t b;
			b = (int8_t)AT91C_BASE_SSC->SSC_RHR;

			// The samples are correlations against I and Q versions of the
			// tone that the tag AM-modulates, so every other sample is I,
			// every other is Q. We just want power, so abs(I) + abs(Q) is
			// close to what we want.
			if(getNext) {
				dest[c++] = (uint8_t) ABS(b) + ABS(prev);

				if(c >= 7000)
					break;
			} else {
				prev = b;
			}

			getNext = !getNext;
			WDT_HIT();
		}
	}
	Dbprintf("fin record");
}


// Initialize the proxmark as iso15k reader 
// (this might produces glitches that confuse some tags
void Iso15693InitReader() {
	LED_A_ON();
	LED_B_ON();
	LED_C_OFF();
	LED_D_OFF();
	
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	// Setup SSC
	// FpgaSetupSsc();

	// Start from off (no field generated)
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelay(10);

	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

	// Give the tags time to energize
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	SpinDelay(250);

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();
	LED_D_OFF();
}

///////////////////////////////////////////////////////////////////////
// ISO 15693 Part 3 - Air Interface
// This section basicly contains transmission and receiving of bits
///////////////////////////////////////////////////////////////////////

// Encode (into the ToSend buffers) an identify request, which is the first
// thing that you must send to a tag to get a response.
static void BuildIdentifyRequest(void)
{
	uint8_t cmd[5] = {0,1,0,0,0};
	uint16_t crc;
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

// uid is in transmission order (which is reverse of display order)
static void BuildReadBlockRequest(uint8_t *uid, uint8_t blockNumber )
{
	uint8_t cmd[13] = {0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint16_t crc;
	// If we set the Option_Flag in this request, the VICC will respond with the secuirty status of the block
	// followed by teh block data
	// one sub-carrier, inventory, 1 slot, fast rate
	cmd[0] = (1 << 6)| (1 << 5) | (1 << 1); // no SELECT bit, ADDR bit, OPTION bit
	// READ BLOCK command code
	cmd[1] = 0x20;
	// UID may be optionally specified here
	// 64-bit UID
	cmd[2] = uid[0];
	cmd[3] = uid[1];
	cmd[4] = uid[2];
	cmd[5] = uid[3];
	cmd[6] = uid[4];
	cmd[7] = uid[5];
	cmd[8] = uid[6];
	cmd[9] = uid[7]; // 0xe0; // always e0 (not exactly unique)
	// Block number to read
	cmd[10] = blockNumber;//0x00;
	//Now the CRC
	crc = Crc(cmd, 11); // the crc needs to be calculated over 12 bytes
	cmd[11] = crc & 0xff;
	cmd[12] = crc >> 8;

	CodeIso15693AsReader(cmd, sizeof(cmd));
}

// Now the VICC>VCD responses when we are simulating a tag
 static void BuildInventoryResponse( uint8_t *uid)
{
	uint8_t cmd[12] = {0,0,0,0,0,0,0,0,0,0,0,0};
	uint16_t crc;
	// one sub-carrier, inventory, 1 slot, fast rate
	// AFI is at bit 5 (1<<4) when doing an INVENTORY
    //(1 << 2) | (1 << 5) | (1 << 1);
	cmd[0] = 0; // 
	cmd[1] = 0; // DSFID (data storage format identifier).  0x00 = not supported
	// 64-bit UID
	cmd[2] = uid[7]; //0x32;
	cmd[3] = uid[6]; //0x4b;
	cmd[4] = uid[5]; //0x03;
	cmd[5] = uid[4]; //0x01;
	cmd[6] = uid[3]; //0x00;
	cmd[7] = uid[2]; //0x10;
	cmd[8] = uid[1]; //0x05;
	cmd[9] = uid[0]; //0xe0;
	//Now the CRC
	crc = Crc(cmd, 10);
	cmd[10] = crc & 0xff;
	cmd[11] = crc >> 8;

	CodeIso15693AsReader(cmd, sizeof(cmd));
}

// Universal Method for sending to and recv bytes from a tag
// 	init ... should we initialize the reader?
// 	speed ... 0 low speed, 1 hi speed 
// 	**recv will return you a pointer to the received data
// 	If you do not need the answer use NULL for *recv[] 
//	return: lenght of received data
int SendDataTag(uint8_t *send, int sendlen, int init, int speed, uint8_t **recv) {

	int samples = 0, tsamples = 0;
	int wait = 0, elapsed = 0;
	int answerLen = 0;
	
	LED_A_ON(); LED_B_ON();
	
	LED_C_OFF(); LED_D_OFF();
	
	if (init) Iso15693InitReader();

	// answer is 100bytes long?
	uint8_t *answer = BigBuf_malloc(100);
	if (recv != NULL) memset(answer, 0, 100);

	if (!speed) {
		// low speed (1 out of 256)
		CodeIso15693AsReader256(send, sendlen);
	} else {
		// high speed (1 out of 4)
		CodeIso15693AsReader(send, sendlen);
	}
	
	LED_A_ON();
	LED_B_OFF();
	
	TransmitTo15693Tag(ToSend, ToSendMax, &tsamples, &wait);	
	// Now wait for a response
	if (recv!=NULL) {
		LED_A_OFF();
		LED_B_ON();
		answerLen = GetIso15693AnswerFromTag(answer, 100, &samples, &elapsed) ;	
		*recv = answer;
	}

	LEDsoff();
	return answerLen;
}


// --------------------------------------------------------------------
// Debug Functions 
// --------------------------------------------------------------------

// Decodes a message from a tag and displays its metadata and content
#define DBD15STATLEN 48
void DbdecodeIso15693Answer(int len, uint8_t *d) {
	char status[DBD15STATLEN+1] = {0};
	uint16_t crc;

	if (len > 3) {
		if (d[0] & ( 1 << 3 )) 
			strncat(status, "ProtExt ", DBD15STATLEN);
		if (d[0] & 1) { 
			// error
			strncat(status, "Error ", DBD15STATLEN);
			switch (d[1]) {
				case 0x01: 
					strncat(status, "01:notSupp", DBD15STATLEN);
					break;
				case 0x02: 
					strncat(status, "02:notRecog", DBD15STATLEN);
					break;
				case 0x03: 
					strncat(status, "03:optNotSupp", DBD15STATLEN);
					break;
				case 0x0f: 
					strncat(status, "0f:noInfo", DBD15STATLEN);
					break;
				case 0x10: 
					strncat(status, "10:dontExist", DBD15STATLEN);
					break;
				case 0x11: 
					strncat(status, "11:lockAgain", DBD15STATLEN);
					break;
				case 0x12: 
					strncat(status, "12:locked", DBD15STATLEN);
					break;
				case 0x13: 
					strncat(status, "13:progErr", DBD15STATLEN);
					break;
				case 0x14: 
					strncat(status, "14:lockErr", DBD15STATLEN);
					break;
				default:
					strncat(status, "unknownErr", DBD15STATLEN);
			}
			strncat(status ," " ,DBD15STATLEN);
		} else {
			strncat(status ,"NoErr ", DBD15STATLEN);
		}
			
		crc = Crc(d,len-2);
		if ( (( crc & 0xff ) == d[len-2]) && (( crc >> 8 ) == d[len-1]) ) 
			strncat(status, "CrcOK", DBD15STATLEN);
		else
			strncat(status, "CrcFail!", DBD15STATLEN); 

		Dbprintf("%s", status);
	}
}

///////////////////////////////////////////////////////////////////////
// Functions called via USB/Client
///////////////////////////////////////////////////////////////////////

void SetDebugIso15693(uint32_t debug) {
	DEBUG = debug;
	Dbprintf("Iso15693 Debug is now %s", DEBUG ? "on" : "off");
	return;
}

//-----------------------------------------------------------------------------
// Simulate an ISO15693 reader, perform anti-collision and then attempt to read a sector
// all demodulation performed in arm rather than host. - greg
//-----------------------------------------------------------------------------
void ReaderIso15693(uint32_t parameter)
{
	LED_A_ON();
	LED_B_ON();
	LED_C_OFF();
	LED_D_OFF();

	int answerLen1 = 0;
	int answerLen2 = 0;
	int answerLen3 = 0;
	int i = 0;
	int samples = 0;
	int tsamples = 0;
	int wait = 0;
	int elapsed = 0;
	uint8_t TagUID[8] = {0x00};

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

	uint8_t *answer1 = BigBuf_malloc(100);
	uint8_t *answer2 = BigBuf_malloc(100);
	uint8_t *answer3 = BigBuf_malloc(100);
	// Blank arrays
	memset(answer1, 0x00, 100);
	memset(answer2, 0x00, 100);
	memset(answer3, 0x00, 100);

	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	// Setup SSC
	FpgaSetupSsc();

	// Start from off (no field generated)
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelay(200);

	// Give the tags time to energize
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	SpinDelay(200);

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();
	LED_D_OFF();

	// FIRST WE RUN AN INVENTORY TO GET THE TAG UID
	// THIS MEANS WE CAN PRE-BUILD REQUESTS TO SAVE CPU TIME

	// Now send the IDENTIFY command
	BuildIdentifyRequest();
	
	TransmitTo15693Tag(ToSend,ToSendMax,&tsamples, &wait);
	
	// Now wait for a response
	answerLen1 = GetIso15693AnswerFromTag(answer1, 100, &samples, &elapsed) ;

	if (answerLen1 >= 12) // we should do a better check than this
	{
		TagUID[0] = answer1[2];
		TagUID[1] = answer1[3];
		TagUID[2] = answer1[4];
		TagUID[3] = answer1[5];
		TagUID[4] = answer1[6];
		TagUID[5] = answer1[7];
		TagUID[6] = answer1[8]; // IC Manufacturer code
		TagUID[7] = answer1[9]; // always E0

	}

	Dbprintf("%d octets read from IDENTIFY request:", answerLen1);
	DbdecodeIso15693Answer(answerLen1, answer1);
	Dbhexdump(answerLen1, answer1, true);

	// UID is reverse
	if (answerLen1>=12) 
		Dbprintf("UID = %02hX%02hX%02hX%02hX%02hX%02hX%02hX%02hX",
			TagUID[7],TagUID[6],TagUID[5],TagUID[4],
			TagUID[3],TagUID[2],TagUID[1],TagUID[0]);


	Dbprintf("%d octets read from SELECT request:", answerLen2);
	DbdecodeIso15693Answer(answerLen2, answer2);
	Dbhexdump(answerLen2, answer2, true);

	Dbprintf("%d octets read from XXX request:", answerLen3);
	DbdecodeIso15693Answer(answerLen3,answer3);
	Dbhexdump(answerLen3, answer3, true);

	// read all pages
	if (answerLen1 >= 12 && DEBUG) {
		i = 0;			
		while ( i < 32 ) {  // sanity check, assume max 32 pages
			BuildReadBlockRequest(TagUID,i);
			TransmitTo15693Tag(ToSend,ToSendMax,&tsamples, &wait);  
			answerLen2 = GetIso15693AnswerFromTag(answer2, 100, &samples, &elapsed);
			if (answerLen2>0) {
				Dbprintf("READ SINGLE BLOCK %d returned %d octets:", i, answerLen2);
				DbdecodeIso15693Answer(answerLen2, answer2);
				Dbhexdump(answerLen2, answer2, true);
				if ( *((uint32_t*) answer2) == 0x07160101 ) break; // exit on NoPageErr 
			} 
			++i;
		} 
	}

	LED_A_OFF();
	LED_B_OFF();
	LED_C_OFF();
	LED_D_OFF();
}

// Simulate an ISO15693 TAG, perform anti-collision and then print any reader commands
// all demodulation performed in arm rather than host. - greg
void SimTagIso15693(uint32_t parameter, uint8_t *uid)
{
	LED_A_ON();
	LED_B_ON();
	LED_C_OFF();
	LED_D_OFF();

	int answerLen1 = 0;
	int samples = 0;
	int tsamples = 0;
	int wait = 0;
	int elapsed = 0;

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

	uint8_t *buf = BigBuf_malloc(100);
	memset(buf, 0x00, 100);

	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

	// Start from off (no field generated)
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelay(200);

	LED_A_OFF();
	LED_B_OFF();
	LED_C_ON();
	LED_D_OFF();

	// Listen to reader
	answerLen1 = GetIso15693AnswerFromSniff(buf, 100, &samples, &elapsed) ;

	if (answerLen1 >=1) // we should do a better check than this
	{
		// Build a suitable reponse to the reader INVENTORY cocmmand
		// not so obsvious, but in the call to BuildInventoryResponse,  the command is copied to the global ToSend buffer used below.
		
		BuildInventoryResponse(uid);
	
		TransmitTo15693Reader(ToSend,ToSendMax, &tsamples, &wait);
	}

	Dbprintf("%d octets read from reader command: %x %x %x %x %x %x %x %x %x", answerLen1,
		buf[0], buf[1], buf[2],	buf[3],
		buf[4], buf[5],	buf[6], buf[7], buf[8]);

	Dbprintf("Simulationg uid: %x %x %x %x %x %x %x %x",
		uid[0], uid[1], uid[2],	uid[3],
		uid[4], uid[5],	uid[6], uid[7]);

	LED_A_OFF();
	LED_B_OFF();
	LED_C_OFF();
	LED_D_OFF();
}


// Since there is no standardized way of reading the AFI out of a tag, we will brute force it
// (some manufactures offer a way to read the AFI, though)
void BruteforceIso15693Afi(uint32_t speed) 
{	
	uint8_t data[20];
	uint8_t *recv = data;
	int datalen = 0, recvlen = 0;

	memset(data, 0, sizeof(data));
	
	Iso15693InitReader();
	
	// first without AFI
	// Tags should respond wihtout AFI and with AFI=0 even when AFI is active
	
	data[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | 
	          ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
	data[1] = ISO15_CMD_INVENTORY;
	data[2] = 0; // mask length
	datalen = AddCrc(data, 3);
	recvlen = SendDataTag(data, datalen, 0, speed, &recv);
	WDT_HIT();
	if (recvlen >= 12) {
		Dbprintf("NoAFI UID=%s", sprintUID(NULL, &recv[2]));
	}
	
	// now with AFI
	
	data[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | 
	          ISO15_REQ_INVENTORY | ISO15_REQINV_AFI | ISO15_REQINV_SLOT1;
	data[1] = ISO15_CMD_INVENTORY;
	data[2] = 0; // AFI
	data[3] = 0; // mask length
	
	for (int i = 0; i < 256; i++) {
		data[2] = i & 0xFF; // iceman 2016,  is & 0xFF needed?
		datalen = AddCrc(data, 4);
		recvlen = SendDataTag(data, datalen, 0, speed, &recv);
		WDT_HIT();
		if (recvlen >= 12) {
			Dbprintf("AFI=%i UID=%s", i, sprintUID(NULL, &recv[2]));
		}
	}	
	Dbprintf("AFI Bruteforcing done.");
}

// Allows to directly send commands to the tag via the client
void DirectTag15693Command(uint32_t datalen,uint32_t speed, uint32_t recv, uint8_t data[]) {

	int recvlen = 0;
	uint8_t *recvbuf = BigBuf_get_addr();
	
	if (DEBUG) {
		Dbprintf("SEND");
		Dbhexdump(datalen,data,true);
	}
	
	recvlen = SendDataTag(data, datalen, 1, speed, (recv ? &recvbuf : NULL));

	if (recv) { 
		LED_B_ON();
		cmd_send(CMD_ACK,recvlen>48?48:recvlen,0,0,recvbuf,48);
		LED_B_OFF();	
		
		if (DEBUG) {
			Dbprintf("RECV");
			DbdecodeIso15693Answer(recvlen,recvbuf); 
			Dbhexdump(recvlen,recvbuf,true);
		}
	}
}