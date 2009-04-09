//-----------------------------------------------------------------------------
// The actual command interpeter for what the user types at the command line.
// Jonathan Westhues, Sept 2005
// Edits by Gerhard de Koning Gans, Sep 2007 (##)
//-----------------------------------------------------------------------------
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <math.h>

#include "prox.h"
#include "../common/iso14443_crc.c"

#define arraylen(x) (sizeof(x)/sizeof((x)[0]))

static int CmdHisamplest(char *str, int nrlow);

static void GetFromBigBuf(BYTE *dest, int bytes)
{
	int n = bytes/4;

	if(n % 48 != 0) {
		PrintToScrollback("bad len in GetFromBigBuf");
		return;
	}

	int i;
	for(i = 0; i < n; i += 12) {
		UsbCommand c;
		c.cmd = CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K;
		c.ext1 = i;
		SendCommand(&c, FALSE);
		ReceiveCommand(&c);
		if(c.cmd != CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K) {
			PrintToScrollback("bad resp\n");
			return;
		}

		memcpy(dest+(i*4), c.d.asBytes, 48);
	}
}

static void CmdQuit(char *str)
{
	exit(0);
}

static void CmdHIDdemodFSK(char *str)
{
	UsbCommand c;
	c.cmd = CMD_HID_DEMOD_FSK;
	SendCommand(&c, FALSE);
}

static void CmdTune(char *str)
{
	UsbCommand c;
	c.cmd = CMD_MEASURE_ANTENNA_TUNING;
	SendCommand(&c, FALSE);
}

static void CmdHi15read(char *str)
{
	UsbCommand c;
	c.cmd = CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693;
	SendCommand(&c, FALSE);
}

static void CmdHi14read(char *str)
{
	UsbCommand c;
	c.cmd = CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443;
	c.ext1 = atoi(str);
	SendCommand(&c, FALSE);
}

// ## New command
static void CmdHi14areader(char *str)
{
	UsbCommand c;
	c.cmd = CMD_READER_ISO_14443a;
	c.ext1 = atoi(str);
	SendCommand(&c, FALSE);
}

// ## New command
static void CmdHi15reader(char *str)
{
	UsbCommand c;
	c.cmd = CMD_READER_ISO_15693;
	c.ext1 = atoi(str);
	SendCommand(&c, FALSE);
}

// ## New command
static void CmdHi15tag(char *str)
{
	UsbCommand c;
	c.cmd = CMD_SIMTAG_ISO_15693;
	c.ext1 = atoi(str);
	SendCommand(&c, FALSE);
}

static void CmdHi14read_sim(char *str)
{
	UsbCommand c;
	c.cmd = CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443_SIM;
	c.ext1 = atoi(str);
	SendCommand(&c, FALSE);
}

static void CmdHi14readt(char *str)
{
	UsbCommand c;
	c.cmd = CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443;
	c.ext1 = atoi(str);
	SendCommand(&c, FALSE);

	//CmdHisamplest(str);
	while(CmdHisamplest(str,atoi(str))==0) {
		c.cmd = CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443;
		c.ext1 = atoi(str);
		SendCommand(&c, FALSE);
	}
	RepaintGraphWindow();
}

static void CmdHisimlisten(char *str)
{
	UsbCommand c;
	c.cmd = CMD_SIMULATE_TAG_HF_LISTEN;
	SendCommand(&c, FALSE);
}

static void CmdHi14sim(char *str)
{
	UsbCommand c;
	c.cmd = CMD_SIMULATE_TAG_ISO_14443;
	SendCommand(&c, FALSE);
}



static void CmdHi14asim(char *str)	// ## simulate iso14443a tag
{					// ## greg - added ability to specify tag UID

	unsigned int hi=0, lo=0;
	int n=0, i=0;
	UsbCommand c;

	while (sscanf(&str[i++], "%1x", &n ) == 1) {
		hi=(hi<<4)|(lo>>28);
		lo=(lo<<4)|(n&0xf);
	}

	c.cmd = CMD_SIMULATE_TAG_ISO_14443a;
	// c.ext should be set to *str or convert *str to the correct format for a uid
	c.ext1 = hi;
	c.ext2 = lo;
	PrintToScrollback("Emulating 14443A TAG with UID %x%16x", hi, lo);
	SendCommand(&c, FALSE);
}

static void CmdHi14snoop(char *str)
{
	UsbCommand c;
	c.cmd = CMD_SNOOP_ISO_14443;
	SendCommand(&c, FALSE);
}

static void CmdHi14asnoop(char *str)
{
	UsbCommand c;
	c.cmd = CMD_SNOOP_ISO_14443a;
	SendCommand(&c, FALSE);
}

static void CmdFPGAOff(char *str)		// ## FPGA Control
{
	UsbCommand c;
	c.cmd = CMD_FPGA_MAJOR_MODE_OFF;
	SendCommand(&c, FALSE);
}

static void CmdLosim(char *str)
{
	int i;

	for(i = 0; i < GraphTraceLen; i += 48) {
		UsbCommand c;
		int j;
		for(j = 0; j < 48; j++) {
			c.d.asBytes[j] = GraphBuffer[i+j];
		}
		c.cmd = CMD_DOWNLOADED_SIM_SAMPLES_125K;
		c.ext1 = i;
		SendCommand(&c, FALSE);
	}

	UsbCommand c;
	c.cmd = CMD_SIMULATE_TAG_125K;
	c.ext1 = GraphTraceLen;
	SendCommand(&c, FALSE);
}

static void CmdLoread(char *str)
{
	UsbCommand c;
	// 'h' means higher-low-frequency, 134 kHz
	if(*str == 'h') {
		c.ext1 = 1;
	} else if (*str == '\0') {
		c.ext1 = 0;
	} else {
		PrintToScrollback("use 'loread' or 'loread h'");
		return;
	}
	c.cmd = CMD_ACQUIRE_RAW_ADC_SAMPLES_125K;
	SendCommand(&c, FALSE);
}

static void CmdLosamples(char *str)
{
	int cnt = 0;
	int i;
	int n;

	n=atoi(str);
	if (n==0) n=128;
	if (n>16000) n=16000;

	for(i = 0; i < n; i += 12) {
		UsbCommand c;
		c.cmd = CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K;
		c.ext1 = i;
		SendCommand(&c, FALSE);
		ReceiveCommand(&c);
		if(c.cmd != CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K) {
			PrintToScrollback("bad resp\n");
			return;
		}
		int j;
		for(j = 0; j < 48; j++) {
			GraphBuffer[cnt++] = ((int)c.d.asBytes[j]) - 128;
		}
	}
	GraphTraceLen = n*4;
	RepaintGraphWindow();
}

static void CmdBitsamples(char *str)
{
	int cnt = 0;
	int i;
	int n;

	n = 3072;
	for(i = 0; i < n; i += 12) {
		UsbCommand c;
		c.cmd = CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K;
		c.ext1 = i;
		SendCommand(&c, FALSE);
		ReceiveCommand(&c);
		if(c.cmd != CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K) {
			PrintToScrollback("bad resp\n");
			return;
		}
		int j, k;
		for(j = 0; j < 48; j++) {
			for(k = 0; k < 8; k++) {
				if(c.d.asBytes[j] & (1 << (7 - k))) {
					GraphBuffer[cnt++] = 1;
				} else {
					GraphBuffer[cnt++] = 0;
				}
			}
		}
	}
	GraphTraceLen = cnt;
	RepaintGraphWindow();
}

static void CmdHisamples(char *str)
{
	int cnt = 0;
	int i;
	int n;
	n = 1000;
	for(i = 0; i < n; i += 12) {
		UsbCommand c;
		c.cmd = CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K;
		c.ext1 = i;
		SendCommand(&c, FALSE);
		ReceiveCommand(&c);
		if(c.cmd != CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K) {
			PrintToScrollback("bad resp\n");
			return;
		}
		int j;
		for(j = 0; j < 48; j++) {
			GraphBuffer[cnt++] = (int)((BYTE)c.d.asBytes[j]);
		}
	}
	GraphTraceLen = n*4;

	RepaintGraphWindow();
}


static int CmdHisamplest(char *str, int nrlow)
{
	int cnt = 0;
	int t1, t2;
	int i;
	int n;
	int hasbeennull;
	int show;


	n = 1000;
	hasbeennull = 0;
	for(i = 0; i < n; i += 12) {
		UsbCommand c;
		c.cmd = CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K;
		c.ext1 = i;
		SendCommand(&c, FALSE);
		ReceiveCommand(&c);
		if(c.cmd != CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K) {
			PrintToScrollback("bad resp\n");
			return 0;
		}
		int j;
		for(j = 0; j < 48; j++) {
			t2 = (int)((BYTE)c.d.asBytes[j]);
			if((t2 ^ 0xC0) & 0xC0) { hasbeennull++; }

			show = 0;
			switch(show) {
				case 0:
					// combined
					t1 = (t2 & 0x80) ^ (t2 & 0x20);
					t2 = ((t2 << 1) & 0x80) ^ ((t2 << 1) & 0x20);
					break;

				case 1:
					// only reader
					t1 = (t2 & 0x80);
					t2 = ((t2 << 1) & 0x80);
					break;

				case 2:
					// only tag
					t1 = (t2 & 0x20);
					t2 = ((t2 << 1) & 0x20);
					break;

				case 3:
					// both, but tag with other algorithm
					t1 = (t2 & 0x80) ^ (t2 & 0x08);
					t2 = ((t2 << 1) & 0x80) ^ ((t2 << 1) & 0x08);
					break;
			}

			GraphBuffer[cnt++] = t1;
			GraphBuffer[cnt++] = t2;
		}
	}
	GraphTraceLen = n*4;
// 1130
	if(hasbeennull>nrlow || nrlow==0) {
		PrintToScrollback("hasbeennull=%d", hasbeennull);
		return 1;
	}
	else {
		return 0;
	}
}


static void CmdHexsamples(char *str)
{
	int i;
	int n;

	if(atoi(str) == 0) {
		n = 12;
	} else {
		n = atoi(str)/4;
	}

	for(i = 0; i < n; i += 12) {
		UsbCommand c;
		c.cmd = CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K;
		c.ext1 = i;
		SendCommand(&c, FALSE);
		ReceiveCommand(&c);
		if(c.cmd != CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K) {
			PrintToScrollback("bad resp\n");
			return;
		}
		int j;
		for(j = 0; j < 48; j += 8) {
			PrintToScrollback("%02x %02x %02x %02x %02x %02x %02x %02x",
				c.d.asBytes[j+0],
				c.d.asBytes[j+1],
				c.d.asBytes[j+2],
				c.d.asBytes[j+3],
				c.d.asBytes[j+4],
				c.d.asBytes[j+5],
				c.d.asBytes[j+6],
				c.d.asBytes[j+7],
				c.d.asBytes[j+8]
			);
		}
	}
}

static void CmdHisampless(char *str)
{
	int cnt = 0;
	int i;
	int n;

	if(atoi(str) == 0) {
		n = 1000;
	} else {
		n = atoi(str)/4;
	}

	for(i = 0; i < n; i += 12) {
		UsbCommand c;
		c.cmd = CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K;
		c.ext1 = i;
		SendCommand(&c, FALSE);
		ReceiveCommand(&c);
		if(c.cmd != CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K) {
			PrintToScrollback("bad resp\n");
			return;
		}
		int j;
		for(j = 0; j < 48; j++) {
			GraphBuffer[cnt++] = (int)((signed char)c.d.asBytes[j]);
		}
	}
	GraphTraceLen = cnt;

	RepaintGraphWindow();
}

static WORD Iso15693Crc(BYTE *v, int n)
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

	return (WORD)~reg;
}

static void CmdHi14bdemod(char *str)
{
	int i, j, iold;
	int isum, qsum;
	int outOfWeakAt;
	BOOL negateI, negateQ;

	BYTE data[256];
	int dataLen=0;

	// As received, the samples are pairs, correlations against I and Q
	// square waves. So estimate angle of initial carrier (or just
	// quadrant, actually), and then do the demod.

	// First, estimate where the tag starts modulating.
	for(i = 0; i < GraphTraceLen; i += 2) {
		if(abs(GraphBuffer[i]) + abs(GraphBuffer[i+1]) > 40) {
			break;
		}
	}
	if(i >= GraphTraceLen) {
		PrintToScrollback("too weak to sync");
		return;
	}
	PrintToScrollback("out of weak at %d", i);
	outOfWeakAt = i;

	// Now, estimate the phase in the initial modulation of the tag
	isum = 0;
	qsum = 0;
	for(; i < (outOfWeakAt + 16); i += 2) {
		isum += GraphBuffer[i+0];
		qsum += GraphBuffer[i+1];
	}
	negateI = (isum < 0);
	negateQ = (qsum < 0);

	// Turn the correlation pairs into soft decisions on the bit.
	j = 0;
	for(i = 0; i < GraphTraceLen/2; i++) {
		int si = GraphBuffer[j];
		int sq = GraphBuffer[j+1];
		if(negateI) si = -si;
		if(negateQ) sq = -sq;
		GraphBuffer[i] = si + sq;
		j += 2;
	}
	GraphTraceLen = i;

	i = outOfWeakAt/2;
	while(GraphBuffer[i] > 0 && i < GraphTraceLen)
		i++;
	if(i >= GraphTraceLen) goto demodError;

	iold = i;
	while(GraphBuffer[i] < 0 && i < GraphTraceLen)
		i++;
	if(i >= GraphTraceLen) goto demodError;
	if((i - iold) > 23) goto demodError;

	PrintToScrollback("make it to demod loop");

	for(;;) {
		iold = i;
		while(GraphBuffer[i] >= 0 && i < GraphTraceLen)
			i++;
		if(i >= GraphTraceLen) goto demodError;
		if((i - iold) > 6) goto demodError;

		WORD shiftReg = 0;
		if(i + 20 >= GraphTraceLen) goto demodError;

		for(j = 0; j < 10; j++) {
			int soft = GraphBuffer[i] + GraphBuffer[i+1];

			if(abs(soft) < ((abs(isum) + abs(qsum))/20)) {
				PrintToScrollback("weak bit");
			}

			shiftReg >>= 1;
			if(GraphBuffer[i] + GraphBuffer[i+1] >= 0) {
				shiftReg |= 0x200;
			}

			i+= 2;
		}

		if( (shiftReg & 0x200) &&
			!(shiftReg & 0x001))
		{
			// valid data byte, start and stop bits okay
			PrintToScrollback("   %02x", (shiftReg >> 1) & 0xff);
			data[dataLen++] = (shiftReg >> 1) & 0xff;
			if(dataLen >= sizeof(data)) {
				return;
			}
		} else if(shiftReg == 0x000) {
			// this is EOF
			break;
		} else {
			goto demodError;
		}
	}

	BYTE first, second;
	ComputeCrc14443(CRC_14443_B, data, dataLen-2, &first, &second);
	PrintToScrollback("CRC: %02x %02x (%s)\n", first, second,
		(first == data[dataLen-2] && second == data[dataLen-1]) ?
			"ok" : "****FAIL****");

	RepaintGraphWindow();
	return;

demodError:
	PrintToScrollback("demod error");
	RepaintGraphWindow();
}

static void CmdHi14list(char *str)
{
	BYTE got[960];
	GetFromBigBuf(got, sizeof(got));

	PrintToScrollback("recorded activity:");
	PrintToScrollback(" time	:rssi: who bytes");
	PrintToScrollback("---------+----+----+-----------");

	int i = 0;
	int prev = -1;

	for(;;) {
		if(i >= 900) {
			break;
		}

		BOOL isResponse;
		int timestamp = *((DWORD *)(got+i));
		if(timestamp & 0x80000000) {
			timestamp &= 0x7fffffff;
			isResponse = 1;
		} else {
			isResponse = 0;
		}
		int metric = *((DWORD *)(got+i+4));

		int len = got[i+8];

		if(len > 100) {
			break;
		}
		if(i + len >= 900) {
			break;
		}

		BYTE *frame = (got+i+9);

		char line[1000] = "";
		int j;
		for(j = 0; j < len; j++) {
			sprintf(line+(j*3), "%02x  ", frame[j]);
		}

		char *crc;
		if(len > 2) {
			BYTE b1, b2;
			ComputeCrc14443(CRC_14443_B, frame, len-2, &b1, &b2);
			if(b1 != frame[len-2] || b2 != frame[len-1]) {
				crc = "**FAIL CRC**";
			} else {
				crc = "";
			}
		} else {
			crc = "(SHORT)";
		}

		char metricString[100];
		if(isResponse) {
			sprintf(metricString, "%3d", metric);
		} else {
			strcpy(metricString, "   ");
		}

		PrintToScrollback(" +%7d: %s: %s %s %s",
			(prev < 0 ? 0 : timestamp - prev),
			metricString,
			(isResponse ? "TAG" : "   "), line, crc);

		prev = timestamp;
		i += (len + 9);
	}
}

static void CmdHi14alist(char *str)
{
	BYTE got[1920];
	GetFromBigBuf(got, sizeof(got));

	PrintToScrollback("recorded activity:");
	PrintToScrollback(" ETU     :rssi: who bytes");
	PrintToScrollback("---------+----+----+-----------");

	int i = 0;
	int prev = -1;

	for(;;) {
		if(i >= 1900) {
			break;
		}

		BOOL isResponse;
		int timestamp = *((DWORD *)(got+i));
		if(timestamp & 0x80000000) {
			timestamp &= 0x7fffffff;
			isResponse = 1;
		} else {
			isResponse = 0;
		}

		int metric = 0;
		int parityBits = *((DWORD *)(got+i+4));
		// 4 bytes of additional information...
		// maximum of 32 additional parity bit information
		//
		// TODO:
		// at each quarter bit period we can send power level (16 levels)
		// or each half bit period in 256 levels.


		int len = got[i+8];

		if(len > 100) {
			break;
		}
		if(i + len >= 1900) {
			break;
		}

		BYTE *frame = (got+i+9);

		// Break and stick with current result if buffer was not completely full
		if(frame[0] == 0x44 && frame[1] == 0x44 && frame[3] == 0x44) { break; }

		char line[1000] = "";
		int j;
		for(j = 0; j < len; j++) {
			int oddparity = 0x01;
			int k;

			for(k=0;k<8;k++) {
				oddparity ^= (((frame[j] & 0xFF) >> k) & 0x01);
			}

			//if((parityBits >> (len - j - 1)) & 0x01) {
			if(isResponse && (oddparity != ((parityBits >> (len - j - 1)) & 0x01))) {
				sprintf(line+(j*4), "%02x!  ", frame[j]);
			}
			else {
				sprintf(line+(j*4), "%02x   ", frame[j]);
			}
		}

		char *crc;
		crc = "";
		if(len > 2) {
			BYTE b1, b2;
			for(j = 0; j < (len - 1); j++) {
				// gives problems... search for the reason..
				/*if(frame[j] == 0xAA) {
					switch(frame[j+1]) {
						case 0x01:
							crc = "[1] Two drops close after each other";
						break;
						case 0x02:
							crc = "[2] Potential SOC with a drop in second half of bitperiod";
							break;
						case 0x03:
							crc = "[3] Segment Z after segment X is not possible";
							break;
						case 0x04:
							crc = "[4] Parity bit of a fully received byte was wrong";
							break;
						default:
							crc = "[?] Unknown error";
							break;
					}
					break;
				}*/
			}

			if(strlen(crc)==0) {
				ComputeCrc14443(CRC_14443_A, frame, len-2, &b1, &b2);
				if(b1 != frame[len-2] || b2 != frame[len-1]) {
					crc = (isResponse & (len < 6)) ? "" : "	!crc";
				} else {
					crc = "";
				}
			}
		} else {
			crc = ""; // SHORT
		}

		char metricString[100];
		if(isResponse) {
			sprintf(metricString, "%3d", metric);
		} else {
			strcpy(metricString, "   ");
		}

		PrintToScrollback(" +%7d: %s: %s %s %s",
			(prev < 0 ? 0 : (timestamp - prev)),
			metricString,
			(isResponse ? "TAG" : "   "), line, crc);

		prev = timestamp;
		i += (len + 9);
	}
	CommandFinished = 1;
}

static void CmdHi15demod(char *str)
{
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

	int i, j;
	int max = 0, maxPos;

	int skip = 4;

	if(GraphTraceLen < 1000) return;

	// First, correlate for SOF
	for(i = 0; i < 100; i++) {
		int corr = 0;
		for(j = 0; j < arraylen(FrameSOF); j += skip) {
			corr += FrameSOF[j]*GraphBuffer[i+(j/skip)];
		}
		if(corr > max) {
			max = corr;
			maxPos = i;
		}
	}
	PrintToScrollback("SOF at %d, correlation %d", maxPos,
		max/(arraylen(FrameSOF)/skip));

	i = maxPos + arraylen(FrameSOF)/skip;
	int k = 0;
	BYTE outBuf[20];
	memset(outBuf, 0, sizeof(outBuf));
	BYTE mask = 0x01;
	for(;;) {
		int corr0 = 0, corr1 = 0, corrEOF = 0;
		for(j = 0; j < arraylen(Logic0); j += skip) {
			corr0 += Logic0[j]*GraphBuffer[i+(j/skip)];
		}
		for(j = 0; j < arraylen(Logic1); j += skip) {
			corr1 += Logic1[j]*GraphBuffer[i+(j/skip)];
		}
		for(j = 0; j < arraylen(FrameEOF); j += skip) {
			corrEOF += FrameEOF[j]*GraphBuffer[i+(j/skip)];
		}
		// Even things out by the length of the target waveform.
		corr0 *= 4;
		corr1 *= 4;

		if(corrEOF > corr1 && corrEOF > corr0) {
			PrintToScrollback("EOF at %d", i);
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
		if((i+(int)arraylen(FrameEOF)) >= GraphTraceLen) {
			PrintToScrollback("ran off end!");
			break;
		}
	}
	if(mask != 0x01) {
		PrintToScrollback("error, uneven octet! (discard extra bits!)");
		PrintToScrollback("   mask=%02x", mask);
	}
	PrintToScrollback("%d octets", k);

	for(i = 0; i < k; i++) {
		PrintToScrollback("# %2d: %02x ", i, outBuf[i]);
	}
	PrintToScrollback("CRC=%04x", Iso15693Crc(outBuf, k-2));
}

static void CmdTiread(char *str)
{
	UsbCommand c;
	c.cmd = CMD_ACQUIRE_RAW_BITS_TI_TYPE;
	SendCommand(&c, FALSE);
}

static void CmdTibits(char *str)
{
	int cnt = 0;
	int i;
	for(i = 0; i < 1536; i += 12) {
		UsbCommand c;
		c.cmd = CMD_DOWNLOAD_RAW_BITS_TI_TYPE;
		c.ext1 = i;
		SendCommand(&c, FALSE);
		ReceiveCommand(&c);
		if(c.cmd != CMD_DOWNLOADED_RAW_BITS_TI_TYPE) {
			PrintToScrollback("bad resp\n");
			return;
		}
		int j;
		for(j = 0; j < 12; j++) {
			int k;
			for(k = 31; k >= 0; k--) {
				if(c.d.asDwords[j] & (1 << k)) {
					GraphBuffer[cnt++] = 1;
				} else {
					GraphBuffer[cnt++] = -1;
				}
			}
		}
	}
	GraphTraceLen = 1536*32;
	RepaintGraphWindow();
}

static void CmdTidemod(char *cmdline)
{
	/* MATLAB as follows:
f_s = 2000000;  % sampling frequency
f_l = 123200;   % low FSK tone
f_h = 134200;   % high FSK tone

T_l = 119e-6;   % low bit duration
T_h = 130e-6;   % high bit duration

l = 2*pi*ones(1, floor(f_s*T_l))*(f_l/f_s);
h = 2*pi*ones(1, floor(f_s*T_h))*(f_h/f_s);

l = sign(sin(cumsum(l)));
h = sign(sin(cumsum(h)));
	*/
	static const int LowTone[] = {
		1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1,
		1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1,
		1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1,
		-1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1,
		-1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1,
		-1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1,
		1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1,
		1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1,
		1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1,
		-1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1,
		-1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1,
		1, 1, 1, 1, 1, 1, 1, -1, -1, -1,
	};
	static const int HighTone[] = {
		1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1,
		1, 1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
		-1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
		-1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, 1, 1,
		1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
		-1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
		-1, -1, -1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
		1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1,
		1, 1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
		-1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
		-1, -1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, 1, 1,
		1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1,
	};

	int convLen = max(arraylen(HighTone), arraylen(LowTone));

	int i;
	for(i = 0; i < GraphTraceLen - convLen; i++) {
		int j;
		int lowSum = 0, highSum = 0;;
		int lowLen = arraylen(LowTone);
		int highLen = arraylen(HighTone);

		for(j = 0; j < lowLen; j++) {
			lowSum += LowTone[j]*GraphBuffer[i+j];
		}
		for(j = 0; j < highLen; j++) {
			highSum += HighTone[j]*GraphBuffer[i+j];
		}
		lowSum = abs((100*lowSum) / lowLen);
		highSum = abs((100*highSum) / highLen);
		GraphBuffer[i] = (highSum << 16) | lowSum;
	}

	for(i = 0; i < GraphTraceLen - convLen - 16; i++) {
		int j;
		int lowTot = 0, highTot = 0;
		// 16 and 15 are f_s divided by f_l and f_h, rounded
		for(j = 0; j < 16; j++) {
			lowTot += (GraphBuffer[i+j] & 0xffff);
		}
		for(j = 0; j < 15; j++) {
			highTot += (GraphBuffer[i+j] >> 16);
		}
		GraphBuffer[i] = lowTot - highTot;
	}

	GraphTraceLen -= (convLen + 16);

	RepaintGraphWindow();

	// Okay, so now we have unsliced soft decisions; find bit-sync, and then
	// get some bits.

	int max = 0, maxPos = 0;
	for(i = 0; i < 6000; i++) {
		int j;
		int dec = 0;
		for(j = 0; j < 8*arraylen(LowTone); j++) {
			dec -= GraphBuffer[i+j];
		}
		for(; j < 8*arraylen(LowTone) + 8*arraylen(HighTone); j++) {
			dec += GraphBuffer[i+j];
		}
		if(dec > max) {
			max = dec;
			maxPos = i;
		}
	}
	GraphBuffer[maxPos] = 800;
	GraphBuffer[maxPos+1] = -800;

	maxPos += 8*arraylen(LowTone);
	GraphBuffer[maxPos] = 800;
	GraphBuffer[maxPos+1] = -800;
	maxPos += 8*arraylen(HighTone);

	GraphBuffer[maxPos] = 800;
	GraphBuffer[maxPos+1] = -800;

	PrintToScrollback("actual data bits start at sample %d", maxPos);

	PrintToScrollback("length %d/%d", arraylen(HighTone), arraylen(LowTone));

	GraphBuffer[maxPos] = 800;
	GraphBuffer[maxPos+1] = -800;

	BYTE bits[64+16+8+1];
	bits[sizeof(bits)-1] = '\0';

	for(i = 0; i < arraylen(bits); i++) {
		int high = 0;
		int low = 0;
		int j;
		for(j = 0; j < arraylen(LowTone); j++) {
			low -= GraphBuffer[maxPos+j];
		}
		for(j = 0; j < arraylen(HighTone); j++) {
			high += GraphBuffer[maxPos+j];
		}
		if(high > low) {
			bits[i] = '1';
			maxPos += arraylen(HighTone);
		} else {
			bits[i] = '.';
			maxPos += arraylen(LowTone);
		}
		GraphBuffer[maxPos] = 800;
		GraphBuffer[maxPos+1] = -800;
	}
	PrintToScrollback("bits: '%s'", bits);

	DWORD h = 0, l = 0;
	for(i = 0; i < 32; i++) {
		if(bits[i] == '1') {
			l |= (1<<i);
		}
	}
	for(i = 32; i < 64; i++) {
		if(bits[i] == '1') {
			h |= (1<<(i-32));
		}
	}
	PrintToScrollback("hex: %08x %08x", h, l);
}

static void CmdNorm(char *str)
{
	int i;
	int max = INT_MIN, min = INT_MAX;
	for(i = 10; i < GraphTraceLen; i++) {
		if(GraphBuffer[i] > max) {
			max = GraphBuffer[i];
		}
		if(GraphBuffer[i] < min) {
			min = GraphBuffer[i];
		}
	}
	if(max != min) {
		for(i = 0; i < GraphTraceLen; i++) {
			GraphBuffer[i] = (GraphBuffer[i] - ((max + min)/2))*1000/
				(max - min);
		}
	}
	RepaintGraphWindow();
}

static void CmdDec(char *str)
{
	int i;
	for(i = 0; i < (GraphTraceLen/2); i++) {
		GraphBuffer[i] = GraphBuffer[i*2];
	}
	GraphTraceLen /= 2;
	PrintToScrollback("decimated by 2");
	RepaintGraphWindow();
}

static void CmdHpf(char *str)
{
	int i;
	int accum = 0;
	for(i = 10; i < GraphTraceLen; i++) {
		accum += GraphBuffer[i];
	}
	accum /= (GraphTraceLen - 10);
	for(i = 0; i < GraphTraceLen; i++) {
		GraphBuffer[i] -= accum;
	}

	RepaintGraphWindow();
}

static void CmdZerocrossings(char *str)
{
	int i;
	// Zero-crossings aren't meaningful unless the signal is zero-mean.
	CmdHpf("");

	int sign = 1;
	int zc = 0;
	int lastZc = 0;
	for(i = 0; i < GraphTraceLen; i++) {
		if(GraphBuffer[i]*sign >= 0) {
			// No change in sign, reproduce the previous sample count.
			zc++;
			GraphBuffer[i] = lastZc;
		} else {
			// Change in sign, reset the sample count.
			sign = -sign;
			GraphBuffer[i] = lastZc;
			if(sign > 0) {
				lastZc = zc;
				zc = 0;
			}
		}
	}

	RepaintGraphWindow();
}

static void CmdLtrim(char *str)
{
	int i;
	int ds = atoi(str);

	for(i = ds; i < GraphTraceLen; i++) {
		GraphBuffer[i-ds] = GraphBuffer[i];
	}
	GraphTraceLen -= ds;

	RepaintGraphWindow();
}

static void CmdAutoCorr(char *str)
{
	static int CorrelBuffer[MAX_GRAPH_TRACE_LEN];

	int window = atoi(str);

	if(window == 0) {
		PrintToScrollback("needs a window");
		return;
	}

	if(window >= GraphTraceLen) {
		PrintToScrollback("window must be smaller than trace (%d samples)",
			GraphTraceLen);
		return;
	}

	PrintToScrollback("performing %d correlations", GraphTraceLen - window);

	int i;
	for(i = 0; i < GraphTraceLen - window; i++) {
		int sum = 0;
		int j;
		for(j = 0; j < window; j++) {
			sum += (GraphBuffer[j]*GraphBuffer[i+j]) / 256;
		}
		CorrelBuffer[i] = sum;
	}
	GraphTraceLen = GraphTraceLen - window;
	memcpy(GraphBuffer, CorrelBuffer, GraphTraceLen*sizeof(int));

	RepaintGraphWindow();
}

static void CmdVchdemod(char *str)
{
	// Is this the entire sync pattern, or does this also include some
	// data bits that happen to be the same everywhere? That would be
	// lovely to know.
	static const int SyncPattern[] = {
		1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
		1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	};

	// So first, we correlate for the sync pattern, and mark that.
	int bestCorrel = 0, bestPos = 0;
	int i;
	// It does us no good to find the sync pattern, with fewer than
	// 2048 samples after it...
	for(i = 0; i < (GraphTraceLen-2048); i++) {
		int sum = 0;
		int j;
		for(j = 0; j < arraylen(SyncPattern); j++) {
			sum += GraphBuffer[i+j]*SyncPattern[j];
		}
		if(sum > bestCorrel) {
			bestCorrel = sum;
			bestPos = i;
		}
	}
	PrintToScrollback("best sync at %d [metric %d]", bestPos, bestCorrel);

	char bits[257];
	bits[256] = '\0';

	int worst = INT_MAX;
	int worstPos;

	for(i = 0; i < 2048; i += 8) {
		int sum = 0;
		int j;
		for(j = 0; j < 8; j++) {
			sum += GraphBuffer[bestPos+i+j];
		}
		if(sum < 0) {
			bits[i/8] = '.';
		} else {
			bits[i/8] = '1';
		}
		if(abs(sum) < worst) {
			worst = abs(sum);
			worstPos = i;
		}
	}
	PrintToScrollback("bits:");
	PrintToScrollback("%s", bits);
	PrintToScrollback("worst metric: %d at pos %d", worst, worstPos);

	if(strcmp(str, "clone")==0) {
		GraphTraceLen = 0;
		char *s;
		for(s = bits; *s; s++) {
			int j;
			for(j = 0; j < 16; j++) {
				GraphBuffer[GraphTraceLen++] = (*s == '1') ? 1 : 0;
			}
		}
		RepaintGraphWindow();
	}
}

static void CmdIndalademod(char *str)
{
	// Usage: recover 64bit UID by default, specify "224" as arg to recover a 224bit UID

	int state = -1;
	int count = 0;
	int i, j;
	// worst case with GraphTraceLen=64000 is < 4096
	// under normal conditions it's < 2048
	BYTE rawbits[4096];
	int rawbit = 0;
	int worst = 0, worstPos = 0;
	PrintToScrollback("Expecting a bit less than %d raw bits", GraphTraceLen/32);
	for(i = 0; i < GraphTraceLen-1; i += 2) {
		count+=1;
		if((GraphBuffer[i] > GraphBuffer[i + 1]) && (state != 1)) {
			if (state == 0) {
				for(j = 0; j <  count - 8; j += 16) {
					rawbits[rawbit++] = 0;
				}
				if ((abs(count - j)) > worst) {
					worst = abs(count - j);
					worstPos = i;
				}
			}
			state = 1;
			count=0;
		} else if((GraphBuffer[i] < GraphBuffer[i + 1]) && (state != 0)) {
			if (state == 1) {
				for(j = 0; j <  count - 8; j += 16) {
					rawbits[rawbit++] = 1;
				}
				if ((abs(count - j)) > worst) {
					worst = abs(count - j);
					worstPos = i;
				}
			}
			state = 0;
			count=0;
		}
	}
	PrintToScrollback("Recovered %d raw bits", rawbit);
	PrintToScrollback("worst metric (0=best..7=worst): %d at pos %d", worst, worstPos);

	// Finding the start of a UID
	int uidlen, long_wait;
	if(strcmp(str, "224") == 0) {
		uidlen=224;
		long_wait=30;
	} else {
		uidlen=64;
		long_wait=29;
	}
	int start;
	int first = 0;
	for(start = 0; start <= rawbit - uidlen; start++) {
		first = rawbits[start];
		for(i = start; i < start + long_wait; i++) {
			if(rawbits[i] != first) {
				break;
			}
		}
		if(i == (start + long_wait)) {
			break;
		}
	}
	if(start == rawbit - uidlen + 1) {
		PrintToScrollback("nothing to wait for");
		return;
	}

	// Inverting signal if needed
	if(first == 1) {
		for(i = start; i < rawbit; i++) {
			rawbits[i] = !rawbits[i];
		}
	}

	// Dumping UID
	BYTE bits[224];
	char showbits[225];
	showbits[uidlen]='\0';
	int bit;
	i = start;
	int times = 0;
	if(uidlen > rawbit) {
		PrintToScrollback("Warning: not enough raw bits to get a full UID");
		for(bit = 0; bit < rawbit; bit++) {
			bits[bit] = rawbits[i++];
			// As we cannot know the parity, let's use "." and "/"
			showbits[bit] = '.' + bits[bit];
		}
		showbits[bit+1]='\0';
		PrintToScrollback("Partial UID=%s", showbits);
		return;
	} else {
		for(bit = 0; bit < uidlen; bit++) {
			bits[bit] = rawbits[i++];
			showbits[bit] = '0' + bits[bit];
		}
		times = 1;
	}
	PrintToScrollback("UID=%s", showbits);

	// Checking UID against next occurences
	for(; i + uidlen <= rawbit;) {
		int failed = 0;
		for(bit = 0; bit < uidlen; bit++) {
			if(bits[bit] != rawbits[i++]) {
				failed = 1;
				break;
			}
		}
		if (failed == 1) {
			break;
		}
		times += 1;
	}
	PrintToScrollback("Occurences: %d (expected %d)", times, (rawbit - start) / uidlen);

	// Remodulating for tag cloning
	GraphTraceLen = 32*uidlen;
	i = 0;
	int phase = 0;
	for(bit = 0; bit < uidlen; bit++) {
		if(bits[bit] == 0) {
			phase = 0;
		} else {
			phase = 1;
		}
		int j;
		for(j = 0; j < 32; j++) {
			GraphBuffer[i++] = phase;
			phase = !phase;
		}
	}

	RepaintGraphWindow();
}

static void CmdFlexdemod(char *str)
{
	int i;
	for(i = 0; i < GraphTraceLen; i++) {
		if(GraphBuffer[i] < 0) {
			GraphBuffer[i] = -1;
		} else {
			GraphBuffer[i] = 1;
		}
	}

#define LONG_WAIT 100
	int start;
	for(start = 0; start < GraphTraceLen - LONG_WAIT; start++) {
		int first = GraphBuffer[start];
		for(i = start; i < start + LONG_WAIT; i++) {
			if(GraphBuffer[i] != first) {
				break;
			}
		}
		if(i == (start + LONG_WAIT)) {
			break;
		}
	}
	if(start == GraphTraceLen - LONG_WAIT) {
		PrintToScrollback("nothing to wait for");
		return;
	}

	GraphBuffer[start] = 2;
	GraphBuffer[start+1] = -2;

	BYTE bits[64];

	int bit;
	i = start;
	for(bit = 0; bit < 64; bit++) {
		int j;
		int sum = 0;
		for(j = 0; j < 16; j++) {
			sum += GraphBuffer[i++];
		}
		if(sum > 0) {
			bits[bit] = 1;
		} else {
			bits[bit] = 0;
		}
		PrintToScrollback("bit %d sum %d", bit, sum);
	}

	for(bit = 0; bit < 64; bit++) {
		int j;
		int sum = 0;
		for(j = 0; j < 16; j++) {
			sum += GraphBuffer[i++];
		}
		if(sum > 0 && bits[bit] != 1) {
			PrintToScrollback("oops1 at %d", bit);
		}
		if(sum < 0 && bits[bit] != 0) {
			PrintToScrollback("oops2 at %d", bit);
		}
	}

	GraphTraceLen = 32*64;
	i = 0;
	int phase = 0;
	for(bit = 0; bit < 64; bit++) {
		if(bits[bit] == 0) {
			phase = 0;
		} else {
			phase = 1;
		}
		int j;
		for(j = 0; j < 32; j++) {
			GraphBuffer[i++] = phase;
			phase = !phase;
		}
	}

	RepaintGraphWindow();
}

/*
 * Generic command to demodulate ASK. bit length in argument.
 * Giving the bit length helps discriminate ripple effects
 * upon zero crossing for noisy traces.
 *
 * Second is convention: positive or negative (High mod means zero
 * or high mod means one)
 *
 * Updates the Graph trace with 0/1 values
 *
 * Arguments:
 * sl : bit length in terms of number of samples per bit
 *      (use yellow/purple markers to compute).
 * c : 0 or 1
 */

static void Cmdaskdemod(char *str) {
	int i;
	int sign = 1;
	int n = 0;
	int c = 0;
	int t1 = 0;

	// TODO: complain if we do not give 2 arguments here !
	sscanf(str, "%i %i", &n, &c);
	if (c == 0) {
		c = 1 ;
	} else {
		c = -1;
	}

	if (GraphBuffer[0]*c > 0) {
		GraphBuffer[0] = 1;
	} else {
		GraphBuffer[0] = 0;
	}
	for(i=1;i<GraphTraceLen;i++) {
		/* Analyse signal within the symbol length */
		/* Decide if we crossed a zero */
		if (GraphBuffer[i]*sign < 0) {
			 /* Crossed a zero, check if this is a ripple or not */
			if ( (i-t1) > n/4 ) {
				sign = -sign;
				t1=i;
				if (GraphBuffer[i]*c > 0){
					GraphBuffer[i]=1;
				} else {
					GraphBuffer[i]=0;
				}
			} else {
			/* This is a ripple, set the current sample value
			   to the same as previous */
				GraphBuffer[i] = GraphBuffer[i-1];
			}
		} else {
			GraphBuffer[i] = GraphBuffer[i-1];
		}
	}
	RepaintGraphWindow();
}


/*
 * Manchester demodulate a bitstream. The bitstream needs to be already in
 * the GraphBuffer as 0 and 1 values
 *
 * Give the clock rate as argument in order to help the sync - the algorithm
 * resyncs at each pulse anyway.
 *
 * Not optimized by any means, this is the 1st time I'm writing this type of
 * routine, feel free to improve...
 *
 * 1st argument: clock rate (as number of samples per clock rate)
 */
static void Cmdmanchesterdemod(char *str) {
	int i;
	int clock;
	int lastval;
	int lc = 0;
	int bitidx = 0;
	int bitidx2;


	sscanf(str, "%i", &clock);

	int tolerance = clock/4;
	/* Holds the decoded bitstream. */
	int BitStream[MAX_GRAPH_TRACE_LEN*2];
	int BitStream2[MAX_GRAPH_TRACE_LEN];

	/* Detect first transition */
	/* Lo-Hi (arbitrary) */
	for(i=1;i<GraphTraceLen;i++) {
		if (GraphBuffer[i-1]<GraphBuffer[i]) {
		lastval = i;
		BitStream[0]=0; // Previous state = 0;
		break;
		}
	}

	/* Then detect duration between 2 successive transitions */
	/* At this stage, GraphTrace is either 0 or 1 */
	for(bitidx = 1 ;i<GraphTraceLen;i++) {
		if (GraphBuffer[i-1] != GraphBuffer[i]) {
			lc = i-lastval;
			lastval = i;
			// Then switch depending on lc length:
			// Tolerance is 1/4 of clock rate (arbitrary)
			if ((lc-clock/2) < tolerance) {
				// Short pulse
				BitStream[bitidx++]=GraphBuffer[i-1];
			} else if ((lc-clock) < tolerance) {
				// Long pulse
				BitStream[bitidx++]=GraphBuffer[i-1];
				BitStream[bitidx++]=GraphBuffer[i-1];
			} else {
				// Error
				PrintToScrollback("Warning: Manchester decode error for pulse width detection.");				
				PrintToScrollback("(too many of those messages mean either the stream is not Manchester encoded, or clock is wrong)");
			}
		}
	}

	// At this stage, we now have a bitstream of "01" ("1") or "10" ("0"), parse it into final decoded bitstream
	for (bitidx2 = 0; bitidx2<bitidx; bitidx2 += 2) {
		if ((BitStream[bitidx2] == 0) && (BitStream[bitidx2+1] == 1)) {
			BitStream2[bitidx2/2] = 1;
		} else if ((BitStream[bitidx2] == 1) && (BitStream[bitidx2+1] == 0)) {
			BitStream2[bitidx2/2] = 0;
		} else {
			// We cannot end up in this state, this means we are unsynchronized,
			// move up 1 bit:
			bitidx2++;
			PrintToScrollback("Unsynchronized, resync...");
			PrintToScrollback("(too many of those messages mean the stream is not Manchester encoded)");
		}
	}
	PrintToScrollback("Manchester decoded bitstream \n---------");
	// Now output the bitstream to the scrollback by line of 16 bits
	for (i = 0; i<bitidx/2; i+=16) {
		PrintToScrollback("%i %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i",
			BitStream2[i],
			BitStream2[i+1],
			BitStream2[i+2],
			BitStream2[i+3],
			BitStream2[i+4],
			BitStream2[i+5],
			BitStream2[i+6],
			BitStream2[i+7],
			BitStream2[i+8],
			BitStream2[i+9],
			BitStream2[i+10],
			BitStream2[i+11],
			BitStream2[i+12],
			BitStream2[i+13],
			BitStream2[i+14],
			BitStream2[i+15]);
	}
}



/*
 * Usage ???
 */
static void CmdHiddemod(char *str)
{
	if(GraphTraceLen < 4800) {
		PrintToScrollback("too short; need at least 4800 samples");
		return;
	}

	GraphTraceLen = 4800;
	int i;
	for(i = 0; i < GraphTraceLen; i++) {
		if(GraphBuffer[i] < 0) {
			GraphBuffer[i] = 0;
		} else {
			GraphBuffer[i] = 1;
		}
	}
	RepaintGraphWindow();
}

static void CmdPlot(char *str)
{
	ShowGraphWindow();
}

static void CmdHide(char *str)
{
	HideGraphWindow();
}

static void CmdScale(char *str)
{
	CursorScaleFactor = atoi(str);
	if(CursorScaleFactor == 0) {
		PrintToScrollback("bad, can't have zero scale");
		CursorScaleFactor = 1;
	}
	RepaintGraphWindow();
}

static void CmdSave(char *str)
{
	FILE *f = fopen(str, "w");
	if(!f) {
		PrintToScrollback("couldn't open '%s'", str);
		return;
	}
	int i;
	for(i = 0; i < GraphTraceLen; i++) {
		fprintf(f, "%d\n", GraphBuffer[i]);
	}
	fclose(f);
	PrintToScrollback("saved to '%s'", str);
}

static void CmdLoad(char *str)
{
	FILE *f = fopen(str, "r");
	if(!f) {
		PrintToScrollback("couldn't open '%s'", str);
		return;
	}

	GraphTraceLen = 0;
	char line[80];
	while(fgets(line, sizeof(line), f)) {
		GraphBuffer[GraphTraceLen] = atoi(line);
		GraphTraceLen++;
	}
	fclose(f);
	PrintToScrollback("loaded %d samples", GraphTraceLen);
	RepaintGraphWindow();
}

static void CmdHIDsimTAG(char *str)
{
	unsigned int hi=0, lo=0;
	int n=0, i=0;
	UsbCommand c;

	while (sscanf(&str[i++], "%1x", &n ) == 1) {
		hi=(hi<<4)|(lo>>28);
		lo=(lo<<4)|(n&0xf);
	}

	PrintToScrollback("Emulating tag with ID %x%16x", hi, lo);

	c.cmd = CMD_HID_SIM_TAG;
	c.ext1 = hi;
	c.ext2 = lo;
	SendCommand(&c, FALSE);
}

static void CmdLcdReset(char *str)
{
	UsbCommand c;
	c.cmd = CMD_LCD_RESET;
	c.ext1 = atoi(str);
	SendCommand(&c, FALSE);
}

static void CmdLcd(char *str)
{
	int i, j;
	UsbCommand c;
	c.cmd = CMD_LCD;
	sscanf(str, "%x %d", &i, &j);
	while (j--) {
		c.ext1 = i&0x1ff;
		SendCommand(&c, FALSE);
	}
}

static void CmdTest(char *str)
{
}

typedef void HandlerFunction(char *cmdline);

static struct {
	char			*name;
	HandlerFunction		*handler;
	char			*docString;
} CommandTable[] = {
	"tune",				CmdTune,			"measure antenna tuning",
	"tiread",			CmdTiread,			"read a TI-type 134 kHz tag",
	"tibits",			CmdTibits,			"get raw bits for TI-type LF tag",
	"tidemod",			CmdTidemod,			"demod raw bits for TI-type LF tag",
	"vchdemod",			CmdVchdemod,		"demod samples for VeriChip",
	"plot",				CmdPlot,			"show graph window",
	"hide",				CmdHide,			"hide graph window",
	"losim",			CmdLosim,			"simulate LF tag",
	"loread",			CmdLoread,			"read (125/134 kHz) LF ID-only tag",
	"losamples",		CmdLosamples,		"get raw samples for LF tag",
	"hisamples",		CmdHisamples,		"get raw samples for HF tag",
	"hisampless",		CmdHisampless,		"get signed raw samples, HF tag",
	"hisamplest",		CmdHi14readt,		"get samples HF, for testing",
	"higet",			CmdHi14read_sim,	"get samples HF, 'analog'",
	"bitsamples",		CmdBitsamples,		"get raw samples as bitstring",
	"hexsamples",		CmdHexsamples,		"dump big buffer as hex bytes",
	"hi15read",			CmdHi15read,		"read HF tag (ISO 15693)",
	"hi15reader",			CmdHi15reader,		"act like an ISO15693 reader", // new command greg
	"hi15sim",			CmdHi15tag,		"fake an ISO15693 tag", // new command greg
	"hi14read",			CmdHi14read,		"read HF tag (ISO 14443)",
	"hi14areader",		CmdHi14areader,		"act like an ISO14443 Type A reader",	// ## New reader command
	"hi15demod",		CmdHi15demod,		"demod ISO15693 from tag",
	"hi14bdemod",		CmdHi14bdemod,		"demod ISO14443 Type B from tag",
	"autocorr",			CmdAutoCorr,		"autocorrelation over window",
	"norm",				CmdNorm,			"normalize max/min to +/-500",
	"dec",				CmdDec,				"decimate",
	"hpf",				CmdHpf,				"remove DC offset from trace",
	"zerocrossings",	CmdZerocrossings,	"count time between zero-crossings",
	"ltrim",			CmdLtrim,			"trim from left of trace",
	"scale",			CmdScale,			"set cursor display scale",
	"flexdemod",		CmdFlexdemod,		"demod samples for FlexPass",
	"indalademod",		CmdIndalademod,		"demod samples for Indala",
	"save",				CmdSave,			"save trace (from graph window)",
	"load",				CmdLoad,			"load trace (to graph window",
	"hisimlisten",		CmdHisimlisten,		"get HF samples as fake tag",
	"hi14sim",			CmdHi14sim,			"fake ISO 14443 tag",
	"hi14asim",			CmdHi14asim,		"fake ISO 14443a tag",					// ## Simulate 14443a tag
	"hi14snoop",		CmdHi14snoop,		"eavesdrop ISO 14443",
	"hi14asnoop",		CmdHi14asnoop,		"eavesdrop ISO 14443 Type A",			// ## New snoop command
	"hi14list",			CmdHi14list,		"list ISO 14443 history",
	"hi14alist",		CmdHi14alist,		"list ISO 14443a history",				// ## New list command
	"hiddemod",			CmdHiddemod,		"HID Prox Card II (not optimal)",
	"hidfskdemod",		CmdHIDdemodFSK,		"HID FSK demodulator",
	"askdemod",		Cmdaskdemod,		"Attempt to demodulate simple ASK tags",
	"hidsimtag",		CmdHIDsimTAG,		"HID tag simulator",
	"mandemod",		Cmdmanchesterdemod,	"Try a Manchester demodulation on a binary stream",
	"fpgaoff",			CmdFPGAOff,			"set FPGA off",							// ## FPGA Control
	"lcdreset",			CmdLcdReset,		"Hardware reset LCD",
	"lcd",				CmdLcd,				"Send command/data to LCD",
	"test",				CmdTest,			"Placeholder command for testing new code",
	"quit",				CmdQuit,			"quit program"
};

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever the user types a command and
// then presses Enter, which the full command line that they typed.
//-----------------------------------------------------------------------------
void CommandReceived(char *cmd)
{
	int i;

	PrintToScrollback("> %s", cmd);

	if(strcmp(cmd, "help")==0) {
		PrintToScrollback("\r\nAvailable commands:");
		for(i = 0; i < sizeof(CommandTable) / sizeof(CommandTable[0]); i++) {
			char line[256];
			memset(line, ' ', sizeof(line));
			strcpy(line+2, CommandTable[i].name);
			line[strlen(line)] = ' ';
			sprintf(line+15, " -- %s", CommandTable[i].docString);
			PrintToScrollback("%s", line);
		}
		PrintToScrollback("");
		PrintToScrollback("and also: help, cls");
		return;
	}

	for(i = 0; i < sizeof(CommandTable) / sizeof(CommandTable[0]); i++) {
		char *name = CommandTable[i].name;
		if(memcmp(cmd, name, strlen(name))==0 &&
			(cmd[strlen(name)] == ' ' || cmd[strlen(name)] == '\0'))
		{
			cmd += strlen(name);
			while(*cmd == ' ') {
				cmd++;
			}
			(CommandTable[i].handler)(cmd);
			return;
		}
	}
	PrintToScrollback(">> bad command '%s'", cmd);
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever we received a packet over USB
// that we weren't necessarily expecting, for example a debug print.
//-----------------------------------------------------------------------------
void UsbCommandReceived(UsbCommand *c)
{
	switch(c->cmd) {
		case CMD_DEBUG_PRINT_STRING: {
			char s[100];
			if(c->ext1 > 70 || c->ext1 < 0) {
				c->ext1 = 0;
			}
			memcpy(s, c->d.asBytes, c->ext1);
			s[c->ext1] = '\0';
			PrintToScrollback("#db# %s", s);
			break;
		}

		case CMD_DEBUG_PRINT_INTEGERS:
			PrintToScrollback("#db# %08x, %08x, %08x\r\n", c->ext1, c->ext2, c->ext3);
			break;

		case CMD_MEASURED_ANTENNA_TUNING: {
			int zLf, zHf;
			int vLf125, vLf134, vHf;
			vLf125 = c->ext1 & 0xffff;
			vLf134 = c->ext1 >> 16;
			vHf = c->ext2;
			zLf = c->ext3 & 0xffff;
			zHf = c->ext3 >> 16;
			PrintToScrollback("# LF antenna @ %3d mA / %5d mV [%d ohms] 125Khz",
				vLf125/zLf, vLf125, zLf);
			PrintToScrollback("# LF antenna @ %3d mA / %5d mV [%d ohms] 134Khz",
				vLf134/((zLf*125)/134), vLf134, (zLf*125)/134);
			PrintToScrollback("# HF antenna @ %3d mA / %5d mV [%d ohms] 13.56Mhz",
				vHf/zHf, vHf, zHf);
			break;
		}
		default:
			PrintToScrollback("unrecognized command %08x\n", c->cmd);
			break;
	}
}
