//-----------------------------------------------------------------------------
// The actual command interpeter for what the user types at the command line.
// Jonathan Westhues, Sept 2005
// Edits by Gerhard de Koning Gans, Sep 2007 (##)
//-----------------------------------------------------------------------------
#ifdef WIN32
#include <windows.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <math.h>

#include "prox.h"
#include "../common/iso14443_crc.c"
#include "../common/crc16.c"
#include "../include/usb_cmd.h"

#define arraylen(x) (sizeof(x)/sizeof((x)[0]))
#define BIT(x) GraphBuffer[x * clock]
#define BITS (GraphTraceLen / clock)
#define SAMPLE_BUFFER_SIZE 64 // XXX check this

int go = 0;
static int CmdHisamplest(char *str, int nrlow);
unsigned int current_command = CMD_UNKNOWN;
unsigned int received_command = CMD_UNKNOWN;
static uint8_t sample_buf[SAMPLE_BUFFER_SIZE];

void wait_for_response(uint32_t response_type)
{
	while (received_command != response_type) {
#ifdef WIN32
		UsbCommand c;
		if (ReceiveCommandPoll(&c))
			UsbCommandReceived(&c);
		Sleep(0);
#else
		usleep(10000); // XXX ugh
#endif
	}
	received_command = CMD_UNKNOWN;
}

static void GetFromBigBuf(uint8_t *dest, int bytes)
{
	int n = bytes/4;

	if(n % 48 != 0) {
		PrintToScrollback("bad len in GetFromBigBuf");
		return;
	}

	int i;
	for(i = 0; i < n; i += 12) {
		UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {i, 0, 0}};
		SendCommand(&c);
		wait_for_response(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);

		memcpy(dest+(i*4), sample_buf, 48);
	}
}

static void CmdReset(char *str)
{
	UsbCommand c = {CMD_HARDWARE_RESET};
	SendCommand(&c);
}

static void CmdBuffClear(char *str)
{
	UsbCommand c = {CMD_BUFF_CLEAR};
	SendCommand(&c);
	CmdClearGraph(true);
}

static void CmdQuit(char *str)
{
	exit(0);
}

static void CmdHIDdemodFSK(char *str)
{
	UsbCommand c={CMD_HID_DEMOD_FSK};
	SendCommand(&c);
}

static void CmdTune(char *str)
{
	UsbCommand c={CMD_MEASURE_ANTENNA_TUNING};
	SendCommand(&c);
}

static void CmdHi15read(char *str)
{
	UsbCommand c={CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693};
	SendCommand(&c);
}

static void CmdHi14read(char *str)
{
	UsbCommand c = {CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443, {strtol(str, NULL, 0), 0, 0}};
	SendCommand(&c);
}


/* New command to read the contents of a SRI512 tag
 * SRI512 tags are ISO14443-B modulated memory tags,
 * this command just dumps the contents of the memory
 */
static void CmdSri512read(char *str)
{
	UsbCommand c={CMD_READ_SRI512_TAG, {strtol(str, NULL, 0), 0, 0}};
	SendCommand(&c);
}

/* New command to read the contents of a SRIX4K tag
 * SRIX4K tags are ISO14443-B modulated memory tags,
 * this command just dumps the contents of the memory/
 */
static void CmdSrix4kread(char *str)
{
	UsbCommand c={CMD_READ_SRIX4K_TAG, {strtol(str, NULL, 0), 0, 0}};
        SendCommand(&c);
}

static void CmdHi14areader(char *str)
{
	UsbCommand c={CMD_READER_ISO_14443a, {strtol(str, NULL, 0), 0, 0}};
	SendCommand(&c);
}

static void CmdHi14amifare(char *str)
{
	UsbCommand c={CMD_READER_MIFARE, {strtol(str, NULL, 0), 0, 0}};
	SendCommand(&c);
}

static void CmdHi15reader(char *str)
{
	UsbCommand c={CMD_READER_ISO_15693, {strtol(str, NULL, 0), 0, 0}};
	SendCommand(&c);
}

static void CmdHi15tag(char *str)
{
	UsbCommand c={CMD_SIMTAG_ISO_15693, {strtol(str, NULL, 0), 0, 0}};
	SendCommand(&c);
}

static void CmdHi14read_sim(char *str)
{
	UsbCommand c={CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443_SIM, {strtol(str, NULL, 0), 0, 0}};
	SendCommand(&c);
}

static void CmdHi14readt(char *str)
{
	UsbCommand c={CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443, {strtol(str, NULL, 0), 0, 0}};
	SendCommand(&c);

	//CmdHisamplest(str);
	while(CmdHisamplest(str,strtol(str, NULL, 0))==0) {
		SendCommand(&c);
	}
	RepaintGraphWindow();
}

static void CmdHisimlisten(char *str)
{
	UsbCommand c={CMD_SIMULATE_TAG_HF_LISTEN};
	SendCommand(&c);
}

static void CmdHi14sim(char *str)
{
	UsbCommand c={CMD_SIMULATE_TAG_ISO_14443};
	SendCommand(&c);
}

static void CmdHi14asim(char *str)	// ## simulate iso14443a tag
{					// ## greg - added ability to specify tag UID

	unsigned int hi=0, lo=0;
	int n=0, i=0;
	while (sscanf(&str[i++], "%1x", &n ) == 1) {
		hi=(hi<<4)|(lo>>28);
		lo=(lo<<4)|(n&0xf);
	}

	// c.arg should be set to *str or convert *str to the correct format for a uid
	UsbCommand c = {CMD_SIMULATE_TAG_ISO_14443a, {hi, lo, 0}};
	PrintToScrollback("Emulating 14443A TAG with UID %x%16x", hi, lo);
	SendCommand(&c);
}

static void CmdHi14snoop(char *str)
{
	UsbCommand c={CMD_SNOOP_ISO_14443};
	SendCommand(&c);
}

static void CmdHi14asnoop(char *str)
{
	UsbCommand c={CMD_SNOOP_ISO_14443a};
	SendCommand(&c);
}

static void CmdLegicRfRead(char *str)
{
	UsbCommand c={CMD_READER_LEGIC_RF};
	SendCommand(&c);
}

static void CmdFPGAOff(char *str)		// ## FPGA Control
{
	UsbCommand c={CMD_FPGA_MAJOR_MODE_OFF};
	SendCommand(&c);
}

/* clear out our graph window */
int CmdClearGraph(int redraw)
{
	int gtl = GraphTraceLen;
	GraphTraceLen = 0;

	if (redraw)
		RepaintGraphWindow();

	return gtl;
}

/* write a bit to the graph */
static void CmdAppendGraph(int redraw, int clock, int bit)
{
	int i;

	for (i = 0; i < (int)(clock/2); i++)
		GraphBuffer[GraphTraceLen++] = bit ^ 1;

	for (i = (int)(clock/2); i < clock; i++)
		GraphBuffer[GraphTraceLen++] = bit;

	if (redraw)
		RepaintGraphWindow();
}

/* Function is equivalent of loread + losamples + em410xread
 * looped until an EM410x tag is detected */
static void CmdEM410xwatch(char *str)
{
	char *zero = "";
	char *twok = "2000";
	go = 1;

	do
	{
		CmdLoread(zero);
		CmdLosamples(twok);
		CmdEM410xread(zero);
	} while (go);
}

/* Read the transmitted data of an EM4x50 tag
 * Format:
 *
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  CCCCCCCC                         <- column parity bits
 *  0                                <- stop bit
 *  LW                               <- Listen Window
 *
 * This pattern repeats for every block of data being transmitted.
 * Transmission starts with two Listen Windows (LW - a modulated
 * pattern of 320 cycles each (32/32/128/64/64)).
 *
 * Note that this data may or may not be the UID. It is whatever data
 * is stored in the blocks defined in the control word First and Last
 * Word Read values. UID is stored in block 32.
 */
static void CmdEM4x50read(char *str)
{
	int i, j, startblock, clock, skip, block, start, end, low, high;
	bool complete= false;
	int tmpbuff[MAX_GRAPH_TRACE_LEN / 64];
	char tmp[6];

	high= low= 0;
	clock= 64;

	/* first get high and low values */
	for (i = 0; i < GraphTraceLen; i++)
	{
		if (GraphBuffer[i] > high)
			high = GraphBuffer[i];
		else if (GraphBuffer[i] < low)
			low = GraphBuffer[i];
	}

	/* populate a buffer with pulse lengths */
	i= 0;
	j= 0;
	while(i < GraphTraceLen)
		{
		// measure from low to low
		while((GraphBuffer[i] > low) && (i<GraphTraceLen))
			++i;
		start= i;
		while((GraphBuffer[i] < high) && (i<GraphTraceLen))
			++i;
		while((GraphBuffer[i] > low) && (i<GraphTraceLen))
			++i;
		if (j>(MAX_GRAPH_TRACE_LEN/64)) {
			break;
		}
		tmpbuff[j++]= i - start;
		}

	/* look for data start - should be 2 pairs of LW (pulses of 192,128) */
	start= -1;
	skip= 0;
	for (i= 0; i < j - 4 ; ++i)
		{
		skip += tmpbuff[i];
		if (tmpbuff[i] >= 190 && tmpbuff[i] <= 194)
			if (tmpbuff[i+1] >= 126 && tmpbuff[i+1] <= 130)
				if (tmpbuff[i+2] >= 190 && tmpbuff[i+2] <= 194)
					if (tmpbuff[i+3] >= 126 && tmpbuff[i+3] <= 130)
						{
						start= i + 3;
						break;
						}
		}
	startblock= i + 3;

	/* skip over the remainder of the LW */
	skip += tmpbuff[i+1]+tmpbuff[i+2];
	while(skip < MAX_GRAPH_TRACE_LEN && GraphBuffer[skip] > low)
		++skip;
	skip += 8;

	/* now do it again to find the end */
	end= start;
	for (i += 3; i < j - 4 ; ++i)
		{
		end += tmpbuff[i];
		if (tmpbuff[i] >= 190 && tmpbuff[i] <= 194)
			if (tmpbuff[i+1] >= 126 && tmpbuff[i+1] <= 130)
				if (tmpbuff[i+2] >= 190 && tmpbuff[i+2] <= 194)
					if (tmpbuff[i+3] >= 126 && tmpbuff[i+3] <= 130)
						{
						complete= true;
						break;
						}
		}

	if (start >= 0)
		PrintToScrollback("Found data at sample: %i",skip);
	else
		{
		PrintToScrollback("No data found!");
		PrintToScrollback("Try again with more samples.");
		return;
		}

	if (!complete)
		{
		PrintToScrollback("*** Warning!");
		PrintToScrollback("Partial data - no end found!");
		PrintToScrollback("Try again with more samples.");
		}

	/* get rid of leading crap */
	sprintf(tmp,"%i",skip);
	CmdLtrim(tmp);

	/* now work through remaining buffer printing out data blocks */
	block= 0;
	i= startblock;
	while(block < 6)
		{
		PrintToScrollback("Block %i:", block);
		// mandemod routine needs to be split so we can call it for data
		// just print for now for debugging
		Cmdmanchesterdemod("i 64");
		skip= 0;
		/* look for LW before start of next block */
		for ( ; i < j - 4 ; ++i)
			{
			skip += tmpbuff[i];
			if (tmpbuff[i] >= 190 && tmpbuff[i] <= 194)
				if (tmpbuff[i+1] >= 126 && tmpbuff[i+1] <= 130)
					break;
			}
		while(GraphBuffer[skip] > low)
			++skip;
		skip += 8;
		sprintf(tmp,"%i",skip);
		CmdLtrim(tmp);
		start += skip;
		block++;
		}
}


/* Read the ID of an EM410x tag.
 * Format:
 *   1111 1111 1           <-- standard non-repeatable header
 *   XXXX [row parity bit] <-- 10 rows of 5 bits for our 40 bit tag ID
 *   ....
 *   CCCC                  <-- each bit here is parity for the 10 bits above in corresponding column
 *   0                     <-- stop bit, end of tag
 */
static void CmdEM410xread(char *str)
{
	int i, j, clock, header, rows, bit, hithigh, hitlow, first, bit2idx, high, low;
	int parity[4];
	char id[11];
	int retested = 0;
	int BitStream[MAX_GRAPH_TRACE_LEN];
	high = low = 0;

	/* Detect high and lows and clock */
	for (i = 0; i < GraphTraceLen; i++)
	{
		if (GraphBuffer[i] > high)
			high = GraphBuffer[i];
		else if (GraphBuffer[i] < low)
			low = GraphBuffer[i];
	}

	/* get clock */
	clock = GetClock(str, high);

	/* parity for our 4 columns */
	parity[0] = parity[1] = parity[2] = parity[3] = 0;
	header = rows = 0;

	/* manchester demodulate */
	bit = bit2idx = 0;
	for (i = 0; i < (int)(GraphTraceLen / clock); i++)
	{
		hithigh = 0;
		hitlow = 0;
		first = 1;

		/* Find out if we hit both high and low peaks */
		for (j = 0; j < clock; j++)
		{
			if (GraphBuffer[(i * clock) + j] == high)
				hithigh = 1;
			else if (GraphBuffer[(i * clock) + j] == low)
				hitlow = 1;

			/* it doesn't count if it's the first part of our read
			 because it's really just trailing from the last sequence */
			if (first && (hithigh || hitlow))
				hithigh = hitlow = 0;
			else
				first = 0;

			if (hithigh && hitlow)
				break;
		}

		/* If we didn't hit both high and low peaks, we had a bit transition */
		if (!hithigh || !hitlow)
			bit ^= 1;

		BitStream[bit2idx++] = bit;
	}

retest:
	/* We go till 5 before the graph ends because we'll get that far below */
	for (i = 1; i < bit2idx - 5; i++)
	{
		/* Step 2: We have our header but need our tag ID */
		if (header == 9 && rows < 10)
		{
			/* Confirm parity is correct */
			if ((BitStream[i] ^ BitStream[i+1] ^ BitStream[i+2] ^ BitStream[i+3]) == BitStream[i+4])
			{
				/* Read another byte! */
				sprintf(id+rows, "%x", (8 * BitStream[i]) + (4 * BitStream[i+1]) + (2 * BitStream[i+2]) + (1 * BitStream[i+3]));
				rows++;

				/* Keep parity info */
				parity[0] ^= BitStream[i];
				parity[1] ^= BitStream[i+1];
				parity[2] ^= BitStream[i+2];
				parity[3] ^= BitStream[i+3];

				/* Move 4 bits ahead */
				i += 4;
			}

			/* Damn, something wrong! reset */
			else
			{
				PrintToScrollback("Thought we had a valid tag but failed at word %d (i=%d)", rows + 1, i);

				/* Start back rows * 5 + 9 header bits, -1 to not start at same place */
				i -= 9 + (5 * rows) - 5;

				rows = header = 0;
			}
		}

		/* Step 3: Got our 40 bits! confirm column parity */
		else if (rows == 10)
		{
			/* We need to make sure our 4 bits of parity are correct and we have a stop bit */
			if (BitStream[i] == parity[0] && BitStream[i+1] == parity[1] &&
				BitStream[i+2] == parity[2] && BitStream[i+3] == parity[3] &&
				BitStream[i+4] == 0)
			{
				/* Sweet! */
				PrintToScrollback("EM410x Tag ID: %s", id);

				/* Stop any loops */
				go = 0;
				return;
			}

			/* Crap! Incorrect parity or no stop bit, start all over */
			else
			{
				rows = header = 0;

				/* Go back 59 bits (9 header bits + 10 rows at 4+1 parity) */
				i -= 59;
			}
		}

		/* Step 1: get our header */
		else if (header < 9)
		{
			/* Need 9 consecutive 1's */
			if (BitStream[i] == 1)
				header++;

			/* We don't have a header, not enough consecutive 1 bits */
			else
				header = 0;
		}
	}

	/* if we've already retested after flipping bits, return */
	if (retested++)
		return;

	/* if this didn't work, try flipping bits */
	for (i = 0; i < bit2idx; i++)
		BitStream[i] ^= 1;

	goto retest;
}

/* emulate an EM410X tag
 * Format:
 *   1111 1111 1           <-- standard non-repeatable header
 *   XXXX [row parity bit] <-- 10 rows of 5 bits for our 40 bit tag ID
 *   ....
 *   CCCC                  <-- each bit here is parity for the 10 bits above in corresponding column
 *   0                     <-- stop bit, end of tag
 */
static void CmdEM410xsim(char *str)
{
	int i, n, j, h, binary[4], parity[4];
	char *s = "0";

	/* clock is 64 in EM410x tags */
	int clock = 64;

	/* clear our graph */
	CmdClearGraph(0);

	/* write it out a few times */
	for (h = 0; h < 4; h++)
	{
		/* write 9 start bits */
		for (i = 0; i < 9; i++)
			CmdAppendGraph(0, clock, 1);

		/* for each hex char */
		parity[0] = parity[1] = parity[2] = parity[3] = 0;
		for (i = 0; i < 10; i++)
		{
			/* read each hex char */
			sscanf(&str[i], "%1x", &n);
			for (j = 3; j >= 0; j--, n/= 2)
				binary[j] = n % 2;

			/* append each bit */
			CmdAppendGraph(0, clock, binary[0]);
			CmdAppendGraph(0, clock, binary[1]);
			CmdAppendGraph(0, clock, binary[2]);
			CmdAppendGraph(0, clock, binary[3]);

			/* append parity bit */
			CmdAppendGraph(0, clock, binary[0] ^ binary[1] ^ binary[2] ^ binary[3]);

			/* keep track of column parity */
			parity[0] ^= binary[0];
			parity[1] ^= binary[1];
			parity[2] ^= binary[2];
			parity[3] ^= binary[3];
		}

		/* parity columns */
		CmdAppendGraph(0, clock, parity[0]);
		CmdAppendGraph(0, clock, parity[1]);
		CmdAppendGraph(0, clock, parity[2]);
		CmdAppendGraph(0, clock, parity[3]);

		/* stop bit */
		CmdAppendGraph(0, clock, 0);
	}

	/* modulate that biatch */
	Cmdmanchestermod(s);

	/* booyah! */
	RepaintGraphWindow();

	CmdLosim(s);
}

static void ChkBitstream(char *str)
{
	int i;

	/* convert to bitstream if necessary */
	for (i = 0; i < (int)(GraphTraceLen / 2); i++)
	{
		if (GraphBuffer[i] > 1 || GraphBuffer[i] < 0)
		{
			Cmdbitstream(str);
			break;
		}
	}
}

static void CmdLosim(char *str)
{
	int i;

	/* convert to bitstream if necessary */
	ChkBitstream(str);

	for (i = 0; i < GraphTraceLen; i += 48) {
		UsbCommand c={CMD_DOWNLOADED_SIM_SAMPLES_125K, {i, 0, 0}};
		int j;
		for(j = 0; j < 48; j++) {
			c.d.asBytes[j] = GraphBuffer[i+j];
		}
		SendCommand(&c);
	}

	UsbCommand c={CMD_SIMULATE_TAG_125K, {GraphTraceLen, 0, 0}};
	SendCommand(&c);
}

static void CmdLosimBidir(char *str)
{
	/* Set ADC to twice the carrier for a slight supersampling */
	UsbCommand c={CMD_LF_SIMULATE_BIDIR, {47, 384, 0}};
	SendCommand(&c);
}

static void CmdLoread(char *str)
{
	UsbCommand c={CMD_ACQUIRE_RAW_ADC_SAMPLES_125K};
	// 'h' means higher-low-frequency, 134 kHz
	if(*str == 'h') {
		c.arg[0] = 1;
	} else if (*str == '\0') {
		c.arg[0] = 0;
	} else {
		PrintToScrollback("use 'loread' or 'loread h'");
		return;
	}
	SendCommand(&c);
}

static void CmdDetectReader(char *str)
{
	UsbCommand c={CMD_LISTEN_READER_FIELD};
	// 'l' means LF - 125/134 kHz
	if(*str == 'l') {
		c.arg[0] = 1;
	} else if (*str == 'h') {
		c.arg[0] = 2;
	} else if (*str != '\0') {
		PrintToScrollback("use 'detectreader' or 'detectreader l' or 'detectreader h'");
		return;
	}
	SendCommand(&c);
}

/* send a command before reading */
static void CmdLoCommandRead(char *str)
{
	static char dummy[3];

	dummy[0]= ' ';

	UsbCommand c={CMD_MOD_THEN_ACQUIRE_RAW_ADC_SAMPLES_125K};
	sscanf(str, "%i %i %i %s %s", &c.arg[0], &c.arg[1], &c.arg[2], (char *) &c.d.asBytes,(char *) &dummy+1);
	// in case they specified 'h'
	strcpy((char *)&c.d.asBytes + strlen((char *)c.d.asBytes), dummy);
	SendCommand(&c);
}

static void CmdLosamples(char *str)
{
	int cnt = 0;
	int i, j, n;

	n=strtol(str, NULL, 0);
	if (n==0) n=128;
	if (n>16000) n=16000;

	PrintToScrollback("Reading %d samples\n", n);
	for(i = 0; i < n; i += 12) {
		UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {i, 0, 0}};
		SendCommand(&c);
		wait_for_response(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
		for(j = 0; j < 48; j++) {
			GraphBuffer[cnt++] = ((int)sample_buf[j]) - 128;
		}
	}
	PrintToScrollback("Done!\n");
	GraphTraceLen = n*4;
	RepaintGraphWindow();
}

static void CmdBitsamples(char *str)
{
	int cnt = 0;
	int i, j, k, n;

	n = 3072;
	for(i = 0; i < n; i += 12) {
		UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {i, 0, 0}};
		SendCommand(&c);
		wait_for_response(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);

		for(j = 0; j < 48; j++) {
			for(k = 0; k < 8; k++) {
				if(sample_buf[j] & (1 << (7 - k))) {
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
	int i, j, n;

	n = 1000;
	for(i = 0; i < n; i += 12) {
		UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {i, 0, 0}};
		SendCommand(&c);
		wait_for_response(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
		for(j = 0; j < 48; j++) {
			GraphBuffer[cnt++] = (int)(sample_buf[j]);
		}
	}

	GraphTraceLen = n*4;
	RepaintGraphWindow();
}

static int CmdHisamplest(char *str, int nrlow)
{
	int cnt = 0;
	int t1, t2;
	int i, j, n;
	int hasbeennull;
	int show;

	n = 1000;
	hasbeennull = 0;
	for(i = 0; i < n; i += 12) {
		UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {i, 0, 0}};
		SendCommand(&c);
		wait_for_response(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
		for(j = 0; j < 48; j++) {
			t2 = (int)(sample_buf[j]);
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
	int i, j, n;
	int requested = strtol(str, NULL, 0);
	int delivered = 0;

	if (requested == 0) {
		n = 12;
		requested = 12;
	} else {
		n = requested/4;
	}

	for(i = 0; i < n; i += 12) {
		UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {i, 0, 0}};
		SendCommand(&c);
		wait_for_response(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
		for (j = 0; j < 48; j += 8) {
			PrintToScrollback("%02x %02x %02x %02x %02x %02x %02x %02x",
				sample_buf[j+0],
				sample_buf[j+1],
				sample_buf[j+2],
				sample_buf[j+3],
				sample_buf[j+4],
				sample_buf[j+5],
				sample_buf[j+6],
				sample_buf[j+7],
				sample_buf[j+8]
			);
			delivered += 8;
			if (delivered >= requested)
				break;
		}
		if (delivered >= requested)
			break;
	}
}

static void CmdHisampless(char *str)
{
	int cnt = 0;
	int i, j;
	int n = strtol(str, NULL, 0);

	if(n == 0) {
		n = 1000;
	} else {
		n/= 4;
	}

	for(i = 0; i < n; i += 12) {
		UsbCommand c = {CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K, {i, 0, 0}};
		SendCommand(&c);
		wait_for_response(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K);
		for(j = 0; j < 48; j++) {
			GraphBuffer[cnt++] = (int)(sample_buf[j]);
		}
	}
	GraphTraceLen = cnt;

	RepaintGraphWindow();
}

static uint16_t Iso15693Crc(uint8_t *v, int n)
{
	uint32_t reg;
	int i, j;

	reg = 0xffff;
	for(i = 0; i < n; i++) {
		reg = reg ^ ((uint32_t)v[i]);
		for (j = 0; j < 8; j++) {
			if (reg & 0x0001) {
				reg = (reg >> 1) ^ 0x8408;
			} else {
				reg = (reg >> 1);
			}
		}
	}

	return (uint16_t)~reg;
}

static void CmdHi14bdemod(char *str)
{
	int i, j, iold;
	int isum, qsum;
	int outOfWeakAt;
	bool negateI, negateQ;

	uint8_t data[256];
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

		uint16_t shiftReg = 0;
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

	uint8_t first, second;
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
	uint8_t got[960];
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

		bool isResponse;
		int timestamp = *((uint32_t *)(got+i));
		if(timestamp & 0x80000000) {
			timestamp &= 0x7fffffff;
			isResponse = 1;
		} else {
			isResponse = 0;
		}
		int metric = *((uint32_t *)(got+i+4));

		int len = got[i+8];

		if(len > 100) {
			break;
		}
		if(i + len >= 900) {
			break;
		}

		uint8_t *frame = (got+i+9);

		char line[1000] = "";
		int j;
		for(j = 0; j < len; j++) {
			sprintf(line+(j*3), "%02x  ", frame[j]);
		}

		char *crc;
		if(len > 2) {
			uint8_t b1, b2;
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
	uint8_t got[1920];
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

		bool isResponse;
		int timestamp = *((uint32_t *)(got+i));
		if(timestamp & 0x80000000) {
			timestamp &= 0x7fffffff;
			isResponse = 1;
		} else {
			isResponse = 0;
		}

		int metric = 0;
		int parityBits = *((uint32_t *)(got+i+4));
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

		uint8_t *frame = (got+i+9);

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
			uint8_t b1, b2;
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
	uint8_t outBuf[20];
	memset(outBuf, 0, sizeof(outBuf));
	uint8_t mask = 0x01;
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

static void CmdFSKdemod(char *cmdline)
{
	static const int LowTone[]  = {
		1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
		1,  1,  1,  1,  1, -1, -1, -1, -1, -1
	};
	static const int HighTone[] = {
		1,  1,  1,  1,  1,     -1, -1, -1, -1,
		1,  1,  1,  1,         -1, -1, -1, -1,
		1,  1,  1,  1,         -1, -1, -1, -1,
		1,  1,  1,  1,         -1, -1, -1, -1,
		1,  1,  1,  1,         -1, -1, -1, -1,
		1,  1,  1,  1,     -1, -1, -1, -1, -1,
	};

	int lowLen = sizeof(LowTone)/sizeof(int);
	int highLen = sizeof(HighTone)/sizeof(int);
	int convLen = (highLen>lowLen)?highLen:lowLen;
	uint32_t hi = 0, lo = 0;

	int i, j;
	int minMark=0, maxMark=0;

	for(i = 0; i < GraphTraceLen - convLen; i++) {
		int lowSum = 0, highSum = 0;

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
		// 10 and 8 are f_s divided by f_l and f_h, rounded
		for(j = 0; j < 10; j++) {
			lowTot += (GraphBuffer[i+j] & 0xffff);
		}
		for(j = 0; j < 8; j++) {
			highTot += (GraphBuffer[i+j] >> 16);
		}
		GraphBuffer[i] = lowTot - highTot;
		if (GraphBuffer[i]>maxMark) maxMark=GraphBuffer[i];
		if (GraphBuffer[i]<minMark) minMark=GraphBuffer[i];
	}

	GraphTraceLen -= (convLen + 16);

	RepaintGraphWindow();

	// Find bit-sync (3 lo followed by 3 high)
	int max = 0, maxPos = 0;
	for(i = 0; i < 6000; i++) {
		int dec = 0;
		for(j = 0; j < 3*lowLen; j++) {
			dec -= GraphBuffer[i+j];
		}
		for(; j < 3*(lowLen + highLen ); j++) {
			dec += GraphBuffer[i+j];
		}
		if(dec > max) {
			max = dec;
			maxPos = i;
		}
	}

	// place start of bit sync marker in graph
	GraphBuffer[maxPos] = maxMark;
	GraphBuffer[maxPos+1] = minMark;

	maxPos += j;

	// place end of bit sync marker in graph
	GraphBuffer[maxPos] = maxMark;
	GraphBuffer[maxPos+1] = minMark;

	PrintToScrollback("actual data bits start at sample %d", maxPos);
	PrintToScrollback("length %d/%d", highLen, lowLen);

	uint8_t bits[46];
	bits[sizeof(bits)-1] = '\0';

	// find bit pairs and manchester decode them
	for(i = 0; i < arraylen(bits)-1; i++) {
		int dec = 0;
		for(j = 0; j < lowLen; j++) {
			dec -= GraphBuffer[maxPos+j];
		}
		for(; j < lowLen + highLen; j++) {
			dec += GraphBuffer[maxPos+j];
		}
		maxPos += j;
		// place inter bit marker in graph
		GraphBuffer[maxPos] = maxMark;
		GraphBuffer[maxPos+1] = minMark;

		// hi and lo form a 64 bit pair
		hi = (hi<<1)|(lo>>31);
		lo = (lo<<1);
		// store decoded bit as binary (in hi/lo) and text (in bits[])
		if(dec<0) {
			bits[i] = '1';
			lo|=1;
		} else {
			bits[i] = '0';
		}
	}
	PrintToScrollback("bits: '%s'", bits);
	PrintToScrollback("hex: %08x %08x", hi, lo);
}

// read a TI tag and return its ID
static void CmdTIRead(char *str)
{
	UsbCommand c={CMD_READ_TI_TYPE};
	SendCommand(&c);
}

// write new data to a r/w TI tag
static void CmdTIWrite(char *str)
{
	UsbCommand c={CMD_WRITE_TI_TYPE};
	int res=0;

	res = sscanf(str, "0x%x 0x%x 0x%x ", &c.arg[0], &c.arg[1], &c.arg[2]);
	if (res == 2) c.arg[2]=0;
	if (res<2)
		PrintToScrollback("Please specify the data as two hex strings, optionally the CRC as a third");
	else
		SendCommand(&c);
}

static void CmdTIDemod(char *cmdline)
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

// 2M*16/134.2k = 238
 static const int LowTone[] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		 -1, -1
 };
// 2M*16/123.2k = 260
 static const int HighTone[] = {
	1, 1, 1, 1, 1, 1, 1, 1,		-1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		-1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1,			-1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1,			-1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1,			-1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1,			-1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		-1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		-1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1,			-1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1,			-1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1,			-1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		-1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		-1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1,		-1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1,			-1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1,			-1, -1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1,			-1, -1, -1, -1, -1, -1, -1,
	1, 1, 1, 1, 1, 1, 1, 1
 };
	int lowLen = sizeof(LowTone)/sizeof(int);
	int highLen = sizeof(HighTone)/sizeof(int);
	int convLen = (highLen>lowLen)?highLen:lowLen;
	uint16_t crc;
	int i, j, TagType;
	int lowSum = 0, highSum = 0;;
	int lowTot = 0, highTot = 0;

	for(i = 0; i < GraphTraceLen - convLen; i++) {
		lowSum = 0;
		highSum = 0;;

		for(j = 0; j < lowLen; j++) {
			lowSum += LowTone[j]*GraphBuffer[i+j];
		}
		for(j = 0; j < highLen; j++) {
			highSum += HighTone[j]*GraphBuffer[i+j];
		}
		lowSum = abs((100*lowSum) / lowLen);
		highSum = abs((100*highSum) / highLen);
		lowSum = (lowSum<0)?-lowSum:lowSum;
		highSum = (highSum<0)?-highSum:highSum;

		GraphBuffer[i] = (highSum << 16) | lowSum;
	}

	for(i = 0; i < GraphTraceLen - convLen - 16; i++) {
		lowTot = 0;
		highTot = 0;
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

	// TI tag data format is 16 prebits, 8 start bits, 64 data bits,
	// 16 crc CCITT bits, 8 stop bits, 15 end bits

	// the 16 prebits are always low
	// the 8 start and stop bits of a tag must match
	// the start/stop prebits of a ro tag are 01111110
	// the start/stop prebits of a rw tag are 11111110
  // the 15 end bits of a ro tag are all low
  // the 15 end bits of a rw tag match bits 15-1 of the data bits

	// Okay, so now we have unsliced soft decisions;
	// find bit-sync, and then get some bits.
	// look for 17 low bits followed by 6 highs (common pattern for ro and rw tags)
	int max = 0, maxPos = 0;
	for(i = 0; i < 6000; i++) {
		int j;
		int dec = 0;
		// searching 17 consecutive lows
		for(j = 0; j < 17*lowLen; j++) {
			dec -= GraphBuffer[i+j];
		}
		// searching 7 consecutive highs
		for(; j < 17*lowLen + 6*highLen; j++) {
			dec += GraphBuffer[i+j];
		}
		if(dec > max) {
			max = dec;
			maxPos = i;
		}
	}

	// place a marker in the buffer to visually aid location
	// of the start of sync
	GraphBuffer[maxPos] = 800;
	GraphBuffer[maxPos+1] = -800;

	// advance pointer to start of actual data stream (after 16 pre and 8 start bits)
	maxPos += 17*lowLen;
	maxPos += 6*highLen;

	// place a marker in the buffer to visually aid location
	// of the end of sync
	GraphBuffer[maxPos] = 800;
	GraphBuffer[maxPos+1] = -800;

	PrintToScrollback("actual data bits start at sample %d", maxPos);

	PrintToScrollback("length %d/%d", highLen, lowLen);

	uint8_t bits[1+64+16+8+16];
	bits[sizeof(bits)-1] = '\0';

	uint32_t shift3 = 0x7e000000, shift2 = 0, shift1 = 0, shift0 = 0;

	for(i = 0; i < arraylen(bits)-1; i++) {
		int high = 0;
		int low = 0;
		int j;
		for(j = 0; j < lowLen; j++) {
			low -= GraphBuffer[maxPos+j];
		}
		for(j = 0; j < highLen; j++) {
			high += GraphBuffer[maxPos+j];
		}

		if(high > low) {
			bits[i] = '1';
			maxPos += highLen;
			// bitstream arrives lsb first so shift right
			shift3 |= (1<<31);
		} else {
			bits[i] = '.';
			maxPos += lowLen;
		}

		// 128 bit right shift register
	  shift0 = (shift0>>1) | (shift1 << 31);
	  shift1 = (shift1>>1) | (shift2 << 31);
	  shift2 = (shift2>>1) | (shift3 << 31);
	  shift3 >>= 1;

		// place a marker in the buffer between bits to visually aid location
		GraphBuffer[maxPos] = 800;
		GraphBuffer[maxPos+1] = -800;
	}
	PrintToScrollback("Info: raw tag bits = %s", bits);

	TagType = (shift3>>8)&0xff;
	if ( TagType != ((shift0>>16)&0xff) ) {
		PrintToScrollback("Error: start and stop bits do not match!");
		return;
	}
	else if (TagType == 0x7e) {
		PrintToScrollback("Info: Readonly TI tag detected.");
		return;
	}
	else if (TagType == 0xfe) {
		PrintToScrollback("Info: Rewriteable TI tag detected.");

	  // put 64 bit data into shift1 and shift0
	  shift0 = (shift0>>24) | (shift1 << 8);
	  shift1 = (shift1>>24) | (shift2 << 8);

		// align 16 bit crc into lower half of shift2
	  shift2 = ((shift2>>24) | (shift3 << 8)) & 0x0ffff;

		// align 16 bit "end bits" or "ident" into lower half of shift3
	  shift3 >>= 16;

		// only 15 bits compare, last bit of ident is not valid
		if ( (shift3^shift0)&0x7fff ) {
			PrintToScrollback("Error: Ident mismatch!");
		}
		// WARNING the order of the bytes in which we calc crc below needs checking
		// i'm 99% sure the crc algorithm is correct, but it may need to eat the
		// bytes in reverse or something
		// calculate CRC
		crc=0;
	 	crc = update_crc16(crc, (shift0)&0xff);
		crc = update_crc16(crc, (shift0>>8)&0xff);
		crc = update_crc16(crc, (shift0>>16)&0xff);
		crc = update_crc16(crc, (shift0>>24)&0xff);
		crc = update_crc16(crc, (shift1)&0xff);
		crc = update_crc16(crc, (shift1>>8)&0xff);
		crc = update_crc16(crc, (shift1>>16)&0xff);
		crc = update_crc16(crc, (shift1>>24)&0xff);
		PrintToScrollback("Info: Tag data = %08X%08X", shift1, shift0);
		if (crc != (shift2&0xffff)) {
			PrintToScrollback("Error: CRC mismatch, calculated %04X, got ^04X", crc, shift2&0xffff);
		} else {
			PrintToScrollback("Info: CRC %04X is good", crc);
		}
	}
	else {
		PrintToScrollback("Unknown tag type.");
		return;
	}
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

static void CmdAmp(char *str)
{
	int i, rising, falling;
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
		rising= falling= 0;
		for(i = 0; i < GraphTraceLen; i++) {
			if(GraphBuffer[i+1] < GraphBuffer[i]) {
				if(rising) {
 					GraphBuffer[i]= max;
					rising= 0;
					}
				falling= 1;
				}
			if(GraphBuffer[i+1] > GraphBuffer[i]) {
				if(falling) {
					GraphBuffer[i]= min;
					falling= 0;
					}
				rising= 1;
				}
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

static void CmdThreshold(char *str)
{
	int i;
	int threshold = atoi(str);

	for(i = 0; i < GraphTraceLen; i++) {
		if(GraphBuffer[i]>= threshold)
			GraphBuffer[i]=1;
		else
			GraphBuffer[i]=-1;
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
	uint8_t rawbits[4096];
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
	uint8_t bits[224];
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

	uint8_t bits[64];

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
 * Generic command to demodulate ASK.
 *
 * Argument is convention: positive or negative (High mod means zero
 * or high mod means one)
 *
 * Updates the Graph trace with 0/1 values
 *
 * Arguments:
 * c : 0 or 1
 */

static void Cmdaskdemod(char *str) {
	int i;
	int c, high = 0, low = 0;

	// TODO: complain if we do not give 2 arguments here !
	// (AL - this doesn't make sense! we're only using one argument!!!)
	sscanf(str, "%i", &c);

	/* Detect high and lows and clock */
	// (AL - clock???)
	for (i = 0; i < GraphTraceLen; i++)
	{
		if (GraphBuffer[i] > high)
			high = GraphBuffer[i];
		else if (GraphBuffer[i] < low)
			low = GraphBuffer[i];
	}
	if(c != 0 && c != 1) {
		PrintToScrollback("Invalid argument: %s",str);
		return;
		}

	if (GraphBuffer[0] > 0) {
		GraphBuffer[0] = 1-c;
	} else {
		GraphBuffer[0] = c;
	}
	for(i=1;i<GraphTraceLen;i++) {
		/* Transitions are detected at each peak
		 * Transitions are either:
		 * - we're low: transition if we hit a high
		 * - we're high: transition if we hit a low
		 * (we need to do it this way because some tags keep high or
		 * low for long periods, others just reach the peak and go
		 * down)
		 */
		if ((GraphBuffer[i]==high) && (GraphBuffer[i-1] == c)) {
					GraphBuffer[i]=1-c;
		} else if ((GraphBuffer[i]==low) && (GraphBuffer[i-1] == (1-c))){
			GraphBuffer[i] = c;
		} else {
			/* No transition */
			GraphBuffer[i] = GraphBuffer[i-1];
		}
	}
	RepaintGraphWindow();
}

/* Print our clock rate */
static void Cmddetectclockrate(char *str)
{
	int clock = detectclock(0);
	PrintToScrollback("Auto-detected clock rate: %d", clock);
}

/*
 * Detect clock rate
 */
int detectclock(int peak)
{
	int i;
	int clock = 0xFFFF;
	int lastpeak = 0;

	/* Detect peak if we don't have one */
	if (!peak)
		for (i = 0; i < GraphTraceLen; i++)
			if (GraphBuffer[i] > peak)
				peak = GraphBuffer[i];

	for (i = 1; i < GraphTraceLen; i++)
	{
		/* If this is the beginning of a peak */
		if (GraphBuffer[i-1] != GraphBuffer[i] && GraphBuffer[i] == peak)
		{
			/* Find lowest difference between peaks */
			if (lastpeak && i - lastpeak < clock)
			{
				clock = i - lastpeak;
			}
			lastpeak = i;
		}
	}

	return clock;
}

/* Get or auto-detect clock rate */
int GetClock(char *str, int peak)
{
	int clock;

	sscanf(str, "%i", &clock);
	if (!strcmp(str, ""))
		clock = 0;

	/* Auto-detect clock */
	if (!clock)
	{
		clock = detectclock(peak);

		/* Only print this message if we're not looping something */
		if (!go)
			PrintToScrollback("Auto-detected clock rate: %d", clock);
	}

	return clock;
}

/*
 * Convert to a bitstream
 */
static void Cmdbitstream(char *str) {
	int i, j;
	int bit;
	int gtl;
	int clock;
	int low = 0;
	int high = 0;
	int hithigh, hitlow, first;

	/* Detect high and lows and clock */
	for (i = 0; i < GraphTraceLen; i++)
	{
		if (GraphBuffer[i] > high)
			high = GraphBuffer[i];
		else if (GraphBuffer[i] < low)
			low = GraphBuffer[i];
	}

	/* Get our clock */
	clock = GetClock(str, high);

	gtl = CmdClearGraph(0);

	bit = 0;
	for (i = 0; i < (int)(gtl / clock); i++)
	{
		hithigh = 0;
		hitlow = 0;
		first = 1;

		/* Find out if we hit both high and low peaks */
		for (j = 0; j < clock; j++)
		{
			if (GraphBuffer[(i * clock) + j] == high)
				hithigh = 1;
			else if (GraphBuffer[(i * clock) + j] == low)
				hitlow = 1;

			/* it doesn't count if it's the first part of our read
			 because it's really just trailing from the last sequence */
			if (first && (hithigh || hitlow))
				hithigh = hitlow = 0;
			else
				first = 0;

			if (hithigh && hitlow)
				break;
		}

		/* If we didn't hit both high and low peaks, we had a bit transition */
		if (!hithigh || !hitlow)
			bit ^= 1;

		CmdAppendGraph(0, clock, bit);
//		for (j = 0; j < (int)(clock/2); j++)
//			GraphBuffer[(i * clock) + j] = bit ^ 1;
//		for (j = (int)(clock/2); j < clock; j++)
//			GraphBuffer[(i * clock) + j] = bit;
	}

	RepaintGraphWindow();
}

/* Modulate our data into manchester */
static void Cmdmanchestermod(char *str)
{
	int i, j;
	int clock;
	int bit, lastbit, wave;

	/* Get our clock */
	clock = GetClock(str, 0);

	wave = 0;
	lastbit = 1;
	for (i = 0; i < (int)(GraphTraceLen / clock); i++)
	{
		bit = GraphBuffer[i * clock] ^ 1;

		for (j = 0; j < (int)(clock/2); j++)
			GraphBuffer[(i * clock) + j] = bit ^ lastbit ^ wave;
		for (j = (int)(clock/2); j < clock; j++)
			GraphBuffer[(i * clock) + j] = bit ^ lastbit ^ wave ^ 1;

		/* Keep track of how we start our wave and if we changed or not this time */
		wave ^= bit ^ lastbit;
		lastbit = bit;
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
 *               Typical values can be 64, 32, 128...
 */
static void Cmdmanchesterdemod(char *str) {
	int i, j, invert= 0;
	int bit;
	int clock;
	int lastval;
	int low = 0;
	int high = 0;
	int hithigh, hitlow, first;
	int lc = 0;
	int bitidx = 0;
	int bit2idx = 0;
	int warnings = 0;

	/* check if we're inverting output */
 	if(*str == 'i')
	{
		PrintToScrollback("Inverting output");
		invert= 1;
		do
			++str;
		while(*str == ' '); // in case a 2nd argument was given
	}

	/* Holds the decoded bitstream: each clock period contains 2 bits       */
	/* later simplified to 1 bit after manchester decoding.                 */
	/* Add 10 bits to allow for noisy / uncertain traces without aborting   */
	/* int BitStream[GraphTraceLen*2/clock+10]; */

	/* But it does not work if compiling on WIndows: therefore we just allocate a */
	/* large array */
	int BitStream[MAX_GRAPH_TRACE_LEN];

	/* Detect high and lows */
	for (i = 0; i < GraphTraceLen; i++)
	{
		if (GraphBuffer[i] > high)
			high = GraphBuffer[i];
		else if (GraphBuffer[i] < low)
			low = GraphBuffer[i];
	}

	/* Get our clock */
	clock = GetClock(str, high);

	int tolerance = clock/4;

	/* Detect first transition */
	/* Lo-Hi (arbitrary)       */
	/* skip to the first high */
	for (i= 0; i < GraphTraceLen; i++)
		if(GraphBuffer[i] == high)
			break;
	/* now look for the first low */
	for (; i < GraphTraceLen; i++)
	{
		if (GraphBuffer[i] == low)
		{
 			lastval = i;
			break;
		}
	}

	/* If we're not working with 1/0s, demod based off clock */
	if (high != 1)
	{
		bit = 0; /* We assume the 1st bit is zero, it may not be
		          * the case: this routine (I think) has an init problem.
		          * Ed.
		          */
		for (; i < (int)(GraphTraceLen / clock); i++)
		{
			hithigh = 0;
			hitlow = 0;
			first = 1;

			/* Find out if we hit both high and low peaks */
			for (j = 0; j < clock; j++)
			{
				if (GraphBuffer[(i * clock) + j] == high)
					hithigh = 1;
				else if (GraphBuffer[(i * clock) + j] == low)
					hitlow = 1;

				/* it doesn't count if it's the first part of our read
				   because it's really just trailing from the last sequence */
				if (first && (hithigh || hitlow))
					hithigh = hitlow = 0;
				else
					first = 0;

				if (hithigh && hitlow)
					break;
			}

			/* If we didn't hit both high and low peaks, we had a bit transition */
			if (!hithigh || !hitlow)
				bit ^= 1;

			BitStream[bit2idx++] = bit ^ invert;
		}
	}

	/* standard 1/0 bitstream */
	else
	{

		/* Then detect duration between 2 successive transitions */
		for (bitidx = 1; i < GraphTraceLen; i++)
		{
			if (GraphBuffer[i-1] != GraphBuffer[i])
			{
			lc = i-lastval;
			lastval = i;

			// Error check: if bitidx becomes too large, we do not
			// have a Manchester encoded bitstream or the clock is really
			// wrong!
			if (bitidx > (GraphTraceLen*2/clock+8) ) {
				PrintToScrollback("Error: the clock you gave is probably wrong, aborting.");
				return;
			}
			// Then switch depending on lc length:
			// Tolerance is 1/4 of clock rate (arbitrary)
			if (abs(lc-clock/2) < tolerance) {
				// Short pulse : either "1" or "0"
				BitStream[bitidx++]=GraphBuffer[i-1];
			} else if (abs(lc-clock) < tolerance) {
				// Long pulse: either "11" or "00"
				BitStream[bitidx++]=GraphBuffer[i-1];
				BitStream[bitidx++]=GraphBuffer[i-1];
			} else {
				// Error
					warnings++;
				PrintToScrollback("Warning: Manchester decode error for pulse width detection.");
				PrintToScrollback("(too many of those messages mean either the stream is not Manchester encoded, or clock is wrong)");

					if (warnings > 100)
					{
						PrintToScrollback("Error: too many detection errors, aborting.");
						return;
					}
				}
			}
		}

		// At this stage, we now have a bitstream of "01" ("1") or "10" ("0"), parse it into final decoded bitstream
		// Actually, we overwrite BitStream with the new decoded bitstream, we just need to be careful
		// to stop output at the final bitidx2 value, not bitidx
		for (i = 0; i < bitidx; i += 2) {
			if ((BitStream[i] == 0) && (BitStream[i+1] == 1)) {
				BitStream[bit2idx++] = 1 ^ invert;
		} else if ((BitStream[i] == 1) && (BitStream[i+1] == 0)) {
			BitStream[bit2idx++] = 0 ^ invert;
		} else {
			// We cannot end up in this state, this means we are unsynchronized,
			// move up 1 bit:
			i++;
				warnings++;
			PrintToScrollback("Unsynchronized, resync...");
			PrintToScrollback("(too many of those messages mean the stream is not Manchester encoded)");

				if (warnings > 100)
				{
					PrintToScrollback("Error: too many decode errors, aborting.");
					return;
				}
			}
		}
	}

	PrintToScrollback("Manchester decoded bitstream");
	// Now output the bitstream to the scrollback by line of 16 bits
	for (i = 0; i < (bit2idx-16); i+=16) {
		PrintToScrollback("%i %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i",
			BitStream[i],
			BitStream[i+1],
			BitStream[i+2],
			BitStream[i+3],
			BitStream[i+4],
			BitStream[i+5],
			BitStream[i+6],
			BitStream[i+7],
			BitStream[i+8],
			BitStream[i+9],
			BitStream[i+10],
			BitStream[i+11],
			BitStream[i+12],
			BitStream[i+13],
			BitStream[i+14],
			BitStream[i+15]);
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

static void CmdGrid(char *str)
{
  	sscanf(str, "%i %i", &PlotGridX, &PlotGridY);
	RepaintGraphWindow();
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

	while (sscanf(&str[i++], "%1x", &n ) == 1) {
		hi=(hi<<4)|(lo>>28);
		lo=(lo<<4)|(n&0xf);
	}

	PrintToScrollback("Emulating tag with ID %x%16x", hi, lo);

	UsbCommand c={CMD_HID_SIM_TAG, {hi, lo, 0}};
	SendCommand(&c);
}

static void CmdReadmem(char *str)
{
	UsbCommand c={CMD_READ_MEM, {strtol(str, NULL, 0), 0, 0}};
	SendCommand(&c);
}

static void CmdVersion(char *str)
{
	UsbCommand c={CMD_VERSION};
	SendCommand(&c);
}

static void CmdLcdReset(char *str)
{
	UsbCommand c={CMD_LCD_RESET, {strtol(str, NULL, 0), 0, 0}};
	SendCommand(&c);
}

static void CmdLcd(char *str)
{
	int i, j;
	UsbCommand c={CMD_LCD};
	sscanf(str, "%x %d", &i, &j);
	while (j--) {
		c.arg[0] = i&0x1ff;
		SendCommand(&c);
	}
}

/*
 * Sets the divisor for LF frequency clock: lets the user choose any LF frequency below
 * 600kHz.
 */
static void CmdSetDivisor(char *str)
{
	UsbCommand c={CMD_SET_LF_DIVISOR, {strtol(str, NULL, 0), 0, 0}};
	if (( c.arg[0]<0) || (c.arg[0]>255)) {
			PrintToScrollback("divisor must be between 19 and 255");
	} else {
			SendCommand(&c);
			PrintToScrollback("Divisor set, expected freq=%dHz", 12000000/(c.arg[0]+1));
	}
}

static void CmdSetMux(char *str)
{
	UsbCommand c={CMD_SET_ADC_MUX};
	if(strcmp(str, "lopkd") == 0) {
		c.arg[0] = 0;
	} else if(strcmp(str, "loraw") == 0) {
		c.arg[0] = 1;
	} else if(strcmp(str, "hipkd") == 0) {
		c.arg[0] = 2;
	} else if(strcmp(str, "hiraw") == 0) {
		c.arg[0] = 3;
	}
	SendCommand(&c);
}

typedef void HandlerFunction(char *cmdline);

/* in alphabetic order */
static struct {
	char		*name;
	HandlerFunction	*handler;
	int		offline;  // 1 if the command can be used when in offline mode
	char		*docString;
} CommandTable[] = {
	{"amp",			CmdAmp,			1, "Amplify peaks"},
	{"askdemod",		Cmdaskdemod,		1, "<0|1> -- Attempt to demodulate simple ASK tags"},
	{"autocorr",		CmdAutoCorr,		1, "<window length> -- Autocorrelation over window"},
	{"bitsamples",		CmdBitsamples,		0, "Get raw samples as bitstring"},
	{"bitstream",		Cmdbitstream,		1, "[clock rate] -- Convert waveform into a bitstream"},
	{"buffclear",		CmdBuffClear,		1, "Clear sample buffer and graph window"},
	{"dec",			CmdDec,			1, "Decimate samples"},
	{"detectclock",		Cmddetectclockrate,	1, "Detect clock rate"},
	{"detectreader",	CmdDetectReader,	0, "['l'|'h'] -- Detect external reader field (option 'l' or 'h' to limit to LF or HF)"},
	{"em410xsim",		CmdEM410xsim,		1, "<UID> -- Simulate EM410x tag"},
	{"em410xread",		CmdEM410xread,		1, "[clock rate] -- Extract ID from EM410x tag"},
	{"em410xwatch",		CmdEM410xwatch,		0, "Watches for EM410x tags"},
	{"em4x50read",		CmdEM4x50read,		1, "Extract data from EM4x50 tag"},
	{"exit",		CmdQuit,		1, "Exit program"},
	{"flexdemod",		CmdFlexdemod,		1, "Demodulate samples for FlexPass"},
	{"fpgaoff",		CmdFPGAOff,		0, "Set FPGA off"},
	{"fskdemod",		CmdFSKdemod,		1, "Demodulate graph window as a HID FSK"},
	{"grid",		CmdGrid,		1, "<x> <y> -- overlay grid on graph window, use zero value to turn off either"},
	{"hexsamples",		CmdHexsamples,		0, "<blocks> -- Dump big buffer as hex bytes"},
	{"hi14alist",		CmdHi14alist,		0, "List ISO 14443a history"},
	{"hi14amifare",		CmdHi14amifare,	0, "Read out sector 0 parity error messages"},
	{"hi14areader",		CmdHi14areader,		0, "Act like an ISO14443 Type A reader"},
	{"hi14asim",		CmdHi14asim,		0, "<UID> -- Fake ISO 14443a tag"},
	{"hi14asnoop",		CmdHi14asnoop,		0, "Eavesdrop ISO 14443 Type A"},
	{"hi14bdemod",		CmdHi14bdemod,		1, "Demodulate ISO14443 Type B from tag"},
	{"hi14list",		CmdHi14list,		0, "List ISO 14443 history"},
	{"hi14read",		CmdHi14read,		0, "Read HF tag (ISO 14443)"},
	{"hi14sim",		CmdHi14sim,		0, "Fake ISO 14443 tag"},
	{"hi14snoop",		CmdHi14snoop,		0, "Eavesdrop ISO 14443"},
	{"hi15demod",		CmdHi15demod,		1, "Demodulate ISO15693 from tag"},
	{"hi15read",		CmdHi15read,		0, "Read HF tag (ISO 15693)"},
	{"hi15reader",		CmdHi15reader,		0, "Act like an ISO15693 reader"},
	{"hi15sim",		CmdHi15tag,		0, "Fake an ISO15693 tag"},
	{"hiddemod",		CmdHiddemod,		1, "Demodulate HID Prox Card II (not optimal)"},
	{"hide",		CmdHide,		1, "Hide graph window"},
	{"hidfskdemod",		CmdHIDdemodFSK,		0, "Realtime HID FSK demodulator"},
	{"hidsimtag",		CmdHIDsimTAG,		0, "<ID> -- HID tag simulator"},
	{"higet",		CmdHi14read_sim,	0, "<samples> -- Get samples HF, 'analog'"},
	{"hisamples",		CmdHisamples,		0, "Get raw samples for HF tag"},
	{"hisampless",		CmdHisampless,		0, "<samples> -- Get signed raw samples, HF tag"},
	{"hisamplest",		CmdHi14readt,		0, "Get samples HF, for testing"},
	{"hisimlisten",		CmdHisimlisten,		0, "Get HF samples as fake tag"},
	{"hpf",			CmdHpf,			1, "Remove DC offset from trace"},
	{"indalademod",		CmdIndalademod,		0, "['224'] -- Demodulate samples for Indala 64 bit UID (option '224' for 224 bit)"},
	{"lcd",			CmdLcd,			0, "<HEX command> <count> -- Send command/data to LCD"},
	{"lcdreset",		CmdLcdReset,		0, "Hardware reset LCD"},
	{"legicrfread",		CmdLegicRfRead,		0, "Start the LEGIC RF reader"},
	{"load",		CmdLoad,		1, "<filename> -- Load trace (to graph window"},
	{"locomread",		CmdLoCommandRead,	0, "<off period> <'0' period> <'1' period> <command> ['h'] -- Modulate LF reader field to send command before read (all periods in microseconds) (option 'h' for 134)"},
	{"loread",		CmdLoread,		0, "['h'] -- Read 125/134 kHz LF ID-only tag (option 'h' for 134)"},
	{"losamples",		CmdLosamples,		0, "[128 - 16000] -- Get raw samples for LF tag"},
	{"losim",		CmdLosim,		0, "Simulate LF tag"},
	{"losimbidir",		CmdLosimBidir,		0, "Simulate LF tag (with bidirectional data transmission between reader and tag)"},
	{"ltrim",		CmdLtrim,		1, "<samples> -- Trim samples from left of trace"},
	{"mandemod",		Cmdmanchesterdemod,	1, "[i] [clock rate] -- Manchester demodulate binary stream (option 'i' to invert output)"},
	{"manmod",		Cmdmanchestermod,	1, "[clock rate] -- Manchester modulate a binary stream"},
	{"norm",		CmdNorm,		1, "Normalize max/min to +/-500"},
	{"plot",		CmdPlot,		1, "Show graph window"},
	{"quit",		CmdQuit,		1, "Quit program"},
	{"readmem",		CmdReadmem,		0, "[address] -- Read memory at decimal address from flash"},
	{"reset",		CmdReset,		0, "Reset the Proxmark3"},
	{"save",		CmdSave,		1, "<filename> -- Save trace (from graph window)"},
	{"scale",		CmdScale,		1, "<int> -- Set cursor display scale"},
	{"setlfdivisor",	CmdSetDivisor,		0, "<19 - 255> -- Drive LF antenna at 12Mhz/(divisor+1)"},
	{"setmux",		CmdSetMux,		0, "<loraw|hiraw|lopkd|hipkd> -- Set the ADC mux to a specific value"},
	{"sri512read",		CmdSri512read,		0, "<int> -- Read contents of a SRI512 tag"},
	{"srix4kread",		CmdSrix4kread,		0, "<int> -- Read contents of a SRIX4K tag"},
	{"tidemod",		CmdTIDemod,		1, "Demodulate raw bits for TI-type LF tag"},
	{"tiread",		CmdTIRead,		0, "Read and decode a TI 134 kHz tag"},
	{"tiwrite",		CmdTIWrite,		0, "Write new data to a r/w TI 134 kHz tag"},
	{"threshold",		CmdThreshold,		1, "Maximize/minimize every value in the graph window depending on threshold"},
	{"tune",		CmdTune,		0, "Measure antenna tuning"},
	{"vchdemod",		CmdVchdemod,		0, "['clone'] -- Demodulate samples for VeriChip"},
	{"version",		CmdVersion,		0, "Show version inforation about the connected Proxmark"},
	{"zerocrossings",	CmdZerocrossings,	1, "Count time between zero-crossings"},
};

static struct {
	char *name;
	char *args;
	char *argshelp;
	char *description;
	} 	CommandExtendedHelp[]= {
		{"detectreader","'l'|'h'","'l' specifies LF antenna scan only, 'h' specifies HF antenna scan only.","Monitor antenna for changes in voltage. Output is in three fields: CHANGED, CURRENT, PERIOD,\nwhere CHANGED is the value just changed from, CURRENT is the current value and PERIOD is the\nnumber of program loops since the last change.\n\nThe RED LED indicates LF field detected, and the GREEN LED indicates HF field detected."},
		{"tune","","","Drive LF antenna at all divisor range values (19 - 255) and store the results in the output\nbuffer. Issuing 'losamples' and then 'plot' commands will display the resulting peak. 12MHz\ndivided by the peak's position plus one gives the antenna's resonant frequency. For convenience,\nthis value is also printed out by the command."},
		};

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever the user types a command and
// then presses Enter, which the full command line that they typed.
//-----------------------------------------------------------------------------
void CommandReceived(char *cmd)
{
	int i;
	char line[256];

	PrintToScrollback("> %s", cmd);

	if(strcmp(cmd, "help") == 0 || strncmp(cmd,"help ",strlen("help ")) == 0) {
		// check if we're doing extended help
		if(strlen(cmd) > strlen("help ")) {
			cmd += strlen("help ");
			for(i = 0; i < sizeof(CommandExtendedHelp) / sizeof(CommandExtendedHelp[0]); i++) {
				if(strcmp(CommandExtendedHelp[i].name,cmd) == 0) {
					PrintToScrollback("\nExtended help for '%s':\n", cmd);
					PrintToScrollback("Args: %s\t- %s\n",CommandExtendedHelp[i].args,CommandExtendedHelp[i].argshelp);
					PrintToScrollback(CommandExtendedHelp[i].description);
					PrintToScrollback("");
					return;
				}
			}
		PrintToScrollback("No extended help available for '%s'", cmd);
		return;
		}
		if (offline) PrintToScrollback("Operating in OFFLINE mode (no device connected)");
		PrintToScrollback("\r\nAvailable commands:");
		for(i = 0; i < sizeof(CommandTable) / sizeof(CommandTable[0]); i++) {
			if (offline && (CommandTable[i].offline==0)) continue;
			memset(line, ' ', sizeof(line));
			strcpy(line+2, CommandTable[i].name);
			line[strlen(line)] = ' ';
			sprintf(line+15, " -- %s", CommandTable[i].docString);
			PrintToScrollback("%s", line);
		}
		PrintToScrollback("");
		PrintToScrollback("'help <command>' for extended help on that command\n");
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
			if (offline && (CommandTable[i].offline==0)) {
				PrintToScrollback("Offline mode, cannot use this command.");
				return;
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
//	printf("%s(%x) current cmd = %x\n", __FUNCTION__, c->cmd, current_command);
/* If we recognize a response, return to avoid further processing */
	switch(c->cmd) {
		case CMD_DEBUG_PRINT_STRING: {
			char s[100];
			if(c->arg[0] > 70 || c->arg[0] < 0) {
				c->arg[0] = 0;
			}
			memcpy(s, c->d.asBytes, c->arg[0]);
			s[c->arg[0]] = '\0';
			PrintToScrollback("#db# %s", s);
			return;
		}

		case CMD_DEBUG_PRINT_INTEGERS:
			PrintToScrollback("#db# %08x, %08x, %08x\r\n", c->arg[0], c->arg[1], c->arg[2]);
			return;

		case CMD_MEASURED_ANTENNA_TUNING: {
			int peakv, peakf;
			int vLf125, vLf134, vHf;
			vLf125 = c->arg[0] & 0xffff;
			vLf134 = c->arg[0] >> 16;
			vHf = c->arg[1] & 0xffff;;
			peakf = c->arg[2] & 0xffff;
			peakv = c->arg[2] >> 16;
			PrintToScrollback("");
			PrintToScrollback("");
			PrintToScrollback("# LF antenna: %5.2f V @   125.00 kHz", vLf125/1000.0);
			PrintToScrollback("# LF antenna: %5.2f V @   134.00 kHz", vLf134/1000.0);
			PrintToScrollback("# LF optimal: %5.2f V @%9.2f kHz", peakv/1000.0, 12000.0/(peakf+1));
			PrintToScrollback("# HF antenna: %5.2f V @    13.56 MHz", vHf/1000.0);
			if (peakv<2000)
				PrintToScrollback("# Your LF antenna is unusable.");
			else if (peakv<10000)
				PrintToScrollback("# Your LF antenna is marginal.");
			if (vHf<2000)
				PrintToScrollback("# Your HF antenna is unusable.");
			else if (vHf<5000)
				PrintToScrollback("# Your HF antenna is marginal.");
			return;
		}
		default:
			break;
	}
	/* Maybe it's a response: */
	switch(current_command) {
		case CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K:
		if (c->cmd != CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K) goto unexpected_response;
		int i;
		for(i=0; i<48; i++) sample_buf[i] = c->d.asBytes[i];
		received_command = c->cmd;
		return;
	default:
	unexpected_response:
		PrintToScrollback("unrecognized command %08x\n", c->cmd);
		break;
	}
}
