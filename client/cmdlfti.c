//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency TI commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "crc16.h"
#include "proxmark3.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmdlfti.h"
#include "cmdmain.h"

static int CmdHelp(const char *Cmd);

int CmdTIDemod(const char *Cmd)
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
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,    -1, -1
  };
  // 2M*16/123.2k = 260
  static const int HighTone[] = {
    1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1,   -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1,      -1, -1, -1, -1, -1, -1, -1,
    1, 1, 1, 1, 1, 1, 1, 1
  };
	int lowLen = sizeof(LowTone)/sizeof(int);
	int highLen = sizeof(HighTone)/sizeof(int);
	int convLen = (highLen>lowLen)?highLen:lowLen;
	uint16_t crc;
	int i, j, TagType;
	int lowSum = 0, highSum = 0;;
	int lowTot = 0, highTot = 0;

	for (i = 0; i < GraphTraceLen - convLen; i++) {
		lowSum = 0;
		highSum = 0;;

		for (j = 0; j < lowLen; j++) {
			lowSum += LowTone[j]*GraphBuffer[i+j];
		}
		for (j = 0; j < highLen; j++) {
			highSum += HighTone[j]*GraphBuffer[i+j];
		}
		lowSum = abs((100*lowSum) / lowLen);
		highSum = abs((100*highSum) / highLen);
		lowSum = (lowSum<0)?-lowSum:lowSum;
		highSum = (highSum<0)?-highSum:highSum;

		GraphBuffer[i] = (highSum << 16) | lowSum;
	}

	for (i = 0; i < GraphTraceLen - convLen - 16; i++) {
		lowTot = 0;
		highTot = 0;
		// 16 and 15 are f_s divided by f_l and f_h, rounded
		for (j = 0; j < 16; j++) {
			lowTot += (GraphBuffer[i+j] & 0xffff);
		}
		for (j = 0; j < 15; j++) {
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
	for (i = 0; i < 6000; i++) {
		int j;
		int dec = 0;
		// searching 17 consecutive lows
		for (j = 0; j < 17*lowLen; j++) {
			dec -= GraphBuffer[i+j];
		}
		// searching 7 consecutive highs
		for (; j < 17*lowLen + 6*highLen; j++) {
			dec += GraphBuffer[i+j];
		}
		if (dec > max) {
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

	PrintAndLogEx(NORMAL, "actual data bits start at sample %d", maxPos);

	PrintAndLogEx(NORMAL, "length %d/%d", highLen, lowLen);

	uint8_t bits[1+64+16+8+16];
	bits[sizeof(bits)-1] = '\0';

	uint32_t shift3 = 0x7e000000, shift2 = 0, shift1 = 0, shift0 = 0;

	for (i = 0; i < ARRAYLEN(bits)-1; i++) {
		int high = 0;
		int low = 0;
		int j;
		for (j = 0; j < lowLen; j++) {
			low -= GraphBuffer[maxPos+j];
		}
		for (j = 0; j < highLen; j++) {
			high += GraphBuffer[maxPos+j];
		}

		if (high > low) {
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

	RepaintGraphWindow();
	
	PrintAndLogEx(INFO, "INFO: raw tag bits = %s", bits);

	TagType = (shift3>>8)&0xff;
	if ( TagType != ((shift0>>16)&0xff) ) {
		PrintAndLogEx(WARNING, "Error: start and stop bits do not match!");
		return 0;
	}
	else if (TagType == 0x7e) {
		PrintAndLogEx(INFO, "INFO: Readonly TI tag detected.");
		return 0;
	}
	else if (TagType == 0xfe) {
		PrintAndLogEx(INFO, "INFO: Rewriteable TI tag detected.");

		// put 64 bit data into shift1 and shift0
		shift0 = (shift0>>24) | (shift1 << 8);
		shift1 = (shift1>>24) | (shift2 << 8);

		// align 16 bit crc into lower half of shift2
		shift2 = ((shift2>>24) | (shift3 << 8)) & 0x0ffff;

		// align 16 bit "end bits" or "ident" into lower half of shift3
		shift3 >>= 16;

		// only 15 bits compare, last bit of ident is not valid
		if ( (shift3^shift0)&0x7fff ) {
		  PrintAndLogEx(WARNING, "Error: Ident mismatch!");
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
		
		//crc =  crc16_ccitt(message, sizeof(message);

		char *crcStr = (crc == (shift2&0xffff) ) ? "Passed" : "Failed";
	
		PrintAndLogEx(NORMAL, "Tag data = %08X%08X  [Crc %04X %s]", shift1, shift0, crc, crcStr );

		if (crc != (shift2&0xffff))
			PrintAndLogEx(WARNING, "Error: CRC mismatch, calculated %04X, got %04X", crc, shift2&0xffff);
   
	}
	else {
		PrintAndLogEx(WARNING, "Unknown tag type.");
	}
	return 0;
}

// read a TI tag and return its ID
int CmdTIRead(const char *Cmd)
{
	UsbCommand c = {CMD_READ_TI_TYPE};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

// write new data to a r/w TI tag
int CmdTIWrite(const char *Cmd)
{
	int res = 0;
	UsbCommand c = {CMD_WRITE_TI_TYPE};
	res = sscanf(Cmd, "%012" SCNx64 " %012" SCNx64 " %012" SCNx64 "", &c.arg[0], &c.arg[1], &c.arg[2]);

	if (res == 2) c.arg[2]=0;
	if (res < 2) {
		PrintAndLogEx(NORMAL, "Please specify the data as two hex strings, optionally the CRC as a third");
		return 1;
	}
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
  {"help",      CmdHelp,        1, "This help"},
  {"demod",     CmdTIDemod,     1, "Demodulate raw bits for TI-type LF tag from the GraphBuffer"},
  {"read",      CmdTIRead,      0, "Read and decode a TI 134 kHz tag"},
  {"write",     CmdTIWrite,     0, "Write new data to a r/w TI 134 kHz tag"},
  {NULL, NULL, 0, NULL}
};

int CmdLFTI(const char *Cmd){
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd){
	CmdsHelp(CommandTable);
	return 0;
}
