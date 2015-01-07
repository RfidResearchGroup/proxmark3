//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include "proxmark3.h"
#include "graph.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf.h"
#include "cmdhf14a.h"
#include "cmdhf14b.h"
#include "cmdhf15.h"
#include "cmdhfepa.h"
#include "cmdhflegic.h"
#include "cmdhficlass.h"
#include "cmdhfmf.h"

static int CmdHelp(const char *Cmd);

int CmdHFTune(const char *Cmd)
{
  UsbCommand c={CMD_MEASURE_ANTENNA_TUNING_HF};
  SendCommand(&c);
  return 0;
}
// for the time being. Need better Bigbuf handling.
#define TRACE_SIZE 3000

#define ICLASS_CMD_ACTALL 0x0A
#define ICLASS_CMD_IDENTIFY 0x0C
#define ICLASS_CMD_READ 0x0C
#define ICLASS_CMD_SELECT 0x81
#define ICLASS_CMD_PAGESEL 0x84
#define ICLASS_CMD_READCHECK 0x88
#define ICLASS_CMD_CHECK 0x05
#define ICLASS_CMD_SOF 0x0F
#define ICLASS_CMD_HALT 0x00

#define iso14443_CMD_WUPA       0x52
#define iso14443_CMD_SELECT     0x93
#define iso14443_CMD_SELECT_2   0x95
#define iso14443_CMD_SELECT_3   0x97
#define iso14443_CMD_REQ        0x26
#define iso14443_CMD_READBLOCK  0x30
#define iso14443_CMD_WRITEBLOCK 0xA0
#define iso14443_CMD_WRITE		0xA2
#define iso14443_CMD_INC        0xC0
#define iso14443_CMD_DEC        0xC1
#define iso14443_CMD_RESTORE    0xC2
#define iso14443_CMD_TRANSFER   0xB0
#define iso14443_CMD_HALT       0x50
#define iso14443_CMD_RATS       0xE0

#define iso14443_CMD_AUTH_KEYA	0x60
#define iso14443_CMD_AUTH_KEYB	0x61

#define iso14443_CMD_AUTH_STEP1	0x1A
#define iso14443_CMD_AUTH_STEP2	0xAA
#define iso14443_CMD_AUTH_RESPONSE	0xAF

#define CHINESE_BACKDOOR_INIT   0x40 
#define CHINESE_BACKDOOR_STEP2   0x43 

void annotateIso14443a(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize)
{
	switch(cmd[0])
	{
	case iso14443_CMD_WUPA:            snprintf(exp,size,"WUPA"); break;
	case iso14443_CMD_SELECT:{
		if(cmdsize > 2)
		{
			snprintf(exp,size,"SELECT_UID"); break;
		}else
		{
			snprintf(exp,size,"SELECT_ALL"); break;
		}
	}
	case iso14443_CMD_SELECT_2:    snprintf(exp,size,"SELECT_2"); break;
	case iso14443_CMD_REQ:         snprintf(exp,size,"REW"); break;
	case iso14443_CMD_READBLOCK:   snprintf(exp,size,"READBLOCK(%d)",cmd[1]); break;
	case iso14443_CMD_WRITEBLOCK:  snprintf(exp,size,"WRITEBLOCK(%d)",cmd[1]); break;
	case iso14443_CMD_WRITE:	   snprintf(exp,size,"WRITE"); break;
	case iso14443_CMD_INC:         snprintf(exp,size,"INC(%d)",cmd[1]); break;
	case iso14443_CMD_DEC:         snprintf(exp,size,"DEC(%d)",cmd[1]); break;
	case iso14443_CMD_RESTORE:     snprintf(exp,size,"RESTORE(%d)",cmd[1]); break;
	case iso14443_CMD_TRANSFER:    snprintf(exp,size,"TRANSFER(%d)",cmd[1]); break;
	case iso14443_CMD_HALT:        snprintf(exp,size,"HALT"); break;
	case iso14443_CMD_RATS:        snprintf(exp,size,"RATS"); break;
	
	case iso14443_CMD_AUTH_KEYA:   snprintf(exp,size,"AUTH KEY A"); break;
	case iso14443_CMD_AUTH_KEYB:   snprintf(exp,size,"AUTH KEY B"); break;
	case iso14443_CMD_AUTH_STEP1:  snprintf(exp,size,"AUTH REQ NONCE"); break;
	case iso14443_CMD_AUTH_STEP2:  snprintf(exp,size,"AUTH STEP 2"); break;
	case iso14443_CMD_AUTH_RESPONSE:  snprintf(exp,size,"AUTH RESPONSE"); break;
	
	case CHINESE_BACKDOOR_INIT:    snprintf(exp,size,"BACKDOOR INIT");break;
	case CHINESE_BACKDOOR_STEP2:    snprintf(exp,size,"BACKDOOR STEP2");break;
	default:                       snprintf(exp,size,"?"); break;
	}
	return;
}

void annotateIclass(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize)
{
	if(cmdsize > 1 && cmd[0] == ICLASS_CMD_READ)
	{
		  snprintf(exp,size,"READ(%d)",cmd[1]);
		  return;
	}

	switch(cmd[0])
	{
	case ICLASS_CMD_ACTALL:      snprintf(exp,size,"ACTALL"); break;
	case ICLASS_CMD_IDENTIFY:    snprintf(exp,size,"IDENTIFY"); break;
	case ICLASS_CMD_SELECT:      snprintf(exp,size,"SELECT"); break;
	case ICLASS_CMD_PAGESEL:     snprintf(exp,size,"PAGESEL"); break;
	case ICLASS_CMD_READCHECK:   snprintf(exp,size,"READCHECK"); break;
	case ICLASS_CMD_CHECK:       snprintf(exp,size,"CHECK"); break;
	case ICLASS_CMD_SOF:         snprintf(exp,size,"SOF"); break;
	case ICLASS_CMD_HALT:        snprintf(exp,size,"HALT"); break;
	default:                     snprintf(exp,size,"?"); break;
	}
	return;
}


uint16_t printTraceLine(uint16_t tracepos, uint8_t* trace, bool iclass, bool showWaitCycles)
{
	bool isResponse;
	uint16_t duration, data_len,parity_len;

	uint32_t timestamp, first_timestamp, EndOfTransmissionTimestamp;
	char explanation[30] = {0};

	first_timestamp = *((uint32_t *)(trace));
	timestamp = *((uint32_t *)(trace + tracepos));
	// Break and stick with current result if buffer was not completely full
	if (timestamp == 0x44444444) return TRACE_SIZE;

	tracepos += 4;
	duration = *((uint16_t *)(trace + tracepos));
	tracepos += 2;
	data_len = *((uint16_t *)(trace + tracepos));
	tracepos += 2;

	if (data_len & 0x8000) {
	  data_len &= 0x7fff;
	  isResponse = true;
	} else {
	  isResponse = false;
	}
	parity_len = (data_len-1)/8 + 1;

	if (tracepos + data_len + parity_len >= TRACE_SIZE) {
		return TRACE_SIZE;
	}

	uint8_t *frame = trace + tracepos;
	tracepos += data_len;
	uint8_t *parityBytes = trace + tracepos;
	tracepos += parity_len;

	//--- Draw the data column
	char line[16][110];
	for (int j = 0; j < data_len; j++) {
		int oddparity = 0x01;
		int k;

		for (k=0 ; k<8 ; k++) {
			oddparity ^= (((frame[j] & 0xFF) >> k) & 0x01);
		}

		uint8_t parityBits = parityBytes[j>>3];

		if (isResponse && (oddparity != ((parityBits >> (7-(j&0x0007))) & 0x01))) {
			sprintf(line[j/16]+((j%16)*4), "%02x! ", frame[j]);
		} else {
			sprintf(line[j/16]+((j%16)*4), "%02x  ", frame[j]);
		}
	}
	//--- Draw the CRC column
	bool crcError = false;

	if (data_len > 2) {
		uint8_t b1, b2;
		if(iclass)
		{
			if(!isResponse && data_len == 4 ) {
				// Rough guess that this is a command from the reader
				// For iClass the command byte is not part of the CRC
				ComputeCrc14443(CRC_ICLASS, &frame[1], data_len-3, &b1, &b2);
			} else {
				// For other data.. CRC might not be applicable (UPDATE commands etc.)
				ComputeCrc14443(CRC_ICLASS, frame, data_len-2, &b1, &b2);
			}

			if (b1 != frame[data_len-2] || b2 != frame[data_len-1]) {
				crcError = true;
			}

		}else{//Iso 14443a

			ComputeCrc14443(CRC_14443_A, frame, data_len-2, &b1, &b2);

			if (b1 != frame[data_len-2] || b2 != frame[data_len-1]) {
				if(!(isResponse & (data_len < 6)))
				{
						crcError = true;
				}
			}
		}
	}
	char *crc = crcError ? "!crc" :"    ";

	EndOfTransmissionTimestamp = timestamp + duration;

	if(!isResponse)
	{
		if(iclass)
			annotateIclass(explanation,sizeof(explanation),frame,data_len);
		else 
			annotateIso14443a(explanation,sizeof(explanation),frame,data_len);
	}

	int num_lines = (data_len - 1)/16 + 1;
	for (int j = 0; j < num_lines; j++) {
		if (j == 0) {
			PrintAndLog(" %9d | %9d | %s | %-64s| %s| %s",
				(timestamp - first_timestamp),
				(EndOfTransmissionTimestamp - first_timestamp),
				(isResponse ? "Tag" : "Rdr"),
				line[j],
				(j == num_lines-1) ? crc : "    ",
				(j == num_lines-1) ? explanation : "");
		} else {
			PrintAndLog("           |           |     | %-64s| %s| %s",
				line[j],
				(j == num_lines-1)?crc:"    ",
				(j == num_lines-1) ? explanation : "");
		}
	}

	bool next_isResponse = *((uint16_t *)(trace + tracepos + 6)) & 0x8000;

	if (showWaitCycles && !isResponse && next_isResponse) {
		uint32_t next_timestamp = *((uint32_t *)(trace + tracepos));
		if (next_timestamp != 0x44444444) {
			PrintAndLog(" %9d | %9d | %s | fdt (Frame Delay Time): %d",
				(EndOfTransmissionTimestamp - first_timestamp),
				(next_timestamp - first_timestamp),
				"   ",
				(next_timestamp - EndOfTransmissionTimestamp));
		}
	}
	return tracepos;
}

int CmdHFList(const char *Cmd)
{
	bool showWaitCycles = false;
	char type[40] = {0};
	int tlen = param_getstr(Cmd,0,type);
	char param = param_getchar(Cmd, 1);
	bool errors = false;
	bool iclass = false;
	//Validate params
	if(tlen == 0 || (strcmp(type, "iclass") != 0 && strcmp(type,"14a") != 0))
	{
		errors = true;
	}
	if(param == 'h' || (param !=0 && param != 'f'))
	{
		errors = true;
	}

	if (errors) {
		PrintAndLog("List protocol data in trace buffer.");
		PrintAndLog("Usage:  hf list [14a|iclass] [f]");
		PrintAndLog("    14a    - interpret data as iso14443a communications");
		PrintAndLog("    iclass - interpret data as iclass communications");
		PrintAndLog("    f      - show frame delay times as well");
		PrintAndLog("");
		PrintAndLog("example: hf list 14a f");
		PrintAndLog("example: hf list iclass");
		return 0;
	}
	if(strcmp(type, "iclass") == 0)
	{
		iclass = true;
	}

	if (param == 'f') {
		showWaitCycles = true;
	}


	uint8_t trace[TRACE_SIZE];
	uint16_t tracepos = 0;
	GetFromBigBuf(trace, TRACE_SIZE, 0);
	WaitForResponse(CMD_ACK, NULL);

	PrintAndLog("Recorded Activity");
	PrintAndLog("");
	PrintAndLog("Start = Start of Start Bit, End = End of last modulation. Src = Source of Transfer");
	PrintAndLog("iso14443a - All times are in carrier periods (1/13.56Mhz)");
	PrintAndLog("iClass    - Timings are not as accurate");
	PrintAndLog("");
	PrintAndLog("     Start |       End | Src | Data (! denotes parity error)                                   | CRC | Annotation         |");
	PrintAndLog("-----------|-----------|-----|-----------------------------------------------------------------|-----|--------------------|");

	while(tracepos < TRACE_SIZE)
	{
		tracepos = printTraceLine(tracepos, trace, iclass, showWaitCycles);
	}
	return 0;
}


static command_t CommandTable[] = 
{
  {"help",        CmdHelp,          1, "This help"},
  {"14a",         CmdHF14A,         1, "{ ISO14443A RFIDs... }"},
  {"14b",         CmdHF14B,         1, "{ ISO14443B RFIDs... }"},
  {"15",          CmdHF15,          1, "{ ISO15693 RFIDs... }"},
  {"epa",         CmdHFEPA,         1, "{ German Identification Card... }"},
  {"legic",       CmdHFLegic,       0, "{ LEGIC RFIDs... }"},
  {"iclass",      CmdHFiClass,      1, "{ ICLASS RFIDs... }"},
  {"mf",      		CmdHFMF,		1, "{ MIFARE RFIDs... }"},
  {"tune",        CmdHFTune,        0, "Continuously measure HF antenna tuning"},
  {"list",       CmdHFList,         1, "List protocol data in trace buffer"},
	{NULL, NULL, 0, NULL}
};

int CmdHF(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0; 
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
