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
#include "cmdhfmfu.h"

static int CmdHelp(const char *Cmd);

int CmdHFTune(const char *Cmd)
{
  UsbCommand c={CMD_MEASURE_ANTENNA_TUNING_HF};
  SendCommand(&c);
  return 0;
}

//The following data is taken from http://www.proxmark.org/forum/viewtopic.php?pid=13501#p13501
/*
ISO14443A (usually NFC tags)
	26 (7bits) = REQA
	30 = Read (usage: 30+1byte block number+2bytes ISO14443A-CRC - answer: 16bytes)
	A2 = Write (usage: A2+1byte block number+4bytes data+2bytes ISO14443A-CRC - answer: 0A [ACK] or 00 [NAK])
	52 (7bits) = WUPA (usage: 52(7bits) - answer: 2bytes ATQA)
	93 20 = Anticollision (usage: 9320 - answer: 4bytes UID+1byte UID-bytes-xor)
	93 70 = Select (usage: 9370+5bytes 9320 answer - answer: 1byte SAK)
	95 20 = Anticollision of cascade level2
	95 70 = Select of cascade level2
	50 00 = Halt (usage: 5000+2bytes ISO14443A-CRC - no answer from card)
Mifare
	60 = Authenticate with KeyA
	61 = Authenticate with KeyB
	40 (7bits) = Used to put Chinese Changeable UID cards in special mode (must be followed by 43 (8bits) - answer: 0A)
	C0 = Decrement
	C1 = Increment
	C2 = Restore
	B0 = Transfer
Ultralight C
	A0 = Compatibility Write (to accomodate MIFARE commands)
	1A = Step1 Authenticate
	AF = Step2 Authenticate


ISO14443B
	05 = REQB
	1D = ATTRIB
	50 = HALT
SRIX4K (tag does not respond to 05)
	06 00 = INITIATE
	0E xx = SELECT ID (xx = Chip-ID)
	0B = Get UID
	08 yy = Read Block (yy = block number)
	09 yy dd dd dd dd = Write Block (yy = block number; dd dd dd dd = data to be written)
	0C = Reset to Inventory
	0F = Completion
	0A 11 22 33 44 55 66 = Authenticate (11 22 33 44 55 66 = data to authenticate)


ISO15693
	MANDATORY COMMANDS (all ISO15693 tags must support those)
		01 = Inventory (usage: 260100+2bytes ISO15693-CRC - answer: 12bytes)
		02 = Stay Quiet
	OPTIONAL COMMANDS (not all tags support them)
		20 = Read Block (usage: 0220+1byte block number+2bytes ISO15693-CRC - answer: 4bytes)
		21 = Write Block (usage: 0221+1byte block number+4bytes data+2bytes ISO15693-CRC - answer: 4bytes)
		22 = Lock Block
		23 = Read Multiple Blocks (usage: 0223+1byte 1st block to read+1byte last block to read+2bytes ISO15693-CRC)
		25 = Select
		26 = Reset to Ready
		27 = Write AFI
		28 = Lock AFI
		29 = Write DSFID
		2A = Lock DSFID
		2B = Get_System_Info (usage: 022B+2bytes ISO15693-CRC - answer: 14 or more bytes)
		2C = Read Multiple Block Security Status (usage: 022C+1byte 1st block security to read+1byte last block security to read+2bytes ISO15693-CRC)

EM Microelectronic CUSTOM COMMANDS
	A5 = Active EAS (followed by 1byte IC Manufacturer code+1byte EAS type)
	A7 = Write EAS ID (followed by 1byte IC Manufacturer code+2bytes EAS value)
	B8 = Get Protection Status for a specific block (followed by 1byte IC Manufacturer code+1byte block number+1byte of how many blocks after the previous is needed the info)
	E4 = Login (followed by 1byte IC Manufacturer code+4bytes password)
NXP/Philips CUSTOM COMMANDS
	A0 = Inventory Read
	A1 = Fast Inventory Read
	A2 = Set EAS
	A3 = Reset EAS
	A4 = Lock EAS
	A5 = EAS Alarm
	A6 = Password Protect EAS
	A7 = Write EAS ID
	A8 = Read EPC
	B0 = Inventory Page Read
	B1 = Fast Inventory Page Read
	B2 = Get Random Number
	B3 = Set Password
	B4 = Write Password
	B5 = Lock Password
	B6 = Bit Password Protection
	B7 = Lock Page Protection Condition
	B8 = Get Multiple Block Protection Status
	B9 = Destroy SLI
	BA = Enable Privacy
	BB = 64bit Password Protection
	40 = Long Range CMD (Standard ISO/TR7003:1990)
		*/

#define ICLASS_CMD_ACTALL           0x0A
#define ICLASS_CMD_READ_OR_IDENTIFY 0x0C
#define ICLASS_CMD_SELECT           0x81
#define ICLASS_CMD_PAGESEL          0x84
#define ICLASS_CMD_READCHECK_KD     0x88
#define ICLASS_CMD_READCHECK_KC     0x18
#define ICLASS_CMD_CHECK            0x05
#define ICLASS_CMD_DETECT           0x0F
#define ICLASS_CMD_HALT             0x00
#define ICLASS_CMD_UPDATE			0x87
#define ICLASS_CMD_ACT              0x8E
#define ICLASS_CMD_READ4            0x06


#define ISO14443A_CMD_REQA       0x26
#define ISO14443A_CMD_READBLOCK  0x30
#define ISO14443A_CMD_WUPA       0x52
#define ISO14443A_CMD_ANTICOLL_OR_SELECT     0x93
#define ISO14443A_CMD_ANTICOLL_OR_SELECT_2   0x95
#define ISO14443A_CMD_WRITEBLOCK 0xA0 // or 0xA2 ?
#define ISO14443A_CMD_HALT       0x50
#define ISO14443A_CMD_RATS       0xE0

#define MIFARE_AUTH_KEYA	    0x60
#define MIFARE_AUTH_KEYB	    0x61
#define MIFARE_MAGICMODE	    0x40
#define MIFARE_CMD_INC          0xC0
#define MIFARE_CMD_DEC          0xC1
#define MIFARE_CMD_RESTORE      0xC2
#define MIFARE_CMD_TRANSFER     0xB0

#define MIFARE_ULC_WRITE        0xA0
#define MIFARE_ULC_AUTH_1       0x1A
#define MIFARE_ULC_AUTH_2        0xAF

#define ISO14443B_REQB         0x05
#define ISO14443B_ATTRIB       0x1D
#define ISO14443B_HALT         0x50

//First byte is 26
#define ISO15693_INVENTORY     0x01
#define ISO15693_STAYQUIET     0x02
//First byte is 02
#define ISO15693_READBLOCK            0x20
#define ISO15693_WRITEBLOCK           0x21
#define ISO15693_LOCKBLOCK            0x22
#define ISO15693_READ_MULTI_BLOCK     0x23
#define ISO15693_SELECT               0x25
#define ISO15693_RESET_TO_READY       0x26
#define ISO15693_WRITE_AFI            0x27
#define ISO15693_LOCK_AFI             0x28
#define ISO15693_WRITE_DSFID          0x29
#define ISO15693_LOCK_DSFID           0x2A
#define ISO15693_GET_SYSTEM_INFO      0x2B
#define ISO15693_READ_MULTI_SECSTATUS 0x2C


#define ISO_14443A 0
#define ICLASS     1
#define ISO_14443B 2


void annotateIso14443a(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize)
{
	switch(cmd[0])
	{
	case ISO14443A_CMD_WUPA:        snprintf(exp,size,"WUPA"); break;
	case ISO14443A_CMD_ANTICOLL_OR_SELECT:{
		// 93 20 = Anticollision (usage: 9320 - answer: 4bytes UID+1byte UID-bytes-xor)
		// 93 70 = Select (usage: 9370+5bytes 9320 answer - answer: 1byte SAK)
		if(cmd[1] == 0x70)
		{
			snprintf(exp,size,"SELECT_UID"); break;
		}else
		{
			snprintf(exp,size,"ANTICOLL"); break;
		}
	}
	case ISO14443A_CMD_ANTICOLL_OR_SELECT_2:{
		//95 20 = Anticollision of cascade level2
		//95 70 = Select of cascade level2
		if(cmd[2] == 0x70)
		{
			snprintf(exp,size,"SELECT_UID-2"); break;
		}else
		{
			snprintf(exp,size,"ANTICOLL-2"); break;
		}
	}
	case ISO14443A_CMD_REQA:       snprintf(exp,size,"REQA"); break;
	case ISO14443A_CMD_READBLOCK:  snprintf(exp,size,"READBLOCK(%d)",cmd[1]); break;
	case ISO14443A_CMD_WRITEBLOCK: snprintf(exp,size,"WRITEBLOCK(%d)",cmd[1]); break;
	case ISO14443A_CMD_HALT:       snprintf(exp,size,"HALT"); break;
	case ISO14443A_CMD_RATS:       snprintf(exp,size,"RATS"); break;
	case MIFARE_CMD_INC:          snprintf(exp,size,"INC(%d)",cmd[1]); break;
	case MIFARE_CMD_DEC:          snprintf(exp,size,"DEC(%d)",cmd[1]); break;
	case MIFARE_CMD_RESTORE:      snprintf(exp,size,"RESTORE(%d)",cmd[1]); break;
	case MIFARE_CMD_TRANSFER:     snprintf(exp,size,"TRANSFER(%d)",cmd[1]); break;
	case MIFARE_AUTH_KEYA:        snprintf(exp,size,"AUTH-A(%d)",cmd[1]); break;
	case MIFARE_AUTH_KEYB:        snprintf(exp,size,"AUTH-B(%d)",cmd[1]); break;
	case MIFARE_MAGICMODE:        snprintf(exp,size,"MAGIC"); break;
	default:                      snprintf(exp,size,"?"); break;
	}
	return;
}

void annotateIclass(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize)
{
	switch(cmd[0])
	{
	case ICLASS_CMD_ACTALL:      snprintf(exp,size,"ACTALL"); break;
	case ICLASS_CMD_READ_OR_IDENTIFY:{
		if(cmdsize > 1){
			snprintf(exp,size,"READ(%d)",cmd[1]);
		}else{
			snprintf(exp,size,"IDENTIFY");
		}
		break;
	}
	case ICLASS_CMD_SELECT:      snprintf(exp,size,"SELECT"); break;
	case ICLASS_CMD_PAGESEL:     snprintf(exp,size,"PAGESEL(%d)", cmd[1]); break;
	case ICLASS_CMD_READCHECK_KC:snprintf(exp,size,"READCHECK[Kc](%d)", cmd[1]); break;
	case ICLASS_CMD_READCHECK_KD:snprintf(exp,size,"READCHECK[Kd](%d)", cmd[1]); break;
	case ICLASS_CMD_CHECK:       snprintf(exp,size,"CHECK"); break;
	case ICLASS_CMD_DETECT:      snprintf(exp,size,"DETECT"); break;
	case ICLASS_CMD_HALT:        snprintf(exp,size,"HALT"); break;
	case ICLASS_CMD_UPDATE:      snprintf(exp,size,"UPDATE(%d)",cmd[1]); break;
	case ICLASS_CMD_ACT:         snprintf(exp,size,"ACT"); break;
	case ICLASS_CMD_READ4:       snprintf(exp,size,"READ4(%d)",cmd[1]); break;
	default:                     snprintf(exp,size,"?"); break;
	}
	return;
}

void annotateIso15693(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize)
{

	if(cmd[0] == 0x26)
	{
		switch(cmd[1]){
		case ISO15693_INVENTORY           :snprintf(exp, size, "INVENTORY");break;
		case ISO15693_STAYQUIET           :snprintf(exp, size, "STAY_QUIET");break;
		default:                     snprintf(exp,size,"?"); break;

		}
	}else if(cmd[0] == 0x02)
	{
		switch(cmd[1])
		{
		case ISO15693_READBLOCK            :snprintf(exp, size, "READBLOCK");break;
		case ISO15693_WRITEBLOCK           :snprintf(exp, size, "WRITEBLOCK");break;
		case ISO15693_LOCKBLOCK            :snprintf(exp, size, "LOCKBLOCK");break;
		case ISO15693_READ_MULTI_BLOCK     :snprintf(exp, size, "READ_MULTI_BLOCK");break;
		case ISO15693_SELECT               :snprintf(exp, size, "SELECT");break;
		case ISO15693_RESET_TO_READY       :snprintf(exp, size, "RESET_TO_READY");break;
		case ISO15693_WRITE_AFI            :snprintf(exp, size, "WRITE_AFI");break;
		case ISO15693_LOCK_AFI             :snprintf(exp, size, "LOCK_AFI");break;
		case ISO15693_WRITE_DSFID          :snprintf(exp, size, "WRITE_DSFID");break;
		case ISO15693_LOCK_DSFID           :snprintf(exp, size, "LOCK_DSFID");break;
		case ISO15693_GET_SYSTEM_INFO      :snprintf(exp, size, "GET_SYSTEM_INFO");break;
		case ISO15693_READ_MULTI_SECSTATUS :snprintf(exp, size, "READ_MULTI_SECSTATUS");break;
		default:                            snprintf(exp,size,"?"); break;
		}
	}
}
void annotateIso14443b(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize)
{
	switch(cmd[0]){
	case ISO14443B_REQB   : snprintf(exp,size,"REQB");break;
	case ISO14443B_ATTRIB : snprintf(exp,size,"ATTRIB");break;
	case ISO14443B_HALT   : snprintf(exp,size,"HALT");break;
	default:                snprintf(exp,size ,"?");break;
	}

}

/**
 * @brief iso14443B_CRC_Ok Checks CRC in command or response
 * @param isResponse
 * @param data
 * @param len
 * @return  0 : CRC-command, CRC not ok
 *          1 : CRC-command, CRC ok
 *          2 : Not crc-command
 */

uint8_t iso14443B_CRC_check(bool isResponse, uint8_t* data, uint8_t len)
{
	uint8_t b1,b2;

	if(len <= 2) return 2;

	ComputeCrc14443(CRC_14443_B, data, len-2, &b1, &b2);
	if(b1 != data[len-2] || b2 != data[len-1]) {
	  return 0;
	}
	return 1;
}

/**
 * @brief iclass_CRC_Ok Checks CRC in command or response
 * @param isResponse
 * @param data
 * @param len
 * @return  0 : CRC-command, CRC not ok
 *	        1 : CRC-command, CRC ok
 *          2 : Not crc-command
 */
uint8_t iclass_CRC_check(bool isResponse, uint8_t* data, uint8_t len)
{
	if(len < 4) return 2;//CRC commands (and responses) are all at least 4 bytes

	uint8_t b1, b2;

	if(!isResponse)//Commands to tag
	{
		/**
		  These commands should have CRC. Total length leftmost
		  4	READ
		  4 READ4
		  12 UPDATE - unsecured, ends with CRC16
		  14 UPDATE - secured, ends with signature instead
		  4 PAGESEL
		  **/
		if(len == 4 || len == 12)//Covers three of them
		{
			//Don't include the command byte
			ComputeCrc14443(CRC_ICLASS, (data+1), len-3, &b1, &b2);
			return b1 == data[len -2] && b2 == data[len-1];
		}
		return 2;
	}else{
		/**
		These tag responses should have CRC. Total length leftmost

		10  READ		data[8] crc[2]
		34  READ4		data[32]crc[2]
		10  UPDATE	data[8] crc[2]
		10 SELECT	csn[8] crc[2]
		10  IDENTIFY  asnb[8] crc[2]
		10  PAGESEL   block1[8] crc[2]
		10  DETECT    csn[8] crc[2]

		These should not

		4  CHECK		chip_response[4]
		8  READCHECK data[8]
		1  ACTALL    sof[1]
		1  ACT	     sof[1]

		In conclusion, without looking at the command; any response
		of length 10 or 34 should have CRC
		  **/
		if(len != 10 && len != 34) return true;

		ComputeCrc14443(CRC_ICLASS, data, len-2, &b1, &b2);
		return b1 == data[len -2] && b2 == data[len-1];
	}
}

uint16_t printTraceLine(uint16_t tracepos, uint16_t traceLen, uint8_t *trace, uint8_t protocol, bool showWaitCycles)
{
	bool isResponse;
	uint16_t duration, data_len, parity_len;

	uint32_t timestamp, first_timestamp, EndOfTransmissionTimestamp;
	char explanation[30] = {0};

	if (tracepos + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) > traceLen) return traceLen;
	
	first_timestamp = *((uint32_t *)(trace));
	timestamp = *((uint32_t *)(trace + tracepos));

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

	if (tracepos + data_len + parity_len > traceLen) {
		return traceLen;
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
	uint8_t crcStatus = 2;

	if (data_len > 2) {
		uint8_t b1, b2;
		if(protocol == ICLASS)
		{
			crcStatus = iclass_CRC_check(isResponse, frame, data_len);

		}else if (protocol == ISO_14443B)
		{
			crcStatus = iso14443B_CRC_check(isResponse, frame, data_len);
		}
		else if (protocol == ISO_14443A){//Iso 14443a

			ComputeCrc14443(CRC_14443_A, frame, data_len-2, &b1, &b2);

			if (b1 != frame[data_len-2] || b2 != frame[data_len-1]) {
				if(!(isResponse & (data_len < 6)))
				{
						crcStatus = 0;
				}
			}
		}
	}
	//0 CRC-command, CRC not ok
	//1 CRC-command, CRC ok
	//2 Not crc-command
	char *crc = (crcStatus == 0 ? "!crc" : (crcStatus == 1 ? " ok " : "    "));

	EndOfTransmissionTimestamp = timestamp + duration;

	if(!isResponse)
	{
		if(protocol == ICLASS)
			annotateIclass(explanation,sizeof(explanation),frame,data_len);
		else if (protocol == ISO_14443A)
			annotateIso14443a(explanation,sizeof(explanation),frame,data_len);
		else if(protocol == ISO_14443B)
			annotateIso14443b(explanation,sizeof(explanation),frame,data_len);
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

	if (tracepos + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) > traceLen) return traceLen;
	
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
	uint8_t protocol = 0;
	//Validate params
	if(tlen == 0)
	{
		errors = true;
	}
	if(param == 'h' || (param !=0 && param != 'f'))
	{
		errors = true;
	}
	if(!errors)
	{
		if(strcmp(type, "iclass") == 0)
		{
			protocol = ICLASS;
		}else if(strcmp(type, "14a") == 0)
		{
			protocol = ISO_14443A;
		}
		else if(strcmp(type, "14b") == 0)
		{
			protocol = ISO_14443B;
		}else if(strcmp(type,"raw")== 0)
		{
			protocol = -1;//No crc, no annotations
		}else{
			errors = true;
		}
	}

	if (errors) {
		PrintAndLog("List protocol data in trace buffer.");
		PrintAndLog("Usage:  hf list [14a|14b|iclass] [f]");
		PrintAndLog("    14a    - interpret data as iso14443a communications");
		PrintAndLog("    14b    - interpret data as iso14443b communications");
		PrintAndLog("    iclass - interpret data as iclass communications");
		PrintAndLog("    raw    - just show raw data");
		PrintAndLog("    f      - show frame delay times as well");
		PrintAndLog("");
		PrintAndLog("example: hf list 14a f");
		PrintAndLog("example: hf list iclass");
		return 0;
	}


	if (param == 'f') {
		showWaitCycles = true;
	}


	uint8_t *trace;
	uint16_t tracepos = 0;
	trace = malloc(USB_CMD_DATA_SIZE);

	// Query for the size of the trace
	UsbCommand response;
	GetFromBigBuf(trace, USB_CMD_DATA_SIZE, 0);
	WaitForResponse(CMD_ACK, &response);
	uint16_t traceLen = response.arg[2];
	if (traceLen > USB_CMD_DATA_SIZE) {
		uint8_t *p = realloc(trace, traceLen);
		if (p == NULL) {
			PrintAndLog("Cannot allocate memory for trace");
			free(trace);
			return 2;
		}
		trace = p;
		GetFromBigBuf(trace, traceLen, 0);
		WaitForResponse(CMD_ACK, NULL);
	}
	
	PrintAndLog("Recorded Activity (TraceLen = %d bytes)", traceLen);
	PrintAndLog("");
	PrintAndLog("Start = Start of Start Bit, End = End of last modulation. Src = Source of Transfer");
	PrintAndLog("iso14443a - All times are in carrier periods (1/13.56Mhz)");
	PrintAndLog("iClass    - Timings are not as accurate");
	PrintAndLog("");
	PrintAndLog("     Start |       End | Src | Data (! denotes parity error)                                   | CRC | Annotation         |");
	PrintAndLog("-----------|-----------|-----|-----------------------------------------------------------------|-----|--------------------|");

	while(tracepos < traceLen)
	{
		tracepos = printTraceLine(tracepos, traceLen, trace, protocol, showWaitCycles);
	}

	free(trace);
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
  {"mfu",			CmdHFMFUltra,		1, "{ MIFARE Ultralight RFIDs... }"},
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
