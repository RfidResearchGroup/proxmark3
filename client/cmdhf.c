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
#include "cmdhfmfdes.h"
#include "cmdhftopaz.h"
#include "protocols.h"

static int CmdHelp(const char *Cmd);

int CmdHFTune(const char *Cmd)
{
  UsbCommand c={CMD_MEASURE_ANTENNA_TUNING_HF};
  SendCommand(&c);
  return 0;
}


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
	case ISO14443A_CMD_REQA:		snprintf(exp,size,"REQA"); break;
	case ISO14443A_CMD_READBLOCK:	snprintf(exp,size,"READBLOCK(%d)",cmd[1]); break;
	case ISO14443A_CMD_WRITEBLOCK:	snprintf(exp,size,"WRITEBLOCK(%d)",cmd[1]); break;
	case ISO14443A_CMD_HALT:		snprintf(exp,size,"HALT"); break;
	case ISO14443A_CMD_RATS:		snprintf(exp,size,"RATS"); break;
	case MIFARE_CMD_INC:			snprintf(exp,size,"INC(%d)",cmd[1]); break;
	case MIFARE_CMD_DEC:			snprintf(exp,size,"DEC(%d)",cmd[1]); break;
	case MIFARE_CMD_RESTORE:		snprintf(exp,size,"RESTORE(%d)",cmd[1]); break;
	case MIFARE_CMD_TRANSFER:		snprintf(exp,size,"TRANSFER(%d)",cmd[1]); break;
	case MIFARE_AUTH_KEYA:{
		if ( cmdsize > 3)
			snprintf(exp,size,"AUTH-A(%d)",cmd[1]); 
		else
			//	case MIFARE_ULEV1_VERSION :  both 0x60.
			snprintf(exp,size,"EV1 VERSION");
		break;
	}
	case MIFARE_AUTH_KEYB:			snprintf(exp,size,"AUTH-B(%d)",cmd[1]); break;
	case MIFARE_MAGICWUPC1:			snprintf(exp,size,"MAGIC WUPC1"); break;
	case MIFARE_MAGICWUPC2:			snprintf(exp,size,"MAGIC WUPC2"); break;
	case MIFARE_MAGICWIPEC:			snprintf(exp,size,"MAGIC WIPEC"); break;
	case MIFARE_ULC_AUTH_1 :		snprintf(exp,size,"AUTH "); break;
	case MIFARE_ULC_AUTH_2 : 		snprintf(exp,size,"AUTH_ANSW"); break;
	case MIFARE_ULEV1_AUTH :	
		if ( cmdsize == 7 )
			snprintf(exp,size,"PWD-AUTH KEY: 0x%02x%02x%02x%02x", cmd[1], cmd[2], cmd[3], cmd[4] );
		else
			snprintf(exp,size,"PWD-AUTH");
		break;
	case MIFARE_ULEV1_FASTREAD : {
		if ( cmdsize >=3 && cmd[2] <= 0xE6)
			snprintf(exp,size,"READ RANGE (%d-%d)",cmd[1],cmd[2]); 
		else
			snprintf(exp,size,"?");
		break;
	}
	case MIFARE_ULC_WRITE : {
		if ( cmd[1] < 0x21 )
			snprintf(exp,size,"WRITEBLOCK(%d)",cmd[1]); 
		else
			snprintf(exp,size,"?");
		break;
	}
	case MIFARE_ULEV1_READ_CNT :{
		if ( cmd[1] < 5 )
			snprintf(exp,size,"READ CNT(%d)",cmd[1]);
		else
			snprintf(exp,size,"?");
		break;
	}
	case MIFARE_ULEV1_INCR_CNT : {
		if ( cmd[1] < 5 )
			snprintf(exp,size,"INCR(%d)",cmd[1]);
		else
			snprintf(exp,size,"?");
		break;
	}
	case MIFARE_ULEV1_READSIG :		snprintf(exp,size,"READ_SIG"); break;
	case MIFARE_ULEV1_CHECKTEAR : 	snprintf(exp,size,"CHK_TEARING(%d)",cmd[1]); break;
	case MIFARE_ULEV1_VCSL :		snprintf(exp,size,"VCSL"); break;
	default:						snprintf(exp,size,"?"); break;
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


void annotateTopaz(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize)
{
	switch(cmd[0]) {
		case TOPAZ_REQA						:snprintf(exp, size, "REQA");break;
		case TOPAZ_WUPA						:snprintf(exp, size, "WUPA");break;
		case TOPAZ_RID						:snprintf(exp, size, "RID");break;
		case TOPAZ_RALL						:snprintf(exp, size, "RALL");break;
		case TOPAZ_READ						:snprintf(exp, size, "READ");break;
		case TOPAZ_WRITE_E					:snprintf(exp, size, "WRITE-E");break;
		case TOPAZ_WRITE_NE					:snprintf(exp, size, "WRITE-NE");break;
		case TOPAZ_RSEG						:snprintf(exp, size, "RSEG");break;
		case TOPAZ_READ8					:snprintf(exp, size, "READ8");break;
		case TOPAZ_WRITE_E8					:snprintf(exp, size, "WRITE-E8");break;
		case TOPAZ_WRITE_NE8				:snprintf(exp, size, "WRITE-NE8");break;
		default:                            snprintf(exp,size,"?"); break;
	}
}


/**
06 00 = INITIATE
0E xx = SELECT ID (xx = Chip-ID)
0B = Get UID
08 yy = Read Block (yy = block number)
09 yy dd dd dd dd = Write Block (yy = block number; dd dd dd dd = data to be written)
0C = Reset to Inventory
0F = Completion
0A 11 22 33 44 55 66 = Authenticate (11 22 33 44 55 66 = data to authenticate)
**/

void annotateIso14443b(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize)
{
	switch(cmd[0]){
	case ISO14443B_REQB   : snprintf(exp,size,"REQB");break;
	case ISO14443B_ATTRIB : snprintf(exp,size,"ATTRIB");break;
	case ISO14443B_HALT   : snprintf(exp,size,"HALT");break;
	case ISO14443B_INITIATE     : snprintf(exp,size,"INITIATE");break;
	case ISO14443B_SELECT       : snprintf(exp,size,"SELECT(%d)",cmd[1]);break;
	case ISO14443B_GET_UID      : snprintf(exp,size,"GET UID");break;
	case ISO14443B_READ_BLK     : snprintf(exp,size,"READ_BLK(%d)", cmd[1]);break;
	case ISO14443B_WRITE_BLK    : snprintf(exp,size,"WRITE_BLK(%d)",cmd[1]);break;
	case ISO14443B_RESET        : snprintf(exp,size,"RESET");break;
	case ISO14443B_COMPLETION   : snprintf(exp,size,"COMPLETION");break;
	case ISO14443B_AUTHENTICATE : snprintf(exp,size,"AUTHENTICATE");break;
	default                     : snprintf(exp,size ,"?");break;
	}

}

/**
 * @brief iso14443A_CRC_check Checks CRC in command or response
 * @param isResponse
 * @param data
 * @param len
 * @return  0 : CRC-command, CRC not ok
 *          1 : CRC-command, CRC ok
 *          2 : Not crc-command
 */

uint8_t iso14443A_CRC_check(bool isResponse, uint8_t* data, uint8_t len)
{
	uint8_t b1,b2;

	if(len <= 2) return 2;

	if(isResponse & (len < 6)) return 2;
	
	ComputeCrc14443(CRC_14443_A, data, len-2, &b1, &b2);
	if (b1 != data[len-2] || b2 != data[len-1]) {
		return 0;
	} else {
		return 1;
	}
}


/**
 * @brief iso14443B_CRC_check Checks CRC in command or response
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


bool is_last_record(uint16_t tracepos, uint8_t *trace, uint16_t traceLen)
{
	return(tracepos + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) >= traceLen);
}


bool next_record_is_response(uint16_t tracepos, uint8_t *trace)
{
	uint16_t next_records_datalen = *((uint16_t *)(trace + tracepos + sizeof(uint32_t) + sizeof(uint16_t)));
	
	return(next_records_datalen & 0x8000);
}


bool merge_topaz_reader_frames(uint32_t timestamp, uint32_t *duration, uint16_t *tracepos, uint16_t traceLen, uint8_t *trace, uint8_t *frame, uint8_t *topaz_reader_command, uint16_t *data_len)
{

#define MAX_TOPAZ_READER_CMD_LEN	16

	uint32_t last_timestamp = timestamp + *duration;

	if ((*data_len != 1) || (frame[0] == TOPAZ_WUPA) || (frame[0] == TOPAZ_REQA)) return false;

	memcpy(topaz_reader_command, frame, *data_len);

	while (!is_last_record(*tracepos, trace, traceLen) && !next_record_is_response(*tracepos, trace)) {
		uint32_t next_timestamp = *((uint32_t *)(trace + *tracepos));
		*tracepos += sizeof(uint32_t);
		uint16_t next_duration = *((uint16_t *)(trace + *tracepos));
		*tracepos += sizeof(uint16_t);
		uint16_t next_data_len = *((uint16_t *)(trace + *tracepos)) & 0x7FFF;
		*tracepos += sizeof(uint16_t);
		uint8_t *next_frame = (trace + *tracepos);
		*tracepos += next_data_len;
		if ((next_data_len == 1) && (*data_len + next_data_len <= MAX_TOPAZ_READER_CMD_LEN)) {
			memcpy(topaz_reader_command + *data_len, next_frame, next_data_len);
			*data_len += next_data_len;
			last_timestamp = next_timestamp + next_duration;
		} else {
			// rewind and exit
			*tracepos = *tracepos - next_data_len - sizeof(uint16_t) - sizeof(uint16_t) - sizeof(uint32_t);
			break;
		}
		uint16_t next_parity_len = (next_data_len-1)/8 + 1;
		*tracepos += next_parity_len;
	}

	*duration = last_timestamp - timestamp;
	
	return true;
}


uint16_t printTraceLine(uint16_t tracepos, uint16_t traceLen, uint8_t *trace, uint8_t protocol, bool showWaitCycles, bool markCRCBytes)
{
	bool isResponse;
	uint16_t data_len, parity_len;
	uint32_t duration;
	uint8_t topaz_reader_command[9];
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

	if (protocol == TOPAZ && !isResponse) {
		// topaz reader commands come in 1 or 9 separate frames with 7 or 8 Bits each.
		// merge them:
		if (merge_topaz_reader_frames(timestamp, &duration, &tracepos, traceLen, trace, frame, topaz_reader_command, &data_len)) {
			frame = topaz_reader_command;
		}
	}
	
	//Check the CRC status
	uint8_t crcStatus = 2;

	if (data_len > 2) {
		switch (protocol) {
			case ICLASS:
				crcStatus = iclass_CRC_check(isResponse, frame, data_len);
				break;
			case ISO_14443B:
			case TOPAZ:
				crcStatus = iso14443B_CRC_check(isResponse, frame, data_len);
				break;
			case ISO_14443A:
				crcStatus = iso14443A_CRC_check(isResponse, frame, data_len);
				break;
			default: 
				break;
		}
	}
	//0 CRC-command, CRC not ok
	//1 CRC-command, CRC ok
	//2 Not crc-command

	//--- Draw the data column
	char line[16][110];

	for (int j = 0; j < data_len && j/16 < 16; j++) {

		int oddparity = 0x01;
		int k;

		for (k=0 ; k<8 ; k++) {
			oddparity ^= (((frame[j] & 0xFF) >> k) & 0x01);
		}
		uint8_t parityBits = parityBytes[j>>3];
		if (protocol != ISO_14443B && isResponse && (oddparity != ((parityBits >> (7-(j&0x0007))) & 0x01))) {
			snprintf(line[j/16]+(( j % 16) * 4),110, "%02x! ", frame[j]);

		} else {
			snprintf(line[j/16]+(( j % 16) * 4),110, "%02x  ", frame[j]);
		}

	}

	if (markCRCBytes) {
		//CRC-command
		if(crcStatus == 0 || crcStatus == 1) {
			char *pos1 = line[(data_len-2)/16]+(((data_len-2) % 16) * 4);
			(*pos1) = '[';
			char *pos2 = line[(data_len)/16]+(((data_len) % 16) * 4);
			sprintf(pos2, "%c", ']');
		}
	}

	if(data_len == 0){
		sprintf(line[0],"<empty trace - possible error>");
	}
	//--- Draw the CRC column
	char *crc = (crcStatus == 0 ? "!crc" : (crcStatus == 1 ? " ok " : "    "));

	EndOfTransmissionTimestamp = timestamp + duration;

	if(!isResponse)
	{
		switch(protocol) {
			case ICLASS:		annotateIclass(explanation,sizeof(explanation),frame,data_len); break;
			case ISO_14443A:	annotateIso14443a(explanation,sizeof(explanation),frame,data_len); break;
			case ISO_14443B:	annotateIso14443b(explanation,sizeof(explanation),frame,data_len); break;
			case TOPAZ:			annotateTopaz(explanation,sizeof(explanation),frame,data_len); break;
			default:			break;
		}
	}

	int num_lines = MIN((data_len - 1)/16 + 1, 16);
	for (int j = 0; j < num_lines ; j++) {
		if (j == 0) {
			PrintAndLog(" %10d | %10d | %s |%-64s | %s| %s",
				(timestamp - first_timestamp),
				(EndOfTransmissionTimestamp - first_timestamp),
				(isResponse ? "Tag" : "Rdr"),
				line[j],
				(j == num_lines-1) ? crc : "    ",
				(j == num_lines-1) ? explanation : "");
		} else {
			PrintAndLog("            |            |     |%-64s | %s| %s",
				line[j],
				(j == num_lines-1) ? crc : "    ",
				(j == num_lines-1) ? explanation : "");
		}
	}

	if (is_last_record(tracepos, trace, traceLen)) return traceLen;
	
	if (showWaitCycles && !isResponse && next_record_is_response(tracepos, trace)) {
		uint32_t next_timestamp = *((uint32_t *)(trace + tracepos));
			PrintAndLog(" %10d | %10d | %s |fdt (Frame Delay Time): %d",
				(EndOfTransmissionTimestamp - first_timestamp),
				(next_timestamp - first_timestamp),
				"   ",
				(next_timestamp - EndOfTransmissionTimestamp));
		}

	return tracepos;
}


int CmdHFList(const char *Cmd)
{
	bool showWaitCycles = false;
	bool markCRCBytes = false;
	char type[40] = {0};
	int tlen = param_getstr(Cmd,0,type);
	char param1 = param_getchar(Cmd, 1);
	char param2 = param_getchar(Cmd, 2);
	bool errors = false;
	uint8_t protocol = 0;
	//Validate params

	if(tlen == 0) {
		errors = true;
	}

	if(param1 == 'h'
			|| (param1 != 0 && param1 != 'f' && param1 != 'c')
			|| (param2 != 0 && param2 != 'f' && param2 != 'c')) {
		errors = true;
	}

	if(!errors) {
		if(strcmp(type, "iclass") == 0)	{
			protocol = ICLASS;
		} else if(strcmp(type, "14a") == 0) {
			protocol = ISO_14443A;
		} else if(strcmp(type, "14b") == 0)	{
			protocol = ISO_14443B;
		} else if(strcmp(type,"topaz")== 0) {
			protocol = TOPAZ;
		} else if(strcmp(type,"raw")== 0) {
			protocol = -1;//No crc, no annotations
		}else{
			errors = true;
		}
	}

	if (errors) {
		PrintAndLog("List protocol data in trace buffer.");
		PrintAndLog("Usage:  hf list <protocol> [f][c]");
		PrintAndLog("    f      - show frame delay times as well");
		PrintAndLog("    c      - mark CRC bytes");
		PrintAndLog("Supported <protocol> values:");
		PrintAndLog("    raw    - just show raw data without annotations");
		PrintAndLog("    14a    - interpret data as iso14443a communications");
		PrintAndLog("    14b    - interpret data as iso14443b communications");
		PrintAndLog("    iclass - interpret data as iclass communications");
		PrintAndLog("    topaz  - interpret data as topaz communications");
		PrintAndLog("");
		PrintAndLog("example: hf list 14a f");
		PrintAndLog("example: hf list iclass");
		return 0;
	}


	if (param1 == 'f' || param2 == 'f') {
		showWaitCycles = true;
	}

	if (param1 == 'c' || param2 == 'c') {
		markCRCBytes = true;
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
    PrintAndLog("      Start |        End | Src | Data (! denotes parity error)                                   | CRC | Annotation         |");
	PrintAndLog("------------|------------|-----|-----------------------------------------------------------------|-----|--------------------|");

	while(tracepos < traceLen)
	{
		tracepos = printTraceLine(tracepos, traceLen, trace, protocol, showWaitCycles, markCRCBytes);
	}

	free(trace);
	return 0;
}

int CmdHFSearch(const char *Cmd){
	int ans = 0;
	PrintAndLog("");
	ans = CmdHF14AReader("s");
	if (ans > 0) {
		PrintAndLog("\nValid ISO14443A Tag Found - Quiting Search\n");
		return ans;
	} 
	ans = HF14BReader(false);
	if (ans) {
		PrintAndLog("\nValid ISO14443B Tag Found - Quiting Search\n");
		return ans;
	}
	ans = HFiClassReader("", false, false);
	if (ans) {
		PrintAndLog("\nValid iClass Tag (or PicoPass Tag) Found - Quiting Search\n");
		return ans;
	}
	ans = HF15Reader("", false);
	if (ans) {
		PrintAndLog("\nValid ISO15693 Tag Found - Quiting Search\n");
		return ans;
	}
	PrintAndLog("\nno known/supported 13.56 MHz tags found\n");
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
  {"mfu",         CmdHFMFUltra,     1, "{ MIFARE Ultralight RFIDs... }"},
  {"mfdes",			CmdHFMFDes,		1, "{ MIFARE Desfire RFIDs... }"},
  {"topaz",			CmdHFTopaz,		1, "{ TOPAZ (NFC Type 1) RFIDs... }"},
  {"tune",			CmdHFTune,      0, "Continuously measure HF antenna tuning"},
  {"list",        CmdHFList,        1, "List protocol data in trace buffer"},
  {"search",      CmdHFSearch,      1, "Search for known HF tags"},
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
