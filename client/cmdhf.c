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

int CmdHFTune(const char *Cmd) {
	PrintAndLog("Measuring HF antenna, press button to exit");
	UsbCommand c = {CMD_MEASURE_ANTENNA_TUNING_HF};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int applyIso14443a(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize) {
	switch ( cmd[0] ){
		case ISO14443A_CMD_WUPA:        snprintf(exp,size,"WUPA"); break;
		case ISO14443A_CMD_ANTICOLL_OR_SELECT:{
			// 93 20 = Anticollision (usage: 9320 - answer: 4bytes UID+1byte UID-bytes-xor)
			// 93 70 = Select (usage: 9370+5bytes 9320 answer - answer: 1byte SAK)
			if(cmd[1] == 0x70)
				snprintf(exp,size,"SELECT_UID");
			else
				snprintf(exp,size,"ANTICOLL");
			break;
		}
		case ISO14443A_CMD_ANTICOLL_OR_SELECT_2:{
			//95 20 = Anticollision of cascade level2
			//95 70 = Select of cascade level2
			if(cmd[2] == 0x70)
				snprintf(exp,size,"SELECT_UID-2");
			else
				snprintf(exp,size,"ANTICOLL-2");
			break;
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
		default:						return 0;
	}
	return 1;
}

void annotateIso14443a(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize) {
	applyIso14443a(exp, size, cmd, cmdsize);
}

void annotateIclass(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize) {
	switch (cmd[0]) {
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

void annotateIso15693(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize) {
	if(cmd[0] == 0x26) {
		switch(cmd[1]){
			case ISO15693_INVENTORY				:snprintf(exp, size, "INVENTORY");break;
			case ISO15693_STAYQUIET				:snprintf(exp, size, "STAY_QUIET");break;
			default								:snprintf(exp,size,"?"); break;
		}
	} else if(cmd[0] == 0x02) {
		switch (cmd[1]) {
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

void annotateTopaz(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize){
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
		default								:snprintf(exp,size,"?"); break;
	}
}

// iso 7816-3 
void annotateIso7816(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize){
	// S-block
	if ( (cmd[0] & 0xC0) && (cmdsize == 3) ) {		
		switch ( (cmd[0] & 0x3f)  ) {
			case 0x00 	: snprintf(exp, size, "S-block RESYNCH req"); break;
			case 0x20 	: snprintf(exp, size, "S-block RESYNCH resp"); break;
			case 0x01 	: snprintf(exp, size, "S-block IFS req"); break;
			case 0x21 	: snprintf(exp, size, "S-block IFS resp"); break;
			case 0x02	: snprintf(exp, size, "S-block ABORT req"); break;
			case 0x22	: snprintf(exp, size, "S-block ABORT resp"); break;
			case 0x03	: snprintf(exp, size, "S-block WTX reqt"); break;
			case 0x23	: snprintf(exp, size, "S-block WTX resp"); break;
			default		: snprintf(exp, size, "S-block"); break;
		}		
	}
	// R-block (ack)
	else if ( ((cmd[0] & 0xD0) == 0x80) && ( cmdsize > 2) ) {
		if ( (cmd[0] & 0x10) == 0 ) 
			snprintf(exp, size, "R-block ACK");
		else
			snprintf(exp, size, "R-block NACK");
	}
	// I-block
	else {

		int pos = (cmd[0] == 2 ||  cmd[0] == 3) ? 2 : 3;
		switch ( cmd[pos] ){
			case ISO7816_READ_BINARY				:snprintf(exp, size, "READ BIN");break;
			case ISO7816_WRITE_BINARY				:snprintf(exp, size, "WRITE BIN");break;
			case ISO7816_UPDATE_BINARY				:snprintf(exp, size, "UPDATE BIN");break;
			case ISO7816_ERASE_BINARY				:snprintf(exp, size, "ERASE BIN");break;
			case ISO7816_READ_RECORDS				:snprintf(exp, size, "READ RECORDS");break;
			case ISO7816_WRITE_RECORDS				:snprintf(exp, size, "WRITE RECORDS");break;
			case ISO7816_APPEND_RECORD				:snprintf(exp, size, "APPEND RECORD");break;
			case ISO7816_UPDATE_RECORD				:snprintf(exp, size, "UPDATE RECORD");break;
			case ISO7816_GET_DATA					:snprintf(exp, size, "GET DATA");break;
			case ISO7816_PUT_DATA					:snprintf(exp, size, "PUT DATA");break;
			case ISO7816_SELECT_FILE				:snprintf(exp, size, "SELECT FILE");break;
			case ISO7816_VERIFY						:snprintf(exp, size, "VERIFY");break;
			case ISO7816_INTERNAL_AUTHENTICATION 	:snprintf(exp, size, "INTERNAL AUTH");break;
			case ISO7816_EXTERNAL_AUTHENTICATION 	:snprintf(exp, size, "EXTERNAL AUTH");break;
			case ISO7816_GET_CHALLENGE				:snprintf(exp, size, "GET CHALLENGE");break;
			case ISO7816_MANAGE_CHANNEL				:snprintf(exp, size, "MANAGE CHANNEL");break;
			default									:snprintf(exp,size,"?"); break;
		}
	}
}

// MIFARE DESFire
void annotateMfDesfire(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize){
	
	// it's basically a ISO14443a tag, so try annotation from there
	if (!applyIso14443a(exp, size, cmd, cmdsize)){
		//PrintAndLog("rest");
		//PrintAndLog("(%d)",cmd[0]);
		// S-block 11xxx010
		if ( (cmd[0] & 0xC0) && (cmdsize == 3) ) {		
			switch ( (cmd[0] & 0x30)  ) {
				case 0x30	: snprintf(exp, size, "S-block DESELECT"); break;
				case 0x00	: snprintf(exp, size, "S-block WTX"); break;
				default		: snprintf(exp, size, "S-block"); break;
			}		
		}
		// R-block (ack) 101xx01x
		else if ( ((cmd[0] & 0xB0) == 0xA0) && ( cmdsize > 2) ) {
			if ( (cmd[0] & 0x10) == 0 ) 
				snprintf(exp, size, "R-block ACK(%d)", (cmd[0] & 0x01));
			else
				snprintf(exp, size, "R-block NACK(%d)", (cmd[0] & 0x01));
		}
		// I-block 000xCN1x
		else if ( (cmd[0] & 0xC0) == 0x00){
			// PCB [CID] [NAD] [INF] CRC CRC
			int pos = 1;
			if ( (cmd[0] & 0x08) == 0x08) // cid byte following
				pos = pos + 1;
			if ( (cmd[0] & 0x04) == 0x04) // nad byte following
				pos = pos + 1;
			//PrintAndLog("[%d]",pos);
			switch ( cmd[pos] ){
				case MFDES_CREATE_APPLICATION			:snprintf(exp, size, "CREATE APPLICATION");break;
				case MFDES_DELETE_APPLICATION			:snprintf(exp, size, "DELETE APPLICATION");break;
				case MFDES_GET_APPLICATION_IDS			:snprintf(exp, size, "GET APPLICATION IDS");break;
				case MFDES_SELECT_APPLICATION			:snprintf(exp, size, "SELECT APPLICATION");break;
				case MFDES_FORMAT_PICC					:snprintf(exp, size, "FORMAT PICC");break;
				case MFDES_GET_VERSION					:snprintf(exp, size, "GET VERSION");break;
				case MFDES_READ_DATA					:snprintf(exp, size, "READ DATA");break;
				case MFDES_WRITE_DATA					:snprintf(exp, size, "WRITE DATA");break;
				case MFDES_GET_VALUE					:snprintf(exp, size, "GET VALUE");break;
				case MFDES_CREDIT						:snprintf(exp, size, "CREDIT");break;
				case MFDES_DEBIT						:snprintf(exp, size, "DEBIT");break;
				case MFDES_LIMITED_CREDIT				:snprintf(exp, size, "LIMITED CREDIT");break;
				case MFDES_WRITE_RECORD					:snprintf(exp, size, "WRITE RECORD");break;
				case MFDES_READ_RECORDS					:snprintf(exp, size, "READ RECORDS");break;
				case MFDES_CLEAR_RECORD_FILE			:snprintf(exp, size, "CLEAR RECORD FILE");break;
				case MFDES_COMMIT_TRANSACTION			:snprintf(exp, size, "COMMIT TRANSACTION");break;
				case MFDES_ABORT_TRANSACTION			:snprintf(exp, size, "ABORT TRANSACTION");break;
				case MFDES_GET_FREE_MEMORY				:snprintf(exp, size, "GET FREE MEMORY");break;
				case MFDES_GET_FILE_IDS					:snprintf(exp, size, "GET FILE IDS");break;
				case MFDES_GET_ISOFILE_IDS				:snprintf(exp, size, "GET ISOFILE IDS");break;
				case MFDES_GET_FILE_SETTINGS			:snprintf(exp, size, "GET FILE SETTINGS");break;
				case MFDES_CHANGE_FILE_SETTINGS			:snprintf(exp, size, "CHANGE FILE SETTINGS");break;
				case MFDES_CREATE_STD_DATA_FILE			:snprintf(exp, size, "CREATE STD DATA FILE");break;
				case MFDES_CREATE_BACKUP_DATA_FILE		:snprintf(exp, size, "CREATE BACKUP DATA FILE");break;
				case MFDES_CREATE_VALUE_FILE			:snprintf(exp, size, "CREATE VALUE FILE");break;
				case MFDES_CREATE_LINEAR_RECORD_FILE	:snprintf(exp, size, "CREATE LINEAR RECORD FILE");break;
				case MFDES_CREATE_CYCLIC_RECORD_FILE	:snprintf(exp, size, "CREATE CYCLIC RECORD FILE");break;
				case MFDES_DELETE_FILE					:snprintf(exp, size, "DELETE FILE");break;
				case MFDES_AUTHENTICATE					:snprintf(exp, size, "AUTH NATIVE (keyNo %d)", cmd[pos+1]);break;  // AUTHENTICATE_NATIVE
				case MFDES_AUTHENTICATE_ISO				:snprintf(exp, size, "AUTH ISO (keyNo %d)", cmd[pos+1]);break;  // AUTHENTICATE_STANDARD
				case MFDES_AUTHENTICATE_AES				:snprintf(exp, size, "AUTH AES (keyNo %d)", cmd[pos+1]);break;
				case MFDES_CHANGE_KEY_SETTINGS			:snprintf(exp, size, "CHANGE KEY SETTINGS");break;
				case MFDES_GET_KEY_SETTINGS				:snprintf(exp, size, "GET KEY SETTINGS");break;
				case MFDES_CHANGE_KEY					:snprintf(exp, size, "CHANGE KEY");break;
				case MFDES_GET_KEY_VERSION				:snprintf(exp, size, "GET KEY VERSION");break;
				case MFDES_AUTHENTICATION_FRAME			:snprintf(exp, size, "AUTH FRAME / NEXT FRAME");break;
				default									:break;
			}
		}else{
			// anything else
			snprintf(exp,size,"?");
		}
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

void annotateIso14443b(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize) {
	switch(cmd[0]){
		case ISO14443B_REQB   		: {
			
			switch ( cmd[2] & 0x07 ) {
				case 0: snprintf(exp, size,"1 slot ");break;
				case 1: snprintf(exp, size,"2 slots ");break; 
				case 2: snprintf(exp, size,"4 slots ");break;
				case 3: snprintf(exp, size,"8 slots ");break;
				default: snprintf(exp, size,"16 slots ");break;
			}			
			if ( (cmd[2] & 0x8) )
				snprintf(exp, size,"WUPB");
			else
				snprintf(exp, size,"REQB");
			break;
		}
		case ISO14443B_ATTRIB 		: snprintf(exp,size,"ATTRIB");break;
		case ISO14443B_HALT   		: snprintf(exp,size,"HALT");break;
		case ISO14443B_INITIATE     : snprintf(exp,size,"INITIATE");break;
		case ISO14443B_SELECT       : snprintf(exp,size,"SELECT(%d)",cmd[1]);break;
		case ISO14443B_GET_UID      : snprintf(exp,size,"GET UID");break;
		case ISO14443B_READ_BLK     : snprintf(exp,size,"READ_BLK(%d)", cmd[1]);break;
		case ISO14443B_WRITE_BLK    : snprintf(exp,size,"WRITE_BLK(%d)",cmd[1]);break;
		case ISO14443B_RESET        : snprintf(exp,size,"RESET");break;
		case ISO14443B_COMPLETION   : snprintf(exp,size,"COMPLETION");break;
		case ISO14443B_AUTHENTICATE : snprintf(exp,size,"AUTHENTICATE");break;
		case ISO14443B_PING			: snprintf(exp,size,"PING");break;
		case ISO14443B_PONG			: snprintf(exp,size,"PONG");break;
		default                     : snprintf(exp,size ,"?");break;
	}
}

// LEGIC 
// 1 = read
// 0 = write
// Quite simpel tag
void annotateLegic(char *exp, size_t size, uint8_t* cmd, uint8_t cmdsize){
	
	if ( cmdsize > 1) {
		switch(cmd[0]) {
			case LEGIC_READ			:snprintf(exp, size, "READ Byte(%d)", cmd[1]);break;
			case LEGIC_WRITE		:snprintf(exp, size, "WRITE Byte(%d)", cmd[1]);break;
			default					:snprintf(exp, size, "?"); break;
		}		
	} else {		
		switch(cmd[0]) {
			case LEGIC_HSK			:snprintf(exp, size, "END Handshake");break;
			default					:snprintf(exp, size, "?"); break;
		}		
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

uint8_t legic_CRC_check(bool isResponse, uint8_t* data, uint8_t len){
	if (len > 2) return 2;
	
	uint8_t calccrc = CRC8Legic(data, len);
	
	return 0;
	// crc_init(&legic_crc, 4, 0x19 >> 1, 0x5, 0);
	// crc_clear(&legic_crc);
	// crc_update(&legic_crc, 1, 1); /* CMD_READ */
	// crc_update(&legic_crc, byte_index, cmd_sz-1);
	// crc_update(&legic_crc, value, 8);
	// return crc_finish(&legic_crc);
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
			case MFDES:
				crcStatus = iso14443A_CRC_check(isResponse, frame, data_len);
				break;
			default: 
				break;
		}
	} else if ( data_len == 2 && protocol == LEGIC ){
		crcStatus = legic_CRC_check(isResponse, frame, data_len);		
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
		if (protocol != ISO_14443B && protocol != ISO_7816_4 &&  (isResponse || protocol == ISO_14443A)  && (oddparity != ((parityBits >> (7-(j&0x0007))) & 0x01))) {
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

	if (data_len == 0 )
		sprintf(line[0],"<empty trace - possible error>");

	//--- Draw the CRC column
	char *crc = (crcStatus == 0 ? "!crc" : (crcStatus == 1 ? " ok " : "    "));

	EndOfTransmissionTimestamp = timestamp + duration;

	if (!isResponse)	{
		switch(protocol) {
			case ICLASS:		annotateIclass(explanation,sizeof(explanation),frame,data_len); break;
			case ISO_14443A:	annotateIso14443a(explanation,sizeof(explanation),frame,data_len); break;
			case MFDES:			annotateMfDesfire(explanation,sizeof(explanation),frame,data_len); break;
			case ISO_14443B:	annotateIso14443b(explanation,sizeof(explanation),frame,data_len); break;
			case TOPAZ:			annotateTopaz(explanation,sizeof(explanation),frame,data_len); break;
			case ISO_7816_4:	annotateIso7816(explanation,sizeof(explanation),frame,data_len); break;
			case LEGIC:			annotateLegic(explanation,sizeof(explanation),frame,data_len); break;
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

int usage_hf_list(){
	PrintAndLog("List protocol data in trace buffer.");
	PrintAndLog("Usage:  hf list <protocol> [f][c]");
	PrintAndLog("    f      - show frame delay times as well");
	PrintAndLog("    c      - mark CRC bytes");
	PrintAndLog("Supported <protocol> values:");
	PrintAndLog("    raw    - just show raw data without annotations");
	PrintAndLog("    14a    - interpret data as iso14443a communications");
	PrintAndLog("    14b    - interpret data as iso14443b communications");
	PrintAndLog("    des 	- interpret data as DESFire communications");
	PrintAndLog("    iclass - interpret data as iclass communications");
	PrintAndLog("    topaz  - interpret data as topaz communications");
	PrintAndLog("    7816   - interpret data as iso7816-4 communications");
	PrintAndLog("    legic  - interpret data as LEGIC communications");
	PrintAndLog("");
	PrintAndLog("example:	hf list 14a f");
	PrintAndLog("			hf list iclass");
	return 0;
}
int usage_hf_search(){
	PrintAndLog("Usage: hf search");
	PrintAndLog("Will try to find a HF read out of the unknown tag. Stops when found.");
	PrintAndLog("Options:");
	PrintAndLog("       h	- This help");
	PrintAndLog("");
	return 0;
}
int usage_hf_snoop(){
	PrintAndLog("Usage: hf snoop <skip pairs> <skip triggers>");
	PrintAndLog("The high frequence snoop will assign all available memory on device for snooped data");
	PrintAndLog("User the 'data samples' command to download from device,  and 'data plot' to look at it");
	PrintAndLog("Press button to quit the snooping.");
	PrintAndLog("Options:");
	PrintAndLog("       h				- This help");
	PrintAndLog("       <skip pairs>	- skip sample pairs");
	PrintAndLog("       <skip triggers>	- skip number of triggers");
	PrintAndLog("");
	PrintAndLog("example:   hf snoop");
	PrintAndLog("           hf snoop 1000 0");
	return 0;
}

int CmdHFList(const char *Cmd) {
	clearCommandBuffer();
		
	bool showWaitCycles = false;
	bool markCRCBytes = false;
	char type[10] = {0};
	//int tlen = param_getstr(Cmd,0,type);
	char param1 = param_getchar(Cmd, 1);
	char param2 = param_getchar(Cmd, 2);
	bool errors = false;
	uint8_t protocol = 0;

	//Validate params H or empty
	if (strlen(Cmd) < 1 || param1 == 'h' || param1 == 'H') return usage_hf_list();
	
	//Validate params  F,C
	if(
		(param1 != 0 && param1 != 'f' && param1 != 'c')	|| 
		(param2 != 0 && param2 != 'f' && param2 != 'c')
		) {
		return usage_hf_list();
	}

	param_getstr(Cmd,0,type);
	
	// validate type of output
	if(strcmp(type, "iclass") == 0)		protocol = ICLASS;
	else if(strcmp(type, "14a") == 0)	protocol = ISO_14443A;
	else if(strcmp(type, "14b") == 0)	protocol = ISO_14443B;
	else if(strcmp(type, "topaz")== 0)	protocol = TOPAZ;
	else if(strcmp(type, "7816")== 0)	protocol = ISO_7816_4;	
	else if(strcmp(type,"des")== 0)		protocol = MFDES;
	else if(strcmp(type,"legic")==0)	protocol = LEGIC;
	else if(strcmp(type, "raw")== 0) 	protocol = -1;//No crc, no annotations
	else errors = true;

	if (errors) return usage_hf_list();

	if (param1 == 'f' || param2 == 'f') showWaitCycles = true;
	if (param1 == 'c' || param2 == 'c') markCRCBytes = true;

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

	while(tracepos < traceLen) {
		tracepos = printTraceLine(tracepos, traceLen, trace, protocol, showWaitCycles, markCRCBytes);
	}

	free(trace);
	return 0;
}

int CmdHFSearch(const char *Cmd){

	char cmdp = param_getchar(Cmd, 0);	
	if (cmdp == 'h' || cmdp == 'H') return usage_hf_search();
	
	PrintAndLog("");
	int ans = CmdHF14AReader("s");

	if (ans > 0) {
		PrintAndLog("\nValid ISO14443-A Tag Found - Quiting Search\n");
		return ans;
	} 
	ans = CmdHF14BReader("s");
	if (ans) {
		PrintAndLog("\nValid ISO14443-B Tag Found - Quiting Search\n");
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
	ans = CmdHFTopazReader("s");
	if (ans == 0) {
		PrintAndLog("\nValid Topaz Tag Found - Quiting Search\n");
		return 1;
	}
	PrintAndLog("\nno known/supported 13.56 MHz tags found\n");
	return 0;
}

int CmdHFSnoop(const char *Cmd) {
	char cmdp = param_getchar(Cmd, 0);	
	if (cmdp == 'h' || cmdp == 'H') return usage_hf_snoop();
	
	int skippairs =  param_get32ex(Cmd, 0, 0, 10);
	int skiptriggers =  param_get32ex(Cmd, 1, 0, 10);
	
	UsbCommand c = {CMD_HF_SNIFFER, {skippairs, skiptriggers, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

static command_t CommandTable[] = {
	{"help",        CmdHelp,          1, "This help"},
	{"14a",         CmdHF14A,         1, "{ ISO14443A RFIDs... }"},
	{"14b",         CmdHF14B,         1, "{ ISO14443B RFIDs... }"},
	{"15",          CmdHF15,          1, "{ ISO15693 RFIDs... }"},
	{"epa",         CmdHFEPA,         1, "{ German Identification Card... }"},
	{"legic",       CmdHFLegic,       1, "{ LEGIC RFIDs... }"},
	{"iclass",      CmdHFiClass,      1, "{ ICLASS RFIDs... }"},
	{"mf",      	CmdHFMF,		  1, "{ MIFARE RFIDs... }"},
	{"mfu",         CmdHFMFUltra,     1, "{ MIFARE Ultralight RFIDs... }"},
	{"mfdes",		CmdHFMFDes,		  1, "{ MIFARE Desfire RFIDs... }"},
	{"topaz",		CmdHFTopaz,		  1, "{ TOPAZ (NFC Type 1) RFIDs... }"},
	{"tune",		CmdHFTune,	      0, "Continuously measure HF antenna tuning"},
	{"list",        CmdHFList,        1, "List protocol data in trace buffer"},
	{"search",      CmdHFSearch,      1, "Search for known HF tags [preliminary]"},
	{"snoop",       CmdHFSnoop,       0, "<samples to skip (10000)> <triggers to skip (1)> Generic LF/HF Snoop in Testing stage"},
	{NULL, NULL, 0, NULL}
};

int CmdHF(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0; 
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}
