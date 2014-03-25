//-----------------------------------------------------------------------------
// Merlok - 2012
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support mifare classic sniffer.
//-----------------------------------------------------------------------------

#include "mifaresniff.h"
#include "apps.h"

static int sniffState = SNF_INIT;
static uint8_t sniffUIDType;
static uint8_t sniffUID[8];
static uint8_t sniffATQA[2];
static uint8_t sniffSAK;
static uint8_t sniffBuf[16];
static uint32_t timerData = 0;


bool MfSniffInit(void){
	memset(sniffUID, 0x00, 8);
	memset(sniffATQA, 0x00, 2);
	sniffSAK = 0;
	sniffUIDType = SNF_UID_4;

	return FALSE;
}

bool MfSniffEnd(void){
	LED_B_ON();
	cmd_send(CMD_ACK,0,0,0,0,0);
	LED_B_OFF();

	return FALSE;
}

bool RAMFUNC MfSniffLogic(const uint8_t *data, uint16_t len, uint32_t parity, uint16_t bitCnt, bool reader) {

	if (reader && (len == 1) && (bitCnt == 7)) { 		// reset on 7-Bit commands from reader
		sniffState = SNF_INIT;
	}

	switch (sniffState) {
		case SNF_INIT:{
			if ((len == 1) && (reader) && (bitCnt == 7) ) {  // REQA or WUPA from reader
				sniffUIDType = SNF_UID_4;
				memset(sniffUID, 0x00, 8);
				memset(sniffATQA, 0x00, 2);
				sniffSAK = 0;
				sniffState = SNF_WUPREQ;
			}
			break;
		}
		case SNF_WUPREQ:{
			if ((!reader) && (len == 2)) { 		// ATQA from tag
				memcpy(sniffATQA, data, 2);
				sniffState = SNF_ATQA;
			}
			break;
		}
		case SNF_ATQA:{
			if ((reader) && (len == 2) && (data[0] == 0x93) && (data[1] == 0x20)) { // Select ALL from reader
				sniffState = SNF_ANTICOL1;
			}
			break;
		}
		case SNF_ANTICOL1:{
			if ((!reader) && (len == 5) && ((data[0] ^ data[1] ^ data[2] ^ data[3]) == data[4])) {  // UID from tag (CL1) 
				memcpy(sniffUID + 3, data, 4);
				sniffState = SNF_UID1;
			}
			break;
		}
		case SNF_UID1:{
			if ((reader) && (len == 9) && (data[0] == 0x93) && (data[1] == 0x70) && (CheckCrc14443(CRC_14443_A, data, 9))) {   // Select 4 Byte UID from reader
				sniffState = SNF_SAK;
			}
			break;
		}
		case SNF_SAK:{
			if ((!reader) && (len == 3) && (CheckCrc14443(CRC_14443_A, data, 3))) { // SAK from card?
				sniffSAK = data[0];
				if (sniffUID[3] == 0x88) {			// CL2 UID part to be expected
					sniffState = SNF_ANTICOL2;
				} else {							// select completed
					sniffState = SNF_CARD_IDLE;
				}
			}
			break;
		}
		case SNF_ANTICOL2:{
			if ((!reader) && (len == 5) && ((data[0] ^ data[1] ^ data[2] ^ data[3]) == data[4])) { // CL2 UID 
				memcpy(sniffUID, sniffUID+4, 3);
				memcpy(sniffUID+3, data, 4);
				sniffUIDType = SNF_UID_7;
				sniffState = SNF_UID2;
			}
			break;
		}
		case SNF_UID2:{
			if ((reader) && (len == 9) && (data[0] == 0x95) && (data[1] == 0x70) && (CheckCrc14443(CRC_14443_A, data, 9))) {	// Select 2nd part of 7 Byte UID
				sniffState = SNF_SAK;
			}
			break;
		}
		case SNF_CARD_IDLE:{	// trace the card select sequence
			sniffBuf[0] = 0xFF;
			sniffBuf[1] = 0xFF;
			memcpy(sniffBuf + 2, sniffUID, 7);
			memcpy(sniffBuf + 9, sniffATQA, 2);
			sniffBuf[11] = sniffSAK;
			sniffBuf[12] = 0xFF;
			sniffBuf[13] = 0xFF;
			LogTrace(sniffBuf, 14, 0, parity, true);
		}	// intentionally no break;
		case SNF_CARD_CMD:{		
			LogTrace(data, len, 0, parity, true);
			sniffState = SNF_CARD_RESP;
			timerData = GetTickCount();
			break;
		}
		case SNF_CARD_RESP:{
			LogTrace(data, len, 0, parity, false);
			sniffState = SNF_CARD_CMD;
			timerData = GetTickCount();
			break;
		}
	
		default:
			sniffState = SNF_INIT;
		break;
	}


	return FALSE;
}

bool RAMFUNC MfSniffSend(uint16_t maxTimeoutMs) {
	if (traceLen && (GetTickCount() > timerData + maxTimeoutMs)) {
		return intMfSniffSend();
	}
	return FALSE;
}

// internal sending function. not a RAMFUNC.
bool intMfSniffSend() {

	int pckSize = 0;
	int pckLen = traceLen;
	int pckNum = 0;

	FpgaDisableSscDma();
	while (pckLen > 0) {
		pckSize = MIN(USB_CMD_DATA_SIZE, pckLen);
		LED_B_ON();
		cmd_send(CMD_ACK, 1, pckSize, pckNum, trace + traceLen - pckLen, pckSize);
		LED_B_OFF();

		pckLen -= pckSize;
		pckNum++;
	}

	LED_B_ON();
	cmd_send(CMD_ACK,2,0,0,0,0);
	LED_B_OFF();

	iso14a_clear_trace();
	
	return TRUE;
}
