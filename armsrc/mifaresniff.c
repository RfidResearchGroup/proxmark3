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

static int sniffState = SNF_INIT;
static uint8_t sniffUIDType = 0;
static uint8_t sniffUID[10] = {0,0,0,0,0,0,0,0,0,0};
static uint8_t sniffATQA[2] = {0,0};
static uint8_t sniffSAK = 0;
static uint8_t sniffBuf[17];
static uint32_t timerData = 0;

void MfSniffInit(void){
	memset(sniffUID, 0x00, sizeof(sniffUID));
	memset(sniffATQA, 0x00, sizeof(sniffATQA));
	memset(sniffBuf, 0x00, sizeof(sniffBuf));
	sniffSAK = 0;
	sniffUIDType = SNF_UID_4;
}

void MfSniffEnd(void){
	LED_B_ON();
	cmd_send(CMD_ACK,0,0,0,0,0);
	LED_B_OFF();
}

bool RAMFUNC MfSniffLogic(const uint8_t *data, uint16_t len, uint8_t *parity, uint16_t bitCnt, bool reader) {

	// reset on 7-Bit commands from reader
	if (reader && (len == 1) && (bitCnt == 7)) { 		
		sniffState = SNF_INIT;
	}

	switch (sniffState) {
		case SNF_INIT:{
			// REQA or WUPA from reader
			if ((len == 1) && (reader) && (bitCnt == 7) ) {
				MfSniffInit();
				sniffState = SNF_WUPREQ;
			}
			break;
		}
		case SNF_WUPREQ:{
			// ATQA from tag
			if ((!reader) && (len == 2)) {
				sniffATQA[0] = data[0];
				sniffATQA[1] = data[1];
				sniffState = SNF_ATQA;
			}
			break;
		}
		case SNF_ATQA:{
			// Select ALL from reader
			if ((reader) && (len == 2) && (data[0] == 0x93) && (data[1] == 0x20))
				sniffState = SNF_ANTICOL1;
			break;
		}
		case SNF_ANTICOL1:{
			// UID from tag (CL1) 
			if ((!reader) && (len == 5) && ((data[0] ^ data[1] ^ data[2] ^ data[3]) == data[4])) {
				memcpy(sniffUID, data, 4);
				sniffState = SNF_UID1;
			}
			break;
		}
		case SNF_UID1:{
			// Select 4 Byte UID from reader
			if ((reader) && (len == 9) && (data[0] == 0x93) && (data[1] == 0x70) && (CheckCrc14443(CRC_14443_A, data, 9)))
				sniffState = SNF_SAK;
			break;
		}
		case SNF_SAK:{
			if ((!reader) && (len == 3) && (CheckCrc14443(CRC_14443_A, data, 3))) { // SAK from card?
				sniffSAK = data[0];
				if (sniffUID[0] == 0x88)			// CL2/3 UID part to be expected					
					sniffState = (sniffState == SNF_ANTICOL2 ) ? SNF_ANTICOL3 : SNF_ANTICOL2;
				else								// select completed
					sniffState = SNF_CARD_IDLE;
			}
			break;
		}
		case SNF_ANTICOL2:{
			 // CL2 UID 
			if ((!reader) && (len == 5) && ((data[0] ^ data[1] ^ data[2] ^ data[3]) == data[4])) {
				sniffUID[0] = sniffUID[1];
				sniffUID[1] = sniffUID[2];
				sniffUID[2] = sniffUID[3];
				memcpy(sniffUID+3, data, 4);
				sniffUIDType = SNF_UID_7;
				sniffState = SNF_UID2;
			}
			break;
		}
		case SNF_UID2:{
			// Select 2nd part of 7 Byte UID
			if ((reader) && (len == 9) && (data[0] == 0x95) && (data[1] == 0x70) && (CheckCrc14443(CRC_14443_A, data, 9)))
				sniffState = SNF_SAK;
			break;
		}
		case SNF_ANTICOL3:{
			// CL3 UID 
			if ((!reader) && (len == 5) && ((data[0] ^ data[1] ^ data[2] ^ data[3]) == data[4])) { 
				// 3+3+4 = 10.
				sniffUID[3] = sniffUID[4];
				sniffUID[4] = sniffUID[5];
				sniffUID[5] = sniffUID[6];
				memcpy(sniffUID+6, data, 4);
				sniffUIDType = SNF_UID_10;
				sniffState = SNF_UID3;
			}
			break;
		}
		case SNF_UID3:{
			// Select 3nd part of 10 Byte UID
			if ((reader) && (len == 9) && (data[0] == 0x97) && (data[1] == 0x70) && (CheckCrc14443(CRC_14443_A, data, 9)))
				sniffState = SNF_SAK;
			break;
		}
		case SNF_CARD_IDLE:{	// trace the card select sequence
			sniffBuf[0] = 0xFF;
			sniffBuf[1] = 0xFF;
			memcpy(sniffBuf + 2, sniffUID, sizeof(sniffUID));
			memcpy(sniffBuf + 12, sniffATQA, sizeof(sniffATQA));
			sniffBuf[14] = sniffSAK;
			sniffBuf[15] = 0xFF;
			sniffBuf[16] = 0xFF;
			LogTrace(sniffBuf, sizeof(sniffBuf), 0, 0, NULL, TRUE);
		}	// intentionally no break;
		case SNF_CARD_CMD:{		
			LogTrace(data, len, 0, 0, NULL, TRUE);
			sniffState = SNF_CARD_RESP;
			timerData = GetTickCount();
			break;
		}
		case SNF_CARD_RESP:{
			LogTrace(data, len, 0, 0, NULL, FALSE);
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
	if (BigBuf_get_traceLen() && (GetTickCount() > timerData + maxTimeoutMs)) {
		return intMfSniffSend();
	}
	return FALSE;
}

// internal sending function. not a RAMFUNC.
bool intMfSniffSend() {

	int pckSize = 0;
	int pckLen = BigBuf_get_traceLen();
	int pckNum = 0;
	uint8_t *data = BigBuf_get_addr();
	
	FpgaDisableSscDma();
	while (pckLen > 0) {
		pckSize = MIN(USB_CMD_DATA_SIZE, pckLen);
		LED_B_ON();
		cmd_send(CMD_ACK, 1, BigBuf_get_traceLen(), pckSize, data + BigBuf_get_traceLen() - pckLen, pckSize);
		LED_B_OFF();
		pckLen -= pckSize;
		pckNum++;
	}

	LED_B_ON();
	cmd_send(CMD_ACK,2,0,0,0,0);  // 2 == data transfer is finished.
	LED_B_OFF();

	clear_trace();
	return TRUE;
}
