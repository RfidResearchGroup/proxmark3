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
static int timerData = 0;


int MfSniffInit(void){
	rsamples = 0;
	memset(sniffUID, 0x00, 8);
	memset(sniffATQA, 0x00, 2);
	sniffSAK = 0;
	sniffUIDType = SNF_UID_4;

	return 0;
}

int MfSniffEnd(void){
	UsbCommand ack = {CMD_ACK, {0, 0, 0}};

	LED_B_ON();
	UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
	LED_B_OFF();

	return 0;
}

int RAMFUNC MfSniffLogic(const uint8_t * data, int len, uint32_t parity, int bitCnt, int reader) {

	if ((len == 1) && (bitCnt = 9) && (data[0] > 0x0F)) { 
		sniffState = SNF_INIT;
	}

	switch (sniffState) {
		case SNF_INIT:{
			if ((reader) && (len == 1) && (bitCnt == 9) && ((data[0] == 0x26) || (data[0] == 0x52))) { 
				sniffUIDType = SNF_UID_4;
				memset(sniffUID, 0x00, 8);
				memset(sniffATQA, 0x00, 2);
				sniffSAK = 0;

				sniffState = SNF_WUPREQ;
			}
			break;
		}
		case SNF_WUPREQ:{
			if ((!reader) && (len == 2)) { 
				memcpy(sniffATQA, data, 2);

				sniffState = SNF_ATQA;
			}
			break;
		}
		case SNF_ATQA:{
			if ((reader) && (len == 2) && (data[0] == 0x93) && (data[1] == 0x20)) { 
				sniffState = SNF_ANTICOL1;
			}
			break;
		}
		case SNF_ANTICOL1:{
			if ((!reader) && (len == 5) && ((data[0] ^ data[1] ^ data[2] ^ data[3]) == data[4])) { 
				memcpy(sniffUID + 3, data, 4);
			
				sniffState = SNF_UID1;
			}
			break;
		}
		case SNF_UID1:{
			if ((reader) && (len == 9) && (data[0] == 0x93) && (data[1] == 0x70) && (CheckCrc14443(CRC_14443_A, data, 9))) { 
				sniffState = SNF_SAK;
			}
			break;
		}
		case SNF_SAK:{
			if ((!reader) && (len == 3) && (CheckCrc14443(CRC_14443_A, data, 3))) { 
				sniffSAK = data[0];
				if (sniffUID[3] == 0x88) {
					sniffState = SNF_ANTICOL2;
				} else {
					sniffState = SNF_CARD_IDLE;
				}
			}
			break;
		}
		case SNF_ANTICOL2:{
			if ((!reader) && (len == 5) && ((data[0] ^ data[1] ^ data[2] ^ data[3]) == data[4])) { 
				memcpy(sniffUID, data, 4);
				sniffUIDType = SNF_UID_7;
			
				sniffState = SNF_UID2;
		}
			break;
		}
		case SNF_UID2:{
			if ((reader) && (len == 9) && (data[0] == 0x95) && (data[1] == 0x70) && (CheckCrc14443(CRC_14443_A, data, 9))) { 
				sniffState = SNF_SAK;
	Dbprintf("SNF_SAK");				
			}
			break;
		}
		case SNF_CARD_IDLE:{
			sniffBuf[0] = 0xFF;
			sniffBuf[1] = 0xFF;
			memcpy(sniffBuf + 2, sniffUID, 7);
			memcpy(sniffBuf + 9, sniffATQA, 2);
			sniffBuf[11] = sniffSAK;
			sniffBuf[12] = 0xFF;
			sniffBuf[13] = 0xFF;
			LogTrace(sniffBuf, 14, 0, parity, true);
			timerData = GetTickCount();
		}
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

	return 0;
}

int RAMFUNC MfSniffSend(int maxTimeoutMs) {
	if (traceLen && (timerData + maxTimeoutMs < GetTickCount())) {
		return intMfSniffSend();
	}
	return 0;
}

// internal seding function. not a RAMFUNC.
int intMfSniffSend() {
	
	int pckSize = 0;
	int pckLen = traceLen;
	int pckNum = 0;
	
	if (!traceLen) return 0;

	FpgaDisableSscDma();

	while (pckLen > 0) {
		pckSize = min(32, pckLen);
		UsbCommand ack = {CMD_ACK, {1, pckSize, pckNum}};
		memcpy(ack.d.asBytes, trace + traceLen - pckLen, pckSize);
	
		LED_B_ON();
		UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
		SpinDelay(20);
		LED_B_OFF();

		pckLen -= pckSize;
		pckNum++;
	}

	UsbCommand ack = {CMD_ACK, {2, 0, 0}};

	LED_B_ON();
	UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
	LED_B_OFF();

	traceLen = 0;
	memset(trace, 0x44, TRACE_SIZE);
	
	return 1;
}
