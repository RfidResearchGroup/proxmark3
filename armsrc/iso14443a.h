//-----------------------------------------------------------------------------
// Merlok - June 2011
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type A.
//-----------------------------------------------------------------------------

#ifndef __ISO14443A_H
#define __ISO14443A_H
#include "common.h"
#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"
#include "cmd.h"
#include "iso14443crc.h"
#include "mifaresniff.h"
#include "iso14443b.h"
#include "crapto1.h"
#include "mifareutil.h"
#include "BigBuf.h"
#include "parity.h"

typedef struct {
	enum {
		DEMOD_UNSYNCD,
		// DEMOD_HALF_SYNCD,
		// DEMOD_MOD_FIRST_HALF,
		// DEMOD_NOMOD_FIRST_HALF,
		DEMOD_MANCHESTER_DATA
	} state;
	uint16_t twoBits;
	uint16_t highCnt;
	uint16_t bitCount;
	uint16_t collisionPos;
	uint16_t syncBit;
	uint8_t  parityBits;
	uint8_t  parityLen;
	uint16_t shiftReg;
	uint16_t samples;
	uint16_t len;
	uint32_t startTime, endTime;
	uint8_t  *output;
	uint8_t  *parity;
} tDemod;

typedef enum {
	MOD_NOMOD = 0,
	MOD_SECOND_HALF,
	MOD_FIRST_HALF,
	MOD_BOTH_HALVES
	} Modulation_t;

typedef struct {
	enum {
		STATE_UNSYNCD,
		STATE_START_OF_COMMUNICATION,
		STATE_MILLER_X,
		STATE_MILLER_Y,
		STATE_MILLER_Z,
		// DROP_NONE,
		// DROP_FIRST_HALF,
		} state;
	uint16_t shiftReg;
	int16_t	 bitCount;
	uint16_t len;
	uint16_t byteCntMax;
	uint16_t posCnt;
	uint16_t syncBit;
	uint8_t  parityBits;
	uint8_t  parityLen;
	uint32_t fourBits;
	uint32_t startTime, endTime;
    uint8_t *output;
	uint8_t *parity;
} tUart;

typedef struct {
	uint8_t* response;
	size_t   response_n;
	uint8_t* modulation;
	size_t   modulation_n;
	uint32_t ProxToAirDuration;
} tag_response_info_t;

extern void GetParity(const uint8_t *pbtCmd, uint16_t len, uint8_t *par);
extern void AppendCrc14443a(uint8_t *data, int len);

extern void ReaderTransmit(uint8_t *frame, uint16_t len, uint32_t *timing);
extern void ReaderTransmitBitsPar(uint8_t *frame, uint16_t bits, uint8_t *par, uint32_t *timing);
extern void ReaderTransmitPar(uint8_t *frame, uint16_t len, uint8_t *par, uint32_t *timing);
extern int ReaderReceive(uint8_t *receivedAnswer, uint8_t *par);

extern void iso14443a_setup(uint8_t fpga_minor_mode);
extern int iso14_apdu(uint8_t *cmd, uint16_t cmd_len, void *data);
extern int iso14443a_select_card(uint8_t *uid_ptr, iso14a_card_select_t *resp_data, uint32_t *cuid_ptr, bool anticollision, uint8_t num_cascades);
extern void iso14a_set_trigger(bool enable);

int EmSendCmd14443aRaw(uint8_t *resp, uint16_t respLen, bool correctionNeeded);
int EmSend4bitEx(uint8_t resp, bool correctionNeeded);
int EmSend4bit(uint8_t resp);
int EmSendCmdExPar(uint8_t *resp, uint16_t respLen, bool correctionNeeded, uint8_t *par);
int EmSendCmdEx(uint8_t *resp, uint16_t respLen, bool correctionNeeded);
extern int EmSendCmd(uint8_t *resp, uint16_t respLen);
int EmSendCmdPar(uint8_t *resp, uint16_t respLen, uint8_t *par);
bool EmLogTrace(uint8_t *reader_data, uint16_t reader_len, uint32_t reader_StartTime, uint32_t reader_EndTime, uint8_t *reader_Parity,
				uint8_t *tag_data, uint16_t tag_len, uint32_t tag_StartTime, uint32_t tag_EndTime, uint8_t *tag_Parity);
#endif /* __ISO14443A_H */
