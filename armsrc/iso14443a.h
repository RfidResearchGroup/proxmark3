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

#ifdef __cplusplus
extern "C" {
#endif
													   
#include "usb_cmd.h"
#include "cmd.h"
#include "apps.h"
#include "util.h"
#include "string.h"
#include "crc16.h"
#include "mifaresniff.h"
#include "crapto1/crapto1.h"
#include "mifareutil.h"
#include "parity.h"
#include "random.h"
#include "mifare.h"  // structs

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
/*
typedef enum {
	MOD_NOMOD = 0,
	MOD_SECOND_HALF,
	MOD_FIRST_HALF,
	MOD_BOTH_HALVES
	} Modulation_t;
*/

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
	//uint16_t byteCntMax;
	uint16_t posCnt;
	uint16_t syncBit;
	uint8_t  parityBits;
	uint8_t  parityLen;
	uint32_t fourBits;
	uint32_t startTime, endTime;
    uint8_t *output;
	uint8_t *parity;
} tUart;

#ifndef AddCrc14A
# define	AddCrc14A(data, len)	compute_crc(CRC_14443_A, (data), (len), (data)+(len), (data)+(len)+1)
#endif

#ifndef AddCrc14B
# define	AddCrc14B(data, len)	compute_crc(CRC_14443_B, (data), (len), (data)+(len), (data)+(len)+1)
#endif

extern void GetParity(const uint8_t *pbtCmd, uint16_t len, uint8_t *par);

extern tDemod* GetDemod(void);
extern void DemodReset(void);
extern void DemodInit(uint8_t *data, uint8_t *parity);
extern tUart* GetUart(void);
extern void UartReset(void);
extern void UartInit(uint8_t *data, uint8_t *parity);
extern RAMFUNC bool MillerDecoding(uint8_t bit, uint32_t non_real_time);
extern RAMFUNC int ManchesterDecoding(uint8_t bit, uint16_t offset, uint32_t non_real_time);

extern void RAMFUNC SniffIso14443a(uint8_t param);
extern void SimulateIso14443aTag(int tagType, int flags, uint8_t *data);
extern void iso14443a_antifuzz(uint32_t flags);
extern void ReaderIso14443a(UsbCommand *c);
extern void ReaderTransmit(uint8_t *frame, uint16_t len, uint32_t *timing);
extern void ReaderTransmitBitsPar(uint8_t *frame, uint16_t bits, uint8_t *par, uint32_t *timing);
extern void ReaderTransmitPar(uint8_t *frame, uint16_t len, uint8_t *par, uint32_t *timing);
extern int ReaderReceive(uint8_t *receivedAnswer, uint8_t *par);

extern void iso14443a_setup(uint8_t fpga_minor_mode);
extern int iso14_apdu(uint8_t *cmd, uint16_t cmd_len, void *data);
extern int iso14443a_select_card(uint8_t *uid_ptr, iso14a_card_select_t *resp_data, uint32_t *cuid_ptr, bool anticollision, uint8_t num_cascades, bool no_rats);
extern int iso14443a_fast_select_card(uint8_t *uid_ptr, uint8_t num_cascades);
extern void iso14a_set_trigger(bool enable);

extern int EmSendCmd14443aRaw(uint8_t *resp, uint16_t respLen);
extern int EmSend4bit(uint8_t resp);
extern int EmSendCmd(uint8_t *resp, uint16_t respLen);
extern int EmGetCmd(uint8_t *received, uint16_t *len, uint8_t *parity);
extern int EmSendCmdPar(uint8_t *resp, uint16_t respLen, uint8_t *par);
extern int EmSendPrecompiledCmd(tag_response_info_t *response_info);

bool EmLogTrace(uint8_t *reader_data, uint16_t reader_len, uint32_t reader_StartTime, uint32_t reader_EndTime, uint8_t *reader_Parity,
				uint8_t *tag_data, uint16_t tag_len, uint32_t tag_StartTime, uint32_t tag_EndTime, uint8_t *tag_Parity);

//extern bool prepare_allocated_tag_modulation(tag_response_info_t *response_info, uint8_t **buffer, size_t *buffer_size);

void ReaderMifare(bool first_try, uint8_t block, uint8_t keytype );
void DetectNACKbug();

#ifdef __cplusplus
}
#endif				

#endif /* __ISO14443A_H */
