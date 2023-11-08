//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Nov 2006
// Copyright (C) Gerhard de Koning Gans - May 2008
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type A.
//-----------------------------------------------------------------------------

#ifndef __ISO14443A_H
#define __ISO14443A_H

#include "common.h"
#include "mifare.h" // struct
#include "pm3_cmd.h"
#include "crc16.h"  // compute_crc

// When the PM acts as tag and is receiving it takes
// 2 ticks delay in the RF part (for the first falling edge),
// 3 ticks for the A/D conversion,
// 8 ticks on average until the start of the SSC transfer,
// 8 ticks until the SSC samples the first data
// 7*16 ticks to complete the transfer from FPGA to ARM
// 8 ticks until the next ssp_clk rising edge
// 4*16 ticks until we measure the time
// - 8*16 ticks because we measure the time of the previous transfer
#define DELAY_AIR2ARM_AS_TAG (2 + 3 + 8 + 8 + 7*16 + 8 + 4*16 - 8*16)

typedef struct {
    enum {
        DEMOD_14A_UNSYNCD,
        // DEMOD_14A_HALF_SYNCD,
        // DEMOD_14A_MOD_FIRST_HALF,
        // DEMOD_14A_NOMOD_FIRST_HALF,
        DEMOD_14A_MANCHESTER_DATA
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
} tDemod14a;
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
        STATE_14A_UNSYNCD,
        STATE_14A_START_OF_COMMUNICATION,
        STATE_14A_MILLER_X,
        STATE_14A_MILLER_Y,
        STATE_14A_MILLER_Z,
        // DROP_NONE,
        // DROP_FIRST_HALF,
    } state;
    uint16_t shiftReg;
    int16_t bitCount;
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
} tUart14a;

// indices into responses array:
typedef enum {
    RESP_INDEX_ATQA,
    RESP_INDEX_UIDC1,
    RESP_INDEX_UIDC2,
    RESP_INDEX_UIDC3,
    RESP_INDEX_SAKC1,
    RESP_INDEX_SAKC2,
    RESP_INDEX_SAKC3,
    RESP_INDEX_RATS,
    RESP_INDEX_VERSION,
    RESP_INDEX_SIGNATURE,
    RESP_INDEX_PPS,
    RESP_INDEX_PACK,
} resp_index_t;

#ifndef AddCrc14A
# define AddCrc14A(data, len) compute_crc(CRC_14443_A, (data), (len), (data)+(len), (data)+(len)+1)
#endif

#ifndef AddCrc14B
# define AddCrc14B(data, len) compute_crc(CRC_14443_B, (data), (len), (data)+(len), (data)+(len)+1)
#endif

#ifndef CheckCrc14A
# define CheckCrc14A(data, len) check_crc(CRC_14443_A, (data), (len))
#endif

void printHf14aConfig(void);
void setHf14aConfig(const hf14a_config *hc);
hf14a_config *getHf14aConfig(void);
void iso14a_set_timeout(uint32_t timeout);
uint32_t iso14a_get_timeout(void);

void GetParity(const uint8_t *pbtCmd, uint16_t len, uint8_t *par);

tDemod14a *GetDemod14a(void);
void Demod14aReset(void);
void Demod14aInit(uint8_t *data, uint8_t *par);
tUart14a *GetUart14a(void);
void Uart14aReset(void);
void Uart14aInit(uint8_t *data, uint8_t *par);
RAMFUNC bool MillerDecoding(uint8_t bit, uint32_t non_real_time);
RAMFUNC int ManchesterDecoding(uint8_t bit, uint16_t offset, uint32_t non_real_time);

void RAMFUNC SniffIso14443a(uint8_t param);
void SimulateIso14443aTag(uint8_t tagType, uint16_t flags, uint8_t *data, uint8_t exitAfterNReads);
bool SimulateIso14443aInit(uint8_t tagType, uint16_t flags, uint8_t *data, tag_response_info_t **responses, uint32_t *cuid, uint32_t counters[3], uint8_t tearings[3], uint8_t *pages);
bool GetIso14443aCommandFromReader(uint8_t *received, uint8_t *par, int *len);
void iso14443a_antifuzz(uint32_t flags);
void ReaderIso14443a(PacketCommandNG *c);
void ReaderTransmit(uint8_t *frame, uint16_t len, uint32_t *timing);
void ReaderTransmitBitsPar(uint8_t *frame, uint16_t bits, uint8_t *par, uint32_t *timing);
void ReaderTransmitPar(uint8_t *frame, uint16_t len, uint8_t *par, uint32_t *timing);
uint16_t ReaderReceive(uint8_t *receivedAnswer, uint8_t *par);

void iso14443a_setup(uint8_t fpga_minor_mode);
int iso14_apdu(uint8_t *cmd, uint16_t cmd_len, bool send_chaining, void *data, uint8_t *res);
int iso14443a_select_card(uint8_t *uid_ptr, iso14a_card_select_t *p_card, uint32_t *cuid_ptr, bool anticollision, uint8_t num_cascades, bool no_rats);
int iso14443a_select_cardEx(uint8_t *uid_ptr, iso14a_card_select_t *p_card, uint32_t *cuid_ptr, bool anticollision, uint8_t num_cascades, bool no_rats, iso14a_polling_parameters_t *polling_parameters);
int iso14443a_fast_select_card(uint8_t *uid_ptr, uint8_t num_cascades);
void iso14a_set_trigger(bool enable);

int EmSendCmd14443aRaw(const uint8_t *resp, uint16_t respLen);
int EmSend4bit(uint8_t resp);
int EmSendCmd(uint8_t *resp, uint16_t respLen);
int EmSendCmdEx(uint8_t *resp, uint16_t respLen, bool collision);
int EmGetCmd(uint8_t *received, uint16_t *len, uint8_t *par);
int EmSendCmdPar(uint8_t *resp, uint16_t respLen, uint8_t *par);
int EmSendCmdParEx(uint8_t *resp, uint16_t respLen, uint8_t *par, bool collision);
int EmSendPrecompiledCmd(tag_response_info_t *p_response);

bool prepare_allocated_tag_modulation(tag_response_info_t *response_info, uint8_t **buffer, size_t *max_buffer_size);
bool prepare_tag_modulation(tag_response_info_t *response_info, size_t max_buffer_size);

bool EmLogTrace(uint8_t *reader_data, uint16_t reader_len, uint32_t reader_StartTime, uint32_t reader_EndTime, uint8_t *reader_Parity,
                uint8_t *tag_data, uint16_t tag_len, uint32_t tag_StartTime, uint32_t tag_EndTime, uint8_t *tag_Parity);

void ReaderMifare(bool first_try, uint8_t block, uint8_t keytype);
void DetectNACKbug(void);

bool GetIso14443aAnswerFromTag_Thinfilm(uint8_t *receivedResponse, uint8_t *received_len);

#endif /* __ISO14443A_H */
