//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Nov 2006
// Copyright (C) Greg Jones, Jan 2009
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
// Definitions internal to the app source.
//-----------------------------------------------------------------------------
#ifndef __ISO15693_H
#define __ISO15693_H

#include "common.h"
#include "pm3_cmd.h" // struct
#include "iso15.h"


// Delays in SSP_CLK ticks.
// SSP_CLK runs at 13,56MHz / 32 = 423.75kHz when simulating a tag
#define DELAY_ISO15693_VCD_TO_VICC_SIM     132  // 132/423.75kHz = 311.5us from end of command EOF to start of tag response

//SSP_CLK runs at 13.56MHz / 4 = 3,39MHz when acting as reader. All values should be multiples of 16
#define DELAY_ISO15693_VCD_TO_VICC_READER 1056 // 1056/3,39MHz = 311.5us from end of command EOF to start of tag response
#define DELAY_ISO15693_VICC_TO_VCD_READER 1024 // 1024/3.39MHz = 302.1us between end of tag response and next reader command

void Iso15693InitReader(void);
void Iso15693InitTag(void);
void CodeIso15693AsReader(const uint8_t *cmd, int n);
void CodeIso15693AsTag(const uint8_t *cmd, size_t len);

void TransmitTo15693Reader(const uint8_t *cmd, size_t len, uint32_t *start_time, uint32_t slot_time, bool slow);
int GetIso15693CommandFromReader(uint8_t *received, size_t max_len, uint32_t *eof_time);
void TransmitTo15693Tag(const uint8_t *cmd, int len, uint32_t *start_time, bool shallow_mod);
int GetIso15693AnswerFromTag(uint8_t *response, uint16_t max_len, uint16_t timeout, uint32_t *eof_time, bool fsk, bool recv_speed, uint16_t *resp_len);

//void RecordRawAdcSamplesIso15693(void);
void AcquireRawAdcSamplesIso15693(void);
void ReaderIso15693(iso15_card_select_t *p_card); // ISO15693 reader
void EmlClearIso15693(void);
void SimTagIso15693(uint8_t *uid, uint8_t block_size); // simulate an ISO15693 tag
void BruteforceIso15693Afi(uint32_t speed); // find an AFI of a tag
void DirectTag15693Command(uint32_t datalen, uint32_t speed, uint32_t recv, uint8_t *data); // send arbitrary commands from CLI

void SniffIso15693(uint8_t jam_search_len, uint8_t *jam_search_string, bool iclass);

int SendDataTag(uint8_t *send, int sendlen, bool init, bool speed_fast, uint8_t *recv,
                uint16_t max_recv_len, uint32_t start_time, uint16_t timeout, uint32_t *eof_time, uint16_t *resp_len);

int SendDataTagEOF(uint8_t *recv, uint16_t max_recv_len, uint32_t start_time, uint16_t timeout, uint32_t *eof_time, bool fsk, bool recv_speed, uint16_t *resp_len);

void SetTag15693Uid(const uint8_t *uid);

void WritePasswordSlixIso15693(const uint8_t *old_password, const uint8_t *new_password, uint8_t pwd_id);
void DisablePrivacySlixIso15693(const uint8_t *password);
void EnablePrivacySlixIso15693(const uint8_t *password);
void DisableEAS_AFISlixIso15693(const uint8_t *password, bool usepwd);
void EnableEAS_AFISlixIso15693(const uint8_t *password, bool usepwd);
void PassProtextEASSlixIso15693(const uint8_t *password);
void PassProtectAFISlixIso15693(const uint8_t *password);
void WriteAFIIso15693(const uint8_t *password, bool usepwd, uint8_t *uid, bool use_uid, uint8_t afi);
#endif
