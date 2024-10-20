//-----------------------------------------------------------------------------
// Copyright (C) Gerhard de Koning Gans - May 2008
// Contribution made during a security research at Radboud University Nijmegen
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
#ifndef __ICLASS_H
#define __ICLASS_H

#include "common.h"
#include "iclass_cmd.h"

// iCLASS has a slightly different timing compared to ISO15693. According to the picopass data sheet the tag response is expected 330us after
// the reader command. This is measured from end of reader EOF to first modulation of the tag's SOF which starts with a 56,64us unmodulated period.
// 330us = 140 ssp_clk cycles @ 423,75kHz when simulating.
// 56,64us = 24 ssp_clk_cycles
#define DELAY_ICLASS_VCD_TO_VICC_SIM     (140 - 26) // (140 - 24)

// times in ssp_clk_cycles @ 3,3625MHz when acting as reader
#define DELAY_ICLASS_VICC_TO_VCD_READER  DELAY_ISO15693_VICC_TO_VCD_READER


// times in samples @ 212kHz when acting as reader
#define ICLASS_READER_TIMEOUT_ACTALL     330 // 1558us, nominal 330us + 7slots*160us = 1450us
#define ICLASS_READER_TIMEOUT_UPDATE    3390 // 16000us, nominal 4-15ms
#define ICLASS_READER_TIMEOUT_OTHERS      80 // 380us, nominal 330us

// The length of a received command will in most cases be no more than 18 bytes.
// we expect max 34 (32+2) bytes as tag answer (response to READ4)
#ifndef ICLASS_BUFFER_SIZE
#define ICLASS_BUFFER_SIZE     34 + 2
#endif


#define AddCrc(data, len) compute_crc(CRC_ICLASS, (data), (len), (data)+(len), (data)+(len)+1)

void SniffIClass(uint8_t jam_search_len, uint8_t *jam_search_string);
void ReaderIClass(uint8_t flags);

void iClass_WriteBlock(uint8_t *msg);
void iclass_credit_epurse(iclass_credit_epurse_t *payload);
void iClass_Dump(uint8_t *msg);

void iClass_Restore(iclass_restore_req_t *msg);

int do_iclass_simulation_nonsec(void);
int do_iclass_simulation(int simulationMode, uint8_t *reader_mac_buf);
void SimulateIClass(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void iclass_simulate(uint8_t sim_type, uint8_t num_csns, bool send_reply, uint8_t *datain, uint8_t *dataout,  uint16_t *dataoutlen);

void iClass_Authentication_fast(iclass_chk_t *p);
bool iclass_auth(iclass_auth_req_t *payload, uint8_t *out);

void iClass_ReadBlock(uint8_t *msg);
bool iclass_read_block(uint16_t blockno, uint8_t *data, uint32_t *start_time, uint32_t *eof_time, bool shallow_mod);

bool select_iclass_tag(picopass_hdr_t *hdr, bool use_credit_key, uint32_t *eof_time, bool shallow_mod);
bool authenticate_iclass_tag(iclass_auth_req_t *payload, picopass_hdr_t *hdr, uint32_t *start_time, uint32_t *eof_time, uint8_t *mac_out);

uint8_t get_pagemap(const picopass_hdr_t *hdr);
void iclass_send_as_reader(uint8_t *frame, int len, uint32_t *start_time, uint32_t *end_time, bool shallow_mod);

void iClass_Recover(iclass_recover_req_t *msg);
#endif
