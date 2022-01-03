//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
// Iceman, August 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions internal to the app source.
//-----------------------------------------------------------------------------
#ifndef __ICLASS_H
#define __ICLASS_H

#include "common.h"
#include "iclass_cmd.h"

void SniffIClass(uint8_t jam_search_len, uint8_t *jam_search_string);
void ReaderIClass(uint8_t flags);

void iClass_WriteBlock(uint8_t *msg);
void iClass_Dump(uint8_t *msg);

void iClass_Restore(iclass_restore_req_t *msg);

int do_iclass_simulation_nonsec(void);
int do_iclass_simulation(int simulationMode, uint8_t *reader_mac_buf);
void SimulateIClass(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void iclass_simulate(uint8_t sim_type, uint8_t num_csns, bool send_reply, uint8_t *datain, uint8_t *dataout,  uint16_t *dataoutlen);

void iClass_Authentication_fast(iclass_chk_t *p);
bool iclass_auth(iclass_auth_req_t *payload, uint8_t *out);

void iClass_ReadBlock(uint8_t *msg);
bool iclass_read_block(uint16_t blockno, uint8_t *data, uint32_t *start_time, uint32_t *eof_time);

bool select_iclass_tag(picopass_hdr_t *hdr, bool use_credit_key, uint32_t *eof_time);
bool authenticate_iclass_tag(iclass_auth_req_t *payload, picopass_hdr_t *hdr, uint32_t *start_time, uint32_t *eof_time, uint8_t *mac_out);
#endif
