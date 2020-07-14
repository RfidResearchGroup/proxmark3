//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
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

void SniffIClass(uint8_t jam_search_len, uint8_t *jam_search_string);
void ReaderIClass(uint8_t arg0);
void ReaderIClass_Replay(uint8_t arg0, uint8_t *mac);

void iClass_WriteBlock(uint8_t blockno, uint8_t *data);
void iClass_Dump(uint8_t blockno, uint8_t numblks);
void iClass_Clone(uint8_t startblock, uint8_t endblock, uint8_t *data);
void iClass_ReadCheck(uint8_t blockno, uint8_t keytype);

int doIClassSimulation(int simulationMode, uint8_t *reader_mac_buf);
void SimulateIClass(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void iclass_simulate(uint8_t sim_type, uint8_t num_csns, bool send_reply, uint8_t *datain, uint8_t *dataout,  uint16_t *dataoutlen);

void iClass_Authentication_fast(uint64_t arg0, uint64_t arg1, uint8_t *datain);
void iClass_Authentication(uint8_t *bytes);
bool iclass_auth(uint8_t *bytes, bool send_reply, uint8_t *dataout);

void iClass_ReadBlk(uint8_t blockno);
bool iclass_readblock(uint8_t blockno, uint8_t *data);
#endif
