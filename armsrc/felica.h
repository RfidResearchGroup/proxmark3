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
#ifndef __FELICA_H
#define __FELICA_H

#include "common.h"
#include "cmd.h"

void felica_sendraw(PacketCommandNG *c);
void felica_sniff(uint32_t samplesToSkip, uint32_t triggersToSkip);
void felica_sim_lite(uint64_t uid);
void felica_dump_lite_s();
void felica_create_read_block_frame(uint16_t blockNr);
void felica_send_request_service(uint8_t *request_service);

#endif
