//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC RF emulation public interface
//-----------------------------------------------------------------------------

#ifndef __LEGICRF_H
#define __LEGICRF_H

#include "proxmark3.h"	//
#include "apps.h"
#include "util.h"		//
#include "string.h"		
#include "legic_prng.h"	// legic PRNG impl
#include "crc.h"		// legic crc-4
#include "ticks.h"		// timers
#include "legic.h"		// legic_card_select_t struct

extern void LegicRfSimulate(int phase, int frame, int reqresp);
extern int LegicRfReader(uint16_t offset, uint16_t len, uint8_t iv);
extern void LegicRfWriter(uint16_t offset, uint16_t byte, uint8_t iv, uint8_t *data);
extern void LegicRfInfo(void);

uint32_t get_key_stream(int skip, int count);
void frame_send_tag(uint16_t response, uint8_t bits);
void frame_sendAsReader(uint32_t data, uint8_t bits);

int legic_read_byte( uint16_t index, uint8_t cmd_sz);
bool legic_write_byte(uint16_t index, uint8_t byte, uint8_t addr_sz);

int legic_select_card(legic_card_select_t *p_card);
int legic_select_card_iv(legic_card_select_t *p_card, uint8_t iv);

void LegicCommonInit(bool clear_mem);

// emulator mem
void LegicEMemSet(uint32_t arg0, uint32_t arg1, uint8_t *data);
void LegicEMemGet(uint32_t arg0, uint32_t arg1);
void legic_emlset_mem(uint8_t *data, int offset, int numofbytes);
void legic_emlget_mem(uint8_t *data, int offset, int numofbytes);

void ice_legic_setup();

#endif /* __LEGICRF_H */
