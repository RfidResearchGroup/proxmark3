//-----------------------------------------------------------------------------
// Merlok - June 2011
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type B.
//-----------------------------------------------------------------------------

#ifndef __ISO14443B_H
#define __ISO14443B_H

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"
#include "iso14443crc.h"
#include "common.h"
#include "mifare.h"
#include "protocols.h"
#include "mifareutil.h"		// access to global variable: MF_DBGLEVEL

extern void AppendCrc14443b(uint8_t *data, int len);

void SendRawCommand14443B_Ex(UsbCommand *c);

void iso14443b_setup();
uint8_t iso14443b_apdu(uint8_t const *message, size_t message_length, uint8_t *response);
uint8_t iso14443b_select_card(iso14b_card_select_t* card);
uint8_t iso14443b_select_card_srx(iso14b_card_select_t* card);

// testfunctions
void WaitForFpgaDelayQueueIsEmpty( uint16_t delay );
void ClearFpgaShiftingRegisters(void);

// States for 14B SIM command
#define SIM_NOFIELD		0
#define SIM_IDLE		1
#define SIM_HALTED		2
#define SIM_SELECTING	3
#define SIM_HALTING		4
#define SIM_ACKNOWLEDGE 5
#define SIM_WORK		6

#endif /* __ISO14443B_H */
