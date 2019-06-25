//-----------------------------------------------------------------------------
// Merlok - June 2012
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support mifare classic sniffer.
//-----------------------------------------------------------------------------

#ifndef __MIFARESNIFF_H
#define __MIFARESNIFF_H

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"
#include "iso14443a.h"
#include "crapto1/crapto1.h"
#include "mifareutil.h"
#include "common.h"

#define SNF_INIT        0
#define SNF_NO_FIELD    1
#define SNF_ATQA        2
#define SNF_UID         3
#define SNF_SAK         4
#define SNF_CARD_IDLE   5
#define SNF_CARD_CMD    6
#define SNF_MAGIC_WUPC2 7

#define SNF_UID_4       0
#define SNF_UID_7       0
#define SNF_UID_10      0

void MfSniffInit(void);
bool RAMFUNC MfSniffLogic(const uint8_t *data, uint16_t len, uint8_t *parity, uint16_t bitCnt, bool reader);
void RAMFUNC MfSniffSend(void);
void MfSniffEnd(void);

#endif
