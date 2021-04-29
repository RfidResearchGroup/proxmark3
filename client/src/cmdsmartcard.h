//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Smartcard module commands
//-----------------------------------------------------------------------------

#ifndef CMDSMARTCARD_H__
#define CMDSMARTCARD_H__

#include "common.h"
#include "mifare.h" // structs

int CmdSmartcard(const char *Cmd);

bool smart_select(bool silent, smart_card_atr_t *atr);
int ExchangeAPDUSC(bool silent, uint8_t *datain, int datainlen, bool activateCard, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);

#endif
