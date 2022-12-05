//-----------------------------------------------------------------------------
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
// Proxmark3 RDV40 Smartcard module commands
//-----------------------------------------------------------------------------

#ifndef CMDSMARTCARD_H__
#define CMDSMARTCARD_H__

#include "common.h"
#include "pm3_cmd.h" // structs

// On ARM side, ISO7816_MAX_FRAME is set to 260
// This means we can receive a full short APDU (256 bytes) of data and have enough room for
// SW status code and surrounding metadata without creating a buffer overflow.
#define MAX_APDU_SIZE 256

int CmdSmartcard(const char *Cmd);

bool smart_select(bool verbose, smart_card_atr_t *atr);
int ExchangeAPDUSC(bool verbose, uint8_t *datain, int datainlen, bool activateCard, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);

#endif
