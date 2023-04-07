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
// High frequency ISO14443B commands
//-----------------------------------------------------------------------------

#ifndef CMDHF14B_H__
#define CMDHF14B_H__

#include "common.h"
#include "iso14b.h"

int CmdHF14B(const char *Cmd);
int CmdHF14BNdefRead(const char *Cmd);

uint8_t *get_uid_from_filename(const char *filename);
int exchange_14b_apdu(uint8_t *datain, int datainlen, bool activate_field, bool leave_signal_on, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, int user_timeout);
int select_card_14443b_4(bool disconnect, iso14b_card_select_t *card);

int infoHF14B(bool verbose, bool do_aid_search);
int readHF14B(bool loop, bool verbose);
#endif
