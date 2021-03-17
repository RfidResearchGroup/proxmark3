//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443B commands
//-----------------------------------------------------------------------------

#ifndef CMDHF14B_H__
#define CMDHF14B_H__

#include "common.h"

int CmdHF14B(const char *Cmd);

int exchange_14b_apdu(uint8_t *datain, int datainlen, bool activate_field, bool leave_signal_on, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, int user_timeout);

int infoHF14B(bool verbose, bool do_aid_search);
int readHF14B(bool verbose);
#endif
