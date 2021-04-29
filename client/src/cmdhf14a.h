//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// 2011,2019 Merlok
// 2015,2016,2017 iceman, marshmellow, piwi
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------

#ifndef CMDHF14A_H__
#define CMDHF14A_H__

#include "common.h"

#include "mifare.h" // structs

// structure and database for uid -> tagtype lookups
typedef struct {
    uint8_t uid;
    const char *desc;
} manufactureName;

int CmdHF14A(const char *Cmd);
int CmdHF14ASniff(const char *Cmd); // used by hf topaz sniff
int CmdHF14ASim(const char *Cmd);   // used by hf mfu sim

int infoHF14A(bool verbose, bool do_nack_test, bool do_aid_search);
const char *getTagInfo(uint8_t uid);
int Hf14443_4aGetCardData(iso14a_card_select_t *card);
int ExchangeAPDU14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);
int ExchangeRAW14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, bool silentMode);

#endif
