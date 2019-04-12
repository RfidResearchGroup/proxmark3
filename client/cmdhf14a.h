//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// 2011, Merlok
// 2015,216,2017 iceman, marshmellow, piwi
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------

#ifndef CMDHF14A_H__
#define CMDHF14A_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "proxmark3.h"
#include "common.h"
#include "ui.h"
#include "util.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "mifare.h"
#include "cmdhfmf.h"
#include "cmdhfmfu.h"
#include "cmdhf.h"  // list cmd
#include "mifare/mifarehost.h"
#include "emv/apduinfo.h"
#include "emv/emvcore.h"

// structure and database for uid -> tagtype lookups
typedef struct {
    uint8_t uid;
    const char *desc;
} manufactureName;

int CmdHF14A(const char *Cmd);
int CmdHF14ASniff(const char *Cmd); // used by hf topaz sniff
int CmdHF14ASim(const char *Cmd);   // used by hf mfu sim

int infoHF14A(bool verbose, bool do_nack_test);
const char *getTagInfo(uint8_t uid);
int Hf14443_4aGetCardData(iso14a_card_select_t *card);
int ExchangeAPDU14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);
int ExchangeRAW14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);

#endif
