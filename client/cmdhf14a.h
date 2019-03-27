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
#include "iso14443crc.h"
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
    char *desc;
} manufactureName;

extern int CmdHF14A(const char *Cmd);
extern int CmdHF14AList(const char *Cmd);
extern int CmdHF14AReader(const char *Cmd);
extern int CmdHF14AInfo(const char *Cmd);
extern int CmdHF14ASim(const char *Cmd);
extern int CmdHF14ASniff(const char *Cmd);
extern int CmdHF14ACmdRaw(const char *Cmd);
extern int CmdHF14ACUIDs(const char *Cmd);
extern int CmdHF14AAntiFuzz(const char *Cmd);

extern char *getTagInfo(uint8_t uid);
extern int Hf14443_4aGetCardData(iso14a_card_select_t *card);
extern int ExchangeAPDU14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);
extern int ExchangeRAW14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);

extern int usage_hf_14a_sim(void);
extern int usage_hf_14a_sniff(void);
extern int usage_hf_14a_raw(void);
extern int usage_hf_14a_antifuzz(void);
#endif
