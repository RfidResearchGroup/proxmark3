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
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------

#ifndef CMDHF14A_H__
#define CMDHF14A_H__

#include "common.h"
#include "pm3_cmd.h" //hf14a_config
#include "mifare.h" // structs

// structure and database for uid -> tagtype lookups
typedef struct {
    uint8_t uid;
    const char *desc;
} manufactureName_t;

typedef struct {
    const char *aid;
    const uint8_t aid_length;
    const char *desc;
    const char *hint;
} hintAIDList_t;

int CmdHF14A(const char *Cmd);
int CmdHF14ASniff(const char *Cmd);         // used by hf topaz sniff
int CmdHF14ASim(const char *Cmd);           // used by hf mfu sim
int CmdHF14ANdefRead(const char *Cmd);      // used by cmdnfc.c
int CmdHF14ANdefFormat(const char *Cmd);    // used by cmdnfc.c
int CmdHF14ANdefWrite(const char *Cmd);     // used by cmdnfc.c

int hf14a_getconfig(hf14a_config *config);
int hf14a_setconfig(hf14a_config *config, bool verbose);
int infoHF14A(bool verbose, bool do_nack_test, bool do_aid_search);
int infoHF14A4Applications(bool verbose);
const char *getTagInfo(uint8_t uid);
int Hf14443_4aGetCardData(iso14a_card_select_t *card);
int ExchangeAPDU14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);
int ExchangeRAW14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, bool silentMode);

iso14a_polling_parameters_t iso14a_get_polling_parameters(bool use_ecp, bool use_magsafe);
int SelectCard14443A_4(bool disconnect, bool verbose, iso14a_card_select_t *card);
int SelectCard14443A_4_WithParameters(bool disconnect, bool verbose, iso14a_card_select_t *card, iso14a_polling_parameters_t *polling_parameters);

bool Get_apdu_in_framing(void);
void Set_apdu_in_framing(bool v);
#endif
