//-----------------------------------------------------------------------------
// Copyright (C) 2011 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE commands
//-----------------------------------------------------------------------------

#ifndef CMDHFMF_H__
#define CMDHFMF_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "proxmark3.h"
#include "iso14443crc.h"
#include "data.h"
//#include "proxusb.h"
#include "ui.h"
#include "cmdparser.h"
#include "common.h"
#include "util.h"
#include "mifarehost.h"

int CmdHFMF(const char *Cmd);

int CmdHF14AMfDbg(const char* cmd);
int CmdHF14AMfRdBl(const char* cmd);
int CmdHF14AMfRdSc(const char* cmd);
int CmdHF14AMfDump(const char* cmd);
int CmdHF14AMfRestore(const char* cmd);
int CmdHF14AMfWrBl(const char* cmd);
int CmdHF14AMfChk(const char* cmd);
int CmdHF14AMifare(const char* cmd);
int CmdHF14AMfNested(const char* cmd);
int CmdHF14AMfSniff(const char* cmd);
int CmdHF14AMf1kSim(const char* cmd);
int CmdHF14AMfEClear(const char* cmd);
int CmdHF14AMfEGet(const char* cmd);
int CmdHF14AMfESet(const char* cmd);
int CmdHF14AMfELoad(const char* cmd);
int CmdHF14AMfESave(const char* cmd);
int CmdHF14AMfECFill(const char* cmd);
int CmdHF14AMfEKeyPrn(const char* cmd);
int CmdHF14AMfCSetUID(const char* cmd);
int CmdHF14AMfCSetBlk(const char* cmd);
int CmdHF14AMfCGetBlk(const char* cmd);
int CmdHF14AMfCGetSc(const char* cmd);
int CmdHF14AMfCLoad(const char* cmd);
int CmdHF14AMfCSave(const char* cmd);

#endif
