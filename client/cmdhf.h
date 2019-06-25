//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency commands
//-----------------------------------------------------------------------------

#ifndef CMDHF_H__
#define CMDHF_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "proxmark3.h"
#include "graph.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf14a.h"       // ISO14443-A
#include "cmdhf14b.h"       // ISO14443-B
#include "cmdhf15.h"        // ISO15693
#include "cmdhfepa.h"
#include "cmdhflegic.h"     // LEGIC
#include "cmdhficlass.h"    // ICLASS
#include "cmdhfmf.h"        // CLASSIC
#include "cmdhfmfu.h"       // ULTRALIGHT/NTAG etc
#include "cmdhfmfp.h"       // Mifare Plus
#include "cmdhfmfdes.h"     // DESFIRE
#include "cmdhftopaz.h"     // TOPAZ
#include "cmdhffelica.h"    // ISO18092 / FeliCa
#include "cmdhffido.h"      // FIDO authenticators
#include "cmdtrace.h"       // trace list

int CmdHF(const char *Cmd);
int CmdHFTune(const char *Cmd);
int CmdHFSearch(const char *Cmd);
int CmdHFSniff(const char *Cmd);

#endif
