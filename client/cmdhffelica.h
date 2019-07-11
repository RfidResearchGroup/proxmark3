//-----------------------------------------------------------------------------
// Copyright (C) 2017 October, Satsuoni
// 2017 iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO18092 / FeliCa commands
//-----------------------------------------------------------------------------

#ifndef CMDHFFELICA_H__
#define CMDHFFELICA_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "proxmark3.h"
#include "common.h"
#include "ui.h"
#include "util.h"
#include "cmdparser.h"
#include "comms.h"      // getfromdevice
#include "cmdhf.h"      // list cmd
#include "mifare.h"     // felica_card_select_t struct

int CmdHFFelica(const char *Cmd);

int readFelicaUid(bool verbose);
#endif
