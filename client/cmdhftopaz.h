//-----------------------------------------------------------------------------
// Copyright (C) 2015 Piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Topaz (NFC Type 1) commands
//-----------------------------------------------------------------------------

#ifndef CMDHFTOPAZ_H__
#define CMDHFTOPAZ_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cmdmain.h"
#include "cmdparser.h"
#include "cmdhf14a.h"
#include "ui.h"
#include "mifare.h"
#include "proxmark3.h"
#include "crc16.h"
#include "protocols.h"
#include "cmdhf.h"

int CmdHFTopaz(const char *Cmd);

int readTopazUid(void);
#endif
