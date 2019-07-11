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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "crc16.h"
#include "proxmark3.h"
#include "graph.h"
#include "util.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "cmdhf14a.h"
#include "cmdhf.h"
#include "prng.h"
#include "mbedtls/sha1.h"
#include "mifare.h"     // structs/enum for ISO14B
#include "protocols.h"  // definitions of ISO14B protocol

int CmdHF14B(const char *Cmd);

int infoHF14B(bool verbose);
int readHF14B(bool verbose);
#endif
