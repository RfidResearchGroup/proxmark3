//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Main command parser entry point
//-----------------------------------------------------------------------------

#ifndef CMDMAIN_H__
#define CMDMAIN_H__

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "util_posix.h"
#include "proxmark3.h"
#include "usb_cmd.h"
#include "util.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf.h"
#include "cmddata.h"
#include "cmdhw.h"
#include "cmdlf.h"
#include "cmdtrace.h"
#include "cmdscript.h"
#include "cmdcrc.h"
#include "cmdanalyse.h"
#include "emv/cmdemv.h"   // EMV

#ifdef WITH_FLASH
#include "cmdflashmem.h"  // rdv40 flashmem commands
#endif

#ifdef WITH_SMARTCARD
#include "cmdsmartcard.h" // rdv40 smart card ISO7816 commands
#endif

extern int CommandReceived(char *Cmd);
extern command_t *getTopLevelCommandTable();

#endif
