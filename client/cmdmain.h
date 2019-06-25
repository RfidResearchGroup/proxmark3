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
#include "pm3_cmd.h"
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
#include "cmdflashmem.h"  // rdv40 flashmem commands
#include "cmdsmartcard.h" // rdv40 smart card ISO7816 commands
#include "cmdusart.h"     // rdv40 FPC USART commands

int CommandReceived(char *Cmd);
command_t *getTopLevelCommandTable(void);

#endif
