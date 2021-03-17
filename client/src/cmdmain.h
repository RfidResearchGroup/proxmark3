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

#include "common.h"
#include "cmdparser.h"    // command_t
#include "util.h"         // print_cb_t

#ifdef __cplusplus
extern "C" {
#endif

int CommandReceived(char *Cmd);
int CmdRem(const char *Cmd);
command_t *getTopLevelCommandTable(void);
int CommandReceivedCB(char *Cmd, print_cb_t callback);

#ifdef __cplusplus
}
#endif
#endif
