//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hardware commands
//-----------------------------------------------------------------------------

#ifndef CMDHW_H__
#define CMDHW_H__

#include "common.h"
#include "pm3_cmd.h"

int CmdHW(const char *Cmd);

int handle_tearoff(tearoff_params_t *params, bool verbose);
void pm3_version(bool verbose, bool oneliner);

#endif
