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
// Hardware commands
//-----------------------------------------------------------------------------

#ifndef CMDHW_H__
#define CMDHW_H__

#include "common.h"
#include "pm3_cmd.h"

int CmdHW(const char *Cmd);

int handle_tearoff(tearoff_params_t *params, bool verbose);
void pm3_version(bool verbose, bool oneliner);
void pm3_version_short(void);
int set_fpga_mode(uint8_t mode);
#endif
