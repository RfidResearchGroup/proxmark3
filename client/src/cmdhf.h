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
// High frequency commands
//-----------------------------------------------------------------------------

#ifndef CMDHF_H__
#define CMDHF_H__

#include "common.h"

int CmdHF(const char *Cmd);
int CmdHFTune(const char *Cmd);
int CmdHFSearch(const char *Cmd);
int CmdHFSniff(const char *Cmd);
int CmdHFPlot(const char *Cmd);

int handle_hf_plot(void);
#endif
