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
// Low frequency commands
//-----------------------------------------------------------------------------

#ifndef CMDLF_H__
#define CMDLF_H__

#include "common.h"
#include "pm3_cmd.h" // sample_config_t

#define T55XX_WRITE_TIMEOUT 1500

int CmdLF(const char *Cmd);

int CmdLFConfig(const char *Cmd);

int CmdLFCommandRead(const char *Cmd);
int CmdFlexdemod(const char *Cmd);
int CmdLFRead(const char *Cmd);
int CmdLFSim(const char *Cmd);
int CmdLFaskSim(const char *Cmd);
int CmdLFfskSim(const char *Cmd);
int CmdLFpskSim(const char *Cmd);
int CmdLFSimBidir(const char *Cmd);
int CmdLFSniff(const char *Cmd);
int CmdVchDemod(const char *Cmd);
int CmdLFfind(const char *Cmd);

int lf_read(bool verbose, uint32_t samples);
int lf_sniff(bool verbose, uint32_t samples);
int lf_config(sample_config *config);
int lf_getconfig(sample_config *config);
int lfsim_upload_gb(void);
int lfsim_wait_check(uint32_t cmd);

int lf_config_savereset(sample_config *config);
#endif
