//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// 2016, 2017 marshmellow, iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x05 commands
//-----------------------------------------------------------------------------

#ifndef CMDLFEM4X05_H__
#define CMDLFEM4X05_H__

#include "common.h"

int CmdLFEM4X05(const char *Cmd);

bool EM4x05IsBlock0(uint32_t *word);
int EM4x05ReadWord_ext(uint8_t addr, uint32_t pwd, bool usePwd, uint32_t *word);


int CmdEM4x05Demod(const char *Cmd);
int CmdEM4x05Dump(const char *Cmd);
int CmdEM4x05Read(const char *Cmd);
int CmdEM4x05Write(const char *Cmd);
int CmdEM4x05Wipe(const char *Cmd);
int CmdEM4x05Info(const char *Cmd);
int CmdEM4x05Chk(const char *Cmd);
int CmdEM4x05Unlock(const char *Cmd);

#endif
