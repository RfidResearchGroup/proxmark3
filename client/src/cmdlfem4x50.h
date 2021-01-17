//-----------------------------------------------------------------------------
// Copyright (C) 2020 tharexde
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x50 commands
//-----------------------------------------------------------------------------

#ifndef CMDLFEM4X50_H__
#define CMDLFEM4X50_H__

#include "em4x50.h"

int CmdLFEM4X50(const char *Cmd);

int read_em4x50_uid(void);
bool detect_4x50_block(void);
int em4x50_read(em4x50_data_t *etd, em4x50_word_t *out);

int CmdEM4x50Info(const char *Cmd);
int CmdEM4x50Write(const char *Cmd);
int CmdEM4x50WritePwd(const char *Cmd);
int CmdEM4x50Read(const char *Cmd);
int CmdEM4x50Dump(const char *Cmd);
int CmdEM4x50Wipe(const char *Cmd);
int CmdEM4x50Brute(const char *Cmd);
int CmdEM4x50Login(const char *Cmd);
int CmdEM4x50Restore(const char *Cmd);
int CmdEM4x50Sim(const char *Cmd);
int CmdEM4x50Reader(const char *Cmd);
int CmdEM4x50ELoad(const char *Cmd);
int CmdEM4x50ESave(const char *Cmd);
int CmdEM4x50Chk(const char *Cmd);
int CmdEM4x50EView(const char *Cmd);

#endif
