//-----------------------------------------------------------------------------
// 2011, Merlok
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------

#ifndef CMDHF14A_H__
#define CMDHF14A_H__

int CmdHF14A(const char *Cmd);
int CmdHF14AList(const char *Cmd);
int CmdHF14AMifare(const char *Cmd);
int CmdHF14AReader(const char *Cmd);
int CmdHF14ASim(const char *Cmd);
int CmdHF14ASniff(const char *Cmd);

char* getTagInfo(uint8_t uid);

int usage_hf_14a_sim(void);
int usage_hf_14a_sniff(void);
int usage_hf_14a_raw(void);
#endif
