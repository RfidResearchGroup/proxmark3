//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Copyright (C) 2011 Gerhard de Koning Gans
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency iClass support
//-----------------------------------------------------------------------------

#ifndef CMDHFICLASS_H__
#define CMDHFICLASS_H__

int CmdHFiClass(const char *Cmd);

int CmdHFiClassCalcNewKey(const char *Cmd);
int CmdHFiClassCloneTag(const char *Cmd);
int CmdHFiClassDecrypt(const char *Cmd);
int CmdHFiClassEncryptBlk(const char *Cmd);
int CmdHFiClassELoad(const char *Cmd);
int CmdHFiClassList(const char *Cmd);
int HFiClassReader(const char *Cmd, bool loop, bool verbose);
int CmdHFiClassReader(const char *Cmd);
int CmdHFiClassReader_Dump(const char *Cmd);
int CmdHFiClassReader_Replay(const char *Cmd);
int CmdHFiClassReadKeyFile(const char *filename);
int CmdHFiClassReadTagFile(const char *Cmd);
int CmdHFiClass_ReadBlock(const char *Cmd);
int CmdHFiClass_TestMac(const char *Cmd);
int CmdHFiClassManageKeys(const char *Cmd);
int CmdHFiClass_loclass(const char *Cmd);
int CmdHFiClassSnoop(const char *Cmd);
int CmdHFiClassSim(const char *Cmd);
int CmdHFiClassWriteKeyFile(const char *Cmd);
int CmdHFiClass_WriteBlock(const char *Cmd);
void printIclassDumpContents(uint8_t *iclass_dump, uint8_t startblock, uint8_t endblock, size_t filesize);
void HFiClassCalcDivKey(uint8_t	*CSN, uint8_t	*KEY, uint8_t *div_key, bool elite);
#endif
