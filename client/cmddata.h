//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data and Graph commands
//-----------------------------------------------------------------------------

#ifndef CMDDATA_H__
#define CMDDATA_H__

command_t * CmdDataCommands();

int CmdData(const char *Cmd);

int CmdAmp(const char *Cmd);
int Cmdaskdemod(const char *Cmd);
int CmdAutoCorr(const char *Cmd);
int CmdBitsamples(const char *Cmd);
int CmdBitstream(const char *Cmd);
int CmdBuffClear(const char *Cmd);
int CmdDec(const char *Cmd);
int CmdDetectClockRate(const char *Cmd);
int CmdFSKdemod(const char *Cmd);
int CmdGrid(const char *Cmd);
int CmdHexsamples(const char *Cmd);
int CmdHide(const char *Cmd);
int CmdHpf(const char *Cmd);
int CmdLoad(const char *Cmd);
int CmdLtrim(const char *Cmd);
int CmdManchesterDemod(const char *Cmd);
int CmdManchesterMod(const char *Cmd);
int CmdNorm(const char *Cmd);
int CmdPlot(const char *Cmd);
int CmdSamples(const char *Cmd);
int CmdSave(const char *Cmd);
int CmdScale(const char *Cmd);
int CmdThreshold(const char *Cmd);
int CmdZerocrossings(const char *Cmd);

#endif
