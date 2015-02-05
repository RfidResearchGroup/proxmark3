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
void printDemodBuff();
int CmdAmp(const char *Cmd);
int Cmdaskdemod(const char *Cmd);
int CmdAskEM410xDemod(const char *Cmd);
int Cmdaskrawdemod(const char *Cmd);
int Cmdaskmandemod(const char *Cmd);
int CmdAutoCorr(const char *Cmd);
int CmdBiphaseDecodeRaw(const char *Cmd);
int CmdBitsamples(const char *Cmd);
int CmdBitstream(const char *Cmd);
int CmdBuffClear(const char *Cmd);
int CmdDec(const char *Cmd);
int CmdDetectClockRate(const char *Cmd);
int CmdDetectNRZClockRate(const char *Cmd);
int CmdDetectPSKClockRate(const char *Cmd);
int CmdFSKdemodAWID(const char *Cmd);
int CmdFSKdemod(const char *Cmd);
int CmdFSKdemodHID(const char *Cmd);
int CmdFSKdemodIO(const char *Cmd);
int CmdFSKdemodParadox(const char *Cmd);
int CmdFSKdemodPyramid(const char *Cmd);
int CmdFSKfcDetect(const char *Cmd);
int CmdFSKrawdemod(const char *Cmd);
int CmdDetectPskClockRate(const char *Cmd);
int CmdPSK1rawDemod(const char *Cmd);
int CmdPSK2rawDemod(const char *Cmd);
int CmdGrid(const char *Cmd);
int CmdHexsamples(const char *Cmd);
int CmdHide(const char *Cmd);
int CmdHpf(const char *Cmd);
int CmdLoad(const char *Cmd);
int CmdLtrim(const char *Cmd);
int CmdRtrim(const char *Cmd);
int Cmdmandecoderaw(const char *Cmd);
int CmdManchesterDemod(const char *Cmd);
int CmdManchesterMod(const char *Cmd);
int CmdNorm(const char *Cmd);
int CmdNRZrawDemod(const char *Cmd);
int CmdPlot(const char *Cmd);
int CmdSamples(const char *Cmd);
int CmdTuneSamples(const char *Cmd);
int CmdSave(const char *Cmd);
int CmdScale(const char *Cmd);
int CmdThreshold(const char *Cmd);
int CmdDirectionalThreshold(const char *Cmd);
int CmdZerocrossings(const char *Cmd);
int CmdIndalaDecode(const char *Cmd);

#define MAX_DEMOD_BUF_LEN (1024*128)
extern uint8_t DemodBuffer[MAX_DEMOD_BUF_LEN];
extern int DemodBufferLen;

#define BIGBUF_SIZE 40000

#endif
