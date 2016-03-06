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

#include <stdlib.h>  //size_t
#include <stdint.h>  //uint_32+
#include <stdbool.h> //bool

#include "cmdparser.h" // for command_t

command_t * CmdDataCommands();

int CmdData(const char *Cmd);
void printDemodBuff(void);
void setDemodBuf(uint8_t *buff, size_t size, size_t startIdx);
int CmdAskEM410xDemod(const char *Cmd);
int CmdVikingDemod(const char *Cmd);
int CmdG_Prox_II_Demod(const char *Cmd);
int Cmdaskrawdemod(const char *Cmd);
int Cmdaskmandemod(const char *Cmd);
int AutoCorrelate(int window, bool SaveGrph, bool verbose);
int CmdAutoCorr(const char *Cmd);
int CmdBiphaseDecodeRaw(const char *Cmd);
int CmdBitsamples(const char *Cmd);
int CmdBuffClear(const char *Cmd);
int CmdDec(const char *Cmd);
int CmdDetectClockRate(const char *Cmd);
int CmdFDXBdemodBI(const char *Cmd);
int CmdFSKdemodAWID(const char *Cmd);
int CmdFSKdemodHID(const char *Cmd);
int CmdFSKdemodIO(const char *Cmd);
int CmdFSKdemodParadox(const char *Cmd);
int CmdFSKdemodPyramid(const char *Cmd);
int CmdFSKrawdemod(const char *Cmd);
int CmdPSK1rawDemod(const char *Cmd);
int CmdPSK2rawDemod(const char *Cmd);
int CmdPSKNexWatch(const char *Cmd);
int CmdGrid(const char *Cmd);
int CmdGetBitStream(const char *Cmd);
int CmdHexsamples(const char *Cmd);
int CmdHide(const char *Cmd);
int CmdHpf(const char *Cmd);
int CmdLoad(const char *Cmd);
int CmdLtrim(const char *Cmd);
int CmdRtrim(const char *Cmd);
int Cmdmandecoderaw(const char *Cmd);
int CmdNorm(const char *Cmd);
int CmdNRZrawDemod(const char *Cmd);
int CmdPlot(const char *Cmd);
int CmdPrintDemodBuff(const char *Cmd);
int CmdRawDemod(const char *Cmd);
int CmdSamples(const char *Cmd);
int CmdTuneSamples(const char *Cmd);
int CmdSave(const char *Cmd);
int CmdScale(const char *Cmd);
int CmdDirectionalThreshold(const char *Cmd);
int CmdZerocrossings(const char *Cmd);
int CmdIndalaDecode(const char *Cmd);
int AskEm410xDecode(bool verbose, uint32_t *hi, uint64_t *lo );
int AskEm410xDemod(const char *Cmd, uint32_t *hi, uint64_t *lo, bool verbose);
int ASKbiphaseDemod(const char *Cmd, bool verbose);
int ASKDemod(const char *Cmd, bool verbose, bool emSearch, uint8_t askType);
int ASKDemod_ext(const char *Cmd, bool verbose, bool emSearch, uint8_t askType, bool *stCheck);
int FSKrawDemod(const char *Cmd, bool verbose);
int PSKDemod(const char *Cmd, bool verbose);
int NRZrawDemod(const char *Cmd, bool verbose);
void printEM410x(uint32_t hi, uint64_t id);
int getSamples(const char *Cmd, bool silent);


#define MAX_DEMOD_BUF_LEN (1024*128)
extern uint8_t DemodBuffer[MAX_DEMOD_BUF_LEN];
extern size_t DemodBufferLen;
extern uint8_t g_debugMode;
#define BIGBUF_SIZE 40000

#endif
