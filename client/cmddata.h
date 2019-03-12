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

#include <stdio.h>    // also included in util.h
#include <string.h>   // also included in util.h
#include <inttypes.h>
#include <limits.h>   // for CmdNorm INT_MIN && INT_MAX
#include "util.h"
#include "cmdmain.h"
#include "proxmark3.h"// sendcommand
#include "ui.h"       // for show graph controls
#include "graph.h"    // for graph data
#include "comms.h"
#include "lfdemod.h"  // for demod code
#include "crc.h"      // for pyramid checksum maxim
#include "crc16.h"    // for FDXB demod checksum
#include "loclass/cipherutils.h" // for decimating samples in getsamples
#include "cmdlfem4x.h" // askem410xdecode

command_t *CmdDataCommands();

int CmdData(const char *Cmd);
void printDemodBuff(void);
void setDemodBuf(uint8_t *buff, size_t size, size_t startIdx);
bool getDemodBuf(uint8_t *buff, size_t *size);
void save_restoreDB(uint8_t saveOpt);// option '1' to save DemodBuffer any other to restore
int CmdPrintDemodBuff(const char *Cmd);

int Cmdaskrawdemod(const char *Cmd);
int Cmdaskmandemod(const char *Cmd);
int AutoCorrelate(const int *in, int *out, size_t len, int window, bool SaveGrph, bool verbose);
int CmdAskEdgeDetect(const char *Cmd);
int CmdAutoCorr(const char *Cmd);
int CmdBiphaseDecodeRaw(const char *Cmd);
int CmdBitsamples(const char *Cmd);
int CmdBuffClear(const char *Cmd);
int CmdDec(const char *Cmd);
int CmdDetectClockRate(const char *Cmd);
int CmdFSKrawdemod(const char *Cmd);
int CmdPSK1rawDemod(const char *Cmd);
int CmdPSK2rawDemod(const char *Cmd);
int CmdIdteckDemod(const char *Cmd);
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
int ASKbiphaseDemod(const char *Cmd, bool verbose);
int ASKDemod(const char *Cmd, bool verbose, bool emSearch, uint8_t askType);
int ASKDemod_ext(const char *Cmd, bool verbose, bool emSearch, uint8_t askType, bool *stCheck);
int FSKrawDemod(const char *Cmd, bool verbose);
int PSKDemod(const char *Cmd, bool verbose);
int NRZrawDemod(const char *Cmd, bool verbose);
int getSamples(int n, bool silent);
void setClockGrid(int clk, int offset);
int directionalThreshold(const int *in, int *out, size_t len, int8_t up, int8_t down);
extern int AskEdgeDetect(const int *in, int *out, int len, int threshold);

int CmdDataIIR(const char *Cmd);

#define MAX_DEMOD_BUF_LEN (1024*128)
#define BIGBUF_SIZE 40000
extern uint8_t DemodBuffer[MAX_DEMOD_BUF_LEN];
extern size_t DemodBufferLen;

extern int g_DemodClock;
extern size_t g_DemodStartIdx;
extern uint8_t g_debugMode;

#endif
