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

int CmdData(const char *Cmd);

// Still quite work to do here to provide proper functions for internal usage...
/*
int Cmdaskrawdemod(const char *Cmd);
int Cmdaskmandemod(const char *Cmd);
int CmdAskEdgeDetect(const char *Cmd);
int CmdAutoCorr(const char *Cmd);
int CmdBiphaseDecodeRaw(const char *Cmd);
int CmdBitsamples(const char *Cmd);
int CmdBuffClear(const char *Cmd);
int CmdDec(const char *Cmd);
int CmdDetectClockRate(const char *Cmd);
int CmdFSKrawdemod(const char *Cmd);
int CmdPSK2rawDemod(const char *Cmd);
int CmdHexsamples(const char *Cmd);
int CmdHide(const char *Cmd);
int CmdLoad(const char *Cmd);
int CmdRtrim(const char *Cmd);
int Cmdmandecoderaw(const char *Cmd);
int CmdNRZrawDemod(const char *Cmd);
int CmdPrintDemodBuff(const char *Cmd);
int CmdRawDemod(const char *Cmd);
int CmdSamples(const char *Cmd);
int CmdSave(const char *Cmd);
int CmdScale(const char *Cmd);
int CmdDirectionalThreshold(const char *Cmd);
int CmdZerocrossings(const char *Cmd);
int CmdDataIIR(const char *Cmd);
*/
int CmdPrintDemodBuff(const char *Cmd);                                                         // used by cmd lf keri, lf nexwatch
int CmdPSK1rawDemod(const char *Cmd);                                                           // used by cmd lf
int CmdGetBitStream(const char *Cmd);                                                           // used by cmd lf
int CmdGrid(const char *Cmd);                                                                   // used by cmd lf cotag
int CmdHpf(const char *Cmd);                                                                    // used by cmd lf data (!)
int CmdLtrim(const char *Cmd);                                                                  // used by cmd lf em4x, lf t55xx
int CmdNorm(const char *Cmd);                                                                   // used by cmd lf data (!)
int CmdPlot(const char *Cmd);                                                                   // used by cmd lf cotag
int CmdTuneSamples(const char *Cmd);                                                            // used by cmd lf hw
int ASKbiphaseDemod(const char *Cmd, bool verbose);                                             // used by cmd lf em4x, lf fdx, lf guard, lf jablotron, lf nedap, lf t55xx
int ASKDemod(const char *Cmd, bool verbose, bool emSearch, uint8_t askType);                    // used by cmd lf em4x, lf t55xx, lf viking
int ASKDemod_ext(const char *Cmd, bool verbose, bool emSearch, uint8_t askType, bool *stCheck); // used by cmd lf, lf em4x, lf noralsy, le presco, lf securekey, lf t55xx, lf visa2k
int FSKrawDemod(const char *Cmd, bool verbose);                                                 // used by cmd lf, lf em4x, lf t55xx
int PSKDemod(const char *Cmd, bool verbose);                                                    // used by cmd lf em4x, lf indala, lf keri, lf nexwatch, lf t55xx
int NRZrawDemod(const char *Cmd, bool verbose);                                                 // used by cmd lf pac, lf t55xx


void printDemodBuff(void);
void setDemodBuff(uint8_t *buff, size_t size, size_t start_idx);
bool getDemodBuff(uint8_t *buff, size_t *size);
void save_restoreDB(uint8_t saveOpt);// option '1' to save DemodBuffer any other to restore
int AutoCorrelate(const int *in, int *out, size_t len, size_t window, bool SaveGrph, bool verbose);
int getSamples(uint32_t n, bool silent);
void setClockGrid(uint32_t clk, int offset);
int directionalThreshold(const int *in, int *out, size_t len, int8_t up, int8_t down);
int AskEdgeDetect(const int *in, int *out, int len, int threshold);
int demodIdteck(void);

#define MAX_DEMOD_BUF_LEN (1024*128)
#define BIGBUF_SIZE 40000
extern uint8_t DemodBuffer[MAX_DEMOD_BUF_LEN];
extern size_t DemodBufferLen;

extern int g_DemodClock;
extern size_t g_DemodStartIdx;
extern uint8_t g_debugMode;

#endif
