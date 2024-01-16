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
// Data and Graph commands
//-----------------------------------------------------------------------------

#ifndef CMDDATA_H__
#define CMDDATA_H__

#include "common.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

//#include <stdlib.h>  //size_t

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
int CmdSave(const char *Cmd);                                                                   // used by cmd auto
int CmdTuneSamples(const char *Cmd);                                                            // used by cmd lf hw

int ASKbiphaseDemod(int offset, int clk, int invert, int maxErr, bool verbose);                 // used by cmd lf em4x, lf fdxb, lf guard, lf jablotron, lf nedap, lf t55xx
int ASKDemod(int clk, int invert, int maxErr, size_t maxlen, bool amplify, bool verbose, bool emSearch, uint8_t askType);                    // used by cmd lf em4x, lf t55xx, lf viking
int ASKDemod_ext(int clk, int invert, int maxErr, size_t maxlen, bool amplify, bool verbose, bool emSearch, uint8_t askType, bool *stCheck); // used by cmd lf, lf em4x, lf noralsy, le presco, lf securekey, lf t55xx, lf visa2k
int FSKrawDemod(uint8_t rfLen, uint8_t invert, uint8_t fchigh, uint8_t fclow, bool verbose);    // used by cmd lf, lf em4x, lf t55xx
int PSKDemod(int clk, int invert, int maxErr, bool verbose);                                    // used by cmd lf em4x, lf indala, lf keri, lf nexwatch, lf t55xx
int NRZrawDemod(int clk, int invert, int maxErr, bool verbose);                                 // used by cmd lf pac, lf t55xx


int printDemodBuff(uint8_t offset, bool strip_leading, bool invert, bool print_hex);

void setDemodBuff(const uint8_t *buff, size_t size, size_t start_idx);
bool getDemodBuff(uint8_t *buff, size_t *size);
void save_restoreDB(uint8_t saveOpt);// option '1' to save g_DemodBuffer any other to restore
int AutoCorrelate(const int *in, int *out, size_t len, size_t window, bool SaveGrph, bool verbose);

int getSamples(uint32_t n, bool verbose);
int getSamplesEx(uint32_t start, uint32_t end, bool verbose, bool ignore_lf_config);

void setClockGrid(uint32_t clk, int offset);
int directionalThreshold(const int *in, int *out, size_t len, int8_t up, int8_t down);
int centerThreshold(const int *in, int *out, size_t len, int8_t up, int8_t down);
int AskEdgeDetect(const int *in, int *out, int len, int threshold);

#define MAX_DEMOD_BUF_LEN (1024*128)
extern uint8_t g_DemodBuffer[MAX_DEMOD_BUF_LEN];
extern size_t g_DemodBufferLen;

extern int g_DemodClock;
extern int32_t g_DemodStartIdx;

#ifdef __cplusplus
}
#endif
#endif
