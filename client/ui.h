//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// UI utilities
//-----------------------------------------------------------------------------

#ifndef UI_H__
#define UI_H__

#include <math.h>
#include <complex.h>
#include "util.h"

void ShowGui(void);
void HideGraphWindow(void);
void ShowGraphWindow(void);
void RepaintGraphWindow(void);
void PrintAndLog(char *fmt, ...);
void SetLogFilename(char *fn);

extern double CursorScaleFactor;
extern int PlotGridX, PlotGridY, PlotGridXdefault, PlotGridYdefault;
extern int offline;
extern int flushAfterWrite;   //buzzy

int manchester_decode( int * data, const size_t len, uint8_t * dataout,  size_t dataoutlen);
int GetT55x7Clock( const int * data, const size_t len, int high );
int DetectFirstTransition(const int * data, const size_t len, int low);
void PrintPaddedManchester( uint8_t * bitStream, size_t len, size_t blocksize);
void ManchesterDiffDecodedString( const uint8_t *bitStream, size_t len, uint8_t invert );
int ManchesterConvertFrom255(const int * data, const size_t len, uint8_t * dataout,int dataoutlen, int high, int low, int clock, int startIndex);
int ManchesterConvertFrom1(const int * data, const size_t len, uint8_t * dataout, int dataoutlen, int clock, int startIndex);
void iceFsk2(int * data, const size_t len);
void iceFsk3(int * data, const size_t len);
#endif
