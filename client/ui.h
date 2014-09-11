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

uint8_t manchester_decode(const uint8_t * data, const size_t len, uint8_t * dataout);
void PrintPaddedManchester( uint8_t * bitStream, size_t len, size_t blocksize);
#endif
