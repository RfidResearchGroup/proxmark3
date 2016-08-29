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

#define _USE_MATH_DEFINES
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <readline/readline.h>
#include <pthread.h>
#include <math.h>
#include <complex.h>
#include "loclass/cipherutils.h"
#include "util.h"
#include "cmdmain.h"
#include "cmddata.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846264338327
#endif
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

void iceIIR_Butterworth(int * data, const size_t len);
void iceSimple_Filter(int *data, const size_t len, uint8_t k);
#endif
