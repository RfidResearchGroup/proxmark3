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
#include <stdint.h>
#include <readline/readline.h>
#include <pthread.h>
#include <math.h>
#include <complex.h>
#include "util.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846264338327
#endif
#define MAX_PRINT_BUFFER 2048
typedef enum logLevel {NORMAL, SUCCESS, INFO, FAILED, WARNING, ERR, DEBUG} logLevel_t;

void ShowGui(void);
void HideGraphWindow(void);
void ShowGraphWindow(void);
void RepaintGraphWindow(void);
extern void PrintAndLog(char *fmt, ...);
void PrintAndLogOptions(char *str[][2], size_t size, size_t space);
void PrintAndLogEx(logLevel_t level, char *fmt, ...);
extern void SetLogFilename(char *fn);
void SetFlushAfterWrite(bool value);

extern double CursorScaleFactor;
extern int PlotGridX, PlotGridY, PlotGridXdefault, PlotGridYdefault, CursorCPos, CursorDPos, GridOffset;
extern bool GridLocked;
extern bool showDemod;

//extern uint8_t g_debugMode;

extern pthread_mutex_t print_lock;

extern void iceIIR_Butterworth(int *data, const size_t len);
extern void iceSimple_Filter(int *data, const size_t len, uint8_t k);
#endif
