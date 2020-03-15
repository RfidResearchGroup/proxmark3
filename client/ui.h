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

#include "common.h"
#include <pthread.h>
#include "ansi.h"

#define _USE_MATH_DEFINES

typedef struct {
    bool stdinOnTTY;
    bool stdoutOnTTY;
    bool supports_colors;
    bool pm3_present;
    bool help_dump_mode;
} session_arg_t;

extern session_arg_t session;

#ifndef M_PI
#define M_PI 3.14159265358979323846264338327
#endif
#define MAX_PRINT_BUFFER 2048
typedef enum logLevel {NORMAL, SUCCESS, INFO, FAILED, WARNING, ERR, DEBUG, INPLACE, HINT} logLevel_t;

void ShowGui(void);
void HideGraphWindow(void);
void ShowGraphWindow(void);
void RepaintGraphWindow(void);
void PrintAndLogOptions(const char *str[][2], size_t size, size_t space);
void PrintAndLogEx(logLevel_t level, const char *fmt, ...);
void SetFlushAfterWrite(bool value);
void memcpy_filter_ansi(void *dest, const void *src, size_t n, bool filter);

extern double CursorScaleFactor;
extern int PlotGridX, PlotGridY, PlotGridXdefault, PlotGridYdefault, GridOffset;
extern uint32_t CursorCPos, CursorDPos;
extern bool GridLocked;
extern bool showDemod;

int searchHomeFilePath(char **foundpath, const char *filename, bool create_home);

extern pthread_mutex_t print_lock;

void iceIIR_Butterworth(int *data, const size_t len);
void iceSimple_Filter(int *data, const size_t len, uint8_t k);
#endif
