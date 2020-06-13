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

#include <pthread.h>
#include "common.h"
#include "ansi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _USE_MATH_DEFINES

typedef enum logLevel {NORMAL, SUCCESS, INFO, FAILED, WARNING, ERR, DEBUG, INPLACE, HINT} logLevel_t;
typedef enum emojiMode {ALIAS, EMOJI, ALTTEXT, ERASE} emojiMode_t;
typedef enum clientdebugLevel {cdbOFF, cdbSIMPLE, cdbFULL} clientdebugLevel_t;
// typedef enum devicedebugLevel {ddbOFF, ddbERROR, ddbINFO, ddbDEBUG, ddbEXTENDED} devicedebugLevel_t;
//typedef enum savePaths {spDefault, spDump, spTrace, spItemCount} savePaths_t; // last item spItemCount used to auto map to number of files
typedef struct {int x; int y; int h; int w;} qtWindow_t;
typedef struct pm3_device pm3_device;

typedef struct {
    bool preferences_loaded;
    bool stdinOnTTY;
    bool stdoutOnTTY;
    bool supports_colors;
    emojiMode_t emoji_mode;
    bool pm3_present;
    bool help_dump_mode;
    bool show_hints;
    bool window_changed; // track if plot/overlay pos/size changed to save on exit
    qtWindow_t plot;
    qtWindow_t overlay;
//    char *defaultPaths[spItemCount]; // Array should allow loop searching for files
    clientdebugLevel_t client_debug_level;
//    uint8_t device_debug_level;
    pm3_device *current_device;
} session_arg_t;

extern session_arg_t session;
extern bool showDemod;
#ifndef M_PI
#define M_PI 3.14159265358979323846264338327
#endif
#define MAX_PRINT_BUFFER 2048

void PrintAndLogOptions(const char *str[][2], size_t size, size_t space);
void PrintAndLogEx(logLevel_t level, const char *fmt, ...);
void SetFlushAfterWrite(bool value);
void memcpy_filter_ansi(void *dest, const void *src, size_t n, bool filter);
void memcpy_filter_rlmarkers(void *dest, const void *src, size_t n);
void memcpy_filter_emoji(void *dest, const void *src, size_t n, emojiMode_t mode);

int searchHomeFilePath(char **foundpath, const char *subdir, const char *filename, bool create_home);

extern pthread_mutex_t print_lock;

void iceIIR_Butterworth(int *data, const size_t len);
void iceSimple_Filter(int *data, const size_t len, uint8_t k);
#ifdef __cplusplus
}
#endif
#endif
