//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// GUI functions
//-----------------------------------------------------------------------------

#ifndef __PROXGUI_H
#define __PROXGUI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

void ShowGraphWindow(void);
void HideGraphWindow(void);
void RepaintGraphWindow(void);
void MainGraphics(void);
void InitGraphics(int argc, char **argv, char *script_cmds_file, char *script_cmd);
void ExitGraphics(void);
#ifndef MAX_GRAPH_TRACE_LEN
#define MAX_GRAPH_TRACE_LEN (40000 * 8)
#endif
extern int GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern size_t GraphTraceLen;
extern int s_Buff[MAX_GRAPH_TRACE_LEN];

extern double CursorScaleFactor;
extern int PlotGridX, PlotGridY, PlotGridXdefault, PlotGridYdefault, GridOffset;
extern uint32_t CursorCPos, CursorDPos;
extern int CommandFinished;
extern int offline;
extern bool GridLocked;

//Operations defined in data_operations
//int autoCorr(const int* in, int *out, size_t len, int window);
int AskEdgeDetect(const int *in, int *out, int len, int threshold);
int AutoCorrelate(const int *in, int *out, size_t len, size_t window, bool SaveGrph, bool verbose);
int directionalThreshold(const int *in, int *out, size_t len, int8_t up, int8_t down);
void save_restoreGB(uint8_t saveOpt);

#define GRAPH_SAVE 1
#define GRAPH_RESTORE 0
#define MAX_DEMOD_BUF_LEN (1024*128)
extern uint8_t DemodBuffer[MAX_DEMOD_BUF_LEN];
extern size_t DemodBufferLen;
extern size_t g_DemodStartIdx;
extern bool showDemod;
extern uint8_t g_debugMode;

#ifdef __cplusplus
}
#endif
#endif
