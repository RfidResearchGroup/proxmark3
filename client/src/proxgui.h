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
#include <stddef.h>
#include <stdbool.h>

void ShowGraphWindow(void);
void HideGraphWindow(void);
void RepaintGraphWindow(void);
void MainGraphics(void);
void InitGraphics(int argc, char **argv, char *script_cmds_file, char *script_cmd, bool stayInCommandLoop);
void ExitGraphics(void);

extern double CursorScaleFactor;
extern int PlotGridX, PlotGridY, PlotGridXdefault, PlotGridYdefault, GridOffset;
extern uint32_t CursorCPos, CursorDPos;
extern int CommandFinished;
extern int offline;
extern bool GridLocked;

#define GRAPH_SAVE 1
#define GRAPH_RESTORE 0

#ifndef FILE_PATH_SIZE
#define FILE_PATH_SIZE 1000
#endif

#ifdef __cplusplus
}
#endif
#endif
