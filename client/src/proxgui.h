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

// hook up picture viewer
void ShowPictureWindow(uint8_t *data, int len);
void ShowBase64PictureWindow(char *b64);
void HidePictureWindow(void);
void RepaintPictureWindow(void);

void MainGraphics(void);
void InitGraphics(int argc, char **argv, char *script_cmds_file, char *script_cmd, bool stayInCommandLoop);
void ExitGraphics(void);

extern double g_CursorScaleFactor;
extern char g_CursorScaleFactorUnit[11];
extern double g_PlotGridX, g_PlotGridY, g_PlotGridXdefault, g_PlotGridYdefault, g_GridOffset;
extern uint32_t g_CursorCPos, g_CursorDPos, g_GraphStart, g_GraphStop;
extern int CommandFinished;
extern int offline;
extern bool g_GridLocked;

#define GRAPH_SAVE 1
#define GRAPH_RESTORE 0

#ifndef FILE_PATH_SIZE
#define FILE_PATH_SIZE 1000
#endif

#ifdef __cplusplus
}
#endif
#endif
