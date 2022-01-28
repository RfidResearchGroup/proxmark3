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
// Graph utilities
//-----------------------------------------------------------------------------

#ifndef GRAPH_H__
#define GRAPH_H__

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

void AppendGraph(bool redraw, uint16_t clock, int bit);
size_t ClearGraph(bool redraw);
bool HasGraphData(void);
void setGraphBuf(const uint8_t *src, size_t size);
void save_restoreGB(uint8_t saveOpt);
size_t getFromGraphBuf(uint8_t *dest);
void convertGraphFromBitstream(void);
void convertGraphFromBitstreamEx(int hi, int low);
bool isGraphBitstream(void);

int GetAskClock(const char *str, bool verbose);
int GetPskClock(const char *str, bool verbose);
int GetPskCarrier(bool verbose);
int GetNrzClock(const char *str, bool verbose);
int GetFskClock(const char *str, bool verbose);
bool fskClocks(uint8_t *fc1, uint8_t *fc2, uint8_t *rf1, int *firstClockEdge);

#define MAX_GRAPH_TRACE_LEN (40000 * 8)
#define GRAPH_SAVE 1
#define GRAPH_RESTORE 0

extern int g_GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern size_t g_GraphTraceLen;

#ifdef __cplusplus
}
#endif
#endif
