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
void setGraphBuffer(const uint8_t *src, size_t size);
void save_restoreGB(uint8_t saveOpt);
size_t getFromGraphBuffer(uint8_t *dest);
size_t getFromGraphBufferEx(uint8_t *dest, size_t maxLen);
size_t get_buffer_chunk(uint8_t *dest, size_t start, size_t end, bool useGraphBuffer);
void convertGraphFromBitstream(void);
void convertGraphFromBitstreamEx(int hi, int low);
bool isGraphBitstream(void);
void modify_graph(uint32_t index, uint32_t data, const bool apply);
void modify_graphEX(const uint32_t *data, size_t start, size_t size, const bool apply);
void apply_operations_between(size_t start, size_t end);
void apply_all_operations(void);
void reset_operation_buffer(void);

int GetAskClock(const char *str, bool verbose);
int GetPskClock(const char *str, bool verbose);
int GetPskCarrier(bool verbose);
int GetNrzClock(const char *str, bool verbose);
int GetFskClock(const char *str, bool verbose);
bool fskClocks(uint8_t *fc1, uint8_t *fc2, uint8_t *rf1, int *firstClockEdge);

#define MAX_GRAPH_TRACE_LEN (40000 * 32)
#define GRAPH_SAVE 1
#define GRAPH_RESTORE 0

extern int32_t g_GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern int32_t g_OperationBuffer[MAX_GRAPH_TRACE_LEN];
extern int32_t g_OverlayBuffer[MAX_GRAPH_TRACE_LEN];
extern bool    g_useOverlays;
extern size_t g_GraphTraceLen;

#ifdef __cplusplus
}
#endif
#endif
