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

typedef struct {
    const uint8_t type; //Used for sanity checks
    const uint32_t *buffer;
    const size_t   bufferSize;
    uint32_t offset;
    uint32_t clock;     //Not used by all buffers
} buffer_savestate_t;

typedef struct {
    uint32_t pos;
    char label[30];
} marker_t;

void AppendGraph(bool redraw, uint16_t clock, int bit);
size_t ClearGraph(bool redraw);
bool HasGraphData(void);
void setGraphBuffer(const uint8_t *src, size_t size);
size_t getFromGraphBuffer(uint8_t *dest);
size_t getFromGraphBufferEx(uint8_t *dest, size_t maxLen);
size_t getGraphBufferChunk(uint8_t *dest, size_t start, size_t end);
void convertGraphFromBitstream(void);
void convertGraphFromBitstreamEx(int hi, int low);
bool isGraphBitstream(void);

int GetAskClock(const char *str, bool verbose);
int GetPskClock(const char *str, bool verbose);
int GetPskCarrier(bool verbose);
int GetNrzClock(const char *str, bool verbose);
int GetFskClock(const char *str, bool verbose);
bool fskClocks(uint8_t *fc1, uint8_t *fc2, uint8_t *rf1, int *firstClockEdge);

buffer_savestate_t save_buffer32(uint32_t *src, size_t length);
buffer_savestate_t save_bufferS32(int32_t *src, size_t length);
buffer_savestate_t save_buffer8(uint8_t *src, size_t length);
size_t restore_buffer32(buffer_savestate_t saveState, uint32_t *dest);
size_t restore_bufferS32(buffer_savestate_t saveState, int32_t *dest);
size_t restore_buffer8(buffer_savestate_t saveState, uint8_t *dest);

#define MAX_GRAPH_TRACE_LEN (40000 * 32)
#define GRAPH_SAVE 1
#define GRAPH_RESTORE 0

extern int32_t g_GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern int32_t g_OperationBuffer[MAX_GRAPH_TRACE_LEN];
extern int32_t g_OverlayBuffer[MAX_GRAPH_TRACE_LEN];
extern bool    g_useOverlays;
extern size_t  g_GraphTraceLen;

extern marker_t g_MarkerA, g_MarkerB, g_MarkerC, g_MarkerD;
extern marker_t *g_TempMarkers;
extern uint8_t g_TempMarkerSize;

extern double g_GridOffset;

extern buffer_savestate_t g_saveState_gb;

#ifdef __cplusplus
}
#endif
#endif
