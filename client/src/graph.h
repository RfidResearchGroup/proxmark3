//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Graph utilities
//-----------------------------------------------------------------------------

#ifndef GRAPH_H__
#define GRAPH_H__

#include "common.h"

void AppendGraph(bool redraw, uint16_t clock, int bit);
size_t ClearGraph(bool redraw);
bool HasGraphData(void);
void setGraphBuf(uint8_t *buff, size_t size);
void save_restoreGB(uint8_t saveOpt);
size_t getFromGraphBuf(uint8_t *buff);
void convertGraphFromBitstream(void);
void convertGraphFromBitstreamEx(int hi, int low);
bool isGraphBitstream(void);

int GetAskClock(const char *str, bool printAns);
int GetPskClock(const char *str, bool printAns);
uint8_t GetPskCarrier(const char *str, bool printAns);
int GetNrzClock(const char *str, bool printAns);
int GetFskClock(const char *str, bool printAns);
bool fskClocks(uint8_t *fc1, uint8_t *fc2, uint8_t *rf1, int *firstClockEdge);

#define MAX_GRAPH_TRACE_LEN (40000 * 8)
#define GRAPH_SAVE 1
#define GRAPH_RESTORE 0

extern int GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern size_t GraphTraceLen;
extern int s_Buff[MAX_GRAPH_TRACE_LEN];

#endif
