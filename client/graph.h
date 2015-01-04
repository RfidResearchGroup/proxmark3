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

void AppendGraph(int redraw, int clock, int bit);
int ClearGraph(int redraw);
int GetFromGraphBuf(uint8_t *buff);
int GetClock(const char *str, int verbose);
void SetGraphBuf(uint8_t *buff,int size);
bool HasGraphData();
void DetectHighLowInGraph(int *high, int *low, bool addFuzz); 

#define MAX_GRAPH_TRACE_LEN (1024*128)
extern int GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern int GraphTraceLen;
#endif
