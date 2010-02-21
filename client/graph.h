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
int DetectClock(int peak);
int GetClock(const char *str, int peak, int verbose);

#define MAX_GRAPH_TRACE_LEN (1024*128)
extern int GraphBuffer[MAX_GRAPH_TRACE_LEN];
extern int GraphTraceLen;

#endif
