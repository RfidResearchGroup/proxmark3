//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Graph utilities
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include "ui.h"
#include "graph.h"

int GraphBuffer[MAX_GRAPH_TRACE_LEN];
int GraphTraceLen;

/* write a bit to the graph */
void AppendGraph(int redraw, int clock, int bit)
{
  int i;

  for (i = 0; i < (int)(clock / 2); ++i)
    GraphBuffer[GraphTraceLen++] = bit ^ 1;
  
  for (i = (int)(clock / 2); i < clock; ++i)
    GraphBuffer[GraphTraceLen++] = bit;

  if (redraw)
    RepaintGraphWindow();
}

/* clear out our graph window */
int ClearGraph(int redraw)
{
  int gtl = GraphTraceLen;
  GraphTraceLen = 0;

  if (redraw)
    RepaintGraphWindow();

  return gtl;
}

/*
 * Detect clock rate
 */
int DetectClock(int peak)
{
  int i;
  int clock = 0xFFFF;
  int lastpeak = 0;

  /* Detect peak if we don't have one */
  if (!peak)
    for (i = 0; i < GraphTraceLen; ++i)
      if (GraphBuffer[i] > peak)
        peak = GraphBuffer[i];

  for (i = 1; i < GraphTraceLen; ++i)
  {
    /* If this is the beginning of a peak */
    if (GraphBuffer[i - 1] != GraphBuffer[i] && GraphBuffer[i] == peak)
    {
      /* Find lowest difference between peaks */
      if (lastpeak && i - lastpeak < clock)
        clock = i - lastpeak;
      lastpeak = i;
    }
  }

  return clock;
}

/* Get or auto-detect clock rate */
int GetClock(const char *str, int peak, int verbose)
{
  int clock;

  sscanf(str, "%i", &clock);
  if (!strcmp(str, ""))
    clock = 0;

  /* Auto-detect clock */
  if (!clock)
  {
    clock = DetectClock(peak);
    /* Only print this message if we're not looping something */
    if (!verbose)
      PrintAndLog("Auto-detected clock rate: %d", clock);
  }

  return clock;
}
