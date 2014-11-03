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
#include <stdbool.h>
#include <string.h>
#include "ui.h"
#include "graph.h"

int GraphBuffer[MAX_GRAPH_TRACE_LEN];
int GraphTraceLen;

/* write a bit to the graph */
void AppendGraph(int redraw, int clock, int bit)
{
  int i;
  int half = (int)(clock/2);
  int firstbit = bit ^ 1;
 
  for (i = 0; i < half; ++i)
    GraphBuffer[GraphTraceLen++] = firstbit;
  
  for (i = 0; i <= half; ++i)
    GraphBuffer[GraphTraceLen++] = bit;

  if (redraw)
    RepaintGraphWindow();
}

/* clear out our graph window */
int ClearGraph(int redraw)
{
  int gtl = GraphTraceLen;
  memset(GraphBuffer, 0x00, GraphTraceLen);

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
	
	int clockmod = clock%8;
	if ( clockmod == 0) 
		return clock;
	
	// When detected clock is 31 or 33 then return 32

	printf("Found clock at %d ", clock);
	switch( clockmod )
	{
		case 7: clock++; break;
		case 6: clock += 2 ; break;
		case 1: clock--; break;
		case 2: clock -= 2; break;
	}
	if ( clock < 32) 
		clock = 32;
		
	printf("- adjusted it to %d \n", clock);
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


/* A simple test to see if there is any data inside Graphbuffer. 
*/
bool HasGraphData(){

	if ( GraphTraceLen <= 0) {
		PrintAndLog("No data available, try reading something first");
		return false;
	}
	return true;	
}