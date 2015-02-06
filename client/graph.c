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
#include "lfdemod.h"

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

// clear out our graph window
int ClearGraph(int redraw)
{
  int gtl = GraphTraceLen;
  memset(GraphBuffer, 0x00, GraphTraceLen);

  GraphTraceLen = 0;

  if (redraw)
    RepaintGraphWindow();

  return gtl;
}

// DETECT CLOCK NOW IN LFDEMOD.C

void setGraphBuf(uint8_t *buff, size_t size)
{
	if ( buff == NULL ) return;
	
	uint16_t i = 0;  
	if ( size > MAX_GRAPH_TRACE_LEN )
		size = MAX_GRAPH_TRACE_LEN;
  ClearGraph(0);
  for (; i < size; ++i){
		GraphBuffer[i]=buff[i]-128;
  }
  GraphTraceLen=size;
  RepaintGraphWindow();
  return;
}
size_t getFromGraphBuf(uint8_t *buff)
{
	if ( buff == NULL ) return 0;
	
  uint32_t i;
  for (i=0;i<GraphTraceLen;++i){
    if (GraphBuffer[i]>127) GraphBuffer[i]=127; //trim
    if (GraphBuffer[i]<-127) GraphBuffer[i]=-127; //trim
    buff[i]=(uint8_t)(GraphBuffer[i]+128);
  }
  return i;
}


// Get or auto-detect clock rate
int GetClock(const char *str, int peak, int verbose)
{
	int clock;
	sscanf(str, "%i", &clock);
	if (!strcmp(str, ""))
		clock = 0;

	// Auto-detect clock
	if (!clock)
	{
		uint8_t grph[MAX_GRAPH_TRACE_LEN]={0};
		size_t size = getFromGraphBuf(grph);
		if ( size == 0 ) {
			PrintAndLog("Failed to copy from graphbuffer");
			return -1;
		}
		clock = DetectASKClock(grph,size,0);
		// Only print this message if we're not looping something
		if (!verbose){
			PrintAndLog("Auto-detected clock rate: %d", clock);
		}
	}
	return clock;
}

// A simple test to see if there is any data inside Graphbuffer. 
bool HasGraphData(){

	if ( GraphTraceLen <= 0) {
		PrintAndLog("No data available, try reading something first");
		return false;
	}
	return true;	
}

// Detect high and lows in Grapbuffer.
// Only loops the first 256 values. 
void DetectHighLowInGraph(int *high, int *low, bool addFuzz) {

	uint8_t loopMax = 255;
	if ( loopMax > GraphTraceLen)
		loopMax = GraphTraceLen;
  
	for (uint8_t i = 0; i < loopMax; ++i) {
		if (GraphBuffer[i] > *high)
			*high = GraphBuffer[i];
		else if (GraphBuffer[i] < *low)
			*low = GraphBuffer[i];
	}
	
	//12% fuzz in case highs and lows aren't clipped
	if (addFuzz) {
		*high = (int)(*high * .88);
		*low  = (int)(*low  * .88);
	}
}

int GetNRZpskClock(const char *str, int peak, int verbose)
{
	int clock;
	sscanf(str, "%i", &clock);
	if (!strcmp(str, ""))
		clock = 0;

	// Auto-detect clock
	if (!clock)
	{
		uint8_t grph[MAX_GRAPH_TRACE_LEN]={0};
		size_t size = getFromGraphBuf(grph);
		if ( size == 0 ) {
			PrintAndLog("Failed to copy from graphbuffer");
			return -1;
		}
		clock = DetectpskNRZClock(grph,size,0);
		// Only print this message if we're not looping something
		if (!verbose){
			PrintAndLog("Auto-detected clock rate: %d", clock);
		}
	}
	return clock;
}
