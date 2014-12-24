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
 //decommissioned - has difficulty detecting rf/32 and only works if data is manchester encoded
/*
int DetectClock2(int peak)
{
  int i;
  int clock = 0xFFFF;
  int lastpeak = 0;

  // Detect peak if we don't have one 
  if (!peak)
    for (i = 0; i < GraphTraceLen; ++i)
      if (GraphBuffer[i] > peak)
        peak = GraphBuffer[i];

 // peak=(int)(peak*.75);
  for (i = 1; i < GraphTraceLen; ++i)
  {
    // If this is the beginning of a peak 
    if (GraphBuffer[i - 1] != GraphBuffer[i] && GraphBuffer[i] >= peak)
    {
      // Find lowest difference between peaks 
      if (lastpeak && i - lastpeak < clock)
        clock = i - lastpeak;
      lastpeak = i;
    }
  }

  return clock;
}
*/

// by marshmellow
// not perfect especially with lower clocks or VERY good antennas (heavy wave clipping)
// maybe somehow adjust peak trimming value based on samples to fix?
int DetectClock(int peak)
{
  int i=0;
  int low=0;
  int clk[]={16,32,40,50,64,100,128,256};
  if (!peak){
    for (i=0;i<GraphTraceLen;++i){
      if(GraphBuffer[i]>peak){
        peak = GraphBuffer[i]; 
      }
      if(GraphBuffer[i]<low){
        low = GraphBuffer[i];
      }
    }
    peak=(int)(peak*.75);
    low= (int)(low*.75);
  }
  //int numbits;
  int ii;
  int loopCnt = 256;
  if (GraphTraceLen<loopCnt) loopCnt = GraphTraceLen;
  int clkCnt;
  int tol = 0;
  int bestErr=1000;
  int errCnt[]={0,0,0,0,0,0,0,0};
 // int good;
  for(clkCnt=0; clkCnt<6;++clkCnt){
    if (clk[clkCnt]==32){
      tol=1;
    }else{
      tol=0;
    }
    bestErr=1000;
    for (ii=0; ii<loopCnt; ++ii){
      if ((GraphBuffer[ii]>=peak) || (GraphBuffer[ii]<=low)){
        //numbits=0;
        //good=1;
        errCnt[clkCnt]=0;
        for (i=0; i<((int)(GraphTraceLen/clk[clkCnt])-1); ++i){
          if (GraphBuffer[ii+(i*clk[clkCnt])]>=peak || GraphBuffer[ii+(i*clk[clkCnt])]<=low){
            //numbits++;
          }else if(GraphBuffer[ii+(i*clk[clkCnt])-tol]>=peak || GraphBuffer[ii+(i*clk[clkCnt])-tol]<=low){
          }else if(GraphBuffer[ii+(i*clk[clkCnt])+tol]>=peak || GraphBuffer[ii+(i*clk[clkCnt])+tol]<=low){
          }else{  //error no peak detected
            //numbits=0;
            //good=0;
            errCnt[clkCnt]++;
            //break;
          }    
        }
        if(errCnt[clkCnt]==0) return clk[clkCnt];
        if(errCnt[clkCnt]<bestErr) bestErr=errCnt[clkCnt];
      }
    } 
    errCnt[clkCnt]=bestErr;
  }
  int iii=0;
  int best=0;
  for (iii=0; iii<6;++iii){
    if (errCnt[iii]<errCnt[best]){
      best = iii;
    }
  }
  PrintAndLog("clkCnt: %d, ii: %d, i: %d peak: %d, low: %d, errcnt: %d, errCnt64: %d",clkCnt,ii,i,peak,low,errCnt[best],errCnt[4]);
  return clk[best];
}


/* Get or auto-detect clock rate */
int GetClock(const char *str, int peak, int verbose)
{
  int clock;
//  int clock2;
  sscanf(str, "%i", &clock);
  if (!strcmp(str, ""))
    clock = 0;

  /* Auto-detect clock */
  if (!clock)
  {
    clock = DetectClock(peak);
    //clock2 = DetectClock2(peak);
    /* Only print this message if we're not looping something */
    if (!verbose){
      PrintAndLog("Auto-detected clock rate: %d", clock);
      //PrintAndLog("clock2: %d",clock2);
    }
  }

  return clock;
}
