//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data and Graph commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "proxmark3.h"
#include "data.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "cmddata.h"

static int CmdHelp(const char *Cmd);

int CmdAmp(const char *Cmd)
{
  int i, rising, falling;
  int max = INT_MIN, min = INT_MAX;

  for (i = 10; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] > max)
      max = GraphBuffer[i];
    if (GraphBuffer[i] < min)
      min = GraphBuffer[i];
  }

  if (max != min) {
    rising = falling= 0;
    for (i = 0; i < GraphTraceLen; ++i) {
      if (GraphBuffer[i + 1] < GraphBuffer[i]) {
        if (rising) {
          GraphBuffer[i] = max;
          rising = 0;
        }
        falling = 1;
      }
      if (GraphBuffer[i + 1] > GraphBuffer[i]) {
        if (falling) {
          GraphBuffer[i] = min;
          falling = 0;
        }
        rising= 1;
      }
    }
  }
  RepaintGraphWindow();
  return 0;
}

/*
 * Generic command to demodulate ASK.
 *
 * Argument is convention: positive or negative (High mod means zero
 * or high mod means one)
 *
 * Updates the Graph trace with 0/1 values
 *
 * Arguments:
 * c : 0 or 1
 */
int Cmdaskdemod(const char *Cmd)
{
  int i;
  int c, high = 0, low = 0;

  // TODO: complain if we do not give 2 arguments here !
  // (AL - this doesn't make sense! we're only using one argument!!!)
  sscanf(Cmd, "%i", &c);

  /* Detect high and lows and clock */
  // (AL - clock???)
  for (i = 0; i < GraphTraceLen; ++i)
  {
    if (GraphBuffer[i] > high)
      high = GraphBuffer[i];
    else if (GraphBuffer[i] < low)
      low = GraphBuffer[i];
  }
  if (c != 0 && c != 1) {
    PrintAndLog("Invalid argument: %s", Cmd);
    return 0;
  }

  if (GraphBuffer[0] > 0) {
    GraphBuffer[0] = 1-c;
  } else {
    GraphBuffer[0] = c;
  }
  for (i = 1; i < GraphTraceLen; ++i) {
    /* Transitions are detected at each peak
     * Transitions are either:
     * - we're low: transition if we hit a high
     * - we're high: transition if we hit a low
     * (we need to do it this way because some tags keep high or
     * low for long periods, others just reach the peak and go
     * down)
     */
    if ((GraphBuffer[i] == high) && (GraphBuffer[i - 1] == c)) {
      GraphBuffer[i] = 1 - c;
    } else if ((GraphBuffer[i] == low) && (GraphBuffer[i - 1] == (1 - c))){
      GraphBuffer[i] = c;
    } else {
      /* No transition */
      GraphBuffer[i] = GraphBuffer[i - 1];
    }
  }
  RepaintGraphWindow();
  return 0;
}

int CmdAutoCorr(const char *Cmd)
{
  static int CorrelBuffer[MAX_GRAPH_TRACE_LEN];

  int window = atoi(Cmd);

  if (window == 0) {
    PrintAndLog("needs a window");
    return 0;
  }
  if (window >= GraphTraceLen) {
    PrintAndLog("window must be smaller than trace (%d samples)",
      GraphTraceLen);
    return 0;
  }

  PrintAndLog("performing %d correlations", GraphTraceLen - window);

  for (int i = 0; i < GraphTraceLen - window; ++i) {
    int sum = 0;
    for (int j = 0; j < window; ++j) {
      sum += (GraphBuffer[j]*GraphBuffer[i + j]) / 256;
    }
    CorrelBuffer[i] = sum;
  }
  GraphTraceLen = GraphTraceLen - window;
  memcpy(GraphBuffer, CorrelBuffer, GraphTraceLen * sizeof (int));

  RepaintGraphWindow();
  return 0;
}

int CmdBitsamples(const char *Cmd)
{
  int cnt = 0;
  uint8_t got[12288];
  
  GetFromBigBuf(got,sizeof(got),0);
  WaitForResponse(CMD_ACK,NULL);

    for (int j = 0; j < sizeof(got); j++) {
      for (int k = 0; k < 8; k++) {
        if(got[j] & (1 << (7 - k))) {
          GraphBuffer[cnt++] = 1;
        } else {
          GraphBuffer[cnt++] = 0;
        }
      }
  }
  GraphTraceLen = cnt;
  RepaintGraphWindow();
  return 0;
}

/*
 * Convert to a bitstream
 */
int CmdBitstream(const char *Cmd)
{
  int i, j;
  int bit;
  int gtl;
  int clock;
  int low = 0;
  int high = 0;
  int hithigh, hitlow, first;

  /* Detect high and lows and clock */
  for (i = 0; i < GraphTraceLen; ++i)
  {
    if (GraphBuffer[i] > high)
      high = GraphBuffer[i];
    else if (GraphBuffer[i] < low)
      low = GraphBuffer[i];
  }

  /* Get our clock */
  clock = GetClock(Cmd, high, 1);
  gtl = ClearGraph(0);

  bit = 0;
  for (i = 0; i < (int)(gtl / clock); ++i)
  {
    hithigh = 0;
    hitlow = 0;
    first = 1;
    /* Find out if we hit both high and low peaks */
    for (j = 0; j < clock; ++j)
    {
      if (GraphBuffer[(i * clock) + j] == high)
        hithigh = 1;
      else if (GraphBuffer[(i * clock) + j] == low)
        hitlow = 1;
      /* it doesn't count if it's the first part of our read
         because it's really just trailing from the last sequence */
      if (first && (hithigh || hitlow))
        hithigh = hitlow = 0;
      else
        first = 0;

      if (hithigh && hitlow)
        break;
    }

    /* If we didn't hit both high and low peaks, we had a bit transition */
    if (!hithigh || !hitlow)
      bit ^= 1;

    AppendGraph(0, clock, bit);
//    for (j = 0; j < (int)(clock/2); j++)
//      GraphBuffer[(i * clock) + j] = bit ^ 1;
//    for (j = (int)(clock/2); j < clock; j++)
//      GraphBuffer[(i * clock) + j] = bit;
  }

  RepaintGraphWindow();
  return 0;
}

int CmdBuffClear(const char *Cmd)
{
  UsbCommand c = {CMD_BUFF_CLEAR};
  SendCommand(&c);
  ClearGraph(true);
  return 0;
}

int CmdDec(const char *Cmd)
{
  for (int i = 0; i < (GraphTraceLen / 2); ++i)
    GraphBuffer[i] = GraphBuffer[i * 2];
  GraphTraceLen /= 2;
  PrintAndLog("decimated by 2");
  RepaintGraphWindow();
  return 0;
}

/* Print our clock rate */
int CmdDetectClockRate(const char *Cmd)
{
  int clock = DetectClock(0);
  PrintAndLog("Auto-detected clock rate: %d", clock);
  return 0;
}

int CmdFSKdemod(const char *Cmd)
{
  static const int LowTone[]  = {
    1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
    1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
    1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
    1,  1,  1,  1,  1, -1, -1, -1, -1, -1,
    1,  1,  1,  1,  1, -1, -1, -1, -1, -1
  };
  static const int HighTone[] = {
    1,  1,  1,  1,  1,     -1, -1, -1, -1,
    1,  1,  1,  1,         -1, -1, -1, -1,
    1,  1,  1,  1,         -1, -1, -1, -1,
    1,  1,  1,  1,         -1, -1, -1, -1,
    1,  1,  1,  1,         -1, -1, -1, -1,
    1,  1,  1,  1,     -1, -1, -1, -1, -1,
  };

  int lowLen = sizeof (LowTone) / sizeof (int);
  int highLen = sizeof (HighTone) / sizeof (int);
  int convLen = (highLen > lowLen) ? highLen : lowLen;
  uint32_t hi = 0, lo = 0;

  int i, j;
  int minMark = 0, maxMark = 0;

  for (i = 0; i < GraphTraceLen - convLen; ++i) {
    int lowSum = 0, highSum = 0;

    for (j = 0; j < lowLen; ++j) {
      lowSum += LowTone[j]*GraphBuffer[i+j];
    }
    for (j = 0; j < highLen; ++j) {
      highSum += HighTone[j] * GraphBuffer[i + j];
    }
    lowSum = abs(100 * lowSum / lowLen);
    highSum = abs(100 * highSum / highLen);
    GraphBuffer[i] = (highSum << 16) | lowSum;
  }

  for(i = 0; i < GraphTraceLen - convLen - 16; ++i) {
    int lowTot = 0, highTot = 0;
    // 10 and 8 are f_s divided by f_l and f_h, rounded
    for (j = 0; j < 10; ++j) {
      lowTot += (GraphBuffer[i+j] & 0xffff);
    }
    for (j = 0; j < 8; j++) {
      highTot += (GraphBuffer[i + j] >> 16);
    }
    GraphBuffer[i] = lowTot - highTot;
    if (GraphBuffer[i] > maxMark) maxMark = GraphBuffer[i];
    if (GraphBuffer[i] < minMark) minMark = GraphBuffer[i];
  }

  GraphTraceLen -= (convLen + 16);
  RepaintGraphWindow();

  // Find bit-sync (3 lo followed by 3 high)
  int max = 0, maxPos = 0;
  for (i = 0; i < 6000; ++i) {
    int dec = 0;
    for (j = 0; j < 3 * lowLen; ++j) {
      dec -= GraphBuffer[i + j];
    }
    for (; j < 3 * (lowLen + highLen ); ++j) {
      dec += GraphBuffer[i + j];
    }
    if (dec > max) {
      max = dec;
      maxPos = i;
    }
  }

  // place start of bit sync marker in graph
  GraphBuffer[maxPos] = maxMark;
  GraphBuffer[maxPos + 1] = minMark;

  maxPos += j;

  // place end of bit sync marker in graph
  GraphBuffer[maxPos] = maxMark;
  GraphBuffer[maxPos+1] = minMark;

  PrintAndLog("actual data bits start at sample %d", maxPos);
  PrintAndLog("length %d/%d", highLen, lowLen);

  uint8_t bits[46];
  bits[sizeof(bits)-1] = '\0';

  // find bit pairs and manchester decode them
  for (i = 0; i < arraylen(bits) - 1; ++i) {
    int dec = 0;
    for (j = 0; j < lowLen; ++j) {
      dec -= GraphBuffer[maxPos + j];
    }
    for (; j < lowLen + highLen; ++j) {
      dec += GraphBuffer[maxPos + j];
    }
    maxPos += j;
    // place inter bit marker in graph
    GraphBuffer[maxPos] = maxMark;
    GraphBuffer[maxPos + 1] = minMark;

    // hi and lo form a 64 bit pair
    hi = (hi << 1) | (lo >> 31);
    lo = (lo << 1);
    // store decoded bit as binary (in hi/lo) and text (in bits[])
    if(dec < 0) {
      bits[i] = '1';
      lo |= 1;
    } else {
      bits[i] = '0';
    }
  }
  PrintAndLog("bits: '%s'", bits);
  PrintAndLog("hex: %08x %08x", hi, lo);
  return 0;
}

int CmdGrid(const char *Cmd)
{
  sscanf(Cmd, "%i %i", &PlotGridX, &PlotGridY);
  PlotGridXdefault= PlotGridX;
  PlotGridYdefault= PlotGridY;
  RepaintGraphWindow();
  return 0;
}

int CmdHexsamples(const char *Cmd)
{
  int i, j;
  int requested = 0;
  int offset = 0;
  char string_buf[25];
  char* string_ptr = string_buf;
  uint8_t got[40000];
 
  sscanf(Cmd, "%i %i", &requested, &offset);

  /* if no args send something */
  if (requested == 0) {
    requested = 8;
  }
  if (offset + requested > sizeof(got)) {
    PrintAndLog("Tried to read past end of buffer, <bytes> + <offset> > 40000");
    return 0;
  } 

  GetFromBigBuf(got,requested,offset);
  WaitForResponse(CMD_ACK,NULL);

  i = 0;
  for (j = 0; j < requested; j++) {
    i++;
    string_ptr += sprintf(string_ptr, "%02x ", got[j]);
    if (i == 8) {
      *(string_ptr - 1) = '\0';    // remove the trailing space
      PrintAndLog("%s", string_buf);
      string_buf[0] = '\0';
      string_ptr = string_buf;
      i = 0;
    }
    if (j == requested - 1 && string_buf[0] != '\0') { // print any remaining bytes
      *(string_ptr - 1) = '\0';
      PrintAndLog("%s", string_buf);
      string_buf[0] = '\0';
    }  
  }
  return 0;
}

int CmdHide(const char *Cmd)
{
  HideGraphWindow();
  return 0;
}

int CmdHpf(const char *Cmd)
{
  int i;
  int accum = 0;

  for (i = 10; i < GraphTraceLen; ++i)
    accum += GraphBuffer[i];
  accum /= (GraphTraceLen - 10);
  for (i = 0; i < GraphTraceLen; ++i)
    GraphBuffer[i] -= accum;

  RepaintGraphWindow();
  return 0;
}

int CmdSamples(const char *Cmd)
{
  int cnt = 0;
  int n;
  uint8_t got[40000];

  n = strtol(Cmd, NULL, 0);
  if (n == 0) n = 512;
  if (n > sizeof(got)) n = sizeof(got);
  
  PrintAndLog("Reading %d samples\n", n);
  GetFromBigBuf(got,n,0);
  WaitForResponse(CMD_ACK,NULL);
  for (int j = 0; j < n; j++) {
    GraphBuffer[cnt++] = ((int)got[j]) - 128;
  }
  
  PrintAndLog("Done!\n");
  GraphTraceLen = n;
  RepaintGraphWindow();
  return 0;
}

int CmdLoad(const char *Cmd)
{
  FILE *f = fopen(Cmd, "r");
  if (!f) {
    PrintAndLog("couldn't open '%s'", Cmd);
    return 0;
  }

  GraphTraceLen = 0;
  char line[80];
  while (fgets(line, sizeof (line), f)) {
    GraphBuffer[GraphTraceLen] = atoi(line);
    GraphTraceLen++;
  }
  fclose(f);
  PrintAndLog("loaded %d samples", GraphTraceLen);
  RepaintGraphWindow();
  return 0;
}

int CmdLtrim(const char *Cmd)
{
  int ds = atoi(Cmd);

  for (int i = ds; i < GraphTraceLen; ++i)
    GraphBuffer[i-ds] = GraphBuffer[i];
  GraphTraceLen -= ds;

  RepaintGraphWindow();
  return 0;
}

/*
 * Manchester demodulate a bitstream. The bitstream needs to be already in
 * the GraphBuffer as 0 and 1 values
 *
 * Give the clock rate as argument in order to help the sync - the algorithm
 * resyncs at each pulse anyway.
 *
 * Not optimized by any means, this is the 1st time I'm writing this type of
 * routine, feel free to improve...
 *
 * 1st argument: clock rate (as number of samples per clock rate)
 *               Typical values can be 64, 32, 128...
 */
int CmdManchesterDemod(const char *Cmd)
{
  int i, j, invert= 0;
  int bit;
  int clock;
  int lastval = 0;
  int low = 0;
  int high = 0;
  int hithigh, hitlow, first;
  int lc = 0;
  int bitidx = 0;
  int bit2idx = 0;
  int warnings = 0;

  /* check if we're inverting output */
  if (*Cmd == 'i')
  {
    PrintAndLog("Inverting output");
    invert = 1;
    ++Cmd;
    do
      ++Cmd;
    while(*Cmd == ' '); // in case a 2nd argument was given
  }

  /* Holds the decoded bitstream: each clock period contains 2 bits       */
  /* later simplified to 1 bit after manchester decoding.                 */
  /* Add 10 bits to allow for noisy / uncertain traces without aborting   */
  /* int BitStream[GraphTraceLen*2/clock+10]; */

  /* But it does not work if compiling on WIndows: therefore we just allocate a */
  /* large array */
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN];

  /* Detect high and lows */
  for (i = 0; i < GraphTraceLen; i++)
  {
    if (GraphBuffer[i] > high)
      high = GraphBuffer[i];
    else if (GraphBuffer[i] < low)
      low = GraphBuffer[i];
  }

  /* Get our clock */
  clock = GetClock(Cmd, high, 1);

  int tolerance = clock/4;

  /* Detect first transition */
  /* Lo-Hi (arbitrary)       */
  /* skip to the first high */
  for (i= 0; i < GraphTraceLen; i++)
    if (GraphBuffer[i] == high)
      break;
  /* now look for the first low */
  for (; i < GraphTraceLen; i++)
  {
    if (GraphBuffer[i] == low)
    {
      lastval = i;
      break;
    }
  }

  /* If we're not working with 1/0s, demod based off clock */
  if (high != 1)
  {
    bit = 0; /* We assume the 1st bit is zero, it may not be
              * the case: this routine (I think) has an init problem.
              * Ed.
              */
    for (; i < (int)(GraphTraceLen / clock); i++)
    {
      hithigh = 0;
      hitlow = 0;
      first = 1;

      /* Find out if we hit both high and low peaks */
      for (j = 0; j < clock; j++)
      {
        if (GraphBuffer[(i * clock) + j] == high)
          hithigh = 1;
        else if (GraphBuffer[(i * clock) + j] == low)
          hitlow = 1;

        /* it doesn't count if it's the first part of our read
           because it's really just trailing from the last sequence */
        if (first && (hithigh || hitlow))
          hithigh = hitlow = 0;
        else
          first = 0;

        if (hithigh && hitlow)
          break;
      }

      /* If we didn't hit both high and low peaks, we had a bit transition */
      if (!hithigh || !hitlow)
        bit ^= 1;

      BitStream[bit2idx++] = bit ^ invert;
    }
  }

  /* standard 1/0 bitstream */
  else
  {

    /* Then detect duration between 2 successive transitions */
    for (bitidx = 1; i < GraphTraceLen; i++)
    {
      if (GraphBuffer[i-1] != GraphBuffer[i])
      {
      lc = i-lastval;
      lastval = i;

      // Error check: if bitidx becomes too large, we do not
      // have a Manchester encoded bitstream or the clock is really
      // wrong!
      if (bitidx > (GraphTraceLen*2/clock+8) ) {
        PrintAndLog("Error: the clock you gave is probably wrong, aborting.");
        return 0;
      }
      // Then switch depending on lc length:
      // Tolerance is 1/4 of clock rate (arbitrary)
      if (abs(lc-clock/2) < tolerance) {
        // Short pulse : either "1" or "0"
        BitStream[bitidx++]=GraphBuffer[i-1];
      } else if (abs(lc-clock) < tolerance) {
        // Long pulse: either "11" or "00"
        BitStream[bitidx++]=GraphBuffer[i-1];
        BitStream[bitidx++]=GraphBuffer[i-1];
      } else {
        // Error
          warnings++;
        PrintAndLog("Warning: Manchester decode error for pulse width detection.");
        PrintAndLog("(too many of those messages mean either the stream is not Manchester encoded, or clock is wrong)");

          if (warnings > 10)
          {
            PrintAndLog("Error: too many detection errors, aborting.");
            return 0;
          }
        }
      }
    }

    // At this stage, we now have a bitstream of "01" ("1") or "10" ("0"), parse it into final decoded bitstream
    // Actually, we overwrite BitStream with the new decoded bitstream, we just need to be careful
    // to stop output at the final bitidx2 value, not bitidx
    for (i = 0; i < bitidx; i += 2) {
      if ((BitStream[i] == 0) && (BitStream[i+1] == 1)) {
        BitStream[bit2idx++] = 1 ^ invert;
    } else if ((BitStream[i] == 1) && (BitStream[i+1] == 0)) {
      BitStream[bit2idx++] = 0 ^ invert;
    } else {
      // We cannot end up in this state, this means we are unsynchronized,
      // move up 1 bit:
      i++;
        warnings++;
      PrintAndLog("Unsynchronized, resync...");
      PrintAndLog("(too many of those messages mean the stream is not Manchester encoded)");

        if (warnings > 10)
        {
          PrintAndLog("Error: too many decode errors, aborting.");
          return 0;
        }
      }
    }
  }

  PrintAndLog("Manchester decoded bitstream");
  // Now output the bitstream to the scrollback by line of 16 bits
  for (i = 0; i < (bit2idx-16); i+=16) {
    PrintAndLog("%i %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i",
      BitStream[i],
      BitStream[i+1],
      BitStream[i+2],
      BitStream[i+3],
      BitStream[i+4],
      BitStream[i+5],
      BitStream[i+6],
      BitStream[i+7],
      BitStream[i+8],
      BitStream[i+9],
      BitStream[i+10],
      BitStream[i+11],
      BitStream[i+12],
      BitStream[i+13],
      BitStream[i+14],
      BitStream[i+15]);
  }
  return 0;
}

/* Modulate our data into manchester */
int CmdManchesterMod(const char *Cmd)
{
  int i, j;
  int clock;
  int bit, lastbit, wave;

  /* Get our clock */
  clock = GetClock(Cmd, 0, 1);

  wave = 0;
  lastbit = 1;
  for (i = 0; i < (int)(GraphTraceLen / clock); i++)
  {
    bit = GraphBuffer[i * clock] ^ 1;

    for (j = 0; j < (int)(clock/2); j++)
      GraphBuffer[(i * clock) + j] = bit ^ lastbit ^ wave;
    for (j = (int)(clock/2); j < clock; j++)
      GraphBuffer[(i * clock) + j] = bit ^ lastbit ^ wave ^ 1;

    /* Keep track of how we start our wave and if we changed or not this time */
    wave ^= bit ^ lastbit;
    lastbit = bit;
  }

  RepaintGraphWindow();
  return 0;
}

int CmdNorm(const char *Cmd)
{
  int i;
  int max = INT_MIN, min = INT_MAX;

  for (i = 10; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] > max)
      max = GraphBuffer[i];
    if (GraphBuffer[i] < min)
      min = GraphBuffer[i];
  }

  if (max != min) {
    for (i = 0; i < GraphTraceLen; ++i) {
      GraphBuffer[i] = (GraphBuffer[i] - ((max + min) / 2)) * 1000 /
        (max - min);
    }
  }
  RepaintGraphWindow();
  return 0;
}

int CmdPlot(const char *Cmd)
{
  ShowGraphWindow();
  return 0;
}

int CmdSave(const char *Cmd)
{
  FILE *f = fopen(Cmd, "w");
  if(!f) {
    PrintAndLog("couldn't open '%s'", Cmd);
    return 0;
  }
  int i;
  for (i = 0; i < GraphTraceLen; i++) {
    fprintf(f, "%d\n", GraphBuffer[i]);
  }
  fclose(f);
  PrintAndLog("saved to '%s'", Cmd);
  return 0;
}

int CmdScale(const char *Cmd)
{
  CursorScaleFactor = atoi(Cmd);
  if (CursorScaleFactor == 0) {
    PrintAndLog("bad, can't have zero scale");
    CursorScaleFactor = 1;
  }
  RepaintGraphWindow();
  return 0;
}

int CmdThreshold(const char *Cmd)
{
  int threshold = atoi(Cmd);

  for (int i = 0; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] >= threshold)
      GraphBuffer[i] = 1;
    else
      GraphBuffer[i] = -1;
  }
  RepaintGraphWindow();
  return 0;
}

int CmdZerocrossings(const char *Cmd)
{
  // Zero-crossings aren't meaningful unless the signal is zero-mean.
  CmdHpf("");

  int sign = 1;
  int zc = 0;
  int lastZc = 0;

  for (int i = 0; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] * sign >= 0) {
      // No change in sign, reproduce the previous sample count.
      zc++;
      GraphBuffer[i] = lastZc;
    } else {
      // Change in sign, reset the sample count.
      sign = -sign;
      GraphBuffer[i] = lastZc;
      if (sign > 0) {
        lastZc = zc;
        zc = 0;
      }
    }
  }

  RepaintGraphWindow();
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",          CmdHelp,            1, "This help"},
  {"amp",           CmdAmp,             1, "Amplify peaks"},
  {"askdemod",      Cmdaskdemod,        1, "<0 or 1> -- Attempt to demodulate simple ASK tags"},
  {"autocorr",      CmdAutoCorr,        1, "<window length> -- Autocorrelation over window"},
  {"bitsamples",    CmdBitsamples,      0, "Get raw samples as bitstring"},
  {"bitstream",     CmdBitstream,       1, "[clock rate] -- Convert waveform into a bitstream"},
  {"buffclear",     CmdBuffClear,       1, "Clear sample buffer and graph window"},
  {"dec",           CmdDec,             1, "Decimate samples"},
  {"detectclock",   CmdDetectClockRate, 1, "Detect clock rate"},
  {"fskdemod",      CmdFSKdemod,        1, "Demodulate graph window as a HID FSK"},
  {"grid",          CmdGrid,            1, "<x> <y> -- overlay grid on graph window, use zero value to turn off either"},
  {"hexsamples",    CmdHexsamples,      0, "<bytes> [<offset>] -- Dump big buffer as hex bytes"},  
  {"hide",          CmdHide,            1, "Hide graph window"},
  {"hpf",           CmdHpf,             1, "Remove DC offset from trace"},
  {"load",          CmdLoad,            1, "<filename> -- Load trace (to graph window"},
  {"ltrim",         CmdLtrim,           1, "<samples> -- Trim samples from left of trace"},
  {"mandemod",      CmdManchesterDemod, 1, "[i] [clock rate] -- Manchester demodulate binary stream (option 'i' to invert output)"},
  {"manmod",        CmdManchesterMod,   1, "[clock rate] -- Manchester modulate a binary stream"},
  {"norm",          CmdNorm,            1, "Normalize max/min to +/-500"},
  {"plot",          CmdPlot,            1, "Show graph window (hit 'h' in window for keystroke help)"},
  {"samples",       CmdSamples,         0, "[512 - 40000] -- Get raw samples for graph window"},
  {"save",          CmdSave,            1, "<filename> -- Save trace (from graph window)"},
  {"scale",         CmdScale,           1, "<int> -- Set cursor display scale"},
  {"threshold",     CmdThreshold,       1, "<threshold> -- Maximize/minimize every value in the graph window depending on threshold"},
  {"zerocrossings", CmdZerocrossings,   1, "Count time between zero-crossings"},
  {NULL, NULL, 0, NULL}
};

int CmdData(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
