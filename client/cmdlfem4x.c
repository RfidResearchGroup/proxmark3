//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "proxusb.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "cmdlfem4x.h"

static int CmdHelp(const char *Cmd);

/* Read the ID of an EM410x tag.
 * Format:
 *   1111 1111 1           <-- standard non-repeatable header
 *   XXXX [row parity bit] <-- 10 rows of 5 bits for our 40 bit tag ID
 *   ....
 *   CCCC                  <-- each bit here is parity for the 10 bits above in corresponding column
 *   0                     <-- stop bit, end of tag
 */
int CmdEM410xRead(const char *Cmd)
{
  int i, j, clock, header, rows, bit, hithigh, hitlow, first, bit2idx, high, low;
  int parity[4];
  char id[11];
  int retested = 0;
  uint8_t BitStream[MAX_GRAPH_TRACE_LEN];
  high = low = 0;

  /* Detect high and lows and clock */
  for (i = 0; i < GraphTraceLen; i++)
  {
    if (GraphBuffer[i] > high)
      high = GraphBuffer[i];
    else if (GraphBuffer[i] < low)
      low = GraphBuffer[i];
  }

  /* get clock */
  clock = GetClock(Cmd, high, 0);

  /* parity for our 4 columns */
  parity[0] = parity[1] = parity[2] = parity[3] = 0;
  header = rows = 0;

  /* manchester demodulate */
  bit = bit2idx = 0;
  for (i = 0; i < (int)(GraphTraceLen / clock); i++)
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

    BitStream[bit2idx++] = bit;
  }

retest:
  /* We go till 5 before the graph ends because we'll get that far below */
  for (i = 1; i < bit2idx - 5; i++)
  {
    /* Step 2: We have our header but need our tag ID */
    if (header == 9 && rows < 10)
    {
      /* Confirm parity is correct */
      if ((BitStream[i] ^ BitStream[i+1] ^ BitStream[i+2] ^ BitStream[i+3]) == BitStream[i+4])
      {
        /* Read another byte! */
        sprintf(id+rows, "%x", (8 * BitStream[i]) + (4 * BitStream[i+1]) + (2 * BitStream[i+2]) + (1 * BitStream[i+3]));
        rows++;

        /* Keep parity info */
        parity[0] ^= BitStream[i];
        parity[1] ^= BitStream[i+1];
        parity[2] ^= BitStream[i+2];
        parity[3] ^= BitStream[i+3];

        /* Move 4 bits ahead */
        i += 4;
      }

      /* Damn, something wrong! reset */
      else
      {
        PrintAndLog("Thought we had a valid tag but failed at word %d (i=%d)", rows + 1, i);

        /* Start back rows * 5 + 9 header bits, -1 to not start at same place */
        i -= 9 + (5 * rows) - 5;

        rows = header = 0;
      }
    }

    /* Step 3: Got our 40 bits! confirm column parity */
    else if (rows == 10)
    {
      /* We need to make sure our 4 bits of parity are correct and we have a stop bit */
      if (BitStream[i] == parity[0] && BitStream[i+1] == parity[1] &&
        BitStream[i+2] == parity[2] && BitStream[i+3] == parity[3] &&
        BitStream[i+4] == 0)
      {
        /* Sweet! */
        PrintAndLog("EM410x Tag ID: %s", id);

        /* Stop any loops */
        return 1;
      }

      /* Crap! Incorrect parity or no stop bit, start all over */
      else
      {
        rows = header = 0;

        /* Go back 59 bits (9 header bits + 10 rows at 4+1 parity) */
        i -= 59;
      }
    }

    /* Step 1: get our header */
    else if (header < 9)
    {
      /* Need 9 consecutive 1's */
      if (BitStream[i] == 1)
        header++;

      /* We don't have a header, not enough consecutive 1 bits */
      else
        header = 0;
    }
  }

  /* if we've already retested after flipping bits, return */
  if (retested++)
    return 0;

  /* if this didn't work, try flipping bits */
  for (i = 0; i < bit2idx; i++)
    BitStream[i] ^= 1;

  goto retest;
}

/* emulate an EM410X tag
 * Format:
 *   1111 1111 1           <-- standard non-repeatable header
 *   XXXX [row parity bit] <-- 10 rows of 5 bits for our 40 bit tag ID
 *   ....
 *   CCCC                  <-- each bit here is parity for the 10 bits above in corresponding column
 *   0                     <-- stop bit, end of tag
 */
int CmdEM410xSim(const char *Cmd)
{
  int i, n, j, h, binary[4], parity[4];

  /* clock is 64 in EM410x tags */
  int clock = 64;

  /* clear our graph */
  ClearGraph(0);

  /* write it out a few times */
  for (h = 0; h < 4; h++)
  {
    /* write 9 start bits */
    for (i = 0; i < 9; i++)
      AppendGraph(0, clock, 1);

    /* for each hex char */
    parity[0] = parity[1] = parity[2] = parity[3] = 0;
    for (i = 0; i < 10; i++)
    {
      /* read each hex char */
      sscanf(&Cmd[i], "%1x", &n);
      for (j = 3; j >= 0; j--, n/= 2)
        binary[j] = n % 2;

      /* append each bit */
      AppendGraph(0, clock, binary[0]);
      AppendGraph(0, clock, binary[1]);
      AppendGraph(0, clock, binary[2]);
      AppendGraph(0, clock, binary[3]);

      /* append parity bit */
      AppendGraph(0, clock, binary[0] ^ binary[1] ^ binary[2] ^ binary[3]);

      /* keep track of column parity */
      parity[0] ^= binary[0];
      parity[1] ^= binary[1];
      parity[2] ^= binary[2];
      parity[3] ^= binary[3];
    }

    /* parity columns */
    AppendGraph(0, clock, parity[0]);
    AppendGraph(0, clock, parity[1]);
    AppendGraph(0, clock, parity[2]);
    AppendGraph(0, clock, parity[3]);

    /* stop bit */
    AppendGraph(0, clock, 0);
  }

  /* modulate that biatch */
  CmdManchesterMod("");

  /* booyah! */
  RepaintGraphWindow();
  
  CmdLFSim("");
  return 0;
}

/* Function is equivalent of loread + losamples + em410xread
 * looped until an EM410x tag is detected */
int CmdEM410xWatch(const char *Cmd)
{
  do
  {
    CmdLFRead("");
    CmdSamples("2000");
  } while ( ! CmdEM410xRead(""));
  return 0;
}

/* Read the transmitted data of an EM4x50 tag
 * Format:
 *
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  CCCCCCCC                         <- column parity bits
 *  0                                <- stop bit
 *  LW                               <- Listen Window
 *
 * This pattern repeats for every block of data being transmitted.
 * Transmission starts with two Listen Windows (LW - a modulated
 * pattern of 320 cycles each (32/32/128/64/64)).
 *
 * Note that this data may or may not be the UID. It is whatever data
 * is stored in the blocks defined in the control word First and Last
 * Word Read values. UID is stored in block 32.
 */
int CmdEM4x50Read(const char *Cmd)
{
  int i, j, startblock, skip, block, start, end, low, high;
  bool complete= false;
  int tmpbuff[MAX_GRAPH_TRACE_LEN / 64];
  char tmp[6];

  high= low= 0;
  memset(tmpbuff, 0, MAX_GRAPH_TRACE_LEN / 64);

  /* first get high and low values */
  for (i = 0; i < GraphTraceLen; i++)
  {
    if (GraphBuffer[i] > high)
      high = GraphBuffer[i];
    else if (GraphBuffer[i] < low)
      low = GraphBuffer[i];
  }

  /* populate a buffer with pulse lengths */
  i= 0;
  j= 0;
  while (i < GraphTraceLen)
  {
    // measure from low to low
    while ((GraphBuffer[i] > low) && (i<GraphTraceLen))
      ++i;
    start= i;
    while ((GraphBuffer[i] < high) && (i<GraphTraceLen))
      ++i;
    while ((GraphBuffer[i] > low) && (i<GraphTraceLen))
      ++i;
    if (j>(MAX_GRAPH_TRACE_LEN/64)) {
      break;
    }
    tmpbuff[j++]= i - start;
  }

  /* look for data start - should be 2 pairs of LW (pulses of 192,128) */
  start= -1;
  skip= 0;
  for (i= 0; i < j - 4 ; ++i)
  {
    skip += tmpbuff[i];
    if (tmpbuff[i] >= 190 && tmpbuff[i] <= 194)
      if (tmpbuff[i+1] >= 126 && tmpbuff[i+1] <= 130)
        if (tmpbuff[i+2] >= 190 && tmpbuff[i+2] <= 194)
          if (tmpbuff[i+3] >= 126 && tmpbuff[i+3] <= 130)
          {
            start= i + 3;
            break;
          }
  }
  startblock= i + 3;

  /* skip over the remainder of the LW */
  skip += tmpbuff[i+1]+tmpbuff[i+2];
  while (skip < MAX_GRAPH_TRACE_LEN && GraphBuffer[skip] > low)
    ++skip;
  skip += 8;

  /* now do it again to find the end */
  end= start;
  for (i += 3; i < j - 4 ; ++i)
  {
    end += tmpbuff[i];
    if (tmpbuff[i] >= 190 && tmpbuff[i] <= 194)
      if (tmpbuff[i+1] >= 126 && tmpbuff[i+1] <= 130)
        if (tmpbuff[i+2] >= 190 && tmpbuff[i+2] <= 194)
          if (tmpbuff[i+3] >= 126 && tmpbuff[i+3] <= 130)
          {
            complete= true;
            break;
          }
  }

  if (start >= 0)
    PrintAndLog("Found data at sample: %i",skip);
  else
  {
    PrintAndLog("No data found!");
    PrintAndLog("Try again with more samples.");
    return 0;
  }

  if (!complete)
  {
    PrintAndLog("*** Warning!");
    PrintAndLog("Partial data - no end found!");
    PrintAndLog("Try again with more samples.");
  }

  /* get rid of leading crap */
  sprintf(tmp,"%i",skip);
  CmdLtrim(tmp);

  /* now work through remaining buffer printing out data blocks */
  block= 0;
  i= startblock;
  while (block < 6)
  {
    PrintAndLog("Block %i:", block);
    // mandemod routine needs to be split so we can call it for data
    // just print for now for debugging
    CmdManchesterDemod("i 64");
    skip= 0;
    /* look for LW before start of next block */
    for ( ; i < j - 4 ; ++i)
    {
      skip += tmpbuff[i];
      if (tmpbuff[i] >= 190 && tmpbuff[i] <= 194)
        if (tmpbuff[i+1] >= 126 && tmpbuff[i+1] <= 130)
          break;
    }
    while (GraphBuffer[skip] > low)
      ++skip;
    skip += 8;
    sprintf(tmp,"%i",skip);
    CmdLtrim(tmp);
    start += skip;
    block++;
  }
  return 0;
}

int CmdEM410xWrite(const char *Cmd)
{
  uint64_t id = 0;
  unsigned int card;

  sscanf(Cmd, "%" PRIx64 " %d", &id, &card);

  if (id >= 0x10000000000) {
    PrintAndLog("Error! Given EM410x ID is longer than 40 bits.\n");
    return 0;
  }

  if (card > 1) {
    PrintAndLog("Error! Bad card type selected.\n");
    return 0;
  }

  PrintAndLog("Writing %s tag with UID 0x%010" PRIx64, card ? "T55x7":"T5555", id);
  UsbCommand c = {CMD_EM410X_WRITE_TAG, {card, (uint32_t)(id >> 32), (uint32_t)id}};
  SendCommand(&c);

  return 0;
}

static command_t CommandTable[] =
{
  {"help",        CmdHelp,        1, "This help"},
  {"em410xread",  CmdEM410xRead,  1, "[clock rate] -- Extract ID from EM410x tag"},
  {"em410xsim",   CmdEM410xSim,   0, "<UID> -- Simulate EM410x tag"},
  {"em410xwatch", CmdEM410xWatch, 0, "Watches for EM410x tags"},
  {"em410xwrite", CmdEM410xWrite, 1, "<UID> <'0' T5555> <'1' T55x7> -- Write EM410x UID to T5555(Q5) or T55x7 tag"},
  {"em4x50read",  CmdEM4x50Read,  1, "Extract data from EM4x50 tag"},
  {NULL, NULL, 0, NULL}
};

int CmdLFEM4X(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
