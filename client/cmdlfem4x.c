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
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "cmdlfem4x.h"
char *global_em410xId;

static int CmdHelp(const char *Cmd);

int CmdEMdemodASK(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	int findone = (cmdp == '1') ? 1 : 0;	
  UsbCommand c={CMD_EM410X_DEMOD};
  c.arg[0]=findone;
  SendCommand(&c);
  return 0;
}

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
  char id[11] = {0x00};
  char id2[11] = {0x00};
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
  clock = GetAskClock(Cmd, false, false);

  /* parity for our 4 columns */
  parity[0] = parity[1] = parity[2] = parity[3] = 0;
  header = rows = 0;

  // manchester demodulate
  bit = bit2idx = 0;
  for (i = 0; i < (int)(GraphTraceLen / clock); i++)
  {
    hithigh = 0;
    hitlow = 0;
    first = 1;

    /* Find out if we hit both high and low peaks */
    for (j = 0; j < clock; j++)
    {
      if (GraphBuffer[(i * clock) + j] >= high)
        hithigh = 1;
      else if (GraphBuffer[(i * clock) + j] <= low)
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
        sprintf(id2+rows, "%x", (8 * BitStream[i+3]) + (4 * BitStream[i+2]) + (2 * BitStream[i+1]) + (1 * BitStream[i]));
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
        PrintAndLog("Unique Tag ID: %s", id2);

		global_em410xId = id;
		
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
	if (retested++){
		PrintAndLog("Failed to decode");
    return 0;
	}

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
	int i, n, j, binary[4], parity[4];

	char cmdp = param_getchar(Cmd, 0);
	uint8_t uid[5] = {0x00};

	if (cmdp == 'h' || cmdp == 'H') {
		PrintAndLog("Usage:  lf em4x 410xsim <UID>");
		PrintAndLog("");
		PrintAndLog("     sample: lf em4x 410xsim 0F0368568B");
		return 0;
	}

	if (param_gethex(Cmd, 0, uid, 10)) {
		PrintAndLog("UID must include 10 HEX symbols");
		return 0;
	}
	
	PrintAndLog("Starting simulating UID %02X%02X%02X%02X%02X", uid[0],uid[1],uid[2],uid[3],uid[4]);
	PrintAndLog("Press pm3-button to about simulation");

  /* clock is 64 in EM410x tags */
  int clock = 64;

  /* clear our graph */
  ClearGraph(0);

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
  AppendGraph(1, clock, 0);
 
  CmdLFSim("0"); //240 start_gap.
  return 0;
}

/* Function is equivalent of lf read + data samples + em410xread
 * looped until an EM410x tag is detected 
 * 
 * Why is CmdSamples("16000")?
 *  TBD: Auto-grow sample size based on detected sample rate.  IE: If the
 *       rate gets lower, then grow the number of samples
 *  Changed by martin, 4000 x 4 = 16000, 
 *  see http://www.proxmark.org/forum/viewtopic.php?pid=7235#p7235

*/
int CmdEM410xWatch(const char *Cmd)
{
	char cmdp = param_getchar(Cmd, 0);
	int read_h = (cmdp == 'h');
	do {
		if (ukbhit()) {
			printf("\naborted via keyboard!\n");
			break;
		}
		
		CmdLFRead(read_h ? "h" : "");
		CmdSamples("6000");		
	} while (
		!CmdEM410xRead("") 
	);
	return 0;
}

int CmdEM410xWatchnSpoof(const char *Cmd)
{
	CmdEM410xWatch(Cmd);
    PrintAndLog("# Replaying : %s",global_em410xId);
    CmdEM410xSim(global_em410xId);
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
    if (j>=(MAX_GRAPH_TRACE_LEN/64)) {
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
  uint64_t id = 0xFFFFFFFFFFFFFFFF; // invalid id value
  int card = 0xFF; // invalid card value
	unsigned int clock = 0; // invalid clock value

	sscanf(Cmd, "%" PRIx64 " %d %d", &id, &card, &clock);

	// Check ID
	if (id == 0xFFFFFFFFFFFFFFFF) {
		PrintAndLog("Error! ID is required.\n");
		return 0;
	}
	if (id >= 0x10000000000) {
		PrintAndLog("Error! Given EM410x ID is longer than 40 bits.\n");
		return 0;
	}

	// Check Card
	if (card == 0xFF) {
		PrintAndLog("Error! Card type required.\n");
		return 0;
	}
	if (card < 0) {
		PrintAndLog("Error! Bad card type selected.\n");
		return 0;
	}

	// Check Clock
	if (card == 1)
	{
		// Default: 64
		if (clock == 0)
			clock = 64;

		// Allowed clock rates: 16, 32 and 64
		if ((clock != 16) && (clock != 32) && (clock != 64)) {
			PrintAndLog("Error! Clock rate %d not valid. Supported clock rates are 16, 32 and 64.\n", clock);
			return 0;
		}
	}
	else if (clock != 0)
	{
		PrintAndLog("Error! Clock rate is only supported on T55x7 tags.\n");
		return 0;
	}

	if (card == 1) {
		PrintAndLog("Writing %s tag with UID 0x%010" PRIx64 " (clock rate: %d)", "T55x7", id, clock);
		// NOTE: We really should pass the clock in as a separate argument, but to
		//   provide for backwards-compatibility for older firmware, and to avoid
		//   having to add another argument to CMD_EM410X_WRITE_TAG, we just store
		//   the clock rate in bits 8-15 of the card value
		card = (card & 0xFF) | (((uint64_t)clock << 8) & 0xFF00);
	}
	else if (card == 0)
		PrintAndLog("Writing %s tag with UID 0x%010" PRIx64, "T5555", id, clock);
	else {
		PrintAndLog("Error! Bad card type selected.\n");
		return 0;
	}

  UsbCommand c = {CMD_EM410X_WRITE_TAG, {card, (uint32_t)(id >> 32), (uint32_t)id}};
  SendCommand(&c);

  return 0;
}

int CmdReadWord(const char *Cmd)
{
	int Word = -1; //default to invalid word
  UsbCommand c;
  
  sscanf(Cmd, "%d", &Word);
  
	if ( (Word > 15) | (Word < 0) ) {
    PrintAndLog("Word must be between 0 and 15");
    return 1;
  }
  
  PrintAndLog("Reading word %d", Word);
  
  c.cmd = CMD_EM4X_READ_WORD;
  c.d.asBytes[0] = 0x0; //Normal mode
  c.arg[0] = 0;
  c.arg[1] = Word;
  c.arg[2] = 0;
  SendCommand(&c);
  return 0;
}

int CmdReadWordPWD(const char *Cmd)
{
	int Word = -1; //default to invalid word
  int Password = 0xFFFFFFFF; //default to blank password
  UsbCommand c;
  
  sscanf(Cmd, "%d %x", &Word, &Password);
  
	if ( (Word > 15) | (Word < 0) ) {
    PrintAndLog("Word must be between 0 and 15");
    return 1;
  }
  
  PrintAndLog("Reading word %d with password %08X", Word, Password);
  
  c.cmd = CMD_EM4X_READ_WORD;
  c.d.asBytes[0] = 0x1; //Password mode
  c.arg[0] = 0;
  c.arg[1] = Word;
  c.arg[2] = Password;
  SendCommand(&c);
  return 0;
}

int CmdWriteWord(const char *Cmd)
{
  int Word = 16; //default to invalid block
  int Data = 0xFFFFFFFF; //default to blank data
  UsbCommand c;
  
  sscanf(Cmd, "%x %d", &Data, &Word);
  
  if (Word > 15) {
    PrintAndLog("Word must be between 0 and 15");
    return 1;
  }
  
  PrintAndLog("Writing word %d with data %08X", Word, Data);
  
  c.cmd = CMD_EM4X_WRITE_WORD;
  c.d.asBytes[0] = 0x0; //Normal mode
  c.arg[0] = Data;
  c.arg[1] = Word;
  c.arg[2] = 0;
  SendCommand(&c);
  return 0;
}

int CmdWriteWordPWD(const char *Cmd)
{
  int Word = 16; //default to invalid word
  int Data = 0xFFFFFFFF; //default to blank data
  int Password = 0xFFFFFFFF; //default to blank password
  UsbCommand c;
  
  sscanf(Cmd, "%x %d %x", &Data, &Word, &Password);
  
  if (Word > 15) {
    PrintAndLog("Word must be between 0 and 15");
    return 1;
  }
  
  PrintAndLog("Writing word %d with data %08X and password %08X", Word, Data, Password);
  
  c.cmd = CMD_EM4X_WRITE_WORD;
  c.d.asBytes[0] = 0x1; //Password mode
  c.arg[0] = Data;
  c.arg[1] = Word;
  c.arg[2] = Password;
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] =
{
  {"help", CmdHelp, 1, "This help"},
  {"em410xdemod", CmdEMdemodASK, 0, "[findone] -- Extract ID from EM410x tag (option 0 for continuous loop, 1 for only 1 tag)"},  
  {"em410xread", CmdEM410xRead, 1, "[clock rate] -- Extract ID from EM410x tag"},
  {"em410xsim", CmdEM410xSim, 0, "<UID> -- Simulate EM410x tag"},
  {"em410xwatch", CmdEM410xWatch, 0, "['h'] -- Watches for EM410x 125/134 kHz tags (option 'h' for 134)"},
  {"em410xspoof", CmdEM410xWatchnSpoof, 0, "['h'] --- Watches for EM410x 125/134 kHz tags, and replays them. (option 'h' for 134)" },
  {"em410xwrite", CmdEM410xWrite, 1, "<UID> <'0' T5555> <'1' T55x7> [clock rate] -- Write EM410x UID to T5555(Q5) or T55x7 tag, optionally setting clock rate"},
  {"em4x50read", CmdEM4x50Read, 1, "Extract data from EM4x50 tag"},
  {"readword", CmdReadWord, 1, "<Word> -- Read EM4xxx word data"},
  {"readwordPWD", CmdReadWordPWD, 1, "<Word> <Password> -- Read EM4xxx word data in password mode"},
  {"writeword", CmdWriteWord, 1, "<Data> <Word> -- Write EM4xxx word data"},
  {"writewordPWD", CmdWriteWordPWD, 1, "<Data> <Word> <Password> -- Write EM4xxx word data in password mode"},
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
