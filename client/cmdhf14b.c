//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443B commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include "iso14443crc.h"
#include "proxusb.h"
#include "data.h"
#include "graph.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf14b.h"

static int CmdHelp(const char *Cmd);

int CmdHF14BDemod(const char *Cmd)
{
  int i, j, iold;
  int isum, qsum;
  int outOfWeakAt;
  bool negateI, negateQ;

  uint8_t data[256];
  int dataLen = 0;

  // As received, the samples are pairs, correlations against I and Q
  // square waves. So estimate angle of initial carrier (or just
  // quadrant, actually), and then do the demod.

  // First, estimate where the tag starts modulating.
  for (i = 0; i < GraphTraceLen; i += 2) {
    if (abs(GraphBuffer[i]) + abs(GraphBuffer[i + 1]) > 40) {
      break;
    }
  }
  if (i >= GraphTraceLen) {
    PrintAndLog("too weak to sync");
    return 0;
  }
  PrintAndLog("out of weak at %d", i);
  outOfWeakAt = i;

  // Now, estimate the phase in the initial modulation of the tag
  isum = 0;
  qsum = 0;
  for (; i < (outOfWeakAt + 16); i += 2) {
    isum += GraphBuffer[i + 0];
    qsum += GraphBuffer[i + 1];
  }
  negateI = (isum < 0);
  negateQ = (qsum < 0);

  // Turn the correlation pairs into soft decisions on the bit.
  j = 0;
  for (i = 0; i < GraphTraceLen / 2; i++) {
    int si = GraphBuffer[j];
    int sq = GraphBuffer[j + 1];
    if (negateI) si = -si;
    if (negateQ) sq = -sq;
    GraphBuffer[i] = si + sq;
    j += 2;
  }
  GraphTraceLen = i;

  i = outOfWeakAt / 2;
  while (GraphBuffer[i] > 0 && i < GraphTraceLen)
    i++;
  if (i >= GraphTraceLen) goto demodError;

  iold = i;
  while (GraphBuffer[i] < 0 && i < GraphTraceLen)
    i++;
  if (i >= GraphTraceLen) goto demodError;
  if ((i - iold) > 23) goto demodError;

  PrintAndLog("make it to demod loop");

  for (;;) {
    iold = i;
    while (GraphBuffer[i] >= 0 && i < GraphTraceLen)
      i++;
    if (i >= GraphTraceLen) goto demodError;
    if ((i - iold) > 6) goto demodError;

    uint16_t shiftReg = 0;
    if (i + 20 >= GraphTraceLen) goto demodError;

    for (j = 0; j < 10; j++) {
      int soft = GraphBuffer[i] + GraphBuffer[i + 1];

      if (abs(soft) < (abs(isum) + abs(qsum)) / 20) {
        PrintAndLog("weak bit");
      }

      shiftReg >>= 1;
      if(GraphBuffer[i] + GraphBuffer[i+1] >= 0) {
        shiftReg |= 0x200;
      }

      i+= 2;
    }

    if ((shiftReg & 0x200) && !(shiftReg & 0x001))
    {
      // valid data byte, start and stop bits okay
      PrintAndLog("   %02x", (shiftReg >> 1) & 0xff);
      data[dataLen++] = (shiftReg >> 1) & 0xff;
      if (dataLen >= sizeof(data)) {
        return 0;
      }
    } else if (shiftReg == 0x000) {
      // this is EOF
      break;
    } else {
      goto demodError;
    }
  }

  uint8_t first, second;
  ComputeCrc14443(CRC_14443_B, data, dataLen-2, &first, &second);
  PrintAndLog("CRC: %02x %02x (%s)\n", first, second,
    (first == data[dataLen-2] && second == data[dataLen-1]) ?
      "ok" : "****FAIL****");

  RepaintGraphWindow();
  return 0;

demodError:
  PrintAndLog("demod error");
  RepaintGraphWindow();
  return 0;
}

int CmdHF14BList(const char *Cmd)
{
  uint8_t got[960];
  GetFromBigBuf(got,sizeof(got),0);

  PrintAndLog("recorded activity:");
  PrintAndLog(" time  :rssi: who bytes");
  PrintAndLog("---------+----+----+-----------");

  int i = 0;
  int prev = -1;

  for(;;) {
    if(i >= 900) {
      break;
    }

    bool isResponse;
    int timestamp = *((uint32_t *)(got+i));
    if(timestamp & 0x80000000) {
      timestamp &= 0x7fffffff;
      isResponse = 1;
    } else {
      isResponse = 0;
    }
    int metric = *((uint32_t *)(got+i+4));

    int len = got[i+8];

    if(len > 100) {
      break;
    }
    if(i + len >= 900) {
      break;
    }

    uint8_t *frame = (got+i+9);

    char line[1000] = "";
    int j;
    for(j = 0; j < len; j++) {
      sprintf(line+(j*3), "%02x  ", frame[j]);
    }

    char *crc;
    if(len > 2) {
      uint8_t b1, b2;
      ComputeCrc14443(CRC_14443_B, frame, len-2, &b1, &b2);
      if(b1 != frame[len-2] || b2 != frame[len-1]) {
        crc = "**FAIL CRC**";
      } else {
        crc = "";
      }
    } else {
      crc = "(SHORT)";
    }

    char metricString[100];
    if(isResponse) {
      sprintf(metricString, "%3d", metric);
    } else {
      strcpy(metricString, "   ");
    }

    PrintAndLog(" +%7d: %s: %s %s %s",
      (prev < 0 ? 0 : timestamp - prev),
      metricString,
      (isResponse ? "TAG" : "   "), line, crc);

    prev = timestamp;
    i += (len + 9);
  }
  return 0;
}

int CmdHF14BRead(const char *Cmd)
{
  UsbCommand c = {CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443, {strtol(Cmd, NULL, 0), 0, 0}};
  SendCommand(&c);
  return 0;
}

int CmdHF14Sim(const char *Cmd)
{
  UsbCommand c={CMD_SIMULATE_TAG_ISO_14443};
  SendCommand(&c);
  return 0;
}

int CmdHFSimlisten(const char *Cmd)
{
  UsbCommand c = {CMD_SIMULATE_TAG_HF_LISTEN};
  SendCommand(&c);
  return 0;
}

int CmdHF14BSnoop(const char *Cmd)
{
  UsbCommand c = {CMD_SNOOP_ISO_14443};
  SendCommand(&c);
  return 0;
}

/* New command to read the contents of a SRI512 tag
 * SRI512 tags are ISO14443-B modulated memory tags,
 * this command just dumps the contents of the memory
 */
int CmdSri512Read(const char *Cmd)
{
  UsbCommand c = {CMD_READ_SRI512_TAG, {strtol(Cmd, NULL, 0), 0, 0}};
  SendCommand(&c);
  return 0;
}

/* New command to read the contents of a SRIX4K tag
 * SRIX4K tags are ISO14443-B modulated memory tags,
 * this command just dumps the contents of the memory/
 */
int CmdSrix4kRead(const char *Cmd)
{
  UsbCommand c = {CMD_READ_SRIX4K_TAG, {strtol(Cmd, NULL, 0), 0, 0}};
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",        CmdHelp,        1, "This help"},
  {"demod",       CmdHF14BDemod,  1, "Demodulate ISO14443 Type B from tag"},
  {"list",        CmdHF14BList,   0, "List ISO 14443 history"},
  {"read",        CmdHF14BRead,   0, "Read HF tag (ISO 14443)"},
  {"sim",         CmdHF14Sim,     0, "Fake ISO 14443 tag"},
  {"simlisten",   CmdHFSimlisten, 0, "Get HF samples as fake tag"},
  {"snoop",       CmdHF14BSnoop,  0, "Eavesdrop ISO 14443"},
  {"sri512read",  CmdSri512Read,  0, "<int> -- Read contents of a SRI512 tag"},
  {"srix4kread",  CmdSrix4kRead,  0, "<int> -- Read contents of a SRIX4K tag"},
  {NULL, NULL, 0, NULL}
};

int CmdHF14B(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
