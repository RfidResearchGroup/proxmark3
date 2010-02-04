#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "proxusb.h"
#include "data.h"
#include "graph.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf15.h"

static int CmdHelp(const char *Cmd);

static uint16_t Iso15693Crc(uint8_t *v, int n)
{
  uint32_t reg;
  int i, j;

  reg = 0xffff;
  for (i = 0; i < n; i++) {
    reg = reg ^ ((uint32_t)v[i]);
    for (j = 0; j < 8; j++) {
      if (reg & 0x0001) {
        reg = (reg >> 1) ^ 0x8408;
      } else {
        reg = (reg >> 1);
      }
    }
  }

  return (uint16_t)~reg;
}

int CmdHF15Demod(const char *Cmd)
{
  // The sampling rate is 106.353 ksps/s, for T = 18.8 us

  // SOF defined as
  // 1) Unmodulated time of 56.64us
  // 2) 24 pulses of 423.75khz
  // 3) logic '1' (unmodulated for 18.88us followed by 8 pulses of 423.75khz)

  static const int FrameSOF[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    -1, -1, -1, -1,
    -1, -1, -1, -1,
     1,  1,  1,  1,
     1,  1,  1,  1
  };
  static const int Logic0[] = {
     1,  1,  1,  1,
     1,  1,  1,  1,
    -1, -1, -1, -1,
    -1, -1, -1, -1
  };
  static const int Logic1[] = {
    -1, -1, -1, -1,
    -1, -1, -1, -1,
     1,  1,  1,  1,
     1,  1,  1,  1
  };

  // EOF defined as
  // 1) logic '0' (8 pulses of 423.75khz followed by unmodulated for 18.88us)
  // 2) 24 pulses of 423.75khz
  // 3) Unmodulated time of 56.64us

  static const int FrameEOF[] = {
     1,  1,  1,  1,
     1,  1,  1,  1,
    -1, -1, -1, -1,
    -1, -1, -1, -1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
  };

  int i, j;
  int max = 0, maxPos;

  int skip = 4;

  if (GraphTraceLen < 1000) return 0;

  // First, correlate for SOF
  for (i = 0; i < 100; i++) {
    int corr = 0;
    for (j = 0; j < arraylen(FrameSOF); j += skip) {
      corr += FrameSOF[j] * GraphBuffer[i + (j / skip)];
    }
    if (corr > max) {
      max = corr;
      maxPos = i;
    }
  }
  PrintAndLog("SOF at %d, correlation %d", maxPos,
    max / (arraylen(FrameSOF) / skip));

  i = maxPos + arraylen(FrameSOF) / skip;
  int k = 0;
  uint8_t outBuf[20];
  memset(outBuf, 0, sizeof(outBuf));
  uint8_t mask = 0x01;
  for (;;) {
    int corr0 = 0, corr1 = 0, corrEOF = 0;
    for (j = 0; j < arraylen(Logic0); j += skip) {
      corr0 += Logic0[j] * GraphBuffer[i + (j / skip)];
    }
    for (j = 0; j < arraylen(Logic1); j += skip) {
      corr1 += Logic1[j] * GraphBuffer[i + (j / skip)];
    }
    for (j = 0; j < arraylen(FrameEOF); j += skip) {
      corrEOF += FrameEOF[j] * GraphBuffer[i + (j / skip)];
    }
    // Even things out by the length of the target waveform.
    corr0 *= 4;
    corr1 *= 4;

    if (corrEOF > corr1 && corrEOF > corr0) {
      PrintAndLog("EOF at %d", i);
      break;
    } else if (corr1 > corr0) {
      i += arraylen(Logic1) / skip;
      outBuf[k] |= mask;
    } else {
      i += arraylen(Logic0) / skip;
    }
    mask <<= 1;
    if (mask == 0) {
      k++;
      mask = 0x01;
    }
    if ((i + (int)arraylen(FrameEOF)) >= GraphTraceLen) {
      PrintAndLog("ran off end!");
      break;
    }
  }
  if (mask != 0x01) {
    PrintAndLog("error, uneven octet! (discard extra bits!)");
    PrintAndLog("   mask=%02x", mask);
  }
  PrintAndLog("%d octets", k);

  for (i = 0; i < k; i++) {
    PrintAndLog("# %2d: %02x ", i, outBuf[i]);
  }
  PrintAndLog("CRC=%04x", Iso15693Crc(outBuf, k - 2));
  return 0;
}

int CmdHF15Read(const char *Cmd)
{
  UsbCommand c = {CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693};
  SendCommand(&c);
  return 0;
}

int CmdHF15Reader(const char *Cmd)
{
  UsbCommand c = {CMD_READER_ISO_15693, {strtol(Cmd, NULL, 0), 0, 0}};
  SendCommand(&c);
  return 0;
}

int CmdHF15Sim(const char *Cmd)
{
  UsbCommand c = {CMD_SIMTAG_ISO_15693, {strtol(Cmd, NULL, 0), 0, 0}};
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",    CmdHelp,        1, "This help"},
  {"demod",   CmdHF15Demod,   1, "Demodulate ISO15693 from tag"},
  {"read",    CmdHF15Read,    0, "Read HF tag (ISO 15693)"},
  {"reader",  CmdHF15Reader,  0, "Act like an ISO15693 reader"},
  {"sim",     CmdHF15Sim,     0, "Fake an ISO15693 tag"},
  {NULL, NULL, 0, NULL}
};

int CmdHF15(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
