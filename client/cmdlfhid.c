//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency HID commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include "proxusb.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmdlfhid.h"

static int CmdHelp(const char *Cmd);

int CmdHIDDemod(const char *Cmd)
{
  if (GraphTraceLen < 4800) {
    PrintAndLog("too short; need at least 4800 samples");
    return 0;
  }

  GraphTraceLen = 4800;
  for (int i = 0; i < GraphTraceLen; ++i) {
    if (GraphBuffer[i] < 0) {
      GraphBuffer[i] = 0;
    } else {
      GraphBuffer[i] = 1;
    }
  }
  RepaintGraphWindow();
  return 0;
}

int CmdHIDDemodFSK(const char *Cmd)
{
  UsbCommand c={CMD_HID_DEMOD_FSK};
  SendCommand(&c);
  return 0;
}

int CmdHIDSim(const char *Cmd)
{
  unsigned int hi = 0, lo = 0;
  int n = 0, i = 0;

  while (sscanf(&Cmd[i++], "%1x", &n ) == 1) {
    hi = (hi << 4) | (lo >> 28);
    lo = (lo << 4) | (n & 0xf);
  }

  PrintAndLog("Emulating tag with ID %x%16x", hi, lo);

  UsbCommand c = {CMD_HID_SIM_TAG, {hi, lo, 0}};
  SendCommand(&c);
  return 0;
}

int CmdHIDClone(const char *Cmd)
{
  unsigned int hi = 0, lo = 0;
  int n = 0, i = 0;

  while (sscanf(&Cmd[i++], "%1x", &n ) == 1) {
    hi = (hi << 4) | (lo >> 28);
    lo = (lo << 4) | (n & 0xf);
  }

  PrintAndLog("Cloning tag with ID %x%08x", hi, lo);

  UsbCommand c = {CMD_HID_CLONE_TAG, {hi, lo}};
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",      CmdHelp,        1, "This help"},
  {"demod",     CmdHIDDemod,    1, "Demodulate HID Prox Card II (not optimal)"},
  {"fskdemod",  CmdHIDDemodFSK, 0, "Realtime HID FSK demodulator"},
  {"sim",       CmdHIDSim,      0, "<ID> -- HID tag simulator"},
  {"clone",     CmdHIDClone,    0, "<ID> -- Clone HID to T55x7 (tag must be in antenna)"},
  {NULL, NULL, 0, NULL}
};

int CmdLFHID(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
