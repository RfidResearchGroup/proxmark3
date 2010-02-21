//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hardware commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "ui.h"
#include "proxusb.h"
#include "cmdparser.h"
#include "cmdhw.h"

/* low-level hardware control */

static int CmdHelp(const char *Cmd);

int CmdDetectReader(const char *Cmd)
{
  UsbCommand c={CMD_LISTEN_READER_FIELD};
  // 'l' means LF - 125/134 kHz
  if(*Cmd == 'l') {
    c.arg[0] = 1;
  } else if (*Cmd == 'h') {
    c.arg[0] = 2;
  } else if (*Cmd != '\0') {
    PrintAndLog("use 'detectreader' or 'detectreader l' or 'detectreader h'");
    return 0;
  }
  SendCommand(&c);
  return 0;
}

// ## FPGA Control
int CmdFPGAOff(const char *Cmd)
{
  UsbCommand c = {CMD_FPGA_MAJOR_MODE_OFF};
  SendCommand(&c);
  return 0;
}

int CmdLCD(const char *Cmd)
{
  int i, j;

  UsbCommand c={CMD_LCD};
  sscanf(Cmd, "%x %d", &i, &j);
  while (j--) {
    c.arg[0] = i & 0x1ff;
    SendCommand(&c);
  }
  return 0;
}

int CmdLCDReset(const char *Cmd)
{
  UsbCommand c = {CMD_LCD_RESET, {strtol(Cmd, NULL, 0), 0, 0}};
  SendCommand(&c);
  return 0;
}

int CmdReadmem(const char *Cmd)
{
  UsbCommand c = {CMD_READ_MEM, {strtol(Cmd, NULL, 0), 0, 0}};
  SendCommand(&c);
  return 0;
}

int CmdReset(const char *Cmd)
{
  UsbCommand c = {CMD_HARDWARE_RESET};
  SendCommand(&c);
  return 0;
}

/*
 * Sets the divisor for LF frequency clock: lets the user choose any LF frequency below
 * 600kHz.
 */
int CmdSetDivisor(const char *Cmd)
{
  UsbCommand c = {CMD_SET_LF_DIVISOR, {strtol(Cmd, NULL, 0), 0, 0}};
  if (c.arg[0] < 0 || c.arg[0] > 255) {
    PrintAndLog("divisor must be between 19 and 255");
  } else {
    SendCommand(&c);
    PrintAndLog("Divisor set, expected freq=%dHz", 12000000 / (c.arg[0]+1));
  }
  return 0;
}

int CmdSetMux(const char *Cmd)
{
  UsbCommand c={CMD_SET_ADC_MUX};
  if (strcmp(Cmd, "lopkd") == 0) {
    c.arg[0] = 0;
  } else if (strcmp(Cmd, "loraw") == 0) {
    c.arg[0] = 1;
  } else if (strcmp(Cmd, "hipkd") == 0) {
    c.arg[0] = 2;
  } else if (strcmp(Cmd, "hiraw") == 0) {
    c.arg[0] = 3;
  }
  SendCommand(&c);
  return 0;
}

int CmdTune(const char *Cmd)
{
  UsbCommand c = {CMD_MEASURE_ANTENNA_TUNING};
  SendCommand(&c);
  return 0;
}

int CmdVersion(const char *Cmd)
{
  UsbCommand c = {CMD_VERSION};
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",          CmdHelp,        1, "This help"},
  {"detectreader",  CmdDetectReader,0, "['l'|'h'] -- Detect external reader field (option 'l' or 'h' to limit to LF or HF)"},
  {"fpgaoff",       CmdFPGAOff,     0, "Set FPGA off"},
  {"lcd",           CmdLCD,         0, "<HEX command> <count> -- Send command/data to LCD"},
  {"lcdreset",      CmdLCDReset,    0, "Hardware reset LCD"},
  {"readmem",       CmdReadmem,     0, "[address] -- Read memory at decimal address from flash"},
  {"reset",         CmdReset,       0, "Reset the Proxmark3"},
  {"setlfdivisor",  CmdSetDivisor,  0, "<19 - 255> -- Drive LF antenna at 12Mhz/(divisor+1)"},
  {"setmux",        CmdSetMux,      0, "<loraw|hiraw|lopkd|hipkd> -- Set the ADC mux to a specific value"},
  {"tune",          CmdTune,        0, "Measure antenna tuning"},
  {"version",       CmdVersion,     0, "Show version inforation about the connected Proxmark"},
  {NULL, NULL, 0, NULL}
};

int CmdHW(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
