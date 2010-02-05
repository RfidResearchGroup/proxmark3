#include <stdio.h>
#include <string.h>
#include "proxusb.h"
#include "cmdparser.h"
#include "cmdhflegic.h"

static int CmdHelp(const char *Cmd);

int CmdLegicRFRead(const char *Cmd)
{
  int byte_count=0,offset=0;
  sscanf(Cmd, "%i %i", &offset, &byte_count);
  if(byte_count == 0) byte_count = 256;
  if(byte_count + offset > 256) byte_count = 256 - offset;
  UsbCommand c={CMD_READER_LEGIC_RF, {offset, byte_count, 0}};
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",        CmdHelp,        1, "This help"},
  {"reader",      CmdLegicRFRead, 0, "[offset [length]] -- read bytes from a LEGIC card"},
  {NULL, NULL, 0, NULL}
};

int CmdHFLegic(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
