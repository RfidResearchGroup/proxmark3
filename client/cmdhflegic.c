#include "proxusb.h"
#include "cmdparser.h"
#include "cmdhflegic.h"

static int CmdHelp(const char *Cmd);

int CmdLegicRFRead(const char *Cmd)
{
  UsbCommand c = {CMD_READER_LEGIC_RF};
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",        CmdHelp,        1, "This help"},
  {"reader",      CmdLegicRFRead, 0, "Start the LEGIC RF reader"},
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
