//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency T55xx commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "proxmark3.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "cmdlft55xx.h"

static int CmdHelp(const char *Cmd);


int CmdReadBlk(const char *Cmd)
{
  int Block = 8; //default to invalid block
  UsbCommand c;

  sscanf(Cmd, "%d", &Block);

  if (Block > 7) {
  	PrintAndLog("Block must be between 0 and 7");
  	return 1;
  }	

  PrintAndLog("Reading block %d", Block);

  c.cmd = CMD_T55XX_READ_BLOCK;
  c.d.asBytes[0] = 0x0; //Normal mode
  c.arg[0] = 0;
  c.arg[1] = Block;
  c.arg[2] = 0;
  SendCommand(&c);
  return 0;
}

int CmdReadBlkPWD(const char *Cmd)
{
  int Block = 8; //default to invalid block
  int Password = 0xFFFFFFFF; //default to blank Block 7
  UsbCommand c;

  sscanf(Cmd, "%d %x", &Block, &Password);

  if (Block > 7) {
  	PrintAndLog("Block must be between 0 and 7");
  	return 1;
  }	

  PrintAndLog("Reading block %d with password %08X", Block, Password);

  c.cmd = CMD_T55XX_READ_BLOCK;
  c.d.asBytes[0] = 0x1; //Password mode
  c.arg[0] = 0;
  c.arg[1] = Block;
  c.arg[2] = Password;
  SendCommand(&c);
  return 0;
}

int CmdWriteBlk(const char *Cmd)
{
  int Block = 8; //default to invalid block
  int Data = 0xFFFFFFFF; //default to blank Block 
  UsbCommand c;

  sscanf(Cmd, "%x %d", &Data, &Block);

  if (Block > 7) {
  	PrintAndLog("Block must be between 0 and 7");
  	return 1;
  }	

  PrintAndLog("Writting block %d with data %08X", Block, Data);

  c.cmd = CMD_T55XX_WRITE_BLOCK;
  c.d.asBytes[0] = 0x0; //Normal mode
  c.arg[0] = Data;
  c.arg[1] = Block;
  c.arg[2] = 0;
  SendCommand(&c);
  return 0;
}

int CmdWriteBlkPWD(const char *Cmd)
{
  int Block = 8; //default to invalid block
  int Data = 0xFFFFFFFF; //default to blank Block 
  int Password = 0xFFFFFFFF; //default to blank Block 7
  UsbCommand c;

  sscanf(Cmd, "%x %d %x", &Data, &Block, &Password);

  if (Block > 7) {
  	PrintAndLog("Block must be between 0 and 7");
  	return 1;
  }	

  PrintAndLog("Writting block %d with data %08X and password %08X", Block, Data, Password);

  c.cmd = CMD_T55XX_WRITE_BLOCK;
  c.d.asBytes[0] = 0x1; //Password mode
  c.arg[0] = Data;
  c.arg[1] = Block;
  c.arg[2] = Password;
  SendCommand(&c);
  return 0;
}

int CmdReadTrace(const char *Cmd)
{

  PrintAndLog("Reading traceability data");

  UsbCommand c = {CMD_T55XX_READ_TRACE, {0, 0, 0}};
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] =
{
  {"help",          CmdHelp,        1, "This help"},
  {"readblock",     CmdReadBlk,     1, "<Block> -- Read T55xx block data (page 0)"},
  {"readblockPWD",  CmdReadBlkPWD,  1, "<Block> <Password> -- Read T55xx block data in password mode(page 0)"},
  {"writeblock",    CmdWriteBlk,    1, "<Data> <Block> -- Write T55xx block data (page 0)"},
  {"writeblockPWD", CmdWriteBlkPWD, 1, "<Data> <Block> <Password> -- Write T55xx block data in password mode(page 0)"},
  {"readtrace",     CmdReadTrace,   1, "Read T55xx traceability data (page 1)"},
  {NULL, NULL, 0, NULL}
};

int CmdLFT55XX(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
