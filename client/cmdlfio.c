#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
//#include "proxusb.h"
#include "proxmark3.h"
#include "data.h"
#include "graph.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "cmddata.h"
#include "cmdlf.h"

static int CmdHelp(const char *Cmd);

int CmdIODemodFSK(const char *Cmd)
{
  UsbCommand c={CMD_IO_DEMOD_FSK};
  SendCommand(&c);
  return 0;
}


int CmdIOProxDemod(const char *Cmd){
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

int CmdIOClone(const char *Cmd)
{
  unsigned int hi = 0, lo = 0;
  int n = 0, i = 0;
  UsbCommand c;

  
  //if (1 == sscanf(str, "0x%"SCNx32, &hi)) {
    // value now contains the value in the string--decimal 255, in this case.
  //}
  
  while (sscanf(&Cmd[i++], "%1x", &n ) == 1) {
      hi = (hi << 4) | (lo >> 28);
      lo = (lo << 4) | (n & 0xf);
  }

  PrintAndLog("Cloning tag with ID %08x %08x", hi, lo);

  c.cmd = CMD_IO_CLONE_TAG;
  c.arg[0] = hi;
  c.arg[1] = lo;

  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",        CmdHelp,            1, "This help"},
  {"demod",	  CmdIOProxDemod,     1, "Demodulate Stream"},
  {"fskdemod",    CmdIODemodFSK,      1, "Demodulate ioProx Tag"},
  {"clone",	  CmdIOClone,         1, "Clone ioProx Tag"},
  {NULL, NULL, 0, NULL}
};

int CmdLFIO(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0; 
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}