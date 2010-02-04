#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "cmdparser.h"
#include "data.h"
#include "usb_cmd.h"
#include "ui.h"
#include "cmdhf.h"
#include "cmddata.h"
#include "cmdhw.h"
#include "cmdlf.h"
#include "cmdmain.h"

unsigned int current_command = CMD_UNKNOWN;
unsigned int received_command = CMD_UNKNOWN;

static int CmdHelp(const char *Cmd);
static int CmdQuit(const char *Cmd);

static command_t CommandTable[] = 
{
  {"help",  CmdHelp,  1, "This help"},
  {"data",  CmdData,  1, "Plot window / data buffer manipulation"},
  {"exit",  CmdQuit,  1, "Exit program"},
  {"hf",    CmdHF,    1, "HF commands"},
  {"hw",    CmdHW,    1, "Hardware commands"},
  {"lf",    CmdLF,    1, "LF commands"},
  {"quit",  CmdQuit,  1, "Quit program"},
  {NULL, NULL, 0, NULL}
};

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}

int CmdQuit(const char *Cmd)
{
  exit(0);
  return 0;
}

void WaitForResponse(uint32_t response_type)
{
  while (received_command != response_type) {
#ifdef WIN32
    UsbCommand c;
    if (ReceiveCommandPoll(&c))
      UsbCommandReceived(&c);
    Sleep(0);
#else
    usleep(10000); // XXX ugh
#endif
  }
  received_command = CMD_UNKNOWN;
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever the user types a command and
// then presses Enter, which the full command line that they typed.
//-----------------------------------------------------------------------------
void CommandReceived(char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever we received a packet over USB
// that we weren't necessarily expecting, for example a debug print.
//-----------------------------------------------------------------------------
void UsbCommandReceived(UsbCommand *UC)
{
  //	printf("%s(%x) current cmd = %x\n", __FUNCTION__, c->cmd, current_command);
  /* If we recognize a response, return to avoid further processing */
  switch(UC->cmd) {
    case CMD_DEBUG_PRINT_STRING: {
      char s[100];
      if(UC->arg[0] > 70 || UC->arg[0] < 0) {
        UC->arg[0] = 0;
      }
      memcpy(s, UC->d.asBytes, UC->arg[0]);
      s[UC->arg[0]] = '\0';
      PrintAndLog("#db# %s", s);
      return;
    }

    case CMD_DEBUG_PRINT_INTEGERS:
      PrintAndLog("#db# %08x, %08x, %08x\r\n", UC->arg[0], UC->arg[1], UC->arg[2]);
      return;

    case CMD_MEASURED_ANTENNA_TUNING: {
      int peakv, peakf;
      int vLf125, vLf134, vHf;
      vLf125 = UC->arg[0] & 0xffff;
      vLf134 = UC->arg[0] >> 16;
      vHf = UC->arg[1] & 0xffff;;
      peakf = UC->arg[2] & 0xffff;
      peakv = UC->arg[2] >> 16;
      PrintAndLog("");
      PrintAndLog("");
      PrintAndLog("# LF antenna: %5.2f V @   125.00 kHz", vLf125/1000.0);
      PrintAndLog("# LF antenna: %5.2f V @   134.00 kHz", vLf134/1000.0);
      PrintAndLog("# LF optimal: %5.2f V @%9.2f kHz", peakv/1000.0, 12000.0/(peakf+1));
      PrintAndLog("# HF antenna: %5.2f V @    13.56 MHz", vHf/1000.0);
      if (peakv<2000)
        PrintAndLog("# Your LF antenna is unusable.");
      else if (peakv<10000)
        PrintAndLog("# Your LF antenna is marginal.");
      if (vHf<2000)
        PrintAndLog("# Your HF antenna is unusable.");
      else if (vHf<5000)
        PrintAndLog("# Your HF antenna is marginal.");
      return;
    }
    default:
      break;
  }
  /* Maybe it's a response: */
  switch(current_command) {
    case CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K:
      if (UC->cmd != CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K) goto unexpected_response;
      int i;
      for(i=0; i<48; i++) sample_buf[i] = UC->d.asBytes[i];
      received_command = UC->cmd;
      return;
    case CMD_DOWNLOADED_SIM_SAMPLES_125K:
      if (UC->cmd != CMD_ACK) goto unexpected_response;
      // got ACK
      received_command = UC->cmd;
      return;
    default:
    unexpected_response:
    PrintAndLog("unrecognized command %08x\n", UC->cmd);
    break;
  }
}