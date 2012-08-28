//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include "proxusb.h"
#include "graph.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdhf.h"
#include "cmdhf14a.h"
#include "cmdhf14b.h"
#include "cmdhf15.h"
#include "cmdhfepa.h"
#include "cmdhflegic.h"
#include "cmdhficlass.h"
#include "cmdhfmf.h"

static int CmdHelp(const char *Cmd);

int CmdHFTune(const char *Cmd)
{
  UsbCommand c={CMD_MEASURE_ANTENNA_TUNING_HF};
  SendCommand(&c);
  return 0;
}

static command_t CommandTable[] = 
{
  {"help",        CmdHelp,          1, "This help"},
  {"14a",         CmdHF14A,         1, "{ ISO14443A RFIDs... }"},
  {"14b",         CmdHF14B,         1, "{ ISO14443B RFIDs... }"},
  {"15",          CmdHF15,          1, "{ ISO15693 RFIDs... }"},
  {"epa",         CmdHFEPA,         1, "{ German Identification Card... }"},
  {"legic",       CmdHFLegic,       0, "{ LEGIC RFIDs... }"},
  {"iclass",      CmdHFiClass,      1, "{ ICLASS RFIDs... }"},
  {"mf",      		CmdHFMF,		      1, "{ MIFARE RFIDs... }"},
  {"tune",        CmdHFTune,        0, "Continuously measure HF antenna tuning"},
  {NULL, NULL, 0, NULL}
};

int CmdHF(const char *Cmd)
{
  CmdsParse(CommandTable, Cmd);
  return 0; 
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
