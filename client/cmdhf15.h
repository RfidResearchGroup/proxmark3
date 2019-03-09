//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO15693 commands
//-----------------------------------------------------------------------------

#ifndef CMDHF15_H__
#define CMDHF15_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "proxmark3.h"
#include "graph.h"
#include "ui.h"
#include "util.h"
#include "cmdparser.h"
#include "crc16.h"             // iso15 crc
#include "cmdmain.h"
#include "cmddata.h"           // getsamples
#include "loclass/fileutils.h" // savefileEML

int CmdHF15(const char *Cmd);

extern int HF15Reader(const char *Cmd, bool verbose);

extern int CmdHF15Demod(const char *Cmd);
extern int CmdHF15Samples(const char *Cmd);
extern int CmdHF15Info(const char *Cmd);
extern int CmdHF15Record(const char *Cmd);
extern int CmdHF15Reader(const char *Cmd);
extern int CmdHF15Sim(const char *Cmd);
extern int CmdHF15Afi(const char *Cmd);
extern int CmdHF15Dump(const char *Cmd);
extern int CmdHF15Raw(const char *cmd);
extern int CmdHF15Readmulti(const char *Cmd);
extern int CmdHF15Read(const char *Cmd);
extern int CmdHF15Write(const char *Cmd);

extern int CmdHF15Help(const char *Cmd);

// usages
extern int usage_15_demod(void);
extern int usage_15_samples(void);
extern int usage_15_info(void);
extern int usage_15_record(void);
extern int usage_15_reader(void);
extern int usage_15_sim(void);
extern int usage_15_findafi(void);
extern int usage_15_dump(void);
extern int usage_15_restore(void);
extern int usage_15_raw(void);

extern int usage_15_read(void);
extern int usage_15_write(void);
extern int usage_15_readmulti(void);

extern int prepareHF15Cmd(char **cmd, UsbCommand *c, uint8_t iso15cmd);
#endif
