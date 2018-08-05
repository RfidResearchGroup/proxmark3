//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency HID commands
//-----------------------------------------------------------------------------

#ifndef CMDLFHID_H__
#define CMDLFHID_H__

#include <stdio.h>
#include <string.h>
#include "proxmark3.h"
#include "ui.h"
#include "graph.h"
#include "cmdparser.h"
#include "util.h"		// wiegand_add_parity etc
#include "cmddata.h"  //for g_debugMode, demodbuff cmds
#include "cmdlf.h"	  // lf_read
#include "cmdmain.h"			   
#include "util_posix.h"
#include "lfdemod.h"

extern int CmdLFHID(const char *Cmd);
extern int CmdHIDDemod(const char *Cmd);
extern int CmdHIDRead(const char *Cmd);
extern int CmdHIDSim(const char *Cmd);
extern int CmdHIDClone(const char *Cmd);
extern int CmdHIDWiegand(const char *Cmd);
extern int CmdHIDBrute(const char *Cmd);

extern int usage_lf_hid_read(void);
extern int usage_lf_hid_wiegand(void);
extern int usage_lf_hid_sim(void);
extern int usage_lf_hid_clone(void);
extern int usage_lf_hid_brute(void);

//void calc26(uint16_t fc, uint32_t cardno, uint8_t *out);
extern void calcWiegand(uint8_t fmtlen, uint16_t fc, uint64_t cardno, uint8_t *bits);
#endif
