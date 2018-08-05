//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Legic commands
//-----------------------------------------------------------------------------

#ifndef CMDHFLEGIC_H__
#define CMDHFLEGIC_H__

#include <stdio.h>
#include <string.h>
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "cmdmain.h"
#include "util.h"
#include "crc.h"
#include "legic_prng.h"
#include "legic.h" // legic_card_select_t struct
#include "cmdhf.h" // "hf list"

int CmdHFLegic(const char *Cmd);

extern int CmdLegicInfo(const char *Cmd);
extern int CmdLegicRdmem(const char *Cmd);
extern int CmdLegicLoad(const char *Cmd);
extern int CmdLegicRfSim(const char *Cmd);
extern int CmdLegicRfWrite(const char *Cmd);
extern int CmdLegicCalcCrc(const char *Cmd);
extern int CmdLegicDump(const char *Cmd);
extern int CmdLegicRestore(const char *Cmd);
extern int CmdLegicReader(const char *Cmd);
extern int CmdLegicELoad(const char *Cmd);
extern int CmdLegicESave(const char *Cmd);
extern int CmdLegicList(const char *Cmd);
extern int CmdLegicWipe(const char *Cmd);

int HFLegicReader(const char *Cmd, bool verbose);
int legic_print_type(uint32_t tagtype, uint8_t spaces);
int legic_get_type(legic_card_select_t *card);
void legic_chk_iv(uint32_t *iv);
void legic_seteml(uint8_t *src, uint32_t offset, uint32_t numofbytes);
int legic_read_mem(uint32_t offset, uint32_t len, uint32_t iv, uint8_t *out, uint16_t *outlen);

int usage_legic_calccrc(void);
int usage_legic_load(void);
int usage_legic_rdmem(void);
int usage_legic_sim(void);
int usage_legic_write(void);
int usage_legic_reader(void);
int usage_legic_info(void);
int usage_legic_dump(void);
int usage_legic_restore(void);
int usage_legic_wipe(void);
#endif
