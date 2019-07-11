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
#include "comms.h"
#include "util.h"
#include "crc.h"
#include "legic_prng.h"
#include "legic.h" // legic_card_select_t struct
#include "cmdhf.h" // "hf list"
#include "loclass/fileutils.h"  //saveFile

int CmdHFLegic(const char *Cmd);

int readLegicUid(bool verbose);
int legic_print_type(uint32_t tagtype, uint8_t spaces);
int legic_get_type(legic_card_select_t *card);
void legic_chk_iv(uint32_t *iv);
void legic_seteml(uint8_t *src, uint32_t offset, uint32_t numofbytes);
int legic_read_mem(uint32_t offset, uint32_t len, uint32_t iv, uint8_t *out, uint16_t *outlen);

#endif
