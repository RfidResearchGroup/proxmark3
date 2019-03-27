//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Smartcard module commands
//-----------------------------------------------------------------------------

#ifndef CMDSMARTCARD_H__
#define CMDSMARTCARD_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "common.h"
#include "util.h"
#include "loclass/fileutils.h"  // saveFile
#include "comms.h"              // getfromdevice
#include "emv/emvcore.h"        // decodeTVL
#include "emv/apduinfo.h"       // APDUcode description
#include "emv/dump.h"           // dump_buffer
#include "crypto/libpcrypto.h"	// sha512hash

extern int CmdSmartcard(const char *Cmd);

extern int CmdSmartRaw(const char *cmd);
extern int CmdSmartUpgrade(const char *cmd);
extern int CmdSmartInfo(const char *cmd);
extern int CmdSmartReader(const char *Cmd);

extern bool smart_select(bool silent, smart_card_atr_t *atr);
extern int ExchangeAPDUSC(uint8_t *datain, int datainlen, bool activateCard, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);

extern int usage_sm_raw(void);
extern int usage_sm_reader(void);
extern int usage_sm_info(void);
extern int usage_sm_upgrade(void);
#endif
