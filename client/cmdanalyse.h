//-----------------------------------------------------------------------------
// Copyright (C) 2016 iceman <iceman at ...>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Data and Graph commands
//-----------------------------------------------------------------------------

#ifndef CMDANALYSE_H__
#define CMDANALYSE_H__

#include <stdlib.h>       // size_t
#include <string.h>
#include <unistd.h>
#include "cmdmain.h"
#include "proxmark3.h"
#include "ui.h"           // PrintAndLog
#include "util.h"
#include "crc.h"
#include "crc16.h"        // crc16 ccitt
#include "tea.h"
#include "legic_prng.h"
#include "loclass/elite_crack.h"
#include "mifare/mfkey.h" // nonce2key
#include "util_posix.h"   // msclock

int CmdAnalyse(const char *Cmd);
#endif
