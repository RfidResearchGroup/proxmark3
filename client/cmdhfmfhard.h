//-----------------------------------------------------------------------------
// Copyright (C) 2015 piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// hf mf hardnested command
//-----------------------------------------------------------------------------

#ifndef CMDHFMFHARD_H__
#define CMDHFMFHARD_H__

#include "sleep.h"
#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <locale.h>
#include <math.h>
#include "proxmark3.h"
#include "cmdmain.h"
#include "ui.h"
#include "util.h"
#include "nonce2key/crapto1.h"
#include "nonce2key/crypto1_bs.h"
#include "parity.h"
#ifdef __WIN32
	#include <windows.h>
#endif
// don't include for APPLE/mac which has malloc stuff elsewhere.
#ifndef __APPLE__
	#include <malloc.h>
#endif
#include <assert.h>

int mfnestedhard(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *trgkey, bool nonce_file_read, bool nonce_file_write, bool slow, int tests);

#endif
