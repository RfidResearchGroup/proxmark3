//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// EMV core functions
//-----------------------------------------------------------------------------

#ifndef EMVCORE_H__
#define EMVCORE_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include "util.h"
#include "common.h"
#include "ui.h"
#include "emv/tlv.h"
#include "emv/dump.h"
#include "emv/emv_tags.h"

extern void TLVPrintFromBuffer(uint8_t *data, int datalen);

#endif




