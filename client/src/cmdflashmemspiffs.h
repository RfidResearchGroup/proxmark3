//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Flash memory commands
//-----------------------------------------------------------------------------

#ifndef CMDFLASHMEMSPIFFS_H__
#define CMDFLASHMEMSPIFFS_H__

#include "common.h"

int CmdFlashMemSpiFFS(const char *Cmd);
int flashmem_spiffs_load(uint8_t *destfn, uint8_t *data, size_t datalen);

#endif
