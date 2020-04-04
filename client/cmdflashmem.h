//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Flash memory commands
//-----------------------------------------------------------------------------

#ifndef CMDFLASHMEM_H__
#define CMDFLASHMEM_H__

#include "common.h"

typedef enum {
    DICTIONARY_NONE = 0,
    DICTIONARY_MIFARE,
    DICTIONARY_T55XX,
    DICTIONARY_ICLASS
} Dictionary_t;

int CmdFlashMem(const char *Cmd);

#endif
