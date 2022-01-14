//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Flash memory commands
//-----------------------------------------------------------------------------

#ifndef CMDFLASHMEM_H__
#define CMDFLASHMEM_H__

#include "common.h"
#include "pmflash.h"           // rdv40validation_t

typedef enum {
    DICTIONARY_NONE = 0,
    DICTIONARY_MIFARE,
    DICTIONARY_T55XX,
    DICTIONARY_ICLASS
} Dictionary_t;

int CmdFlashMem(const char *Cmd);
int rdv4_get_signature(rdv40_validation_t *out);
int rdv4_validate(rdv40_validation_t *mem);
#endif
