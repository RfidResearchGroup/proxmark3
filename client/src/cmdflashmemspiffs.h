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

#ifndef CMDFLASHMEMSPIFFS_H__
#define CMDFLASHMEMSPIFFS_H__

#include "common.h"

int CmdFlashMemSpiFFS(const char *Cmd);
int flashmem_spiffs_load(char *destfn, uint8_t *data, size_t datalen);
int flashmem_spiffs_download(char *fn, uint8_t fnlen, void **pdest, size_t *destlen);

#endif
