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
// Proxmark3 RDV40 AID list library
//-----------------------------------------------------------------------------

#ifndef AIDSEARCH_H__
#define AIDSEARCH_H__

#include "common.h"

#include <stdint.h>
#include <stdbool.h>
#include "jansson.h"

int PrintAIDDescription(json_t *xroot, char *aid, bool verbose);
int PrintAIDDescriptionBuf(json_t *root, uint8_t *aid, size_t aidlen, bool verbose);
json_t *AIDSearchInit(bool verbose);
json_t *AIDSearchGetElm(json_t *root, size_t elmindx);
bool AIDGetFromElm(json_t *data, uint8_t *aid, size_t aidmaxlen, int *aidlen);
int AIDSearchFree(json_t *root);

#endif
