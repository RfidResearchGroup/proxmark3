//-----------------------------------------------------------------------------
// Copyright (C) 2019 merlokk
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 AID list library
//-----------------------------------------------------------------------------

#ifndef AIDSEARCH_H__
#define AIDSEARCH_H__

#include "common.h"

#include <stdint.h>
#include <stdbool.h>

#include <jansson.h>

int PrintAIDDescription(json_t *xroot, char *aid, bool verbose);
int PrintAIDDescriptionBuf(json_t *root, uint8_t *aid, size_t aidlen, bool verbose);
json_t *AIDSearchInit(bool verbose);
json_t *AIDSearchGetElm(json_t *root, int elmindx);
bool AIDGetFromElm(json_t *data, uint8_t *aid, size_t aidmaxlen, int *aidlen);
int AIDSearchFree();

#endif
