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
// Utility functions used in many places, not specific to any piece of code.
//-----------------------------------------------------------------------------

#ifndef __CARDHELPER_H
#define __CARDHELPER_H

#include <ctype.h>
#include "common.h"

bool IsHIDSamPresent(bool verbose);
bool IsCardHelperPresent(bool verbose);
bool Encrypt(uint8_t *src, uint8_t *dest);
bool Decrypt(uint8_t *src, uint8_t *dest);
void DecodeBlock6(uint8_t *src);
uint8_t GetNumberBlocksForUserId(uint8_t *src);
uint8_t GetPinSize(uint8_t *src);

int GetConfigCardByIdx(uint8_t typ, uint8_t *blocks);
int GetConfigCardStrByIdx(uint8_t typ, uint8_t *out);
int VerifyRdv4Signature(uint8_t *memid, uint8_t *signature);
#endif
