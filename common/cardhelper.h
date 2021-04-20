//-----------------------------------------------------------------------------
// Iceman, February 2020
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Utility functions used in many places, not specific to any piece of code.
//-----------------------------------------------------------------------------

#ifndef __CARDHELPER_H
#define __CARDHELPER_H

#include <ctype.h>
#include "common.h"

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
