//-----------------------------------------------------------------------------
// Copyright (C) 2019 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// MIFARE Application Directory (MAD) functions
//-----------------------------------------------------------------------------

#ifndef _MAD_H_
#define _MAD_H_

#include "common.h"

int MADCheck(uint8_t *sector0, uint8_t *sector10, bool verbose, bool *haveMAD2);
int MADDecode(uint8_t *sector0, uint8_t *sector10, uint16_t *mad, size_t *madlen, bool swapmad);
int MAD1DecodeAndPrint(uint8_t *sector, bool swapmad, bool verbose, bool *haveMAD2);
int MAD2DecodeAndPrint(uint8_t *sector, bool swapmad, bool verbose);
int MADCardHolderInfoDecode(uint8_t *data, size_t dataLen, bool verbose);

#endif // _MAD_H_
