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
// MIFARE Application Directory (MAD) functions
//-----------------------------------------------------------------------------

#ifndef _MAD_H_
#define _MAD_H_

#include "common.h"

int MADCheck(uint8_t *sector0, uint8_t *sector10, bool verbose, bool *haveMAD2);
int MADDecode(uint8_t *sector0, uint8_t *sector10, uint16_t *mad, size_t *madlen, bool swapmad);
int MAD1DecodeAndPrint(uint8_t *sector, bool swapmad, bool verbose, bool *haveMAD2);
int MAD2DecodeAndPrint(uint8_t *sector, bool swapmad, bool verbose);
int MADDFDecodeAndPrint(uint32_t short_aid, bool verbose);
int MADCardHolderInfoDecode(uint8_t *data, size_t datalen, bool verbose);
void MADPrintHeader(void);
bool HasMADKey(uint8_t *d);
int DetectHID(uint8_t *d, uint16_t manufacture);
int convert_mad_to_arr(uint8_t *in, uint16_t ilen, uint8_t *out, uint16_t *olen);
#endif // _MAD_H_
