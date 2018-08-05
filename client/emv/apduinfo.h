//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// APDU status bytes information
//-----------------------------------------------------------------------------

#ifndef APDUINFO_H__
#define APDUINFO_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

#define APDUCODE_TYPE_NONE		0
#define APDUCODE_TYPE_INFO		1
#define APDUCODE_TYPE_WARNING	2
#define APDUCODE_TYPE_ERROR		3
#define APDUCODE_TYPE_SECURITY	4

typedef struct {
	const char *ID;
	const uint8_t Type;
	const char *Description;
} APDUCode;
	
extern const APDUCode* const GetAPDUCode(uint8_t sw1, uint8_t sw2);
extern const char* GetAPDUCodeDescription(uint8_t sw1, uint8_t sw2);

#endif
