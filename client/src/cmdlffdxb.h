//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency fdx-b tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFFDXB_H__
#define CMDLFFDXB_H__

#include "common.h"

typedef struct {
    uint16_t code;
    const char *desc;
} fdxbCountryMapping_t;

int CmdLFFdxB(const char *Cmd);
int detectFDXB(uint8_t *dest, size_t *size);
int demodFDXB(bool verbose);
//int getFDXBBits(uint64_t national_code, uint16_t country_code, uint8_t is_animal, uint8_t is_extended, uint16_t extended, uint8_t *bits);

#endif

