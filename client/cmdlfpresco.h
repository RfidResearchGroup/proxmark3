//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Presco tag commands
//-----------------------------------------------------------------------------
#ifndef CMDLFPRESCO_H__
#define CMDLFPRESCO_H__

#include "common.h"

int CmdLFPresco(const char *Cmd);

int demodPresco(void);
int detectPresco(uint8_t *dest, size_t *size);
int getPrescoBits(uint32_t fullcode, uint8_t *prescoBits);
int getWiegandFromPresco(const char *Cmd, uint32_t *sitecode, uint32_t *usercode, uint32_t *fullcode, bool *Q5);

#endif

