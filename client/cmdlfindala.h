//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Indala commands
//-----------------------------------------------------------------------------

#ifndef CMDLFINDALA_H__
#define CMDLFINDALA_H__

#include "common.h"

int CmdLFINDALA(const char *Cmd);

int detectIndala(uint8_t *dest, size_t *size, uint8_t *invert);
int detectIndala26(uint8_t *bitStream, size_t *size, uint8_t *invert);
int detectIndala64(uint8_t *bitStream, size_t *size, uint8_t *invert);
int detectIndala224(uint8_t *bitStream, size_t *size, uint8_t *invert);
int demodIndala(void);
int getIndalaBits(uint8_t fc, uint16_t cn, uint8_t *bits);

#endif
