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
// Low frequency Indala commands
//-----------------------------------------------------------------------------

#ifndef CMDLFINDALA_H__
#define CMDLFINDALA_H__

#include "common.h"

int CmdLFINDALA(const char *Cmd);

int detectIndala(uint8_t *dest, size_t *size, uint8_t *invert);
//int detectIndala26(uint8_t *bitStream, size_t *size, uint8_t *invert);
//int detectIndala64(uint8_t *bitStream, size_t *size, uint8_t *invert);
//int detectIndala224(uint8_t *bitStream, size_t *size, uint8_t *invert);
int demodIndalaEx(int clk, int invert, int maxErr, bool verbose);
int demodIndala(bool verbose);
int getIndalaBits(uint8_t fc, uint16_t cn, uint8_t *bits);
int getIndalaBits4041x(uint8_t fc, uint16_t cn, uint8_t *bits);
bool parityOdd(uint16_t x);
bool parityEven(uint16_t x);

#endif
