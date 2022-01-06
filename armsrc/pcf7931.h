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
#ifndef __PCF7931_H
#define __PCF7931_H

#include "common.h"

size_t DemodPCF7931(uint8_t **outBlocks, bool ledcontrol);
bool IsBlock0PCF7931(uint8_t *block);
bool IsBlock1PCF7931(uint8_t *block);
void ReadPCF7931(bool ledcontrol);
void SendCmdPCF7931(uint32_t *tab, bool ledcontrol);
bool AddBytePCF7931(uint8_t byte, uint32_t *tab, int32_t l, int32_t p);
bool AddBitPCF7931(bool b, uint32_t *tab, int32_t l, int32_t p);
bool AddPatternPCF7931(uint32_t a, uint32_t b, uint32_t c, uint32_t *tab);
void WritePCF7931(uint8_t pass1, uint8_t pass2, uint8_t pass3, uint8_t pass4, uint8_t pass5, uint8_t pass6, uint8_t pass7, uint16_t init_delay, int32_t l, int32_t p, uint8_t address, uint8_t byte, uint8_t data, bool ledcontrol);

#endif
