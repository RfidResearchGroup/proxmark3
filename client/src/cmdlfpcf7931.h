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
// Low frequency PCF7931 commands
//-----------------------------------------------------------------------------

#ifndef CMDLFPCF7931_H__
#define CMDLFPCF7931_H__

#include "common.h"

struct pcf7931_config {
    uint8_t Pwd[7];
    uint16_t InitDelay;
    int16_t OffsetWidth;
    int16_t OffsetPosition;
};

int pcf7931_resetConfig(void);
int pcf7931_printConfig(void);

int CmdLFPCF7931(const char *Cmd);

#endif
