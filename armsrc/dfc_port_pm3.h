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
#ifndef __DFC_PORT_PM3_H
#define __DFC_PORT_PM3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool dfc_pm3_workspace_init(void);
void dfc_pm3_workspace_release(void);

void dfc_pm3_random_set(const uint8_t *data, size_t length, bool strict);
void dfc_pm3_random_clear(void);
size_t dfc_pm3_random_remaining(void);
bool dfc_pm3_random_underflowed(void);

#endif
