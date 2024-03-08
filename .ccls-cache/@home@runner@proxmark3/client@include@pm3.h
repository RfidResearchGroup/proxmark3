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
#ifndef LIBPM3_H
#define LIBPM3_H

typedef struct pm3_device pm3;

pm3 *pm3_open(const char *port);
int pm3_console(pm3 *dev, const char *cmd);
const char *pm3_name_get(pm3 *dev);
void pm3_close(pm3 *dev);
pm3 *pm3_get_current_dev(void);
#endif // LIBPM3_H
