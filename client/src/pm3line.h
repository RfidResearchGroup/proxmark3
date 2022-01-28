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
// API to abstract Readline / Linenoise support
//-----------------------------------------------------------------------------

#ifndef PM3LINE_H__
#define PM3LINE_H__

void pm3line_init(void);
void pm3line_install_signals(void);
char *pm3line_read(const char *s);
void pm3line_free(void *ref);
void pm3line_update_prompt(const char *prompt);
int pm3line_load_history(const char *path);
void pm3line_add_history(const char *line);
void pm3line_flush_history(void);
void pm3line_check(int (check)(void));

#endif // PM3LINE_H__
