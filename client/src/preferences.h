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
// Settings Functions
//-----------------------------------------------------------------------------
#ifndef PREFERENCES_H_
#define PREFERENCES_H_

#include "fileutils.h"
#include <errno.h>

// Current working directory will be prepended.
#define preferencesFilename "preferences.json"

int CmdPreferences(const char *Cmd);
int preferences_load(void);
int preferences_save(void);

void preferences_save_callback(json_t *root);
void preferences_load_callback(json_t *root);

#endif
