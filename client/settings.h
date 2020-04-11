//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Settings Functions
//-----------------------------------------------------------------------------
#ifndef SETTINGS_H_
#define SETTINGS_H_

#include "fileutils.h"

#define settingsFilename "settings.json"

int settings_load (void);
int settings_save (void);

void settings_save_callback (json_t *root);
void settings_load_callback (json_t *root);

#endif
