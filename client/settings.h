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

#include "fileutils.h"

#define settingsFilename "settings.json"
typedef struct {
        bool loaded;
        char version[20];
        bool os_windows_usecolor;
        bool os_windows_useansicolor;
        int  window_xpos;
        int  window_ypos;
        int  window_hsize;
        int  window_wsize;
} settings_t;

settings_t mySettings; 

void settingsLoad (void);
int settingsSave (void);

void JsonSaveCallback ( json_t *root);
void JsonLoadCallback ( json_t *root);
