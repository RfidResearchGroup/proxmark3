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
#ifndef settings_h
#define settings_h

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
        bool use_emojis;
        bool use_hints;        
} settings_t;

// Settings struct so as to be available to other modules by including settings.h
settings_t mySettings; 

int settings_load (void);
int settings_save (void);

void settings_save_callback (json_t *root);
void settings_load_callback (json_t *root);

#endif
