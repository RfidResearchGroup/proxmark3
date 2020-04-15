//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Settings Functions
//-----------------------------------------------------------------------------
#ifndef PREFERENCES_H_
#define PREFERENCES_H_

#include "fileutils.h"

// Current working directory will be prepended.
#define preferencesFilename "preferences.json"

int CmdPreferences (const char *Cmd);
int preferences_load (void);
int preferences_save (void);

void preferences_save_callback (json_t *root);
void preferences_load_callback (json_t *root);

#endif
