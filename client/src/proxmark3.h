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
// Main binary
//-----------------------------------------------------------------------------

#ifndef PROXMARK3_H__
#define PROXMARK3_H__

#include <unistd.h>
#include "common.h"

#define PROXPROMPT_MAX_SIZE 255

#define PROXPROMPT_COMPOSE "[" "%s%s" "] pm3 --> "

#define PROXPROMPT_CTX_SCRIPTFILE  "|" _RL_GREEN_("script")
#define PROXPROMPT_CTX_SCRIPTCMD   "|" _RL_GREEN_("script")
#define PROXPROMPT_CTX_STDIN       "|" _RL_GREEN_("script")
#define PROXPROMPT_CTX_INTERACTIVE ""

#define PROXPROMPT_DEV_USB     _RL_BOLD_GREEN_("usb")
#define PROXPROMPT_DEV_FPC     _RL_BOLD_GREEN_("fpc")
#define PROXPROMPT_DEV_OFFLINE _RL_BOLD_RED_("offline")

#define PROXHISTORY "history.txt"
#define PROXLOG "log_%Y%m%d%H%M%S.txt"
#define MAX_NESTED_CMDSCRIPT 10
#define MAX_NESTED_LUASCRIPT 10

#ifdef __cplusplus
extern "C" {
#endif

// Load all settings into memory (struct)
#ifdef _WIN32
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#define GetCurrentDir getcwd
#endif

int push_cmdscriptfile(char *path, bool stayafter);
const char *get_my_executable_path(void);
const char *get_my_executable_directory(void);
const char *get_my_user_directory(void);
void pm3_init(void);
void main_loop(char *script_cmds_file, char *script_cmd, bool stayInCommandLoop);

#ifdef __cplusplus
}
#endif

#endif
