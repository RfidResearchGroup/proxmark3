//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Main binary
//-----------------------------------------------------------------------------

#ifndef PROXMARK3_H__
#define PROXMARK3_H__

#include "common.h"

#define PROXPROMPT_MAX_SIZE 255

#define PROXPROMPT_COMPOSE "[" "%s" "] pm3 %s--> "

#define PROXPROMPT_CTX_SCRIPTFILE  "(" _YELLOW_("script") ")"
#define PROXPROMPT_CTX_SCRIPTCMD   "(" _YELLOW_("command") ")"
#define PROXPROMPT_CTX_STDIN       "(" _YELLOW_("stdin") ")"
#define PROXPROMPT_CTX_INTERACTIVE ""

#define PROXPROMPT_DEV_USB     _BOLD_GREEN_("usb")
#define PROXPROMPT_DEV_FPC     _BOLD_GREEN_("fpc")
#define PROXPROMPT_DEV_OFFLINE _BOLD_RED_("offline")


#define PROXHISTORY "history.txt"
#define PROXLOG "log_%Y%m%d.txt"
#define MAX_NESTED_CMDSCRIPT 10
#define MAX_NESTED_LUASCRIPT 10

#ifdef __cplusplus
extern "C" {
#endif

int push_cmdscriptfile(char *path, bool stayafter);
const char *get_my_executable_path(void);
const char *get_my_executable_directory(void);
const char *get_my_user_directory(void);
void main_loop(char *script_cmds_file, char *script_cmd, bool stayInCommandLoop);

#ifdef __cplusplus
}
#endif

#endif
