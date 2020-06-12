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
#define PROXLOG "log_%Y%m%d.txt"
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
void main_loop(char *script_cmds_file, char *script_cmd, bool stayInCommandLoop);

typedef struct pm3_context pm3_context;
pm3_context *pm3_init(void);
void pm3_exit(pm3_context *ctx);
pm3_context *pm3_get_current_context(void);
typedef struct pm3_device pm3_device;
pm3_device *pm3_open(pm3_context *ctx, char *port);
pm3_device *pm3_get_dev(pm3_context *ctx, int n);
int pm3_console(pm3_device *dev, char *cmd);
void pm3_close(pm3_device *dev);

#ifdef __cplusplus
}
#endif

#endif
