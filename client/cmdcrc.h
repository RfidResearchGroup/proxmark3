//-----------------------------------------------------------------------------
// Copyright (C) 2015 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CRC Calculations from the software reveng commands
//-----------------------------------------------------------------------------

#ifndef CMDCRC_H__
#define CMDCRC_H__

#ifdef _WIN32
#  include <io.h>
#  include <fcntl.h>
#  ifndef STDIN_FILENO
#    define STDIN_FILENO 0
#  endif /* STDIN_FILENO */
#endif /* _WIN32 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "cmdmain.h"
#include "reveng/reveng.h"
#include "ui.h"
#include "util.h"

int CmdCrc(const char *Cmd);

int GetModels(char *Models[], int *count, uint8_t *width);
int RunModel(char *inModel, char *inHexStr, bool reverse, char endian, char *result);
#endif
