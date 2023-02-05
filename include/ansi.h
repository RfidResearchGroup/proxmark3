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
#ifndef __ANSI_H
#define __ANSI_H

// Not ANSI but dirty trick to specify we don't want a \n
#define NOLF "\xff"

#define AEND  "\x1b[0m"

#define _BLACK_(s)          "\x1b[30m" s AEND
#define _RED_(s)            "\x1b[31m" s AEND
#define _GREEN_(s)          "\x1b[32m" s AEND
#define _YELLOW_(s)         "\x1b[33m" s AEND
#define _BLUE_(s)           "\x1b[34m" s AEND
#define _MAGENTA_(s)        "\x1b[35m" s AEND
#define _CYAN_(s)           "\x1b[36m" s AEND
#define _WHITE_(s)          "\x1b[37m" s AEND

#define _BRIGHT_BLACK_(s)   "\x1b[30;1m" s AEND
#define _BRIGHT_RED_(s)     "\x1b[31;1m" s AEND
#define _BRIGHT_GREEN_(s)   "\x1b[32;1m" s AEND
#define _BRIGHT_YELLOW_(s)  "\x1b[33;1m" s AEND
#define _BRIGHT_BLUE_(s)    "\x1b[34;1m" s AEND
#define _BRIGHT_MAGENTA_(s) "\x1b[35;1m" s AEND
#define _BRIGHT_CYAN_(s)    "\x1b[36;1m" s AEND
#define _BRIGHT_WHITE_(s)   "\x1b[37;1m" s AEND

#define _BACK_BLACK_(s)     "\x1b[40m" s AEND
#define _BACK_RED_(s)       "\x1b[41m" s AEND
#define _BACK_GREEN_(s)     "\x1b[42m" s AEND
#define _BACK_YELLOW_(s)    "\x1b[43m" s AEND
#define _BACK_BLUE_(s)      "\x1b[44m" s AEND
#define _BACK_MAGENTA_(s)   "\x1b[45m" s AEND
#define _BACK_CYAN_(s)      "\x1b[46m" s AEND
#define _BACK_WHITE_(s)     "\x1b[47m" s AEND

#define _BACK_BRIGHT_BLACK_(s)   "\x1b[40;1m" s AEND
#define _BACK_BRIGHT_RED_(s)     "\x1b[41;1m" s AEND
#define _BACK_BRIGHT_GREEN_(s)   "\x1b[42;1m" s AEND
#define _BACK_BRIGHT_YELLOW_(s)  "\x1b[43;1m" s AEND
#define _BACK_BRIGHT_BLUE_(s)    "\x1b[44;1m" s AEND
#define _BACK_BRIGHT_MAGENTA_(s) "\x1b[45;1m" s AEND
#define _BACK_BRIGHT_CYAN_(s)    "\x1b[46;1m" s AEND
#define _BACK_BRIGHT_WHITE_(s)   "\x1b[47;1m" s AEND

#define _CLEAR_ "\x1b[2J"
#define _CLEAR_SCROLLBACK_ "\x1b[3J"
#define _TOP_   "\x1b[1;1f"

#if defined(HAVE_READLINE)
// https://wiki.hackzine.org/development/misc/readline-color-prompt.html
// Applications may indicate that the prompt contains
// characters that take up no physical screen space when displayed by
// bracketing a sequence of such characters with the special markers
// RL_PROMPT_START_IGNORE = '\001' and RL_PROMPT_END_IGNORE = '\002'
#define RL_ESC(a) "\001" a "\002"
#else
#define RL_ESC(a) a
#endif // HAVE_READLINE

#define _RL_RED_(s) RL_ESC("\x1b[31m") s RL_ESC(AEND)
#define _RL_GREEN_(s) RL_ESC("\x1b[32m") s RL_ESC(AEND)
#define _RL_BOLD_RED_(s) RL_ESC("\x1b[1;31m") s RL_ESC(AEND)
#define _RL_BOLD_GREEN_(s) RL_ESC("\x1b[1;32m") s RL_ESC(AEND)

#endif
