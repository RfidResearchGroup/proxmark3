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
// API to abstract Readline / Linenoise support
//-----------------------------------------------------------------------------

#include "pm3line.h"
#include <stdlib.h>
#include <stdio.h> // for Mingw readline and for getline
#include <string.h>
#include <signal.h>
#if defined(HAVE_READLINE)
#include <readline/readline.h>
#include <readline/history.h>
#endif
#include "pm3line_vocabulory.h"
#include "pm3_cmd.h"
#include "ui.h"                          // g_session
#include "util.h"                        // str_ndup

#if defined(HAVE_READLINE)

static char *rl_command_generator(const char *text, int state) {
    static int index;
    static size_t len;
    size_t rlen = strlen(rl_line_buffer);
    const char *command;

    if (!state) {
        index = 0;
        len = strlen(text);
    }

    while ((command = vocabulory[index].name))  {

        // When no pm3 device present
        // and the command is not available offline,
        // we skip it.
        if ((g_session.pm3_present == false) && (vocabulory[index].offline == false))  {
            index++;
            continue;
        }

        index++;

        if (strncmp(command, rl_line_buffer, rlen) == 0) {
            const char *next = command + (rlen - len);
            const char *space = strstr(next, " ");
            if (space != NULL) {
                return str_ndup(next, space - next);
            }
            return str_dup(next);
        }
    }

    return NULL;
}

static char **rl_command_completion(const char *text, int start, int end) {
    rl_attempted_completion_over = 0;
    return rl_completion_matches(text, rl_command_generator);
}

#endif // HAVE_READLINE

#  if defined(_WIN32)
/*
static bool WINAPI terminate_handler(DWORD t) {
    if (t == CTRL_C_EVENT) {
        flush_history();
        return true;
    }
    return false;
}
*/
#  else
static struct sigaction gs_old_sigint_action;
static void sigint_handler(int signum) {
    sigaction(SIGINT, &gs_old_sigint_action, NULL);
    pm3line_flush_history();
    kill(0, SIGINT);
}
#endif

void pm3line_install_signals(void) {
#  if defined(_WIN32)
//    SetConsoleCtrlHandler((PHANDLER_ROUTINE)terminate_handler, true);
#  else
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;
    sigaction(SIGINT, &action, &gs_old_sigint_action);
#  endif
#if defined(HAVE_READLINE)
    rl_catch_signals = 1;
    rl_set_signals();
#endif // HAVE_READLINE
}

void pm3line_init(void) {
#if defined(HAVE_READLINE)
    /* initialize history */
    using_history();
    rl_readline_name = "PM3";
    rl_attempted_completion_function = rl_command_completion;

#ifdef RL_STATE_READCMD
    rl_extend_line_buffer(1024);
#endif // RL_STATE_READCMD
#endif // HAVE_READLINE
}

char *pm3line_read(const char *s) {
#if defined(HAVE_READLINE)
    return readline(s);
#else
    printf("%s", s);
    char *answer = NULL;
    size_t anslen = 0;
    int ret;
    if ((ret = getline(&answer, &anslen, stdin)) < 0) {
        // TODO this happens also when kbd_enter_pressed() is used, with a key pressed or not
        printf("DEBUG: getline returned %i", ret);
        free(answer);
        answer = NULL;
    }
    return answer;
#endif
}

void pm3line_free(void *ref) {
    free(ref);
}

void pm3line_update_prompt(const char *prompt) {
#if defined(HAVE_READLINE)
    rl_set_prompt(prompt);
    rl_forced_update_display();
#else
    (void) prompt;
#endif
}

int pm3line_load_history(const char *path) {
#if defined(HAVE_READLINE)
    if (read_history(path) == 0) {
        return PM3_SUCCESS;
    } else {
        return PM3_ESOFT;
    }
#else
    (void) path;
    return PM3_ENOTIMPL;
#endif
}

void pm3line_add_history(const char *line) {
#if defined(HAVE_READLINE)
    HIST_ENTRY *entry = history_get(history_length);
    // add if not identical to latest recorded line
    if ((!entry) || (strcmp(entry->line, line) != 0)) {
        add_history(line);
    }
#else
    (void) line;
#endif
}

void pm3line_flush_history(void) {
    if (g_session.history_path) {
#if defined(HAVE_READLINE)
        write_history(g_session.history_path);
#endif // HAVE_READLINE
        free(g_session.history_path);
        g_session.history_path = NULL;
    }
}

void pm3line_check(int (check)(void)) {
#if defined(HAVE_READLINE)
    rl_event_hook = check;
#else
    check();
#endif
}

// TODO:
// src/ui.c print_progress()
