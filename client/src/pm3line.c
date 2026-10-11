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
#ifndef _WIN32
#include <unistd.h>                      // write, isatty, STDOUT_FILENO
#endif
#if defined(HAVE_READLINE)
#include <readline/readline.h>
#include <readline/history.h>
#elif defined(HAVE_LINENOISE)
#include "linenoise.h"
#endif
#include "pm3line_vocabulary.h"
#include "pm3_cmd.h"
#include "ui.h"                          // g_session
#include "util.h"                        // str_ndup
#include "frame_data2.h"                 // fx_terminal_restore

static void pm3line_claim_signals(void);

#if defined(HAVE_READLINE)

static char *rl_command_generator(const char *text, int state) {
    static size_t index;
    static size_t len;
    static size_t count;
    static const vocabulary_t *vocabulary;
    size_t rlen = strlen(rl_line_buffer);

    if (!state) {
        index = 0;
        len = strlen(text);
        vocabulary = pm3line_vocabulary_get(&count);
    }

    while (index < count) {

        const vocabulary_t *entry = &vocabulary[index++];

        // Skip commands which are not available right now,
        // using the same rules as "help"
        if (pm3line_vocabulary_is_available(entry) == false) {
            continue;
        }

        const char *command = entry->name;

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

static int (*gs_check_hook)(void) = NULL;

static int pm3line_startup_hook(void) {
    pm3line_claim_signals();
    return 0;
}

#elif defined(HAVE_LINENOISE)
static void ln_command_completion(const char *text, linenoiseCompletions *lc) {
    const char *prev_match = "";
    size_t prev_match_len = 0;
    size_t len = strlen(text);
    size_t count = 0;
    const vocabulary_t *vocabulary = pm3line_vocabulary_get(&count);

    for (size_t index = 0; index < count; index++) {

        const vocabulary_t *entry = &vocabulary[index];

        // Skip commands which are not available right now,
        // using the same rules as "help"
        if (pm3line_vocabulary_is_available(entry) == false) {
            continue;
        }

        const char *command = entry->name;

        if (strncmp(command, text, len) == 0) {
            const char *space = strstr(command + len, " ");
            if (space != NULL) {
                if ((prev_match_len == 0) || (strncmp(prev_match, command, prev_match_len < space - command ? prev_match_len : space - command) != 0)) {
                    linenoiseAddCompletion(lc, str_ndup(command, space - command + 1));
                    prev_match = command;
                    prev_match_len = space - command + 1;
                }
            } else {
                linenoiseAddCompletion(lc, command);
            }
        }
    }
}
#endif // HAVE_READLINE

static volatile sig_atomic_t gs_sigint_caught = 0;
static volatile sig_atomic_t gs_at_prompt = 0;

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
static struct sigaction gs_old_sigtstp_action;
static volatile sig_atomic_t gs_echo_ctrl_c = 0;
static void sigtstp_handler(int signum);
static void sigint_handler(int signum) {

    switch (signum) {
        case SIGINT: {
            // Second CTRL-C. The graceful path did not take, restore the
            // default disposition and let this one through.
            if (gs_sigint_caught) {
                fx_terminal_restore();
                sigaction(SIGINT, &gs_old_sigint_action, NULL);
                raise(SIGINT);
                break;
            }
            // Only set a flag here. Saving the history means malloc and stdio,
            // neither is safe to call from a signal handler in a threaded
            // client. write() is, and the terminal no longer echoes the
            // character for us since readline turned ECHO off
            gs_sigint_caught = 1;

            if (gs_echo_ctrl_c) {
                static const char at_prompt[] = "^C";
                // the terminal is out of raw mode while a command runs, so it
                // echoed the ^C itself. Only say what happens next
                static const char in_command[] = "\nquitting once this command is done. CTRL-C again to force\n";
                ssize_t ignored;
                if (gs_at_prompt) {
                    ignored = write(STDOUT_FILENO, at_prompt, sizeof(at_prompt) - 1);
                } else {
                    ignored = write(STDOUT_FILENO, in_command, sizeof(in_command) - 1);
                }
                (void) ignored;
            }
            break;
        }
        default: {
            break;
        }
    }
}

// CTRL-Z. Put the terminal back the way the shell expects it, stop for real
// on this thread, and set the line editor up again once we are continued
static void sigtstp_handler(int signum) {

    if (signum != SIGTSTP) {
        return;
    }

    int at_prompt = gs_at_prompt;
    (void) at_prompt;

    fx_terminal_restore();

#if defined(HAVE_READLINE)
    if (at_prompt) {
        rl_cleanup_after_signal();
    }
#endif

    sigaction(SIGTSTP, &gs_old_sigtstp_action, NULL);

    sigset_t set;
    sigprocmask(SIG_BLOCK, NULL, &set);
    sigdelset(&set, SIGTSTP);

    raise(SIGTSTP);

    // the signal raised above is blocked while we are inside the handler,
    // unblocking it is what stops us. We resume here on SIGCONT
    sigprocmask(SIG_SETMASK, &set, NULL);

    pm3line_claim_signals();
    fx_terminal_resume();

#if defined(HAVE_READLINE)
    if (at_prompt) {
        rl_reset_after_signal();
    }
#endif
}

// Leave the terminal usable when the client is killed instead of quit
static void sigfatal_handler(int signum) {

    fx_terminal_restore();

#if defined(HAVE_READLINE)
    if (gs_at_prompt) {
        rl_cleanup_after_signal();
    }
#endif

    signal(signum, SIG_DFL);
    raise(signum);
}

static void claim_one_signal(int signum, void (*handler)(int)) {

    struct sigaction current;
    if (sigaction(signum, NULL, &current) != 0) {
        return;
    }

    if (current.sa_handler == handler) {
        return;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigaction(signum, &action, NULL);
}

#endif

// Readline answers a caught signal by cleaning up, re-raising it and then
// reinstalling its handler. In a threaded client that re-raise lands on
// whichever handler is installed at that instant, which can be readline's own
// again, and the cycle repeats. Measured on CTRL-C and CTRL-Z alike, one
// keypress gave a dozen echoes and a coin flip over whether it did anything.
// So the client owns them, and takes them back from anything that grabs one,
// like the flasher progress bar, which installs a handler it never restores
static void pm3line_claim_signals(void) {
#  if !defined(_WIN32)
    claim_one_signal(SIGINT, &sigint_handler);
    claim_one_signal(SIGTSTP, &sigtstp_handler);
#  endif
}

void pm3line_install_signals(void) {
#  if defined(_WIN32)
//    SetConsoleCtrlHandler((PHANDLER_ROUTINE)terminate_handler, true);
#  else
    gs_echo_ctrl_c = (isatty(STDOUT_FILENO) == 1);

    struct sigaction action;
    memset(&action, 0, sizeof(action));

    action.sa_handler = &sigint_handler;
    sigaction(SIGINT, &action, &gs_old_sigint_action);

    action.sa_handler = &sigtstp_handler;
    sigaction(SIGTSTP, &action, &gs_old_sigtstp_action);

    action.sa_handler = &sigfatal_handler;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
#  endif

#if defined(HAVE_READLINE)
    // Readline must not catch these itself, see pm3line_claim_signals().
    // rl_catch_sigwinch is a separate flag, window resizes stay with readline
    rl_catch_signals = 0;
    rl_startup_hook = pm3line_startup_hook;
#endif // HAVE_READLINE
}

#if defined(HAVE_READLINE)
// readline calls this roughly ten times a second while it waits for input
static int pm3line_event_hook(void) {

    pm3line_claim_signals();

    if (gs_sigint_caught) {
        // Drop the line being edited and make readline() return, so the caller
        // reaches the normal shutdown instead of dying inside a handler
        rl_free_line_state();
        rl_replace_line("", 0);
        rl_done = 1;
        return 0;
    }

    if (gs_check_hook) {
        return gs_check_hook();
    }
    return 0;
}
#endif // HAVE_READLINE

void pm3line_init(void) {
#if defined(HAVE_READLINE) || defined(HAVE_LINENOISE)
    // Build the completion vocabulary from the live command tree
    pm3line_vocabulary_build();
#endif
#if defined(HAVE_READLINE)
    /* initialize history */
    using_history();
    rl_readline_name = "PM3";
    rl_attempted_completion_function = rl_command_completion;

// don't hook signal in MINGW
#if defined(__MINGW32__) || defined(__MINGW64__)
#else
    rl_getc_function = getc;
#endif

#ifdef RL_STATE_READCMD
    rl_extend_line_buffer(1024);
#endif // RL_STATE_READCMD
#elif defined(HAVE_LINENOISE)
    linenoiseInstallWindowChangeHandler();
    linenoiseSetCompletionCallback(ln_command_completion);
#endif // HAVE_READLINE

    pm3line_install_signals();
}

char *pm3line_read(const char *s) {

    pm3line_claim_signals();

    // CTRL-C already asked for a shutdown, do not put up another prompt.
    // NULL is what CTRL-D returns, the caller exits cleanly on it and that
    // path flushes the history
    if (gs_sigint_caught) {
        return NULL;
    }

    gs_at_prompt = 1;

#if defined(HAVE_READLINE)
    char *line = readline(s);
    gs_at_prompt = 0;
    if (gs_sigint_caught) {
        free(line);
        return NULL;
    }
    return line;
#elif defined(HAVE_LINENOISE)
    char *line = linenoise(s);
    gs_at_prompt = 0;
    if (gs_sigint_caught) {
        free(line);
        return NULL;
    }
    return line;
#else
    printf("%s", s);
    // MinGW/ProxSpace builds do not provide getline() in this fallback path.
    char input[1024] = {0};
    if (fgets(input, sizeof(input), stdin) == NULL) {
        gs_at_prompt = 0;
        return NULL;
    }

    gs_at_prompt = 0;
    if (gs_sigint_caught) {
        return NULL;
    }

    size_t len = strlen(input);
    while (len > 0 && (input[len - 1] == '\n' || input[len - 1] == '\r')) {
        input[--len] = '\0';
    }

    char *answer = calloc(len + 1, sizeof(char));
    if (answer == NULL) {
        return NULL;
    }

    memcpy(answer, input, len);
    return answer;
#endif
}

void pm3line_free(void *ref) {
    free(ref);
}

void pm3line_cleanup(void) {
    pm3line_vocabulary_free();
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
#elif defined(HAVE_LINENOISE)
    if (linenoiseHistoryLoad(path) == 0) {
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
        // keep the file in sync, so a crash or a kill -9 does not take the
        // history with it. append_history fails when the file is not there yet
        if (g_session.history_path) {
            if (append_history(1, g_session.history_path) != 0) {
                write_history(g_session.history_path);
            }
        }
    }
#elif defined(HAVE_LINENOISE)
    // linenoiseHistoryAdd takes already care of duplicate entries
    linenoiseHistoryAdd(line);
    if (g_session.history_path) {
        linenoiseHistorySave(g_session.history_path);
    }
#else
    (void) line;
#endif
}

void pm3line_flush_history(void) {
    if (g_session.history_path) {
#if defined(HAVE_READLINE)
        write_history(g_session.history_path);
#elif defined(HAVE_LINENOISE)
        linenoiseHistorySave(g_session.history_path);
#endif // HAVE_READLINE
        free(g_session.history_path);
        g_session.history_path = NULL;
    }
}

void pm3line_check(int (check)(void)) {
#if defined(HAVE_READLINE)
    gs_check_hook = check;
    rl_event_hook = pm3line_event_hook;
#else
    check();
#endif
}

// TODO:
// src/ui.c print_progress()
