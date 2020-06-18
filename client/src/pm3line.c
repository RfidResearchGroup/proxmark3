// Copyright (C) 2020 Doegox
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------

#include "pm3line.h"
#include <stdlib.h>
#include <stdio.h> // for Mingw readline and for getline
#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#elif HAVE_LINENOISE
#include "linenoise.h"
#endif
#include "pm3_cmd.h"

void pm3line_init(void) {
#ifdef HAVE_READLINE
    /* initialize history */
    using_history();

#ifdef RL_STATE_READCMD
    rl_extend_line_buffer(1024);
#endif // RL_STATE_READCMD
#elif HAVE_LINENOISE
    linenoiseInstallWindowChangeHandler();
#endif // HAVE_READLINE
}

char *pm3line_read(const char *s) {
#ifdef HAVE_READLINE
    return readline(s);
#elif HAVE_LINENOISE
    return linenoise(s);
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
#ifdef HAVE_READLINE
    rl_set_prompt(prompt);
    rl_forced_update_display();
#else
    (void) prompt;
#endif
}

int pm3line_load_history(const char *path) {
#ifdef HAVE_READLINE
    if (read_history(path) == 0) {
        return PM3_SUCCESS;
    } else {
        return PM3_ESOFT;
    }
#elif HAVE_LINENOISE
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
#ifdef HAVE_READLINE
    HIST_ENTRY *entry = history_get(history_length);
    // add if not identical to latest recorded line
    if ((!entry) || (strcmp(entry->line, line) != 0)) {
        add_history(line);
    }
#elif HAVE_LINENOISE
    // linenoiseHistoryAdd takes already care of duplicate entries
    linenoiseHistoryAdd(line);
#else
    (void) line;
#endif
}

int pm3line_save_history(const char *path) {
#ifdef HAVE_READLINE
    if (write_history(path) == 0) {
        return PM3_SUCCESS;
    } else {
        return PM3_ESOFT;
    }
#elif HAVE_LINENOISE
    if (linenoiseHistorySave(path) == 0) {
        return PM3_SUCCESS;
    } else {
        return PM3_ESOFT;
    }
#else
    (void) path;
    return PM3_ENOTIMPL;
#endif
}

void pm3line_check(int (check)(void)) {
#ifdef HAVE_READLINE
    rl_event_hook = check;
#else
    check();
#endif
}
