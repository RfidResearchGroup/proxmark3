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
// Line editor auto complete vocabulary, built at runtime from the live
// command tree so it can never drift from what "help" shows.
//-----------------------------------------------------------------------------

// this define is needed for scandir/alphasort to work
#define _GNU_SOURCE
#include "pm3line_vocabulary.h"
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "scandir.h"
#include "cmdmain.h"      // getTopLevelCommandTable
#include "fileutils.h"    // path_is_directory
#include "proxmark3.h"    // get_my_executable_directory, get_my_user_directory
#include "ui.h"           // PrintAndLogEx
#include "util.h"         // str_dup, str_endswith, g_printAndLog

#define VOCAB_INITIAL_CAPACITY  1024
#define VOCAB_MAX_PATH          1024

static vocabulary_t *s_vocab = NULL;
static size_t s_count = 0;
static size_t s_capacity = 0;
static bool s_built = false;

// Append an entry with the given name. Returns NULL if the name is already
// present or on allocation failure.
static vocabulary_t *vocab_add(const char *name) {

    for (size_t i = 0; i < s_count; i++) {
        if (strcmp(s_vocab[i].name, name) == 0) {
            return NULL;
        }
    }

    if (s_count == s_capacity) {
        size_t new_capacity = s_capacity ? s_capacity * 2 : VOCAB_INITIAL_CAPACITY;
        vocabulary_t *tmp = realloc(s_vocab, new_capacity * sizeof(vocabulary_t));
        if (tmp == NULL) {
            PrintAndLogEx(WARNING, "Failed to allocate memory for completion vocabulary");
            return NULL;
        }
        s_vocab = tmp;
        s_capacity = new_capacity;
    }

    vocabulary_t *entry = &s_vocab[s_count];
    memset(entry, 0, sizeof(*entry));
    entry->name = str_dup(name);
    if (entry->name == NULL) {
        return NULL;
    }
    s_count++;
    return entry;
}

// Visitor for walkCommandsRecursive(): one call per leaf command.
static void vocab_visit_command(const command_t *const path[], size_t depth, void *ctx) {
    (void) ctx;

    char name[MAX_PM3_INPUT_ARGS_LENGTH] = {0};
    size_t pos = 0;
    for (size_t i = 0; i < depth; i++) {
        int n = snprintf(name + pos, sizeof(name) - pos, "%s%s", i ? " " : "", path[i]->Name);
        if (n < 0 || (size_t)n >= sizeof(name) - pos) {
            return;
        }
        pos += (size_t)n;
    }

    vocabulary_t *entry = vocab_add(name);
    if (entry == NULL) {
        return;
    }

    entry->depth = (uint8_t)depth;
    for (size_t i = 0; i < depth; i++) {
        entry->is_available[i] = path[i]->IsAvailable;
    }
}

// Add "script run <file>" entries for every script with extension ext found
// under dir (recursively), inheriting the availability of "script run" itself.
// rel is the path of dir relative to the script directory ("" or e.g. "examples/"),
// which is what "script run" needs to find a script in a subdirectory.
static void vocab_add_scripts_dir(const char *dir, const char *rel, const char *ext, const vocabulary_t *script_run) {

    struct dirent **namelist;
    int n = scandir(dir, &namelist, NULL, alphasort);
    if (n < 0) {
        return;
    }

    for (int i = 0; i < n; i++) {

        const char *fname = namelist[i]->d_name;

        if (strcmp(fname, ".") == 0 || strcmp(fname, "..") == 0) {
            free(namelist[i]);
            continue;
        }

        char fullpath[VOCAB_MAX_PATH] = {0};
        int len = snprintf(fullpath, sizeof(fullpath), "%s%s", dir, fname);
        if (len < 0 || (size_t)len >= sizeof(fullpath) - 1) {
            free(namelist[i]);
            continue;
        }

        if (path_is_directory(fullpath)) {
            fullpath[len] = PATHSEP[0];
            fullpath[len + 1] = '\0';

            char subrel[VOCAB_MAX_PATH] = {0};
            len = snprintf(subrel, sizeof(subrel), "%s%s%s", rel, fname, PATHSEP);
            if (len > 0 && (size_t)len < sizeof(subrel)) {
                vocab_add_scripts_dir(fullpath, subrel, ext, script_run);
            }
            free(namelist[i]);
            continue;
        }

        if (str_endswith(fname, ext)) {
            char name[MAX_PM3_INPUT_ARGS_LENGTH] = {0};
            len = snprintf(name, sizeof(name), "%s %s%s", script_run->name, rel, fname);
            if (len > 0 && (size_t)len < sizeof(name)) {
                vocabulary_t *entry = vocab_add(name);
                if (entry != NULL) {
                    entry->depth = script_run->depth;
                    memcpy(entry->is_available, script_run->is_available, sizeof(entry->is_available));
                }
            }
        }
        free(namelist[i]);
    }
    free(namelist);
}

// Same search order as searchAndList() / "script list":
// dev tree next to the executable, user directory, installed share directory.
static void vocab_add_scripts(const char *pm3dir, const char *ext, const vocabulary_t *script_run) {

    const char *exec_path = get_my_executable_directory();
    const char *user_path = get_my_user_directory();

    if (exec_path != NULL) {
        char path[VOCAB_MAX_PATH] = {0};
        int n = snprintf(path, sizeof(path), "%s%s", exec_path, pm3dir);
        if (n > 0 && (size_t)n < sizeof(path)) {
            vocab_add_scripts_dir(path, "", ext, script_run);
        }
    }

    if (user_path != NULL) {
        char path[VOCAB_MAX_PATH] = {0};
        int n = snprintf(path, sizeof(path), "%s%s%s", user_path, PM3_USER_DIRECTORY, pm3dir);
        if (n > 0 && (size_t)n < sizeof(path)) {
            vocab_add_scripts_dir(path, "", ext, script_run);
        }
    }

    if (exec_path != NULL) {
        char path[VOCAB_MAX_PATH] = {0};
        int n = snprintf(path, sizeof(path), "%s%s%s", exec_path, PM3_SHARE_RELPATH, pm3dir);
        if (n > 0 && (size_t)n < sizeof(path)) {
            vocab_add_scripts_dir(path, "", ext, script_run);
        }
    }
}

void pm3line_vocabulary_build(void) {

    pm3line_vocabulary_free();

    // The walk goes through the Parse() of every category. Keep it silent:
    // a few commands shown like categories (e.g. "reveng") run their own
    // parser on the walk token and would complain about it.
    uint8_t old_printAndLog = g_printAndLog;
    g_printAndLog = 0;
    walkCommandsRecursive(getTopLevelCommandTable(), vocab_visit_command, NULL);
    g_printAndLog = old_printAndLog;

    // Script files complete as "script run <file>", with the availability of "script run".
    // Take a copy: vocab_add() may realloc the array while scripts are being added.
    vocabulary_t script_run = {0};
    for (size_t i = 0; i < s_count; i++) {
        if (strcmp(s_vocab[i].name, "script run") == 0) {
            script_run = s_vocab[i];
            break;
        }
    }

    if (script_run.name != NULL) {
        vocab_add_scripts(LUA_SCRIPTS_SUBDIR, ".lua", &script_run);
        vocab_add_scripts(CMD_SCRIPTS_SUBDIR, ".cmd", &script_run);
#ifdef HAVE_PYTHON
        vocab_add_scripts(PYTHON_SCRIPTS_SUBDIR, ".py", &script_run);
#endif
    }

    s_built = true;
}

void pm3line_vocabulary_free(void) {
    for (size_t i = 0; i < s_count; i++) {
        free(s_vocab[i].name);
    }
    free(s_vocab);
    s_vocab = NULL;
    s_count = 0;
    s_capacity = 0;
    s_built = false;
}

const vocabulary_t *pm3line_vocabulary_get(size_t *count) {
    if (s_built == false) {
        pm3line_vocabulary_build();
    }
    if (count != NULL) {
        *count = s_count;
    }
    return s_vocab;
}

bool pm3line_vocabulary_is_available(const vocabulary_t *entry) {
    if (entry == NULL) {
        return false;
    }
    for (uint8_t i = 0; i < entry->depth; i++) {
        if (entry->is_available[i] != NULL && entry->is_available[i]() == false) {
            return false;
        }
    }
    return true;
}
