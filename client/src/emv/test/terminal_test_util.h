//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Helpers for EMV terminal offline self-tests (portable temp paths)
//-----------------------------------------------------------------------------

#ifndef TERMINAL_TEST_UTIL_H
#define TERMINAL_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <process.h>
#define emv_term_test_pid() _getpid()
#else
#include <unistd.h>
#define emv_term_test_pid() getpid()
#endif

static inline void emv_term_test_temp_path(char *path, size_t path_len, const char *basename) {
    if (!path || path_len == 0) {
        return;
    }
    path[0] = '\0';
    if (!basename || !basename[0]) {
        return;
    }

#if defined(_WIN32)
    const char *dir = getenv("TEMP");
    if (!dir || !dir[0]) {
        dir = getenv("TMP");
    }
    if (!dir || !dir[0]) {
        dir = ".";
    }
    snprintf(path, path_len, "%s/emv_%s_%d", dir, basename, (int)emv_term_test_pid());
#else
    snprintf(path, path_len, "/tmp/emv_%s_%d", basename, (int)emv_term_test_pid());
#endif
}

#endif
