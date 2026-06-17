//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "terminal_exception_test.h"
#include "../terminal/emv_term_exception.h"
#include "ui.h"
#include "fileutils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int write_temp_exception(const char *content, char *path, size_t path_len) {
    snprintf(path, path_len, "/tmp/emv_exc_test_%d.txt", (int)getpid());
    FILE *f = fopen(path, "w");
    if (!f) {
        return PM3_ESOFT;
    }
    fputs(content, f);
    fclose(f);
    return PM3_SUCCESS;
}

static int test_exception_pan_hit(bool verbose) {
    char path[256] = {0};
    if (write_temp_exception("pan:4111111111111111\n", path, sizeof(path))) {
        return 1;
    }

    emv_term_exception_file_t *ef = emv_term_exception_load(path);
    if (!ef) {
        if (verbose) {
            PrintAndLogEx(ERR, "exception load failed");
        }
        remove(path);
        return 1;
    }

    uint8_t pan[] = {0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    if (!emv_term_exception_pan_match(ef, pan, sizeof(pan))) {
        if (verbose) {
            PrintAndLogEx(ERR, "PAN should match exception file");
        }
        emv_term_exception_free(ef);
        remove(path);
        return 1;
    }

    uint8_t other[] = {0x42, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    if (emv_term_exception_pan_match(ef, other, sizeof(other))) {
        if (verbose) {
            PrintAndLogEx(ERR, "unlisted PAN should not match");
        }
        emv_term_exception_free(ef);
        remove(path);
        return 1;
    }

    emv_term_exception_free(ef);
    remove(path);
    if (verbose) {
        PrintAndLogEx(SUCCESS, "exception PAN hit/miss OK");
    }
    return 0;
}

static int test_exception_bad_line(bool verbose) {
    char path[256] = {0};
    if (write_temp_exception("# comment\nnot-a-valid-line\npan:4111111111111111\n", path, sizeof(path))) {
        return 1;
    }

    emv_term_exception_file_t *ef = emv_term_exception_load(path);
    if (!ef) {
        if (verbose) {
            PrintAndLogEx(ERR, "bad line should be skipped, one valid entry expected");
        }
        remove(path);
        return 1;
    }

    uint8_t pan[] = {0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    if (!emv_term_exception_pan_match(ef, pan, sizeof(pan))) {
        if (verbose) {
            PrintAndLogEx(ERR, "valid pan line should survive bad line");
        }
        emv_term_exception_free(ef);
        remove(path);
        return 1;
    }

    emv_term_exception_free(ef);
    remove(path);
    if (verbose) {
        PrintAndLogEx(SUCCESS, "exception bad line skip OK");
    }
    return 0;
}

int exec_terminal_exception_test(bool verbose) {
    if (test_exception_pan_hit(verbose)) {
        return 1;
    }
    if (test_exception_bad_line(verbose)) {
        return 1;
    }
    return 0;
}
