//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_banner.h"
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define EMV_TERM_ACK_FILENAME "emv_terminal_ack"

static bool ack_env_set(void) {
    const char *env = getenv("EMV_TERMINAL_I_ACK");
    return env && env[0] && strcmp(env, "0") != 0;
}

static bool ack_file_exists(const char *ud) {
    if (!ud || !ud[0]) {
        return false;
    }
    char path[FILE_PATH_SIZE];
    snprintf(path, sizeof(path), "%s/%s", ud, EMV_TERM_ACK_FILENAME);
    FILE *f = fopen(path, "r");
    if (!f) {
        return false;
    }
    fclose(f);
    return true;
}

static void write_ack_file(const char *ud) {
    if (!ud || !ud[0]) {
        return;
    }
    char path[FILE_PATH_SIZE];
    snprintf(path, sizeof(path), "%s/%s", ud, EMV_TERM_ACK_FILENAME);
    FILE *f = fopen(path, "w");
    if (!f) {
        return;
    }
    time_t now = time(NULL);
    fprintf(f, "ack_ts=%lld\n", (long long)now);
    fclose(f);
}

void emv_term_banner_maybe_show(bool skip_for_mock) {
    if (skip_for_mock || ack_env_set()) {
        return;
    }

    const char *ud = get_my_user_directory();
    if (ack_file_exists(ud)) {
        return;
    }

    PrintAndLogEx(WARNING, "[!] EMV terminal emulator — authorized test cards and lab use only.");
    PrintAndLogEx(WARNING, "    See docs/emv-terminal-emulator/SPEC-security-privacy.md");
    write_ack_file(ud);
}
