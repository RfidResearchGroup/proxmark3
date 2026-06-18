//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_exception.h"
#include "crypto/libpcrypto.h"
#include "ui.h"
#include "util.h"
#include "commonutil.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EMV_EXCEPTION_MAX 4096

struct emv_term_exception_file {
    uint8_t hashes[EMV_EXCEPTION_MAX][32];
    size_t count;
    char path[FILE_PATH_SIZE];
};

static bool parse_pan_digits(const char *s, uint8_t *pan, size_t *pan_len, size_t max_len) {
    size_t n = 0;
    while (s[n] && n < max_len * 2) {
        if (!isdigit((unsigned char)s[n])) {
            return false;
        }
        n++;
    }
    if (n < 12 || n > 19) {
        return false;
    }
    *pan_len = 0;
    for (size_t i = 0; i < n; i += 2) {
        uint8_t hi = (uint8_t)(s[i] - '0');
        uint8_t lo = (i + 1 < n) ? (uint8_t)(s[i + 1] - '0') : 0x0F;
        pan[(*pan_len)++] = (hi << 4) | lo;
    }
    return true;
}

static bool line_to_hash(const char *line, uint8_t hash[32]) {
    while (*line == ' ' || *line == '\t') {
        line++;
    }
    if (!line[0] || line[0] == '#') {
        return false;
    }

    const char *hex = line;
    if (strncmp(line, "panhash:", 8) == 0) {
        hex = line + 8;
    } else if (strncmp(line, "pan:", 4) == 0) {
        uint8_t pan[16] = {0};
        size_t pan_len = 0;
        if (!parse_pan_digits(line + 4, pan, &pan_len, sizeof(pan))) {
            return false;
        }
        sha256hash(pan, (int)pan_len, hash);
        return true;
    }

    if (strlen(hex) != 64) {
        return false;
    }
    int buflen = 0;
    if (param_gethex_to_eol(hex, 0, hash, 32, &buflen) || buflen != 32) {
        return false;
    }
    return true;
}

emv_term_exception_file_t *emv_term_exception_load(const char *path) {
    if (!path || !path[0]) {
        return NULL;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        PrintAndLogEx(ERR, "Cannot open exception file: %s", path);
        return NULL;
    }

    emv_term_exception_file_t *ef = calloc(1, sizeof(*ef));
    if (!ef) {
        fclose(f);
        return NULL;
    }
    str_copy(ef->path, sizeof(ef->path), path);

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) {
            *nl = '\0';
        }
        uint8_t hash[32] = {0};
        if (!line_to_hash(line, hash)) {
            if (line[0] && line[0] != '#') {
                PrintAndLogEx(WARNING, "Exception file: skip bad line: %s", line);
            }
            continue;
        }
        if (ef->count >= EMV_EXCEPTION_MAX) {
            PrintAndLogEx(WARNING, "Exception file full - truncating at %zu entries", ef->count);
            break;
        }
        memcpy(ef->hashes[ef->count++], hash, 32);
    }
    fclose(f);

    PrintAndLogEx(INFO, "Exception file loaded: %zu entries from %s", ef->count, path);
    return ef;
}

void emv_term_exception_free(emv_term_exception_file_t *ef) {
    free(ef);
}

bool emv_term_exception_pan_match(const emv_term_exception_file_t *ef,
                                  const uint8_t *pan, size_t pan_len) {
    if (!ef || !ef->count || !pan || !pan_len) {
        return false;
    }

    uint8_t hash[32] = {0};
    sha256hash((uint8_t *)pan, (int)pan_len, hash);

    for (size_t i = 0; i < ef->count; i++) {
        if (memcmp(hash, ef->hashes[i], 32) == 0) {
            return true;
        }
    }
    return false;
}
