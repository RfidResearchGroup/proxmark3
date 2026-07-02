//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_pin_prompt.h"
#include "emv_term_secure.h"
#include "ui.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <conio.h>
#include <io.h>
#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#else
#include <unistd.h>
#endif

bool emv_term_pin_tty_available(void) {
    return isatty(STDIN_FILENO) != 0;
}

static bool valid_pin_digits(const char *pin) {
    if (!pin) {
        return false;
    }
    size_t n = strlen(pin);
    if (n < 4 || n > 12) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (!isdigit((unsigned char)pin[i])) {
            return false;
        }
    }
    return true;
}

#if defined(_WIN32)
static int read_pin_tty(const char *prompt, char *pin_buf, size_t pin_buf_len) {
    fputs(prompt, stderr);
    fflush(stderr);
    size_t n = 0;
    while (n + 1 < pin_buf_len) {
        int c = _getch();
        if (c == '\r' || c == '\n') {
            pin_buf[n] = '\0';
            fputc('\n', stderr);
            return PM3_SUCCESS;
        }
        if (c == '\b' || c == 127) {
            if (n > 0) {
                n--;
            }
            continue;
        }
        if (!isdigit((unsigned char)c)) {
            continue;
        }
        pin_buf[n++] = (char)c;
    }
    pin_buf[pin_buf_len - 1] = '\0';
    return PM3_SUCCESS;
}
#else
static int read_pin_tty(const char *prompt, char *pin_buf, size_t pin_buf_len) {
    char *got = getpass(prompt);
    if (!got) {
        return PM3_EIO;
    }
    str_copy(pin_buf, pin_buf_len, got);
    emv_term_secure_zero(got, strlen(got));
    return PM3_SUCCESS;
}
#endif

int emv_term_pin_prompt(const char *label, char *pin_buf, size_t pin_buf_len) {
    if (!pin_buf || pin_buf_len < 13) {
        return PM3_EINVARG;
    }
    pin_buf[0] = '\0';

    const char *prompt = label ? label : "Enter PIN: ";
    if (!emv_term_pin_tty_available()) {
        PrintAndLogEx(ERR, "Non-interactive terminal - use --pin or EMV_TEST_PIN");
        return PM3_EIO;
    }

    int res = read_pin_tty(prompt, pin_buf, pin_buf_len);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "PIN prompt failed");
        return res;
    }

    if (!valid_pin_digits(pin_buf)) {
        emv_term_secure_zero(pin_buf, strlen(pin_buf));
        PrintAndLogEx(ERR, "PIN must be 4-12 decimal digits");
        return PM3_EINVARG;
    }

    return PM3_SUCCESS;
}
