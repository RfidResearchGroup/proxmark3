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
#include <unistd.h>

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

    char *got = getpass(prompt);
    if (!got) {
        PrintAndLogEx(ERR, "PIN prompt failed");
        return PM3_EIO;
    }

    if (!valid_pin_digits(got)) {
        emv_term_secure_zero(got, strlen(got));
        PrintAndLogEx(ERR, "PIN must be 4-12 decimal digits");
        return PM3_EINVARG;
    }

    str_copy(pin_buf, pin_buf_len, got);
    emv_term_secure_zero(got, strlen(got));
    return PM3_SUCCESS;
}
