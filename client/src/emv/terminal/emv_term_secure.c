//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_secure.h"
#include <string.h>

void emv_term_secure_zero(void *buf, size_t len) {
    if (!buf || !len) {
        return;
    }
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) {
        *p++ = 0;
    }
}
