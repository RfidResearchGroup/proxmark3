//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_PIN_PROMPT_H__
#define EMV_TERM_PIN_PROMPT_H__

#include "common.h"

// Returns PM3_SUCCESS and sets *pin_out (caller must emv_term_secure_zero after use).
// pin_buf must hold at least 13 bytes.
int emv_term_pin_prompt(const char *label, char *pin_buf, size_t pin_buf_len);

bool emv_term_pin_tty_available(void);

#endif
