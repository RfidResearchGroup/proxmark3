//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_EXCEPTION_H__
#define EMV_TERM_EXCEPTION_H__

#include "common.h"
#include <stddef.h>

typedef struct emv_term_exception_file emv_term_exception_file_t;

emv_term_exception_file_t *emv_term_exception_load(const char *path);
void emv_term_exception_free(emv_term_exception_file_t *ef);

bool emv_term_exception_pan_match(const emv_term_exception_file_t *ef,
                                  const uint8_t *pan, size_t pan_len);

#endif
