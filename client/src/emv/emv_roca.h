//-----------------------------------------------------------------------------
// Borrowed initially from https://gist.github.com/robstradling/f525d423c79690b72e650e2ad38a161d
// Copyright (C) 2017-2018 Rob Stradling
// Copyright (C) 2017-2018 Sectigo Limited
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
// roca.c - ROCA (CVE-2017-15361) fingerprint checker.
//-----------------------------------------------------------------------------

#ifndef EMV_ROCA_H__
#define EMV_ROCA_H__

#include <stdbool.h>
#include <stddef.h>

#include "common.h"

#define ROCA_PRINTS_LENGTH 17

typedef enum {
    EMV_ROCA_ERROR = -1,
    EMV_ROCA_NOT_FOUND = 0,
    EMV_ROCA_FOUND = 1,
} emv_roca_result_t;

emv_roca_result_t emv_rocacheck_ex(const unsigned char *buf, size_t buflen, bool verbose);
bool emv_rocacheck(const unsigned char *buf, size_t buflen, bool verbose);
bool emv_rsa_has_small_factor(const unsigned char *buf, size_t buflen);
bool emv_rsa_has_shared_factor(const unsigned char *a, size_t alen,
                               const unsigned char *b, size_t blen);
int roca_self_test(void);

#endif
