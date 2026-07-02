//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_SCHEME_H__
#define EMV_TERM_SCHEME_H__

#include "emv_term_ctx.h"

typedef struct {
    char name[32];
    char profile_path[FILE_PATH_SIZE];
    char host_keys_path[FILE_PATH_SIZE];
    bool flash_skip_offline_pin;
} emv_term_scheme_info_t;

int emv_term_scheme_resolve(const char *profile_arg, const uint8_t *aid, size_t aid_len,
                            emv_term_scheme_info_t *info);

int emv_term_scheme_apply(emv_term_ctx_t *ctx, const emv_term_scheme_info_t *info);

const char *emv_term_scheme_name_for_aid(const uint8_t *aid, size_t aid_len);

#endif
