//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_PROFILE_H__
#define EMV_TERM_PROFILE_H__

#include "common.h"
#include "../emvcore.h"
#include "../tlv.h"

bool emv_term_profile_load(struct tlvdb *terminal, const char *profile_path);
int emv_term_profile_validate(const char *profile_path);
int emv_term_profile_print(const char *profile_path);

void emv_term_param_defaults(struct tlvdb *tlvRoot);
void emv_term_init_transaction_params(struct tlvdb *tlvRoot, bool paramLoadJSON, const char *profile_path,
                                      TransactionType_t TrType, bool GenACGPO);

#endif
