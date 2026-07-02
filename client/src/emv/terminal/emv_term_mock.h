//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_MOCK_H__
#define EMV_TERM_MOCK_H__

#include "common.h"
#include "iso7816/iso7816core.h"
#include <stdbool.h>

int emv_term_mock_load(const char *path);
void emv_term_mock_clear(void);
bool emv_term_mock_active(void);

int emv_term_mock_exchange(Iso7816CommandChannel channel, bool activate_field, bool leave_field_on,
                           sAPDU_t apdu, bool include_le, uint8_t *result, size_t max_result_len,
                           size_t *result_len, uint16_t *sw);

#endif
