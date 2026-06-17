//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_REDACT_H__
#define EMV_TERM_REDACT_H__

#include "common.h"
#include <jansson.h>

void emv_term_redact_session_json(json_t *root, bool full_export);

#endif
