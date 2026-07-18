//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_GOLDEN_H__
#define EMV_TERM_GOLDEN_H__

#include "common.h"

int emv_term_golden_run(const char *fixture_name, bool verbose);
int emv_term_golden_run_all(bool verbose);

#endif
