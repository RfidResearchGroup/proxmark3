//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator - legal / authorized-use banner
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_BANNER_H__
#define EMV_TERM_BANNER_H__

#include "common.h"

void emv_term_banner_maybe_show(bool skip_for_mock);

#endif
