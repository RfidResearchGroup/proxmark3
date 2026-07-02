//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_READER_SESSION_H__
#define EMV_TERM_READER_SESSION_H__

int emv_term_reader_session_log(const char *path, const char *aid_hex, const char *note);
void emv_term_reader_compare_hint(void);

#endif
