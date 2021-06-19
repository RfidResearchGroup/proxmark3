//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// NFC commands
//-----------------------------------------------------------------------------

#ifndef CMDNFC_H__
#define CMDNFC_H__

#include "common.h"

int CmdNFC(const char *Cmd);
void print_type4_cc_info(uint8_t *d, uint8_t n);

#endif
