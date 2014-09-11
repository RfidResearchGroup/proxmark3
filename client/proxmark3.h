//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Main binary
//-----------------------------------------------------------------------------

#ifndef PROXMARK3_H__
#define PROXMARK3_H__

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#define llx PRIx64
#define lli PRIi64
#define hhu PRIu8

#include "usb_cmd.h"

#define PROXPROMPT "pm3 --> "

void SendCommand(UsbCommand *c);

#endif
