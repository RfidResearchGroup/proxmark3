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

// Handle platform specific includes
#ifdef _WIN32
// for MINGW32 environments
  #ifndef _USE_32BIT_TIME_T
    #define _USE_32BIT_TIME_T 1
  #endif  
  #include <time.h>
  #include <windows.h>
#else
  #include <sys/time.h>
#endif

#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include "usb_cmd.h"

#define lu PRIu32
#define lx  PRIx32
#define llx PRIx64
#define lli PRIi64
#define llu PRIu64
#define hhu PRIu8
#define PROXPROMPT "pm3 --> "

void SendCommand(UsbCommand *c);

#endif
