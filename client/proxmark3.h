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

#define PROXPROMPT "pm3 --> "
#ifdef __cplusplus
extern "C" {
#endif

void SendCommand(UsbCommand *c);
const char *get_my_executable_path(void);
const char *get_my_executable_directory(void);

#ifdef __cplusplus
}
#endif

#endif
