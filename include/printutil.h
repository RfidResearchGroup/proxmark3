//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Print Bridge and Utilities
//-----------------------------------------------------------------------------
// This header provides a standardized set of macros to use in common code
// to redirect the logging to the right places, depending on where it's being
// ran from.
//
// This will also include various utilities for such things
//-----------------------------------------------------------------------------

#ifndef PRINTUTIL_H__
#define PRINTUTIL_H__

#include "common.h"
#include "ansi.h"

#ifdef ON_DEVICE
    // Device side includes
    #include "dbprint.h"
#else
    // Client side includes
    #include "ui.h"
    #include "util.h"
    #include "cmddata.h"
#endif

// Macro defines
#ifdef ON_DEVICE // Device side

#define print_trace(...)           { if(g_dbglevel >= 1) Dbprintf(__VA_ARGS__); }
#define print_debug(...)           { if(g_dbglevel >= 3) Dbprintf(__VA_ARGS__); }
#define print_critical(...)        { if(g_dbglevel >= 4) Dbprintf(__VA_ARGS__); }
#define print_error(...)           { if(g_dbglevel >= 1) Dbprintf(__VA_ARGS__); }
#define print_warning(...)         { if(g_dbglevel >= 2) Dbprintf(__VA_ARGS__); }
#define print_info(...)            { if(g_dbglevel >= 2) Dbprintf(__VA_ARGS__); }
#define force_print(force, ...)    { if(force || g_dbglevel >= 2) Dbprintf(__VA_ARGS__); }
#else // Client side

#define print_trace(...)        PrintAndLogEx(HINT, __VA_ARGS__)
#define print_debug(...)        PrintAndLogEx(DEBUG, __VA_ARGS__)
#define print_critical(...)     PrintAndLogEx(FAILED, __VA_ARGS__)
#define print_error(...)        PrintAndLogEx(ERR, __VA_ARGS__)
#define print_warning(...)      PrintAndLogEx(WARNING, __VA_ARGS__)
#define print_info(...)         PrintAndLogEx(INFO, __VA_ARGS__)
#define force_print(force, ...) PrintAndLogEx((force ? WARNING : INFO), format, args);
#endif

#endif // PRINT_UTIL_H__