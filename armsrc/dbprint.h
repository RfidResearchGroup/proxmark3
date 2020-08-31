//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions internal to the app source.
//-----------------------------------------------------------------------------
#ifndef __DBPRINT_H
#define __DBPRINT_H

#include "common.h"
#include "ansi.h"

#define NOLF "\xff"

#define Dbprintf_usb(...) {\
        bool tmpfpc = g_reply_via_fpc;\
        bool tmpusb = g_reply_via_usb;\
        g_reply_via_fpc = false;\
        g_reply_via_usb = true;\
        Dbprintf(__VA_ARGS__);\
        g_reply_via_fpc = tmpfpc;\
        g_reply_via_usb = tmpusb;}

#define Dbprintf_fpc(...) {\
        bool tmpfpc = g_reply_via_fpc;\
        bool tmpusb = g_reply_via_usb;\
        g_reply_via_fpc = true;\
        g_reply_via_usb = false;\
        Dbprintf(__VA_ARGS__);\
        g_reply_via_fpc = tmpfpc;\
        g_reply_via_usb = tmpusb;}

#define Dbprintf_all(...) {\
        bool tmpfpc = g_reply_via_fpc;\
        bool tmpusb = g_reply_via_usb;\
        g_reply_via_fpc = true;\
        g_reply_via_usb = true;\
        Dbprintf(__VA_ARGS__);\
        g_reply_via_fpc = tmpfpc;\
        g_reply_via_usb = tmpusb;}


void DbpString(const char *str);
void DbpStringEx(uint32_t flags, const char *src, size_t srclen);
void Dbprintf(const char *fmt, ...);
void DbprintfEx(uint32_t flags, const char *fmt, ...);
void Dbhexdump(int len, uint8_t *d, bool bAsci);
void print_result(const char *name, uint8_t *buf, size_t len);
//void PrintToSendBuffer(void);

// Functions for umm_malloc
// Alternatively, use https://github.com/rhempel/c-helper-macros/blob/develop/dbglog/dbglog.h

#define DBGLOGS_FORCE(force, format) {\
    if (force) Dbprintf (format NOLF); \
    }

#define DBGLOG_FORCE(force, format, ...) {\
    if (force) Dbprintf (format NOLF, __VA_ARGS__); \
    }

#define DBGLOGS_ERROR(format) {\
    if (DBGLEVEL >= DBG_ERROR) Dbprintf (format NOLF); \
    }

#define DBGLOG_ERROR(format, ...) {\
    if (DBGLEVEL >= DBG_ERROR) Dbprintf (format NOLF, __VA_ARGS__); \
    }

#define DBGLOGS_CRITICAL(format) {\
    if (DBGLEVEL >= DBG_ERROR) Dbprintf (format NOLF); \
    }

#define DBGLOG_CRITICAL(format, ...) {\
    if (DBGLEVEL >= DBG_ERROR) Dbprintf (format NOLF, __VA_ARGS__); \
    }

#define DBGLOGS_DEBUG(format) {\
    if (DBGLEVEL >= DBG_DEBUG) Dbprintf (format NOLF); \
    }

#define DBGLOG_DEBUG(format, ...) {\
    if (DBGLEVEL >= DBG_DEBUG) Dbprintf (format NOLF, __VA_ARGS__); \
    }

#define DBGLOGS_TRACE(format) {\
    if (DBGLEVEL >= DBG_EXTENDED) Dbprintf (format NOLF); \
    }

#define DBGLOG_TRACE(format, ...) {\
    if (DBGLEVEL >= DBG_EXTENDED) Dbprintf (format NOLF, __VA_ARGS__); \
    }

#define DBGLOG_32_BIT_PTR(ptr) (ptr)
#endif
