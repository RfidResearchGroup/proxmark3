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

#define Dbprintf_usb(...) {\
        bool tmpfpc = reply_via_fpc;\
        bool tmpusb = reply_via_usb;\
        reply_via_fpc = false;\
        reply_via_usb = true;\
        Dbprintf(__VA_ARGS__);\
        reply_via_fpc = tmpfpc;\
        reply_via_usb = tmpusb;}

#define Dbprintf_fpc(...) {\
        bool tmpfpc = reply_via_fpc;\
        bool tmpusb = reply_via_usb;\
        reply_via_fpc = true;\
        reply_via_usb = false;\
        Dbprintf(__VA_ARGS__);\
        reply_via_fpc = tmpfpc;\
        reply_via_usb = tmpusb;}

#define Dbprintf_all(...) {\
        bool tmpfpc = reply_via_fpc;\
        bool tmpusb = reply_via_usb;\
        reply_via_fpc = true;\
        reply_via_usb = true;\
        Dbprintf(__VA_ARGS__);\
        reply_via_fpc = tmpfpc;\
        reply_via_usb = tmpusb;}


void DbpString(char *str);
void DbpStringEx(uint32_t flags, char *src, size_t srclen);
void Dbprintf(const char *fmt, ...);
void DbprintfEx(uint32_t flags, const char *fmt, ...);
void Dbhexdump(int len, uint8_t *d, bool bAsci);
void print_result(char *name, uint8_t *buf, size_t len);
//void PrintToSendBuffer(void);

#endif
