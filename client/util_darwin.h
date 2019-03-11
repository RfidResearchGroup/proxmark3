//-----------------------------------------------------------------------------
// (c) 2018 AntiCat
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// macOS framework bindings
//-----------------------------------------------------------------------------

#ifndef UTIL_DARWIN_H__
#define UTIL_DARWIN_H__

void disableAppNap(const char *reason);
void enableAppNap();
void makeUnfocusable();
void makeFocusable();

#endif
