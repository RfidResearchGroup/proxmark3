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
// macOS framework bindings
//-----------------------------------------------------------------------------

#import "util_darwin.h"

#import <Foundation/NSString.h>
#import <Foundation/NSProcessInfo.h>
#import <AppKit/NSApplication.h>

static id activity = nil;

//OS X Version 10.10 is defined in OS X 10.10 and later
#if defined(MAC_OS_X_VERSION_10_10)
void disableAppNap(const char* reason) {
    if(activity == nil) {
        //NSLog(@"disableAppNap: %@", @(reason));
        activity = [[NSProcessInfo processInfo] beginActivityWithOptions:NSActivityBackground reason:@(reason)];
        [activity retain];
    }
}

void enableAppNap() {
    if(activity != nil) {
        //NSLog(@"enableAppNap");
        [[NSProcessInfo processInfo] endActivity:activity];
        [activity release];
        activity = nil;
    }
}

#else
void disableAppNap(const char* reason) { }
void enableAppNap() { }
#endif


//OS X Version 10.6 is defined in OS X 10.6 and later
#if defined(MAC_OS_X_VERSION_10_6)
void makeUnfocusable() {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited];
}
void makeFocusable() {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
}
#else
void makeUnfocusable() { }
void makeFocusable() { }
#endif