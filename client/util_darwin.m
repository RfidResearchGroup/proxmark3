//-----------------------------------------------------------------------------
// (c) 2018 AntiCat
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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