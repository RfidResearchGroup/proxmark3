//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Sniff binary
//-----------------------------------------------------------------------------

#include "util_posix.h"
#include "ui.h"
#include "cmdmain.h"

#define HANDLE_ERROR if (error_occured) { \
        error_occured = 0;\
        break;\
    }

int main() {
    usb_init();
    SetLogFilename("sniffer.log");

    return_on_error = 1;

    while (1) {
        while (!OpenProxmark()) { sleep(1); }
        while (1) {
            UsbCommand cmdbuf;
            CommandReceived("hf 14a sniff");
            HANDLE_ERROR;
            ReceiveCommand(&cmdbuf);
            HANDLE_ERROR;
            for (int i = 0; i < 5; ++i) {
                ReceiveCommandPoll(&cmdbuf);
            }
            HANDLE_ERROR;
            CommandReceived("hf list 14a");
            HANDLE_ERROR;
        }
    }

    CloseProxmark();
    return 0;
}
