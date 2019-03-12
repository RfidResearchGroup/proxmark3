//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Command line binary
//-----------------------------------------------------------------------------

#include <stdio.h>
#include "util_posix.h"
#include "ui.h"
//#include "proxusb.h"
#include "cmdmain.h"

#define HANDLE_ERROR if (error_occured) { \
        error_occured = 0;\
        break;\
    }

int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) {
        printf("\n\tusage: cli <command 1> <command 2> [logfile (default cli.log)]\n");
        printf("\n");
        printf("\texample: cli hf 14a sniff hf 14a list h14a.log\n");
        printf("\n");
        return -1;
    }

    usb_init();
    if (argc == 4)
        SetLogFilename(argv[3]);
    else
        SetLogFilename("cli.log");

    return_on_error = 1;

    while (1) {
        while (!OpenProxmark()) { sleep(1); }
        while (1) {
            UsbCommand cmdbuf;
            CommandReceived(argv[1]);
            HANDLE_ERROR;
            ReceiveCommand(&cmdbuf);
            HANDLE_ERROR;
            for (int i = 0; i < 5; ++i) {
                ReceiveCommandPoll(&cmdbuf);
            }
            HANDLE_ERROR;
            CommandReceived(argv[2]);
            HANDLE_ERROR;
        }
    }

    CloseProxmark();
    return 0;
}
