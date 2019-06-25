//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Flasher frontend tool
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include <unistd.h>
#include "util_posix.h"
#include "proxmark3.h"
#include "util.h"
#include "flash.h"
#include "comms.h"
#include "pm3_cmd.h"
#include "ui.h"

#define MAX_FILES 4

static void usage(char *argv0) {
    PrintAndLogEx(NORMAL, "Usage:   %s <port> [-b] image.elf [image.elf...]\n", argv0);
    PrintAndLogEx(NORMAL, "\t-b\tEnable flashing of bootloader area (DANGEROUS)\n");
    PrintAndLogEx(NORMAL, "\nExample:\n\n\t %s "SERIAL_PORT_EXAMPLE_H" armsrc/obj/fullimage.elf", argv0);
#ifdef __linux__
    PrintAndLogEx(NORMAL, "\nNote (Linux): if the flasher gets stuck in 'Waiting for Proxmark3 to reappear on <DEVICE>',");
    PrintAndLogEx(NORMAL, "              you need to blacklist Proxmark3 for modem-manager - see wiki for more details:\n");
    PrintAndLogEx(NORMAL, "              https://github.com/Proxmark/proxmark3/wiki/Gentoo Linux\n");
    PrintAndLogEx(NORMAL, "              https://github.com/Proxmark/proxmark3/wiki/Ubuntu Linux\n");
    PrintAndLogEx(NORMAL, "              https://github.com/Proxmark/proxmark3/wiki/OSX\n");
#endif
}

int main(int argc, char **argv) {
    int can_write_bl = 0;
    int num_files = 0;
    int res;
    flash_file_t files[MAX_FILES];

    memset(files, 0, sizeof(files));

    session.supports_colors = false;
    session.stdinOnTTY = isatty(STDIN_FILENO);
    session.stdoutOnTTY = isatty(STDOUT_FILENO);
#if defined(__linux__) || (__APPLE__)
    if (session.stdinOnTTY && session.stdoutOnTTY)
        session.supports_colors = true;
#endif
    session.help_dump_mode = false;

    if (argc < 3) {
        usage(argv[0]);
        return -1;
    }

    for (int i = 2; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (!strcmp(argv[i], "-b")) {
                can_write_bl = 1;
            } else {
                usage(argv[0]);
                return -1;
            }
        } else {
            res = flash_load(&files[num_files], argv[i], can_write_bl);
            if (res < 0)
                return -1;

            PrintAndLogEx(NORMAL, "");
            num_files++;
        }
    }

    char *serial_port_name = argv[1];

    if (OpenProxmark(serial_port_name, true, 60, true, FLASHMODE_SPEED)) {
        PrintAndLogEx(NORMAL, _GREEN_("Found"));
    } else {
        PrintAndLogEx(ERR, "Could not find Proxmark3 on " _RED_("%s") ".\n", serial_port_name);
        return -1;
    }

    res = flash_start_flashing(can_write_bl, serial_port_name);
    if (res < 0)
        return -1;

    PrintAndLogEx(SUCCESS, "\n" _BLUE_("Flashing..."));

    for (int i = 0; i < num_files; i++) {
        res = flash_write(&files[i]);
        if (res < 0)
            return -1;
        flash_free(&files[i]);
        PrintAndLogEx(NORMAL, "\n");
    }

    res = flash_stop_flashing();
    if (res < 0)
        return -1;

    CloseProxmark();

    PrintAndLogEx(SUCCESS, _BLUE_("All done."));
    PrintAndLogEx(SUCCESS, "\nHave a nice day!");
    return 0;
}
