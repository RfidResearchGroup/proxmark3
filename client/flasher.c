//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Flasher frontend tool
//-----------------------------------------------------------------------------

#include <string.h>
#include <unistd.h>
#include "usart_defs.h"
#include "flash.h"
#include "comms.h"
#include "ui.h"

#define MAX_FILES 4
#define ONE_KB 1024

static void usage(char *argv0) {
    PrintAndLogEx(NORMAL, "Usage:   %s <port> [-b] image.elf [image.elf...]", argv0);
    PrintAndLogEx(NORMAL, "         %s <port> -i\n", argv0);
    PrintAndLogEx(NORMAL, "\t-b\tEnable flashing of bootloader area (DANGEROUS)");
    PrintAndLogEx(NORMAL, "\t-i\tProbe the connected Proxmark3 to retrieve its memory size");
    PrintAndLogEx(NORMAL, "\nExamples:\n\t %s "SERIAL_PORT_EXAMPLE_H" -i", argv0);
    PrintAndLogEx(NORMAL, "\t %s "SERIAL_PORT_EXAMPLE_H" armsrc/obj/fullimage.elf", argv0);
#ifdef __linux__
    PrintAndLogEx(NORMAL, "\nNote (Linux):\nif the flasher gets stuck in 'Waiting for Proxmark3 to reappear on <DEVICE>',");
    PrintAndLogEx(NORMAL, "you need to blacklist Proxmark3 for modem-manager - see documentation for more details:");
    PrintAndLogEx(NORMAL, "* https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/ModemManager-Must-Be-Discarded.md");
    PrintAndLogEx(NORMAL, "\nMore info on flashing procedure from the official Proxmark3 wiki:");
    PrintAndLogEx(NORMAL, "* https://github.com/Proxmark/proxmark3/wiki/Gentoo%%20Linux");
    PrintAndLogEx(NORMAL, "* https://github.com/Proxmark/proxmark3/wiki/Ubuntu%%20Linux");
    PrintAndLogEx(NORMAL, "* https://github.com/Proxmark/proxmark3/wiki/OSX\n");
#endif
}

int main(int argc, char **argv) {
    int can_write_bl = 0;
    int num_files = 0;
    int res;
    int ret = 0;
    flash_file_t files[MAX_FILES];
    char *filenames[MAX_FILES];
    bool info = false;
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
            } else if (!strcmp(argv[i], "-i")) {
                info = true;
            } else {
                usage(argv[0]);
                return -1;
            }
        } else {
            filenames[num_files] = argv[i];
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

    uint32_t max_allowed = 0;
    res = flash_start_flashing(can_write_bl, serial_port_name, &max_allowed);
    if (res < 0) {
        ret = -1;
        goto finish;
    }

    if (info)
        goto finish;

    for (int i = 0 ; i < num_files; ++i) {
        res = flash_load(&files[i], filenames[i], can_write_bl, max_allowed * ONE_KB);
        if (res < 0) {
            ret = -1;
            goto finish;
        }
        PrintAndLogEx(NORMAL, "");
    }

    PrintAndLogEx(SUCCESS, "\n" _BLUE_("Flashing..."));

    for (int i = 0; i < num_files; i++) {
        res = flash_write(&files[i]);
        if (res < 0) {
            ret = -1;
            goto finish;
        }
        flash_free(&files[i]);
        PrintAndLogEx(NORMAL, "\n");
    }

finish:
    res = flash_stop_flashing();
    if (res < 0)
        ret = -1;

    CloseProxmark();

    if (ret == 0)
        PrintAndLogEx(SUCCESS, _BLUE_("All done."));
    else
        PrintAndLogEx(ERR, "Aborted on error.");
    PrintAndLogEx(NORMAL, "\nHave a nice day!");
    return ret;
}
