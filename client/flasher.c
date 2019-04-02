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
#include "util_posix.h"
#include "proxmark3.h"
#include "util.h"
#include "flash.h"
#include "comms.h"
#include "usb_cmd.h"

#define MAX_FILES 4

void cmd_debug(UsbCommand *c) {
    //  Debug
    printf("UsbCommand length[len=%zd]\n", sizeof(UsbCommand));
    printf("  cmd[len=%zd]: %016" PRIx64"\n", sizeof(c->cmd), c->cmd);
    printf(" arg0[len=%zd]: %016" PRIx64"\n", sizeof(c->arg[0]), c->arg[0]);
    printf(" arg1[len=%zd]: %016" PRIx64"\n", sizeof(c->arg[1]), c->arg[1]);
    printf(" arg2[len=%zd]: %016" PRIx64"\n", sizeof(c->arg[2]), c->arg[2]);
    printf(" data[len=%zd]: ", sizeof(c->d.asBytes));

    for (size_t i = 0; i < 16; i++)
        printf("%02x", c->d.asBytes[i]);

    printf("...\n");
}

static void usage(char *argv0) {
    fprintf(stdout, "Usage:   %s <port> [-b] image.elf [image.elf...]\n\n", argv0);
    fprintf(stdout, "\t-b\tEnable flashing of bootloader area (DANGEROUS)\n\n");
    fprintf(stdout, "\nExample:\n\n\t %s "SERIAL_PORT_H" armsrc/obj/fullimage.elf\n", argv0);
#ifdef __linux__
    fprintf(stdout, "\nNote (Linux): if the flasher gets stuck in 'Waiting for Proxmark to reappear on <DEVICE>',\n");
    fprintf(stdout, "              you need to blacklist proxmark for modem-manager - see wiki for more details:\n\n");
    fprintf(stdout, "              https://github.com/Proxmark/proxmark3/wiki/Gentoo Linux\n\n");
    fprintf(stdout, "              https://github.com/Proxmark/proxmark3/wiki/Ubuntu Linux\n\n");
    fprintf(stdout, "              https://github.com/Proxmark/proxmark3/wiki/OSX\n\n");
#endif
}

int main(int argc, char **argv) {
    int can_write_bl = 0;
    int num_files = 0;
    int res;
    flash_file_t files[MAX_FILES];

    memset(files, 0, sizeof(files));

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

            fprintf(stderr, "\n");
            num_files++;
        }
    }

    char *serial_port_name = argv[1];

    if (!OpenProxmark(serial_port_name, true, 60, true, FLASHMODE_SPEED)) {
        fprintf(stderr, "Could not find Proxmark on " _RED_("%s") ".\n\n", serial_port_name);
        return -1;
    } else {
        fprintf(stderr, _GREEN_("Found") "\n");
    }

    res = flash_start_flashing(can_write_bl, serial_port_name);
    if (res < 0)
        return -1;

    fprintf(stdout, "\n" _BLUE_("Flashing...")"\n");

    for (int i = 0; i < num_files; i++) {
        res = flash_write(&files[i]);
        if (res < 0)
            return -1;
        flash_free(&files[i]);
        fprintf(stdout, "\n");
    }

    fprintf(stdout, _BLUE_("Resetting hardware...") "\n");

    res = flash_stop_flashing();
    if (res < 0)
        return -1;

    CloseProxmark();

    fprintf(stdout, _BLUE_("All done.") "\n\nHave a nice day!\n");
    return 0;
}
