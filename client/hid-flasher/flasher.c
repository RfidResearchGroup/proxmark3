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
#include "util_posix.h"
#include "proxusb.h"
#include "flash.h"

static void usage(char *argv0) {
    fprintf(stderr, "Usage:   %s [-b] image.elf [image.elf...]\n\n", argv0);
    fprintf(stderr, "\t-b\tEnable flashing of bootloader area (DANGEROUS)\n\n");
    fprintf(stderr, "Example: %s path/to/osimage.elf path/to/fpgaimage.elf\n", argv0);
}

#define MAX_FILES 4

int main(int argc, char **argv) {
    int can_write_bl = 0;
    int num_files = 0;
    int res;
    flash_file_t files[MAX_FILES];

    memset(files, 0, sizeof(files));

    if (argc < 2) {
        usage(argv[0]);
        return -1;
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (!strcmp(argv[i], "-b")) {
                can_write_bl = 1;
            } else {
                usage(argv[0]);
                return -1;
            }
        } else {
            res = flash_load(&files[num_files], argv[i], can_write_bl);
            if (res < 0) {
                fprintf(stderr, "Error while loading %s\n", argv[i]);
                return -1;
            }
            fprintf(stderr, "\n");
            num_files++;
        }
    }

    usb_init();

    fprintf(stderr, "Waiting for Proxmark to appear on USB...");
    while (!OpenProxmark(1)) {
        msleep(1000);
        fprintf(stderr, ".");
        fflush(stdout);
    }
    fprintf(stderr, " Found.\n");

    res = flash_start_flashing(can_write_bl);
    if (res < 0)
        return -1;

    fprintf(stderr, "\nFlashing...\n");

    for (int i = 0; i < num_files; i++) {
        res = flash_write(&files[i]);
        if (res < 0)
            return -1;
        flash_free(&files[i]);
        fprintf(stderr, "\n");
    }

    fprintf(stderr, "Resetting hardware...\n");

    res = flash_stop_flashing();
    if (res < 0)
        return -1;

    CloseProxmark();

    fprintf(stderr, "All done.\n\n");
    fprintf(stderr, "Have a nice day!\n");

    return 0;
}
