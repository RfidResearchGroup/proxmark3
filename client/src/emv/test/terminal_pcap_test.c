//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "terminal_pcap_test.h"
#include "../terminal/emv_term_pcap.h"
#include "terminal_test_util.h"
#include "ui.h"
#include <stdio.h>
#include <string.h>

static int test_pcap_write_records(bool verbose) {
    char path[256];
    emv_term_test_temp_path(path, sizeof(path), "pcap_test.pcap");

    if (emv_term_pcap_open(path, true) != PM3_SUCCESS) {
        return 1;
    }

    uint8_t capdu[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10};
    uint8_t rapdu[] = {0x6F, 0x10, 0x84, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10};
    emv_term_pcap_record(capdu, sizeof(capdu), rapdu, sizeof(rapdu), 0x9000);

    uint8_t pin_capdu[] = {0x00, 0x20, 0x00, 0x80, 0x08, 0x12, 0x34, 0x56, 0x78, 0xFF, 0xFF, 0xFF, 0xFF};
    emv_term_pcap_record(pin_capdu, sizeof(pin_capdu), NULL, 0, 0x6983);

    emv_term_pcap_close();

    FILE *f = fopen(path, "rb");
    if (!f) {
        return 1;
    }

    uint8_t hdr[24];
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f);
        remove(path);
        return 1;
    }

    uint32_t magic = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    uint32_t linktype = (uint32_t)hdr[20] | ((uint32_t)hdr[21] << 8) | ((uint32_t)hdr[22] << 16) | ((uint32_t)hdr[23] << 24);

    int records = 0;
    uint8_t rec_hdr[16];
    while (fread(rec_hdr, 1, sizeof(rec_hdr), f) == sizeof(rec_hdr)) {
        uint32_t incl = (uint32_t)rec_hdr[8] | ((uint32_t)rec_hdr[9] << 8) |
                        ((uint32_t)rec_hdr[10] << 16) | ((uint32_t)rec_hdr[11] << 24);
        if (fseek(f, (long)incl, SEEK_CUR) != 0) {
            break;
        }
        records++;
    }
    fclose(f);
    remove(path);

    int fail = (magic != 0xA1B2C3D4) || (linktype != EMV_PCAP_LINKTYPE) || (records < 3);
    if (verbose && !fail) {
        PrintAndLogEx(SUCCESS, "pcap write OK (%d records)", records);
    }
    return fail ? 1 : 0;
}

int exec_terminal_pcap_test(bool verbose) {
    return test_pcap_write_records(verbose);
}
