//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_pcap.h"
#include "proxmark3.h"
#include "fileutils.h"
#include "ui.h"
#include "util_posix.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PCAP_MAGIC 0xA1B2C3D4
#define EMV_PCAP_VERSION 0x00
#define EMV_PCAP_SNAPLEN 65535

typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_global_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_record_hdr_t;

static FILE *g_pcap = NULL;
static bool g_redact_pin = true;
static uint64_t g_base_us = 0;

static uint64_t now_us(void) {
    return msclock() * 1000ULL;
}

static void redact_pin_in_capdu(uint8_t *buf, size_t len) {
    if (len < 5 || !g_redact_pin) {
        return;
    }
    uint8_t ins = buf[1];
    if (ins != 0x20 && ins != 0x24 && ins != 0x2A) {
        return;
    }
    size_t lc_pos = 4;
    if (len <= lc_pos) {
        return;
    }
    uint8_t lc = buf[lc_pos];
    size_t data_off = lc_pos + 1;
    if (data_off + lc > len) {
        return;
    }
    memset(buf + data_off, 0, lc);
}

static int write_record(emv_pcap_dir_t dir, const uint8_t *payload, size_t payload_len) {
    if (!g_pcap || !payload || payload_len == 0) {
        return PM3_EINVARG;
    }

    uint8_t frame[EMV_PCAP_SNAPLEN];
    if (payload_len + 4 > sizeof(frame)) {
        return PM3_ESOFT;
    }

    frame[0] = EMV_PCAP_VERSION;
    frame[1] = (uint8_t)dir;
    frame[2] = (uint8_t)((payload_len >> 8) & 0xFF);
    frame[3] = (uint8_t)(payload_len & 0xFF);
    memcpy(frame + 4, payload, payload_len);

    size_t frame_len = payload_len + 4;
    uint64_t us = now_us();
    if (g_base_us == 0) {
        g_base_us = us;
    }
    us -= g_base_us;

    pcap_record_hdr_t rh = {
        .ts_sec = (uint32_t)(us / 1000000ULL),
        .ts_usec = (uint32_t)(us % 1000000ULL),
        .incl_len = (uint32_t)frame_len,
        .orig_len = (uint32_t)frame_len,
    };

    if (fwrite(&rh, sizeof(rh), 1, g_pcap) != 1 ||
        fwrite(frame, frame_len, 1, g_pcap) != 1) {
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

int emv_term_pcap_open(const char *path, bool redact_pin) {
    emv_term_pcap_close();
    if (!path || !path[0]) {
        return PM3_EINVARG;
    }

    g_pcap = fopen(path, "wb");
    if (!g_pcap) {
        PrintAndLogEx(ERR, "Cannot open pcap output: %s", path);
        return PM3_ESOFT;
    }

    pcap_global_hdr_t gh = {
        .magic = PCAP_MAGIC,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = EMV_PCAP_SNAPLEN,
        .network = EMV_PCAP_LINKTYPE,
    };

    if (fwrite(&gh, sizeof(gh), 1, g_pcap) != 1) {
        fclose(g_pcap);
        g_pcap = NULL;
        return PM3_ESOFT;
    }

    g_redact_pin = redact_pin;
    g_base_us = 0;
    PrintAndLogEx(SUCCESS, "PCAP recording: %s (linktype %u)", path, EMV_PCAP_LINKTYPE);
    return PM3_SUCCESS;
}

void emv_term_pcap_close(void) {
    if (g_pcap) {
        fclose(g_pcap);
        g_pcap = NULL;
    }
    g_base_us = 0;
}

bool emv_term_pcap_active(void) {
    return g_pcap != NULL;
}

void emv_term_pcap_record(const uint8_t *capdu, size_t capdu_len,
                           const uint8_t *rapdu, size_t rapdu_len, uint16_t sw) {
    if (!g_pcap) {
        return;
    }

    if (capdu && capdu_len) {
        uint8_t tx[EMV_PCAP_SNAPLEN];
        if (capdu_len <= sizeof(tx)) {
            memcpy(tx, capdu, capdu_len);
            redact_pin_in_capdu(tx, capdu_len);
            write_record(EMV_PCAP_DIR_PMD_TO_ICC, tx, capdu_len);
        }
    }

    if (rapdu || sw) {
        uint8_t rx[EMV_PCAP_SNAPLEN];
        size_t rx_len = 0;
        if (rapdu && rapdu_len) {
            if (rapdu_len > sizeof(rx) - 2) {
                return;
            }
            memcpy(rx, rapdu, rapdu_len);
            rx_len = rapdu_len;
        }
        if (rx_len + 2 <= sizeof(rx)) {
            rx[rx_len++] = (uint8_t)((sw >> 8) & 0xFF);
            rx[rx_len++] = (uint8_t)(sw & 0xFF);
            write_record(EMV_PCAP_DIR_ICC_TO_PMD, rx, rx_len);
        }
    }
}

int emv_term_pcap_write_meta(const char *pcap_path, const char *session_path) {
    if (!pcap_path || !pcap_path[0] || !session_path || !session_path[0]) {
        return PM3_EINVARG;
    }

    char meta_path[FILE_PATH_SIZE];
    snprintf(meta_path, sizeof(meta_path), "%s.meta.json", pcap_path);

    FILE *f = fopen(meta_path, "w");
    if (!f) {
        PrintAndLogEx(ERR, "Cannot write pcap meta: %s", meta_path);
        return PM3_ESOFT;
    }

    fprintf(f, "{\n  \"pcap\": \"%s\",\n  \"session\": \"%s\"\n}\n", pcap_path, session_path);
    fclose(f);
    PrintAndLogEx(INFO, "PCAP meta: %s", meta_path);
    return PM3_SUCCESS;
}
