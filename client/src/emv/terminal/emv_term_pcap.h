//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — ISO7816 APDU pcap export
//-----------------------------------------------------------------------------

#ifndef EMV_TERM_PCAP_H__
#define EMV_TERM_PCAP_H__

#include "common.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define EMV_PCAP_LINKTYPE 265

typedef enum {
    EMV_PCAP_DIR_PMD_TO_ICC = 0xFE,
    EMV_PCAP_DIR_ICC_TO_PMD = 0xFF,
} emv_pcap_dir_t;

int emv_term_pcap_open(const char *path, bool redact_pin);
void emv_term_pcap_close(void);
bool emv_term_pcap_active(void);

void emv_term_pcap_record(const uint8_t *capdu, size_t capdu_len,
                          const uint8_t *rapdu, size_t rapdu_len, uint16_t sw);

int emv_term_pcap_write_meta(const char *pcap_path, const char *session_path);

#endif
