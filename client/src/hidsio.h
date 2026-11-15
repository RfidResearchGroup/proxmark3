//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// HID Global SIO utilities
//-----------------------------------------------------------------------------
#ifndef __HIDSIO_H_
#define __HIDSIO_H_

#include "common.h"
#include "stdint.h"
#include "pm3_cmd.h"
#include "cliparser.h"

const char *getSioMediaTypeInfo(uint8_t uid);

// Where a SAM read credential came from
typedef enum {
    HID_SRC_UNKNOWN = 0,
    HID_SRC_ICLASS,
    HID_SRC_ISO14443A,  // Seos / DESFire via CMD_HF_SAM_SEOS
    HID_SRC_MFC,
} hid_sam_source_t;

// Credential read through a HID SAM, plus what was seen on the air
typedef struct {
    hid_sam_source_t source;
    uint8_t pacs[16];       // pad bit count + payload, as the SAM returns it
    uint8_t pacs_len;
    char binstr[129];
    uint8_t bit_len;
    bool has_media_type;
    uint8_t media_type;
    uint8_t oid[16];
    uint8_t oid_len;
    uint8_t uid[10];        // CSN for iCLASS
    uint8_t uid_len;
    uint8_t sio[SAM_EXT_SIO_MAX];
    uint8_t sio_len;
    uint8_t sio_start;      // iCLASS block the SIO was read from
} hid_sam_cred_t;

// Seader's save formats, less the agnostic one
typedef enum {
    HID_DG_NONE = 0,
    HID_DG_LEGACY,          // iCLASS legacy, PACS only
    HID_DG_SR,              // iCLASS SR, PACS plus SIO in block 10
    HID_DG_PROX,            // LF HID Prox
    HID_DG_MFC,             // MIFARE Classic 1K, HID layout
} hid_dg_t;

extern const CLIParserOption hid_dg_opts[];

#define HID_PICOPASS_IMAGE_BLOCKS   20
#define HID_MFC_IMAGE_SIZE          1024

void hid_sam_unwrap_reply(uint8_t **d, size_t *len, hid_sam_cred_t *cred);
bool hid_sam_is_pacs_reply(const uint8_t *d, size_t len);
int hid_sam_print_pacs(const uint8_t *d, size_t len, hid_sam_cred_t *cred, bool verbose);
int hid_sam_cred_from_pacs(hid_sam_cred_t *cred, const uint8_t *pacs, size_t pacs_len);
int hid_sam_cred_from_bin(hid_sam_cred_t *cred, const char *binstr);

int hid_build_picopass_image(const hid_sam_cred_t *cred, bool with_sio, uint8_t *out);
int hid_build_mfc_image(const hid_sam_cred_t *cred, uint8_t *out);

int hid_sam_output(const hid_sam_cred_t *cred, hid_dg_t dg, bool save);
int hid_sam_load_cred(const char *fn, hid_sam_cred_t *cred);
int hid_sam_iso14a_cmd(const char *Cmd, const char *name, uint16_t pm3_cmd, hid_sam_source_t source);
int hid_sam_selftest(void);

#endif
