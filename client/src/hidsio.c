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
//
// Downgrade images follow Seader (bettse/seader, GPLv3) seader_credential.c
//-----------------------------------------------------------------------------
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "commonutil.h"
#include "hidsio.h"
#include "ui.h"
#include "util.h"
#include "fileutils.h"
#include "jansson.h"
#include "jansson_path.h"
#include "emv/emvjson.h"
#include "crypto/asn1utils.h"
#include "loclass/ikeys.h"
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"
#include "comms.h"
#include "cardhelper.h"

// structure and database for uid -> tagtype lookups
typedef struct {
    uint8_t uid;
    const char *desc;
} sioMediaTypeName_t;

static const sioMediaTypeName_t sioMediaTypeMapping[] = {
    { 0x00, "Unknown"},
    { 0x01, "DESFire"},
    { 0x02, "MIFARE"},
    { 0x03, "iCLASS (PicoPass)"},
    { 0x04, "ISO14443AL4"},
    { 0x06, "MIFARE Plus"},
    { 0x07, "Seos"},
    { 0xFF, "INVALID VALUE"}
};

// get a SIO media type based on the UID
//  uid[8] tag uid
// returns description of the best match
const char *getSioMediaTypeInfo(uint8_t uid) {

    for (int i = 0; i < ARRAYLEN(sioMediaTypeMapping); ++i) {
        if (uid == sioMediaTypeMapping[i].uid) {
            return sioMediaTypeMapping[i].desc;
        }
    }

    //No match, return default
    return sioMediaTypeMapping[ARRAYLEN(sioMediaTypeMapping) - 1].desc;
}

const CLIParserOption hid_dg_opts[] = {
    {HID_DG_LEGACY, "legacy"},
    {HID_DG_SR,     "sr"},
    {HID_DG_PROX,   "prox"},
    {HID_DG_MFC,    "mfc"},
    {0, NULL},
};

// HID iCLASS standard key
static const uint8_t hid_iclass_std_key[8] = { 0xAE, 0xA6, 0x84, 0xA6, 0xDA, 0xB2, 0x32, 0x78 };

// Seader's picopass image constants
static const uint8_t hid_picopass_fake_csn[8] = { 0x7A, 0xF5, 0x31, 0x13, 0xFE, 0xFF, 0x12, 0xE0 };
static const uint8_t hid_picopass_cfg[8] = { 0x12, 0xFF, 0xFF, 0xFF, 0x7F, 0x1F, 0xFF, 0x3C };
static const uint8_t hid_picopass_epurse[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xE3, 0xFF, 0xFF, 0xFF };
// unencrypted PACS, block6[0] becomes 0xA3 for SR
static const uint8_t hid_picopass_pacs_cfg[8] = { 0x03, 0x03, 0x03, 0x03, 0x00, 0x03, 0xE0, 0x14 };

// Seader's MIFARE Classic image constants
static const uint8_t hid_mfc_manuf_block[16] = {
    0xDF, 0xC6, 0x9C, 0x05, 0x80, 0x08, 0x04, 0x00, 0x00, 0x00, 0x73, 0x65, 0x61, 0x64, 0x65, 0x72
};
static const uint8_t hid_mfc_mad_block[16] = {
    0x1B, 0x01, 0x4D, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t hid_mfc_sector0_trailer[16] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x78, 0x77, 0x88, 0xC1, 0x89, 0xEC, 0xA9, 0x7F, 0x8C, 0x2A
};
static const uint8_t hid_mfc_sector1_trailer[16] = {
    0x48, 0x49, 0x44, 0x20, 0x49, 0x53, 0x78, 0x77, 0x88, 0xAA, 0x20, 0x47, 0x52, 0x45, 0x41, 0x54
};
static const uint8_t hid_mfc_trailer[16] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// Strips a sam_ext_reply_hdr_t, if there is one, and keeps its UID and SIO.
void hid_sam_unwrap_reply(uint8_t **d, size_t *len, hid_sam_cred_t *cred) {

    sam_ext_reply_hdr_t hdr;
    if (*len < sizeof(hdr) || (*d)[0] != SAM_EXT_REPLY_MAGIC) {
        return;
    }

    memcpy(&hdr, *d, sizeof(hdr));
    if (hdr.uid_len > sizeof(hdr.uid) || hdr.sio_len > SAM_EXT_SIO_MAX ||
            sizeof(hdr) + hdr.sio_len + hdr.sam_len != *len) {
        return;
    }

    cred->uid_len = hdr.uid_len;
    memcpy(cred->uid, hdr.uid, hdr.uid_len);
    cred->sio_len = hdr.sio_len;
    cred->sio_start = hdr.sio_start;
    memcpy(cred->sio, *d + sizeof(hdr), hdr.sio_len);

    *d += sizeof(hdr) + hdr.sio_len;
    *len = hdr.sam_len;
}

// SamCommandGetContentElement or samCommandGetContentElement2 answer
bool hid_sam_is_pacs_reply(const uint8_t *d, size_t len) {
    if (len < 6 || d[0] != 0xBD) {
        return false;
    }
    return ((d[2] == 0x8A && d[4] == 0x03) || (d[2] == 0xB3 && d[4] == 0xA0));
}

int hid_sam_cred_from_pacs(hid_sam_cred_t *cred, const uint8_t *pacs, size_t pacs_len) {
    if (pacs_len < 2 || pacs_len > sizeof(cred->pacs)) {
        return PM3_EINVARG;
    }

    if (wiegand_new_pacs_to_binstr(pacs, pacs_len, cred->binstr, sizeof(cred->binstr)) == false) {
        return PM3_EINVARG;
    }

    memcpy(cred->pacs, pacs, pacs_len);
    cred->pacs_len = pacs_len;
    cred->bit_len = strlen(cred->binstr);
    return PM3_SUCCESS;
}

int hid_sam_cred_from_bin(hid_sam_cred_t *cred, const char *binstr) {
    size_t n = strlen(binstr);
    if (n == 0 || n > (sizeof(cred->pacs) - 1) * 8 || strspn(binstr, "01") != n) {
        return PM3_EINVARG;
    }

    // pad to whole bytes, the pad count leads the PACS
    char padded[129] = {0};
    memcpy(padded, binstr, n);
    uint8_t pad = (8 - (n % 8)) % 8;
    memset(padded + n, '0', pad);

    uint8_t pacs[16] = {0};
    size_t plen = 0;
    pacs[0] = pad;
    binstr_2_bytes(pacs + 1, &plen, padded);
    return hid_sam_cred_from_pacs(cred, pacs, plen + 1);
}

static void hid_sam_print_air(const hid_sam_cred_t *cred, bool verbose) {

    if (cred->uid_len) {
        PrintAndLogEx(SUCCESS, "%s.............. " _GREEN_("%s"),
                      (cred->source == HID_SRC_ICLASS) ? "CSN" : "UID",
                      sprint_hex_inrow(cred->uid, cred->uid_len));
    }

    if (cred->sio_len == 0) {
        return;
    }

    if (cred->sio_start == 6) {
        PrintAndLogEx(SUCCESS, "SIO.............. block 6 ( SE )");
    } else if (cred->sio_start == 10) {
        PrintAndLogEx(SUCCESS, "SIO.............. block 10 ( SR )");
    } else if (cred->sio_start) {
        PrintAndLogEx(SUCCESS, "SIO.............. block %u", cred->sio_start);
    } else {
        PrintAndLogEx(SUCCESS, "SIO.............. %u bytes", cred->sio_len);
    }
    print_hex_noascii_break(cred->sio, cred->sio_len, 32);

    if (verbose) {
        PrintAndLogEx(INFO, "----------------------- " _CYAN_("SIO - ASN1 TLV") " ---------------------------");
        uint8_t sio[SAM_EXT_SIO_MAX];
        memcpy(sio, cred->sio, cred->sio_len);
        asn1_print(sio, cred->sio_len, "  ");
    }
}

// Prints a PACS answer and fills cred. PM3_ENOPACS when the SAM gave no access bits.
int hid_sam_print_pacs(const uint8_t *d, size_t len, hid_sam_cred_t *cred, bool verbose) {

    const uint8_t *pacs;
    uint8_t pacs_len;
    const uint8_t *p = NULL;
    const uint8_t *end = NULL;

    if (d[2] == 0x8A) {
        // check for standard SamCommandGetContentElement response
        // bd 09
        //    8a 07
        //       03 05 <- tag + length
        //          06 85 80 6d c0 <- decoded PACS data
        pacs_len = d[5];
        pacs = d + 6;
    } else {
        // check for standard samCommandGetContentElement2:
        // bd 1e
        //    b3 1c
        //       a0 1a
        //          80 05
        //             06 85 80 6d c0
        //          81 0e
        //             2b 06 01 04 01 81 e4 38 01 01 02 04 3c ff
        //          82 01
        //             07
        const uint8_t *elm = d + 6;
        // The a0 content element normally starts with 80 <len> <PACS bits>.
        // Some SAMs / cards return a status-only element with no access-bits
        // field, e.g. a0 03 82 01 03 - here the first inner tag is 82, not 80.
        // Don't parse the status byte as PACS (that yields a bogus
        // "Invalid PACS value"); report that the card has no readable PACS.
        if (len < 8 || elm[0] != 0x80) {
            PrintAndLogEx(WARNING, "No PACS/SIO access-bits returned by the SAM");
            if (len >= 9 && elm[0] == 0x82 && elm[1] == 0x01) {
                PrintAndLogEx(INFO, "SAM content status: " _YELLOW_("0x%02X") " (no physicalAccessBits field)", elm[2]);
            }
            if (verbose) {
                print_hex(d, len);
            }
            return PM3_ENOPACS;
        }
        pacs_len = elm[1];
        pacs = elm + 2;

        // The a0 element holds 80 (PACS) and optionally 81 (SIO OID) and 82
        // (media type). An iCLASS SE credential often omits 81, so walk the
        // nodes rather than assuming all three are present in order.
        p = pacs + pacs_len;
        end = d + 6 + d[5];
        if (end > d + len) {
            end = d + len;
        }
    }

    if (pacs + pacs_len > d + len) {
        PrintAndLogEx(ERR, "Invalid PACS value");
        return PM3_EINVARG;
    }

    int res = HIDDumpPACSBits(pacs, pacs_len, verbose);
    if (res != PM3_SUCCESS) {
        return res;
    }

    hid_sam_cred_from_pacs(cred, pacs, pacs_len);

    while (p != NULL && p + 1 < end) {

        uint8_t tag = p[0];
        uint8_t tlen = p[1];
        if (p + 2 + tlen > end) {
            break;
        }

        if (tag == 0x81) {
            PrintAndLogEx(SUCCESS, "SIO OID.......... " _GREEN_("%s"), sprint_hex_inrow(p + 2, tlen));
            cred->oid_len = MIN(tlen, sizeof(cred->oid));
            memcpy(cred->oid, p + 2, cred->oid_len);
        } else if ((tag == 0x82) && (tlen >= 1)) {
            PrintAndLogEx(SUCCESS, "SIO Media Type... " _GREEN_("%s"), getSioMediaTypeInfo(p[2]));
            cred->has_media_type = true;
            cred->media_type = p[2];
        }

        p += 2 + tlen;
    }

    hid_sam_print_air(cred, verbose);
    return PM3_SUCCESS;
}

// iCLASS image as Seader's "Save Picopass" / "Save SR" builds it, 20 blocks.
int hid_build_picopass_image(const hid_sam_cred_t *cred, bool with_sio, uint8_t *out) {

    // PACS block holds sentinel plus bits in 64 bits
    if (cred->bit_len == 0 || cred->bit_len > 63) {
        return PM3_EINVARG;
    }

    // SR keeps the SIO in blocks 10 - 17
    if (with_sio && (cred->sio_len == 0 || cred->sio_len > (8 * 8))) {
        return PM3_EINVARG;
    }

    memset(out, 0, HID_PICOPASS_IMAGE_BLOCKS * 8);

    // Seader means to use a fake CSN for anything not read from iCLASS
    uint8_t csn[8];
    if (cred->source == HID_SRC_ICLASS && cred->uid_len == 8) {
        memcpy(csn, cred->uid, sizeof(csn));
    } else {
        memcpy(csn, hid_picopass_fake_csn, sizeof(csn));
    }

    uint8_t key[8];
    memcpy(key, hid_iclass_std_key, sizeof(key));

    memcpy(out + (0 * 8), csn, 8);
    memcpy(out + (1 * 8), hid_picopass_cfg, 8);
    memcpy(out + (2 * 8), hid_picopass_epurse, 8);
    diversifyKey(csn, key, out + (3 * 8));
    // block 4, Kc, stays zero as in Seader
    memset(out + (5 * 8), 0xFF, 8);
    memcpy(out + (6 * 8), hid_picopass_pacs_cfg, 8);

    if (wiegand_pack_sentinel_bytes(cred->binstr, out + (7 * 8), 8) != PM3_SUCCESS) {
        return PM3_EINVARG;
    }

    if (with_sio) {
        out[6 * 8] = 0xA3;
        memcpy(out + (10 * 8), cred->sio, cred->sio_len);
    }
    return PM3_SUCCESS;
}

// MIFARE Classic 1K image as Seader's "Save MFC" builds it.
int hid_build_mfc_image(const hid_sam_cred_t *cred, uint8_t *out) {

    if (cred->bit_len == 0) {
        return PM3_EINVARG;
    }

    memset(out, 0, HID_MFC_IMAGE_SIZE);

    for (uint8_t s = 0; s < 16; s++) {
        memcpy(out + (((s * 4) + 3) * 16), hid_mfc_trailer, 16);
    }

    memcpy(out + (0 * 16), hid_mfc_manuf_block, 16);
    memcpy(out + (1 * 16), hid_mfc_mad_block, 16);
    memcpy(out + (3 * 16), hid_mfc_sector0_trailer, 16);
    memcpy(out + (7 * 16), hid_mfc_sector1_trailer, 16);

    // block 5: 0x02, then sentinel plus bits right aligned
    out[5 * 16] = 0x02;
    return wiegand_pack_sentinel_bytes(cred->binstr, out + (5 * 16) + 1, 15);
}

static const char *hid_sam_file_tag(const hid_sam_cred_t *cred) {
    if (cred->has_media_type) {
        switch (cred->media_type) {
            case 0x01:
                return "mfdes";
            case 0x02:
                return "mf";
            case 0x03:
                return "iclass";
            case 0x07:
                return "seos";
            default:
                break;
        }
    }

    switch (cred->source) {
        case HID_SRC_ICLASS:
            return "iclass";
        case HID_SRC_MFC:
            return "mf";
        case HID_SRC_ISO14443A:
            return "14a";
        case HID_SRC_UNKNOWN:
        default:
            return "sam";
    }
}

static int hid_sam_save_cred(const hid_sam_cred_t *cred, const char *fn) {

    json_t *root = json_object();
    if (root == NULL) {
        return PM3_EMALLOC;
    }

    uint8_t buf[SAM_EXT_SIO_MAX];

    JsonSaveStr(root, "Created", "proxmark3");
    JsonSaveStr(root, "FileType", "hid credential");
    JsonSaveStr(root, "$.Credential.Source", hid_sam_file_tag(cred));
    JsonSaveInt(root, "$.Credential.Bits", cred->bit_len);
    JsonSaveStr(root, "$.Credential.Binary", cred->binstr);

    memcpy(buf, cred->pacs, cred->pacs_len);
    JsonSaveBufAsHexCompact(root, "$.Credential.PACS", buf, cred->pacs_len);

    if (cred->has_media_type) {
        JsonSaveInt(root, "$.Credential.MediaType", cred->media_type);
    }
    if (cred->oid_len) {
        memcpy(buf, cred->oid, cred->oid_len);
        JsonSaveBufAsHexCompact(root, "$.Credential.OID", buf, cred->oid_len);
    }
    if (cred->uid_len) {
        memcpy(buf, cred->uid, cred->uid_len);
        JsonSaveBufAsHexCompact(root, "$.Credential.UID", buf, cred->uid_len);
    }
    if (cred->sio_len) {
        memcpy(buf, cred->sio, cred->sio_len);
        JsonSaveBufAsHexCompact(root, "$.Credential.SIO", buf, cred->sio_len);
        JsonSaveInt(root, "$.Credential.SIOStartBlock", cred->sio_start);
    }

    int res = saveFileJSONroot(fn, root, JSON_INDENT(2), true);
    json_decref(root);
    return res;
}

int hid_sam_load_cred(const char *fn, hid_sam_cred_t *cred) {

    json_t *root = NULL;
    if (loadFileJSONroot(fn, (void **)&root, true) != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    int res = PM3_ESOFT;
    memset(cred, 0, sizeof(*cred));

    json_t *jft = json_path_get(root, "$.FileType");
    if (jft == NULL || json_is_string(jft) == false || strcmp(json_string_value(jft), "hid credential")) {
        PrintAndLogEx(ERR, "Not a HID credential file");
        goto out;
    }

    uint8_t pacs[16] = {0};
    size_t pacs_len = 0;
    if (JsonLoadBufAsHex(root, "$.Credential.PACS", pacs, sizeof(pacs), &pacs_len) ||
            hid_sam_cred_from_pacs(cred, pacs, pacs_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Invalid PACS in credential file");
        goto out;
    }

    json_t *jsrc = json_path_get(root, "$.Credential.Source");
    if (jsrc && json_is_string(jsrc)) {
        const char *src = json_string_value(jsrc);
        if (strcmp(src, "iclass") == 0) {
            cred->source = HID_SRC_ICLASS;
        } else if (strcmp(src, "mf") == 0) {
            cred->source = HID_SRC_MFC;
        } else {
            cred->source = HID_SRC_ISO14443A;
        }
    }

    json_t *jmt = json_path_get(root, "$.Credential.MediaType");
    if (jmt && json_is_integer(jmt)) {
        cred->has_media_type = true;
        cred->media_type = (uint8_t)json_integer_value(jmt);
    }

    size_t n = 0;
    if (JsonLoadBufAsHex(root, "$.Credential.OID", cred->oid, sizeof(cred->oid), &n) == 0) {
        cred->oid_len = n;
    }
    if (JsonLoadBufAsHex(root, "$.Credential.UID", cred->uid, sizeof(cred->uid), &n) == 0) {
        cred->uid_len = n;
    }
    if (JsonLoadBufAsHex(root, "$.Credential.SIO", cred->sio, sizeof(cred->sio), &n) == 0) {
        cred->sio_len = n;
    }

    json_t *jsb = json_path_get(root, "$.Credential.SIOStartBlock");
    if (jsb && json_is_integer(jsb)) {
        cred->sio_start = (uint8_t)json_integer_value(jsb);
    }

    res = PM3_SUCCESS;

out:
    json_decref(root);
    return res;
}

static void hid_sam_print_prox(const hid_sam_cred_t *cred) {

    // LF HID transport carries at most 84 bits
    if (cred->bit_len > 84) {
        PrintAndLogEx(FAILED, "%u bits does not fit HID Prox", cred->bit_len);
        return;
    }

    PrintAndLogEx(INFO, "Downgrade to " _YELLOW_("HID Prox") ", T55x7");
    PrintAndLogEx(SUCCESS, "    lf hid clone --bin %s", cred->binstr);

    // Seader writes 26 bit credentials as H10301
    if (cred->bit_len == 26) {
        char fc[9] = {0}, cn[17] = {0};
        memcpy(fc, cred->binstr + 1, 8);
        memcpy(cn, cred->binstr + 9, 16);
        PrintAndLogEx(SUCCESS, "    lf hid clone -w H10301 --fc %u --cn %u",
                      (uint32_t)strtoul(fc, NULL, 2), (uint32_t)strtoul(cn, NULL, 2));
    }
}

// Saves the agnostic credential and / or builds one downgrade target.
int hid_sam_output(const hid_sam_cred_t *cred, hid_dg_t dg, bool save) {

    if (dg == HID_DG_NONE && save == false) {
        return PM3_SUCCESS;
    }

    if (cred->bit_len == 0) {
        PrintAndLogEx(WARNING, "No PACS to save or downgrade");
        return PM3_EINVARG;
    }

    char base[FILE_PATH_SIZE] = {0};
    if (cred->uid_len) {
        snprintf(base, sizeof(base), "hf-%s-%s", hid_sam_file_tag(cred), sprint_hex_inrow(cred->uid, cred->uid_len));
    } else {
        snprintf(base, sizeof(base), "hf-%s", hid_sam_file_tag(cred));
    }

    char fn[FILE_PATH_SIZE] = {0};
    PrintAndLogEx(NORMAL, "");

    if (save) {
        snprintf(fn, sizeof(fn), "%s-credential", base);
        int res = hid_sam_save_cred(cred, fn);
        if (res != PM3_SUCCESS) {
            return res;
        }
        PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("wiegand downgrade -f %s.json --dg <legacy|sr|prox|mfc>") "`", fn);
    }

    switch (dg) {
        case HID_DG_LEGACY:
        case HID_DG_SR: {
            bool sr = (dg == HID_DG_SR);
            if (sr && (cred->source != HID_SRC_ICLASS || cred->uid_len != 8 || cred->sio_len == 0)) {
                PrintAndLogEx(FAILED, "iCLASS SR needs a SIO read from an iCLASS card");
                return PM3_EINVARG;
            }

            uint8_t img[HID_PICOPASS_IMAGE_BLOCKS * 8];
            if (hid_build_picopass_image(cred, sr, img) != PM3_SUCCESS) {
                PrintAndLogEx(FAILED, "Credential does not fit iCLASS %s ( %u bits, SIO %u bytes )", sr ? "SR" : "legacy", cred->bit_len, cred->sio_len);
                return PM3_EINVARG;
            }

            if (cred->source != HID_SRC_ICLASS || cred->uid_len != 8) {
                PrintAndLogEx(INFO, "Using CSN " _YELLOW_("%s"), sprint_hex_inrow(img, 8));
            }

            snprintf(fn, sizeof(fn), "%s-%s-dump", base, sr ? "sr" : "legacy");
            int res = pm3_save_dump(fn, img, sizeof(img), jsfIclass);
            if (res != PM3_SUCCESS) {
                return res;
            }
            PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf iclass view -f %s.bin") "` to view dump file", fn);
            PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf iclass restore -f %s.bin --first 6 --last %u --ki 0") "` to write, add " _YELLOW_("--elite") " for an elite keyed card", fn, sr ? 17 : 9);
            PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf iclass eload -f %s.bin") "` and `" _YELLOW_("hf iclass sim -t 3") "` to simulate", fn);
            break;
        }
        case HID_DG_MFC: {
            uint8_t img[HID_MFC_IMAGE_SIZE];
            if (hid_build_mfc_image(cred, img) != PM3_SUCCESS) {
                PrintAndLogEx(FAILED, "Credential does not fit MIFARE Classic ( %u bits )", cred->bit_len);
                return PM3_EINVARG;
            }

            snprintf(fn, sizeof(fn), "%s-mfc-dump", base);
            int res = pm3_save_mf_dump(fn, img, sizeof(img), jsfCardMemory);
            if (res != PM3_SUCCESS) {
                return res;
            }
            PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf mf encodehid --bin %s") "` to write a blank card", cred->binstr);
            PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf mf cload -f %s.bin") "` to write a Gen1a magic card", fn);
            PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf mf eload -f %s.bin") "` and `" _YELLOW_("hf mf sim --1k -u DFC69C05") "` to simulate", fn);
            break;
        }
        case HID_DG_PROX: {
            hid_sam_print_prox(cred);
            break;
        }
        case HID_DG_NONE:
        default:
            break;
    }
    return PM3_SUCCESS;
}

// `hf seos sam`, `hf mfdes sam` and `hf mf sam`
int hid_sam_iso14a_cmd(const char *Cmd, const char *name, uint16_t pm3_cmd, hid_sam_source_t source) {

    char examples[256] = {0};
    snprintf(examples, sizeof(examples),
             "%s\n"
             "%s -d a005a103800104 -> get PACS data\n"
             "%s --dg mfc          -> get PACS, save a MIFARE Classic dump\n"
             "%s --save --dg prox  -> save credential, print HID Prox clone commands\n",
             name, name, name, name);

    CLIParserContext *ctx;
    CLIParserInit(&ctx, name,
                  "Extract PACS information via a HID SAM\n"
                  "Make sure you got a SAM inserted in your sim module",
                  examples
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("k", "keep", "keep the field active after command executed"),
        arg_lit0("n", "nodetect", "skip selecting the card and sending card details to SAM"),
        arg_lit0("t",  "tlv",      "decode TLV"),
        arg_strx0("d", "data",     "<hex>", "DER encoded command to send to SAM"),
        arg_str0(NULL, "dg",       "<legacy|sr|prox|mfc>", "downgrade the credential to"),
        arg_lit0(NULL, "save",     "save credential to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool disconnectAfter = !arg_get_lit(ctx, 2);
    bool skipDetect = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);

    int dg = HID_DG_NONE;
    if (CLIGetOptionList(arg_get_str(ctx, 6), hid_dg_opts, &dg)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    bool save_cred = arg_get_lit(ctx, 7);

    uint8_t flags = 0;
    if (disconnectAfter) {
        flags |= BITMASK(0);
    }

    if (skipDetect) {
        flags |= BITMASK(1);
    }

    // extended reply with UID and SIO
    flags |= BITMASK(2);

    uint8_t data[PM3_CMD_DATA_SIZE] = {0};
    data[0] = flags;

    int cmdlen = 0;
    if (CLIParamHexToBuf(arg_get_str(ctx, 5), data + 1, g_conn.max_cmd_data_size - 1, &cmdlen) != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    CLIParserFree(ctx);

    // The ARM pings the SAM itself before anything else, so this costs a card
    // reset and an ATR to learn what it is about to learn again. Only pay for
    // it when the detail was asked for.
    if (verbose && (IsHIDSamPresent(verbose) == false)) {
        return PM3_ESOFT;
    }

    clearCommandBuffer();
    SendCommandNG(pm3_cmd, data, cmdlen + 1);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(pm3_cmd, &resp, 4000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    switch (resp.status) {
        case PM3_SUCCESS: {
            break;
        }
        case PM3_ENOPACS: {
            PrintAndLogEx(SUCCESS, "No PACS data found. Card empty?");
            return resp.status;
        }
        default: {
            PrintAndLogEx(WARNING, "SAM select failed");
            PrintAndLogEx(HINT, "Hint: is a HID SAM in the slot? Try `" _YELLOW_("smart info") "`");
            return resp.status;
        }
    }

    hid_sam_cred_t cred;
    memset(&cred, 0, sizeof(cred));
    cred.source = source;

    uint8_t *d = resp.data.asBytes;
    size_t dlen = resp.length;
    hid_sam_unwrap_reply(&d, &dlen, &cred);

    bool got_pacs = false;
    if (hid_sam_is_pacs_reply(d, dlen)) {
        int res = hid_sam_print_pacs(d, dlen, &cred, verbose);
        if (res != PM3_SUCCESS) {
            return res;
        }
        got_pacs = true;
    } else {
        print_hex(d, dlen);
    }

    if (decodeTLV && dlen >= 2) {
        asn1_print(d, d[1] + 2, " ");
    }

    if (got_pacs) {
        return hid_sam_output(&cred, dg, save_cred);
    }

    if (dg != HID_DG_NONE || save_cred) {
        PrintAndLogEx(WARNING, "No PACS to save or downgrade");
    }
    return PM3_SUCCESS;
}

static bool hid_selftest_check(const char *name, bool ok) {
    PrintAndLogEx(ok ? SUCCESS : FAILED, "%-30s ( %s )", name, ok ? _GREEN_("ok") : _RED_("fail"));
    return ok;
}

int hid_sam_selftest(void) {

    PrintAndLogEx(INFO, "------------------- " _CYAN_("HID SAM selftest") " ----------------------");
    bool ok = true;

    // MFC SAM frames, vectors cross checked against a port of Seader's code
    const uint8_t air4[] = { 0xA1, 0xB9, 0xF8, 0x3C, 0x08 };
    const uint8_t dat4[] = { 0xA1, 0x5C, 0x3E, 0x07 };
    const uint8_t air8[] = { 0x01, 0x04, 0x12, 0x40, 0x08, 0x11, 0x04, 0x50, 0x40 };
    const uint8_t dat8[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
    uint8_t data[16] = {0}, par[2] = {0}, air[16] = {0};

    uint16_t n = iso14a_air_bits_unpack(air4, sizeof(air4), data, par);
    ok &= hid_selftest_check("MFC frame unpack 4", n == 4 && memcmp(data, dat4, 4) == 0 && par[0] == 0xB0);

    n = iso14a_air_bits_unpack(air8, sizeof(air8), data, par);
    ok &= hid_selftest_check("MFC frame unpack 8", n == 8 && memcmp(data, dat8, 8) == 0 && par[0] == 0x5A);

    par[0] = 0x5A;
    n = iso14a_air_bits_pack(dat8, par, 8, air);
    ok &= hid_selftest_check("MFC frame pack 8", n == sizeof(air8) && memcmp(air, air8, n) == 0);

    // FC 31 CN 337 (H10301)
    hid_sam_cred_t cred;
    memset(&cred, 0, sizeof(cred));
    const uint8_t pacs[] = { 0x06, 0x8F, 0x80, 0xA8, 0xC0 };
    ok &= hid_selftest_check("PACS to bits", hid_sam_cred_from_pacs(&cred, pacs, sizeof(pacs)) == PM3_SUCCESS &&
                             cred.bit_len == 26 && strcmp(cred.binstr, "10001111100000001010100011") == 0);

    // extended reply around a samCommandGetContentElement2 answer
    uint8_t sam[] = {
        0xBD, 0x1E, 0xB3, 0x1C, 0xA0, 0x1A, 0x80, 0x05, 0x06, 0x85, 0x80, 0x6D, 0xC0,
        0x81, 0x0E, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xE4, 0x38, 0x01, 0x01, 0x02, 0x04, 0x3C, 0xFF,
        0x82, 0x01, 0x07
    };
    uint8_t reply[sizeof(sam_ext_reply_hdr_t) + 4 + sizeof(sam)] = {0};
    sam_ext_reply_hdr_t *hdr = (sam_ext_reply_hdr_t *)reply;
    hdr->magic = SAM_EXT_REPLY_MAGIC;
    hdr->uid_len = 4;
    memcpy(hdr->uid, "\x01\x02\x03\x04", 4);
    hdr->sio_len = 4;
    hdr->sam_len = sizeof(sam);
    memcpy(reply + sizeof(*hdr), "\x30\x02\x81\x00", 4);
    memcpy(reply + sizeof(*hdr) + 4, sam, sizeof(sam));
    uint8_t *d = reply;
    size_t dlen = sizeof(reply);
    hid_sam_cred_t xc;
    memset(&xc, 0, sizeof(xc));
    hid_sam_unwrap_reply(&d, &dlen, &xc);
    bool res = dlen == sizeof(sam) && xc.uid_len == 4 && xc.sio_len == 4 && hid_sam_is_pacs_reply(d, dlen);
    res &= hid_sam_print_pacs(d, dlen, &xc, false) == PM3_SUCCESS;
    res &= xc.bit_len == 26 && xc.has_media_type && xc.media_type == 7 && xc.oid_len == 14;
    PrintAndLogEx(NORMAL, "");
    ok &= hid_selftest_check("Extended PACS reply", res);

    // a plain reply is left as is
    d = sam;
    dlen = sizeof(sam);
    memset(&xc, 0, sizeof(xc));
    hid_sam_unwrap_reply(&d, &dlen, &xc);
    ok &= hid_selftest_check("Plain PACS reply", d == sam && dlen == sizeof(sam) && xc.uid_len == 0);

    // legacy image, fake CSN. Kd values computed with Seader's loclass copy
    uint8_t img[HID_MFC_IMAGE_SIZE];
    const uint8_t kd[] = { 0xE3, 0xF3, 0x07, 0x84, 0x4A, 0x0B, 0x62, 0x04 };
    const uint8_t sr_kd[] = { 0xA5, 0xA6, 0x18, 0x98, 0x67, 0xDD, 0xA4, 0x4B };
    const uint8_t blk7[] = { 0x00, 0x00, 0x00, 0x00, 0x06, 0x3E, 0x02, 0xA3 };
    res = hid_build_picopass_image(&cred, false, img) == PM3_SUCCESS;
    res &= memcmp(img, hid_picopass_fake_csn, 8) == 0;
    res &= memcmp(img + (3 * 8), kd, 8) == 0;
    res &= memcmp(img + (6 * 8), hid_picopass_pacs_cfg, 8) == 0;
    res &= memcmp(img + (7 * 8), blk7, 8) == 0;
    ok &= hid_selftest_check("iCLASS legacy image", res);

    // SR image, SIO from iCLASS
    cred.source = HID_SRC_ICLASS;
    cred.uid_len = 8;
    memcpy(cred.uid, "\xE4\x4B\x44\x03\xF8\xFF\x12\xE0", 8);
    cred.sio_len = 10;
    memcpy(cred.sio, "\x30\x08\x81\x01\x01\xA6\x03\x81\x01\x02", 10);
    res = hid_build_picopass_image(&cred, true, img) == PM3_SUCCESS;
    res &= memcmp(img, cred.uid, 8) == 0;
    res &= memcmp(img + (3 * 8), sr_kd, 8) == 0;
    res &= img[6 * 8] == 0xA3;
    res &= memcmp(img + (10 * 8), cred.sio, cred.sio_len) == 0;
    ok &= hid_selftest_check("iCLASS SR image", res);

    // an SR SIO must fit blocks 10 - 17
    cred.sio_len = 65;
    ok &= hid_selftest_check("iCLASS SR SIO too long", hid_build_picopass_image(&cred, true, img) != PM3_SUCCESS);
    cred.sio_len = 0;

    // MFC image, blocks as hf mf encodehid writes them
    const uint8_t blk5[] = { 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06, 0x3E, 0x02, 0xA3 };
    res = hid_build_mfc_image(&cred, img) == PM3_SUCCESS;
    res &= memcmp(img, hid_mfc_manuf_block, 16) == 0;
    res &= (img[0] ^ img[1] ^ img[2] ^ img[3]) == img[4];
    res &= memcmp(img + (1 * 16), hid_mfc_mad_block, 16) == 0;
    res &= memcmp(img + (5 * 16), blk5, 16) == 0;
    res &= memcmp(img + (7 * 16), hid_mfc_sector1_trailer, 16) == 0;
    res &= memcmp(img + (63 * 16), hid_mfc_trailer, 16) == 0;
    ok &= hid_selftest_check("MIFARE Classic image", res);

    // 64 bits leave no room for the iCLASS sentinel
    memset(&cred, 0, sizeof(cred));
    memset(cred.binstr, '1', 64);
    cred.bit_len = 64;
    ok &= hid_selftest_check("iCLASS 64 bit rejected", hid_build_picopass_image(&cred, false, img) != PM3_SUCCESS);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(ok ? SUCCESS : FAILED, "Tests ( %s )", ok ? _GREEN_("ok") : _RED_("fail"));
    return ok ? PM3_SUCCESS : PM3_ESOFT;
}
