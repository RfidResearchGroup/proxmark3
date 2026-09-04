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
// High frequency Electronic Machine Readable Travel Document commands
//-----------------------------------------------------------------------------

// This code is heavily based on mrpkey.py of RFIDIOt

#include "cmdhfemrtd.h"
#include <ctype.h>
#include "fileutils.h"              // saveFile
#include "cmdparser.h"              // command_t
#include "cmdtrace.h"               // CmdTraceList
#include "cliparser.h"              // CLIParserContext etc
#include "protocols.h"              // definitions of ISO14A/7816 protocol
#include "iso7816/apduinfo.h"       // GetAPDUCodeDescription
#include "iso7816/iso7816core.h"    // Iso7816ExchangeEx etc
#include "crypto/libpcrypto.h"      // Hash calculation (sha1, sha256, sha512), des_encrypt/des_decrypt
#include "emrtd/emrtd_pace.h"       // PACE primitives and secure messaging session
#include "emrtd/emrtd_pacetest.h"   // emrtd_test
#include "des.h"                    // mbedtls_des_key_set_parity
#include "crapto1/crapto1.h"        // prng_successor
#include "commonutil.h"             // num_to_bytes
#include "util_posix.h"             // msclock
#include "ui.h"                     // search home directory
#include "proxgui.h"                // Picture Window

// Max file size in bytes. Used in several places.
// Average EF_DG2 seems to be around 20-25kB or so, but ICAO doesn't set an upper limit
// Iris data seems to be suggested to be around 35kB per eye (Presumably bumping up the file size to around 70kB)
// but as we cannot read that until we implement PACE, 35k seems to be a safe point.
#define EMRTD_MAX_FILE_SIZE 70000

// ISO7816 commands
#define EMRTD_P1_SELECT_BY_EF       0x02
#define EMRTD_P1_SELECT_BY_NAME     0x04
#define EMRTD_P2_PROPRIETARY        0x0C

// App IDs
#define EMRTD_AID_MRTD {0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01}

#define EMRTD_KMAC_LEN              16

// DESKey Types
static const uint8_t KENC_type[4] = {0x00, 0x00, 0x00, 0x01};
static const uint8_t KMAC_type[4] = {0x00, 0x00, 0x00, 0x02};

/*
* BAC = Basic Access Control
* PA = Passive Authentication
* AA = Active Authentication
* EAC = Extended Access Control
* SAC = Suppliment Access Control

File structures
----------------
 Mastefile MF
  -- EF.ATR/INFO (01)
  -- EF.DIR (1E)
  -- EF.CardSecurity (1D)
  -- EF.CardAccess (1C)
  Data Files DF
    -- eMRTD Application DF (AID: )
    -- Travel Records Application DF (AID: A0 00 00 02 47 20 01)
      - EF.Certificates (1A)
      - EF.EntryRecords (01)
      - EF.ExitRecords (02)
    -- Visa Records Application DF (AID: A0 00 00 02 47 20 02)
      - EF.Certificates (1A)
      - EF.ExitRecords (03)
    -- Additional Biometrics Application DF (AID: ‘A0 00 00 02 47 20 03)
      - EF.Certificates (011A)
      - EF.Biometrics1  (0201)
      - EF.Biometrics2  (0202)
      - EF.Biometrics64 (0240)

eMRTD Application DF
-----------------------
File names and what they contain
  EG.COM = Common data
  EG.DG1 = MRZ data
  EG.DG2 = Biometric template, Photo
  EG.DG3 = Biometric template, Fingerprint (EAC / AA)
  EG.DG4 = Biometric template, Iris (EAC / AA)
  EG.DG5 = Image template
  EG.DG6 = Image template
  EG.DG7 = Image template (Signature?)
  EG.DG8 = Data Feature
  EG.DG9 = Structure Feature
  EG.DG10 = Substance Feature
  EG.DG11 = Additional personal details
  EG.DG12 = Additional Document Detail
  EG.DG13 = Optional Details
  EG.DG14 = Security Options
  EG.DG15 = AA public key
  EG.DG16 = Persons to notify
  EG.SOD = Security, signatures of all data files


*/
const char *pad = ".....................................";

static int emrtd_dump_ef_dg2(uint8_t *file_contents, size_t file_length, const char *path);
static int emrtd_dump_ef_dg5(uint8_t *file_contents, size_t file_length, const char *path);
static int emrtd_dump_ef_dg7(uint8_t *file_contents, size_t file_length, const char *path);
static int emrtd_dump_ef_sod(uint8_t *file_contents, size_t file_length, const char *path);
static int emrtd_print_ef_com_info(uint8_t *data, size_t datalen);
static int emrtd_print_ef_dg1_info(uint8_t *data, size_t datalen);
static int emrtd_print_ef_dg2_info(uint8_t *data, size_t datalen);
static int emrtd_print_ef_dg5_info(uint8_t *data, size_t datalen);
static int emrtd_print_ef_dg7_info(uint8_t *data, size_t datalen);
static int emrtd_print_ef_dg11_info(uint8_t *data, size_t datalen);
static int emrtd_print_ef_dg12_info(uint8_t *data, size_t datalen);
static int emrtd_print_ef_cardaccess_info(uint8_t *data, size_t datalen);

typedef enum  { // list must match dg_table
    EF_COM = 0,
    EF_DG1,
    EF_DG2,
    EF_DG3,
    EF_DG4,
    EF_DG5,
    EF_DG6,
    EF_DG7,
    EF_DG8,
    EF_DG9,
    EF_DG10,
    EF_DG11,
    EF_DG12,
    EF_DG13,
    EF_DG14,
    EF_DG15,
    EF_DG16,
    EF_SOD,
    EF_CardAccess,
    EF_CardSecurity,
} emrtd_dg_enum;

static emrtd_dg_t dg_table[] = {
//  tag    dg# fileid  filename           desc                                                  pace   eac    req    fast   parser                          dumper
    {0x60, 0,  0x011E, "EF_COM",          "Header and Data Group Presence Information",         false, false, true,  true,  emrtd_print_ef_com_info,        NULL},
    {0x61, 1,  0x0101, "EF_DG1",          "Details recorded in MRZ",                            false, false, true,  true,  emrtd_print_ef_dg1_info,        NULL},
    {0x75, 2,  0x0102, "EF_DG2",          "Encoded Face",                                       false, false, true,  false, emrtd_print_ef_dg2_info,        emrtd_dump_ef_dg2},
    {0x63, 3,  0x0103, "EF_DG3",          "Encoded Finger(s)",                                  false, true,  false, false, NULL,                           NULL},
    {0x76, 4,  0x0104, "EF_DG4",          "Encoded Eye(s)",                                     false, true,  false, false, NULL,                           NULL},
    {0x65, 5,  0x0105, "EF_DG5",          "Displayed Portrait",                                 false, false, false, false, emrtd_print_ef_dg5_info,        emrtd_dump_ef_dg5},
    {0x66, 6,  0x0106, "EF_DG6",          "Reserved for Future Use",                            false, false, false, false, NULL,                           NULL},
    {0x67, 7,  0x0107, "EF_DG7",          "Displayed Signature or Usual Mark",                  false, false, false, false, emrtd_print_ef_dg7_info,        emrtd_dump_ef_dg7},
    {0x68, 8,  0x0108, "EF_DG8",          "Data Feature(s)",                                    false, false, false, true,  NULL,                           NULL},
    {0x69, 9,  0x0109, "EF_DG9",          "Structure Feature(s)",                               false, false, false, true,  NULL,                           NULL},
    {0x6a, 10, 0x010A, "EF_DG10",         "Substance Feature(s)",                               false, false, false, true,  NULL,                           NULL},
    {0x6b, 11, 0x010B, "EF_DG11",         "Additional Personal Detail(s)",                      false, false, false, true,  emrtd_print_ef_dg11_info,       NULL},
    {0x6c, 12, 0x010C, "EF_DG12",         "Additional Document Detail(s)",                      false, false, false, true,  emrtd_print_ef_dg12_info,       NULL},
    {0x6d, 13, 0x010D, "EF_DG13",         "Optional Detail(s)",                                 false, false, false, true,  NULL,                           NULL},
    {0x6e, 14, 0x010E, "EF_DG14",         "Security Options",                                   false, false, false, true,  NULL,                           NULL},
    {0x6f, 15, 0x010F, "EF_DG15",         "Active Authentication Public Key Info",              false, false, false, true,  NULL,                           NULL},
    {0x70, 16, 0x0110, "EF_DG16",         "Person(s) to Notify",                                false, false, false, true,  NULL,                           NULL},
    {0x77, 0,  0x011D, "EF_SOD",          "Document Security Object",                           false, false, false, false, NULL,                           emrtd_dump_ef_sod},
    {0xff, 0,  0x011C, "EF_CardAccess",   "PACE SecurityInfos",                                 true,  false, true,  true,  emrtd_print_ef_cardaccess_info, NULL},
    {0xff, 0,  0x011D, "EF_CardSecurity", "PACE SecurityInfos for Chip Authentication Mapping", true,  false, false, true,  NULL,                           NULL},
    {0x00, 0,  0, NULL, NULL, false, false, false, false, NULL, NULL}
};

// https://security.stackexchange.com/questions/131241/where-do-magic-constants-for-signature-algorithms-come-from
// https://tools.ietf.org/html/rfc3447#page-43
static emrtd_hashalg_t hashalg_table[] = {
//  name        hash func   len len descriptor
    {"SHA-1",   sha1hash,   20,  7, {0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A}},
    {"SHA-256", sha256hash, 32, 11, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}},
    {"SHA-512", sha512hash, 64, 11, {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}},
    {NULL,      NULL,       0,  0,  {0}}
};

static emrtd_dg_t *emrtd_tag_to_dg(uint8_t tag) {
    for (int dgi = 0; dg_table[dgi].filename != NULL; dgi++) {
        if (dg_table[dgi].tag == tag) {
            return &dg_table[dgi];
        }
    }
    return NULL;
}
static emrtd_dg_t *emrtd_fileid_to_dg(uint16_t file_id) {
    for (int dgi = 0; dg_table[dgi].filename != NULL; dgi++) {
        if (dg_table[dgi].fileid == file_id) {
            return &dg_table[dgi];
        }
    }
    return NULL;
}

static int CmdHelp(const char *Cmd);

static bool emrtd_exchange_commands(sAPDU_t apdu, bool include_le, uint16_t le, uint8_t *dataout, size_t maxdataoutlen, size_t *dataoutlen, bool activate_field, bool keep_field_on) {
    uint16_t sw;
    int res = Iso7816ExchangeEx(CC_CONTACTLESS, activate_field, keep_field_on, apdu, include_le, le, dataout, maxdataoutlen, dataoutlen, &sw);

    if (res != PM3_SUCCESS) {
        return false;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(DEBUG, "Command failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return false;
    }
    return true;
}

static int emrtd_exchange_commands_noout(sAPDU_t apdu, bool activate_field, bool keep_field_on) {
    uint8_t response[PM3_CMD_DATA_SIZE] = {0};
    size_t resplen = 0;
    return emrtd_exchange_commands(apdu, false, 0, response, 0, &resplen, activate_field, keep_field_on);
}

static int emrtd_get_asn1_data_length(uint8_t *datain, int datainlen, int offset) {
    PrintAndLogEx(DEBUG, "asn1 datalength, datain: %s", sprint_hex_inrow(datain, datainlen));
    int lenfield = (int) * (datain + offset);
    PrintAndLogEx(DEBUG, "asn1 datalength, lenfield: %02X", lenfield);
    if (lenfield <= 0x7f) {
        return lenfield;
    } else if (lenfield == 0x80) {
        // TODO: 0x80 means indeterminate, and this impl is a workaround.
        // Giving rest of the file is a workaround, nothing more, nothing less.
        // https://wf.lavatech.top/ave-but-random/emrtd-data-quirks#EF_SOD
        return datainlen;
    } else if (lenfield == 0x81) {
        int tmp = (*(datain + offset + 1));
        return tmp;
        //return ((int) * (datain + offset + 1));
    } else if (lenfield == 0x82) {
        int tmp = (*(datain + offset + 1) << 8);
        tmp |= *(datain + offset + 2);
        return tmp;
        //return ((int) * (datain + offset + 1) << 8) | ((int) * (datain + offset + 2));
    } else if (lenfield == 0x83) {
        int tmp = (*(datain + offset + 1) << 16);
        tmp |= (*(datain + offset + 2) << 8);
        tmp |= *(datain + offset + 3);
        return tmp;
        //return (((int) * (datain + offset + 1) << 16) | ((int) * (datain + offset + 2)) << 8) | ((int) * (datain + offset + 3));
    }
    return 0;
}

static int emrtd_get_asn1_field_length(uint8_t *datain, int datainlen, int offset) {
    PrintAndLogEx(DEBUG, "asn1 fieldlength, datain: %s", sprint_hex_inrow(datain, datainlen));
    int lenfield = (int) * (datain + offset);
    PrintAndLogEx(DEBUG, "asn1 fieldlength, lenfield: %02X", lenfield);
    if (lenfield <= 0x80) {
        return 1;
    } else if (lenfield == 0x81) {
        return 2;
    } else if (lenfield == 0x82) {
        return 3;
    } else if (lenfield == 0x83) {
        return 4;
    }
    return 0;
}

static void emrtd_deskey(uint8_t *seed, const uint8_t *type, int length, uint8_t *dataout) {
    PrintAndLogEx(DEBUG, "seed.............. %s", sprint_hex_inrow(seed, 16));

    // combine seed and type
    uint8_t data[50] = { 0x00 };
    memcpy(data, seed, length);
    memcpy(data + length, type, 4);
    PrintAndLogEx(DEBUG, "data.............. %s", sprint_hex_inrow(data, length + 4));

    // SHA1 the key
    unsigned char key[64] = { 0x00 };
    sha1hash(data, length + 4, key);
    PrintAndLogEx(DEBUG, "key............... %s", sprint_hex_inrow(key, length + 4));

    // Set parity bits
    for (int i = 0; i < ((length + 4) / 8); i++) {
        mbedtls_des_key_set_parity(key + (i * 8));
    }
    PrintAndLogEx(DEBUG, "post-parity key... %s", sprint_hex_inrow(key, 20));

    memcpy(dataout, &key, length);
}

static void _emrtd_convert_fileid(uint16_t file, uint8_t *dataout) {
    dataout[0] = file >> 8;
    dataout[1] = file & 0xFF;
}

static int emrtd_select_file_by_name(uint8_t namelen, uint8_t *name) {
    return emrtd_exchange_commands_noout((sAPDU_t) {0, ISO7816_SELECT_FILE, EMRTD_P1_SELECT_BY_NAME, 0x0C, namelen, name}, false, true);
}

static int emrtd_select_file_by_ef(uint16_t file_id) {
    uint8_t data[2];
    _emrtd_convert_fileid(file_id, data);
    return emrtd_exchange_commands_noout((sAPDU_t) {0, ISO7816_SELECT_FILE, EMRTD_P1_SELECT_BY_EF, 0x0C, sizeof(data), data}, false, true);
}

static int emrtd_get_challenge(int length, uint8_t *dataout, size_t maxdataoutlen, size_t *dataoutlen) {
    return emrtd_exchange_commands((sAPDU_t) {0, ISO7816_GET_CHALLENGE, 0, 0, 0, NULL}, true, length, dataout, maxdataoutlen, dataoutlen, false, true);
}

static int emrtd_external_authenticate(uint8_t *data, int length, uint8_t *dataout, size_t maxdataoutlen, size_t *dataoutlen) {
    return emrtd_exchange_commands((sAPDU_t) {0, ISO7816_EXTERNAL_AUTHENTICATION, 0, 0, length, data}, true, length, dataout, maxdataoutlen, dataoutlen, false, true);
}

static int _emrtd_read_binary(int offset, int bytes_to_read, uint8_t *dataout, size_t maxdataoutlen, size_t *dataoutlen) {
    return emrtd_exchange_commands((sAPDU_t) {0, ISO7816_READ_BINARY, offset >> 8, offset & 0xFF, 0, NULL}, true, bytes_to_read, dataout, maxdataoutlen, dataoutlen, false, true);
}

// Walks the secure messaging response DOs. Returns the offset of DO'8E' and,
// when present, the offset and length of the encrypted data object DO'87'.
static bool emrtd_sm_split_rapdu(const uint8_t *rapdu, size_t rapdulen, size_t *off8e,
                                 const uint8_t **do87, size_t *do87len) {
    const uint8_t *cur = rapdu;
    const uint8_t *end = rapdu + rapdulen;
    uint32_t tag = 0;
    const uint8_t *val = NULL;
    size_t vlen = 0;

    *do87 = NULL;
    *do87len = 0;

    while (cur < end) {
        const uint8_t *tlvstart = cur;
        if (emrtd_tlv_next(&cur, end, &tag, &val, &vlen) == false) {
            PrintAndLogEx(DEBUG, "SM: malformed response DO at offset %zu", (size_t)(tlvstart - rapdu));
            return false;
        }

        if (tag == 0x8E) {
            if (vlen != 8) {
                PrintAndLogEx(DEBUG, "SM: DO'8E' has unexpected length %zu", vlen);
                return false;
            }
            *off8e = (size_t)(tlvstart - rapdu);
            return true;
        }

        if (tag == 0x87) {
            *do87 = val;
            *do87len = vlen;
        }
    }

    PrintAndLogEx(DEBUG, "SM: response has no DO'8E'");
    return false;
}

// ICAO 9303-11 9.8.6: MAC over SSC || every response DO that precedes DO'8E'
static bool emrtd_check_cc(emrtd_session_t *ssn, uint8_t *rapdu, size_t rapdulength) {
    // https://elixi.re/i/clarkson.png
    uint8_t k[EMRTD_SM_MAX_BLOCK_LEN + 512] = { 0x00 };
    uint8_t cc[8] = { 0x00 };
    size_t off8e = 0;
    const uint8_t *do87 = NULL;
    size_t do87len = 0;

    emrtd_sm_bump_ssc(ssn);

    if (emrtd_sm_split_rapdu(rapdu, rapdulength, &off8e, &do87, &do87len) == false) {
        return false;
    }

    if ((ssn->ssclen + off8e) > sizeof(k)) {
        PrintAndLogEx(ERR, "error (emrtd_check_cc) response out-of-bounds");
        return false;
    }

    memcpy(k, ssn->ssc, ssn->ssclen);
    memcpy(k + ssn->ssclen, rapdu, off8e);
    size_t klength = ssn->ssclen + off8e;

    if (emrtd_sm_mac(ssn, k, klength, cc) != PM3_SUCCESS) {
        return false;
    }

    PrintAndLogEx(DEBUG, "cc: %s", sprint_hex_inrow(cc, 8));
    PrintAndLogEx(DEBUG, "rapdu: %s", sprint_hex_inrow(rapdu, rapdulength));
    PrintAndLogEx(DEBUG, "rapdu cc: %s", sprint_hex_inrow(rapdu + off8e + 2, 8));
    PrintAndLogEx(DEBUG, "k: %s", sprint_hex_inrow(k, klength));

    return memcmp(cc, rapdu + off8e + 2, 8) == 0;
}

// Builds the trailing DO'8E' of a protected command over
// SSC || padded command header || the command DOs
static bool emrtd_sm_finish_command(emrtd_session_t *ssn, const uint8_t *header, const uint8_t *dos,
                                    size_t doslen, uint8_t *out, size_t outlen, size_t *lc) {
    uint8_t n[EMRTD_SM_MAX_BLOCK_LEN * 2 + 64] = { 0x00 };
    size_t blocksize = emrtd_sm_blocksize(ssn);
    size_t nlen = 0;

    if ((ssn->ssclen + blocksize + doslen) > sizeof(n)) {
        PrintAndLogEx(ERR, "error (emrtd_sm_finish_command) command out-of-bounds");
        return false;
    }

    memcpy(n, ssn->ssc, ssn->ssclen);
    nlen += ssn->ssclen;
    nlen += emrtd_pad_block(header, 4, blocksize, n + nlen);
    memcpy(n + nlen, dos, doslen);
    nlen += doslen;
    PrintAndLogEx(DEBUG, "n: %s", sprint_hex_inrow(n, nlen));

    uint8_t cc[8] = { 0x00 };
    if (emrtd_sm_mac(ssn, n, nlen, cc) != PM3_SUCCESS) {
        return false;
    }
    PrintAndLogEx(DEBUG, "cc: %s", sprint_hex_inrow(cc, 8));

    if ((doslen + 10) > outlen) {
        PrintAndLogEx(ERR, "error (emrtd_sm_finish_command) data out-of-bounds");
        return false;
    }

    memcpy(out, dos, doslen);
    out[doslen] = 0x8E;
    out[doslen + 1] = 0x08;
    memcpy(out + doslen + 2, cc, 8);
    *lc = doslen + 10;
    PrintAndLogEx(DEBUG, "data: %s", sprint_hex_inrow(out, *lc));
    return true;
}

static bool emrtd_secure_select(emrtd_session_t *ssn, uint8_t p1, const uint8_t *sel, size_t sellen);

static bool emrtd_secure_select_file_by_ef(emrtd_session_t *ssn, uint16_t file) {
    uint8_t file_id[2] = { 0x00 };
    _emrtd_convert_fileid(file, file_id);
    return emrtd_secure_select(ssn, EMRTD_P1_SELECT_BY_EF, file_id, sizeof(file_id));
}

static bool _emrtd_secure_read_binary(emrtd_session_t *ssn, int offset, int bytes_to_read, uint8_t *dataout, size_t maxdataoutlen, size_t *dataoutlen) {
    const uint8_t header[4] = {0x0C, ISO7816_READ_BINARY, (uint8_t)(offset >> 8), (uint8_t)(offset & 0xFF)};
    uint8_t do97[3] = {0x97, 0x01, (uint8_t)bytes_to_read};

    emrtd_sm_bump_ssc(ssn);

    uint8_t data[16] = { 0x00 };
    size_t lc = 0;
    if (emrtd_sm_finish_command(ssn, header, do97, sizeof(do97), data, sizeof(data), &lc) == false) {
        return false;
    }

    if (emrtd_exchange_commands((sAPDU_t) {0x0C, ISO7816_READ_BINARY, offset >> 8, offset & 0xFF, lc, data}, true, 0, dataout, maxdataoutlen, dataoutlen, false, true) == false) {
        return false;
    }

    return emrtd_check_cc(ssn, dataout, *dataoutlen);
}

static bool _emrtd_secure_read_binary_decrypt(emrtd_session_t *ssn, int offset, int bytes_to_read, uint8_t *dataout, size_t *dataoutlen) {
    uint8_t response[500] = { 0x00 };
    uint8_t temp[500] = { 0x00 };
    size_t resplen = 0;
    size_t off8e = 0;
    const uint8_t *do87 = NULL;
    size_t do87len = 0;

    if (_emrtd_secure_read_binary(ssn, offset, bytes_to_read, response, sizeof(response), &resplen) == false) {
        return false;
    }

    PrintAndLogEx(DEBUG, "secreadbindec, offset %i on read %i: encrypted: %s", offset, bytes_to_read, sprint_hex_inrow(response, resplen));

    if (emrtd_sm_split_rapdu(response, resplen, &off8e, &do87, &do87len) == false) {
        return false;
    }

    // DO'87' content is 01 || cryptogram
    if ((do87 == NULL) || (do87len < 2) || (do87[0] != 0x01)) {
        PrintAndLogEx(ERR, "error (emrtd_secure_read_binary_decrypt) no encrypted data in response");
        return false;
    }

    size_t cryptolen = do87len - 1;
    if ((cryptolen > sizeof(temp)) || ((cryptolen % emrtd_sm_blocksize(ssn)) != 0)) {
        PrintAndLogEx(ERR, "error (emrtd_secure_read_binary_decrypt) cryptogram out-of-bounds, %zu bytes", cryptolen);
        return false;
    }

    if ((size_t)bytes_to_read > cryptolen) {
        PrintAndLogEx(ERR, "error (emrtd_secure_read_binary_decrypt) short read, wanted %i got %zu", bytes_to_read, cryptolen);
        return false;
    }

    if (emrtd_sm_decrypt(ssn, do87 + 1, cryptolen, temp) != PM3_SUCCESS) {
        return false;
    }

    memcpy(dataout, temp, bytes_to_read);
    PrintAndLogEx(DEBUG, "secreadbindec, offset %i on read %i: decrypted: %s", offset, bytes_to_read, sprint_hex_inrow(temp, cryptolen));
    PrintAndLogEx(DEBUG, "secreadbindec, offset %i on read %i: decrypted and cut: %s", offset, bytes_to_read, sprint_hex_inrow(dataout, bytes_to_read));
    *dataoutlen = bytes_to_read;
    return true;
}

static int emrtd_read_file(uint8_t *dataout, size_t *dataoutlen, emrtd_session_t *ssn) {
    uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    size_t resplen = 0;
    uint8_t tempresponse[500] = { 0x00 };
    size_t tempresplen = 0;
    int toread = 4;
    int offset = 0;
    bool use_secure = (ssn->type != EMRTD_SM_NONE);

    if (use_secure) {
        if (_emrtd_secure_read_binary_decrypt(ssn, offset, toread, response, &resplen) == false) {
            return false;
        }
    } else {
        if (_emrtd_read_binary(offset, toread, response, sizeof(response), &resplen) == false) {
            return false;
        }
    }

    int datalen = emrtd_get_asn1_data_length(response, resplen, 1);
    int readlen = datalen - (3 - emrtd_get_asn1_field_length(response, resplen, 1));
    offset = 4;

    uint8_t lnbreak = 32;
    PrintAndLogEx(INFO, "." NOLF);
    while (readlen > 0) {
        toread = readlen;
        if (readlen > 118) {
            toread = 118;
        }

        if (use_secure) {
            if (_emrtd_secure_read_binary_decrypt(ssn, offset, toread, tempresponse, &tempresplen) == false) {
                PrintAndLogEx(NORMAL, "");
                return false;
            }
        } else {
            if (_emrtd_read_binary(offset, toread, tempresponse, sizeof(tempresponse), &tempresplen) == false) {
                PrintAndLogEx(NORMAL, "");
                return false;
            }
        }

        memcpy(response + resplen, tempresponse, tempresplen);
        offset += toread;
        readlen -= toread;
        resplen += tempresplen;

        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
        lnbreak--;
        if (lnbreak == 0) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "." NOLF);
            lnbreak = 32;
        }
    }
    PrintAndLogEx(NORMAL, "");

    memcpy(dataout, &response, resplen);
    *dataoutlen = resplen;
    return true;
}

static int emrtd_lds_determine_tag_length(uint8_t tag) {
    if ((tag == 0x5F) || (tag == 0x7F)) {
        return 2;
    }
    return 1;
}

static bool emrtd_lds_get_data_by_tag(uint8_t *datain, size_t datainlen, uint8_t *dataout, size_t *dataoutlen, int tag1, int tag2, bool twobytetag, bool entertoptag, size_t skiptagcount) {
    int offset = 0;
    int skipcounter = 0;

    if (entertoptag) {
        offset += emrtd_lds_determine_tag_length(*datain);
        offset += emrtd_get_asn1_field_length(datain, datainlen, offset);
    }

    while (offset < datainlen) {
        PrintAndLogEx(DEBUG, "emrtd_lds_get_data_by_tag, offset: %i, data: %X", offset, *(datain + offset));
        // Determine element ID length to set as offset on asn1datalength
        int e_idlen = emrtd_lds_determine_tag_length(*(datain + offset));

        // Get the length of the element
        int e_datalen = emrtd_get_asn1_data_length(datain + offset, datainlen - offset, e_idlen);

        // Get the length of the element's length
        int e_fieldlen = emrtd_get_asn1_field_length(datain + offset, datainlen - offset, e_idlen);

        PrintAndLogEx(DEBUG, "emrtd_lds_get_data_by_tag, e_idlen: %02X, e_datalen: %02X, e_fieldlen: %02X", e_idlen, e_datalen, e_fieldlen);

        // If the element is what we're looking for, get the data and return true
        if (*(datain + offset) == tag1 && (!twobytetag || *(datain + offset + 1) == tag2)) {
            if (skipcounter < skiptagcount) {
                skipcounter += 1;
            } else if (datainlen > e_datalen) {
                *dataoutlen = e_datalen;
                memcpy(dataout, datain + offset + e_idlen + e_fieldlen, e_datalen);
                return true;
            } else {
                PrintAndLogEx(ERR, "error (emrtd_lds_get_data_by_tag) e_datalen out-of-bounds");
                return false;
            }
        }
        offset += e_idlen + e_datalen + e_fieldlen;
    }
    // Return false if we can't find the relevant element
    return false;
}

static bool emrtd_select_and_read(uint8_t *dataout, size_t *dataoutlen, uint16_t file, emrtd_session_t *ssn) {
    if (ssn->type != EMRTD_SM_NONE) {
        if (emrtd_secure_select_file_by_ef(ssn, file) == false) {
            PrintAndLogEx(ERR, "Failed to secure select %04X", file);
            return false;
        }
    } else {
        if (emrtd_select_file_by_ef(file) == false) {
            PrintAndLogEx(ERR, "Failed to select %04X", file);
            return false;
        }
    }

    if (emrtd_read_file(dataout, dataoutlen, ssn) == false) {
        PrintAndLogEx(ERR, "Failed to read %04X", file);
        return false;
    }
    return true;
}

static const uint8_t jpeg_header[4] = { 0xFF, 0xD8, 0xFF, 0xE0 };
static const uint8_t jpeg2k_header[6] = { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50 };
static const uint8_t jpeg2k_cs_header[4] = { 0xFF, 0x4F, 0xFF, 0x51 };

static int emrtd_dump_ef_dg2(uint8_t *file_contents, size_t file_length, const char *path) {
    size_t offset;
    int datalen = 0;
    char suffix[5] = { '\0' };

    // This is a hacky impl that just looks for the image header. I'll improve it eventually.
    // based on mrpkey.py
    // Note: Doing file_length - 6 to account for the longest data we're checking.
    // Checks first byte before the rest to reduce overhead
    for (offset = 0; offset < file_length - 6; offset++) {
        if (file_contents[offset] == 0xFF) {
            if (memcmp(jpeg_header, file_contents + offset, 4) == 0) {
                datalen = file_length - offset;
                strcpy(suffix, ".jpg");
                break;
            } else if (memcmp(jpeg2k_cs_header, file_contents + offset, 4) == 0) {
                datalen = file_length - offset;
                // no standardized extension for codestream data, using .jpc
                strcpy(suffix, ".jpc");
                break;
            }
        } else if (file_contents[offset] == 0x00 && memcmp(jpeg2k_header, file_contents + offset, 6) == 0) {
            strcpy(suffix, ".jp2");
            datalen = file_length - offset;
            break;
        }
    }
    // If we didn't get any data, return false.
    if (datalen == 0) {
        return PM3_ESOFT;
    }

    char *filepath = calloc(strlen(path) + 100, sizeof(char));
    if (filepath == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    strcpy(filepath, path);
    strncat(filepath, PATHSEP, 2);
    strcat(filepath, dg_table[EF_DG2].filename);

    saveFile(filepath, suffix, file_contents + offset, datalen);

    free(filepath);
    return PM3_SUCCESS;
}

static int emrtd_dump_ef_dg5(uint8_t *file_contents, size_t file_length, const char *path) {
    uint8_t data[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    size_t datalen = 0;

    // If we can't find image in EF_DG5, return false.
    if (emrtd_lds_get_data_by_tag(file_contents, file_length, data, &datalen, 0x5F, 0x40, true, true, 0) == false) {
        return PM3_ESOFT;
    }

    if (datalen < EMRTD_MAX_FILE_SIZE) {
        char *filepath = calloc(strlen(path) + 100, sizeof(char));
        if (filepath == NULL) {
            PrintAndLogEx(WARNING, "Failed to allocate memory");
            return PM3_EMALLOC;
        }
        strcpy(filepath, path);
        strncat(filepath, PATHSEP, 2);
        strcat(filepath, dg_table[EF_DG5].filename);

        saveFile(filepath, data[0] == 0xFF ? ".jpg" : ".jp2", data, datalen);

        free(filepath);
    } else {
        PrintAndLogEx(ERR, "error (emrtd_dump_ef_dg5) datalen out-of-bounds");
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int emrtd_dump_ef_dg7(uint8_t *file_contents, size_t file_length, const char *path) {
    uint8_t data[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    size_t datalen = 0;

    // If we can't find image in EF_DG7, return false.
    if (emrtd_lds_get_data_by_tag(file_contents, file_length, data, &datalen, 0x5F, 0x42, true, true, 0) == false) {
        return PM3_ESOFT;
    }

    if (datalen < EMRTD_MAX_FILE_SIZE) {
        char *filepath = calloc(strlen(path) + 100, sizeof(char));
        if (filepath == NULL) {
            PrintAndLogEx(WARNING, "Failed to allocate memory");
            return PM3_EMALLOC;
        }
        strcpy(filepath, path);
        strncat(filepath, PATHSEP, 2);
        strcat(filepath, dg_table[EF_DG7].filename);

        saveFile(filepath, data[0] == 0xFF ? ".jpg" : ".jp2", data, datalen);

        free(filepath);
    } else {
        PrintAndLogEx(ERR, "error (emrtd_dump_ef_dg7) datalen out-of-bounds");
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int emrtd_dump_ef_sod(uint8_t *file_contents, size_t file_length, const char *path) {
    int fieldlen = emrtd_get_asn1_field_length(file_contents, file_length, 1);
    int datalen = emrtd_get_asn1_data_length(file_contents, file_length, 1);

    if (fieldlen + 1 > EMRTD_MAX_FILE_SIZE) {
        PrintAndLogEx(ERR, "error (emrtd_dump_ef_sod) fieldlen out-of-bounds");
        return PM3_EOUTOFBOUND;
    }

    char *filepath = calloc(strlen(path) + 100, sizeof(char));
    if (filepath == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    strcpy(filepath, path);
    strncat(filepath, PATHSEP, 2);
    strcat(filepath, dg_table[EF_SOD].filename);

    saveFile(filepath, ".p7b", file_contents + fieldlen + 1, datalen);
    free(filepath);
    return PM3_ESOFT;
}

static bool emrtd_save_file(uint8_t *response, size_t resplen, uint16_t file, const char *name, const char *path) {
    char *filepath = calloc(strlen(path) + 100, sizeof(char));
    if (filepath == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return false;
    }

    strcpy(filepath, path);
    strncat(filepath, PATHSEP, 2);
    strcat(filepath, name);

    PrintAndLogEx(INFO, "Read " _YELLOW_("%s") ", len %zu", name, resplen);
    PrintAndLogEx(DEBUG, "Contents (may be incomplete over 2k chars)");
    PrintAndLogEx(DEBUG, "------------------------------------------");
    PrintAndLogEx(DEBUG, "%s", sprint_hex_inrow(response, resplen));
    PrintAndLogEx(DEBUG, "------------------------------------------");
    saveFile(filepath, ".bin", response, resplen);

    emrtd_dg_t *dg = emrtd_fileid_to_dg(file);
    if ((dg != NULL) && (dg->dumper != NULL)) {
        dg->dumper(response, resplen, path);
    }

    free(filepath);
    return true;
}

static bool emrtd_dump_file(emrtd_session_t *ssn, uint16_t file, const char *name, const char *path) {
    uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    size_t resplen = 0;

    if (emrtd_select_and_read(response, &resplen, file, ssn) == false) {
        return false;
    }

    return emrtd_save_file(response, resplen, file, name, path);
}

static void rng(int length, uint8_t *dataout) {
    // Zero nonces are fatal for PACE and were never a good idea for BAC either,
    // so this is a real CSPRNG (mbedtls CTR_DRBG seeded from mbedtls entropy).
    if (pcrypto_rng_fill_oneshot(dataout, length, "emrtd") != PM3_SUCCESS) {
        // Never hand back a predictable nonce, the caller has to fail instead
        memset(dataout, 0x00, length);
        PrintAndLogEx(ERR, "Failed to generate random data");
    }
}

static bool emrtd_do_bac(const char *documentnumber, const char *dob, const char *expiry, emrtd_session_t *ssn) {
    uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    size_t resplen = 0;

    uint8_t rnd_ic[10] = { 0x00 }; // 8 + SW
    uint8_t kenc[50] = { 0x00 };
    uint8_t kmac[50] = { 0x00 };
    uint8_t k_icc[16] = { 0x00 };
    uint8_t S[32] = { 0x00 };

    uint8_t rnd_ifd[8] = { 0x00 };
    uint8_t k_ifd[16] = { 0x00 };
    rng(8, rnd_ifd);
    rng(16, k_ifd);

    PrintAndLogEx(DEBUG, "doc............... " _GREEN_("%s"), documentnumber);
    PrintAndLogEx(DEBUG, "dob............... " _GREEN_("%s"), dob);
    PrintAndLogEx(DEBUG, "exp............... " _GREEN_("%s"), expiry);

    char kmrz[25] = { 0x00 };
    if (emrtd_pace_kmrz(documentnumber, dob, expiry, kmrz, sizeof(kmrz)) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Couldn't build the MRZ information string.");
        return false;
    }
    PrintAndLogEx(DEBUG, "kmrz.............. " _GREEN_("%s"), kmrz);

    uint8_t kseed[20] = { 0x00 };
    sha1hash((unsigned char *)kmrz, strlen(kmrz), kseed);
    PrintAndLogEx(DEBUG, "kseed (sha1)...... %s ", sprint_hex_inrow(kseed, 16));

    emrtd_deskey(kseed, KENC_type, 16, kenc);
    emrtd_deskey(kseed, KMAC_type, 16, kmac);
    PrintAndLogEx(DEBUG, "kenc.............. %s", sprint_hex_inrow(kenc, 16));
    PrintAndLogEx(DEBUG, "kmac.............. %s", sprint_hex_inrow(kmac, 16));

    // Get Challenge
    if (emrtd_get_challenge(8, rnd_ic, sizeof(rnd_ic), &resplen) == false) {
        PrintAndLogEx(ERR, "Couldn't get challenge.");
        return false;
    }
    PrintAndLogEx(DEBUG, "rnd_ic............ %s", sprint_hex_inrow(rnd_ic, 8));

    memcpy(S, rnd_ifd, 8);
    memcpy(S + 8, rnd_ic, 8);
    memcpy(S + 16, k_ifd, 16);

    PrintAndLogEx(DEBUG, "S................. %s", sprint_hex_inrow(S, 32));

    uint8_t iv[8] = { 0x00 };
    uint8_t e_ifd[32] = { 0x00 };

    emrtd_des3_encrypt_cbc(iv, kenc, S, sizeof(S), e_ifd);
    PrintAndLogEx(DEBUG, "e_ifd............. %s", sprint_hex_inrow(e_ifd, 32));

    uint8_t m_ifd[8] = { 0x00 };

    emrtd_retail_mac(kmac, e_ifd, 32, m_ifd);
    PrintAndLogEx(DEBUG, "m_ifd............. %s", sprint_hex_inrow(m_ifd, 8));

    uint8_t cmd_data[40];
    memcpy(cmd_data, e_ifd, 32);
    memcpy(cmd_data + 32, m_ifd, 8);

    // Do external authentication
    if (emrtd_external_authenticate(cmd_data, sizeof(cmd_data), response, sizeof(response), &resplen) == false) {
        PrintAndLogEx(ERR, "Couldn't do external authentication. Did you supply the correct MRZ info?");
        return false;
    }
    PrintAndLogEx(INFO, "External authentication with BAC successful");

    uint8_t dec_output[32] = { 0x00 };
    emrtd_des3_decrypt_cbc(iv, kenc, response, 32, dec_output);
    PrintAndLogEx(DEBUG, "dec_output........ %s", sprint_hex_inrow(dec_output, 32));

    if (memcmp(rnd_ifd, dec_output + 8, 8) != 0) {
        PrintAndLogEx(ERR, "Challenge failed, rnd_ifd does not match.");
        return false;
    }

    memcpy(k_icc, dec_output + 16, 16);

    // Calculate session keys
    for (int x = 0; x < 16; x++) {
        kseed[x] = k_ifd[x] ^ k_icc[x];
    }

    PrintAndLogEx(DEBUG, "kseed............ %s", sprint_hex_inrow(kseed, 16));

    uint8_t ks_enc[EMRTD_KMAC_LEN] = { 0x00 };
    uint8_t ks_mac[EMRTD_KMAC_LEN] = { 0x00 };
    emrtd_deskey(kseed, KENC_type, 16, ks_enc);
    emrtd_deskey(kseed, KMAC_type, 16, ks_mac);

    PrintAndLogEx(DEBUG, "ks_enc........ %s", sprint_hex_inrow(ks_enc, 16));
    PrintAndLogEx(DEBUG, "ks_mac........ %s", sprint_hex_inrow(ks_mac, 16));

    if (emrtd_sm_setup(ssn, EMRTD_PACE_CIPHER_3DES, ks_enc, ks_mac) != PM3_SUCCESS) {
        return false;
    }

    memcpy(ssn->ssc, rnd_ic + 4, 4);
    memcpy(ssn->ssc + 4, rnd_ifd + 4, 4);

    PrintAndLogEx(DEBUG, "ssc........... %s", sprint_hex_inrow(ssn->ssc, ssn->ssclen));

    return true;
}

static bool emrtd_connect(void) {
    int res = Iso7816Connect(CC_CONTACTLESS);
    return res == PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// PACE, ICAO 9303-11 4.4 and TR-03110 part 3, 3.2
//-----------------------------------------------------------------------------

#define EMRTD_INS_MSE                   0x22
#define EMRTD_INS_GENERAL_AUTHENTICATE  0x86

#define EMRTD_PACE_PWD_MRZ              0x01
#define EMRTD_PACE_PWD_CAN              0x02

// Like emrtd_exchange_commands(), but hands the status word back so that the
// caller can report the 63CX retry counter of a wrong PACE password.
static bool emrtd_exchange_commands_sw(sAPDU_t apdu, bool include_le, uint16_t le, uint8_t *dataout,
                                       size_t maxdataoutlen, size_t *dataoutlen, uint16_t *sw) {
    uint16_t lsw = 0;
    int res = Iso7816ExchangeEx(CC_CONTACTLESS, false, true, apdu, include_le, le, dataout, maxdataoutlen, dataoutlen, &lsw);

    *sw = lsw;

    if ((res != PM3_SUCCESS) && (lsw == 0)) {
        return false;
    }

    if (lsw != ISO7816_OK) {
        PrintAndLogEx(DEBUG, "Command failed (%04x - %s).", lsw, GetAPDUCodeDescription(lsw >> 8, lsw & 0xff));
        return false;
    }
    return true;
}

static bool emrtd_secure_select(emrtd_session_t *ssn, uint8_t p1, const uint8_t *sel, size_t sellen) {
    uint8_t response[PM3_CMD_DATA_SIZE] = { 0x00 };
    size_t resplen = 0;

    size_t blocksize = emrtd_sm_blocksize(ssn);
    const uint8_t header[4] = {0x0C, ISO7816_SELECT_FILE, p1, 0x0C};

    uint8_t plain[EMRTD_SM_MAX_BLOCK_LEN * 2] = { 0x00 };
    if ((sellen + 1) > sizeof(plain)) {
        return false;
    }
    size_t plainlen = emrtd_pad_block(sel, sellen, blocksize, plain);

    // the AES IV depends on the SSC, so it has to be bumped before encrypting
    emrtd_sm_bump_ssc(ssn);

    uint8_t cryptogram[sizeof(plain)] = { 0x00 };
    if (emrtd_sm_encrypt(ssn, plain, plainlen, cryptogram) != PM3_SUCCESS) {
        return false;
    }

    uint8_t do87[sizeof(plain) + 3] = {0x87, 0x00, 0x01};
    do87[1] = (uint8_t)(plainlen + 1);
    memcpy(do87 + 3, cryptogram, plainlen);
    PrintAndLogEx(DEBUG, "do87: %s", sprint_hex_inrow(do87, plainlen + 3));

    uint8_t data[sizeof(do87) + 16] = { 0x00 };
    size_t lc = 0;
    if (emrtd_sm_finish_command(ssn, header, do87, plainlen + 3, data, sizeof(data), &lc) == false) {
        return false;
    }

    uint16_t sw = 0;
    if (emrtd_exchange_commands_sw((sAPDU_t) {0x0C, ISO7816_SELECT_FILE, p1, 0x0C, lc, data}, true, 0, response, sizeof(response), &resplen, &sw) == false) {
        if (sw != 0) {
            PrintAndLogEx(ERR, "Secure select rejected by the document (%04X - %s)", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        } else {
            PrintAndLogEx(ERR, "Secure select got no response");
        }
        return false;
    }

    if (emrtd_check_cc(ssn, response, resplen) == false) {
        PrintAndLogEx(ERR, "Secure select response failed the MAC check");
        PrintAndLogEx(ERR, "response.......... %s", sprint_hex_inrow(response, resplen));
        return false;
    }
    return true;
}

// MSE:Set AT, ICAO 9303-11 4.4.4.1
static bool emrtd_mse_set_at(const emrtd_paceinfo_t *info, uint8_t password_ref) {
    uint8_t data[32] = { 0x00 };
    size_t o = 0;

    data[o++] = 0x80;
    data[o++] = (uint8_t)info->oidlen;
    memcpy(data + o, info->oid, info->oidlen);
    o += info->oidlen;

    data[o++] = 0x83;
    data[o++] = 0x01;
    data[o++] = password_ref;

    if (info->has_param) {
        data[o++] = 0x84;
        data[o++] = 0x01;
        data[o++] = info->param_id;
    }

    PrintAndLogEx(DEBUG, "MSE:Set AT........ %s", sprint_hex_inrow(data, o));

    uint8_t response[16] = { 0x00 };
    size_t resplen = 0;
    uint16_t sw = 0;

    if (emrtd_exchange_commands_sw((sAPDU_t) {0x00, EMRTD_INS_MSE, 0xC1, 0xA4, o, data}, false, 0, response, sizeof(response), &resplen, &sw)) {
        return true;
    }

    if ((sw & 0xFFF0) == 0x63C0) {
        PrintAndLogEx(ERR, "PACE: wrong password, " _RED_("%i") " attempt(s) left before the password is blocked", sw & 0x000F);
    } else if (sw == 0x6A80) {
        PrintAndLogEx(ERR, "PACE: the document rejected the algorithm we selected (6A80)");
    } else if (sw != 0) {
        PrintAndLogEx(ERR, "PACE: MSE:Set AT failed (%04X - %s)", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
    } else {
        PrintAndLogEx(ERR, "PACE: MSE:Set AT got no response");
    }
    return false;
}

// One step of the GENERAL AUTHENTICATE chain. inner_tag 0 sends an empty 7C.
// Pulls one data object out of the dynamic authentication data of a response
static bool emrtd_ga_get(const uint8_t *dyn, size_t dynlen, uint8_t wanted,
                         uint8_t *out, size_t maxout, size_t *outlen) {
    const uint8_t *cur = dyn;
    const uint8_t *end = dyn + dynlen;
    uint32_t tag = 0;
    const uint8_t *val = NULL;
    size_t vlen = 0;

    while (emrtd_tlv_next(&cur, end, &tag, &val, &vlen)) {
        if (tag != wanted) {
            continue;
        }
        if (vlen > maxout) {
            PrintAndLogEx(ERR, "PACE: response object %02X is too large (%zu bytes)", wanted, vlen);
            return false;
        }
        memcpy(out, val, vlen);
        *outlen = vlen;
        return true;
    }
    return false;
}

// Runs one step of the chain and hands back the content of the response's 7C
static bool emrtd_general_authenticate(const char *step, bool more, uint8_t inner_tag, const uint8_t *payload, size_t payloadlen,
                                       uint8_t *out, size_t maxout, size_t *outlen) {
    uint8_t inner[EMRTD_EC_POINT_MAXLEN + 8] = { 0x00 };
    size_t innerlen = 0;

    if (inner_tag != 0) {
        innerlen = emrtd_tlv_write_header(inner, sizeof(inner), inner_tag, payloadlen);
        if ((innerlen == 0) || ((innerlen + payloadlen) > sizeof(inner))) {
            PrintAndLogEx(ERR, "PACE: general authenticate payload out-of-bounds");
            return false;
        }
        memcpy(inner + innerlen, payload, payloadlen);
        innerlen += payloadlen;
    }

    uint8_t data[sizeof(inner) + 8] = { 0x00 };
    size_t datalen = emrtd_tlv_write_header(data, sizeof(data), 0x7C, innerlen);
    if (datalen == 0) {
        return false;
    }
    memcpy(data + datalen, inner, innerlen);
    datalen += innerlen;

    if (datalen > 0xFF) {
        PrintAndLogEx(ERR, "PACE: general authenticate command too long for a short APDU");
        return false;
    }

    PrintAndLogEx(DEBUG, "GA >>............. %s", sprint_hex_inrow(data, datalen));

    uint8_t response[PM3_CMD_DATA_SIZE] = { 0x00 };
    size_t resplen = 0;
    uint16_t sw = 0;

    // CLA 0x10 marks every step of the chain except the last one
    uint8_t cla = more ? 0x10 : 0x00;

    if (emrtd_exchange_commands_sw((sAPDU_t) {cla, EMRTD_INS_GENERAL_AUTHENTICATE, 0x00, 0x00, datalen, data}, true, 0, response, sizeof(response), &resplen, &sw) == false) {
        if ((sw & 0xFFF0) == 0x63C0) {
            PrintAndLogEx(ERR, "PACE: wrong password, " _RED_("%i") " attempt(s) left before the password is blocked", sw & 0x000F);
        } else if (sw == 0x6300) {
            // no counter given, but at the mutual authentication step this can
            // only mean our token did not match, i.e. the password is wrong
            PrintAndLogEx(ERR, "PACE: %s failed (6300), the document rejected it", step);
        } else if (sw != 0) {
            PrintAndLogEx(ERR, "PACE: %s failed (%04X - %s)", step, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        } else {
            PrintAndLogEx(ERR, "PACE: %s got no response", step);
        }
        return false;
    }

    PrintAndLogEx(DEBUG, "GA <<............. %s", sprint_hex_inrow(response, resplen));

    const uint8_t *cur = response;
    const uint8_t *end = response + resplen;
    uint32_t tag = 0;
    const uint8_t *val = NULL;
    size_t vlen = 0;

    if ((emrtd_tlv_next(&cur, end, &tag, &val, &vlen) == false) || (tag != 0x7C)) {
        PrintAndLogEx(ERR, "PACE: %s returned malformed dynamic authentication data", step);
        return false;
    }

    if (vlen > maxout) {
        PrintAndLogEx(ERR, "PACE: %s response is too large (%zu bytes)", step, vlen);
        return false;
    }

    memcpy(out, val, vlen);
    *outlen = vlen;
    return true;
}

// Runs one step and picks a single expected data object out of the response
static bool emrtd_general_authenticate_one(const char *step, bool more, uint8_t inner_tag,
                                           const uint8_t *payload, size_t payloadlen,
                                           uint8_t expect_tag, uint8_t *out, size_t maxout, size_t *outlen) {
    uint8_t dyn[PM3_CMD_DATA_SIZE] = { 0x00 };
    size_t dynlen = 0;

    if (emrtd_general_authenticate(step, more, inner_tag, payload, payloadlen, dyn, sizeof(dyn), &dynlen) == false) {
        return false;
    }

    if (emrtd_ga_get(dyn, dynlen, expect_tag, out, maxout, outlen) == false) {
        PrintAndLogEx(ERR, "PACE: %s response is missing data object %02X", step, expect_tag);
        return false;
    }
    return true;
}

static int emrtd_do_pace(const emrtd_paceinfo_t *info, const uint8_t *password, size_t passwordlen,
                         uint8_t password_ref, emrtd_session_t *ssn) {
    const emrtd_pacealg_t *alg = info->alg;
    mbedtls_ecp_group_id curve = info->sdp->curve;

    uint8_t kpi[EMRTD_SM_MAX_KEY_LEN] = { 0x00 };
    size_t kpilen = 0;

    // Kpi = KDF(K, 3)
    if (emrtd_pace_kdf(alg->cipher, password, passwordlen, 3, kpi, &kpilen) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "kpi............... %s", sprint_hex_inrow(kpi, kpilen));

    if (emrtd_mse_set_at(info, password_ref) == false) {
        return PM3_ESOFT;
    }

    uint8_t response[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    size_t resplen = 0;

    // Step 1, encrypted nonce
    if (emrtd_general_authenticate_one("step 1 (encrypted nonce)", true, 0x00, NULL, 0, 0x80, response, sizeof(response), &resplen) == false) {
        return PM3_ESOFT;
    }

    uint8_t s[32] = { 0x00 };
    if (emrtd_pace_decrypt_nonce(alg->cipher, kpi, response, resplen, s) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    size_t slen = resplen;
    PrintAndLogEx(DEBUG, "nonce s........... %s", sprint_hex_inrow(s, slen));

    // Step 2, map the nonce
    uint8_t priv1[EMRTD_PACE_SECRET_MAXLEN] = { 0x00 };
    uint8_t pub1[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    size_t priv1len = 0, pub1len = 0;

    if (emrtd_pace_ec_keygen(curve, NULL, 0, priv1, &priv1len, pub1, &pub1len) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "PK.Map.IFD........ %s", sprint_hex_inrow(pub1, pub1len));

    if (emrtd_general_authenticate_one("step 2 (map nonce)", true, 0x81, pub1, pub1len, 0x82, response, sizeof(response), &resplen) == false) {
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "PK.Map.IC......... %s", sprint_hex_inrow(response, resplen));

    // Chip Authentication Mapping proves this key belongs to the chip's static
    // CA key, which can only be checked once EF_DG14 is readable
    if (alg->mapping == EMRTD_PACE_MAP_CAM) {
        ssn->cam.negotiated = true;
        ssn->cam.curve = curve;
        memcpy(ssn->cam.pk_map_ic, response, resplen);
        ssn->cam.pk_map_iclen = resplen;
        // the terminal half of the Chip Authentication ECDH
        memcpy(ssn->cam.sk_map_ifd, priv1, priv1len);
        ssn->cam.sk_map_ifdlen = priv1len;
    }

    uint8_t mapped[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    size_t mappedlen = 0;
    if (emrtd_pace_ec_gm(curve, s, slen, priv1, priv1len, response, resplen, mapped, &mappedlen) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "mapped generator.. %s", sprint_hex_inrow(mapped, mappedlen));

    // Step 3, key agreement over the mapped generator
    uint8_t priv2[EMRTD_PACE_SECRET_MAXLEN] = { 0x00 };
    uint8_t pub2[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    size_t priv2len = 0, pub2len = 0;

    if (emrtd_pace_ec_keygen(curve, mapped, mappedlen, priv2, &priv2len, pub2, &pub2len) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "PK.DH.IFD......... %s", sprint_hex_inrow(pub2, pub2len));

    if (ssn->cam.negotiated) {
        memcpy(ssn->cam.sk_dh_ifd, priv2, priv2len);
        ssn->cam.sk_dh_ifdlen = priv2len;
    }

    uint8_t pk2_ic[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    size_t pk2_iclen = 0;
    if (emrtd_general_authenticate_one("step 3 (key agreement)", true, 0x83, pub2, pub2len, 0x84, pk2_ic, sizeof(pk2_ic), &pk2_iclen) == false) {
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "PK.DH.IC.......... %s", sprint_hex_inrow(pk2_ic, pk2_iclen));

    if (ssn->cam.negotiated) {
        memcpy(ssn->cam.pk_dh_ic, pk2_ic, pk2_iclen);
        ssn->cam.pk_dh_iclen = pk2_iclen;
    }

    // ICAO 9303-11 4.4.3.3, the two ephemeral keys must differ
    if ((pk2_iclen == pub2len) && (memcmp(pk2_ic, pub2, pub2len) == 0)) {
        PrintAndLogEx(ERR, "PACE: the document echoed our ephemeral public key back, aborting");
        return PM3_ESOFT;
    }

    uint8_t shared[EMRTD_PACE_SECRET_MAXLEN] = { 0x00 };
    size_t sharedlen = 0;
    if (emrtd_pace_ec_shared_x(curve, priv2, priv2len, pk2_ic, pk2_iclen, shared, &sharedlen) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    // Step 4, session keys and mutual authentication tokens
    uint8_t ks_enc[EMRTD_SM_MAX_KEY_LEN] = { 0x00 };
    uint8_t ks_mac[EMRTD_SM_MAX_KEY_LEN] = { 0x00 };
    size_t kslen = 0;

    if ((emrtd_pace_kdf(alg->cipher, shared, sharedlen, 1, ks_enc, &kslen) != PM3_SUCCESS) ||
            (emrtd_pace_kdf(alg->cipher, shared, sharedlen, 2, ks_mac, &kslen) != PM3_SUCCESS)) {
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "ks_enc............ %s", sprint_hex_inrow(ks_enc, kslen));
    PrintAndLogEx(DEBUG, "ks_mac............ %s", sprint_hex_inrow(ks_mac, kslen));

    uint8_t t_ifd[8] = { 0x00 };
    if (emrtd_pace_token(alg, ks_mac, pk2_ic, pk2_iclen, t_ifd) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    uint8_t dyn[PM3_CMD_DATA_SIZE] = { 0x00 };
    size_t dynlen = 0;
    if (emrtd_general_authenticate("step 4 (mutual authentication)", false, 0x85, t_ifd, sizeof(t_ifd), dyn, sizeof(dyn), &dynlen) == false) {
        return PM3_ESOFT;
    }

    uint8_t t_ic[8] = { 0x00 };
    size_t t_iclen = 0;
    if (emrtd_ga_get(dyn, dynlen, 0x86, t_ic, sizeof(t_ic), &t_iclen) == false) {
        PrintAndLogEx(ERR, "PACE: step 4 (mutual authentication) response is missing data object 86");
        return PM3_ESOFT;
    }

    if (ssn->cam.negotiated) {
        // DO'8A', TR-03110 part 3, 3.4.4
        if (emrtd_ga_get(dyn, dynlen, 0x8A, ssn->cam.enc_data, sizeof(ssn->cam.enc_data), &ssn->cam.enc_datalen) == false) {
            PrintAndLogEx(WARNING, "PACE-CAM: the document returned no encrypted chip authentication data");
            ssn->cam.negotiated = false;
        } else {
            PrintAndLogEx(DEBUG, "CAM data.......... %s", sprint_hex_inrow(ssn->cam.enc_data, ssn->cam.enc_datalen));
        }
    }

    uint8_t t_ic_expected[8] = { 0x00 };
    if (emrtd_pace_token(alg, ks_mac, pub2, pub2len, t_ic_expected) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    if ((t_iclen != sizeof(t_ic_expected)) || (memcmp(t_ic, t_ic_expected, sizeof(t_ic_expected)) != 0)) {
        PrintAndLogEx(ERR, "PACE: the document's authentication token is wrong, aborting");
        PrintAndLogEx(DEBUG, "T_IC got.......... %s", sprint_hex_inrow(t_ic, t_iclen));
        PrintAndLogEx(DEBUG, "T_IC expected..... %s", sprint_hex_inrow(t_ic_expected, sizeof(t_ic_expected)));
        return PM3_ESOFT;
    }

    if (emrtd_sm_setup(ssn, alg->cipher, ks_enc, ks_mac) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    // SSC starts at zero after PACE, ICAO 9303-11 9.8.6.3
    ssn->pace = true;
    ssn->pace_alg = alg->name;
    ssn->pace_curve = info->sdp->name;

    PrintAndLogEx(INFO, "Authentication with PACE successful ( " _GREEN_("%s") ", %s )", alg->name, info->sdp->name);
    return PM3_SUCCESS;
}

// Picks the PACE password out of what the user supplied
static int emrtd_pace_password(const emrtd_auth_t *auth, uint8_t *k, size_t *klen, uint8_t *password_ref) {
    if (auth->can_available) {
        if (emrtd_pace_password_can(auth->can, k, klen) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "PACE: invalid CAN");
            return PM3_EINVARG;
        }
        *password_ref = EMRTD_PACE_PWD_CAN;
        return PM3_SUCCESS;
    }

    if (auth->mrz_available) {
        if (emrtd_pace_password_mrz(auth->documentnumber, auth->dob, auth->expiry, k, klen) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "PACE: invalid MRZ data");
            return PM3_EINVARG;
        }
        *password_ref = EMRTD_PACE_PWD_MRZ;
        return PM3_SUCCESS;
    }

    PrintAndLogEx(ERR, "PACE needs a password, supply `" _YELLOW_("--can") "` or `" _YELLOW_("-n") "` `" _YELLOW_("-d") "` `" _YELLOW_("-e") "`");
    return PM3_EINVARG;
}

// Orders every usable SecurityInfo strongest first, returns how many there are
static size_t emrtd_pace_candidates(const emrtd_cardaccess_t *ca, size_t *order, size_t maxorder) {
    size_t count = 0;

    for (size_t i = 0; i < ca->count; i++) {

        if (emrtd_pace_rank(&ca->infos[i]) <= 0) {
            continue;
        }

        if (count >= maxorder) {
            break;
        }

        // insertion sort, the list is never longer than EMRTD_PACE_MAX_INFOS
        size_t pos = count;
        while ((pos > 0) && (emrtd_pace_rank(&ca->infos[order[pos - 1]]) < emrtd_pace_rank(&ca->infos[i]))) {
            order[pos] = order[pos - 1];
            pos--;
        }
        order[pos] = i;
        count++;
    }

    return count;
}

// Reads EF_DG14 over the freshly established session and checks the chip's
// Chip Authentication Mapping proof against the key it publishes there.
//
// Note: while no encoding of DO'8A' has been confirmed against real hardware, a
// check that does not come out is reported as "unverified" rather than as a
// failure, because our own support is the far likelier culprit. Once a document
// verifies, drop the probing in emrtd_pace_cam_verify(), keep only the encoding
// that worked, and make a mismatch loud again: at that point it means a clone.
static void emrtd_check_cam(emrtd_session_t *ssn) {
    uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    size_t resplen = 0;

    PrintAndLogEx(INFO, "Verifying Chip Authentication Mapping");

    if (emrtd_select_and_read(response, &resplen, dg_table[EF_DG14].fileid, ssn) == false) {
        PrintAndLogEx(WARNING, "Chip Authentication.. " _YELLOW_("unverified") " ( couldn't read EF_DG14 )");
        return;
    }

    uint8_t pk_icc[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    size_t pk_icclen = 0;
    size_t expected = emrtd_pace_ec_pointlen(ssn->cam.curve);
    bool found_any = false;

    // a document may publish more than one chip authentication key
    for (size_t i = 0; i < EMRTD_PACE_MAX_INFOS; i++) {

        if (emrtd_pace_find_ca_pubkey(response, resplen, i, pk_icc, &pk_icclen) != PM3_SUCCESS) {
            break;
        }

        found_any = true;
        PrintAndLogEx(DEBUG, "PK.CA.IC[%zu]....... %s", i, sprint_hex_inrow(pk_icc, pk_icclen));

        if (pk_icclen != expected) {
            PrintAndLogEx(DEBUG, "CAM: key %zu is %zu bytes, the PACE curve needs %zu, skipping", i, pk_icclen, expected);
            continue;
        }

        const char *mode = NULL;
        if (emrtd_pace_cam_verify(ssn, pk_icc, pk_icclen, &mode) == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "Chip Authentication.. " _GREEN_("verified") " ( the chip is genuine, not a clone )");
            PrintAndLogEx(INFO, "CAM encoding...... %s", mode);
            return;
        }
    }

    if (found_any == false) {
        PrintAndLogEx(WARNING, "Chip Authentication.. " _YELLOW_("unverified") " ( no EC chip authentication key in EF_DG14 )");
        return;
    }

    PrintAndLogEx(WARNING, "Chip Authentication.. " _YELLOW_("not verified") " ( we cannot check this document's CAM proof )");
    PrintAndLogEx(HINT, "Hint: the secure channel is valid and every file is authentic. Only the anti-clone");
    PrintAndLogEx(HINT, "Hint: proof is unchecked, which is a known gap, not a sign of a bad document");
    PrintAndLogEx(HINT, "Hint: if you want to help close it, please report everything below");
    emrtd_pace_cam_dump(ssn, pk_icc, pk_icclen);
}

static bool emrtd_do_auth(const emrtd_auth_t *auth, const emrtd_cardaccess_t *ca, bool ca_valid,
                          bool *BAC, emrtd_session_t *ssn) {
    uint8_t aid[] = EMRTD_AID_MRTD;

    *BAC = false;

    //-------------------------------------------------------------------------
    // PACE. EF_CardAccess lives on the MF, so this runs before the LDS applet
    // is selected. On success the applet is selected under secure messaging.
    //-------------------------------------------------------------------------
    bool try_pace = (auth->force_bac == false) && ca_valid;

    if (auth->force_pace && (ca_valid == false)) {
        PrintAndLogEx(ERR, "PACE was forced but this document has no usable EF_CardAccess.");
        return false;
    }

    if (try_pace) {

        size_t order[EMRTD_PACE_MAX_INFOS] = { 0 };
        size_t candidates = emrtd_pace_candidates(ca, order, ARRAYLEN(order));

        uint8_t k[EMRTD_PACE_SECRET_MAXLEN] = { 0x00 };
        size_t klen = 0;
        uint8_t password_ref = 0;

        if (candidates == 0) {
            PrintAndLogEx(ERR, "PACE: this document offers no algorithm we can do");
            for (size_t i = 0; i < ca->count; i++) {
                if (ca->infos[i].reason != NULL) {
                    PrintAndLogEx(ERR, "  %s: %s",
                                  (ca->infos[i].alg != NULL) ? ca->infos[i].alg->name : "unknown protocol",
                                  ca->infos[i].reason);
                }
            }
        }

        if ((candidates != 0) && (emrtd_pace_password(auth, k, &klen, &password_ref) == PM3_SUCCESS)) {

            PrintAndLogEx(INFO, "Trying PACE with the %s", (password_ref == EMRTD_PACE_PWD_CAN) ? "CAN" : "MRZ");

            // strongest first, and drop down a rung if the document does not
            // actually honour what it advertised
            for (size_t i = 0; i < candidates; i++) {

                const emrtd_paceinfo_t *info = &ca->infos[order[i]];

                if (i != 0) {
                    PrintAndLogEx(INFO, "Retrying with " _YELLOW_("%s"), info->alg->name);
                    DropField();
                    msleep(50);
                    if (emrtd_connect() == false) {
                        PrintAndLogEx(ERR, "Couldn't reconnect to the document.");
                        return false;
                    }
                }

                if (emrtd_do_pace(info, k, klen, password_ref, ssn) != PM3_SUCCESS) {
                    emrtd_sm_clear(ssn);
                    continue;
                }

                if (emrtd_secure_select(ssn, EMRTD_P1_SELECT_BY_NAME, aid, sizeof(aid)) == false) {
                    PrintAndLogEx(ERR, "Couldn't select the MRTD application over PACE.");
                    emrtd_sm_clear(ssn);
                    continue;
                }

                if (ssn->cam.negotiated) {
                    emrtd_check_cam(ssn);
                }

                *BAC = true;
                return true;
            }
        }

        emrtd_sm_clear(ssn);

        if (auth->force_pace) {
            PrintAndLogEx(ERR, "PACE was forced, not falling back to BAC.");
            return false;
        }

        PrintAndLogEx(INFO, "PACE failed, falling back to BAC");
        // the document is in an undefined state after a failed PACE run
        DropField();
        msleep(50);
        if (emrtd_connect() == false) {
            PrintAndLogEx(ERR, "Couldn't reconnect to the document.");
            return false;
        }
    }

    //-------------------------------------------------------------------------
    // BAC
    //-------------------------------------------------------------------------

    // Select MRTD applet
    if (emrtd_select_file_by_name(sizeof(aid), aid) == false) {
        PrintAndLogEx(ERR, "Couldn't select the MRTD application.");
        return false;
    }

    // Select EF_COM
    if (emrtd_select_file_by_ef(dg_table[EF_COM].fileid) == false) {
        *BAC = true;
        PrintAndLogEx(INFO, "Authentication is enforced");
        PrintAndLogEx(INFO, "Switching to external authentication");
    } else {
        *BAC = false;
        // Select EF_DG1
        emrtd_select_file_by_ef(dg_table[EF_DG1].fileid);

        size_t resplen = 0;
        uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
        emrtd_session_t plain;
        emrtd_sm_clear(&plain);
        if (emrtd_read_file(response, &resplen, &plain) == false) {
            *BAC = true;
            PrintAndLogEx(INFO, "Authentication is enforced");
            PrintAndLogEx(INFO, "Switching to external authentication");
        } else {
            *BAC = false;
        }
    }

    // Do Basic Access Control
    if (*BAC) {
        // If BAC isn't available, exit out and warn user.
        if (auth->mrz_available == false) {
            PrintAndLogEx(ERR, "This eMRTD enforces authentication, but you didn't supply MRZ data. Cannot proceed.");
            PrintAndLogEx(HINT, "Hint: Check out `" _YELLOW_("hf emrtd info/dump --h") "`, supply data with `-n` `-d` and `-e`");
            return false;
        }

        if (emrtd_do_bac(auth->documentnumber, auth->dob, auth->expiry, ssn) == false) {
            return false;
        }
    }
    return true;
}

int dumpHF_EMRTD(const emrtd_auth_t *auth, const char *path) {
    uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    size_t resplen = 0;
    emrtd_session_t ssn;
    emrtd_cardaccess_t ca;
    bool ca_valid = false;
    bool BAC = false;

    emrtd_sm_clear(&ssn);
    memset(&ca, 0, sizeof(ca));
    ca.best = -1;

    // Select the eMRTD
    if (emrtd_connect() == false) {
        DropField();
        return PM3_ESOFT;
    }

    // Read and dump EF_CardAccess (if available). This lives on the MF and is
    // readable without authentication, so it has to happen before anything else.
    if (emrtd_select_and_read(response, &resplen, dg_table[EF_CardAccess].fileid, &ssn) == false) {
        PrintAndLogEx(INFO, "Couldn't read EF_CardAccess, card does not support PACE");
        PrintAndLogEx(HINT, "Hint: This is expected behavior for cards without PACE and isn't something to be worried about");
    } else {
        emrtd_save_file(response, resplen, dg_table[EF_CardAccess].fileid, dg_table[EF_CardAccess].filename, path);
        ca_valid = (emrtd_pace_parse_cardaccess(response, resplen, &ca) == PM3_SUCCESS);
        if (ca_valid == false) {
            PrintAndLogEx(WARNING, "Couldn't parse EF_CardAccess, PACE is not available");
        }
    }

    // Authenticate with the eMRTD
    if (emrtd_do_auth(auth, &ca, ca_valid, &BAC, &ssn) == false) {
        DropField();
        return PM3_ESOFT;
    }

    // Select EF_COM
    if (emrtd_select_and_read(response, &resplen, dg_table[EF_COM].fileid, &ssn) == false) {
        PrintAndLogEx(ERR, "Failed to read EF_COM");
        DropField();
        return PM3_ESOFT;
    }


    char *filepath = calloc(strlen(path) + 100, sizeof(char));
    if (filepath == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    strcpy(filepath, path);
    strncat(filepath, PATHSEP, 2);
    strcat(filepath, dg_table[EF_COM].filename);

    PrintAndLogEx(INFO, "Read EF_COM, len %zu", resplen);
    PrintAndLogEx(DEBUG, "Contents (may be incomplete over 2k chars)... %s", sprint_hex_inrow(response, resplen));
    saveFile(filepath, ".bin", response, resplen);

    free(filepath);

    uint8_t filelist[50];
    size_t filelistlen = 0;

    if (emrtd_lds_get_data_by_tag(response, resplen, filelist, &filelistlen, 0x5c, 0x00, false, true, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read file list from EF_COM");
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(DEBUG, "File List... %s", sprint_hex_inrow(filelist, filelistlen));
    // Add EF_SOD to the list
    filelist[filelistlen++] = 0x77;
    // Dump all files in the file list
    for (int i = 0; i < filelistlen; i++) {
        emrtd_dg_t *dg = emrtd_tag_to_dg(filelist[i]);
        if (dg == NULL) {
            PrintAndLogEx(INFO, "File tag not found, skipping... %02X", filelist[i]);
            continue;
        }
        PrintAndLogEx(DEBUG, "Current file... %s", dg->filename);
        // dg->pace files are only reachable once a PACE session is up, dg->eac
        // files need EAC which we do not implement at all
        if ((!dg->pace || ssn.pace) && !dg->eac) {
            emrtd_dump_file(&ssn, dg->fileid, dg->filename, path);
        }
    }
    DropField();
    return PM3_SUCCESS;
}

static bool emrtd_compare_check_digit(char *datain, int datalen, char expected_check_digit) {
    char tempdata[90] = { 0x00 };
    memcpy(tempdata, datain, datalen);

    uint8_t check_digit = emrtd_calculate_check_digit(tempdata) + 0x30;
    bool res = check_digit == expected_check_digit;
    PrintAndLogEx(DEBUG, "emrtd_compare_check_digit, expected %c == %c calculated ( %s )"
                  , expected_check_digit
                  , check_digit
                  , (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool emrtd_mrz_verify_check_digit(char *mrz, int offset, int datalen) {
    char tempdata[90] = { 0x00 };
    memcpy(tempdata, mrz + offset, datalen);
    return emrtd_compare_check_digit(tempdata, datalen, mrz[offset + datalen]);
}

static void emrtd_print_legal_sex(char *legal_sex) {
    char sex[12] = { 0x00 };
    switch (*legal_sex) {
        case 'M':
            strncpy(sex, "Male", 5);
            break;
        case 'F':
            strncpy(sex, "Female", 7);
            break;
        case '<':
            strncpy(sex, "Unspecified", 12);
            break;
    }
    PrintAndLogEx(SUCCESS, "Legal Sex Marker......... " _YELLOW_("%s"), sex);
}

static int emrtd_mrz_determine_length(const char *mrz, int offset, int max_length) {
    int i;
    for (i = max_length; i >= 1; i--) {
        if (mrz[offset + i - 1] != '<') {
            return i;
        }
    }

    return 0;
}

static int emrtd_mrz_determine_separator(const char *mrz, int offset, int max_length) {
    // Note: this function does not account for len=0
    int i;
    for (i = max_length - 1; i > 0; i--) {
        if (mrz[offset + i] == '<' && mrz[offset + i + 1] == '<') {
            break;
        }
    }
    return i;
}

static void emrtd_mrz_replace_pad(char *data, int datalen, char newchar) {
    for (int i = 0; i < datalen; i++) {
        if (data[i] == '<') {
            data[i] = newchar;
        }
    }
}

static void emrtd_print_optional_elements(char *mrz, int offset, int length, bool verify_check_digit) {
    int i = emrtd_mrz_determine_length(mrz, offset, length);
    if (i == 0) {
        return;
    }

    PrintAndLogEx(SUCCESS, "Optional elements........ " _YELLOW_("%.*s"), i, mrz + offset);

    if (verify_check_digit && !emrtd_mrz_verify_check_digit(mrz, offset, length)) {
        PrintAndLogEx(SUCCESS, _RED_("Optional element check digit is invalid."));
    }
}

static void emrtd_print_document_number(char *mrz, int offset) {
    int i = emrtd_mrz_determine_length(mrz, offset, 9);
    if (i == 0) {
        return;
    }

    PrintAndLogEx(SUCCESS, "Document Number.......... " _YELLOW_("%.*s"), i, mrz + offset);

    if (!emrtd_mrz_verify_check_digit(mrz, offset, 9)) {
        PrintAndLogEx(SUCCESS, _RED_("Document number check digit is invalid."));
    }
}

static void emrtd_print_name(char *mrz, int offset, int max_length, bool localized) {
    char final_name[100] = { 0x00 };
    int namelen = emrtd_mrz_determine_length(mrz, offset, max_length);
    if (namelen == 0) {
        return;
    }
    int sep = emrtd_mrz_determine_separator(mrz, offset, namelen);

    // Account for mononyms
    if (sep != 0) {
        int firstnamelen = (namelen - (sep + 2));

        memcpy(final_name, mrz + offset + sep + 2, firstnamelen);
        final_name[firstnamelen] = ' ';
        memcpy(final_name + firstnamelen + 1, mrz + offset, sep);
    } else {
        memcpy(final_name, mrz + offset, namelen);
    }

    // Replace < characters with spaces
    emrtd_mrz_replace_pad(final_name, namelen, ' ');

    if (localized) {
        PrintAndLogEx(SUCCESS, "Legal Name (Localized)... " _YELLOW_("%s"), final_name);
    } else {
        PrintAndLogEx(SUCCESS, "Legal Name............... " _YELLOW_("%s"), final_name);
    }
}

static void emrtd_mrz_convert_date(char *mrz, int offset, char *final_date, bool is_expiry, bool is_full, bool is_ascii) {
    char work_date[9] = { 0x00 };
    int len = is_full ? 8 : 6;

    // Copy the data to a working array in the right format
    if (!is_ascii) {
        memcpy(work_date, sprint_hex_inrow((uint8_t *)mrz + offset, len / 2), len);
    } else {
        memcpy(work_date, mrz + offset, len);
    }

    // Set offset to 0 as we've now copied data.
    offset = 0;

    if (is_full) {
        // If we get the full date, use the first two characters from that for year
        memcpy(final_date, work_date, 2);
        // and do + 2 on offset so that rest of code uses the right data
        offset += 2;
    } else {
        char temp_year[3] = { 0x00 };
        memcpy(temp_year, work_date, 2);
        // If it's > 20, assume 19xx.
        if (strtol(temp_year, NULL, 10) < 20 || is_expiry) {
            final_date[0] = '2';
            final_date[1] = '0';
        } else {
            final_date[0] = '1';
            final_date[1] = '9';
        }
    }

    memcpy(final_date + 2, work_date + offset, 2);
    final_date[4] = '-';
    memcpy(final_date + 5, work_date + offset + 2, 2);
    final_date[7] = '-';
    memcpy(final_date + 8, work_date + offset + 4, 2);
}

static void emrtd_print_dob(char *mrz, int offset, bool full, bool ascii) {
    char final_date[12] = { 0x00 };
    emrtd_mrz_convert_date(mrz, offset, final_date, false, full, ascii);

    PrintAndLogEx(SUCCESS, "Date of birth............ " _YELLOW_("%s"), final_date);

    if (!full && !emrtd_mrz_verify_check_digit(mrz, offset, 6)) {
        PrintAndLogEx(SUCCESS, _RED_("Date of Birth check digit is invalid."));
    }
}

static void emrtd_print_expiry(char *mrz, int offset) {
    char final_date[12] = { 0x00 };
    emrtd_mrz_convert_date(mrz, offset, final_date, true, false, true);

    PrintAndLogEx(SUCCESS, "Date of expiry........... " _YELLOW_("%s"), final_date);

    if (!emrtd_mrz_verify_check_digit(mrz, offset, 6)) {
        PrintAndLogEx(SUCCESS, _RED_("Date of expiry check digit is invalid."));
    }
}

static void emrtd_print_issuance(char *data, bool ascii) {
    char final_date[12] = { 0x00 };
    emrtd_mrz_convert_date(data, 0, final_date, true, true, ascii);

    PrintAndLogEx(SUCCESS, "Date of issue............ " _YELLOW_("%s"), final_date);
}

static void emrtd_print_personalization_timestamp(uint8_t *data, size_t datalen) {
    if (datalen < 7) {
        return;
    }

    char str_date[0x0F] = { 0x00 };
    strncpy(str_date, sprint_hex_inrow(data, 0x07), sizeof(str_date) - 1);

    char final_date[20] = { 0x00 };
    snprintf(final_date, sizeof(final_date), "%.4s-%.2s-%.2s %.2s:%.2s:%.2s"
             , str_date
             , str_date + 4
             , str_date + 6
             , str_date + 8
             , str_date + 10
             , str_date + 12
            );

    PrintAndLogEx(SUCCESS, "Personalization at....... " _YELLOW_("%s"), final_date);
}

static void emrtd_print_unknown_timestamp_5f85(uint8_t *data, size_t datalen) {
    if (datalen < 14) {
        return;
    }
    char final_date[20] = { 0x00 };
    snprintf(final_date, sizeof(final_date), "%.4s-%.2s-%.2s %.2s:%.2s:%.2s"
             , data
             , data + 4
             , data + 6
             , data + 8
             , data + 10
             , data + 12
            );

    PrintAndLogEx(SUCCESS, "Unknown timestamp 5F85... " _YELLOW_("%s"), final_date);
    PrintAndLogEx(HINT, "Hint: This is very likely the personalization timestamp but it is using an undocumented tag.");
}

static int emrtd_print_ef_com_info(uint8_t *data, size_t datalen) {
    uint8_t filelist[50];
    size_t filelistlen = 0;
    bool res = emrtd_lds_get_data_by_tag(data, datalen, filelist, &filelistlen, 0x5c, 0x00, false, true, 0);
    if (res == false) {
        PrintAndLogEx(ERR, "Failed to read file list from EF_COM.");
        return PM3_ESOFT;
    }

    // List files in the file list
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------------------ " _CYAN_("EF_COM") " ------------------------");
    for (int i = 0; i < filelistlen; i++) {
        emrtd_dg_t *dg = emrtd_tag_to_dg(filelist[i]);
        if (dg == NULL) {
            PrintAndLogEx(INFO, "File tag not found, skipping: %02X", filelist[i]);
            continue;
        }
        int n = 25 - strlen(dg->filename);
        PrintAndLogEx(SUCCESS, "%s%.*s " _YELLOW_("%s"), dg->filename, n, pad, dg->desc);

    }
    return PM3_SUCCESS;
}

static int emrtd_print_ef_dg1_info(uint8_t *data, size_t datalen) {
    int td_variant = 0;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------------------ " _CYAN_("EF_DG1") " ------------------------");

    // MRZ on TD1 is 90 characters, 30 on each row.
    // MRZ on TD3 is 88 characters, 44 on each row.
    char mrz[90] = { 0x00 };
    size_t mrzlen = 0;

    if (emrtd_lds_get_data_by_tag(data, datalen, (uint8_t *) mrz, &mrzlen, 0x5f, 0x1f, true, true, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read MRZ from EF_DG1.");
        return PM3_ESOFT;
    }

    // Determine and print the document type
    if (mrz[0] == 'I' && mrz[1] == 'P') {
        PrintAndLogEx(SUCCESS, "Document Type............ " _YELLOW_("Passport Card"));
    } else if (mrz[0] == 'I') {
        PrintAndLogEx(SUCCESS, "Document Type............ " _YELLOW_("ID Card"));
    } else if (mrz[0] == 'P') {
        PrintAndLogEx(SUCCESS, "Document Type............ " _YELLOW_("Passport"));
    } else if (mrz[0] == 'A') {
        PrintAndLogEx(SUCCESS, "Document Type............ " _YELLOW_("Residency Permit"));
    } else {
        PrintAndLogEx(SUCCESS, "Document Type............ " _YELLOW_("Unknown"));
    }

    if (mrzlen == 90) {
        td_variant = 1;
    } else if (mrzlen == 88) {
        td_variant = 3;
    } else {
        PrintAndLogEx(ERR, "MRZ length (%zu) is wrong.", mrzlen);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Document Form Factor..... " _YELLOW_("TD%i"), td_variant);

    // Print the MRZ
    if (td_variant == 1) {
        PrintAndLogEx(DEBUG, "MRZ Row 1... " _YELLOW_("%.30s"), mrz);
        PrintAndLogEx(DEBUG, "MRZ Row 2... " _YELLOW_("%.30s"), mrz + 30);
        PrintAndLogEx(DEBUG, "MRZ Row 3... " _YELLOW_("%.30s"), mrz + 60);
    } else if (td_variant == 3) {
        PrintAndLogEx(DEBUG, "MRZ Row 1... " _YELLOW_("%.44s"), mrz);
        PrintAndLogEx(DEBUG, "MRZ Row 2... " _YELLOW_("%.44s"), mrz + 44);
    }

    PrintAndLogEx(SUCCESS, "Issuing state............ " _YELLOW_("%.3s"), mrz + 2);

    if (td_variant == 3) {
        // Passport form factor
        PrintAndLogEx(SUCCESS, "Nationality.............. " _YELLOW_("%.3s"), mrz + 44 + 10);
        emrtd_print_name(mrz, 5, 38, false);
        emrtd_print_document_number(mrz, 44);
        emrtd_print_dob(mrz, 44 + 13, false, true);
        emrtd_print_legal_sex(&mrz[44 + 20]);
        emrtd_print_expiry(mrz, 44 + 21);
        emrtd_print_optional_elements(mrz, 44 + 28, 14, true);

        // Calculate and verify composite check digit
        char composite_check_data[50] = { 0x00 };
        memcpy(composite_check_data, mrz + 44, 10);
        memcpy(composite_check_data + 10, mrz + 44 + 13, 7);
        memcpy(composite_check_data + 17, mrz + 44 + 21, 23);

        if (emrtd_compare_check_digit(composite_check_data, 39, mrz[87]) == false) {
            PrintAndLogEx(SUCCESS, _RED_("Composite check digit is invalid."));
        }
    } else if (td_variant == 1) {
        // ID form factor
        PrintAndLogEx(SUCCESS, "Nationality.............. " _YELLOW_("%.3s"), mrz + 30 + 15);
        emrtd_print_name(mrz, 60, 30, false);
        emrtd_print_document_number(mrz, 5);
        emrtd_print_dob(mrz, 30, false, true);
        emrtd_print_legal_sex(&mrz[30 + 7]);
        emrtd_print_expiry(mrz, 30 + 8);
        emrtd_print_optional_elements(mrz, 15, 15, false);
        emrtd_print_optional_elements(mrz, 30 + 18, 11, false);

        // Calculate and verify composite check digit
        if (emrtd_compare_check_digit(mrz, 59, mrz[59]) == false) {
            PrintAndLogEx(SUCCESS, _RED_("Composite check digit is invalid."));
        }
    }

    return PM3_SUCCESS;
}

// Extract an image out of a data group and hand it to the picture viewer.
// The viewer keeps an array of images, so DG2 / DG5 / DG7 all end up
// side by side, each in its own tab named by "title"
static int emrtd_print_image(const char *title, uint8_t *data, size_t datalen) {

    if (data == NULL || datalen < 6) {
        return PM3_ESOFT;
    }

    // This is a hacky impl that just looks for the image header. I'll improve it eventually.
    // based on mrpkey.py
    // Note: Doing datalen - 6 to account for the longest data we're checking.
    // Checks first byte before the rest to reduce overhead
    bool found = false;
    size_t offset = 0;
    for (offset = 0; offset < datalen - 6; offset++) {

        if (data[offset] == 0xFF) {
            // JPEG SOI + any APPn marker,  JFIF (FFE0) is the common one but
            // Exif (FFE1) / raw DQT (FFDB) show up as well
            if (memcmp(jpeg_header, data + offset, 3) == 0) {
                found = true;
                break;
            }
            // JPEG2000 raw codestream, no JP2 container
            if (memcmp(jpeg2k_cs_header, data + offset, 4) == 0) {
                found = true;
                break;
            }
        } else if (data[offset] == 0x00 && memcmp(jpeg2k_header, data + offset, 6) == 0) {
            // JPEG2000 in a JP2 container
            found = true;
            break;
        }
    }

    // If we didn't find any image, return false.
    if (found == false) {
        PrintAndLogEx(DEBUG, "No image header found in %s", title);
        return PM3_ESOFT;
    }

    ShowPictureWindow(title, data + offset, (int)(datalen - offset));
    return PM3_SUCCESS;
}

static int emrtd_print_ef_dg2_info(uint8_t *data, size_t datalen) {
    return emrtd_print_image("DG2 - Encoded Face", data, datalen);
}

static int emrtd_print_ef_dg5_info(uint8_t *data, size_t datalen) {
    return emrtd_print_image("DG5 - Displayed Portrait", data, datalen);
}

static int emrtd_print_ef_dg7_info(uint8_t *data, size_t datalen) {
    return emrtd_print_image("DG7 - Signature", data, datalen);
}

static int emrtd_print_ef_dg11_info(uint8_t *data, size_t datalen) {
    uint8_t taglist[100] = { 0x00 };
    size_t taglistlen = 0;
    uint8_t tagdata[1000] = { 0x00 };
    size_t tagdatalen = 0;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------------------ " _CYAN_("EF_DG11") " -----------------------");

    if (emrtd_lds_get_data_by_tag(data, datalen, taglist, &taglistlen, 0x5c, 0x00, false, true, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read file list from EF_DG11.");
        return PM3_ESOFT;
    }

    for (int i = 0; i < taglistlen; i++) {
        bool res = emrtd_lds_get_data_by_tag(data, datalen, tagdata, &tagdatalen, taglist[i], taglist[i + 1], taglist[i] == 0x5f, true, 0);
        (void)res;
        // Don't bother with empty tags
        if (tagdatalen == 0) {
            continue;
        }
        // Special behavior for two char tags
        if (taglist[i] == 0x5f) {
            switch (taglist[i + 1]) {
                case 0x0e:
                    emrtd_print_name((char *) tagdata, 0, tagdatalen, true);
                    break;
                case 0x0f:
                    emrtd_print_name((char *) tagdata, 0, tagdatalen, false);
                    break;
                case 0x10:
                    PrintAndLogEx(SUCCESS, "Personal Number.......... " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x11:
                    // TODO: acc for < separation
                    PrintAndLogEx(SUCCESS, "Place of Birth........... " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x42:
                    // TODO: acc for < separation
                    PrintAndLogEx(SUCCESS, "Permanent Address........ " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x12:
                    PrintAndLogEx(SUCCESS, "Telephone................ " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x13:
                    PrintAndLogEx(SUCCESS, "Profession............... " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x14:
                    PrintAndLogEx(SUCCESS, "Title.................... " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x15:
                    PrintAndLogEx(SUCCESS, "Personal Summary......... " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x16:
                    saveFile("ProofOfCitizenship", tagdata[0] == 0xFF ? ".jpg" : ".jp2", tagdata, tagdatalen);
                    break;
                case 0x17:
                    // TODO: acc for < separation
                    PrintAndLogEx(SUCCESS, "Other valid TDs nums..... " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x18:
                    PrintAndLogEx(SUCCESS, "Custody Information...... " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x2b:
                    emrtd_print_dob((char *) tagdata, 0, true, tagdatalen != 4);
                    break;
                default:
                    PrintAndLogEx(SUCCESS, "Unknown Field %02X%02X....... %s", taglist[i], taglist[i + 1], sprint_hex_inrow(tagdata, tagdatalen));
                    break;
            }

            i += 1;
        } else {
            // TODO: Account for A0
            PrintAndLogEx(SUCCESS, "Unknown Field %02X......... %s", taglist[i], sprint_hex_inrow(tagdata, tagdatalen));
        }
    }
    return PM3_SUCCESS;
}

static int emrtd_print_ef_dg12_info(uint8_t *data, size_t datalen) {
    uint8_t taglist[100] = { 0x00 };
    size_t taglistlen = 0;
    uint8_t tagdata[1000] = { 0x00 };
    size_t tagdatalen = 0;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------------------ " _CYAN_("EF_DG12") " -----------------------");

    if (emrtd_lds_get_data_by_tag(data, datalen, taglist, &taglistlen, 0x5c, 0x00, false, true, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read file list from EF_DG12.");
        return PM3_ESOFT;
    }

    for (int i = 0; i < taglistlen; i++) {
        bool res = emrtd_lds_get_data_by_tag(data, datalen, tagdata, &tagdatalen, taglist[i], taglist[i + 1], taglist[i] == 0x5f, true, 0);
        (void)res;
        // Don't bother with empty tags
        if (tagdatalen == 0) {
            continue;
        }
        // Special behavior for two char tags
        if (taglist[i] == 0x5f) {
            // Several things here are longer than the rest but I can't think of a way to shorten them
            // ...and I doubt many states are using them.
            switch (taglist[i + 1]) {
                case 0x19:
                    PrintAndLogEx(SUCCESS, "Issuing Authority........ " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x26:
                    emrtd_print_issuance((char *) tagdata, tagdatalen != 4);
                    break;
                case 0x1b:
                    PrintAndLogEx(SUCCESS, "Endorsements & Observations... " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x1c:
                    PrintAndLogEx(SUCCESS, "Tax/Exit Requirements.... " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x1d:
                    saveFile("FrontOfDocument", tagdata[0] == 0xFF ? ".jpg" : ".jp2", tagdata, tagdatalen);
                    break;
                case 0x1e:
                    saveFile("BackOfDocument", tagdata[0] == 0xFF ? ".jpg" : ".jp2", tagdata, tagdatalen);
                    break;
                case 0x55:
                    emrtd_print_personalization_timestamp(tagdata, tagdatalen);
                    break;
                case 0x56:
                    PrintAndLogEx(SUCCESS, "Serial of Personalization System... " _YELLOW_("%.*s"), (int)tagdatalen, tagdata);
                    break;
                case 0x85:
                    emrtd_print_unknown_timestamp_5f85(tagdata, tagdatalen);
                    break;
                default:
                    PrintAndLogEx(SUCCESS, "Unknown Field %02X%02X....... %s", taglist[i], taglist[i + 1], sprint_hex_inrow(tagdata, tagdatalen));
                    break;
            }

            i += 1;
        } else {
            // TODO: Account for A0
            PrintAndLogEx(SUCCESS, "Unknown Field %02X......... %s", taglist[i], sprint_hex_inrow(tagdata, tagdatalen));
        }
    }
    return PM3_SUCCESS;
}

static int emrtd_ef_sod_extract_signatures(uint8_t *data, size_t datalen, uint8_t *dataout, size_t *dataoutlen) {
    uint8_t *buffers = calloc(5, EMRTD_MAX_FILE_SIZE);
    if (buffers == NULL) {
        PrintAndLogEx(ERR, "Failed to allocate EF_SOD parser buffers.");
        return PM3_EMALLOC;
    }

    uint8_t *top = buffers;
    uint8_t *signeddata = top + EMRTD_MAX_FILE_SIZE;
    uint8_t *emrtdsigcontainer = signeddata + EMRTD_MAX_FILE_SIZE;
    uint8_t *emrtdsig = emrtdsigcontainer + EMRTD_MAX_FILE_SIZE;
    uint8_t *emrtdsigtext = emrtdsig + EMRTD_MAX_FILE_SIZE;
    size_t toplen, signeddatalen, emrtdsigcontainerlen, emrtdsiglen, emrtdsigtextlen = 0;

    if (emrtd_lds_get_data_by_tag(data, datalen, top, &toplen, 0x30, 0x00, false, true, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read top from EF_SOD.");
        free(buffers);
        return false;
    }

    PrintAndLogEx(DEBUG, "top: %s.", sprint_hex_inrow(top, toplen));

    if (emrtd_lds_get_data_by_tag(top, toplen, signeddata, &signeddatalen, 0xA0, 0x00, false, false, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read signedData from EF_SOD.");
        free(buffers);
        return false;
    }

    PrintAndLogEx(DEBUG, "signeddata: %s.", sprint_hex_inrow(signeddata, signeddatalen));

    // Do true on reading into the tag as it's a "sequence"
    if (emrtd_lds_get_data_by_tag(signeddata, signeddatalen, emrtdsigcontainer, &emrtdsigcontainerlen, 0x30, 0x00, false, true, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read eMRTDSignature container from EF_SOD.");
        free(buffers);
        return false;
    }

    PrintAndLogEx(DEBUG, "emrtdsigcontainer: %s.", sprint_hex_inrow(emrtdsigcontainer, emrtdsigcontainerlen));

    if (emrtd_lds_get_data_by_tag(emrtdsigcontainer, emrtdsigcontainerlen, emrtdsig, &emrtdsiglen, 0xA0, 0x00, false, false, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read eMRTDSignature from EF_SOD.");
        free(buffers);
        return false;
    }

    PrintAndLogEx(DEBUG, "emrtdsig: %s.", sprint_hex_inrow(emrtdsig, emrtdsiglen));

    // TODO: Not doing memcpy here, it didn't work, fix it somehow
    if (emrtd_lds_get_data_by_tag(emrtdsig, emrtdsiglen, emrtdsigtext, &emrtdsigtextlen, 0x04, 0x00, false, false, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read eMRTDSignature (text) from EF_SOD.");
        free(buffers);
        return false;
    }
    memcpy(dataout, emrtdsigtext, emrtdsigtextlen);
    *dataoutlen = emrtdsigtextlen;
    free(buffers);
    return PM3_SUCCESS;
}

static int emrtd_parse_ef_sod_hash_algo(uint8_t *data, size_t datalen, int *hashalgo) {
    uint8_t hashalgoset[64] = { 0x00 };
    size_t hashalgosetlen = 0;

    // We'll return hash algo -1 if we can't find anything
    *hashalgo = -1;

    if (emrtd_lds_get_data_by_tag(data, datalen, hashalgoset, &hashalgosetlen, 0x30, 0x00, false, true, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read hash algo set from EF_SOD.");
        return false;
    }

    PrintAndLogEx(DEBUG, "hash algo set: %s", sprint_hex_inrow(hashalgoset, hashalgosetlen));

    // If last two bytes are 05 00, ignore them.
    // https://wf.lavatech.top/ave-but-random/emrtd-data-quirks#EF_SOD
    if (hashalgoset[hashalgosetlen - 2] == 0x05 && hashalgoset[hashalgosetlen - 1] == 0x00) {
        hashalgosetlen -= 2;
    }

    for (int hashi = 0; hashalg_table[hashi].name != NULL; hashi++) {
        PrintAndLogEx(DEBUG, "trying: %s", hashalg_table[hashi].name);
        // We're only interested in checking if the length matches to avoid memory shenanigans
        if (hashalg_table[hashi].descriptorlen != hashalgosetlen) {
            PrintAndLogEx(DEBUG, "len mismatch: %zu", hashalgosetlen);
            continue;
        }

        if (memcmp(hashalg_table[hashi].descriptor, hashalgoset, hashalgosetlen) == 0) {
            *hashalgo = hashi;
            return PM3_SUCCESS;
        }
    }

    PrintAndLogEx(ERR, "Failed to parse hash list (Unknown algo: %s). Hash verification won't be available.", sprint_hex_inrow(hashalgoset, hashalgosetlen));
    return PM3_ESOFT;
}

static int emrtd_parse_ef_sod_hashes(uint8_t *data, size_t datalen, uint8_t *hashes, int *hashalgo) {
    uint8_t *buffers = calloc(2, EMRTD_MAX_FILE_SIZE);
    if (buffers == NULL) {
        PrintAndLogEx(ERR, "Failed to allocate EF_SOD hash buffers.");
        return PM3_EMALLOC;
    }

    uint8_t *emrtdsig = buffers;
    uint8_t *hashlist = emrtdsig + EMRTD_MAX_FILE_SIZE;
    uint8_t hash[64] = { 0x00 };
    size_t hashlen = 0;

    uint8_t hashidstr[4] = { 0x00 };
    size_t hashidstrlen = 0;

    size_t emrtdsiglen = 0;
    size_t hashlistlen = 0;
    size_t offset = 0;

    if (emrtd_ef_sod_extract_signatures(data, datalen, emrtdsig, &emrtdsiglen) != PM3_SUCCESS) {
        free(buffers);
        return false;
    }

    PrintAndLogEx(DEBUG, "hash data... %s", sprint_hex_inrow(emrtdsig, emrtdsiglen));

    emrtd_parse_ef_sod_hash_algo(emrtdsig, emrtdsiglen, hashalgo);

    if (emrtd_lds_get_data_by_tag(emrtdsig, emrtdsiglen, hashlist, &hashlistlen, 0x30, 0x00, false, true, 1) == false) {
        PrintAndLogEx(ERR, "Failed to read hash list from EF_SOD");
        free(buffers);
        return false;
    }

    PrintAndLogEx(DEBUG, "hash list... %s", sprint_hex_inrow(hashlist, hashlistlen));

    while (offset < hashlistlen) {
        // Get the length of the element
        int e_datalen = emrtd_get_asn1_data_length(hashlist + offset, hashlistlen - offset, 1);

        // Get the length of the element's length
        int e_fieldlen = emrtd_get_asn1_field_length(hashlist + offset, hashlistlen - offset, 1);

        switch (hashlist[offset]) {
            case 0x30: {
                // iceman:  if these two calls fails,  feels like we should have a better check in place
                bool res = emrtd_lds_get_data_by_tag(hashlist + offset + e_fieldlen + 1, e_datalen, hashidstr, &hashidstrlen, 0x02, 0x00, false, false, 0);
                (void)res;
                res = emrtd_lds_get_data_by_tag(hashlist + offset + e_fieldlen + 1, e_datalen, hash, &hashlen, 0x04, 0x00, false, false, 0);
                (void)res;
                if (hashlen <= 64) {
                    memcpy(hashes + (hashidstr[0] * 64), hash, hashlen);
                } else {
                    PrintAndLogEx(ERR, "error (emrtd_parse_ef_sod_hashes) hashlen out-of-bounds");
                }
                break;
            }
        }
        // + 1 for length of ID
        offset += 1 + e_datalen + e_fieldlen;
    }

    free(buffers);
    return PM3_SUCCESS;
}

static int emrtd_print_ef_sod_info(uint8_t *dg_hashes_calc, uint8_t *dg_hashes_sod, int hash_algo, bool fastdump) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------------------ " _CYAN_("EF_SOD") " ------------------------");
    PrintAndLogEx(INFO, "Document Security Object");
    PrintAndLogEx(INFO, "contains the digital signatures of the passport data");
    PrintAndLogEx(INFO, "");

    if (hash_algo == -1) {
        PrintAndLogEx(SUCCESS, "Hash algorithm... " _YELLOW_("Unknown"));
    } else {

        PrintAndLogEx(SUCCESS, "Hash algorithm... " _YELLOW_("%s"), hashalg_table[hash_algo].name);

        uint8_t all_zeroes[64] = { 0x00 };

        for (int i = 1; i <= 16; i++) {

            bool calc_all_zero = (memcmp(dg_hashes_calc + (i * 64), all_zeroes, hashalg_table[hash_algo].hashlen) == 0);
            bool sod_all_zero = (memcmp(dg_hashes_sod + (i * 64), all_zeroes, hashalg_table[hash_algo].hashlen) == 0);
            bool hash_matches = (memcmp(dg_hashes_sod + (i * 64), dg_hashes_calc + (i * 64), hashalg_table[hash_algo].hashlen) == 0);

            // Ignore files we don't haven't read and lack hashes to
            if (calc_all_zero == true && sod_all_zero == true) {
                continue;
            }

            // silly padding thingy
            int n = 40 - strlen(dg_table[i].desc);

            if (calc_all_zero == true) {

                if (dg_table[i].eac) {
                    // Terminal Authentication with a country signed inspection
                    // system certificate, which we neither have nor implement
                    PrintAndLogEx(SUCCESS, _YELLOW_("EF_DG%-2i") " %s%.*s " _YELLOW_("Needs EAC"), i, dg_table[i].desc, n, pad);
                } else if (dg_table[i].pace) {
                    PrintAndLogEx(SUCCESS, _YELLOW_("EF_DG%-2i") " %s%.*s " _YELLOW_("Needs PACE"), i, dg_table[i].desc, n, pad);
                } else if (fastdump && !dg_table[i].fastdump) {
                    PrintAndLogEx(SUCCESS, _YELLOW_("EF_DG%-2i") " %s%.*s File was skipped, but is in EF_SOD", i, dg_table[i].desc, n, pad);
                } else {
                    PrintAndLogEx(SUCCESS, _YELLOW_("EF_DG%-2i") " %s%.*s File couldn't be read, but is in EF_SOD", i, dg_table[i].desc, n, pad);
                }

            } else if (sod_all_zero == true) {
                PrintAndLogEx(SUCCESS, _YELLOW_("EF_DG%-2i") " %s%.*s " _RED_("File is not in EF_SOD"), i, dg_table[i].desc, n, pad);
            } else if (hash_matches == false) {
                PrintAndLogEx(SUCCESS, _YELLOW_("EF_DG%-2i") " %s%.*s " _RED_("Invalid"), i, dg_table[i].desc, n, pad);
            } else {
                PrintAndLogEx(SUCCESS, _YELLOW_("EF_DG%-2i") " %s%.*s " _GREEN_("Valid"), i, dg_table[i].desc, n, pad);
            }
        }
    }

    return PM3_SUCCESS;
}

static void emrtd_print_cardaccess(const emrtd_cardaccess_t *ca) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--------------------- " _CYAN_("EF_CardAccess") " --------------------");

    for (size_t i = 0; i < ca->count; i++) {
        const emrtd_paceinfo_t *info = &ca->infos[i];

        if (i != 0) {
            PrintAndLogEx(SUCCESS, "");
        }

        if (info->alg != NULL) {
            PrintAndLogEx(SUCCESS, "PACE algorithm........... " _YELLOW_("%s"), info->alg->name);
        } else {
            PrintAndLogEx(SUCCESS, "PACE algorithm........... " _YELLOW_("unknown") " ( OID %s )",
                          sprint_hex_inrow((uint8_t *)info->oid, info->oidlen));
        }

        if (info->version != 0) {
            PrintAndLogEx(SUCCESS, "PACE version............. " _YELLOW_("%u"), info->version);
        }

        if (info->has_param) {
            if (info->sdp != NULL) {
                PrintAndLogEx(SUCCESS, "PACE parameter........... " _YELLOW_("%s") " ( id %u )", info->sdp->name, info->param_id);
            } else {
                // TR-03110 part 3, table A.2 leaves 3-7 and 19-31 reserved
                PrintAndLogEx(SUCCESS, "PACE parameter........... " _YELLOW_("RFU / unknown") " ( id %u )", info->param_id);
            }
        }

        if (info->supported) {
            PrintAndLogEx(SUCCESS, "Supported by this client. " _GREEN_("yes")
                          "%s", ((int)i == ca->best) ? _GREEN_(" (selected)") : "");
        } else {
            PrintAndLogEx(SUCCESS, "Supported by this client. " _YELLOW_("no") " ( %s )",
                          (info->reason != NULL) ? info->reason : "unsupported");
        }
    }

    if (ca->best < 0) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(WARNING, "None of the offered PACE algorithms is supported by this client");
    }
}

// dg_table parser entry point, used by the offline path
static int emrtd_print_ef_cardaccess_info(uint8_t *data, size_t datalen) {
    emrtd_cardaccess_t ca;

    int res = emrtd_pace_parse_cardaccess(data, datalen, &ca);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--------------------- " _CYAN_("EF_CardAccess") " --------------------");
        PrintAndLogEx(ERR, "Failed to parse EF_CardAccess.");
        return res;
    }

    emrtd_print_cardaccess(&ca);
    return PM3_SUCCESS;
}

int infoHF_EMRTD(const emrtd_auth_t *auth, bool only_fast) {
    uint8_t response[EMRTD_MAX_FILE_SIZE] = { 0x00 };
    size_t resplen = 0;
    emrtd_session_t ssn;
    emrtd_cardaccess_t ca;
    bool ca_valid = false;
    bool PACE_available = true;
    bool BAC = false;

    emrtd_sm_clear(&ssn);
    memset(&ca, 0, sizeof(ca));
    ca.best = -1;

    // Select the eMRTD
    if (emrtd_connect() == false) {
        DropField();
        return PM3_ESOFT;
    }
    bool use14b = (GetISODEPState() == ISODEP_NFCB);

    // Read EF_CardAccess
    if (emrtd_select_and_read(response, &resplen, dg_table[EF_CardAccess].fileid, &ssn) == false) {
        PACE_available = false;
        PrintAndLogEx(HINT, "Hint: The error above this is normal. It just means that your eMRTD lacks PACE.");
    } else {
        ca_valid = (emrtd_pace_parse_cardaccess(response, resplen, &ca) == PM3_SUCCESS);
        if (ca_valid == false) {
            PrintAndLogEx(WARNING, "Couldn't parse EF_CardAccess, PACE is not available");
        }
    }

    // Select and authenticate with the eMRTD
    bool auth_result = emrtd_do_auth(auth, &ca, ca_valid, &BAC, &ssn);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------------- " _CYAN_("Basic Info") " ----------------------");
    PrintAndLogEx(SUCCESS, "Communication standard... %s", use14b ? _YELLOW_("ISO/IEC 14443(B)") : _YELLOW_("ISO/IEC 14443(A)"));
    PrintAndLogEx(SUCCESS, "Authentication........... %s", BAC ? _GREEN_("Enforced") : _RED_("Not enforced"));
    PrintAndLogEx(SUCCESS, "PACE..................... %s", PACE_available ? _GREEN_("Available") : _YELLOW_("Not available"));
    PrintAndLogEx(SUCCESS, "Authentication result.... %s", auth_result ? _GREEN_("Successful") : _RED_("Failed"));

    if (auth_result) {
        if (ssn.pace) {
            PrintAndLogEx(SUCCESS, "Session.................. " _GREEN_("PACE") " ( %s, %s )", ssn.pace_alg, ssn.pace_curve);
        } else if (ssn.type == EMRTD_SM_3DES) {
            PrintAndLogEx(SUCCESS, "Session.................. " _GREEN_("BAC") " ( 3DES-CBC-CBC )");
        } else {
            PrintAndLogEx(SUCCESS, "Session.................. " _YELLOW_("plain") " ( no secure messaging )");
        }
    }

    if (ca_valid) {
        emrtd_print_cardaccess(&ca);
    }

    if (auth_result == false) {
        DropField();
        return PM3_ESOFT;
    }

    // Read EF_COM to get file list
    if (emrtd_select_and_read(response, &resplen, dg_table[EF_COM].fileid, &ssn) == false) {
        PrintAndLogEx(ERR, "Failed to read EF_COM");
        DropField();
        return PM3_ESOFT;
    }

    int res = emrtd_print_ef_com_info(response, resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint8_t filelist[50];
    size_t filelistlen = 0;

    if (emrtd_lds_get_data_by_tag(response, resplen, filelist, &filelistlen, 0x5c, 0x00, false, true, 0) == false) {
        PrintAndLogEx(ERR, "Failed to read file list from EF_COM.");
        DropField();
        return PM3_ESOFT;
    }

    // Grab the hash list from EF_SOD
    uint8_t dg_hashes_sod[17][64] = { { 0 } };
    uint8_t dg_hashes_calc[17][64] = { { 0 } };
    int hash_algo = 0;

    if (!emrtd_select_and_read(response, &resplen, dg_table[EF_SOD].fileid, &ssn)) {
        PrintAndLogEx(ERR, "Failed to read EF_SOD.");
        DropField();
        return PM3_ESOFT;
    }

    res = emrtd_parse_ef_sod_hashes(response, resplen, *dg_hashes_sod, &hash_algo);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to read hash list from EF_SOD. Hash checks will fail");
    }

    // start with an empty picture viewer,  the data groups below fill it up
    ClearPictureWindow();

    // Dump all files in the file list
    for (int i = 0; i < filelistlen; i++) {

        emrtd_dg_t *dg = emrtd_tag_to_dg(filelist[i]);
        if (dg == NULL) {
            PrintAndLogEx(INFO, "File tag not found, skipping... %02X", filelist[i]);
            continue;
        }

        // dg->pace files are only reachable once a PACE session is up, dg->eac
        // files need EAC which we do not implement at all
        if (((dg->fastdump && only_fast) || !only_fast) && (!dg->pace || ssn.pace) && !dg->eac) {
            if (emrtd_select_and_read(response, &resplen, dg->fileid, &ssn)) {
                if (dg->parser != NULL)
                    dg->parser(response, resplen);

                PrintAndLogEx(DEBUG, "EF_DG%i hash algo... %i", dg->dgnum, hash_algo);
                // Check file hash
                if (hash_algo != -1) {
                    PrintAndLogEx(DEBUG, "EF_DG%i hash on EF_SOD... %s", dg->dgnum, sprint_hex_inrow(dg_hashes_sod[dg->dgnum], hashalg_table[hash_algo].hashlen));
                    hashalg_table[hash_algo].hasher(response, resplen, dg_hashes_calc[dg->dgnum]);
                    PrintAndLogEx(DEBUG, "EF_DG%i hash calc........ %s", dg->dgnum, sprint_hex_inrow(dg_hashes_calc[dg->dgnum], hashalg_table[hash_algo].hashlen));
                }
            }
        }
    }
    DropField();

    emrtd_print_ef_sod_info(*dg_hashes_calc, *dg_hashes_sod, hash_algo, true);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

int infoHF_EMRTD_offline(const char *path) {
    uint8_t *data;
    size_t datalen = 0;
    char *filepath = calloc(strlen(path) + 100, sizeof(char));
    if (filepath == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    strcpy(filepath, path);
    strncat(filepath, PATHSEP, 2);
    strcat(filepath, dg_table[EF_COM].filename);

    if ((loadFile_safeEx(filepath, ".BIN", (void **)&data, (size_t *)&datalen, false) != PM3_SUCCESS) &&
            (loadFile_safeEx(filepath, ".bin", (void **)&data, (size_t *)&datalen, false) != PM3_SUCCESS)) {
        PrintAndLogEx(ERR, "Failed to read EF_COM");
        free(filepath);
        return PM3_ESOFT;
    }

    int res = emrtd_print_ef_com_info(data, datalen);
    if (res != PM3_SUCCESS) {
        free(data);
        free(filepath);
        return res;
    }

    uint8_t filelist[50];
    size_t filelistlen = 0;
    res = emrtd_lds_get_data_by_tag(data, datalen, filelist, &filelistlen, 0x5c, 0x00, false, true, 0);
    if (res == false) {
        PrintAndLogEx(ERR, "Failed to read file list from EF_COM");
        free(data);
        free(filepath);
        return PM3_ESOFT;
    }
    free(data);

    // Grab the hash list
    uint8_t dg_hashes_sod[17][64] = { { 0 } };
    uint8_t dg_hashes_calc[17][64] = { { 0 } };
    int hash_algo = 0;

    strcpy(filepath, path);
    strncat(filepath, PATHSEP, 2);
    strcat(filepath, dg_table[EF_CardAccess].filename);

    if ((loadFile_safeEx(filepath, ".BIN", (void **)&data, (size_t *)&datalen, false) == PM3_SUCCESS) ||
            (loadFile_safeEx(filepath, ".bin", (void **)&data, (size_t *)&datalen, false) == PM3_SUCCESS)) {
        emrtd_print_ef_cardaccess_info(data, datalen);
        free(data);
    } else {
        PrintAndLogEx(HINT, "Hint: The error above this is normal. It just means that your eMRTD lacks PACE");
    }

    strcpy(filepath, path);
    strncat(filepath, PATHSEP, 2);
    strcat(filepath, dg_table[EF_SOD].filename);

    if ((loadFile_safeEx(filepath, ".BIN", (void **)&data, (size_t *)&datalen, false) != PM3_SUCCESS) &&
            (loadFile_safeEx(filepath, ".bin", (void **)&data, (size_t *)&datalen, false) != PM3_SUCCESS)) {
        PrintAndLogEx(ERR, "Failed to read EF_SOD");
        free(filepath);
        return PM3_ESOFT;
    }

    // coverity scan CID 395630,
    if (data == NULL) {
        free(filepath);
        return PM3_ESOFT;
    }

    res = emrtd_parse_ef_sod_hashes(data, datalen, *dg_hashes_sod, &hash_algo);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to read hash list from EF_SOD. Hash checks will fail");
    }
    free(data);

    // start with an empty picture viewer,  the data groups below fill it up
    ClearPictureWindow();

    // Read files in the file list
    for (int i = 0; i < filelistlen; i++) {

        emrtd_dg_t *dg = emrtd_tag_to_dg(filelist[i]);
        if (dg == NULL) {
            PrintAndLogEx(INFO, "File tag not found, skipping... %02X", filelist[i]);
            continue;
        }

        if (!dg->pace && !dg->eac) {
            strcpy(filepath, path);
            strncat(filepath, PATHSEP, 2);
            strcat(filepath, dg->filename);
            if ((loadFile_safeEx(filepath, ".BIN", (void **)&data, (size_t *)&datalen, false) == PM3_SUCCESS) ||
                    (loadFile_safeEx(filepath, ".bin", (void **)&data, (size_t *)&datalen, false) == PM3_SUCCESS)) {
                // we won't halt on parsing errors
                if (dg->parser != NULL) {
                    dg->parser(data, datalen);
                }

                PrintAndLogEx(DEBUG, "EF_DG%i hash algo... %i", dg->dgnum, hash_algo);
                // Check file hash
                if (hash_algo != -1) {
                    PrintAndLogEx(DEBUG, "EF_DG%i hash on EF_SOD... %s", dg->dgnum, sprint_hex_inrow(dg_hashes_sod[dg->dgnum], hashalg_table[hash_algo].hashlen));
                    hashalg_table[hash_algo].hasher(data, datalen, dg_hashes_calc[dg->dgnum]);
                    PrintAndLogEx(DEBUG, "EF_DG%i hash calc........ %s", dg->dgnum, sprint_hex_inrow(dg_hashes_calc[dg->dgnum], hashalg_table[hash_algo].hashlen));
                }
                free(data);
            }
        }
    }
    free(filepath);

    emrtd_print_ef_sod_info(*dg_hashes_calc, *dg_hashes_sod, hash_algo, false);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static bool validate_date(uint8_t *data, int datalen) {
    // Date has to be 6 chars
    if (datalen != 6) {
        return false;
    }

    // Check for valid date and month numbers
    char temp[4] = { 0x00 };
    memcpy(temp, data + 2, 2);
    int month = (int) strtol(temp, NULL, 10);
    memcpy(temp, data + 4, 2);
    int day = (int) strtol(temp, NULL, 10);

    return !(day <= 0 || day > 31 || month <= 0 || month > 12);
}

static bool emrtd_validate_can(const char *can, int canlen) {
    if ((canlen < 1) || (canlen > 14)) {
        PrintAndLogEx(ERR, "CAN length is incorrect, it should be 1 to 14 chars, not %i", canlen);
        return false;
    }

    for (int i = 0; i < canlen; i++) {
        if (isdigit((unsigned char)can[i]) == false) {
            PrintAndLogEx(ERR, "CAN has to be numeric.");
            return false;
        }
    }

    if (canlen != 6) {
        PrintAndLogEx(WARNING, "CAN is usually 6 digits, yours is %i. Continuing anyway.", canlen);
    }
    return true;
}

static bool emrtd_check_auth_args(bool mrz, bool can, bool force_pace, bool force_bac) {
    if (mrz && can) {
        PrintAndLogEx(ERR, "`" _YELLOW_("--can") "` and the MRZ arguments are mutually exclusive as PACE passwords.");
        PrintAndLogEx(HINT, "Hint: pick one, the CAN with `" _YELLOW_("--can") "` or the MRZ with `" _YELLOW_("-n") "` `" _YELLOW_("-d") "` `" _YELLOW_("-e") "`");
        return false;
    }

    if (force_pace && force_bac) {
        PrintAndLogEx(ERR, "`" _YELLOW_("--pace") "` and `" _YELLOW_("--bac") "` are mutually exclusive.");
        return false;
    }

    if (force_bac && can && (mrz == false)) {
        PrintAndLogEx(ERR, "BAC needs MRZ data, the CAN is a PACE only password.");
        return false;
    }

    if (force_pace && (mrz == false) && (can == false)) {
        PrintAndLogEx(ERR, "PACE needs a password, supply `" _YELLOW_("--can") "` or `" _YELLOW_("-n") "` `" _YELLOW_("-d") "` `" _YELLOW_("-e") "`");
        return false;
    }

    return true;
}

static void emrtd_fill_auth(emrtd_auth_t *auth, const char *docnum, const char *dob, const char *expiry,
                            const char *can, bool mrz_available, bool can_available,
                            bool force_pace, bool force_bac) {
    memset(auth, 0, sizeof(emrtd_auth_t));
    snprintf(auth->documentnumber, sizeof(auth->documentnumber), "%s", docnum);
    snprintf(auth->dob, sizeof(auth->dob), "%s", dob);
    snprintf(auth->expiry, sizeof(auth->expiry), "%s", expiry);
    snprintf(auth->can, sizeof(auth->can), "%s", can);
    auth->mrz_available = mrz_available;
    auth->can_available = can_available;
    auth->force_pace = force_pace;
    auth->force_bac = force_bac;
}

static int CmdHFeMRTDDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf emrtd dump",
                  "Dump all files on an eMRTD",
                  "hf emrtd dump\n"
                  "hf emrtd dump --dir ../dump\n"
                  "hf emrtd dump -n 123456789 -d 890101 -e 250401\n"
                  "hf emrtd dump --can 123456                    -> PACE with the Card Access Number\n"
                  "hf emrtd dump --can 123456 --pace             -> PACE only, no BAC fallback\n"
                  "hf emrtd dump -n 123456789 -d 890101 -e 250401 --bac -> force BAC"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("n", "doc", "<alphanum>", "document number, up to 9 chars"),
        arg_str0("d", "date", "<YYMMDD>", "date of birth in YYMMDD format"),
        arg_str0("e", "expiry", "<YYMMDD>", "expiry in YYMMDD format"),
        arg_str0("m", "mrz", "<[0-9A-Z<]>", "2nd line of MRZ, 44 chars"),
        arg_str0(NULL, "can", "<digits>", "Card Access Number, PACE password instead of the MRZ"),
        arg_lit0(NULL, "pace", "force PACE, fail instead of falling back to BAC"),
        arg_lit0(NULL, "bac", "force BAC, skip PACE"),
        arg_str0(NULL, "dir", "<str>", "save dump to the given dirpath"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t mrz[45] = { 0x00 };
    uint8_t docnum[10] = { 0x00 };
    uint8_t dob[7] = { 0x00 };
    uint8_t expiry[7] = { 0x00 };
    bool BAC = true;
    bool error = false;
    int slen = 0;
    // Go through all args, if even one isn't supplied, mark BAC as unavailable
    if (CLIParamStrToBuf(arg_get_str(ctx, 1), docnum, 9, &slen) != 0 || slen == 0) {
        BAC = false;
    } else {
        strn_upper((char *)docnum, slen);
        if (slen != 9) {
            // Pad to 9 with <
            memset(docnum + slen, '<', 9 - slen);
        }
    }

    if (CLIParamStrToBuf(arg_get_str(ctx, 2), dob, 6, &slen) != 0 || slen == 0) {
        BAC = false;
    } else {
        if (!validate_date(dob, slen)) {
            PrintAndLogEx(ERR, "Date of birth date format is incorrect, cannot continue.");
            PrintAndLogEx(HINT, "Hint: Use the format YYMMDD.");
            error = true;
        }
    }

    if (CLIParamStrToBuf(arg_get_str(ctx, 3), expiry, 6, &slen) != 0 || slen == 0) {
        BAC = false;
    } else {
        if (!validate_date(expiry, slen)) {
            PrintAndLogEx(ERR, "Expiry date format is incorrect, cannot continue.");
            PrintAndLogEx(HINT, "Hint: Use the format YYMMDD.");
            error = true;
        }
    }

    if (CLIParamStrToBuf(arg_get_str(ctx, 4), mrz, 44, &slen) == 0 && slen != 0) {
        if (slen != 44) {
            PrintAndLogEx(ERR, "MRZ length is incorrect, it should be 44, not %i", slen);
            error = true;
        } else {
            BAC = true;
            strn_upper((char *)mrz, slen);
            memcpy(docnum, &mrz[0], 9);
            memcpy(dob,    &mrz[13], 6);
            memcpy(expiry, &mrz[21], 6);
            // TODO check MRZ checksums?
            if (!validate_date(dob, 6)) {
                PrintAndLogEx(ERR, "Date of birth date format is incorrect, cannot continue.");
                PrintAndLogEx(HINT, "Hint: Use the format YYMMDD.");
                error = true;
            }
            if (!validate_date(expiry, 6)) {
                PrintAndLogEx(ERR, "Expiry date format is incorrect, cannot continue.");
                PrintAndLogEx(HINT, "Hint: Use the format YYMMDD.");
                error = true;
            }
        }
    }

    uint8_t can[15] = { 0x00 };
    bool CAN = false;
    if (CLIParamStrToBuf(arg_get_str(ctx, 5), can, sizeof(can) - 1, &slen) == 0 && slen != 0) {
        CAN = true;
        if (emrtd_validate_can((const char *)can, slen) == false) {
            error = true;
        }
    }

    bool force_pace = arg_get_lit(ctx, 6);
    bool force_bac = arg_get_lit(ctx, 7);

    uint8_t path[FILENAME_MAX] = { 0x00 };
    if (CLIParamStrToBuf(arg_get_str(ctx, 8), path, sizeof(path), &slen) != 0 || slen == 0) {
        path[0] = '.';
    }

    CLIParserFree(ctx);

    if (emrtd_check_auth_args(BAC, CAN, force_pace, force_bac) == false) {
        error = true;
    }

    if (error) {
        return PM3_ESOFT;
    }
    bool restore_apdu_logging = GetAPDULogging();
    if (g_debugMode >= 2) {
        SetAPDULogging(true);
    }

    uint64_t t1 = msclock();

    emrtd_auth_t auth;
    emrtd_fill_auth(&auth, (const char *)docnum, (const char *)dob, (const char *)expiry,
                    (const char *)can, BAC, CAN, force_pace, force_bac);

    int res = dumpHF_EMRTD(&auth, (const char *)path);

    PrintAndLogEx(SUCCESS, "time: %" PRIu64 " seconds\n", (msclock() - t1) / 1000);

    SetAPDULogging(restore_apdu_logging);
    return res;
}

static int CmdHFeMRTDInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf emrtd info",
                  "Display info about an eMRTD",
                  "hf emrtd info\n"
                  "hf emrtd info --dir ../dumps\n"
                  "hf emrtd info -n 123456789 -d 890101 -e 250401\n"
                  "hf emrtd info -n 123456789 -d 890101 -e 250401 -i\n"
                  "hf emrtd info --can 123456                    -> PACE with the Card Access Number\n"
                  "hf emrtd info --can 123456 --pace             -> PACE only, no BAC fallback"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("n", "doc", "<alphanum>", "document number, up to 9 chars"),
        arg_str0("d", "date", "<YYMMDD>", "date of birth in YYMMDD format"),
        arg_str0("e", "expiry", "<YYMMDD>", "expiry in YYMMDD format"),
        arg_str0("m", "mrz", "<[0-9A-Z<]>", "2nd line of MRZ, 44 chars (passports only)"),
        arg_str0(NULL, "can", "<digits>", "Card Access Number, PACE password instead of the MRZ"),
        arg_lit0(NULL, "pace", "force PACE, fail instead of falling back to BAC"),
        arg_lit0(NULL, "bac", "force BAC, skip PACE"),
        arg_str0(NULL, "dir", "<str>", "display info from offline dump stored in dirpath"),
        arg_lit0("i", "images", "show images"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t mrz[45] = { 0x00 };
    uint8_t docnum[10] = { 0x00 };
    uint8_t dob[7] = { 0x00 };
    uint8_t expiry[7] = { 0x00 };
    bool BAC = true;
    bool error = false;
    int slen = 0;
    // Go through all args, if even one isn't supplied, mark BAC as unavailable
    if (CLIParamStrToBuf(arg_get_str(ctx, 1), docnum, 9, &slen) != 0 || slen == 0) {
        BAC = false;
    } else {
        strn_upper((char *)docnum, slen);
        if (slen != 9) {
            memset(docnum + slen, '<', 9 - slen);
        }
    }

    if (CLIParamStrToBuf(arg_get_str(ctx, 2), dob, 6, &slen) != 0 || slen == 0) {
        BAC = false;
    } else {
        if (!validate_date(dob, slen)) {
            PrintAndLogEx(ERR, "Date of birth date format is incorrect, cannot continue.");
            PrintAndLogEx(HINT, "Hint: Use the format YYMMDD.");
            error = true;
        }
    }

    if (CLIParamStrToBuf(arg_get_str(ctx, 3), expiry, 6, &slen) != 0 || slen == 0) {
        BAC = false;
    } else {
        if (!validate_date(expiry, slen)) {
            PrintAndLogEx(ERR, "Expiry date format is incorrect, cannot continue.");
            PrintAndLogEx(HINT, "Hint: Use the format YYMMDD.");
            error = true;
        }
    }

    if (CLIParamStrToBuf(arg_get_str(ctx, 4), mrz, 44, &slen) == 0 && slen != 0) {
        if (slen != 44) {
            PrintAndLogEx(ERR, "MRZ length is incorrect, it should be 44, not %i", slen);
            error = true;
        } else {
            BAC = true;
            strn_upper((char *)mrz, slen);
            memcpy(docnum, &mrz[0], 9);
            memcpy(dob,    &mrz[13], 6);
            memcpy(expiry, &mrz[21], 6);
            // TODO check MRZ checksums?
            if (!validate_date(dob, 6)) {
                PrintAndLogEx(ERR, "Date of birth date format is incorrect, cannot continue.");
                PrintAndLogEx(HINT, "Hint: Use the format YYMMDD.");
                error = true;
            }
            if (!validate_date(expiry, 6)) {
                PrintAndLogEx(ERR, "Expiry date format is incorrect, cannot continue.");
                PrintAndLogEx(HINT, "Hint: Use the format YYMMDD.");
                error = true;
            }
        }
    }
    uint8_t can[15] = { 0x00 };
    bool CAN = false;
    if (CLIParamStrToBuf(arg_get_str(ctx, 5), can, sizeof(can) - 1, &slen) == 0 && slen != 0) {
        CAN = true;
        if (emrtd_validate_can((const char *)can, slen) == false) {
            error = true;
        }
    }

    bool force_pace = arg_get_lit(ctx, 6);
    bool force_bac = arg_get_lit(ctx, 7);

    uint8_t path[FILENAME_MAX] = { 0x00 };
    bool is_offline = CLIParamStrToBuf(arg_get_str(ctx, 8), path, sizeof(path), &slen) == 0 && slen > 0;
    bool show_images = arg_get_lit(ctx, 9);
    CLIParserFree(ctx);

    if ((IfPm3Iso14443() == false) && (is_offline == false)) {
        PrintAndLogEx(WARNING, "Only offline mode is available");
        error = true;
    }

    if ((is_offline == false) && (emrtd_check_auth_args(BAC, CAN, force_pace, force_bac) == false)) {
        error = true;
    }

    if (error) {
        return PM3_ESOFT;
    }

    if (is_offline) {
        return infoHF_EMRTD_offline((const char *)path);
    } else {
        bool restore_apdu_logging = GetAPDULogging();
        if (g_debugMode >= 2) {
            SetAPDULogging(true);
        }
        emrtd_auth_t auth;
        emrtd_fill_auth(&auth, (const char *)docnum, (const char *)dob, (const char *)expiry,
                        (const char *)can, BAC, CAN, force_pace, force_bac);

        int res = infoHF_EMRTD(&auth, !show_images);
        SetAPDULogging(restore_apdu_logging);
        return res;
    }
}

static int CmdHFeMRTDTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf emrtd test",
                  "Regression tests for the PACE and secure messaging primitives",
                  "hf emrtd test");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    return emrtd_test(true) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFeMRTDList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf emrtd", "7816");
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,           AlwaysAvailable, "This help"},
    {"-----------", CmdHelp,           IfPm3Iso14443,   "------------------- " _CYAN_("Operations") " -------------------"},
    {"dump",    CmdHFeMRTDDump,    IfPm3Iso14443,   "Dump eMRTD files to binary files"},
    {"info",        CmdHFeMRTDInfo,    AlwaysAvailable, "Tag information"},
    {"list",    CmdHFeMRTDList,    AlwaysAvailable, "List ISO 14443A/7816 history"},
    {"test",    CmdHFeMRTDTest,    AlwaysAvailable, "Regression tests"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFeMRTD(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
