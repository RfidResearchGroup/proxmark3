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
// Commands for FMCOS CPU smart cards (Fudan Microelectronics)
//-----------------------------------------------------------------------------

#include "cmdhffmcos.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "comms.h"
#include "cmdmain.h"
#include "util.h"
#include "ui.h"
#include "cliparser.h"
#include "cmdhf14a.h"
#include "iso7816/apduinfo.h"
#include "iso7816/iso7816core.h"
#include "protocols.h"
#include "mbedtls/des.h"
#include <time.h>

static int CmdHelp(const char *Cmd);

// ---------------------------------------------------------------------------
// APDU / SW helpers
// ---------------------------------------------------------------------------

// True when the RF field is on and a DF was selected with -k by the last command.
// When true, commands skip ISO14443-4 re-activation so the card state is preserved.
static bool g_fmcos_session_active = false;

// Send a raw APDU over ISO14443-A.
// resp receives the full card response including SW1SW2.
// If g_fmcos_session_active is true and activate is true, the activation step is
// suppressed so the previously selected DF is not reset to MF.
static int fmcos_send_apdu(const uint8_t *apdu, size_t apdu_len,
                           bool activate, bool leave_on,
                           uint8_t *resp, int *resp_len) {
    bool do_activate = activate && !g_fmcos_session_active;
    int res = ExchangeAPDU14a(apdu, (int)apdu_len, do_activate, leave_on,
                              resp, APDU_RES_LEN, resp_len);
    if (res != PM3_SUCCESS) {
        g_fmcos_session_active = false;
        PrintAndLogEx(ERR, "APDU exchange failed");
        return res;
    }
    g_fmcos_session_active = leave_on;
    return PM3_SUCCESS;
}

// Decode and print a SW1/SW2 status word.
static const char *fmcos_print_sw(uint8_t sw1, uint8_t sw2) {
    const char *desc = "Unknown";

    switch (sw1) {
        case 0x62:
            if (sw2 >= 0x02 && sw2 <= 0x80) {
                desc = "Triggering by the card";
                break;
            }
            switch (sw2) {
                case 0x81:
                    desc = "Part of returned data may be corrupted";
                    break;
                case 0x82:
                    desc = "End of file/record reached before reading Ne bytes";
                    break;
                case 0x83:
                    desc = "Selected file deactivated";
                    break;
                case 0x84:
                    desc = "FCI not formatted";
                    break;
                case 0x85:
                    desc = "Selected file in termination state";
                    break;
                case 0x86:
                    desc = "No input data from sensor";
                    break;
                default:
                    break;
            }
            break;

        case 0x63:
            if (sw2 == 0x81) {
                desc = "File filled up by last write";
                break;
            }
            if ((sw2 & 0xF0) == 0xC0) {
                desc = "Counter (0-15) encoded in SW2 low nibble";
                break;
            }
            break;

        case 0x64:
            if (sw2 >= 0x02 && sw2 <= 0x80) {
                desc = "Triggering by the card";
                break;
            }
            if (sw2 == 0x01) {
                desc = "Immediate response required by card";
                break;
            }
            break;

        case 0x65:
            if (sw2 == 0x81) {
                desc = "Memory failure";
                break;
            }
            break;

        case 0x67:
            if (sw2 == 0x00) {
                desc = "Invalid length";
                break;
            }
            break;

        case 0x68:
            switch (sw2) {
                case 0x81:
                    desc = "Logical channel not supported";
                    break;
                case 0x82:
                    desc = "Secure messaging not supported";
                    break;
                case 0x83:
                    desc = "Last command of chain expected";
                    break;
                case 0x84:
                    desc = "Command chaining not supported";
                    break;
                default:
                    break;
            }
            break;

        case 0x69:
            switch (sw2) {
                case 0x81:
                    desc = "Command incompatible with file structure";
                    break;
                case 0x82:
                    desc = "Security status not satisfied";
                    break;
                case 0x83:
                    desc = "Authentication method blocked";
                    break;
                case 0x84:
                    desc = "Reference data not usable";
                    break;
                case 0x85:
                    desc = "Conditions of use not satisfied";
                    break;
                case 0x86:
                    desc = "Command not allowed (no current EF)";
                    break;
                case 0x87:
                    desc = "Secure messaging data objects missing";
                    break;
                case 0x88:
                    desc = "Incorrect secure messaging data objects";
                    break;
                default:
                    break;
            }
            break;

        case 0x6A:
            switch (sw2) {
                case 0x80:
                    desc = "Incorrect parameters in data field";
                    break;
                case 0x81:
                    desc = "Function not supported";
                    break;
                case 0x82:
                    desc = "File or application not found";
                    break;
                case 0x83:
                    desc = "Record not found";
                    break;
                case 0x84:
                    desc = "Not enough memory in file";
                    break;
                case 0x85:
                    desc = "Nc inconsistent with TLV structure";
                    break;
                case 0x86:
                    desc = "Incorrect parameters P1-P2";
                    break;
                case 0x87:
                    desc = "Nc inconsistent with parameters P1-P2";
                    break;
                case 0x88:
                    desc = "Referenced data not found";
                    break;
                case 0x89:
                    desc = "File already exists";
                    break;
                case 0x8A:
                    desc = "DF name already exists";
                    break;
                default:
                    break;
            }
            break;

        case 0x6D:
            if (sw2 == 0x00) {
                desc = "Invalid INS";
                break;
            }
            break;

        case 0x6E:
            if (sw2 == 0x00) {
                desc = "Invalid CLA";
                break;
            }
            break;

        case 0x93:
            if (sw2 == 0x02) {
                desc = "Invalid MAC";
                break;
            }
            break;

        case 0x94:
            switch (sw2) {
                case 0x01:
                    desc = "Insufficient balance";
                    break;
                case 0x03:
                    desc = "Key index not supported";
                    break;
                default:
                    break;
            }
            break;

        case 0x90:
            if (sw2 == 0x00) {
                desc = "Success";
                break;
            }
            break;

        default:
            break;
    }

    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "SW: " _GREEN_("%02X%02X") " - %s", sw1, sw2, desc);
    } else {
        PrintAndLogEx(WARNING, "SW: " _RED_("%02X%02X") " - %s", sw1, sw2, desc);
    }

    return desc;
}

// ---------------------------------------------------------------------------
// Crypto helpers (DES / 3DES ECB via mbedtls)
// ---------------------------------------------------------------------------

// Encrypt one 8-byte block with DES or 3DES ECB depending on key length.
// key_len 8  -> single DES
// key_len 16 -> 3DES (two-key; if both halves equal, degrades to single DES)
// Returns 0 on success.
static int fmcos_ecb_encrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *in, uint8_t *out) {
    if (key_len == 8) {
        mbedtls_des_context ctx;
        mbedtls_des_init(&ctx);
        mbedtls_des_setkey_enc(&ctx, key);
        mbedtls_des_crypt_ecb(&ctx, in, out);
        mbedtls_des_free(&ctx);
    } else if (key_len == 16) {
        // If both halves identical, use single DES with the first half
        if (memcmp(key, key + 8, 8) == 0) {
            mbedtls_des_context ctx;
            mbedtls_des_init(&ctx);
            mbedtls_des_setkey_enc(&ctx, key);
            mbedtls_des_crypt_ecb(&ctx, in, out);
            mbedtls_des_free(&ctx);
        } else {
            mbedtls_des3_context ctx;
            mbedtls_des3_init(&ctx);
            mbedtls_des3_set2key_enc(&ctx, key);
            mbedtls_des3_crypt_ecb(&ctx, in, out);
            mbedtls_des3_free(&ctx);
        }
    } else {
        PrintAndLogEx(ERR, "Unsupported key length %zu (must be 8 or 16)", key_len);
        return PM3_EINVARG;
    }
    return PM3_SUCCESS;
}

// ---------------------------------------------------------------------------
// Crypto helpers - Phase 3
// ---------------------------------------------------------------------------

// Raw single-DES ECB encrypt (always 8-byte key, 8-byte block).
static void fmcos_des8_ecb_enc(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]) {
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, in, out);
    mbedtls_des_free(&ctx);
}

// Raw single-DES ECB decrypt (always 8-byte key, 8-byte block).
static void fmcos_des8_ecb_dec(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]) {
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    mbedtls_des_setkey_dec(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, in, out);
    mbedtls_des_free(&ctx);
}

// ISO7816 pad: append 0x80 then zeros to reach a multiple of 8.
// out must have room for at least in_len + 8 bytes.  Returns padded length.
static size_t fmcos_iso7816_pad(const uint8_t *in, size_t in_len, uint8_t *out) {
    memcpy(out, in, in_len);
    out[in_len] = 0x80;
    size_t padded = in_len + 1;
    while (padded % 8 != 0) {
        out[padded++] = 0x00;
    }
    return padded;
}


// DES CBC-MAC with ISO7816 padding.  key must be exactly 8 bytes.
// iv is 8 bytes (typically the GET CHALLENGE response).
// Writes mac_len bytes (<= 8) into mac_out.
static int fmcos_des_mac(const uint8_t *buf, size_t buf_len,
                         const uint8_t key[8],
                         const uint8_t iv[8],
                         uint8_t *mac_out, size_t mac_len) {
    size_t max_padded = buf_len + 8;
    uint8_t *padded = calloc(max_padded, 1);
    if (padded == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t padded_len = fmcos_iso7816_pad(buf, buf_len, padded);

    uint8_t val[8];
    memcpy(val, iv, 8);

    for (size_t i = 0; i < padded_len; i += 8) {
        uint8_t xored[8];
        for (int j = 0; j < 8; j++) {
            xored[j] = val[j] ^ padded[i + j];
        }
        fmcos_des8_ecb_enc(key, xored, val);
    }

    free(padded);

    if (mac_len > 8) {
        mac_len = 8;
    }
    memcpy(mac_out, val, mac_len);
    return PM3_SUCCESS;
}

// 3DES Retail MAC: DES-CBC-MAC with left-key-half (8 bytes), then decrypt
// with right-key-half, then re-encrypt with left-key-half.
// key must be exactly 16 bytes.  Writes mac_len bytes (<= 8) into mac_out.
static int fmcos_3des_mac(const uint8_t *buf, size_t buf_len,
                          const uint8_t key[16],
                          const uint8_t iv[8],
                          uint8_t *mac_out, size_t mac_len) {
    const uint8_t *key_l = key;
    const uint8_t *key_r = key + 8;

    uint8_t val[8];
    int res = fmcos_des_mac(buf, buf_len, key_l, iv, val, 8);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t tmp[8];
    fmcos_des8_ecb_dec(key_r, val, tmp);
    fmcos_des8_ecb_enc(key_l, tmp, val);

    if (mac_len > 8) {
        mac_len = 8;
    }
    memcpy(mac_out, val, mac_len);
    return PM3_SUCCESS;
}


// Build a 4-byte command MAC over CLA|INS|P1|P2|Lc[|data].
// iv is the 8-byte GET CHALLENGE response used as the CBC IV.
// key_len 8 -> fmcos_des_mac; key_len 16 -> fmcos_3des_mac.
// Lc encodes payload_len + 4 (reserves space for the MAC itself).
static int fmcos_packet_mac(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                            const uint8_t *data, size_t data_len,
                            const uint8_t *iv,
                            const uint8_t *key, size_t key_len,
                            uint8_t *mac_out) {
    size_t buf_len = 5 + data_len;
    uint8_t *mac_buf = calloc(buf_len, 1);
    if (mac_buf == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    mac_buf[0] = cla;
    mac_buf[1] = ins;
    mac_buf[2] = p1;
    mac_buf[3] = p2;
    mac_buf[4] = (uint8_t)((data_len + 4) & 0xFF);
    if (data_len > 0) {
        memcpy(&mac_buf[5], data, data_len);
    }

    int res;
    if (key_len == 8) {
        res = fmcos_des_mac(mac_buf, buf_len, key, iv, mac_out, 4);
    } else {
        res = fmcos_3des_mac(mac_buf, buf_len, key, iv, mac_out, 4);
    }

    free(mac_buf);
    return res;
}

// ---------------------------------------------------------------------------
// Crypto helpers - Phase 5 (encrypt / decrypt for secure channel)
// ---------------------------------------------------------------------------

// Remove ISO7816 padding: scan backwards for 0x80 marker.
static int fmcos_iso7816_unpad(const uint8_t *buf, size_t padded_len, size_t *out_len) {
    if (padded_len == 0 || padded_len % 8 != 0) {
        return PM3_ESOFT;
    }
    for (size_t i = padded_len; i > 0; i--) {
        if (buf[i - 1] == 0x80) {
            *out_len = i - 1;
            return PM3_SUCCESS;
        }
        if (buf[i - 1] != 0x00) {
            break;
        }
    }
    PrintAndLogEx(ERR, "ISO7816 padding marker not found");
    return PM3_ESOFT;
}

// Pad with ISO7816 and ECB-encrypt (DES or 3DES) the full buffer.
// out must hold at least data_len + 8 bytes.  Returns encrypted length.
static size_t fmcos_encrypt(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len, uint8_t *out) {
    uint8_t padded[512] = {0};
    if (data_len + 8 > sizeof(padded)) {
        PrintAndLogEx(ERR, "fmcos_encrypt: data too large (%zu bytes)", data_len);
        return 0;
    }
    size_t padded_len = fmcos_iso7816_pad(data, data_len, padded);
    for (size_t off = 0; off < padded_len; off += 8) {
        if (fmcos_ecb_encrypt(key, key_len, padded + off, out + off) != PM3_SUCCESS) {
            return 0;
        }
    }
    return padded_len;
}

// ECB-decrypt (DES or 3DES) then remove ISO7816 padding.
// out must be at least data_len bytes.  *out_len receives unpadded length.
static int fmcos_decrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *out, size_t *out_len) {
    if (data_len == 0 || data_len % 8 != 0) {
        PrintAndLogEx(ERR, "Encrypted length must be a non-zero multiple of 8");
        return PM3_ESOFT;
    }
    for (size_t off = 0; off < data_len; off += 8) {
        if (key_len == 8) {
            fmcos_des8_ecb_dec(key, data + off, out + off);
        } else {
            mbedtls_des3_context c3;
            mbedtls_des3_init(&c3);
            mbedtls_des3_set2key_dec(&c3, key);
            mbedtls_des3_crypt_ecb(&c3, data + off, out + off);
            mbedtls_des3_free(&c3);
        }
    }
    return fmcos_iso7816_unpad(out, data_len, out_len);
}

// ---------------------------------------------------------------------------
// Card-level primitives
// ---------------------------------------------------------------------------

// SELECT FILE by 2-byte file ID.
static int fmcos_select(uint16_t file_id, bool activate, bool leave_on,
                        uint8_t *resp, int *resp_len) {
    uint8_t apdu[7];
    apdu[0] = 0x00;
    apdu[1] = 0xA4;
    apdu[2] = 0x00;
    apdu[3] = 0x00;
    apdu[4] = 0x02;
    apdu[5] = (file_id >> 8) & 0xFF;
    apdu[6] = file_id & 0xFF;
    return fmcos_send_apdu(apdu, sizeof(apdu), activate, leave_on, resp, resp_len);
}

// SELECT by AID / DF name.
static int fmcos_select_by_name(const uint8_t *name, size_t name_len,
                                bool activate, bool leave_on,
                                uint8_t *resp, int *resp_len) {
    if (name_len == 0 || name_len > 16) {
        PrintAndLogEx(ERR, "AID must be 1-16 bytes");
        return PM3_EINVARG;
    }
    uint8_t apdu[21];
    apdu[0] = 0x00;
    apdu[1] = 0xA4;
    apdu[2] = 0x04;
    apdu[3] = 0x00;
    apdu[4] = (uint8_t)name_len;
    memcpy(&apdu[5], name, name_len);
    return fmcos_send_apdu(apdu, 5 + name_len, activate, leave_on, resp, resp_len);
}

// GET CHALLENGE - request a random nonce from the card.
// chal_len must be 4 or 8. Always writes 8 bytes into chal_out
// (4-byte responses are zero-padded to 8 per FMCOS spec).
// activate: pass true when the RF field is not yet on.
static int fmcos_get_challenge(uint8_t chal_len, bool activate, uint8_t *chal_out) {
    if (chal_len != 4 && chal_len != 8) {
        PrintAndLogEx(ERR, "Challenge length must be 4 or 8");
        return PM3_EINVARG;
    }

    uint8_t apdu[5] = {0x00, 0x84, 0x00, 0x00, chal_len};
    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;

    int res = fmcos_send_apdu(apdu, sizeof(apdu), activate, true, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (resp_len < 2) {
        PrintAndLogEx(ERR, "Empty response to GET CHALLENGE");
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2];
    uint8_t sw2 = resp[resp_len - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        fmcos_print_sw(sw1, sw2);
        return PM3_ESOFT;
    }

    int data_len = resp_len - 2;
    if (data_len != (int)chal_len) {
        PrintAndLogEx(ERR, "Expected %d challenge bytes, got %d", chal_len, data_len);
        return PM3_ESOFT;
    }

    memset(chal_out, 0x00, 8);
    memcpy(chal_out, resp, data_len);
    return PM3_SUCCESS;
}

// Simple TLV walker: find first occurrence of a 1-byte tag.
static const uint8_t *fmcos_tlv_find(const uint8_t *buf, size_t len,
                                     uint8_t tag, size_t *vlen) {
    size_t i = 0;
    while (i + 1 < len) {
        uint8_t cur_tag = buf[i++];
        uint8_t cur_len = buf[i++];
        if (i + cur_len > len) {
            break;
        }
        if (cur_tag == tag) {
            *vlen = cur_len;
            return &buf[i];
        }
        i += cur_len;
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// hf fmcos info  (Phase 1)
// ---------------------------------------------------------------------------

static int CmdHFFmcosInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos info",
                  "Detect and print information about an FMCOS CPU card.\n"
                  "Selects the Master File (3F00) and parses the FCI TLV response.",
                  "hf fmcos info\n"
                  "hf fmcos info -a");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool apdu_log = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    SetAPDULogging(apdu_log);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;

    int res = fmcos_select(0x3F00, true, false, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "No card in field or APDU exchange failed");
        DropField();
        return res;
    }

    if (resp_len < 2) {
        PrintAndLogEx(ERR, "Card returned empty response");
        DropField();
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2];
    uint8_t sw2 = resp[resp_len - 1];

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("FMCOS Card Information") " ---");

    if (sw1 != 0x90 || sw2 != 0x00) {
        fmcos_print_sw(sw1, sw2);
        PrintAndLogEx(WARNING, "SELECT MF (3F00) failed - may not be an FMCOS card");
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "SELECT MF (3F00) " _GREEN_("OK"));

    int data_len = resp_len - 2;
    if (data_len > 0) {
        PrintAndLogEx(INFO, "FCI: %s", sprint_hex(resp, (size_t)data_len));

        size_t outer_len = 0;
        const uint8_t *outer = fmcos_tlv_find(resp, (size_t)data_len, 0x6F, &outer_len);

        if (outer != NULL) {
            size_t dfname_len = 0;
            const uint8_t *dfname = fmcos_tlv_find(outer, outer_len, 0x84, &dfname_len);
            if (dfname != NULL) {
                bool name_is_ascii = true;
                for (size_t i = 0; i < dfname_len; i++) {
                    if (dfname[i] < 0x20 || dfname[i] > 0x7E) {
                        name_is_ascii = false;
                        break;
                    }
                }
                if (name_is_ascii) {
                    PrintAndLogEx(INFO, "DF Name (84): %s ( " _GREEN_("%.*s") " )",
                                  sprint_hex(dfname, dfname_len),
                                  (int)dfname_len, (const char *)dfname);
                } else {
                    PrintAndLogEx(INFO, "DF Name (84): %s", sprint_hex(dfname, dfname_len));
                }
            }

            size_t prop_len = 0;
            const uint8_t *prop = fmcos_tlv_find(outer, outer_len, 0xA5, &prop_len);
            if (prop != NULL) {
                size_t sfi_len = 0;
                const uint8_t *sfi = fmcos_tlv_find(prop, prop_len, 0x88, &sfi_len);
                if (sfi != NULL && sfi_len >= 1) {
                    PrintAndLogEx(INFO, "SFI (88): " _YELLOW_("%02X"), sfi[0]);
                }

                // 9F0C is a 2-byte tag - walk manually
                for (size_t i = 0; i + 3 < prop_len; i++) {
                    if (prop[i] == 0x9F && prop[i + 1] == 0x0C) {
                        uint8_t vl = prop[i + 2];
                        if (i + 3 + vl <= prop_len) {
                            PrintAndLogEx(INFO, "Issuer ID (9F0C): %s",
                                          sprint_hex(&prop[i + 3], vl));
                        }
                        break;
                    }
                }
            }
        }
    }

    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf fmcos select --id 3f00") "` to navigate the file system");
    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf fmcos authexternal --id 0 --key ffffffffffffffff") "` to authenticate");
    PrintAndLogEx(NORMAL, "");

    DropField();
    return PM3_SUCCESS;
}

// ---------------------------------------------------------------------------
// hf fmcos select  (Phase 2)
// ---------------------------------------------------------------------------

static int CmdHFFmcosSelect(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos select",
                  "SELECT FILE by 2-byte ID or AID name.\n"
                  "Activates the RF field, selects the file, then drops the field.",
                  "hf fmcos select --id 3f00\n"
                  "hf fmcos select --id 5f00 -v\n"
                  "hf fmcos select --name 325041592e5359532e4444463031");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "id",   "<hex>", "2-byte file ID (4 hex chars)"),
        arg_str0(NULL, "name", "<hex>", "AID / DF name bytes (up to 16 bytes)"),
        arg_lit0("k", "keep",    "keep field ON after command"),
        arg_lit0("v", "verbose", "print full FCI TLV response"),
        arg_lit0("a", "apdu",    "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t id_buf[2] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 1, id_buf, &id_len);

    uint8_t name_buf[16] = {0};
    int name_len = 0;
    CLIGetHexWithReturn(ctx, 2, name_buf, &name_len);

    bool keep    = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    bool apdu_log = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (id_len == 0 && name_len == 0) {
        PrintAndLogEx(ERR, "Provide either --id or --name");
        return PM3_EINVARG;
    }
    if (id_len > 0 && id_len != 2) {
        PrintAndLogEx(ERR, "--id must be exactly 2 bytes (4 hex chars)");
        return PM3_EINVARG;
    }

    SetAPDULogging(apdu_log);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res;

    if (name_len > 0) {
        res = fmcos_select_by_name(name_buf, (size_t)name_len, true, keep, resp, &resp_len);
    } else {
        uint16_t file_id = ((uint16_t)id_buf[0] << 8) | id_buf[1];
        res = fmcos_select(file_id, true, keep, resp, &resp_len);
    }

    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (resp_len < 2) {
        PrintAndLogEx(ERR, "Empty card response");
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2];
    uint8_t sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);

    if (sw1 == 0x90 && sw2 == 0x00 && verbose) {
        int data_len = resp_len - 2;
        if (data_len > 0) {
            PrintAndLogEx(INFO, "FCI: %s", sprint_hex(resp, (size_t)data_len));
        }
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// Parse a required hex integer argument; returns PM3_EINVARG and prints an
// error on malformed input.  Accepts bare hex digits (no "0x" prefix required).
static int fmcos_parse_hex_int(const char *s, int *out) {
    if (s == NULL || *s == '\0') {
        PrintAndLogEx(ERR, "Empty hex value");
        return PM3_EINVARG;
    }
    char *end = NULL;
    long v = strtol(s, &end, 16);
    if (end == s || *end != '\0') {
        PrintAndLogEx(ERR, "Invalid hex value: %s", s);
        return PM3_EINVARG;
    }
    *out = (int)v;
    return PM3_SUCCESS;
}

// ---------------------------------------------------------------------------
// hf fmcos authexternal  (Phase 2)
// ---------------------------------------------------------------------------

static int CmdHFFmcosAuthExternal(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos authexternal",
                  "EXTERNAL AUTHENTICATE.\n"
                  "Requests a challenge from the card, encrypts it with the provided\n"
                  "DES (8-byte) or 3DES (16-byte) key, then sends EXTERNAL AUTHENTICATE.",
                  "hf fmcos authexternal --id 0 --key ffffffffffffffff\n"
                  "hf fmcos authexternal --id 1 --key 0102030405060708090a0b0c0d0e0f10");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",  "<hex>",   "key ID (P2 in EXTERNAL AUTHENTICATE)"),
        arg_str1(NULL, "key", "<hex>",   "DES key (8 bytes) or 3DES key (16 bytes)"),
        arg_lit0("k", "keep", "keep field ON after command"),
        arg_lit0("a", "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int key_id;
    int res = fmcos_parse_hex_int(arg_get_str(ctx, 1)->sval[0], &key_id);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t key[16] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 2, key, &key_len);

    bool keep     = arg_get_lit(ctx, 3);
    bool apdu_log = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (key_id < 0 || key_id > 0xFF) {
        PrintAndLogEx(ERR, "Key ID must be 0-255");
        return PM3_EINVARG;
    }
    if (key_len != 8 && key_len != 16) {
        PrintAndLogEx(ERR, "Key must be 8 bytes (DES) or 16 bytes (3DES)");
        return PM3_EINVARG;
    }

    SetAPDULogging(apdu_log);

    // GET CHALLENGE (8 bytes) - activates the field
    uint8_t challenge[8] = {0};
    res = fmcos_get_challenge(8, true, challenge);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    PrintAndLogEx(INFO, "Challenge: %s", sprint_hex(challenge, 8));

    // Encrypt challenge with the key (DES or 3DES ECB, single 8-byte block)
    uint8_t encrypted[8] = {0};
    res = fmcos_ecb_encrypt(key, (size_t)key_len, challenge, encrypted);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    // EXTERNAL AUTHENTICATE: CLA=00 INS=82 P1=00 P2=key_id Lc=08 Data=encrypted
    uint8_t ea_apdu[13];
    ea_apdu[0] = 0x00;
    ea_apdu[1] = 0x82;
    ea_apdu[2] = 0x00;
    ea_apdu[3] = (uint8_t)key_id;
    ea_apdu[4] = 0x08;
    memcpy(&ea_apdu[5], encrypted, 8);

    uint8_t ea_resp[APDU_RES_LEN] = {0};
    int ea_resp_len = 0;
    res = fmcos_send_apdu(ea_apdu, sizeof(ea_apdu), false, keep, ea_resp, &ea_resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (ea_resp_len < 2) {
        PrintAndLogEx(ERR, "Empty response to EXTERNAL AUTHENTICATE");
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = ea_resp[ea_resp_len - 2];
    uint8_t sw2 = ea_resp[ea_resp_len - 1];
    fmcos_print_sw(sw1, sw2);

    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "External authentication " _GREEN_("successful"));
    } else {
        PrintAndLogEx(FAILED, "External authentication " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// ---------------------------------------------------------------------------
// hf fmcos authinternal  (Phase 2)
// ---------------------------------------------------------------------------

static int CmdHFFmcosAuthInternal(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos authinternal",
                  "INTERNAL AUTHENTICATE.\n"
                  "Sends a challenge to the card and the card proves it knows the key.",
                  "hf fmcos authinternal --p1 00 --p2 00 --data 0102030405060708");

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "p1",   "<0-255>", "P1 parameter (default 0)"),
        arg_int0(NULL, "p2",   "<0-255>", "P2 parameter / key ID (default 0)"),
        arg_str1(NULL, "data", "<hex>",   "challenge data (8 bytes)"),
        arg_lit0("k", "keep", "keep field ON after command"),
        arg_lit0("a", "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int p1 = arg_get_int_def(ctx, 1, 0);
    int p2 = arg_get_int_def(ctx, 2, 0);

    uint8_t data[32] = {0};
    int data_len = 0;
    CLIGetHexWithReturn(ctx, 3, data, &data_len);

    bool keep     = arg_get_lit(ctx, 4);
    bool apdu_log = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (data_len == 0) {
        PrintAndLogEx(ERR, "Provide challenge --data (8 bytes)");
        return PM3_EINVARG;
    }

    SetAPDULogging(apdu_log);

    // INTERNAL AUTHENTICATE: CLA=00 INS=88
    uint8_t apdu[5 + 32];
    apdu[0] = 0x00;
    apdu[1] = 0x88;
    apdu[2] = (uint8_t)p1;
    apdu[3] = (uint8_t)p2;
    apdu[4] = (uint8_t)data_len;
    memcpy(&apdu[5], data, (size_t)data_len);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res = fmcos_send_apdu(apdu, (size_t)(5 + data_len), true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (resp_len < 2) {
        PrintAndLogEx(ERR, "Empty response to INTERNAL AUTHENTICATE");
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2];
    uint8_t sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);

    int rdata_len = resp_len - 2;
    if (rdata_len > 0) {
        PrintAndLogEx(INFO, "Response: %s", sprint_hex(resp, (size_t)rdata_len));
    }

    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "Internal authentication " _GREEN_("successful"));
    } else {
        PrintAndLogEx(FAILED, "Internal authentication " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// ---------------------------------------------------------------------------
// Phase 4 - File management
// ---------------------------------------------------------------------------

// Protection level constants shared by create-file, read, write, write-key.
#define FMCOS_PROT_NONE   0
#define FMCOS_PROT_MAC  0x80
#define FMCOS_PROT_ENC  0xC0

// Shared inner helper: execute an UPDATE BINARY / UPDATE RECORD / APPEND RECORD
// (or WRITE KEY) APDU with optional MAC or encrypt-then-MAC protection.
// cla: base class byte (0x00 for data commands, 0x80 for proprietary).
// data/data_len: application payload before any protection transforms.
// prot: FMCOS_PROT_NONE, FMCOS_PROT_MAC, or FMCOS_PROT_ENC.
// activate: true to wake the card (passed to GET CHALLENGE if protected, else
//           to the write APDU directly).
static int fmcos_write_cmd(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                           const uint8_t *data, size_t data_len,
                           int prot, const uint8_t *key, size_t key_len,
                           bool activate, bool leave_on,
                           uint8_t *resp_out, int *resp_len_out) {
    uint8_t payload[272] = {0};
    size_t  payload_len = 0;

    if (prot == FMCOS_PROT_ENC) {
        uint8_t enc_in[256];
        if (data_len >= sizeof(enc_in)) {
            PrintAndLogEx(ERR, "Write data too large for ENC mode (%zu bytes, max 255)", data_len);
            return PM3_EINVARG;
        }
        enc_in[0] = (uint8_t)(data_len & 0xFF);
        memcpy(enc_in + 1, data, data_len);
        payload_len = fmcos_encrypt(key, key_len, enc_in, 1 + data_len, payload);
        if (payload_len == 0) {
            return PM3_ESOFT;
        }
        cla |= 0x04;
    } else {
        memcpy(payload, data, data_len);
        payload_len = data_len;
        if (prot == FMCOS_PROT_MAC) {
            cla |= 0x04;
        }
    }

    if (prot != FMCOS_PROT_NONE) {
        uint8_t chal[8] = {0};
        int res = fmcos_get_challenge(8, activate, chal);
        if (res != PM3_SUCCESS) {
            return res;
        }
        activate = false;

        uint8_t mac[4] = {0};
        res = fmcos_packet_mac(cla, ins, p1, p2, payload, payload_len, chal, key, key_len, mac);
        if (res != PM3_SUCCESS) {
            return res;
        }
        memcpy(payload + payload_len, mac, 4);
        payload_len += 4;
    }

    uint8_t apdu[280];
    apdu[0] = cla;
    apdu[1] = ins;
    apdu[2] = p1;
    apdu[3] = p2;
    apdu[4] = (uint8_t)payload_len;
    memcpy(apdu + 5, payload, payload_len);
    return fmcos_send_apdu(apdu, 5 + payload_len, activate, leave_on, resp_out, resp_len_out);
}

// Shared inner helper: execute READ BINARY or READ RECORD with optional
// MAC or encrypt protection.  On success, decrypted (or raw) data is written
// to data_out and *data_out_len receives the byte count.
// The response MAC is verified when prot != FMCOS_PROT_NONE.
static int fmcos_read_cmd(uint8_t ins, uint8_t p1, uint8_t p2, uint8_t read_len,
                          int prot, const uint8_t *key, size_t key_len,
                          bool activate, bool leave_on,
                          uint8_t *data_out, int *data_out_len) {
    uint8_t cla = 0x00;
    uint8_t mac_iv[8] = {0};

    if (prot != FMCOS_PROT_NONE) {
        cla = 0x04;
        int res = fmcos_get_challenge(8, activate, mac_iv);
        if (res != PM3_SUCCESS) {
            return res;
        }
        activate = false;
    }

    uint8_t apdu[11];
    size_t  apdu_len;
    if (prot != FMCOS_PROT_NONE) {
        // Case 4: CLA INS P1 P2 Lc=4 [MAC4] Le
        uint8_t mac[4] = {0};
        int res = fmcos_packet_mac(cla, ins, p1, p2, NULL, 0, mac_iv, key, key_len, mac);
        if (res != PM3_SUCCESS) {
            return res;
        }
        apdu[0] = cla;
        apdu[1] = ins;
        apdu[2] = p1;
        apdu[3] = p2;
        apdu[4] = 0x04;
        memcpy(apdu + 5, mac, 4);
        apdu[9] = read_len;
        apdu_len = 10;
    } else {
        // Case 2: CLA INS P1 P2 Le
        apdu[0] = cla;
        apdu[1] = ins;
        apdu[2] = p1;
        apdu[3] = p2;
        apdu[4] = read_len;
        apdu_len = 5;
    }

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res = fmcos_send_apdu(apdu, apdu_len, activate, leave_on, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (resp_len < 2) {
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 != 0x90 || sw2 != 0x00) {
        return PM3_ESOFT;
    }

    int data_len = resp_len - 2;

    if (prot == FMCOS_PROT_NONE) {
        memcpy(data_out, resp, (size_t)data_len);
        *data_out_len = data_len;
        return PM3_SUCCESS;
    }

    // Protected: response = [msg_bytes][mac4]
    if (data_len < 4) {
        PrintAndLogEx(ERR, "Protected response too short");
        return PM3_ESOFT;
    }
    int msg_len = data_len - 4;
    uint8_t *ret_mac = resp + msg_len;

    uint8_t calc_mac[4] = {0};
    if (key_len == 8) {
        res = fmcos_des_mac(resp, (size_t)msg_len, key, mac_iv, calc_mac, 4);
    } else {
        res = fmcos_3des_mac(resp, (size_t)msg_len, key, mac_iv, calc_mac, 4);
    }
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (memcmp(calc_mac, ret_mac, 4) != 0) {
        PrintAndLogEx(ERR, "Response MAC " _RED_("mismatch"));
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "Response MAC " _GREEN_("verified"));

    if (prot == FMCOS_PROT_ENC) {
        uint8_t plain[256] = {0};
        size_t  plain_len  = 0;
        res = fmcos_decrypt(key, key_len, resp, (size_t)msg_len, plain, &plain_len);
        if (res != PM3_SUCCESS) {
            return res;
        }
        if (plain_len == 0) {
            PrintAndLogEx(ERR, "Decrypted length byte missing");
            return PM3_ESOFT;
        }
        uint8_t actual_len = plain[0];
        if (actual_len > plain_len - 1) {
            PrintAndLogEx(ERR, "Decrypted length byte %u exceeds payload %zu", actual_len, plain_len - 1);
            return PM3_ESOFT;
        }
        memcpy(data_out, plain + 1, actual_len);
        *data_out_len = (int)actual_len;
    } else {
        memcpy(data_out, resp, (size_t)msg_len);
        *data_out_len = msg_len;
    }
    return PM3_SUCCESS;
}

static int CmdHFFmcosErase(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos erase",
                  "ERASE DF - erase all EFs in the currently selected DF",
                  "hf fmcos erase");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "keep field ON after command"),
        arg_lit0("a", "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool keep     = arg_get_lit(ctx, 1);
    bool apdu_log = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    SetAPDULogging(apdu_log);

    // CLA=80 INS=0E P1=00 P2=00 (no data, trailing 00 = Le/case-1 sentinel)
    uint8_t apdu[5] = {0x80, 0x0E, 0x00, 0x00, 0x00};
    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res = fmcos_send_apdu(apdu, sizeof(apdu), true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "DF " _GREEN_("erased"));
    } else {
        PrintAndLogEx(FAILED, "Erase " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFFmcosCreateDir(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos createdir",
                  "CREATE DIRECTORY (DF) inside the currently selected directory",
                  "hf fmcos createdir --id 3F01 --space 200 --cperm F0 --eperm F0 --appid 95 --name 77616C6C6574546573740A");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",    "<4hex>", "2-byte file ID"),
        arg_str1(NULL, "space", "<hex>",  "space to allocate for DF (bytes, hex, e.g. 200 = 512)"),
        arg_str1(NULL, "cperm", "<hex>",  "create permission byte"),
        arg_str1(NULL, "eperm", "<hex>",  "erase permission byte"),
        arg_str1(NULL, "appid", "<hex>",  "application ID byte"),
        arg_str0(NULL, "name",  "<hex>",  "DF name / AID, 0-16 bytes"),
        arg_lit0("k",  "keep",  "keep field ON after command"),
        arg_lit0("a",  "apdu",  "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t id_buf[2] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 1, id_buf, &id_len);
    int space;
    int res = fmcos_parse_hex_int(arg_get_str(ctx, 2)->sval[0], &space);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    uint8_t cperm[1] = {0};
    int cperm_len = 0;
    CLIGetHexWithReturn(ctx, 3, cperm, &cperm_len);
    uint8_t eperm[1] = {0};
    int eperm_len = 0;
    CLIGetHexWithReturn(ctx, 4, eperm, &eperm_len);
    uint8_t appid[1] = {0};
    int appid_len = 0;
    CLIGetHexWithReturn(ctx, 5, appid, &appid_len);
    uint8_t name[16] = {0};
    int name_len = 0;
    CLIGetHexWithReturn(ctx, 6, name, &name_len);
    bool keep     = arg_get_lit(ctx, 7);
    bool apdu_log = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if (id_len != 2) {
        PrintAndLogEx(ERR, "--id must be 2 bytes");
        return PM3_EINVARG;
    }
    if (space < 1 || space > 0xFFFF) {
        PrintAndLogEx(ERR, "--space out of range");
        return PM3_EINVARG;
    }
    if (cperm_len != 1 || eperm_len != 1 || appid_len != 1) {
        PrintAndLogEx(ERR, "--cperm, --eperm, --appid must each be 1 byte");
        return PM3_EINVARG;
    }
    SetAPDULogging(apdu_log);

    uint8_t data[25] = {0};
    size_t data_len = 0;
    data[data_len++] = 0x38;
    data[data_len++] = (space >> 8) & 0xFF;
    data[data_len++] = space & 0xFF;
    data[data_len++] = cperm[0];
    data[data_len++] = eperm[0];
    data[data_len++] = appid[0];
    data[data_len++] = 0xFF;
    data[data_len++] = 0xFF;
    if (name_len > 0) {
        memcpy(data + data_len, name, (size_t)name_len);
        data_len += (size_t)name_len;
    }

    uint8_t apdu[30];
    apdu[0] = 0x80;
    apdu[1] = 0xE0;
    apdu[2] = id_buf[0];
    apdu[3] = id_buf[1];
    apdu[4] = (uint8_t)data_len;
    memcpy(apdu + 5, data, data_len);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_send_apdu(apdu, 5 + data_len, true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "Directory " _GREEN_("created"));
    } else {
        PrintAndLogEx(FAILED, "Create directory " _RED_("failed"));
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// Option lists shared by create-file, read, write, write-key
static const CLIParserOption g_fmcos_filetype_opts[] = {
    {0x28, "bin"},
    {0x2A, "fix"},
    {0x2C, "var"},
    {0x2E, "loop"},
    {0x2F, "wallet"},
    {0,    NULL}
};

static const CLIParserOption g_fmcos_prot_opts[] = {
    {FMCOS_PROT_NONE, "none"},
    {FMCOS_PROT_MAC,  "mac"},
    {FMCOS_PROT_ENC,  "enc"},
    {0, NULL}
};

static const CLIParserOption g_fmcos_baltype_opts[] = {
    {0x01, "passbook"},
    {0x02, "wallet"},
    {0,    NULL}
};

static int CmdHFFmcosCreateFile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos createfile",
                  "CREATE EF in the current DF\n"
                  "Types: bin(0x28)  fix(0x2A)  var(0x2C)  loop(0x2E)  wallet(0x2F)\n"
                  "Prot:  none  mac(0x80)  enc(0xC0)  -- ORed into the type byte\n"
                  "For wallet/passbook type: --rperm=usage rights, --wperm ignored (EDEP write always 0x00),\n"
                  "--access=loop file link (low byte of the linked loop EF's file ID)",
                  "hf fmcos createfile --id 0101 --type bin  --size 32   --rperm FF --wperm FF --access 00\n"
                  "hf fmcos createfile --id 0018 --type loop --size 0517 --rperm F0 --wperm EF --access FF\n"
                  "hf fmcos createfile --id 0002 --type wallet --size 0208 --rperm F0 --wperm 00 --access 18");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",     "<4hex>", "2-byte file ID"),
        arg_str1(NULL, "type",   "<type>", "file type: bin fix var loop wallet"),
        arg_str1(NULL, "size",   "<hex>",  "file size in bytes (hex, e.g. 0208 = 520)"),
        arg_str1(NULL, "rperm",  "<hex>",  "read permission byte"),
        arg_str1(NULL, "wperm",  "<hex>",  "write permission byte"),
        arg_str1(NULL, "access", "<hex>",  "access rights byte"),
        arg_str0(NULL, "prot",   "<type>", "line protection: none(def) mac enc"),
        arg_lit0("k",  "keep",   "keep field ON after command"),
        arg_lit0("a",  "apdu",   "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t id_buf[2] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 1, id_buf, &id_len);
    int ftype = 0;
    int res = CLIGetOptionList(arg_get_str(ctx, 2), g_fmcos_filetype_opts, &ftype);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }

    int size;
    res = fmcos_parse_hex_int(arg_get_str(ctx, 3)->sval[0], &size);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    uint8_t rperm[1] = {0};
    int rperm_len = 0;
    CLIGetHexWithReturn(ctx, 4, rperm, &rperm_len);
    uint8_t wperm[1] = {0};
    int wperm_len = 0;
    CLIGetHexWithReturn(ctx, 5, wperm, &wperm_len);
    uint8_t access[1] = {0};
    int access_len = 0;
    CLIGetHexWithReturn(ctx, 6, access, &access_len);
    int prot = FMCOS_PROT_NONE;
    res = CLIGetOptionList(arg_get_str(ctx, 7), g_fmcos_prot_opts, &prot);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }

    bool keep     = arg_get_lit(ctx, 8);
    bool apdu_log = arg_get_lit(ctx, 9);
    CLIParserFree(ctx);

    if (id_len != 2) {
        PrintAndLogEx(ERR, "--id must be 2 bytes");
        return PM3_EINVARG;
    }
    if (size < 1 || size > 0xFFFF) {
        PrintAndLogEx(ERR, "--size out of range");
        return PM3_EINVARG;
    }
    if (rperm_len != 1 || wperm_len != 1 || access_len != 1) {
        PrintAndLogEx(ERR, "--rperm, --wperm, --access must each be 1 byte");
        return PM3_EINVARG;
    }
    SetAPDULogging(apdu_log);

    // For wallet/passbook (0x2F): [type][size_hi][size_lo][usage_rights][0x00][0xFF][loop_file_id]
    //   byte[4] is always 0x00 -- EDEP write permission is fixed; balance written via financial APDUs only
    //   byte[6] is the low byte of the linked loop EF's file ID (e.g. 0x18 for loop file 0x0018)
    // For all other types: [type|prot][size_hi][size_lo][rperm][wperm][0xFF][access]
    uint8_t data[7] = {
        (uint8_t)(ftype | prot),
        (size >> 8) & 0xFF, size & 0xFF,
        rperm[0],
        (ftype == 0x2F) ? 0x00 : wperm[0],
        0xFF,
        access[0]
    };
    uint8_t apdu[12];
    apdu[0] = 0x80;
    apdu[1] = 0xE0;
    apdu[2] = id_buf[0];
    apdu[3] = id_buf[1];
    apdu[4] = 7;
    memcpy(apdu + 5, data, 7);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_send_apdu(apdu, 12, true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "File " _GREEN_("created"));
    } else {
        PrintAndLogEx(FAILED, "Create file " _RED_("failed"));
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFFmcosCreateKeyfile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos createkeyfile",
                  "CREATE KEYFILE in the current DF",
                  "hf fmcos createkeyfile --id 0000 --space 200 --dfsid 95 --perm F0");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",    "<4hex>", "2-byte file ID (usually 0000)"),
        arg_str1(NULL, "space", "<hex>",  "space to allocate (bytes, hex, e.g. 200 = 512)"),
        arg_str1(NULL, "dfsid", "<hex>",  "DF SID byte"),
        arg_str1(NULL, "perm",  "<hex>",  "key permission byte"),
        arg_lit0("k",  "keep",  "keep field ON after command"),
        arg_lit0("a",  "apdu",  "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t id_buf[2] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 1, id_buf, &id_len);
    int space;
    int res = fmcos_parse_hex_int(arg_get_str(ctx, 2)->sval[0], &space);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    uint8_t dfsid[1] = {0};
    int dfsid_len = 0;
    CLIGetHexWithReturn(ctx, 3, dfsid, &dfsid_len);
    uint8_t perm[1] = {0};
    int perm_len = 0;
    CLIGetHexWithReturn(ctx, 4, perm, &perm_len);
    bool keep     = arg_get_lit(ctx, 5);
    bool apdu_log = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (id_len != 2) {
        PrintAndLogEx(ERR, "--id must be 2 bytes");
        return PM3_EINVARG;
    }
    if (space < 1 || space > 0xFFFF) {
        PrintAndLogEx(ERR, "--space out of range");
        return PM3_EINVARG;
    }
    if (dfsid_len != 1 || perm_len != 1) {
        PrintAndLogEx(ERR, "--dfsid and --perm must each be 1 byte");
        return PM3_EINVARG;
    }
    SetAPDULogging(apdu_log);

    // data = [0x3F][space_hi][space_lo][dfsid][perm][0xFF][0xFF]
    uint8_t data[7] = {
        0x3F,
        (space >> 8) & 0xFF, space & 0xFF,
        dfsid[0], perm[0], 0xFF, 0xFF
    };
    uint8_t apdu[12];
    apdu[0] = 0x80;
    apdu[1] = 0xE0;
    apdu[2] = id_buf[0];
    apdu[3] = id_buf[1];
    apdu[4] = 7;
    memcpy(apdu + 5, data, 7);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_send_apdu(apdu, 12, true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "Keyfile " _GREEN_("created"));
    } else {
        PrintAndLogEx(FAILED, "Create keyfile " _RED_("failed"));
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// ---------------------------------------------------------------------------
// Phase 5 - Data access
// ---------------------------------------------------------------------------

static int CmdHFFmcosReadBinary(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos readbinary",
                  "READ BINARY from the current transparent EF\n"
                  "p1/p2 encode the file offset (p1=offset_hi, p2=offset_lo).\n"
                  "Protection: none(def)  mac  enc",
                  "hf fmcos readbinary --p1 00 --p2 00 --len 16\n"
                  "hf fmcos readbinary --p1 00 --p2 00 --len 16 --prot mac --key aabbccddeeff0011");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "p1",   "<hex>", "P1 byte (offset high)"),
        arg_str1(NULL, "p2",   "<hex>", "P2 byte (offset low)"),
        arg_int1(NULL, "len",  "<n>",   "number of bytes to read (0 = read all)"),
        arg_str0(NULL, "prot", "<type>", "protection: none(def) mac enc"),
        arg_str0(NULL, "key",  "<hex>", "line-protection key (8 or 16 bytes)"),
        arg_lit0("k",  "keep", "keep field ON after command"),
        arg_lit0("a",  "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t p1b[1] = {0};
    int p1_len = 0;
    CLIGetHexWithReturn(ctx, 1, p1b, &p1_len);
    uint8_t p2b[1] = {0};
    int p2_len = 0;
    CLIGetHexWithReturn(ctx, 2, p2b, &p2_len);
    int rlen = arg_get_int_def(ctx, 3, 0);
    int prot = FMCOS_PROT_NONE;
    int res = CLIGetOptionList(arg_get_str(ctx, 4), g_fmcos_prot_opts, &prot);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }

    uint8_t key[16] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 5, key, &key_len);
    bool keep     = arg_get_lit(ctx, 6);
    bool apdu_log = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if (p1_len != 1 || p2_len != 1) {
        PrintAndLogEx(ERR, "--p1 and --p2 must each be 1 byte");
        return PM3_EINVARG;
    }
    if (rlen < 0 || rlen > 255) {
        PrintAndLogEx(ERR, "--len must be 0-255");
        return PM3_EINVARG;
    }
    if (prot != FMCOS_PROT_NONE) {
        if (key_len != 8 && key_len != 16) {
            PrintAndLogEx(ERR, "--key must be 8 or 16 bytes when --prot is set");
            return PM3_EINVARG;
        }
    }
    SetAPDULogging(apdu_log);

    uint8_t data_out[256] = {0};
    int data_out_len = 0;
    res = fmcos_read_cmd(0xB0, p1b[0], p2b[0], (uint8_t)rlen,
                         prot, key, (size_t)key_len,
                         true, keep, data_out, &data_out_len);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Data: " _GREEN_("%s"), sprint_hex(data_out, (size_t)data_out_len));
    }
    if (!keep) {
        DropField();
    }
    return res;
}

static int CmdHFFmcosReadRecord(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos readrecord",
                  "READ RECORD from the current record-based EF\n"
                  "Protection: none(def)  mac  enc\n"
                  "Use --tlv for variable-length (VAR) files: requests 2 extra bytes and strips the 00[len] TLV prefix from the response.",
                  "hf fmcos readrecord --rec 01 --fid 01 --len 20\n"
                  "hf fmcos readrecord --rec 01 --fid 06 --len 16 --tlv\n"
                  "hf fmcos readrecord --rec 01 --fid 01 --len 20 --prot mac --key aabbccddeeff0011");
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "rec",  "<n>",   "record number (1-based)"),
        arg_str1(NULL, "fid",  "<hex>", "SFI reference byte (1 byte, 1-30)"),
        arg_int1(NULL, "len",  "<n>",   "record data length in bytes (without TLV overhead)"),
        arg_str0(NULL, "prot", "<type>", "protection: none(def) mac enc"),
        arg_str0(NULL, "key",  "<hex>", "line-protection key (8 or 16 bytes)"),
        arg_lit0(NULL, "tlv",  "wrap/unwrap TLV (00[len][data]) for variable-length records"),
        arg_lit0("k",  "keep", "keep field ON after command"),
        arg_lit0("a",  "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int rec     = arg_get_int_def(ctx, 1, 0);
    uint8_t fid_buf[1] = {0};
    int fid_len = 0;
    CLIGetHexWithReturn(ctx, 2, fid_buf, &fid_len);
    int rlen    = arg_get_int_def(ctx, 3, 0);
    int prot    = FMCOS_PROT_NONE;
    int res = CLIGetOptionList(arg_get_str(ctx, 4), g_fmcos_prot_opts, &prot);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    uint8_t key[16] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 5, key, &key_len);
    bool use_tlv  = arg_get_lit(ctx, 6);
    bool keep     = arg_get_lit(ctx, 7);
    bool apdu_log = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if (rec < 1 || rec > 255) {
        PrintAndLogEx(ERR, "--rec must be 1-255");
        return PM3_EINVARG;
    }
    if (fid_len != 1) {
        PrintAndLogEx(ERR, "--fid must be 1 byte");
        return PM3_EINVARG;
    }
    if (rlen < 0 || rlen > 253) {
        PrintAndLogEx(ERR, "--len must be 0-253");
        return PM3_EINVARG;
    }
    if (prot != FMCOS_PROT_NONE) {
        if (key_len != 8 && key_len != 16) {
            PrintAndLogEx(ERR, "--key must be 8 or 16 bytes when --prot is set");
            return PM3_EINVARG;
        }
    }
    SetAPDULogging(apdu_log);

    // For TLV records the card returns 00[len][data], so request 2 extra bytes
    int le = use_tlv ? rlen + 2 : rlen;
    uint8_t p2 = (uint8_t)(((fid_buf[0] & 0x1F) << 3) | 4);
    uint8_t data_out[256] = {0};
    int data_out_len = 0;
    res = fmcos_read_cmd(0xB2, (uint8_t)rec, p2, (uint8_t)le,
                         prot, key, (size_t)key_len,
                         true, keep, data_out, &data_out_len);
    if (res == PM3_SUCCESS) {
        uint8_t *payload = data_out;
        int payload_len  = data_out_len;
        if (use_tlv) {
            // Strip 00[len] prefix; verify tag is 00 and length matches
            if (data_out_len >= 2 && data_out[0] == 0x00) {
                payload     = data_out + 2;
                payload_len = data_out_len - 2;
            } else {
                PrintAndLogEx(WARNING, "TLV prefix not found in response (tag=%02X)", data_out[0]);
            }
        }
        PrintAndLogEx(SUCCESS, "Record: " _GREEN_("%s"), sprint_hex(payload, (size_t)payload_len));
    }
    if (!keep) {
        DropField();
    }
    return res;
}


static int CmdHFFmcosWriteBinary(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos writebinary",
                  "UPDATE BINARY in the current transparent EF\n"
                  "Protection: none(def)  mac  enc",
                  "hf fmcos writebinary --p1 00 --p2 00 --data 0102030405060708\n"
                  "hf fmcos writebinary --p1 00 --p2 00 --data 01020304 --prot mac --key aabbccddeeff0011");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "p1",   "<hex>",  "P1 byte (offset high)"),
        arg_str1(NULL, "p2",   "<hex>",  "P2 byte (offset low)"),
        arg_str1(NULL, "data", "<hex>",  "data to write"),
        arg_str0(NULL, "prot", "<type>", "protection: none(def) mac enc"),
        arg_str0(NULL, "key",  "<hex>",  "line-protection key (8 or 16 bytes)"),
        arg_lit0("k",  "keep", "keep field ON after command"),
        arg_lit0("a",  "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t p1b[1] = {0};
    int p1_len = 0;
    CLIGetHexWithReturn(ctx, 1, p1b, &p1_len);
    uint8_t p2b[1] = {0};
    int p2_len = 0;
    CLIGetHexWithReturn(ctx, 2, p2b, &p2_len);
    uint8_t wdata[245] = {0};
    int wdata_len = 0;
    CLIGetHexWithReturn(ctx, 3, wdata, &wdata_len);
    int prot = FMCOS_PROT_NONE;
    int res = CLIGetOptionList(arg_get_str(ctx, 4), g_fmcos_prot_opts, &prot);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    uint8_t key[16] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 5, key, &key_len);
    bool keep     = arg_get_lit(ctx, 6);
    bool apdu_log = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if (p1_len != 1 || p2_len != 1) {
        PrintAndLogEx(ERR, "--p1 and --p2 must each be 1 byte");
        return PM3_EINVARG;
    }
    if (wdata_len < 1) {
        PrintAndLogEx(ERR, "--data required");
        return PM3_EINVARG;
    }
    if (prot != FMCOS_PROT_NONE && key_len != 8 && key_len != 16) {
        PrintAndLogEx(ERR, "--key must be 8 or 16 bytes when --prot is set");
        return PM3_EINVARG;
    }
    SetAPDULogging(apdu_log);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_write_cmd(0x00, 0xD6, p1b[0], p2b[0],
                          wdata, (size_t)wdata_len,
                          prot, key, (size_t)key_len,
                          true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "Binary " _GREEN_("written"));
    } else {
        PrintAndLogEx(FAILED, "Write binary " _RED_("failed"));
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFFmcosWriteRecord(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos writerecord",
                  "UPDATE RECORD in the current record-based EF\n"
                  "Protection: none(def)  mac  enc\n"
                  "Use --tlv for variable-length (VAR) files: wraps data as 00[len][data] before sending.",
                  "hf fmcos writerecord --rec 01 --fid 01 --data 0102030405060708\n"
                  "hf fmcos writerecord --rec 01 --fid 06 --data 0102030405060708 --tlv\n"
                  "hf fmcos writerecord --rec 01 --fid 01 --data 01020304 --prot mac --key aabbccddeeff0011");
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "rec",  "<n>",    "record number (1-based)"),
        arg_str1(NULL, "fid",  "<hex>",  "SFI reference byte (1 byte, 1-30)"),
        arg_str1(NULL, "data", "<hex>",  "record data to write"),
        arg_str0(NULL, "prot", "<type>", "protection: none(def) mac enc"),
        arg_str0(NULL, "key",  "<hex>",  "line-protection key (8 or 16 bytes)"),
        arg_lit0(NULL, "tlv",  "wrap data as 00[len][data] TLV for variable-length records"),
        arg_lit0("k",  "keep", "keep field ON after command"),
        arg_lit0("a",  "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int rec = arg_get_int_def(ctx, 1, 0);
    uint8_t fid_buf[1] = {0};
    int fid_len = 0;
    CLIGetHexWithReturn(ctx, 2, fid_buf, &fid_len);
    uint8_t wdata[243] = {0};
    int wdata_len = 0;
    CLIGetHexWithReturn(ctx, 3, wdata, &wdata_len);
    int prot = FMCOS_PROT_NONE;
    int res = CLIGetOptionList(arg_get_str(ctx, 4), g_fmcos_prot_opts, &prot);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    uint8_t key[16] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 5, key, &key_len);
    bool use_tlv  = arg_get_lit(ctx, 6);
    bool keep     = arg_get_lit(ctx, 7);
    bool apdu_log = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if (rec < 1 || rec > 255) {
        PrintAndLogEx(ERR, "--rec must be 1-255");
        return PM3_EINVARG;
    }
    if (fid_len != 1) {
        PrintAndLogEx(ERR, "--fid must be 1 byte");
        return PM3_EINVARG;
    }
    if (wdata_len < 1) {
        PrintAndLogEx(ERR, "--data required");
        return PM3_EINVARG;
    }
    if (use_tlv && wdata_len > 243) {
        PrintAndLogEx(ERR, "--data too long for TLV write (max 243 bytes)");
        return PM3_EINVARG;
    }
    if (prot != FMCOS_PROT_NONE && key_len != 8 && key_len != 16) {
        PrintAndLogEx(ERR, "--key must be 8 or 16 bytes when --prot is set");
        return PM3_EINVARG;
    }
    SetAPDULogging(apdu_log);

    // For VAR records: prepend 00[len] TLV wrapper
    uint8_t send_buf[245] = {0};
    size_t  send_len;
    if (use_tlv) {
        send_buf[0] = 0x00;
        send_buf[1] = (uint8_t)wdata_len;
        memcpy(send_buf + 2, wdata, (size_t)wdata_len);
        send_len = (size_t)wdata_len + 2;
    } else {
        memcpy(send_buf, wdata, (size_t)wdata_len);
        send_len = (size_t)wdata_len;
    }

    uint8_t p2 = (uint8_t)(((fid_buf[0] & 0x1F) << 3) | 4);
    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_write_cmd(0x00, 0xDC, (uint8_t)rec, p2,
                          send_buf, send_len,
                          prot, key, (size_t)key_len,
                          true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "Record " _GREEN_("written"));
    } else {
        PrintAndLogEx(FAILED, "Write record " _RED_("failed"));
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}


static int CmdHFFmcosAppend(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos append",
                  "APPEND RECORD to a cyclic or linear EF\n"
                  "Protection: none(def)  mac  enc",
                  "hf fmcos append --fid 01 --data 0102030405060708\n"
                  "hf fmcos append --fid 01 --data 01020304 --prot mac --key aabbccddeeff0011");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "fid",  "<hex>",  "SFI reference byte (1 byte, 1-30)"),
        arg_str1(NULL, "data", "<hex>",  "record data to append"),
        arg_str0(NULL, "prot", "<type>", "protection: none(def) mac enc"),
        arg_str0(NULL, "key",  "<hex>",  "line-protection key (8 or 16 bytes)"),
        arg_lit0("k",  "keep", "keep field ON after command"),
        arg_lit0("a",  "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t fid_buf[1] = {0};
    int fid_len = 0;
    CLIGetHexWithReturn(ctx, 1, fid_buf, &fid_len);
    uint8_t wdata[245] = {0};
    int wdata_len = 0;
    CLIGetHexWithReturn(ctx, 2, wdata, &wdata_len);
    int prot = FMCOS_PROT_NONE;
    int res = CLIGetOptionList(arg_get_str(ctx, 3), g_fmcos_prot_opts, &prot);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    uint8_t key[16] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 4, key, &key_len);
    bool keep     = arg_get_lit(ctx, 5);
    bool apdu_log = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (fid_len != 1) {
        PrintAndLogEx(ERR, "--fid must be 1 byte");
        return PM3_EINVARG;
    }
    if (wdata_len < 1) {
        PrintAndLogEx(ERR, "--data required");
        return PM3_EINVARG;
    }
    if (prot != FMCOS_PROT_NONE && key_len != 8 && key_len != 16) {
        PrintAndLogEx(ERR, "--key must be 8 or 16 bytes when --prot is set");
        return PM3_EINVARG;
    }
    SetAPDULogging(apdu_log);

    // P1=0, P2 = ((fid & 0x1F) << 3) | 4
    uint8_t p2 = (uint8_t)(((fid_buf[0] & 0x1F) << 3) | 4);
    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_write_cmd(0x00, 0xE2, 0x00, p2,
                          wdata, (size_t)wdata_len,
                          prot, key, (size_t)key_len,
                          true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "Record " _GREEN_("appended"));
    } else {
        PrintAndLogEx(FAILED, "Append record " _RED_("failed"));
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// Key type option list for WRITE KEY
static const CLIParserOption g_fmcos_keytype_opts[] = {
    {0x30, "desenc"},
    {0x31, "desdec"},
    {0x32, "desmac"},
    {0x34, "internal"},
    {0x36, "lineprotect"},
    {0x37, "unlockpin"},
    {0x38, "changepin"},
    {0x39, "extauth"},
    {0x3A, "pin"},
    {0x3C, "overdraft"},
    {0x3D, "debit"},
    {0x3E, "purchase"},
    {0x3F, "credit"},
    {0,    NULL}
};

static int CmdHFFmcosWriteKey(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos key",
                  "WRITE KEY to the currently selected keyfile (INS D4)\n"
                  "Key types - Group A (need --change --version --algo):\n"
                  "  desenc desdec desmac internal overdraft debit purchase credit\n"
                  "Group B (need --followup --errcount; extauth also needs --change):\n"
                  "  extauth  pin\n"
                  "Group C (need --change --errcount):\n"
                  "  lineprotect  unlockpin  changepin\n"
                  "Use --authkey with --prot mac|enc to protect the command.",
                  "hf fmcos key --op 01 --id 00 --type internal --usage F0 --change 02 --version 00 --algo 01 --key 3434343434343434343434343434343\n"
                  "hf fmcos key --op 01 --id 00 --type pin     --usage F0 --followup 01 --errcount 33 --key 123456");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "op",       "<hex>",  "authorization key slot (P1), e.g. 01"),
        arg_str1(NULL, "id",       "<hex>",  "key slot to write (P2), e.g. 00"),
        arg_str1(NULL, "type",     "<type>", "key type (see above)"),
        arg_str1(NULL, "usage",    "<hex>",  "usage rights byte"),
        arg_str0(NULL, "change",   "<hex>",  "change rights byte (Group A/B-extauth/C)"),
        arg_str0(NULL, "version",  "<hex>",  "key version byte (Group A)"),
        arg_str0(NULL, "algo",     "<hex>",  "algorithm ID byte (Group A)"),
        arg_str0(NULL, "followup", "<hex>",  "follow-up status byte (Group B)"),
        arg_str0(NULL, "errcount", "<hex>",  "error counter byte (Group B/C)"),
        arg_str1(NULL, "key",      "<hex>",  "key value (8 or 16 bytes; 2-6 bytes for pin type)"),
        arg_str0(NULL, "authkey",  "<hex>",  "line-protect key for MAC/enc (8 or 16 bytes)"),
        arg_str0(NULL, "prot",     "<type>", "protection: none(def) mac enc"),
        arg_lit0("k",  "keep",     "keep field ON after command"),
        arg_lit0("a",  "apdu",     "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t op_buf[1] = {0};
    int op_len = 0;
    CLIGetHexWithReturn(ctx, 1,  op_buf, &op_len);
    uint8_t id_buf[1] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 2,  id_buf, &id_len);
    int ktype = 0;
    int res = CLIGetOptionList(arg_get_str(ctx, 3), g_fmcos_keytype_opts, &ktype);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    uint8_t usage_b[1] = {0};
    int usage_len = 0;
    CLIGetHexWithReturn(ctx, 4,  usage_b, &usage_len);
    uint8_t change_b[1] = {0};
    int change_len = 0;
    CLIGetHexWithReturn(ctx, 5,  change_b, &change_len);
    uint8_t version_b[1] = {0};
    int version_len = 0;
    CLIGetHexWithReturn(ctx, 6,  version_b, &version_len);
    uint8_t algo_b[1] = {0};
    int algo_len = 0;
    CLIGetHexWithReturn(ctx, 7,  algo_b, &algo_len);
    uint8_t followup_b[1] = {0};
    int followup_len = 0;
    CLIGetHexWithReturn(ctx, 8,  followup_b, &followup_len);
    uint8_t errcnt_b[1] = {0};
    int errcnt_len = 0;
    CLIGetHexWithReturn(ctx, 9,  errcnt_b, &errcnt_len);
    uint8_t kval[16] = {0};
    int kval_len = 0;
    CLIGetHexWithReturn(ctx, 10, kval, &kval_len);
    uint8_t authkey[16] = {0};
    int authkey_len = 0;
    CLIGetHexWithReturn(ctx, 11, authkey, &authkey_len);
    int prot = FMCOS_PROT_NONE;
    res = CLIGetOptionList(arg_get_str(ctx, 12), g_fmcos_prot_opts, &prot);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    bool keep     = arg_get_lit(ctx, 13);
    bool apdu_log = arg_get_lit(ctx, 14);
    CLIParserFree(ctx);

    if (op_len != 1 || id_len != 1) {
        PrintAndLogEx(ERR, "--op and --id must each be 1 byte");
        return PM3_EINVARG;
    }
    if (usage_len != 1) {
        PrintAndLogEx(ERR, "--usage must be 1 byte");
        return PM3_EINVARG;
    }
    if (ktype == 0x3A) {
        if (kval_len < 2 || kval_len > 6) {
            PrintAndLogEx(ERR, "--key for pin type must be 2-6 bytes (PIN value)");
            return PM3_EINVARG;
        }
    } else {
        if (kval_len != 8 && kval_len != 16) {
            PrintAndLogEx(ERR, "--key must be 8 or 16 bytes");
            return PM3_EINVARG;
        }
    }
    if (prot != FMCOS_PROT_NONE && authkey_len != 8 && authkey_len != 16) {
        PrintAndLogEx(ERR, "--authkey must be 8 or 16 bytes when --prot is set");
        return PM3_EINVARG;
    }

    // Build metadata according to key type group.
    // The first byte ORs in the protection level per FMCOS spec.
    uint8_t data[64] = {0};
    size_t  data_len = 0;
    data[data_len++] = (uint8_t)(ktype | prot);
    data[data_len++] = usage_b[0];

    // Group A: desenc desdec desmac internal overdraft debit purchase credit
    if (ktype == 0x30 || ktype == 0x31 || ktype == 0x32 || ktype == 0x34 ||
            ktype == 0x3C || ktype == 0x3D || ktype == 0x3E || ktype == 0x3F) {
        if (change_len != 1 || version_len != 1 || algo_len != 1) {
            PrintAndLogEx(ERR, "This key type needs --change --version --algo");
            return PM3_EINVARG;
        }
        data[data_len++] = change_b[0];
        data[data_len++] = version_b[0];
        data[data_len++] = algo_b[0];
        // Group B-extauth: extauth
    } else if (ktype == 0x39) {
        if (change_len != 1 || followup_len != 1 || errcnt_len != 1) {
            PrintAndLogEx(ERR, "extauth key type needs --change --followup --errcount");
            return PM3_EINVARG;
        }
        data[data_len++] = change_b[0];
        data[data_len++] = followup_b[0];
        data[data_len++] = errcnt_b[0];
        // Group B-pin: pin
    } else if (ktype == 0x3A) {
        if (followup_len != 1 || errcnt_len != 1) {
            PrintAndLogEx(ERR, "pin key type needs --followup --errcount");
            return PM3_EINVARG;
        }
        data[data_len++] = 0xEF;
        data[data_len++] = followup_b[0];
        data[data_len++] = errcnt_b[0];
        // Group C: lineprotect unlockpin changepin
    } else if (ktype == 0x36 || ktype == 0x37 || ktype == 0x38) {
        if (change_len != 1 || errcnt_len != 1) {
            PrintAndLogEx(ERR, "This key type needs --change --errcount");
            return PM3_EINVARG;
        }
        data[data_len++] = change_b[0];
        data[data_len++] = 0xFF;
        data[data_len++] = errcnt_b[0];
    } else {
        PrintAndLogEx(ERR, "Unknown key type 0x%02X", ktype);
        return PM3_EINVARG;
    }

    // Append key value
    memcpy(data + data_len, kval, (size_t)kval_len);
    data_len += (size_t)kval_len;

    SetAPDULogging(apdu_log);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_write_cmd(0x80, 0xD4, op_buf[0], id_buf[0],
                          data, data_len,
                          prot, authkey, (size_t)authkey_len,
                          true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "Key " _GREEN_("written"));
    } else {
        PrintAndLogEx(FAILED, "Write key " _RED_("failed"));
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// ---------------------------------------------------------------------------
// Phase 6 - PIN management
// ---------------------------------------------------------------------------

// VERIFY PIN (INS=20): present the PIN to the card.
static int CmdHFFmcosPinVerify(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos pinverify",
                  "VERIFY PIN (INS 20) - present PIN to the card",
                  "hf fmcos pinverify --id 00 --pin 123456\n"
                  "hf fmcos pinverify --id 00 --pin 1234");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",  "<hex>", "key slot (P2), 1 byte"),
        arg_str1(NULL, "pin", "<hex>", "PIN bytes (2-6 bytes)"),
        arg_lit0("k",  "keep", "keep field ON after command"),
        arg_lit0("a",  "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t id_buf[1] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 1, id_buf, &id_len);
    uint8_t pin[8] = {0};
    int pin_len = 0;
    CLIGetHexWithReturn(ctx, 2, pin, &pin_len);
    bool keep     = arg_get_lit(ctx, 3);
    bool apdu_log = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (id_len != 1) {
        PrintAndLogEx(ERR, "--id must be 1 byte");
        return PM3_EINVARG;
    }
    if (pin_len < 2 || pin_len > 6) {
        PrintAndLogEx(ERR, "--pin must be 2-6 bytes");
        return PM3_EINVARG;
    }
    SetAPDULogging(apdu_log);

    // CLA=00 INS=20 P1=00 P2=key_id Lc=pin_len Data=pin
    uint8_t apdu[11];
    apdu[0] = 0x00;
    apdu[1] = 0x20;
    apdu[2] = 0x00;
    apdu[3] = id_buf[0];
    apdu[4] = (uint8_t)pin_len;
    memcpy(apdu + 5, pin, (size_t)pin_len);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res = fmcos_send_apdu(apdu, 5 + (size_t)pin_len, true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "PIN " _GREEN_("verified"));
    } else if (sw1 == 0x63) {
        PrintAndLogEx(FAILED, "Wrong PIN, retries remaining: %d", sw2 & 0x0F);
    } else {
        PrintAndLogEx(FAILED, "PIN verify " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// CHANGE PIN (INS=5E P1=01): present old PIN and new PIN.
static int CmdHFFmcosPinChange(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos pinchange",
                  "CHANGE PIN (INS 5E P1=01) - change PIN with old PIN authorization\n"
                  "Data sent: old_pin + 0xFF + new_pin",
                  "hf fmcos pinchange --id 00 --old 123456 --new 13371337");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",  "<hex>", "key slot (P2), 1 byte"),
        arg_str1(NULL, "old", "<hex>", "old PIN bytes (2-6 bytes)"),
        arg_str1(NULL, "new", "<hex>", "new PIN bytes (2-6 bytes)"),
        arg_lit0("k",  "keep", "keep field ON after command"),
        arg_lit0("a",  "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t id_buf[1] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 1, id_buf, &id_len);
    uint8_t old_pin[8] = {0};
    int old_len = 0;
    CLIGetHexWithReturn(ctx, 2, old_pin, &old_len);
    uint8_t new_pin[8] = {0};
    int new_len = 0;
    CLIGetHexWithReturn(ctx, 3, new_pin, &new_len);
    bool keep     = arg_get_lit(ctx, 4);
    bool apdu_log = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (id_len != 1) {
        PrintAndLogEx(ERR, "--id must be 1 byte");
        return PM3_EINVARG;
    }
    if (old_len < 2 || old_len > 6) {
        PrintAndLogEx(ERR, "--old must be 2-6 bytes");
        return PM3_EINVARG;
    }
    if (new_len < 2 || new_len > 6) {
        PrintAndLogEx(ERR, "--new must be 2-6 bytes");
        return PM3_EINVARG;
    }
    SetAPDULogging(apdu_log);

    // Data = old_pin + 0xFF + new_pin
    uint8_t data[13];
    size_t data_len = 0;
    memcpy(data, old_pin, (size_t)old_len);
    data_len += (size_t)old_len;
    data[data_len++] = 0xFF;
    memcpy(data + data_len, new_pin, (size_t)new_len);
    data_len += (size_t)new_len;

    uint8_t apdu[22];
    apdu[0] = 0x80;
    apdu[1] = 0x5E;
    apdu[2] = 0x01;
    apdu[3] = id_buf[0];
    apdu[4] = (uint8_t)data_len;
    memcpy(apdu + 5, data, data_len);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res = fmcos_send_apdu(apdu, 5 + data_len, true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "PIN " _GREEN_("changed"));
    } else {
        PrintAndLogEx(FAILED, "PIN change " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// RESET PIN (INS=5E P1=00): set new PIN authorized by a change-PIN key.
// MAC = DES-MAC(new_pin, XOR(key_left, key_right))
static int CmdHFFmcosPinReset(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos pinreset",
                  "RESET PIN (INS 5E P1=00) - set new PIN using change-PIN key\n"
                  "Appends DES-MAC(new_pin, key_left XOR key_right) to the data.",
                  "hf fmcos pinreset --id 00 --pin 123456 --key aabbccddeeff001122334455667788aa");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",  "<hex>", "key slot (P2), 1 byte"),
        arg_str1(NULL, "pin", "<hex>", "new PIN bytes (2-6 bytes)"),
        arg_str1(NULL, "key", "<hex>", "change-PIN key (16 bytes)"),
        arg_lit0("k",  "keep", "keep field ON after command"),
        arg_lit0("a",  "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t id_buf[1] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 1, id_buf, &id_len);
    uint8_t pin[8] = {0};
    int pin_len = 0;
    CLIGetHexWithReturn(ctx, 2, pin, &pin_len);
    uint8_t key[16] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 3, key, &key_len);
    bool keep     = arg_get_lit(ctx, 4);
    bool apdu_log = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (id_len != 1) {
        PrintAndLogEx(ERR, "--id must be 1 byte");
        return PM3_EINVARG;
    }
    if (pin_len < 2 || pin_len > 6) {
        PrintAndLogEx(ERR, "--pin must be 2-6 bytes");
        return PM3_EINVARG;
    }
    if (key_len != 16) {
        PrintAndLogEx(ERR, "--key must be 16 bytes (change-PIN key)");
        return PM3_EINVARG;
    }
    SetAPDULogging(apdu_log);

    // mac_key = key_left XOR key_right
    uint8_t mac_key[8];
    for (int i = 0; i < 8; i++) {
        mac_key[i] = key[i] ^ key[i + 8];
    }

    // MAC = DES-CBC-MAC(new_pin, mac_key, iv=0)
    uint8_t zero_iv[8] = {0};
    uint8_t mac[4] = {0};
    int res = fmcos_des_mac(pin, (size_t)pin_len, mac_key, zero_iv, mac, 4);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // Data = new_pin + mac[4]
    uint8_t data[10];
    memcpy(data, pin, (size_t)pin_len);
    memcpy(data + pin_len, mac, 4);
    size_t data_len = (size_t)pin_len + 4;

    uint8_t apdu[15];
    apdu[0] = 0x80;
    apdu[1] = 0x5E;
    apdu[2] = 0x00;
    apdu[3] = id_buf[0];
    apdu[4] = (uint8_t)data_len;
    memcpy(apdu + 5, data, data_len);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_send_apdu(apdu, 5 + data_len, true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "PIN " _GREEN_("reset"));
    } else {
        PrintAndLogEx(FAILED, "PIN reset " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// UNBLOCK PIN (INS=24): present encrypted new PIN + packet MAC, authorized by unlock-PIN key.
// Data = encrypt([len|new_pin], unlock_key) + packet_mac(cla, ins, p1, p2, enc_data, chal_iv, unlock_key)
static int CmdHFFmcosPinUnblock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos pinunblock",
                  "UNBLOCK PIN (INS 24) - unblock a locked PIN using the unlock-PIN key\n"
                  "Data = encrypt([len|new_pin], unlock_key) + packet_MAC",
                  "hf fmcos pinunblock --id 00 --pin 123456 --key aabbccddeeff001122334455667788aa");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",  "<hex>", "PIN key slot (P1), 1 byte"),
        arg_str1(NULL, "pin", "<hex>", "new PIN bytes (2-6 bytes)"),
        arg_str1(NULL, "key", "<hex>", "unlock-PIN key (8 or 16 bytes)"),
        arg_lit0("k",  "keep", "keep field ON after command"),
        arg_lit0("a",  "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t id_buf[1] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 1, id_buf, &id_len);
    uint8_t pin[8] = {0};
    int pin_len = 0;
    CLIGetHexWithReturn(ctx, 2, pin, &pin_len);
    uint8_t key[16] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 3, key, &key_len);
    bool keep     = arg_get_lit(ctx, 4);
    bool apdu_log = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (id_len != 1) {
        PrintAndLogEx(ERR, "--id must be 1 byte");
        return PM3_EINVARG;
    }
    if (pin_len < 2 || pin_len > 6) {
        PrintAndLogEx(ERR, "--pin must be 2-6 bytes");
        return PM3_EINVARG;
    }
    if (key_len != 8 && key_len != 16) {
        PrintAndLogEx(ERR, "--key must be 8 or 16 bytes");
        return PM3_EINVARG;
    }
    SetAPDULogging(apdu_log);

    // Encrypt [len_byte | pin] with the unlock key
    uint8_t plain[7];
    plain[0] = (uint8_t)pin_len;
    memcpy(plain + 1, pin, (size_t)pin_len);
    uint8_t enc_data[16] = {0};
    size_t  enc_len = fmcos_encrypt(key, (size_t)key_len, plain, 1 + (size_t)pin_len, enc_data);
    if (enc_len == 0) {
        return PM3_ESOFT;
    }

    // GET CHALLENGE for packet MAC IV - CLA=84, INS=24
    uint8_t chal[8] = {0};
    int res = fmcos_get_challenge(8, true, chal);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    uint8_t mac[4] = {0};
    res = fmcos_packet_mac(0x84, 0x24, id_buf[0], 0x00,
                           enc_data, enc_len, chal, key, (size_t)key_len, mac);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    // Build data = enc_data + mac
    uint8_t data[20];
    memcpy(data, enc_data, enc_len);
    memcpy(data + enc_len, mac, 4);
    size_t data_len = enc_len + 4;

    uint8_t apdu[25];
    apdu[0] = 0x84;
    apdu[1] = 0x24;
    apdu[2] = id_buf[0];
    apdu[3] = 0x00;
    apdu[4] = (uint8_t)data_len;
    memcpy(apdu + 5, data, data_len);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_send_apdu(apdu, 5 + data_len, false, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "PIN " _GREEN_("unblocked"));
    } else {
        PrintAndLogEx(FAILED, "PIN unblock " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}


// ---------------------------------------------------------------------------
// Phase 7 helpers
// ---------------------------------------------------------------------------

static void fmcos_get_datetime_bcd(uint8_t date_out[4], uint8_t time_out[3]) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ds[9], ts[7];
    strftime(ds, sizeof(ds), "%Y%m%d", t);
    strftime(ts, sizeof(ts), "%H%M%S", t);
    for (int i = 0; i < 4; i++) {
        date_out[i] = (uint8_t)((((ds[i * 2] - '0') & 0xF) << 4) | ((ds[i * 2 + 1] - '0') & 0xF));
    }
    for (int i = 0; i < 3; i++) {
        time_out[i] = (uint8_t)((((ts[i * 2] - '0') & 0xF) << 4) | ((ts[i * 2 + 1] - '0') & 0xF));
    }
}

// ---------------------------------------------------------------------------
// Financial operations
// ---------------------------------------------------------------------------

static int CmdHFFmcosBalance(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos balance",
                  "GET BALANCE - read wallet or passbook balance",
                  "hf fmcos balance --type wallet\n"
                  "hf fmcos balance --type passbook");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "type", "<type>", "balance type: wallet, passbook"),
        arg_lit0("k", "keep",            "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int bal_type = 0;
    int res = CLIGetOptionList(arg_get_str(ctx, 1), g_fmcos_baltype_opts, &bal_type);
    bool keep = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t apdu[5] = {0x80, 0x5C, 0x00, (uint8_t)bal_type, 0x04};
    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;

    res = fmcos_send_apdu(apdu, sizeof(apdu), true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (resp_len < 2) {
        PrintAndLogEx(ERR, "Short response");
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);

    if (sw1 == 0x90 && sw2 == 0x00 && resp_len >= 6) {
        uint32_t balance = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                           ((uint32_t)resp[2] << 8)  | resp[3];
        PrintAndLogEx(SUCCESS, "Balance (%s): " _GREEN_("%u") " (0x%08X)",
                      bal_type == 0x01 ? "passbook" : "wallet", balance, balance);
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFFmcosCredit(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos credit",
                  "ADD CREDIT to wallet or passbook (two-phase with MAC/TAC verification).\n"
                  "Phase 1: card returns old balance, serial, RNG; derive process key, verify MAC1.\n"
                  "Phase 2: send date/time and MAC2; card returns TAC which is verified.",
                  "hf fmcos credit --type wallet --id 01 --amount 1000\n"
                  "  --terminal 010203040506\n"
                  "  --key 00112233445566778899aabbccddeeff\n"
                  "  --ikey aabbccddeeff00112233445566778899");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "type",     "<type>", "balance type: wallet, passbook"),
        arg_str1(NULL, "id",       "<hex>",  "credit key file ID (1 byte)"),
        arg_int1(NULL, "amount",   "<n>",    "credit amount"),
        arg_str1(NULL, "terminal", "<hex>",  "terminal ID (6 bytes)"),
        arg_str1(NULL, "key",      "<hex>",  "credit key (16 bytes)"),
        arg_str1(NULL, "ikey",     "<hex>",  "internal key (16 bytes, for TAC verification)"),
        arg_lit0("k", "keep",               "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int bal_type = 0;
    int res = CLIGetOptionList(arg_get_str(ctx, 1), g_fmcos_baltype_opts, &bal_type);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    int key_id = 0;
    res = fmcos_parse_hex_int(arg_get_str(ctx, 2)->sval[0], &key_id);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    int amount_i = arg_get_int(ctx, 3);

    uint8_t terminal[6] = {0};
    int terminal_len = 0;
    CLIGetHexWithReturn(ctx, 4, terminal, &terminal_len);

    uint8_t crde_key[16] = {0};
    int crde_key_len = 0;
    CLIGetHexWithReturn(ctx, 5, crde_key, &crde_key_len);

    uint8_t ikey[16] = {0};
    int ikey_len = 0;
    CLIGetHexWithReturn(ctx, 6, ikey, &ikey_len);

    bool keep = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if (key_id < 0 || key_id > 0xFF) {
        PrintAndLogEx(ERR, "Key ID must be 0-255");
        return PM3_EINVARG;
    }
    if (amount_i <= 0) {
        PrintAndLogEx(ERR, "Amount must be positive");
        return PM3_EINVARG;
    }
    if (terminal_len != 6) {
        PrintAndLogEx(ERR, "Terminal ID must be 6 bytes");
        return PM3_EINVARG;
    }
    if (crde_key_len != 16) {
        PrintAndLogEx(ERR, "Credit key must be 16 bytes");
        return PM3_EINVARG;
    }
    if (ikey_len != 16) {
        PrintAndLogEx(ERR, "Internal key must be 16 bytes");
        return PM3_EINVARG;
    }

    uint32_t amount  = (uint32_t)amount_i;
    uint8_t  tx_type = (uint8_t)bal_type;   // transaction_type == balance_type for credit

    // ---- Phase 1: INITIALIZE FOR CREDIT (INS 50, P1 00) ----
    // APDU: CLA INS P1 P2 Lc[=11] key_id amount[4] terminal[6] Le[=16]
    uint8_t ph1[17];
    ph1[0] = 0x80;
    ph1[1] = 0x50;
    ph1[2] = 0x00;
    ph1[3] = (uint8_t)bal_type;
    ph1[4] = 0x0B;
    ph1[5]  = (uint8_t)key_id;
    ph1[6]  = (amount >> 24) & 0xFF;
    ph1[7]  = (amount >> 16) & 0xFF;
    ph1[8]  = (amount >>  8) & 0xFF;
    ph1[9]  = amount & 0xFF;
    memcpy(&ph1[10], terminal, 6);
    ph1[16] = 0x10;

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;

    res = fmcos_send_apdu(ph1, sizeof(ph1), true, true, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return res;
    }

    // Response: old_balance[4] online_serial[2] key_ver[1] algo[1] random_1[4] mac_1[4] SW[2]
    if (resp_len < 18) {
        if (resp_len >= 2) {
            fmcos_print_sw(resp[resp_len - 2], resp[resp_len - 1]);
        }
        PrintAndLogEx(ERR, "Phase 1 short response (%d bytes) -- DF selected?", resp_len);
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        fmcos_print_sw(sw1, sw2);
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint32_t old_balance = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                           ((uint32_t)resp[2] << 8)  | resp[3];
    uint8_t online_serial[2];
    memcpy(online_serial, resp + 4, 2);

    // Process key: fmcos_encrypt(random_1[4] | online_serial[2], crde_key) -> first 8 bytes
    uint8_t pk_buf[6];
    memcpy(pk_buf, resp + 8, 4);      // random_1
    memcpy(pk_buf + 4, resp + 4, 2);  // online_serial
    uint8_t pk_enc[24] = {0};
    if (fmcos_encrypt(crde_key, (size_t)crde_key_len, pk_buf, 6, pk_enc) == 0) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t process_key[8];
    memcpy(process_key, pk_enc, 8);

    // Verify MAC1: DES-CBC-MAC(old_bal[4] | amount[4] | tx_type[1] | terminal[6], process_key)
    uint8_t mac1_buf[15];
    memcpy(mac1_buf, resp, 4);
    mac1_buf[4] = (amount >> 24) & 0xFF;
    mac1_buf[5] = (amount >> 16) & 0xFF;
    mac1_buf[6] = (amount >>  8) & 0xFF;
    mac1_buf[7] = amount & 0xFF;
    mac1_buf[8] = tx_type;
    memcpy(mac1_buf + 9, terminal, 6);

    uint8_t zero_iv[8] = {0};
    uint8_t mac1_calc[4] = {0};
    res = fmcos_des_mac(mac1_buf, 15, process_key, zero_iv, mac1_calc, 4);
    if (res != PM3_SUCCESS) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (memcmp(mac1_calc, resp + 12, 4) != 0) {
        PrintAndLogEx(ERR, "MAC1 mismatch - card response invalid");
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "MAC1 OK  old balance %u", old_balance);

    // Compute MAC2: DES-CBC-MAC(amount[4] | tx_type[1] | terminal[6] | date[4] | time[3], process_key)
    uint8_t date[4], ttime[3];
    fmcos_get_datetime_bcd(date, ttime);

    uint8_t mac2_buf[18];
    mac2_buf[0] = (amount >> 24) & 0xFF;
    mac2_buf[1] = (amount >> 16) & 0xFF;
    mac2_buf[2] = (amount >>  8) & 0xFF;
    mac2_buf[3] = amount & 0xFF;
    mac2_buf[4] = tx_type;
    memcpy(mac2_buf + 5,  terminal, 6);
    memcpy(mac2_buf + 11, date, 4);
    memcpy(mac2_buf + 15, ttime, 3);

    uint8_t mac2[4] = {0};
    res = fmcos_des_mac(mac2_buf, 18, process_key, zero_iv, mac2, 4);
    if (res != PM3_SUCCESS) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return res;
    }

    // ---- Phase 2: CREDIT (INS 52) ----
    // APDU: CLA INS P1 P2 Lc[=11] date[4] time[3] mac2[4] Le[=4]
    uint8_t ph2[17];
    ph2[0] = 0x80;
    ph2[1] = 0x52;
    ph2[2] = 0x00;
    ph2[3] = 0x00;
    ph2[4] = 0x0B;
    memcpy(&ph2[5],  date, 4);
    memcpy(&ph2[9],  ttime, 3);
    memcpy(&ph2[12], mac2, 4);
    ph2[16] = 0x04;

    memset(resp, 0, sizeof(resp));
    resp_len = 0;
    res = fmcos_send_apdu(ph2, sizeof(ph2), false, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    // Response: TAC[4] SW[2]
    if (resp_len < 6) {
        PrintAndLogEx(ERR, "Phase 2 short response (%d bytes)", resp_len);
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    sw1 = resp[resp_len - 2];
    sw2 = resp[resp_len - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        fmcos_print_sw(sw1, sw2);
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    // Verify TAC: DES-CBC-MAC(new_bal[4] | online_serial[2] | mac2_buf[18], tac_key)
    // tac_key = XOR of the two 8-byte halves of the internal key
    uint32_t new_balance = old_balance + amount;
    uint8_t tac_key[8];
    for (int i = 0; i < 8; i++) {
        tac_key[i] = ikey[i] ^ ikey[i + 8];
    }

    uint8_t tac_buf[24];
    tac_buf[0] = (new_balance >> 24) & 0xFF;
    tac_buf[1] = (new_balance >> 16) & 0xFF;
    tac_buf[2] = (new_balance >>  8) & 0xFF;
    tac_buf[3] = new_balance & 0xFF;
    memcpy(tac_buf + 4, online_serial, 2);
    memcpy(tac_buf + 6, mac2_buf, 18);

    uint8_t tac_calc[4] = {0};
    res = fmcos_des_mac(tac_buf, 24, tac_key, zero_iv, tac_calc, 4);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (memcmp(tac_calc, resp, 4) != 0) {
        PrintAndLogEx(WARNING, "TAC mismatch - new balance %u may be incorrect", new_balance);
    } else {
        PrintAndLogEx(SUCCESS, "TAC OK  new balance " _GREEN_("%u"), new_balance);
    }
    fmcos_print_sw(sw1, sw2);
    if (!keep) {
        DropField();
    }
    return PM3_SUCCESS;
}

static int CmdHFFmcosPurchase(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos purchase",
                  "PURCHASE from wallet or passbook (two-phase with process key/TAC verification).\n"
                  "Phase 1: card returns balance, serial, RNG; derive process key, compute MAC1.\n"
                  "Phase 2: send tx serial, date/time, MAC1; card returns TAC which is verified.",
                  "hf fmcos purchase --type wallet --id 02 --amount 100\n"
                  "  --terminal 010203040506\n"
                  "  --key 00112233445566778899aabbccddeeff\n"
                  "  --ikey aabbccddeeff00112233445566778899\n"
                  "  --serial 01020304");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "type",     "<type>", "balance type: wallet, passbook"),
        arg_str1(NULL, "id",       "<hex>",  "purchase key file ID (1 byte)"),
        arg_int1(NULL, "amount",   "<n>",    "purchase amount"),
        arg_str1(NULL, "terminal", "<hex>",  "terminal ID (6 bytes)"),
        arg_str1(NULL, "key",      "<hex>",  "purchase key (16 bytes)"),
        arg_str1(NULL, "ikey",     "<hex>",  "internal key (16 bytes, for TAC verification)"),
        arg_str0(NULL, "serial",   "<hex>",  "transaction serial (4 bytes, default 00000001)"),
        arg_lit0("k", "keep",               "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int bal_type = 0;
    int res = CLIGetOptionList(arg_get_str(ctx, 1), g_fmcos_baltype_opts, &bal_type);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    int key_id = 0;
    res = fmcos_parse_hex_int(arg_get_str(ctx, 2)->sval[0], &key_id);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    int amount_i = arg_get_int(ctx, 3);

    uint8_t terminal[6] = {0};
    int terminal_len = 0;
    CLIGetHexWithReturn(ctx, 4, terminal, &terminal_len);

    uint8_t purch_key[16] = {0};
    int purch_key_len = 0;
    CLIGetHexWithReturn(ctx, 5, purch_key, &purch_key_len);

    uint8_t ikey[16] = {0};
    int ikey_len = 0;
    CLIGetHexWithReturn(ctx, 6, ikey, &ikey_len);

    uint8_t tx_serial[4] = {0x00, 0x00, 0x00, 0x01};
    int serial_len = 0;
    CLIGetHexWithReturn(ctx, 7, tx_serial, &serial_len);

    bool keep = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if (key_id < 0 || key_id > 0xFF) {
        PrintAndLogEx(ERR, "Key ID must be 0-255");
        return PM3_EINVARG;
    }
    if (amount_i <= 0) {
        PrintAndLogEx(ERR, "Amount must be positive");
        return PM3_EINVARG;
    }
    if (terminal_len != 6) {
        PrintAndLogEx(ERR, "Terminal ID must be 6 bytes");
        return PM3_EINVARG;
    }
    if (purch_key_len != 16) {
        PrintAndLogEx(ERR, "Purchase key must be 16 bytes");
        return PM3_EINVARG;
    }
    if (ikey_len != 16) {
        PrintAndLogEx(ERR, "Internal key must be 16 bytes");
        return PM3_EINVARG;
    }
    if (serial_len != 0 && serial_len != 4) {
        PrintAndLogEx(ERR, "Serial must be 4 bytes");
        return PM3_EINVARG;
    }

    uint32_t amount  = (uint32_t)amount_i;
    // transaction_type: 0x05 passbook purchase, 0x06 wallet purchase
    uint8_t tx_type = (bal_type == 0x01) ? 0x05 : 0x06;

    // ---- Phase 1: INITIALIZE FOR PURCHASE (INS 50, P1 01) ----
    // APDU: CLA INS P1 P2 Lc[=11] key_id amount[4] terminal[6] Le[=15]
    uint8_t ph1[17];
    ph1[0] = 0x80;
    ph1[1] = 0x50;
    ph1[2] = 0x01;
    ph1[3] = (uint8_t)bal_type;
    ph1[4] = 0x0B;
    ph1[5]  = (uint8_t)key_id;
    ph1[6]  = (amount >> 24) & 0xFF;
    ph1[7]  = (amount >> 16) & 0xFF;
    ph1[8]  = (amount >>  8) & 0xFF;
    ph1[9]  = amount & 0xFF;
    memcpy(&ph1[10], terminal, 6);
    ph1[16] = 0x0F;

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;

    res = fmcos_send_apdu(ph1, sizeof(ph1), true, true, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return res;
    }

    // Response: old_balance[4] offline_serial[2] overdraft_lim[3] key_ver[1] algo[1] random_1[4] SW[2]
    if (resp_len < 17) {
        if (resp_len >= 2) {
            fmcos_print_sw(resp[resp_len - 2], resp[resp_len - 1]);
        }
        PrintAndLogEx(ERR, "Phase 1 short response (%d bytes) -- DF selected?", resp_len);
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        fmcos_print_sw(sw1, sw2);
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint32_t old_balance = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                           ((uint32_t)resp[2] << 8)  | resp[3];
    PrintAndLogEx(INFO, "Old balance: %u", old_balance);

    // Process key: fmcos_encrypt(random_1[4] | offline_serial[2] | tx_serial[2], purchase_key) -> first 8 bytes
    uint8_t pk_buf[8];
    memcpy(pk_buf, resp + 11, 4);    // random_1
    memcpy(pk_buf + 4, resp + 4, 2); // offline_serial
    pk_buf[6] = tx_serial[2];
    pk_buf[7] = tx_serial[3];
    uint8_t pk_enc[24] = {0};
    if (fmcos_encrypt(purch_key, (size_t)purch_key_len, pk_buf, 8, pk_enc) == 0) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t process_key[8];
    memcpy(process_key, pk_enc, 8);

    // Compute MAC1: DES-CBC-MAC(amount[4] | tx_type[1] | terminal[6] | date[4] | time[3], process_key)
    uint8_t date[4], ttime[3];
    fmcos_get_datetime_bcd(date, ttime);

    uint8_t mac1_buf[18];
    mac1_buf[0] = (amount >> 24) & 0xFF;
    mac1_buf[1] = (amount >> 16) & 0xFF;
    mac1_buf[2] = (amount >>  8) & 0xFF;
    mac1_buf[3] = amount & 0xFF;
    mac1_buf[4] = tx_type;
    memcpy(mac1_buf + 5,  terminal, 6);
    memcpy(mac1_buf + 11, date, 4);
    memcpy(mac1_buf + 15, ttime, 3);

    uint8_t zero_iv[8] = {0};
    uint8_t mac1[4] = {0};
    res = fmcos_des_mac(mac1_buf, 18, process_key, zero_iv, mac1, 4);
    if (res != PM3_SUCCESS) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return res;
    }

    // ---- Phase 2: DEBIT (INS 54, P1 01, P2 00) ----
    // APDU: CLA INS P1 P2 Lc[=15] tx_serial[4] date[4] time[3] mac1[4] Le[=8]
    uint8_t ph2[21];
    ph2[0] = 0x80;
    ph2[1] = 0x54;
    ph2[2] = 0x01;
    ph2[3] = 0x00;
    ph2[4] = 0x0F;
    memcpy(&ph2[5],  tx_serial, 4);
    memcpy(&ph2[9],  date, 4);
    memcpy(&ph2[13], ttime, 3);
    memcpy(&ph2[16], mac1, 4);
    ph2[20] = 0x08;

    memset(resp, 0, sizeof(resp));
    resp_len = 0;
    res = fmcos_send_apdu(ph2, sizeof(ph2), false, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    // Response: TAC[4] mac2_card[4] SW[2]
    if (resp_len < 10) {
        PrintAndLogEx(ERR, "Phase 2 short response (%d bytes)", resp_len);
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    sw1 = resp[resp_len - 2];
    sw2 = resp[resp_len - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        fmcos_print_sw(sw1, sw2);
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    // Verify TAC: DES-CBC-MAC(amount[4] | tx_type[1] | terminal[6] | tx_serial[4] | date[4] | time[3], tac_key)
    // tac_key = XOR of the two 8-byte halves of the internal key
    uint32_t new_balance = old_balance - amount;
    uint8_t tac_key[8];
    for (int i = 0; i < 8; i++) {
        tac_key[i] = ikey[i] ^ ikey[i + 8];
    }

    uint8_t tac_buf[22];
    tac_buf[0] = (amount >> 24) & 0xFF;
    tac_buf[1] = (amount >> 16) & 0xFF;
    tac_buf[2] = (amount >>  8) & 0xFF;
    tac_buf[3] = amount & 0xFF;
    tac_buf[4] = tx_type;
    memcpy(tac_buf + 5,  terminal, 6);
    memcpy(tac_buf + 11, tx_serial, 4);
    memcpy(tac_buf + 15, date, 4);
    memcpy(tac_buf + 19, ttime, 3);

    uint8_t tac_calc[4] = {0};
    res = fmcos_des_mac(tac_buf, 22, tac_key, zero_iv, tac_calc, 4);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (memcmp(tac_calc, resp, 4) != 0) {
        PrintAndLogEx(WARNING, "TAC mismatch - new balance %u may be incorrect", new_balance);
    } else {
        PrintAndLogEx(SUCCESS, "TAC OK  new balance " _GREEN_("%u"), new_balance);
    }
    fmcos_print_sw(sw1, sw2);
    if (!keep) {
        DropField();
    }
    return PM3_SUCCESS;
}

static int CmdHFFmcosOverdraft(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos overdraft",
                  "UPDATE OVERDRAFT LIMIT on passbook (two-phase with MAC1/MAC2 verification).\n"
                  "Phase 1: card returns balance, serial, old limit, RNG, MAC1; verify MAC1.\n"
                  "Phase 2: send new limit, date/time, MAC2; card returns TAC (4 bytes).\n"
                  "Provide --ikey (internal key DTK) to verify the TAC returned by the card.",
                  "hf fmcos overdraft --id 01 --limit 5000 --terminal 010203040506\n"
                  "  --key 00112233445566778899aabbccddeeff\n"
                  "hf fmcos overdraft --id 01 --limit 5000 --terminal 010203040506\n"
                  "  --key 00112233445566778899aabbccddeeff --ikey aabbccddeeff00112233445566778899");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",       "<hex>", "overdraft key file ID (1 byte)"),
        arg_int1(NULL, "limit",    "<n>",   "new overdraft limit (24-bit max 16777215)"),
        arg_str1(NULL, "terminal", "<hex>", "terminal ID (6 bytes)"),
        arg_str1(NULL, "key",      "<hex>", "overdraft key (16 bytes)"),
        arg_str0(NULL, "ikey",     "<hex>", "internal key DTK (16 bytes) for TAC verification (optional)"),
        arg_lit0("k", "keep",              "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int key_id;
    int res = fmcos_parse_hex_int(arg_get_str(ctx, 1)->sval[0], &key_id);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    int limit_i = arg_get_int(ctx, 2);

    uint8_t terminal[6] = {0};
    int terminal_len = 0;
    CLIGetHexWithReturn(ctx, 3, terminal, &terminal_len);

    uint8_t od_key[16] = {0};
    int od_key_len = 0;
    CLIGetHexWithReturn(ctx, 4, od_key, &od_key_len);

    uint8_t ikey[16] = {0};
    int ikey_len = 0;
    CLIGetHexWithReturn(ctx, 5, ikey, &ikey_len);

    bool keep = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (key_id < 0 || key_id > 0xFF) {
        PrintAndLogEx(ERR, "Key ID must be 0-255");
        return PM3_EINVARG;
    }
    if (limit_i < 0 || limit_i > 0xFFFFFF) {
        PrintAndLogEx(ERR, "Limit must be 0-16777215");
        return PM3_EINVARG;
    }
    if (terminal_len != 6) {
        PrintAndLogEx(ERR, "Terminal ID must be 6 bytes");
        return PM3_EINVARG;
    }
    if (od_key_len != 16) {
        PrintAndLogEx(ERR, "Overdraft key must be 16 bytes");
        return PM3_EINVARG;
    }
    if (ikey_len != 0 && ikey_len != 16) {
        PrintAndLogEx(ERR, "Internal key must be 16 bytes");
        return PM3_EINVARG;
    }

    bool verify_tac = (ikey_len == 16);
    uint32_t new_limit = (uint32_t)limit_i;

    // ---- Phase 1: INITIALIZE FOR OVERDRAFT (INS 50, P1 04, P2 01=passbook) ----
    // APDU: CLA INS P1 P2 Lc[=7] key_id terminal[6] Le[=19]
    uint8_t ph1[13];
    ph1[0] = 0x80;
    ph1[1] = 0x50;
    ph1[2] = 0x04;
    ph1[3] = 0x01;
    ph1[4] = 0x07;
    ph1[5] = (uint8_t)key_id;
    memcpy(&ph1[6], terminal, 6);
    ph1[12] = 0x13;

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;

    res = fmcos_send_apdu(ph1, sizeof(ph1), true, true, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return res;
    }

    // Response: old_balance[4] online_serial[2] old_od_limit[3] key_ver[1] algo[1] random_1[4] card_mac1[4] SW[2]
    if (resp_len < 21) {
        if (resp_len >= 2) {
            fmcos_print_sw(resp[resp_len - 2], resp[resp_len - 1]);
        }
        PrintAndLogEx(ERR, "Phase 1 short response (%d bytes) -- DF selected?", resp_len);
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        fmcos_print_sw(sw1, sw2);
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint32_t old_balance = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                           ((uint32_t)resp[2] << 8)  | resp[3];
    uint8_t online_serial[2];
    memcpy(online_serial, resp + 4, 2);
    uint32_t old_od_limit = ((uint32_t)resp[6] << 16) | ((uint32_t)resp[7] << 8) | resp[8];
    PrintAndLogEx(INFO, "Old balance: %u  old overdraft limit: %u", old_balance, old_od_limit);

    // Process key: fmcos_encrypt(random_1[4] | online_serial[2], od_key) -> first 8 bytes
    uint8_t pk_buf[6];
    memcpy(pk_buf, resp + 11, 4);
    memcpy(pk_buf + 4, resp + 4, 2);
    uint8_t pk_enc[24] = {0};
    if (fmcos_encrypt(od_key, (size_t)od_key_len, pk_buf, 6, pk_enc) == 0) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t process_key[8];
    memcpy(process_key, pk_enc, 8);

    // Verify MAC1: DES-CBC-MAC(old_bal[4] | old_od_limit[3] | 0x07[1] | terminal[6], process_key)
    uint8_t mac1_buf[14];
    memcpy(mac1_buf, resp, 4);           // old_balance
    memcpy(mac1_buf + 4, resp + 6, 3);  // old_od_limit (3 bytes at resp[6..8])
    mac1_buf[7] = 0x07;                  // transaction_type = Overdraft
    memcpy(mac1_buf + 8, terminal, 6);

    uint8_t zero_iv[8] = {0};
    uint8_t mac1_calc[4] = {0};
    res = fmcos_des_mac(mac1_buf, 14, process_key, zero_iv, mac1_calc, 4);
    if (res != PM3_SUCCESS) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (memcmp(mac1_calc, resp + 15, 4) != 0) {
        PrintAndLogEx(ERR, "MAC1 mismatch - card response invalid");
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "MAC1 OK");

    // Compute MAC2: DES-CBC-MAC(new_limit[3] | 0x07[1] | terminal[6] | date[4] | time[3], process_key)
    uint8_t date[4], ttime[3];
    fmcos_get_datetime_bcd(date, ttime);

    uint8_t mac2_buf[17];
    mac2_buf[0] = (new_limit >> 16) & 0xFF;
    mac2_buf[1] = (new_limit >>  8) & 0xFF;
    mac2_buf[2] = new_limit & 0xFF;
    mac2_buf[3] = 0x07;
    memcpy(mac2_buf + 4,  terminal, 6);
    memcpy(mac2_buf + 10, date, 4);
    memcpy(mac2_buf + 14, ttime, 3);

    uint8_t mac2[4] = {0};
    res = fmcos_des_mac(mac2_buf, 17, process_key, zero_iv, mac2, 4);
    if (res != PM3_SUCCESS) {
        g_fmcos_session_active = keep;
        if (!keep) {
            DropField();
        }
        return res;
    }

    // ---- Phase 2: UPDATE OVERDRAFT (INS 58, P1 00, P2 00) ----
    // APDU: CLA INS P1 P2 Lc[=14] new_limit[3] date[4] time[3] mac2[4] Le[=4]
    uint8_t ph2[20];
    ph2[0] = 0x80;
    ph2[1] = 0x58;
    ph2[2] = 0x00;
    ph2[3] = 0x00;
    ph2[4] = 0x0E;
    ph2[5] = (new_limit >> 16) & 0xFF;
    ph2[6] = (new_limit >>  8) & 0xFF;
    ph2[7] = new_limit & 0xFF;
    memcpy(&ph2[8],  date, 4);
    memcpy(&ph2[12], ttime, 3);
    memcpy(&ph2[15], mac2, 4);
    ph2[19] = 0x04;

    memset(resp, 0, sizeof(resp));
    resp_len = 0;
    res = fmcos_send_apdu(ph2, sizeof(ph2), false, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (resp_len < 2) {
        PrintAndLogEx(ERR, "Phase 2 short response");
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    sw1 = resp[resp_len - 2];
    sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);

    if (sw1 != 0x90 || sw2 != 0x00) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Overdraft limit updated to " _GREEN_("%u"), new_limit);

    if (verify_tac) {
        if (resp_len < 6) {
            PrintAndLogEx(WARNING, "TAC not present in Phase 2 response (got %d bytes)", resp_len);
        } else {
            // TAC key: XOR of the two 8-byte halves of the internal key (same as credit/purchase)
            uint8_t tac_key[8];
            for (int i = 0; i < 8; i++) {
                tac_key[i] = ikey[i] ^ ikey[i + 8];
            }

            // TAC buffer: tac_bal[4]|serial[2]|new_limit[3]|0x07[1]|terminal[6]|date[4]|time[3]
            // The card stores (actual_funds + od_limit) as its balance field.  When the limit
            // changes, the new stored balance = old_balance + new_limit - old_od_limit.
            uint32_t tac_balance = old_balance + new_limit - old_od_limit;
            uint8_t tac_buf[23];
            tac_buf[0] = (tac_balance >> 24) & 0xFF;
            tac_buf[1] = (tac_balance >> 16) & 0xFF;
            tac_buf[2] = (tac_balance >>  8) & 0xFF;
            tac_buf[3] = tac_balance & 0xFF;
            memcpy(tac_buf + 4, online_serial, 2);
            tac_buf[6] = (new_limit >> 16) & 0xFF;
            tac_buf[7] = (new_limit >>  8) & 0xFF;
            tac_buf[8] = new_limit & 0xFF;
            tac_buf[9] = 0x07;
            memcpy(tac_buf + 10, terminal, 6);
            memcpy(tac_buf + 16, date, 4);
            memcpy(tac_buf + 20, ttime, 3);

            uint8_t tac_calc[4] = {0};
            res = fmcos_des_mac(tac_buf, 23, tac_key, zero_iv, tac_calc, 4);
            if (res != PM3_SUCCESS) {
                if (!keep) {
                    DropField();
                }
                return res;
            }

            if (memcmp(tac_calc, resp, 4) != 0) {
                PrintAndLogEx(WARNING, "TAC mismatch - overdraft limit update may be unverified");
                PrintAndLogEx(INFO,    "Verify --ikey is the type-0x34 internal key for this card");
            } else {
                PrintAndLogEx(SUCCESS, "TAC OK  " _GREEN_("%s"), sprint_hex(resp, 4));
            }
        }
    } else if (resp_len >= 6) {
        PrintAndLogEx(INFO, "TAC (unverified): %s", sprint_hex(resp, 4));
    }

    if (!keep) {
        DropField();
    }
    return PM3_SUCCESS;
}

static int CmdHFFmcosBlock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos block",
                  "BLOCK the card or an application.\n"
                  "Uses the line-protection key to generate a MAC. One of --card or --app is required.\n"
                  "Application block type: --perm (permanent) or --temp (temporary, default).",
                  "hf fmcos block --card --key aabbccddeeff0011\n"
                  "hf fmcos block --app --perm --key aabbccddeeff001122334455667788aa");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "card", "block the entire card (CARD BLOCK, INS 16)"),
        arg_lit0(NULL, "app",  "block the current application (APP BLOCK, INS 1E)"),
        arg_lit0(NULL, "perm", "permanent application block (default is temporary)"),
        arg_str1(NULL, "key",  "<hex>", "line-protection key (8 or 16 bytes)"),
        arg_lit0("k", "keep", "keep field ON after command"),
        arg_lit0("a", "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool block_card = arg_get_lit(ctx, 1);
    bool block_app  = arg_get_lit(ctx, 2);
    bool permanent  = arg_get_lit(ctx, 3);

    uint8_t key[16] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 4, key, &key_len);

    bool keep     = arg_get_lit(ctx, 5);
    bool apdu_log = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (!block_card && !block_app) {
        PrintAndLogEx(ERR, "Specify --card or --app");
        return PM3_EINVARG;
    }
    if (block_card && block_app) {
        PrintAndLogEx(ERR, "Specify only one of --card or --app");
        return PM3_EINVARG;
    }
    if (key_len != 8 && key_len != 16) {
        PrintAndLogEx(ERR, "Key must be 8 bytes (DES) or 16 bytes (3DES)");
        return PM3_EINVARG;
    }

    SetAPDULogging(apdu_log);

    // GET CHALLENGE (8 bytes) as MAC IV - activates the field
    uint8_t chal[8] = {0};
    int res = fmcos_get_challenge(8, true, chal);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    uint8_t cla, ins, p2;
    if (block_card) {
        cla = 0x84;
        ins = 0x16;
        p2 = 0x00;
    } else {
        // APP BLOCK: P2=0x00 temporary, P2=0x01 permanent
        cla = 0x84;
        ins = 0x1E;
        p2 = permanent ? 0x01 : 0x00;
    }
    uint8_t p1 = 0x00;

    uint8_t mac[4] = {0};
    res = fmcos_packet_mac(cla, ins, p1, p2, NULL, 0, chal, key, (size_t)key_len, mac);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    uint8_t apdu[9];
    apdu[0] = cla;
    apdu[1] = ins;
    apdu[2] = p1;
    apdu[3] = p2;
    apdu[4] = 0x04;
    memcpy(&apdu[5], mac, 4);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_send_apdu(apdu, sizeof(apdu), false, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (resp_len < 2) {
        PrintAndLogEx(ERR, "Empty response");
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2];
    uint8_t sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);

    if (sw1 == 0x90 && sw2 == 0x00) {
        if (block_card) {
            PrintAndLogEx(SUCCESS, "Card " _GREEN_("blocked"));
        } else {
            PrintAndLogEx(SUCCESS, "Application " _GREEN_("blocked") " (%s)",
                          permanent ? "permanent" : "temporary");
        }
    } else {
        PrintAndLogEx(FAILED, "Block command " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFFmcosUnblock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos unblock",
                  "UNBLOCK the current application (APP UNBLOCK, INS 18).\n"
                  "Uses the line-protection key to generate a MAC.",
                  "hf fmcos unblock --key aabbccddeeff0011\n"
                  "hf fmcos unblock --key aabbccddeeff001122334455667788aa");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "key", "<hex>", "line-protection key (8 or 16 bytes)"),
        arg_lit0("k", "keep", "keep field ON after command"),
        arg_lit0("a", "apdu", "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t key[16] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 1, key, &key_len);

    bool keep     = arg_get_lit(ctx, 2);
    bool apdu_log = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (key_len != 8 && key_len != 16) {
        PrintAndLogEx(ERR, "Key must be 8 bytes (DES) or 16 bytes (3DES)");
        return PM3_EINVARG;
    }

    SetAPDULogging(apdu_log);

    uint8_t chal[8] = {0};
    int res = fmcos_get_challenge(8, true, chal);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    // APP UNBLOCK: CLA=84 INS=18 P1=00 P2=00
    uint8_t mac[4] = {0};
    res = fmcos_packet_mac(0x84, 0x18, 0x00, 0x00, NULL, 0, chal, key, (size_t)key_len, mac);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    uint8_t apdu[9];
    apdu[0] = 0x84;
    apdu[1] = 0x18;
    apdu[2] = 0x00;
    apdu[3] = 0x00;
    apdu[4] = 0x04;
    memcpy(&apdu[5], mac, 4);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_send_apdu(apdu, sizeof(apdu), false, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (resp_len < 2) {
        PrintAndLogEx(ERR, "Empty response");
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }

    uint8_t sw1 = resp[resp_len - 2];
    uint8_t sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);

    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "Application " _GREEN_("unblocked"));
    } else {
        PrintAndLogEx(FAILED, "Unblock command " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// ---------------------------------------------------------------------------
// Transaction history
// ---------------------------------------------------------------------------

static int CmdHFFmcosHistory(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos history",
                  "Read transaction history records from a loop (cyclic) EF.\n"
                  "Each record is 23 bytes: serial[2] | od_limit[3] | amount[4] | type[1] | terminal[6] | date[4] | time[3]\n"
                  "Record 1 is the most recent. Reading stops when the card returns a non-9000 SW.",
                  "hf fmcos history --fid 18\n"
                  "hf fmcos history --fid 19 --count 20");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "fid",   "<hex>", "loop file SFI (1 byte, e.g. 18 for wallet, 19 for passbook)"),
        arg_int0(NULL, "count", "<n>",   "max records to read (default 10, 0=read all up to 255)"),
        arg_lit0("k", "keep",           "keep field ON after command"),
        arg_lit0("a", "apdu",           "show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t fid_buf[1] = {0};
    int fid_len = 0;
    CLIGetHexWithReturn(ctx, 1, fid_buf, &fid_len);
    int count    = arg_get_int_def(ctx, 2, 10);
    bool keep    = arg_get_lit(ctx, 3);
    bool apdu_log = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (fid_len != 1) {
        PrintAndLogEx(ERR, "--fid must be 1 byte");
        return PM3_EINVARG;
    }
    if (count < 0 || count > 255) {
        PrintAndLogEx(ERR, "--count must be 0-255");
        return PM3_EINVARG;
    }
    if (count == 0) {
        count = 255;
    }

    SetAPDULogging(apdu_log);

    uint8_t sfi = fid_buf[0] & 0x1F;
    uint8_t p2  = (sfi << 3) | 0x04;

    static const struct { uint8_t code; const char *name; } tx_types[] = {
        {0x04, "PB cash W/D "},
        {0x05, "PB purchase "},
        {0x06, "WL purchase "},
        {0x07, "OD limit upd"},
        {0x09, "Compound pur"},
    };
    const size_t ntypes = sizeof(tx_types) / sizeof(tx_types[0]);

    PrintAndLogEx(INFO, " # | Date       | Time     | Type         | Amount     | OD Limit | Serial | Terminal");
    PrintAndLogEx(INFO, "---+------------+----------+--------------+------------+----------+--------+-------------------");

    int found = 0;
    for (int rec = 1; rec <= count; rec++) {
        uint8_t apdu[5] = {0x00, 0xB2, (uint8_t)rec, p2, 23};
        uint8_t resp[APDU_RES_LEN] = {0};
        int resp_len = 0;

        if (fmcos_send_apdu(apdu, sizeof(apdu), true, true, resp, &resp_len) != PM3_SUCCESS) {
            break;
        }

        if (resp_len < 2) {
            break;
        }
        uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
        if (sw1 != 0x90 || sw2 != 0x00) {
            if (rec == 1) {
                fmcos_print_sw(sw1, sw2);
            }
            break;
        }
        if (resp_len < 25) {
            break;
        }

        uint8_t *p = resp;
        uint16_t serial   = ((uint16_t)p[0] << 8) | p[1];
        uint32_t od_limit = ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | p[4];
        uint32_t amount   = ((uint32_t)p[5] << 24) | ((uint32_t)p[6] << 16) |
                            ((uint32_t)p[7] << 8)  | p[8];
        uint8_t  tx_type  = p[9];
        uint8_t *terminal = p + 10;
        uint8_t *date     = p + 16;
        uint8_t *ttime    = p + 20;

        // BCD date YYYYMMDD -> "YYYY-MM-DD"
        char date_str[11];
        snprintf(date_str, sizeof(date_str), "%02X%02X-%02X-%02X",
                 date[0], date[1], date[2], date[3]);
        // BCD time HHMMSS -> "HH:MM:SS"
        char time_str[9];
        snprintf(time_str, sizeof(time_str), "%02X:%02X:%02X",
                 ttime[0], ttime[1], ttime[2]);

        char type_hex_buf[13];
        snprintf(type_hex_buf, sizeof(type_hex_buf), "0x%02X        ", tx_type);
        const char *type_name = type_hex_buf;
        for (size_t i = 0; i < ntypes; i++) {
            if (tx_types[i].code == tx_type) {
                type_name = tx_types[i].name;
                break;
            }
        }

        PrintAndLogEx(INFO, "%2d | %s | %s | %s | %10u | %8u | %06X | %s",
                      rec, date_str, time_str, type_name,
                      amount, od_limit, serial,
                      sprint_hex(terminal, 6));
        found++;
    }

    if (!keep) {
        DropField();
    }

    if (found == 0) {
        PrintAndLogEx(INFO, "(no records found)");
    } else {
        PrintAndLogEx(SUCCESS, "%d record%s", found, found == 1 ? "" : "s");
    }

    return PM3_SUCCESS;
}

// ---------------------------------------------------------------------------
// TID card provisioning
// ---------------------------------------------------------------------------

#define FMCOS_TID_AUTH_LOCKED   0xAA
#define FMCOS_TID_AUTH_UNLOCKED 0x55

static const uint8_t g_fmcos_tid_setcard_data[39] = {
    0x00, 0x90, 0x80, 0xEC, 0xFF, 0xED, 0x00, 0xFF, 0xFF, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0x08, 0x74, 0x11, 0x00, 0x02, 0x5A, 0x54, 0x40, 0xBD
};

static const uint8_t g_fmcos_tid_keyfile_data[11] = {
    0x1E, 0x00, 0x00, 0x00, 0x30, 0xFF, 0xFF, 0x00, 0x30, 0x00, 0x00
};

// "1PAY.SYS.DDF01"
static const uint8_t g_fmcos_tid_mf_name[] = {
    0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53,
    0x2E, 0x44, 0x44, 0x46, 0x30, 0x31
};

static int CmdHFFmcosTidSetCard(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos tidsetcard",
                  "Send the TID SET CARD configuration APDU (fixed 39-byte payload).",
                  "hf fmcos tidsetcard");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool keep = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    uint8_t apdu[44] = {0x00, 0xEF, 0x00, 0x00, 0x27};
    memcpy(apdu + 5, g_fmcos_tid_setcard_data, 39);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res = fmcos_send_apdu(apdu, sizeof(apdu), true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "SET CARD " _GREEN_("OK"));
    } else {
        PrintAndLogEx(FAILED, "SET CARD " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFFmcosTidSetUID(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos tidsetuid",
                  "Program the TID card UID (4-7 bytes).",
                  "hf fmcos tidsetuid --uid 13371337\n"
                  "hf fmcos tidsetuid --uid 0102030405060708");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "uid", "<hex>", "UID bytes (4-7 bytes)"),
        arg_lit0("k",  "keep",         "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t uid[7] = {0};
    int uid_len = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uid_len);
    bool keep = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (uid_len < 4 || uid_len > 7) {
        PrintAndLogEx(ERR, "--uid must be 4-7 bytes");
        return PM3_EINVARG;
    }

    uint8_t apdu[12] = {0x00, 0x85, 0x00, 0x00, (uint8_t)uid_len};
    memcpy(apdu + 5, uid, (size_t)uid_len);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res = fmcos_send_apdu(apdu, 5 + (size_t)uid_len, true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "SET UID " _GREEN_("OK"));
    } else {
        PrintAndLogEx(FAILED, "SET UID " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFFmcosTidSetAuth(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos tidsetauth",
                  "Write the TID internal authentication key and set the lock state.\n"
                  "Lock byte: 0xAA = locked (permanent), 0x55 = unlocked (default).",
                  "hf fmcos tidsetauth --key 1122334455667788\n"
                  "hf fmcos tidsetauth --key 1122334455667788 --lock");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "key",  "<hex>", "internal auth key (8 bytes)"),
        arg_lit0(NULL, "lock",          "lock the key permanently (0xAA); default unlocked (0x55)"),
        arg_lit0("k",  "keep",          "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t key[8] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 1, key, &key_len);
    bool lock = arg_get_lit(ctx, 2);
    bool keep = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (key_len != 8) {
        PrintAndLogEx(ERR, "--key must be 8 bytes");
        return PM3_EINVARG;
    }

    // 00 21 00 00 0A [key[8]] [lock_byte] 00
    uint8_t apdu[15] = {0x00, 0x21, 0x00, 0x00, 0x0A};
    memcpy(apdu + 5, key, 8);
    apdu[13] = lock ? FMCOS_TID_AUTH_LOCKED : FMCOS_TID_AUTH_UNLOCKED;
    apdu[14] = 0x00;

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res = fmcos_send_apdu(apdu, sizeof(apdu), true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "SET INTERNAL AUTH " _GREEN_("OK") " (key %s)",
                      lock ? _RED_("locked") : "unlocked");
    } else {
        PrintAndLogEx(FAILED, "SET INTERNAL AUTH " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFFmcosTidErase(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos tiderase",
                  "Erase the TID card file system (CLA=E0 INS=EC -- irreversible).",
                  "hf fmcos tiderase");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool keep = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    PrintAndLogEx(WARNING, "Erasing TID card file system -- this is irreversible");

    uint8_t apdu[5] = {0xE0, 0xEC, 0x00, 0x00, 0x00};
    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res = fmcos_send_apdu(apdu, sizeof(apdu), true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }

    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "ERASE " _GREEN_("OK"));
    } else {
        PrintAndLogEx(FAILED, "ERASE " _RED_("failed"));
    }

    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFFmcosTidProvision(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos tidprovision",
                  "Full TID card provisioning sequence:\n"
                  "  SET CARD -> SET UID -> SET INTERNAL AUTH -> ERASE\n"
                  "  -> SELECT MF -> CREATE MF (3F00, 1PAY.SYS.DDF01) -> SELECT MF -> CREATE KEYFILE",
                  "hf fmcos tidprovision --uid 13371337 --key 1122334455667788\n"
                  "hf fmcos tidprovision --uid 13371337 --key 1122334455667788 --lock");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "uid",  "<hex>", "UID bytes (4-7 bytes)"),
        arg_str1(NULL, "key",  "<hex>", "internal auth key (8 bytes)"),
        arg_lit0(NULL, "lock",          "lock the auth key permanently"),
        arg_lit0("k",  "keep",          "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t uid[7] = {0};
    int uid_len = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uid_len);
    uint8_t key[8] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 2, key, &key_len);
    bool lock = arg_get_lit(ctx, 3);
    bool keep = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (uid_len < 4 || uid_len > 7) {
        PrintAndLogEx(ERR, "--uid must be 4-7 bytes");
        return PM3_EINVARG;
    }
    if (key_len != 8) {
        PrintAndLogEx(ERR, "--key must be 8 bytes");
        return PM3_EINVARG;
    }

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;

#define TID_STEP(label, apdu_ptr, apdu_sz, act, lon) \
    do { \
        if (fmcos_send_apdu((apdu_ptr), (apdu_sz), (act), (lon), resp, &resp_len) != PM3_SUCCESS || \
                resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) { \
            PrintAndLogEx(FAILED, label " " _RED_("failed") " (SW:%02X%02X)", \
                          resp_len >= 2 ? resp[resp_len-2] : 0, \
                          resp_len >= 2 ? resp[resp_len-1] : 0); \
            goto tid_provision_fail; \
        } \
        PrintAndLogEx(SUCCESS, label " " _GREEN_("OK")); \
    } while (0)

    // 1 - SET CARD
    {
        uint8_t apdu[44] = {0x00, 0xEF, 0x00, 0x00, 0x27};
        memcpy(apdu + 5, g_fmcos_tid_setcard_data, 39);
        TID_STEP("SET CARD", apdu, sizeof(apdu), true, true);
    }

    // 2 - SET UID
    {
        uint8_t apdu[12] = {0x00, 0x85, 0x00, 0x00, (uint8_t)uid_len};
        memcpy(apdu + 5, uid, (size_t)uid_len);
        TID_STEP("SET UID", apdu, 5 + (size_t)uid_len, true, true);
    }

    // 3 - SET INTERNAL AUTH
    {
        uint8_t apdu[15] = {0x00, 0x21, 0x00, 0x00, 0x0A};
        memcpy(apdu + 5, key, 8);
        apdu[13] = lock ? FMCOS_TID_AUTH_LOCKED : FMCOS_TID_AUTH_UNLOCKED;
        apdu[14] = 0x00;
        TID_STEP("SET INTERNAL AUTH", apdu, sizeof(apdu), true, true);
    }

    // 4 - ERASE
    PrintAndLogEx(WARNING, "Erasing card file system...");
    {
        uint8_t apdu[5] = {0xE0, 0xEC, 0x00, 0x00, 0x00};
        TID_STEP("ERASE", apdu, sizeof(apdu), true, true);
    }

    // 5 - SELECT MF (3F00)
    {
        uint8_t apdu[7] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
        TID_STEP("SELECT MF", apdu, sizeof(apdu), true, true);
    }

    // 6 - CREATE DF (3F00, SFI=02, name="1PAY.SYS.DDF01")
    {
        uint8_t name_len = (uint8_t)sizeof(g_fmcos_tid_mf_name);
        uint8_t apdu[32] = {0x80, 0xE0, 0x00, 0x00, (uint8_t)(name_len + 9),
                            0x3F, 0x00, 0x6F, 0xFF, 0xF0, 0xF0, 0x02, 0x01, 0x00
                           };
        memcpy(apdu + 14, g_fmcos_tid_mf_name, name_len);
        TID_STEP("CREATE DF (3F00)", apdu, 14 + name_len, true, true);
    }

    // 7 - SELECT DF 3F00
    {
        uint8_t apdu[7] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
        TID_STEP("SELECT DF (3F00)", apdu, sizeof(apdu), true, true);
    }

    // 8 - CREATE KEYFILE
    {
        uint8_t apdu[16] = {0x80, 0xE0, 0x02, 0x00, 0x0B};
        memcpy(apdu + 5, g_fmcos_tid_keyfile_data, 11);
        TID_STEP("CREATE KEYFILE", apdu, sizeof(apdu), true, keep);
    }

#undef TID_STEP

    PrintAndLogEx(SUCCESS, "TID provisioning " _GREEN_("complete"));
    if (!keep) {
        DropField();
    }
    return PM3_SUCCESS;

tid_provision_fail:
    DropField();
    return PM3_ESOFT;
}

static int CmdHFFmcosTidCreateDF(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos tidcreatedf",
                  "CREATE sub-DF using TID format (P1=01, FID in data).\n"
                  "Note: TID CREATE DF has a different layout from standard 'hf fmcos createdir'.",
                  "hf fmcos tidcreatedf --id 3f01 --size 0f00 --sfi 96 --name 44444630 31");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",   "<4hex>", "2-byte file ID"),
        arg_str1(NULL, "size", "<hex>",  "DF space in bytes (hex, e.g. 0f00)"),
        arg_str1(NULL, "sfi",  "<hex>",  "short file ID (1 byte)"),
        arg_str0(NULL, "name", "<hex>",  "DF name bytes (variable, 0-16 bytes)"),
        arg_lit0("k",  "keep", "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t id_buf[2] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 1, id_buf, &id_len);
    int size;
    int res = fmcos_parse_hex_int(arg_get_str(ctx, 2)->sval[0], &size);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    uint8_t sfi_buf[1] = {0};
    int sfi_len = 0;
    CLIGetHexWithReturn(ctx, 3, sfi_buf, &sfi_len);
    uint8_t name[16] = {0};
    int name_len = 0;
    CLIGetHexWithReturn(ctx, 4, name, &name_len);
    bool keep = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (id_len != 2) {
        PrintAndLogEx(ERR, "--id must be 2 bytes");
        return PM3_EINVARG;
    }
    if (sfi_len != 1) {
        PrintAndLogEx(ERR, "--sfi must be 1 byte");
        return PM3_EINVARG;
    }
    if (size < 1 || size > 0xFFFF) {
        PrintAndLogEx(ERR, "--size out of range");
        return PM3_EINVARG;
    }

    // 80 E0 01 00 <lc> [fid_hi][fid_lo] [size_hi][size_lo] F0 F0 [sfi] 01 FF [name...]
    uint8_t apdu[32] = {
        0x80, 0xE0, 0x01, 0x00, (uint8_t)(name_len + 9),
        id_buf[0], id_buf[1],
        (size >> 8) & 0xFF, size & 0xFF,
        0xF0, 0xF0,
        sfi_buf[0],
        0x01, 0xFF
    };
    memcpy(apdu + 14, name, (size_t)name_len);

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_send_apdu(apdu, 14 + (size_t)name_len, true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "CREATE DF " _GREEN_("OK"));
    } else {
        PrintAndLogEx(FAILED, "CREATE DF " _RED_("failed"));
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static const CLIParserOption g_fmcos_tid_create_opts[] = {
    {0, "bin"},
    {1, "keyfile"},
    {0, NULL}
};

static int CmdHFFmcosTidCreateBin(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos tidcreatebin",
                  "CREATE binary EF or KEYFILE using TID format (P1=02, FID in data, fixed Lc=11).\n"
                  "Use --type keyfile to create the fixed TID keyfile in the currently selected DF.\n"
                  "Note: TID CREATE EF has a different layout from standard 'hf fmcos createfile'.",
                  "hf fmcos tidcreatebin --id 0001 --size 0100 --sfi 01\n"
                  "hf fmcos tidcreatebin --id 0002 --size 0040 --sfi 02 --rperm 20 --wperm f0\n"
                  "hf fmcos tidcreatebin --type keyfile");
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "type",  "<type>", "file type: bin (default) or keyfile"),
        arg_str0(NULL, "id",    "<4hex>", "2-byte file ID (required for type bin)"),
        arg_str0(NULL, "size",  "<hex>",  "file size in bytes (required for type bin)"),
        arg_str0(NULL, "sfi",   "<hex>",  "short file ID, 1 byte (required for type bin)"),
        arg_str0(NULL, "rperm", "<hex>",  "read permission byte (default F0, bin only)"),
        arg_str0(NULL, "wperm", "<hex>",  "write permission byte (default F0, bin only)"),
        arg_lit0("k",  "keep",  "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int ftype = 0;
    int res = CLIGetOptionList(arg_get_str(ctx, 1), g_fmcos_tid_create_opts, &ftype);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return res;
    }
    bool is_keyfile = (ftype == 1);

    uint8_t id_buf[2] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 2, id_buf, &id_len);
    int size = 0;
    if (arg_get_str(ctx, 3)->count > 0) {
        res = fmcos_parse_hex_int(arg_get_str(ctx, 3)->sval[0], &size);
        if (res != PM3_SUCCESS) {
            CLIParserFree(ctx);
            return res;
        }
    }
    uint8_t sfi_buf[1] = {0};
    int sfi_len = 0;
    CLIGetHexWithReturn(ctx, 4, sfi_buf, &sfi_len);
    uint8_t rperm_buf[1] = {0};
    int rperm_len = 0;
    CLIGetHexWithReturn(ctx, 5, rperm_buf, &rperm_len);
    uint8_t wperm_buf[1] = {0};
    int wperm_len = 0;
    CLIGetHexWithReturn(ctx, 6, wperm_buf, &wperm_len);
    bool keep = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    uint8_t apdu[16] = {0x80, 0xE0, 0x02, 0x00, 0x0B};

    if (is_keyfile) {
        // Fixed TID keyfile: 80 E0 02 00 0B 1E 00 00 00 30 FF FF 00 30 00 00
        memcpy(apdu + 5, g_fmcos_tid_keyfile_data, 11);
    } else {
        if (rperm_len == 0) {
            rperm_buf[0] = 0xF0;
        }
        if (wperm_len == 0) {
            wperm_buf[0] = 0xF0;
        }
        if (id_len != 2) {
            PrintAndLogEx(ERR, "--id must be 2 bytes");
            return PM3_EINVARG;
        }
        if (sfi_len != 1) {
            PrintAndLogEx(ERR, "--sfi must be 1 byte");
            return PM3_EINVARG;
        }
        if (size < 1 || size > 0xFFFF) {
            PrintAndLogEx(ERR, "--size out of range");
            return PM3_EINVARG;
        }
        // 80 E0 02 00 0B 00 [fid_hi][fid_lo] [size_hi][size_lo] [rperm][wperm] [sfi] 00 FF 00
        apdu[5]  = 0x00;
        apdu[6]  = id_buf[0];
        apdu[7]  = id_buf[1];
        apdu[8]  = (size >> 8) & 0xFF;
        apdu[9]  = size & 0xFF;
        apdu[10] = rperm_buf[0];
        apdu[11] = wperm_buf[0];
        apdu[12] = sfi_buf[0];
        apdu[13] = 0x00;
        apdu[14] = 0xFF;
        apdu[15] = 0x00;
    }

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    res = fmcos_send_apdu(apdu, sizeof(apdu), true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, is_keyfile ? "CREATE KEYFILE " _GREEN_("OK") : "CREATE binary EF " _GREEN_("OK"));
    } else {
        PrintAndLogEx(FAILED,  is_keyfile ? "CREATE KEYFILE " _RED_("failed") : "CREATE binary EF " _RED_("failed"));
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFFmcosTidCreateRec(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fmcos tidcreaterec",
                  "CREATE fixed-length record EF using TID format (P1=02, subtype=01, FID in data, fixed Lc=11).\n"
                  "Note: TID CREATE EF has a different layout from standard 'hf fmcos createfile'.",
                  "hf fmcos tidcreaterec --id 0003 --count 04 --reclen 08 --sfi 03\n"
                  "hf fmcos tidcreaterec --id 0003 --count 04 --reclen 10 --sfi 03 --rperm 20 --wperm f0");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "id",     "<4hex>", "2-byte file ID"),
        arg_str1(NULL, "count",  "<hex>",  "number of records (1 byte)"),
        arg_str1(NULL, "reclen", "<hex>",  "bytes per record (1 byte)"),
        arg_str1(NULL, "sfi",    "<hex>",  "short file ID (1 byte)"),
        arg_str0(NULL, "rperm",  "<hex>",  "read permission byte (default F0)"),
        arg_str0(NULL, "wperm",  "<hex>",  "write permission byte (default F0)"),
        arg_lit0("k",  "keep",   "keep field ON after command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t id_buf[2] = {0};
    int id_len = 0;
    CLIGetHexWithReturn(ctx, 1, id_buf, &id_len);
    uint8_t cnt_buf[1] = {0};
    int cnt_len = 0;
    CLIGetHexWithReturn(ctx, 2, cnt_buf, &cnt_len);
    uint8_t rlen_buf[1] = {0};
    int rlen_len = 0;
    CLIGetHexWithReturn(ctx, 3, rlen_buf, &rlen_len);
    uint8_t sfi_buf[1] = {0};
    int sfi_len = 0;
    CLIGetHexWithReturn(ctx, 4, sfi_buf, &sfi_len);
    uint8_t rperm_buf[1] = {0};
    int rperm_len = 0;
    CLIGetHexWithReturn(ctx, 5, rperm_buf, &rperm_len);
    uint8_t wperm_buf[1] = {0};
    int wperm_len = 0;
    CLIGetHexWithReturn(ctx, 6, wperm_buf, &wperm_len);
    bool keep = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if (rperm_len == 0) {
        rperm_buf[0] = 0xF0;
    }
    if (wperm_len == 0) {
        wperm_buf[0] = 0xF0;
    }

    if (id_len != 2) {
        PrintAndLogEx(ERR, "--id must be 2 bytes");
        return PM3_EINVARG;
    }
    if (cnt_len != 1) {
        PrintAndLogEx(ERR, "--count must be 1 byte");
        return PM3_EINVARG;
    }
    if (rlen_len != 1) {
        PrintAndLogEx(ERR, "--reclen must be 1 byte");
        return PM3_EINVARG;
    }
    if (sfi_len != 1)  {
        PrintAndLogEx(ERR, "--sfi must be 1 byte");
        return PM3_EINVARG;
    }

    // 80 E0 02 00 0B 01 [fid_hi][fid_lo] [count][reclen] [rperm][wperm] [sfi] 00 FF 00
    uint8_t apdu[16] = {
        0x80, 0xE0, 0x02, 0x00, 0x0B,
        0x01,
        id_buf[0], id_buf[1],
        cnt_buf[0], rlen_buf[0],
        rperm_buf[0], wperm_buf[0],
        sfi_buf[0],
        0x00, 0xFF, 0x00
    };

    uint8_t resp[APDU_RES_LEN] = {0};
    int resp_len = 0;
    int res = fmcos_send_apdu(apdu, sizeof(apdu), true, keep, resp, &resp_len);
    if (res != PM3_SUCCESS) {
        if (!keep) {
            DropField();
        }
        return res;
    }
    if (resp_len < 2) {
        if (!keep) {
            DropField();
        }
        return PM3_ESOFT;
    }
    uint8_t sw1 = resp[resp_len - 2], sw2 = resp[resp_len - 1];
    fmcos_print_sw(sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00) {
        PrintAndLogEx(SUCCESS, "CREATE record EF " _GREEN_("OK"));
    } else {
        PrintAndLogEx(FAILED, "CREATE record EF " _RED_("failed"));
    }
    if (!keep) {
        DropField();
    }
    return (sw1 == 0x90 && sw2 == 0x00) ? PM3_SUCCESS : PM3_ESOFT;
}

// ---------------------------------------------------------------------------
// Top-level command table
// ---------------------------------------------------------------------------

static command_t CommandTable[] = {
    {"help",      CmdHelp,            AlwaysAvailable, "This help"},
    {"--------",  CmdHelp,            AlwaysAvailable, "--------- " _CYAN_("Card information") " ---------"},
    {"info",      CmdHFFmcosInfo,     IfPm3Iso14443a,  "Detect card and print file-system info"},
    {"select",    CmdHFFmcosSelect,   IfPm3Iso14443a,  "SELECT FILE by 2-byte ID or AID name"},
    {"--------",  CmdHelp,            AlwaysAvailable, "--------- " _CYAN_("File management") " ----------"},
    {"erase",     CmdHFFmcosErase,    IfPm3Iso14443a,  "ERASE DF contents"},
    {"createdir",     CmdHFFmcosCreateDir,     IfPm3Iso14443a,  "CREATE DIRECTORY (DF)"},
    {"createfile",    CmdHFFmcosCreateFile,    IfPm3Iso14443a,  "CREATE EF (binary / fixed / variable / loop / wallet)"},
    {"createkeyfile", CmdHFFmcosCreateKeyfile, IfPm3Iso14443a,  "CREATE KEYFILE"},
    {"--------",  CmdHelp,            AlwaysAvailable, "--------- " _CYAN_("Data access") " --------------"},
    {"readbinary", CmdHFFmcosReadBinary, IfPm3Iso14443a,  "READ BINARY from transparent EF"},
    {"readrecord", CmdHFFmcosReadRecord, IfPm3Iso14443a,  "READ RECORD from record-based EF"},
    {"writebinary", CmdHFFmcosWriteBinary, IfPm3Iso14443a,  "UPDATE BINARY in transparent EF"},
    {"writerecord", CmdHFFmcosWriteRecord, IfPm3Iso14443a,  "UPDATE RECORD in record-based EF"},
    {"append",    CmdHFFmcosAppend,   IfPm3Iso14443a,  "APPEND RECORD to cyclic / linear EF"},
    {"--------",  CmdHelp,            AlwaysAvailable, "--------- " _CYAN_("Authentication") " -----------"},
    {"authexternal", CmdHFFmcosAuthExternal, IfPm3Iso14443a,  "EXTERNAL AUTHENTICATE using DES/3DES key"},
    {"authinternal", CmdHFFmcosAuthInternal, IfPm3Iso14443a,  "INTERNAL AUTHENTICATE (card proves key knowledge)"},
    {"key",       CmdHFFmcosWriteKey, IfPm3Iso14443a,  "WRITE KEY to keyfile"},
    {"--------",  CmdHelp,            AlwaysAvailable, "--------- " _CYAN_("PIN management") " -----------"},
    {"pinverify",  CmdHFFmcosPinVerify,  IfPm3Iso14443a,  "VERIFY PIN (present PIN to card)"},
    {"pinchange",  CmdHFFmcosPinChange,  IfPm3Iso14443a,  "CHANGE PIN (old + new, requires old PIN)"},
    {"pinreset",   CmdHFFmcosPinReset,   IfPm3Iso14443a,  "RESET PIN (new PIN + change-PIN key MAC)"},
    {"pinunblock", CmdHFFmcosPinUnblock, IfPm3Iso14443a,  "UNBLOCK PIN (encrypted new PIN + MAC)"},
    {"--------",  CmdHelp,            AlwaysAvailable, "--------- " _CYAN_("Financial") " ----------------"},
    {"balance",   CmdHFFmcosBalance,  IfPm3Iso14443a,  "GET BALANCE (wallet or passbook)"},
    {"credit",    CmdHFFmcosCredit,   IfPm3Iso14443a,  "ADD CREDIT to wallet or passbook"},
    {"purchase",  CmdHFFmcosPurchase, IfPm3Iso14443a,  "PURCHASE from wallet or passbook"},
    {"overdraft", CmdHFFmcosOverdraft, IfPm3Iso14443a,  "UPDATE OVERDRAFT LIMIT"},
    {"history",   CmdHFFmcosHistory,  IfPm3Iso14443a,  "READ transaction history from loop EF"},
    {"block",     CmdHFFmcosBlock,    IfPm3Iso14443a,  "BLOCK card or application"},
    {"unblock",   CmdHFFmcosUnblock,  IfPm3Iso14443a,  "UNBLOCK application"},
    {"--------",      CmdHelp,                AlwaysAvailable, "--------- " _CYAN_("TID provisioning") " ----------"},
    {"tidsetcard",   CmdHFFmcosTidSetCard,   IfPm3Iso14443a,  "SET CARD configuration block"},
    {"tidsetuid",    CmdHFFmcosTidSetUID,    IfPm3Iso14443a,  "SET UID"},
    {"tidsetauth",   CmdHFFmcosTidSetAuth,   IfPm3Iso14443a,  "SET INTERNAL AUTH key"},
    {"tiderase",     CmdHFFmcosTidErase,     IfPm3Iso14443a,  "ERASE TID card file system"},
    {"tidprovision", CmdHFFmcosTidProvision, IfPm3Iso14443a,  "Full TID provisioning sequence"},
    {"--------",      CmdHelp,                AlwaysAvailable, "--------- " _CYAN_("TID file creation") " ---------"},
    {"tidcreatedf",  CmdHFFmcosTidCreateDF,  IfPm3Iso14443a,  "CREATE sub-DF (TID format)"},
    {"tidcreatebin", CmdHFFmcosTidCreateBin, IfPm3Iso14443a,  "CREATE binary EF (TID format)"},
    {"tidcreaterec", CmdHFFmcosTidCreateRec, IfPm3Iso14443a,  "CREATE record EF (TID format)"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFFmcos(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
