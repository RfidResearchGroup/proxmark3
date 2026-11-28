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
// High frequency JavaCard / GlobalPlatform commands
//
// Implements an ISO14443-A management subset of GlobalPlatform Card Specification v2.3.1 + SCP03:
//   Read-only interrogation (no authentication, nothing written):
//   - info:      CPLC, Card Recognition Data, key information, capabilities, IIN/CIN, KDD,
//                sequence/confirmation counters and free resources, with platform fingerprinting
//   - scan:      applet discovery by SELECTing well-known AIDs (optionally every registry instance)
//   - keyaudit:  per-KVN default-key check; cryptogram verified offline, never sends EXTERNAL AUTH
//   - getdata / getkey / select / challenge / send: raw and decoded single objects
//   Secure channel:
//   - SCP01 (3DES, legacy), SCP02 (3DES, i auto-detected from CRD), SCP03 (S8/S16, AES-128/192/256)
//   - R-MAC verification and SCP03 R-ENC (SL 11 / 13 / 33); session status and close
//   - Default-key and diversification (EMV, VISA2, VISA, KDF3) discovery
//   Registry (GET STATUS, tagged and legacy formats): list, dump (+ JSON report)
//   Card management (every state-changing command requires --confirm):
//   - load / install / autoinstall (IJC and CAP/ZIP), delete
//   - PUT KEY (TDEA-ECB and AES with key-length byte), DELETE KEY, KCV
//   - SET STATUS, lock/unlock applet, lock-card, secure-card
//   Tooling: .gp scripts with secret redaction, INS fuzzer (state-changing INS skipped by default),
//   offline regression tests (hf javacard test)
//// References:
//   GlobalPlatform Card Specification v2.3.1 (GPC_SPE_034)
//   GlobalPlatform Secure Channel Protocol '03' Amendment D v1.2
//   Java Card Virtual Machine Specification v3.1: CAP file format
//   Java source: Java/GlobalPlatformPro (Martin Paljak, LGPL-3.0)
//   Java source: Java/JCardEngine  (Martin Paljak, Apache-2.0)
//
// Deliberate transport/scope limits:
//   - Short APDUs and the basic logical channel only
//   - Explicit, modified-APDU SCP01/SCP02 profiles only
//   - Compact single-package CAP loading (plus StaticResources.capx)
//   - No SCP11/SCP04, DAP/token generation, or receipt verification
//-----------------------------------------------------------------------------

#include "cmdhfjavacard.h"

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#include "cmdparser.h"              // command_t
#include "commonutil.h"             // ARRAYLEN
#include "comms.h"                  // clearCommandBuffer
#include "ui.h"                     // PrintAndLogEx
#include "util.h"                   // sprint_hex*
#include "util_posix.h"             // msleep
#include "cliparser.h"              // CLIParserContext
#include "cmdhf14a.h"               // ExchangeAPDU14a
#include "iso7816/iso7816core.h"    // Iso7816Select
#include "iso7816/apduinfo.h"       // GetAPDUCodeDescription, sAPDU_t
#include "fileutils.h"              // loadFile_safe
#include "aidsearch.h"              // AIDSearchInit/Free, PrintAIDDescriptionBuf
#include "mbedtls/des.h"            // 3DES / DES primitives
#include "mbedtls/aes.h"            // AES-128/192/256 primitives
#include "mbedtls/entropy.h"        // mbedTLS entropy source
#include "mbedtls/ctr_drbg.h"       // CTR-DRBG CSPRNG
#include "emv/tlv.h"                // tlvdb_parse / tlvdb_free / tlvdb_visit
#include "cmdhfjavacard_db.h"       // default keys, IC fabricator lookup, known AIDs
#include "scripting.h"              // lua_State (for Lua GP bindings)
#include "lauxlib.h"                // luaL_*

//=============================================================================
// Constants
//=============================================================================

static const uint8_t GP_ISD_AID[] = { 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00 };
#define GP_ISD_AID_LEN  8

#define GP_INS_SELECT               0xA4
#define GP_INS_GET_DATA             0xCA
#define GP_INS_INITIALIZE_UPDATE    0x50
#define GP_INS_EXTERNAL_AUTH        0x82
#define GP_INS_GET_STATUS           0xF2
#define GP_INS_SET_STATUS           0xF0
#define GP_INS_PUT_KEY              0xD8
#define GP_INS_STORE_DATA           0xE2
#define GP_INS_DELETE               0xE4
#define GP_INS_INSTALL              0xE6
#define GP_INS_LOAD                 0xE8

#define GP_CLA_PLAIN        0x80
#define GP_CLA_MAC          0x84
#define GP_CLA_CHAIN        0x10

#define GP_INIT_UPDATE_RESP_LEN_SCP02   28
#define GP_INIT_UPDATE_RESP_LEN_SCP03   29

#define GP_STATUS_ISD               0x80
#define GP_STATUS_APPS_AND_SSD      0x40
#define GP_STATUS_LOAD_FILES        0x20
#define GP_STATUS_LOAD_FILES_MODS   0x10
#define GP_STATUS_FIRST_BLOCK       0x00
#define GP_STATUS_NEXT_BLOCK        0x01

#define GP_INSTALL_P1_LOAD                  0x02
#define GP_INSTALL_P1_INSTALL               0x04
#define GP_INSTALL_P1_MAKE_SELECTABLE       0x08
#define GP_INSTALL_P1_INSTALL_SELECTABLE    0x0C
#define GP_INSTALL_P1_EXTRADITION           0x10
#define GP_INSTALL_P1_PERSONALIZATION       0x20
#define GP_INSTALL_P1_REGISTRY_UPDATE       0x40

// Security level bits
#define GP_SL_NO_SECURITY   0x00
#define GP_SL_C_MAC         0x01
#define GP_SL_C_DEC_MAC     0x03
#define GP_SL_R_MAC         0x10
#define GP_SL_C_MAC_R_MAC   0x11
#define GP_SL_C_DEC_MAC_R   0x13
#define GP_SL_R_ENC_MAC     0x30
#define GP_SL_C_DEC_R_ENC   0x33

// Short-APDU response data + S16 R-MAC + SW + margin.
#define GP_RESP_BUF_SIZE        320
#define GP_MAX_AES_KEY_LEN      32
#define GP_MAX_MAC_LEN          16
#define GP_MAX_SHORT_APDU_DATA  255
#define GP_MAX_WRAPPED_APDU     320
#define GP_MAX_RMAC_CONTEXT     280

// SCP02 derivation constants (Annex E.5)
static const uint8_t GP_SCP02_DERIVE_ENC[2]  = { 0x01, 0x82 };
static const uint8_t GP_SCP02_DERIVE_MAC[2]  = { 0x01, 0x01 };
static const uint8_t GP_SCP02_DERIVE_DEK[2]  = { 0x01, 0x81 };
static const uint8_t GP_SCP02_DERIVE_RMAC[2] = { 0x01, 0x02 };

// SCP03 data derivation constants, GlobalPlatform SCP03 Amendment D.
#define GP_SCP03_CONST_CARD_CG   0x00    // card authentication cryptogram
#define GP_SCP03_CONST_HOST_CG   0x01    // host authentication cryptogram
#define GP_SCP03_CONST_CARD_CHAL 0x02    // pseudo-random card challenge generation
#define GP_SCP03_CONST_ENC       0x04    // S-ENC
#define GP_SCP03_CONST_MAC       0x06    // S-MAC
#define GP_SCP03_CONST_RMAC      0x07    // S-RMAC

//=============================================================================
// Session State
//=============================================================================

typedef struct {
    bool     active;
    uint8_t  scp_version;       // 1, 2, or 3
    uint8_t  scp_i;             // implementation option reported by the card
    uint8_t  security_level;
    size_t   key_len;           // 16 for SCP01/02; 16/24/32 for SCP03
    size_t   mac_len;           // 8 in S8; 16 in S16
    uint8_t  enc_key[GP_MAX_AES_KEY_LEN];
    uint8_t  mac_key[GP_MAX_AES_KEY_LEN];
    uint8_t  dek_key[GP_MAX_AES_KEY_LEN];
    uint8_t  rmac_key[GP_MAX_AES_KEY_LEN];

    // SCP01/SCP02 state.
    uint8_t  icv[8];
    uint8_t  rmac_icv[8];
    uint8_t  ssc[2];
    bool     scp02_modified_apdu;
    bool     scp02_icv_encrypt;
    uint8_t  rmac_context[GP_MAX_RMAC_CONTEXT];
    size_t   rmac_context_len;

    // SCP03 state.
    uint8_t  chaining_value[16];
    uint8_t  enc_counter[16];
} gp_session_t;

static gp_session_t gp_ctx = { .active = false };
typedef int (*gp_exchange_fn)(const uint8_t *, int, bool, bool, uint8_t *, int, int *);
static int gp_isodep_exchange(const uint8_t *apdu, int apdu_len, bool activate, bool leave_on,
                              uint8_t *out, int out_max, int *out_len);
static gp_exchange_fn gp_exchange = gp_isodep_exchange;
// Wall-clock duration of the last / slowest card exchange (diagnostics).
static uint64_t gp_last_exchange_ms = 0;
static uint64_t gp_max_exchange_ms = 0;
static void gp_device_field_off(void) {
    DropField();
}
static void (*gp_field_off)(void) = gp_device_field_off;

//=============================================================================
// ISO/IEC 14443-4 (ISO-DEP) transport with timing derived from the card's ATS
//=============================================================================
//
// Every timeout below is computed from the parameters the card announces in
// its ATS and from how the device firmware handles WTX; there are no fixed
// guesses. Two defects of the generic ExchangeAPDU14a() path are avoided:
//
//  1. The firmware arms its frame timer with exactly FWT. ISO/IEC 14443-4
//     7.2 requires the PCD to wait FWT + dFWT (dFWT = 49152/fc): a JCOP that
//     sends S(WTX) close to FWT while it writes EEPROM was missed, R(NAK)
//     recovery collided with the card's processing and LOAD failed after
//     5 x FWT. We pass FWT + dFWT with every APDU (ISO14A_SET_TIMEOUT), so the
//     firmware's WTX and recovery logic run on the correct base.
//
//  2. The client waited a fixed 1500 ms for the device, although one WTX
//     round in the firmware may legitimately last up to 524288 * 128/fc.
//     The client deadline here is an idle deadline (comms resets it on every
//     device packet, including WTX notifications) set to the longest silence
//     the firmware can produce before it reports back.

#define GP_FC_HZ               13560000ULL
#define GP_DFWT_FC             49152U        // ISO/IEC 14443-4 7.2 dFWT
#define GP_ETU_FC              128U          // firmware iso14a_timeout unit (128/fc)
#define GP_FW_MAX_WTX_TIMEOUT  524288U       // armsrc MAX_ISO14A_TIMEOUT, in 128/fc
#define GP_FW_MAX_RETRANS      2U            // armsrc ISO14_MAX_RETRANS
#define GP_WTXM_MAX            59U           // ISO/IEC 14443-4 7.3: WTXM 1..59

typedef struct {
    bool valid;
    uint8_t fwi, sfgi, fsci;
    uint16_t fsc;                 // max frame size the PICC accepts (bytes incl. PCB+CRC)
    uint32_t fwt_fc;              // frame waiting time in 1/fc
    uint32_t reader_timeout_etu;  // FWT + dFWT in firmware units (128/fc)
    uint32_t client_idle_ms;      // longest device silence before it reports back
    bool last_failure_was_reset;  // PICC answered WUPA right after going silent
    uint8_t ats[64];              // ATS of the last activation (fingerprinting)
    uint8_t ats_len;
} gp_link_t;

static gp_link_t gp_link = { .valid = false };

static uint32_t gp_fc_to_ms_ceil(uint64_t fc) {
    return (uint32_t)((fc * 1000ULL + GP_FC_HZ - 1) / GP_FC_HZ);
}

// Derive link timing from the ATS (ats[0] = TL, ats[1] = T0, ...).
static void gp_link_from_ats(const uint8_t *ats, size_t ats_len) {
    static const uint16_t fsc_table[] = {16, 24, 32, 40, 48, 64, 96, 128, 256};
    // ISO/IEC 14443-4 5.2 defaults when T0/TB(1) are absent.
    uint8_t fsci = 2, fwi = 4, sfgi = 0;
    gp_link.ats_len = 0;
    if (ats != NULL && ats_len != 0) {
        gp_link.ats_len = (uint8_t)MIN(ats_len, sizeof(gp_link.ats));
        memcpy(gp_link.ats, ats, gp_link.ats_len);
    }
    if (ats != NULL && ats_len >= 2 && ats[0] >= 2) {
        uint8_t t0 = ats[1];
        fsci = t0 & 0x0F;
        size_t pos = 2;
        if (t0 & 0x10) pos++;                              // TA(1)
        if ((t0 & 0x20) && pos < ats_len && pos < ats[0]) { // TB(1)
            fwi = ats[pos] >> 4;
            sfgi = ats[pos] & 0x0F;
        }
    }
    if (fwi == 15) fwi = 4;           // RFU: use the default
    if (sfgi == 15) sfgi = 0;
    if (fsci >= ARRAYLEN(fsc_table)) fsci = ARRAYLEN(fsc_table) - 1; // >256 not usable here

    gp_link.fwi = fwi;
    gp_link.sfgi = sfgi;
    gp_link.fsci = fsci;
    gp_link.fsc = fsc_table[fsci];
    gp_link.fwt_fc = (256U * 16U) << fwi;
    // FWT + dFWT is only the minimum a PCD must wait. Measured on JCOP3 the
    // S(WTX) that covers an EEPROM-bound command occasionally arrives later,
    // and a missed frame turns into R(NAK)/retransmission while the PICC is
    // still busy. Silence can only mean "busy" or "link gone" (a damaged frame
    // ends the receive at once), so listen for the longest time the PICC could
    // legitimately need: the maximum WTX multiplier applied to FWT + dFWT,
    // bounded by the firmware's largest timeout.
    uint64_t wait_fc = (uint64_t)GP_WTXM_MAX * (gp_link.fwt_fc + GP_DFWT_FC);
    uint64_t wait_etu = (wait_fc + GP_ETU_FC - 1) / GP_ETU_FC;
    if (wait_etu > GP_FW_MAX_WTX_TIMEOUT) wait_etu = GP_FW_MAX_WTX_TIMEOUT;
    gp_link.reader_timeout_etu = (uint32_t)wait_etu;

    // Longest time the firmware can stay silent inside one APDU exchange:
    // the WTX loop arms MAX(WTXM * T, MAX_ISO14A_TIMEOUT) and a lost frame
    // costs up to 1 + 2 * ISO14_MAX_RETRANS waits at that timeout. If the
    // client deadline expires anyway, the firmware loop is aborted (see
    // gp_isodep_block) so device and client never drift apart.
    uint64_t round_etu = gp_link.reader_timeout_etu;
    if (round_etu < GP_FW_MAX_WTX_TIMEOUT) round_etu = GP_FW_MAX_WTX_TIMEOUT;
    uint64_t silent_fc = round_etu * GP_ETU_FC * (1U + 2U * GP_FW_MAX_RETRANS);
    gp_link.client_idle_ms = gp_fc_to_ms_ceil(silent_fc);
    gp_link.valid = true;
}

// Send one I-block (or an R(ACK) when data == NULL) and read the PICC's reply.
// *pcb receives the reply PCB as reported by the firmware.
static int gp_isodep_block(bool chaining, const uint8_t *data, uint16_t len,
                           uint8_t *out, size_t out_max, size_t *out_len, uint8_t *pcb) {
    uint32_t flags = ISO14A_APDU | ISO14A_NO_DISCONNECT | ISO14A_SET_TIMEOUT;
    if (chaining) flags |= ISO14A_SEND_CHAINING;
    SendIso14aReaderEx(flags, data, len, len, 0, gp_link.reader_timeout_etu, 0);

    PacketResponseNG resp;
    uint16_t rlen = 0;
    uint8_t res = 0;
    if (WaitForIso14aReply(&resp, gp_link.client_idle_ms, &rlen, &res) == false) {
        PrintAndLogEx(DEBUG, "ISO-DEP: device silent for %u ms, aborting the exchange", gp_link.client_idle_ms);
        // Any host packet makes the firmware's WTX/recovery loop return; drain
        // its reply so the next command is not answered with this one's.
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        WaitForIso14aReply(&resp, 1000, NULL, NULL);
        return PM3_ETIMEOUT;
    }
    *pcb = res;
    *out_len = 0;
    if ((res & 0xF6) == 0xA2) return PM3_SUCCESS;     // R(ACK): next chained block
    if (rlen == 0) {
        PrintAndLogEx(DEBUG, "ISO-DEP: no answer after recovery (PCB %02X)", res);
        return PM3_ECARDEXCHANGE;
    }
    if (rlen < 2) return PM3_EWRONGANSWER;
    size_t dlen = (size_t)rlen - 2;                    // firmware leaves the CRC
    if (dlen > out_max) return PM3_EOVFLOW;
    memcpy(out, resp.data.asBytes, dlen);
    *out_len = dlen;
    return PM3_SUCCESS;
}

static int gp_isodep_exchange(const uint8_t *apdu, int apdu_len, bool activate, bool leave_on,
                              uint8_t *out, int out_max, int *out_len) {
    *out_len = 0;
    if (apdu == NULL || apdu_len <= 0 || out == NULL || out_max <= 0) return PM3_EINVARG;

    if (activate || gp_link.valid == false) {
        iso14a_card_select_t card;
        int res = SelectCard14443A_4(false, false, &card);
        if (res != PM3_SUCCESS) {
            gp_link.valid = false;
            return res;
        }
        gp_link_from_ats(card.ats, card.ats_len);
    }

    int ret = PM3_SUCCESS;
    size_t total = 0;
    uint8_t pcb = 0;
    // Command chaining: an I-block carries FSC - 3 bytes (PCB + CRC); the
    // device also bounds what one USB frame may carry.
    size_t max_inf = (size_t)gp_link.fsc - 3;
    size_t usb_max = g_conn.max_cmd_data_size > sizeof(iso14a_raw_cmd_t) + 3
                     ? g_conn.max_cmd_data_size - sizeof(iso14a_raw_cmd_t) - 3 : 0;
    if (usb_max < max_inf) max_inf = usb_max;
    if (max_inf == 0) { ret = PM3_EINVARG; goto out; }

    size_t sent = 0;
    while (sent < (size_t)apdu_len) {
        size_t chunk = (size_t)apdu_len - sent;
        if (chunk > max_inf) chunk = max_inf;
        bool more = sent + chunk < (size_t)apdu_len;
        size_t got = 0;
        ret = gp_isodep_block(more, apdu + sent, (uint16_t)chunk, out, (size_t)out_max, &got, &pcb);
        if (ret != PM3_SUCCESS) goto out;
        if (more && (pcb & 0xF6) != 0xA2) { ret = PM3_EWRONGANSWER; goto out; }
        sent += chunk;
        total = got;
    }
    // Response chaining: acknowledge until the PICC sends its last I-block.
    while ((pcb & 0xE0) == 0x00 && (pcb & 0x10)) {
        size_t got = 0;
        ret = gp_isodep_block(false, NULL, 0, out + total, (size_t)out_max - total, &got, &pcb);
        if (ret != PM3_SUCCESS) goto out;
        total += got;
    }
    *out_len = (int)total;

out:
    gp_link.last_failure_was_reset = false;
    if (ret == PM3_ETIMEOUT || ret == PM3_ECARDEXCHANGE) {
        // A PICC in ISO 14443-4 PROTOCOL state ignores WUPA. If it answers one
        // right after going silent, it went through a power-on reset: the
        // command was lost to a supply brown-out, not to protocol timing.
        iso14a_card_select_t probe;
        gp_link.last_failure_was_reset = SelectCard14443A_4(true, false, &probe) == PM3_SUCCESS;
    }
    if (ret != PM3_SUCCESS || leave_on == false) DropField();
    if (ret != PM3_SUCCESS) gp_link.valid = false;
    return ret;
}

// Console layout helpers (defined with the info command).
static void gp_print_kv(const char *label, const char *format, ...) __attribute__((format(PM3_PRINTF_FORMAT, 2, 3)));
static void gp_print_banner(const char *title);
static void gp_print_section(const char *title);

static void gp_secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len-- > 0) *p++ = 0;
}

static int gp_parse_hex_string(const char *text, uint8_t *out,
                               size_t out_size, size_t *out_len) {
    if (text == NULL || out == NULL || out_len == NULL) return PM3_EINVARG;
    *out_len = 0;
    int high = -1;
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
        if (isspace(*p) || *p == ':' || *p == '-') continue;
        int value;
        if (*p >= '0' && *p <= '9') value = *p - '0';
        else if (*p >= 'a' && *p <= 'f') value = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') value = *p - 'A' + 10;
        else return PM3_EINVARG;
        if (high < 0) {
            high = value;
        } else {
            if (*out_len >= out_size) return PM3_EINVARG;
            out[(*out_len)++] = (uint8_t)((high << 4) | value);
            high = -1;
        }
    }
    return high < 0 ? PM3_SUCCESS : PM3_EINVARG;
}


static bool gp_consttime_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    if (a == NULL || b == NULL) return false;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static bool gp_parse_hex_byte(const char *text, int *value) {
    if (!text || !value) return false;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;
    size_t len = strlen(text);
    if (!len || len > 2) return false;
    unsigned result = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];
        int digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return false;
        result = result * 16 + (unsigned)digit;
    }
    *value = (int)result;
    return true;
}

static int gp_hex_option(CLIParserContext *ctx, int index, int default_value, int *value) {
    const struct arg_str *arg = arg_get_str(ctx, index);
    *value = default_value;
    if (!arg->count) return PM3_SUCCESS;
    if (gp_parse_hex_byte(arg->sval[0], value)) return PM3_SUCCESS;
    PrintAndLogEx(ERR, "--%s requires a hexadecimal byte (00..FF)", arg->hdr.longopts);
    return PM3_EINVARG;
}

#define GP_HEX_OPTION_OR_RETURN(ctx_, index_, default_, value_) do { \
    int _gp_hex_result = gp_hex_option((ctx_), (index_), (default_), &(value_)); \
    if (_gp_hex_result != PM3_SUCCESS) { CLIParserFree(ctx_); return _gp_hex_result; } \
} while (0)

static void gp_session_reset(void) {
    gp_secure_zero(&gp_ctx, sizeof(gp_ctx));
}

static void gp_drop_field(void) {
    gp_field_off();
    gp_session_reset();
}

static bool gp_sw_is_success_or_warning(uint16_t sw) {
    return sw == 0x9000 || (sw & 0xFF00) == 0x6200 || (sw & 0xFF00) == 0x6300;
}

static void gp_counter_increment(uint8_t counter[16]) {
    for (int i = 15; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) break;
    }
}

static int gp_unpad80(uint8_t *data, size_t *data_len) {
    if (data == NULL || data_len == NULL || *data_len == 0) return PM3_EINVARG;
    size_t i = *data_len;
    while (i > 0 && data[i - 1] == 0x00) i--;
    if (i == 0 || data[i - 1] != 0x80) return PM3_ESOFT;
    *data_len = i - 1;
    return PM3_SUCCESS;
}

//=============================================================================
// SCP02 Crypto
//=============================================================================

static int gp_des3_cbc_enc(const uint8_t *key, size_t key_len,
                            const uint8_t *iv,
                            const uint8_t *data, size_t data_len,
                            uint8_t *out) {
    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);
    int ret = (key_len == 16)
        ? mbedtls_des3_set2key_enc(&ctx, key)
        : mbedtls_des3_set3key_enc(&ctx, key);
    if (ret != 0) { mbedtls_des3_free(&ctx); return PM3_ESOFT; }
    uint8_t iv_buf[8];
    memcpy(iv_buf, iv, 8);
    ret = mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, data_len, iv_buf, data, out);
    mbedtls_des3_free(&ctx);
    return (ret == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

static int gp_des_ecb_enc(const uint8_t *key, const uint8_t *data, uint8_t *out) {
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, data, out);
    mbedtls_des_free(&ctx);
    return PM3_SUCCESS;
}

static int gp_des3_ecb_enc(const uint8_t *key, size_t key_len, const uint8_t *data, uint8_t *out) {
    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);
    int ret = (key_len == 16)
        ? mbedtls_des3_set2key_enc(&ctx, key)
        : mbedtls_des3_set3key_enc(&ctx, key);
    if (ret == 0) mbedtls_des3_crypt_ecb(&ctx, data, out);
    mbedtls_des3_free(&ctx);
    return (ret == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

static int gp_aes_setkey_enc(mbedtls_aes_context *ctx, const uint8_t *key, size_t key_len) {
    if (ctx == NULL || key == NULL || (key_len != 16 && key_len != 24 && key_len != 32))
        return PM3_EINVARG;
    return mbedtls_aes_setkey_enc(ctx, key, (unsigned int)(key_len * 8)) == 0 ? PM3_SUCCESS : PM3_ESOFT;
}

static int gp_aes_setkey_dec(mbedtls_aes_context *ctx, const uint8_t *key, size_t key_len) {
    if (ctx == NULL || key == NULL || (key_len != 16 && key_len != 24 && key_len != 32))
        return PM3_EINVARG;
    return mbedtls_aes_setkey_dec(ctx, key, (unsigned int)(key_len * 8)) == 0 ? PM3_SUCCESS : PM3_ESOFT;
}

static int gp_aes_ecb_encrypt(const uint8_t *key, size_t key_len,
                              const uint8_t in[16], uint8_t out[16]) {
    if (in == NULL || out == NULL) return PM3_EINVARG;
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int ret = gp_aes_setkey_enc(&ctx, key, key_len);
    if (ret == PM3_SUCCESS &&
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out) != 0)
        ret = PM3_ESOFT;
    mbedtls_aes_free(&ctx);
    return ret;
}

static int gp_aes_cbc_encrypt(const uint8_t *key, size_t key_len,
                              const uint8_t iv[16], const uint8_t *in,
                              size_t len, uint8_t *out) {
    if (iv == NULL || in == NULL || out == NULL || len == 0 || (len % 16) != 0)
        return PM3_EINVARG;
    mbedtls_aes_context ctx;
    uint8_t iv_work[16];
    memcpy(iv_work, iv, sizeof(iv_work));
    mbedtls_aes_init(&ctx);
    int ret = gp_aes_setkey_enc(&ctx, key, key_len);
    if (ret == PM3_SUCCESS &&
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv_work, in, out) != 0)
        ret = PM3_ESOFT;
    mbedtls_aes_free(&ctx);
    gp_secure_zero(iv_work, sizeof(iv_work));
    return ret;
}

static int gp_aes_cbc_decrypt(const uint8_t *key, size_t key_len,
                              const uint8_t iv[16], const uint8_t *in,
                              size_t len, uint8_t *out) {
    if (iv == NULL || in == NULL || out == NULL || len == 0 || (len % 16) != 0)
        return PM3_EINVARG;
    mbedtls_aes_context ctx;
    uint8_t iv_work[16];
    memcpy(iv_work, iv, sizeof(iv_work));
    mbedtls_aes_init(&ctx);
    int ret = gp_aes_setkey_dec(&ctx, key, key_len);
    if (ret == PM3_SUCCESS &&
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv_work, in, out) != 0)
        ret = PM3_ESOFT;
    mbedtls_aes_free(&ctx);
    gp_secure_zero(iv_work, sizeof(iv_work));
    return ret;
}

static void gp_shift_left_128(const uint8_t in[16], uint8_t out[16]) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t next = (uint8_t)(in[i] >> 7);
        out[i] = (uint8_t)((in[i] << 1) | carry);
        carry = next;
    }
}

// NIST SP 800-38B AES-CMAC supporting AES-128, AES-192 and AES-256.
static int gp_aes_cmac(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t mac[16]) {
    if (key == NULL || mac == NULL || (data == NULL && data_len != 0))
        return PM3_EINVARG;

    uint8_t zero[16] = {0};
    uint8_t l[16], k1[16], k2[16], x[16] = {0}, y[16], last[16] = {0};
    int ret = gp_aes_ecb_encrypt(key, key_len, zero, l);
    if (ret != PM3_SUCCESS) return ret;

    gp_shift_left_128(l, k1);
    k1[15] ^= (uint8_t)(0x87 & (uint8_t)(0 - (l[0] >> 7)));
    gp_shift_left_128(k1, k2);
    k2[15] ^= (uint8_t)(0x87 & (uint8_t)(0 - (k1[0] >> 7)));

    size_t blocks = (data_len + 15) / 16;
    bool complete = data_len != 0 && (data_len % 16) == 0;
    if (blocks == 0) blocks = 1;

    if (complete) {
        memcpy(last, data + 16 * (blocks - 1), 16);
        for (size_t i = 0; i < 16; i++) last[i] ^= k1[i];
    } else {
        size_t tail = data_len % 16;
        if (tail > 0) memcpy(last, data + 16 * (blocks - 1), tail);
        last[tail] = 0x80;
        for (size_t i = 0; i < 16; i++) last[i] ^= k2[i];
    }

    for (size_t block = 0; block + 1 < blocks; block++) {
        for (size_t i = 0; i < 16; i++) y[i] = (uint8_t)(x[i] ^ data[block * 16 + i]);
        ret = gp_aes_ecb_encrypt(key, key_len, y, x);
        if (ret != PM3_SUCCESS) goto out;
    }
    for (size_t i = 0; i < 16; i++) y[i] = (uint8_t)(x[i] ^ last[i]);
    ret = gp_aes_ecb_encrypt(key, key_len, y, mac);

out:
    gp_secure_zero(l, sizeof(l));
    gp_secure_zero(k1, sizeof(k1));
    gp_secure_zero(k2, sizeof(k2));
    gp_secure_zero(x, sizeof(x));
    gp_secure_zero(y, sizeof(y));
    gp_secure_zero(last, sizeof(last));
    return ret;
}


#ifdef HAVE_ZLIB
static int gp_zip_inflate_raw(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    zs.next_in = (Bytef *)src;
    zs.avail_in = (uInt)src_len;
    zs.next_out = dst;
    zs.avail_out = (uInt)dst_len;

    int ret = inflateInit2(&zs, -MAX_WBITS);
    if (ret != Z_OK) return PM3_ESOFT;
    ret = inflate(&zs, Z_FINISH);
    inflateEnd(&zs);
    if (ret != Z_STREAM_END || zs.total_out != dst_len) return PM3_ESOFT;
    return PM3_SUCCESS;
}
#endif

// ISO/IEC 7816-4 padding (0x80 || 0x00...)
static size_t gp_pad80(const uint8_t *data, size_t data_len, size_t block_size, uint8_t *out) {
    if (out == NULL || block_size == 0) return 0;
    if (data_len > 0) {
        if (data == NULL) return 0;
        memcpy(out, data, data_len);
    }
    out[data_len] = 0x80;
    size_t rem = (data_len + 1) % block_size;
    size_t pad_len = rem == 0 ? 0 : block_size - rem;
    if (pad_len > 0) memset(out + data_len + 1, 0x00, pad_len);
    return data_len + 1 + pad_len;
}


// Cryptographically-secure random bytes via mbedTLS CTR-DRBG.
static int gp_random_bytes(uint8_t *out, size_t len) {
    if (out == NULL || len == 0) return PM3_EINVARG;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "pm3-gp-host-challenge";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret == 0)
        ret = mbedtls_ctr_drbg_random(&ctr_drbg, out, len);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return (ret == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

// ISO 9797-1 MAC Algorithm 3 (Retail MAC)
static int gp_retail_mac(const uint8_t *key16, const uint8_t *data, size_t data_len,
                          const uint8_t *icv, uint8_t *mac_out) {
    if (data_len == 0 || (data_len % 8) != 0) return PM3_EINVARG;
    uint8_t state[8];
    memcpy(state, icv, 8);
    size_t num_blocks = data_len / 8;
    mbedtls_des_context des_ctx;
    mbedtls_des_init(&des_ctx);
    mbedtls_des_setkey_enc(&des_ctx, key16);
    for (size_t i = 0; i < num_blocks - 1; i++) {
        uint8_t xored[8];
        for (size_t j = 0; j < 8; j++) xored[j] = state[j] ^ data[i * 8 + j];
        mbedtls_des_crypt_ecb(&des_ctx, xored, state);
    }
    mbedtls_des_free(&des_ctx);
    uint8_t xored_last[8];
    for (size_t j = 0; j < 8; j++) xored_last[j] = state[j] ^ data[(num_blocks - 1) * 8 + j];
    gp_des3_ecb_enc(key16, 16, xored_last, mac_out);
    return PM3_SUCCESS;
}

// GPPro GPCrypto.mac_3des: pad unpadded data, 3DES-CBC, return the last block.
static int gp_mac_3des(const uint8_t *key16, const uint8_t *data, size_t data_len,
                        const uint8_t *iv, uint8_t *mac_out) {
    if (data == NULL || iv == NULL || mac_out == NULL) return PM3_EINVARG;

    size_t padded_len = data_len + 1;
    while ((padded_len % 8) != 0) padded_len++;

    uint8_t *padded = calloc(padded_len, 1);
    if (!padded) return PM3_EMALLOC;
    if (data_len > 0) memcpy(padded, data, data_len);
    padded[data_len] = 0x80;

    uint8_t *out = calloc(padded_len, 1);
    if (!out) { free(padded); return PM3_EMALLOC; }

    int ret = gp_des3_cbc_enc(key16, 16, iv, padded, padded_len, out);
    if (ret == PM3_SUCCESS) memcpy(mac_out, out + padded_len - 8, 8);
    free(padded);
    free(out);
    return ret;
}

static int gp_full_3des_mac(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            const uint8_t iv[8], uint8_t mac[8]) {
    if (key == NULL || data == NULL || iv == NULL || mac == NULL ||
        data_len == 0 || (data_len % 8) != 0)
        return PM3_EINVARG;
    uint8_t *cipher = calloc(data_len, 1);
    if (cipher == NULL) return PM3_EMALLOC;
    int ret = gp_des3_cbc_enc(key, key_len, iv, data, data_len, cipher);
    if (ret == PM3_SUCCESS) memcpy(mac, cipher + data_len - 8, 8);
    gp_secure_zero(cipher, data_len);
    free(cipher);
    return ret;
}


// Encrypt a 16-byte TDEA key component for PUT KEY: DEK, TDEA-ECB per block.
static int gp_scp02_encrypt_key_component(const uint8_t dek[16], const uint8_t key[16],
                                          uint8_t out[16]) {
    if (dek == NULL || key == NULL || out == NULL) return PM3_EINVARG;
    int ret = gp_des3_ecb_enc(dek, 16, key, out);
    if (ret == PM3_SUCCESS) ret = gp_des3_ecb_enc(dek, 16, key + 8, out + 8);
    return ret;
}

// Build one SCP03 AES key component for PUT KEY (GP Amendment D 7.2 / GPPro):
// 88 || L(1 + |cipher|) || clear key length || AES-CBC(DEK, IV=0, key || 0-pad) || 03 || KCV.
static int gp_scp03_build_key_component(const uint8_t *dek, size_t dek_len,
                                        const uint8_t *key, size_t key_len,
                                        uint8_t *out, size_t out_size, size_t *out_len) {
    if (dek == NULL || key == NULL || out == NULL || out_len == NULL ||
        (key_len != 16 && key_len != 24 && key_len != 32))
        return PM3_EINVARG;
    size_t cipher_len = (key_len + 15) & ~(size_t)15;
    if (out_size < 2 + 1 + cipher_len + 1 + 3) return PM3_EINVARG;

    uint8_t padded[32] = {0}, cipher[32] = {0}, iv[16] = {0}, kcv[16] = {0}, ones[16];
    memset(ones, 0x01, sizeof(ones));
    memcpy(padded, key, key_len);
    int ret = gp_aes_cbc_encrypt(dek, dek_len, iv, padded, cipher_len, cipher);
    if (ret == PM3_SUCCESS) ret = gp_aes_ecb_encrypt(key, key_len, ones, kcv);
    if (ret == PM3_SUCCESS) {
        size_t off = 0;
        out[off++] = 0x88;
        out[off++] = (uint8_t)(1 + cipher_len);
        out[off++] = (uint8_t)key_len;
        memcpy(out + off, cipher, cipher_len);
        off += cipher_len;
        out[off++] = 0x03;
        memcpy(out + off, kcv, 3);
        off += 3;
        *out_len = off;
    }
    gp_secure_zero(padded, sizeof(padded));
    gp_secure_zero(cipher, sizeof(cipher));
    gp_secure_zero(kcv, sizeof(kcv));
    return ret;
}

// SCP02 session key derivation
static int gp_scp02_derive_key(const uint8_t *master, size_t key_len,
                                const uint8_t *type_const2, const uint8_t ssc[2],
                                uint8_t *out) {
    uint8_t deriv[16] = {0};
    deriv[0] = type_const2[0]; deriv[1] = type_const2[1];
    deriv[2] = ssc[0];         deriv[3] = ssc[1];
    uint8_t iv[8] = {0};
    return gp_des3_cbc_enc(master, key_len, iv, deriv, 16, out);
}

typedef enum {
    GP_KDF_NONE = 0,
    GP_KDF_EMV,
    GP_KDF_VISA2,
    GP_KDF_VISA,
    GP_KDF_KDF3
} gp_kdf_template_t;

static const char *gp_kdf_template_name(gp_kdf_template_t kdf) {
    switch (kdf) {
        case GP_KDF_NONE:  return "none";
        case GP_KDF_EMV:   return "EMV";
        case GP_KDF_VISA2: return "VISA2";
        case GP_KDF_VISA:  return "VISA";
        case GP_KDF_KDF3:  return "KDF3";
        default:           return "none";
    }
}

// GlobalPlatformPro PlaintextKeys SCP01/SCP02 diversification templates:
// EMV   = $4 $5 $6 $7 $8 $9 F0 $k $4 $5 $6 $7 $8 $9 0F $k
// VISA2 = $0 $1 $4 $5 $6 $7 F0 $k $0 $1 $4 $5 $6 $7 0F $k
// VISA  = $0 $1 $2 $3 $8 $9 F0 $k $0 $1 $2 $3 $8 $9 0F $k
static int gp_diversify_3des_key(const uint8_t *master, const uint8_t *kdd,
                                  uint8_t key_type, gp_kdf_template_t kdf,
                                  uint8_t *out) {
    if (master == NULL || kdd == NULL || out == NULL) return PM3_EINVARG;

    uint8_t deriv[16] = {0};
    switch (kdf) {
        case GP_KDF_NONE:
            memcpy(out, master, 16);
            return PM3_SUCCESS;
        case GP_KDF_EMV:
            memcpy(deriv + 0, kdd + 4, 6);
            deriv[6] = 0xF0;
            deriv[7] = key_type;
            memcpy(deriv + 8, kdd + 4, 6);
            deriv[14] = 0x0F;
            deriv[15] = key_type;
            break;
        case GP_KDF_VISA2:
            memcpy(deriv + 0, kdd + 0, 2);
            memcpy(deriv + 2, kdd + 4, 4);
            deriv[6] = 0xF0;
            deriv[7] = key_type;
            memcpy(deriv + 8, kdd + 0, 2);
            memcpy(deriv + 10, kdd + 4, 4);
            deriv[14] = 0x0F;
            deriv[15] = key_type;
            break;
        case GP_KDF_VISA:
            memcpy(deriv + 0, kdd + 0, 4);
            memcpy(deriv + 4, kdd + 8, 2);
            deriv[6] = 0xF0;
            deriv[7] = key_type;
            memcpy(deriv + 8, kdd + 0, 4);
            memcpy(deriv + 12, kdd + 8, 2);
            deriv[14] = 0x0F;
            deriv[15] = key_type;
            break;
        case GP_KDF_KDF3:
            return PM3_EINVARG;
    }

    if (gp_des3_ecb_enc(master, 16, deriv, out) != PM3_SUCCESS) return PM3_ESOFT;
    if (gp_des3_ecb_enc(master, 16, deriv + 8, out + 8) != PM3_SUCCESS) return PM3_ESOFT;
    return PM3_SUCCESS;
}

//=============================================================================
// SCP01 key derivation (GPC 2.3.1 Annex E.4)
//=============================================================================

static bool gp_scp01_try_keyset(const uint8_t *enc_key, const uint8_t *mac_key,
                                 const uint8_t *host_chal, const uint8_t *card_chal,
                                 const uint8_t *card_cg,
                                 uint8_t *s_enc, uint8_t *s_mac) {
    if (enc_key == NULL || mac_key == NULL || host_chal == NULL ||
        card_chal == NULL || card_cg == NULL || s_enc == NULL || s_mac == NULL)
        return false;

    uint8_t deriv[16];
    memcpy(deriv + 0, card_chal + 4, 4);
    memcpy(deriv + 4, host_chal + 0, 4);
    memcpy(deriv + 8, card_chal + 0, 4);
    memcpy(deriv + 12, host_chal + 4, 4);
    uint8_t zero_iv[8] = {0};
    if (gp_des3_cbc_enc(enc_key, 16, zero_iv, deriv, sizeof(deriv), s_enc) != PM3_SUCCESS)
        return false;
    if (gp_des3_cbc_enc(mac_key, 16, zero_iv, deriv, sizeof(deriv), s_mac) != PM3_SUCCESS)
        return false;

    uint8_t input[16];
    uint8_t expected[8];
    memcpy(input, host_chal, 8);
    memcpy(input + 8, card_chal, 8);
    bool ok = gp_mac_3des(s_enc, input, sizeof(input), zero_iv, expected) == PM3_SUCCESS &&
              gp_consttime_equal(expected, card_cg, sizeof(expected));
    gp_secure_zero(deriv, sizeof(deriv));
    gp_secure_zero(input, sizeof(input));
    gp_secure_zero(expected, sizeof(expected));
    return ok;
}


//=============================================================================
// SCP03 Crypto (GP Amendment D)
//=============================================================================

// KDF in counter mode with AES-CMAC.
// Block A = [0x00 x 11] || constant || 0x00 || out_bits_hi || out_bits_lo.
// SCP03 orders the fixed input as: Block A || counter || context.
static int gp_scp03_kdf_raw(const uint8_t *key, size_t key_len,
                            const uint8_t *block_a, size_t block_a_len,
                            const uint8_t *block_b, size_t block_b_len,
                            size_t out_bytes, uint8_t *out) {
    if (key == NULL || out == NULL || out_bytes == 0 || out_bytes > GP_MAX_AES_KEY_LEN)
        return PM3_EINVARG;
    if (key_len != 16 && key_len != 24 && key_len != 32) return PM3_EINVARG;
    if ((block_a == NULL && block_a_len != 0) || (block_b == NULL && block_b_len != 0))
        return PM3_EINVARG;
    if (block_a_len + block_b_len + 1 > 96) return PM3_EINVARG;

    uint8_t input[96];
    uint8_t cmac[16];
    size_t produced = 0;
    uint8_t counter = 1;

    while (produced < out_bytes) {
        size_t off = 0;
        if (block_a_len > 0) {
            memcpy(input + off, block_a, block_a_len);
            off += block_a_len;
        }
        input[off++] = counter++;
        if (block_b_len > 0) {
            memcpy(input + off, block_b, block_b_len);
            off += block_b_len;
        }

        int ret = gp_aes_cmac(key, key_len, input, off, cmac);
        if (ret != PM3_SUCCESS) {
            gp_secure_zero(input, sizeof(input));
            gp_secure_zero(cmac, sizeof(cmac));
            return ret;
        }
        size_t take = out_bytes - produced;
        if (take > sizeof(cmac)) take = sizeof(cmac);
        memcpy(out + produced, cmac, take);
        produced += take;
    }

    gp_secure_zero(input, sizeof(input));
    gp_secure_zero(cmac, sizeof(cmac));
    return PM3_SUCCESS;
}


static int gp_scp03_kdf(const uint8_t *key, size_t key_len, uint8_t constant,
                         const uint8_t *context, size_t context_len,
                         size_t out_bytes, uint8_t *out) {
    if (context_len > 64 || (context == NULL && context_len != 0) ||
        out_bytes == 0 || out_bytes > GP_MAX_AES_KEY_LEN)
        return PM3_EINVARG;

    uint16_t out_bits = (uint16_t)(out_bytes * 8);
    uint8_t block_a[15] = {0};
    block_a[11] = constant;
    block_a[12] = 0x00;
    block_a[13] = (uint8_t)(out_bits >> 8);
    block_a[14] = (uint8_t)out_bits;
    return gp_scp03_kdf_raw(key, key_len, block_a, sizeof(block_a),
                            context, context_len, out_bytes, out);
}


// GlobalPlatformPro KDF3 template for SCP03:
// $_ 00 00 00 $k 00 $0 $1 $2 $3 $4 $5 $6 $7 $8 $9
static int gp_scp03_diversify_key(const uint8_t *master, size_t key_len,
                                  const uint8_t *kdd, uint8_t key_type,
                                  gp_kdf_template_t kdf, uint8_t *out) {
    if (master == NULL || kdd == NULL || out == NULL) return PM3_EINVARG;
    if (key_len != 16 && key_len != 24 && key_len != 32) return PM3_EINVARG;
    if (kdf == GP_KDF_NONE) {
        memcpy(out, master, key_len);
        return PM3_SUCCESS;
    }
    if (kdf != GP_KDF_KDF3) return PM3_EINVARG;

    uint8_t block_b[15] = {0x00, 0x00, 0x00, key_type, 0x00};
    memcpy(block_b + 5, kdd, 10);
    return gp_scp03_kdf_raw(master, key_len, NULL, 0, block_b, sizeof(block_b),
                            key_len, out);
}


// SCP03 APDU wrap (AES-CMAC MAC, optional AES-CBC encryption).
// Session state is committed only after the complete APDU has been built.
static int gp_scp03_wrap(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                          const uint8_t *data_in, size_t data_in_len,
                          uint8_t *apdu_out, size_t *apdu_out_len) {
    if (!gp_ctx.active || gp_ctx.scp_version != 3 ||
        apdu_out == NULL || apdu_out_len == NULL ||
        (data_in == NULL && data_in_len != 0))
        return PM3_EINVARG;
    if (gp_ctx.mac_len != 8 && gp_ctx.mac_len != 16) return PM3_ESOFT;
    if (gp_ctx.key_len != 16 && gp_ctx.key_len != 24 && gp_ctx.key_len != 32)
        return PM3_ESOFT;

    // The secure-messaging indicator is included for MAC calculation. Preserve
    // basic logical-channel bits, but reject supplementary-channel coding until
    // the transport exposes it explicitly.
    if ((cla & 0x40) != 0) {
        PrintAndLogEx(ERR, "SCP03 supplementary logical channels are not supported");
        return PM3_EINVARG;
    }
    uint8_t secure_cla = (uint8_t)((cla & 0xFB) | 0x04);

    const bool do_enc = (gp_ctx.security_level & 0x02) != 0;
    uint8_t command_counter[16];
    memcpy(command_counter, gp_ctx.enc_counter, sizeof(command_counter));
    gp_counter_increment(command_counter); // every post-authentication C-APDU

    uint8_t protected_data[GP_MAX_SHORT_APDU_DATA + 16] = {0};
    size_t protected_len = data_in_len;

    if (do_enc && data_in_len > 0) {
        uint8_t padded[GP_MAX_SHORT_APDU_DATA + 16] = {0};
        size_t padded_len = gp_pad80(data_in, data_in_len, 16, padded);
        if (padded_len == 0 || padded_len + gp_ctx.mac_len > GP_MAX_SHORT_APDU_DATA)
            return PM3_EINVARG;

        uint8_t icv[16];
        int ret = gp_aes_ecb_encrypt(gp_ctx.enc_key, gp_ctx.key_len,
                                     command_counter, icv);
        if (ret != PM3_SUCCESS) return ret;
        ret = gp_aes_cbc_encrypt(gp_ctx.enc_key, gp_ctx.key_len, icv,
                                 padded, padded_len, protected_data);
        gp_secure_zero(icv, sizeof(icv));
        gp_secure_zero(padded, sizeof(padded));
        if (ret != PM3_SUCCESS) return ret;
        protected_len = padded_len;
    } else if (data_in_len > 0) {
        if (data_in_len + gp_ctx.mac_len > GP_MAX_SHORT_APDU_DATA)
            return PM3_EINVARG;
        memcpy(protected_data, data_in, data_in_len);
    }

    if (protected_len + gp_ctx.mac_len > GP_MAX_SHORT_APDU_DATA)
        return PM3_EINVARG;

    uint8_t mac_input[16 + 5 + GP_MAX_SHORT_APDU_DATA] = {0};
    size_t mac_input_len = 0;
    memcpy(mac_input, gp_ctx.chaining_value, 16);
    mac_input_len += 16;
    mac_input[mac_input_len++] = secure_cla;
    mac_input[mac_input_len++] = ins;
    mac_input[mac_input_len++] = p1;
    mac_input[mac_input_len++] = p2;
    mac_input[mac_input_len++] = (uint8_t)(protected_len + gp_ctx.mac_len);
    if (protected_len > 0) {
        memcpy(mac_input + mac_input_len, protected_data, protected_len);
        mac_input_len += protected_len;
    }

    uint8_t full_mac[16];
    int ret = gp_aes_cmac(gp_ctx.mac_key, gp_ctx.key_len,
                          mac_input, mac_input_len, full_mac);
    gp_secure_zero(mac_input, sizeof(mac_input));
    if (ret != PM3_SUCCESS) return ret;

    size_t off = 0;
    apdu_out[off++] = secure_cla;
    apdu_out[off++] = ins;
    apdu_out[off++] = p1;
    apdu_out[off++] = p2;
    apdu_out[off++] = (uint8_t)(protected_len + gp_ctx.mac_len);
    if (protected_len > 0) {
        memcpy(apdu_out + off, protected_data, protected_len);
        off += protected_len;
    }
    memcpy(apdu_out + off, full_mac, gp_ctx.mac_len);
    off += gp_ctx.mac_len;
    *apdu_out_len = off;

    memcpy(gp_ctx.enc_counter, command_counter, sizeof(gp_ctx.enc_counter));
    memcpy(gp_ctx.chaining_value, full_mac, sizeof(gp_ctx.chaining_value));

    gp_secure_zero(command_counter, sizeof(command_counter));
    gp_secure_zero(protected_data, sizeof(protected_data));
    gp_secure_zero(full_mac, sizeof(full_mac));
    return PM3_SUCCESS;
}


// Verify SCP03 R-MAC (last S8/S16 bytes of response are the R-MAC).
// Input to CMAC: chaining_value(16) || resp_without_rmac || SW1 || SW2
// R-MAC = first S8/S16 bytes of CMAC result (most significant).
static bool gp_scp03_verify_rmac(const uint8_t *resp_data, size_t resp_data_len,
                                  uint8_t sw1, uint8_t sw2) {
    if (!gp_ctx.active || gp_ctx.scp_version != 3 || resp_data == NULL ||
        (gp_ctx.mac_len != 8 && gp_ctx.mac_len != 16) ||
        resp_data_len < gp_ctx.mac_len)
        return false;

    size_t body_len = resp_data_len - gp_ctx.mac_len;
    if (body_len > GP_MAX_SHORT_APDU_DATA) return false;
    const uint8_t *received = resp_data + body_len;

    uint8_t input[16 + GP_MAX_SHORT_APDU_DATA + 2] = {0};
    size_t input_len = 0;
    memcpy(input, gp_ctx.chaining_value, 16);
    input_len += 16;
    if (body_len > 0) {
        memcpy(input + input_len, resp_data, body_len);
        input_len += body_len;
    }
    input[input_len++] = sw1;
    input[input_len++] = sw2;

    uint8_t expected[16];
    int ret = gp_aes_cmac(gp_ctx.rmac_key, gp_ctx.key_len,
                          input, input_len, expected);
    bool ok = ret == PM3_SUCCESS &&
              gp_consttime_equal(expected, received, gp_ctx.mac_len);
    gp_secure_zero(input, sizeof(input));
    gp_secure_zero(expected, sizeof(expected));
    return ok;
}

static int gp_scp03_decrypt_response(uint8_t *data, size_t *data_len) {
    if (data == NULL || data_len == NULL || *data_len == 0)
        return PM3_EINVARG;
    if ((*data_len % 16) != 0) return PM3_ESOFT;

    uint8_t response_counter[16];
    uint8_t iv[16];
    memcpy(response_counter, gp_ctx.enc_counter, sizeof(response_counter));
    response_counter[0] = 0x80;

    int ret = gp_aes_ecb_encrypt(gp_ctx.enc_key, gp_ctx.key_len,
                                 response_counter, iv);
    if (ret == PM3_SUCCESS) {
        uint8_t plain[GP_MAX_SHORT_APDU_DATA + 16];
        if (*data_len > sizeof(plain)) ret = PM3_EINVARG;
        else {
            ret = gp_aes_cbc_decrypt(gp_ctx.enc_key, gp_ctx.key_len, iv,
                                     data, *data_len, plain);
            if (ret == PM3_SUCCESS) {
                size_t plain_len = *data_len;
                ret = gp_unpad80(plain, &plain_len);
                if (ret == PM3_SUCCESS) {
                    memcpy(data, plain, plain_len);
                    *data_len = plain_len;
                }
            }
        }
        gp_secure_zero(plain, sizeof(plain));
    }
    gp_secure_zero(response_counter, sizeof(response_counter));
    gp_secure_zero(iv, sizeof(iv));
    return ret;
}


//=============================================================================
// SCP02 APDU wrapping
//=============================================================================

static int gp_scp02_wrap(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                          const uint8_t *data_in, size_t data_in_len,
                          uint8_t *apdu_out, size_t *apdu_out_len) {
    if (!gp_ctx.active || (gp_ctx.scp_version != 1 && gp_ctx.scp_version != 2) ||
        apdu_out == NULL || apdu_out_len == NULL ||
        (data_in == NULL && data_in_len != 0))
        return PM3_EINVARG;
    if (data_in_len > GP_MAX_SHORT_APDU_DATA) return PM3_EINVARG;

    const bool is_scp01 = gp_ctx.scp_version == 1;
    const bool do_mac = (gp_ctx.security_level & GP_SL_C_MAC) != 0;
    const bool do_enc = (gp_ctx.security_level & 0x02) != 0;

    if (!do_mac && do_enc) return PM3_EINVARG;
    if (!do_mac && !do_enc) {
        size_t off = 0;
        apdu_out[off++] = cla;
        apdu_out[off++] = ins;
        apdu_out[off++] = p1;
        apdu_out[off++] = p2;
        if (data_in_len > 0) {
            apdu_out[off++] = (uint8_t)data_in_len;
            memcpy(apdu_out + off, data_in, data_in_len);
            off += data_in_len;
        }
        *apdu_out_len = off;
        return PM3_SUCCESS;
    }

    if (!gp_ctx.scp02_modified_apdu) {
        PrintAndLogEx(ERR, "This build supports only SCP01/02 modified-APDU C-MAC variants");
        return PM3_EINVARG;
    }

    // Save the unwrapped command context for SCP02 R-MAC.  The response MAC
    // binds the response to the exact command/response pair.
    gp_ctx.rmac_context_len = 0;
    if ((gp_ctx.security_level & GP_SL_R_MAC) && gp_ctx.scp_version == 2) {
        size_t needed = 5 + data_in_len;
        if (needed > sizeof(gp_ctx.rmac_context)) return PM3_EINVARG;
        gp_ctx.rmac_context[gp_ctx.rmac_context_len++] = (uint8_t)(cla & 0xFB);
        gp_ctx.rmac_context[gp_ctx.rmac_context_len++] = ins;
        gp_ctx.rmac_context[gp_ctx.rmac_context_len++] = p1;
        gp_ctx.rmac_context[gp_ctx.rmac_context_len++] = p2;
        gp_ctx.rmac_context[gp_ctx.rmac_context_len++] = (uint8_t)data_in_len;
        if (data_in_len > 0) {
            memcpy(gp_ctx.rmac_context + gp_ctx.rmac_context_len, data_in, data_in_len);
            gp_ctx.rmac_context_len += data_in_len;
        }
    }

    uint8_t protected_data[GP_MAX_SHORT_APDU_DATA + 16] = {0};
    size_t protected_len = data_in_len;
    if (do_enc && data_in_len > 0) {
        uint8_t padded[GP_MAX_SHORT_APDU_DATA + 16] = {0};
        size_t padded_len;
        if (is_scp01) {
            uint8_t with_len[GP_MAX_SHORT_APDU_DATA + 1];
            with_len[0] = (uint8_t)data_in_len;
            memcpy(with_len + 1, data_in, data_in_len);
            if ((data_in_len + 1) % 8 == 0) {
                padded_len = data_in_len + 1;
                memcpy(padded, with_len, padded_len);
            } else {
                padded_len = gp_pad80(with_len, data_in_len + 1, 8, padded);
            }
            gp_secure_zero(with_len, sizeof(with_len));
        } else {
            padded_len = gp_pad80(data_in, data_in_len, 8, padded);
        }
        if (padded_len == 0 || padded_len + 8 > GP_MAX_SHORT_APDU_DATA)
            return PM3_EINVARG;
        uint8_t zero_iv[8] = {0};
        int ret = gp_des3_cbc_enc(gp_ctx.enc_key, 16, zero_iv,
                                  padded, padded_len, protected_data);
        gp_secure_zero(padded, sizeof(padded));
        if (ret != PM3_SUCCESS) return ret;
        protected_len = padded_len;
    } else if (data_in_len > 0) {
        if (data_in_len + 8 > GP_MAX_SHORT_APDU_DATA) return PM3_EINVARG;
        memcpy(protected_data, data_in, data_in_len);
    }

    uint8_t secure_cla = (uint8_t)((cla & 0xFB) | 0x04);
    uint8_t mac_input[5 + GP_MAX_SHORT_APDU_DATA] = {0};
    size_t mac_input_len = 0;
    mac_input[mac_input_len++] = secure_cla;
    mac_input[mac_input_len++] = ins;
    mac_input[mac_input_len++] = p1;
    mac_input[mac_input_len++] = p2;
    // SCP01/02 authenticate the original data, before command encryption.
    mac_input[mac_input_len++] = (uint8_t)(data_in_len + 8);
    if (data_in_len > 0) {
        memcpy(mac_input + mac_input_len, data_in, data_in_len);
        mac_input_len += data_in_len;
    }

    uint8_t padded_mac[5 + GP_MAX_SHORT_APDU_DATA + 8] = {0};
    size_t padded_mac_len = gp_pad80(mac_input, mac_input_len, 8, padded_mac);
    if (padded_mac_len == 0) return PM3_ESOFT;

    uint8_t mac_iv[8];
    if (!gp_ctx.scp02_icv_encrypt) {
        memcpy(mac_iv, gp_ctx.icv, sizeof(mac_iv));
    } else if (is_scp01) {
        int ret = gp_des3_ecb_enc(gp_ctx.mac_key, 16, gp_ctx.icv, mac_iv);
        if (ret != PM3_SUCCESS) return ret;
    } else {
        int ret = gp_des_ecb_enc(gp_ctx.mac_key, gp_ctx.icv, mac_iv);
        if (ret != PM3_SUCCESS) return ret;
    }

    uint8_t mac[8];
    int ret = is_scp01
        ? gp_full_3des_mac(gp_ctx.mac_key, 16, padded_mac, padded_mac_len, mac_iv, mac)
        : gp_retail_mac(gp_ctx.mac_key, padded_mac, padded_mac_len, mac_iv, mac);
    gp_secure_zero(mac_input, sizeof(mac_input));
    gp_secure_zero(padded_mac, sizeof(padded_mac));
    gp_secure_zero(mac_iv, sizeof(mac_iv));
    if (ret != PM3_SUCCESS) return ret;
    memcpy(gp_ctx.icv, mac, sizeof(gp_ctx.icv));

    size_t off = 0;
    apdu_out[off++] = secure_cla;
    apdu_out[off++] = ins;
    apdu_out[off++] = p1;
    apdu_out[off++] = p2;
    apdu_out[off++] = (uint8_t)(protected_len + 8);
    if (protected_len > 0) {
        memcpy(apdu_out + off, protected_data, protected_len);
        off += protected_len;
    }
    memcpy(apdu_out + off, mac, sizeof(mac));
    off += sizeof(mac);
    *apdu_out_len = off;

    gp_secure_zero(protected_data, sizeof(protected_data));
    gp_secure_zero(mac, sizeof(mac));
    return PM3_SUCCESS;
}


// Verify SCP02 R-MAC (last 8 bytes of response using R-MAC key + current ICV)
static bool gp_scp02_verify_rmac(const uint8_t *resp_data, size_t resp_data_len,
                                  uint8_t sw1, uint8_t sw2) {
    if (!gp_ctx.active || gp_ctx.scp_version != 2 || resp_data == NULL ||
        resp_data_len < 8 || gp_ctx.rmac_context_len == 0)
        return false;

    size_t body_len = resp_data_len - 8;
    if (body_len > GP_MAX_SHORT_APDU_DATA) return false;
    const uint8_t *received = resp_data + body_len;

    uint8_t input[GP_MAX_RMAC_CONTEXT + 1 + GP_MAX_SHORT_APDU_DATA + 2] = {0};
    size_t off = 0;
    if (gp_ctx.rmac_context_len > sizeof(input)) return false;
    memcpy(input, gp_ctx.rmac_context, gp_ctx.rmac_context_len);
    off += gp_ctx.rmac_context_len;
    input[off++] = (uint8_t)body_len;
    if (body_len > 0) {
        memcpy(input + off, resp_data, body_len);
        off += body_len;
    }
    input[off++] = sw1;
    input[off++] = sw2;

    uint8_t padded[sizeof(input) + 8] = {0};
    size_t padded_len = gp_pad80(input, off, 8, padded);
    uint8_t expected[8];
    int ret = padded_len == 0 ? PM3_ESOFT
                              : gp_retail_mac(gp_ctx.rmac_key, padded, padded_len,
                                              gp_ctx.rmac_icv, expected);
    bool ok = ret == PM3_SUCCESS && gp_consttime_equal(expected, received, 8);
    if (ok) memcpy(gp_ctx.rmac_icv, expected, sizeof(gp_ctx.rmac_icv));

    gp_secure_zero(input, sizeof(input));
    gp_secure_zero(padded, sizeof(padded));
    gp_secure_zero(expected, sizeof(expected));
    gp_secure_zero(gp_ctx.rmac_context, sizeof(gp_ctx.rmac_context));
    gp_ctx.rmac_context_len = 0;
    return ok;
}


//=============================================================================
// Card communication helpers
//=============================================================================

static int gp_send_apdu(bool activate, bool leave_on,
                        const uint8_t *apdu, size_t apdu_len,
                        uint8_t *resp, size_t resp_buf_len, size_t *resp_len,
                        uint16_t *sw, bool verbose) {
    if (resp_len) *resp_len = 0;
    if (sw) *sw = 0;
    if (apdu == NULL || apdu_len < 4 || resp == NULL || resp_len == NULL ||
        sw == NULL || apdu_len > INT_MAX || resp_buf_len < 2 || resp_buf_len > INT_MAX)
        return PM3_EINVARG;

    if (activate) {
        gp_drop_field();
        msleep(50);
    }

    int rlen = 0;
    uint64_t started = msclock();
    int ret = gp_exchange(apdu, (int)apdu_len, activate, leave_on,
                              resp, (int)resp_buf_len, &rlen);
    gp_last_exchange_ms = msclock() - started;
    if (gp_last_exchange_ms > gp_max_exchange_ms) gp_max_exchange_ms = gp_last_exchange_ms;
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "APDU exchange failed (%d) after %" PRIu64 " ms, received %d byte(s)",
                      ret, gp_last_exchange_ms, rlen);
        if (gp_link.last_failure_was_reset) {
            PrintAndLogEx(WARNING, "The card " _RED_("reset") " during the command (it answered a fresh WUPA): "
                          "supply brown-out, typically while it programs EEPROM.");
            PrintAndLogEx(HINT, "Hint: centre the card flat on the HF antenna, avoid metal nearby, and check `"
                          _YELLOW_("hw tune") "`");
        }
        *resp_len = 0;
        *sw = 0;
        gp_drop_field();
        return ret;
    }
    if (rlen < 2 || (size_t)rlen > resp_buf_len) {
        *resp_len = 0;
        *sw = 0;
        gp_drop_field();
        return PM3_ESOFT;
    }

    *sw = (uint16_t)(((uint16_t)resp[rlen - 2] << 8) | resp[rlen - 1]);
    *resp_len = (size_t)rlen - 2;
    if (verbose) {
        if (activate && gp_link.valid)
            PrintAndLogEx(INFO, "    link: FSC %u, FWI %u, listen %.1f ms, device deadline %u ms", gp_link.fsc, gp_link.fwi,
                          gp_link.reader_timeout_etu * (double)GP_ETU_FC * 1000.0 / GP_FC_HZ, gp_link.client_idle_ms);
        PrintAndLogEx(INFO, "<<< %s | SW: " _YELLOW_("%04X") " - %s  (%" PRIu64 " ms)",
                      sprint_hex_inrow(resp, *resp_len), *sw,
                      GetAPDUCodeDescription(resp[rlen - 2], resp[rlen - 1]), gp_last_exchange_ms);
    }
    if (!leave_on) gp_session_reset();
    return PM3_SUCCESS;
}


static int gp_plain_command(bool activate, uint8_t *apdu, size_t apdu_len, bool has_le,
                             uint8_t *response, size_t capacity, size_t *length, uint16_t *sw, bool verbose) {
    int ret = gp_send_apdu(activate, true, apdu, apdu_len, response, capacity, length, sw, verbose);
    if (ret || (*sw & 0xff00) != 0x6c00) return ret;
    if (*length) return PM3_EWRONGANSWER;
    if (!has_le) {
        if (apdu_len >= 261) return PM3_EOVFLOW;
        apdu_len++;
    }
    apdu[apdu_len - 1] = (uint8_t)*sw;
    ret = gp_send_apdu(false, true, apdu, apdu_len, response, capacity, length, sw, verbose);
    if (!ret && (*sw & 0xff00) == 0x6c00) return PM3_EWRONGANSWER;
    return ret;
}

static int gp_plain_apdu(bool activate, bool leave_on,
                         uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                         const uint8_t *data, size_t data_len, bool include_le, uint16_t le,
                         uint8_t *resp, size_t resp_buf_len, size_t *resp_len,
                         uint16_t *sw, bool verbose) {
    if ((data == NULL && data_len != 0) || resp == NULL || resp_len == NULL || sw == NULL ||
        resp_buf_len < 2 || data_len > GP_MAX_SHORT_APDU_DATA || (include_le && (le == 0 || le > 0x100))) {
        PrintAndLogEx(ERR, "Only valid short APDUs are supported");
        return PM3_EINVARG;
    }

    uint8_t apdu[5 + GP_MAX_SHORT_APDU_DATA + 1];
    size_t apdu_len = 0;
    apdu[apdu_len++] = cla;
    apdu[apdu_len++] = ins;
    apdu[apdu_len++] = p1;
    apdu[apdu_len++] = p2;
    if (data_len > 0) {
        apdu[apdu_len++] = (uint8_t)data_len;
        memcpy(apdu + apdu_len, data, data_len);
        apdu_len += data_len;
    }
    if (include_le) apdu[apdu_len++] = le == 0x100 ? 0x00 : (uint8_t)le;

    if (verbose) PrintAndLogEx(INFO, ">>> %s", sprint_hex_inrow(apdu, apdu_len));
    // Wrong-Le recovery is limited to unprotected APDUs.
    int ret = gp_plain_command(activate, apdu, apdu_len, include_le,
                                resp, resp_buf_len, resp_len, sw, verbose);
    if (ret != PM3_SUCCESS) goto failure;

    // Collect ordinary 61xx response chaining with GET RESPONSE. The command
    // response is accumulated without the intermediate status words.
    size_t total = *resp_len;
    unsigned continuations = 0;
    while ((*sw & 0xFF00) == 0x6100) {
        if (++continuations > 32) { ret = PM3_EOVFLOW; goto failure; }
        uint16_t next_le = (*sw & 0xFF) == 0 ? 0x100 : (*sw & 0xFF);
        uint8_t get_response[5] = {
            (uint8_t)(cla & 0x03), 0xC0, 0x00, 0x00,
            next_le == 0x100 ? 0x00 : (uint8_t)next_le
        };
        if (verbose) PrintAndLogEx(INFO, ">>> %s", sprint_hex_inrow(get_response, sizeof(get_response)));
        size_t part_len = 0;
        if (total > resp_buf_len - 2) { ret = PM3_EOVFLOW; goto failure; }
        ret = gp_plain_command(false, get_response, sizeof(get_response), true,
                           resp + total, resp_buf_len - total, &part_len, sw, verbose);
        if (ret != PM3_SUCCESS) goto failure;
        if (part_len > resp_buf_len - total) { ret = PM3_EOVFLOW; goto failure; }
        total += part_len;
    }
    *resp_len = total;
    if (!leave_on) gp_drop_field();
    return PM3_SUCCESS;
failure:
    *resp_len = 0;
    gp_drop_field();
    return ret;
}


// Wrap + send via the active session (SCP01/SCP02/SCP03)
// If R-MAC is expected (SL & 0x10), verifies and strips the 8-byte R-MAC.
static int gp_wrapped_apdu(bool activate, bool leave_on,
                           uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                           const uint8_t *data, size_t data_len, bool include_le, uint16_t le,
                           uint8_t *resp, size_t resp_buf_len, size_t *resp_len,
                           uint16_t *sw, bool verbose) {
    if (!gp_ctx.active) {
        PrintAndLogEx(ERR, "No secure-channel session is open; run 'hf javacard auth'");
        return PM3_EINVARG;
    }
    if (activate) {
        PrintAndLogEx(ERR, "A wrapped command cannot reactivate the RF field");
        return PM3_EINVARG;
    }
    if ((data == NULL && data_len != 0) || data_len > GP_MAX_SHORT_APDU_DATA ||
        (include_le && (le == 0 || le > 0x100)) ||
        resp == NULL || resp_len == NULL || sw == NULL)
        return PM3_EINVARG;

    // An authenticated session may explicitly select NO_SECURITY. In that case
    // transmit the command as a plain APDU instead of appending a bogus MAC.
    if (gp_ctx.security_level == GP_SL_NO_SECURITY) {
        return gp_plain_apdu(false, leave_on, cla, ins, p1, p2, data, data_len,
                             include_le, le, resp, resp_buf_len, resp_len, sw, verbose);
    }

    uint8_t wrapped[GP_MAX_WRAPPED_APDU];
    size_t wrapped_len = 0;
    int ret = gp_ctx.scp_version == 3
        ? gp_scp03_wrap(cla, ins, p1, p2, data, data_len, wrapped, &wrapped_len)
        : gp_scp02_wrap(cla, ins, p1, p2, data, data_len, wrapped, &wrapped_len);
    if (ret != PM3_SUCCESS) { gp_drop_field(); return ret; }

    if (include_le) {
        if (wrapped_len >= sizeof(wrapped)) { gp_drop_field(); return PM3_EINVARG; }
        wrapped[wrapped_len++] = le == 0x100 ? 0x00 : (uint8_t)le;
    }
    if (verbose) PrintAndLogEx(INFO, ">>> %s", sprint_hex_inrow(wrapped, wrapped_len));

    // Keep the session until response authentication/decryption is complete.
    ret = gp_send_apdu(false, true, wrapped, wrapped_len,
                       resp, resp_buf_len, resp_len, sw, verbose);
    if (ret != PM3_SUCCESS) return ret;

    const bool protected_status = gp_sw_is_success_or_warning(*sw);
    // SCP02 explicit R-MAC covers error responses too (Li=0 plus SW1/SW2).
    // SCP03 response protection is present only on successful/warning responses.
    const bool response_requires_rmac = gp_ctx.active &&
        (gp_ctx.security_level & GP_SL_R_MAC) &&
        (gp_ctx.scp_version == 2 || protected_status);
    if (response_requires_rmac) {
        size_t mac_len = gp_ctx.scp_version == 3 ? gp_ctx.mac_len : 8;
        if (*resp_len < mac_len) {
            PrintAndLogEx(ERR, "R-MAC expected but response is too short");
            gp_drop_field();
            return PM3_ESOFT;
        }

        bool ok = gp_ctx.scp_version == 3
            ? gp_scp03_verify_rmac(resp, *resp_len, (uint8_t)(*sw >> 8), (uint8_t)*sw)
            : gp_scp02_verify_rmac(resp, *resp_len, (uint8_t)(*sw >> 8), (uint8_t)*sw);
        if (!ok) {
            PrintAndLogEx(ERR, "R-MAC verification " _RED_("FAILED") " -- session invalidated");
            gp_drop_field();
            return PM3_ESOFT;
        }
        *resp_len -= mac_len;
        if (verbose) PrintAndLogEx(SUCCESS, "  R-MAC " _GREEN_("verified"));
    } else if (gp_ctx.scp_version == 2) {
        gp_secure_zero(gp_ctx.rmac_context, sizeof(gp_ctx.rmac_context));
        gp_ctx.rmac_context_len = 0;
    }

    if (gp_ctx.active && gp_ctx.scp_version == 3 &&
        (gp_ctx.security_level & 0x20) && protected_status && *resp_len > 0) {
        ret = gp_scp03_decrypt_response(resp, resp_len);
        if (ret != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "SCP03 response decryption/padding failed; session invalidated");
            gp_drop_field();
            return ret;
        }
    }

    if (!leave_on) gp_drop_field();
    return PM3_SUCCESS;
}


//=============================================================================
// BER-TLV helpers
//=============================================================================

static int gp_ber_read_length(const uint8_t *buf, size_t buf_len,
                              size_t *offset, size_t *value_len) {
    if (buf == NULL || offset == NULL || value_len == NULL || *offset >= buf_len)
        return PM3_EINVARG;

    uint8_t first = buf[(*offset)++];
    if ((first & 0x80) == 0) {
        *value_len = first;
        return PM3_SUCCESS;
    }

    size_t n = first & 0x7F;
    if (n == 0 || n > sizeof(size_t) || n > 4 || *offset + n > buf_len)
        return PM3_ESOFT;

    size_t value = 0;
    if (n > 1 && buf[*offset] == 0x00) return PM3_ESOFT;  // non-minimal
    for (size_t i = 0; i < n; i++) {
        if (value > (SIZE_MAX >> 8)) return PM3_ESOFT;
        value = (value << 8) | buf[(*offset)++];
    }
    if (value < 0x80) return PM3_ESOFT;  // non-minimal long form
    *value_len = value;
    return PM3_SUCCESS;
}

static int gp_ber_read_tlv(const uint8_t *buf, size_t buf_len, size_t *offset,
                           uint32_t *tag, const uint8_t **value, size_t *value_len) {
    if (buf == NULL || offset == NULL || tag == NULL || value == NULL ||
        value_len == NULL || *offset >= buf_len)
        return PM3_EINVARG;

    size_t pos = *offset;
    uint8_t first = buf[pos++];
    uint32_t parsed_tag = first;
    if ((first & 0x1F) == 0x1F) {
        size_t tag_octets = 1;
        bool terminated = false;
        do {
            if (pos >= buf_len || tag_octets >= 4) return PM3_ESOFT;
            uint8_t b = buf[pos++];
            if (tag_octets == 1 && (b & 0x7F) == 0) return PM3_ESOFT;
            parsed_tag = (parsed_tag << 8) | b;
            tag_octets++;
            terminated = (b & 0x80) == 0;
        } while (!terminated);
    }

    size_t len = 0;
    if (gp_ber_read_length(buf, buf_len, &pos, &len) != PM3_SUCCESS ||
        len > buf_len - pos)
        return PM3_ESOFT;

    *tag = parsed_tag;
    *value = buf + pos;
    *value_len = len;
    *offset = pos + len;
    return PM3_SUCCESS;
}

static size_t gp_ber_length_size(size_t len) {
    if (len < 0x80) return 1;
    if (len <= 0xFF) return 2;
    if (len <= 0xFFFF) return 3;
    return 0;
}

static int gp_ber_write_length(uint8_t *out, size_t out_size,
                               size_t len, size_t *written) {
    if (out == NULL || written == NULL) return PM3_EINVARG;
    size_t need = gp_ber_length_size(len);
    if (need == 0 || out_size < need) return PM3_EINVARG;
    if (need == 1) {
        out[0] = (uint8_t)len;
    } else if (need == 2) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
    } else {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)len;
    }
    *written = need;
    return PM3_SUCCESS;
}

//=============================================================================
// Pretty-print helpers
//=============================================================================

static const char *gp_lcs_app_str(uint8_t lcs) {
    switch (lcs & 0xFF) {
        case 0x01: return "Installed";
        case 0x03: return "Installed";
        case 0x07: return "Selectable";
        case 0x0F: return "Personalized";
        case 0x83: return "Blocked";
        case 0x87: return "Locked";
        default:
            if (lcs & 0x80) return "Locked";
            if (lcs >= 0x07 && lcs <= 0x7F) return "App-specific";
            return "Unknown";
    }
}

static const char *gp_lcs_isd_str(uint8_t lcs) {
    switch (lcs) {
        case 0x01: return "OP READY";
        case 0x07: return "Initialized";
        case 0x0F: return "Secured";
        case 0x7F: return "Card Locked";
        case 0xFF: return "Terminated";
        default:   return "Unknown";
    }
}

static const char *gp_lcs_pkg_str(uint8_t lcs) {
    return ((lcs & 0x0F) == 0x01) ? "Loaded" : "Unknown";
}

// Decode GP privilege byte(s) to a human-readable string.
// GP Card Spec v2.3.1 §11.1.2 — Privileges are 1–3 bytes (byte 1 always present).
static const char *gp_priv_str(const uint8_t *privs, size_t privs_len) {
    static char buf[256];
    if (!privs || privs_len == 0) return "none";
    buf[0] = '\0';

    // Byte 1 (most common)
    uint8_t b1 = privs[0];
    if (b1 & 0x80) strncat(buf, "SecurityDomain ", sizeof(buf) - strlen(buf) - 1);
    if (b1 & 0x40) strncat(buf, "DAPVerification ", sizeof(buf) - strlen(buf) - 1);
    if (b1 & 0x20) strncat(buf, "DelegatedMgmt ", sizeof(buf) - strlen(buf) - 1);
    if (b1 & 0x10) strncat(buf, "CardLock ", sizeof(buf) - strlen(buf) - 1);
    if (b1 & 0x08) strncat(buf, "CardTerminate ", sizeof(buf) - strlen(buf) - 1);
    if (b1 & 0x04) strncat(buf, "CardReset ", sizeof(buf) - strlen(buf) - 1);
    if (b1 & 0x02) strncat(buf, "CVMMgmt ", sizeof(buf) - strlen(buf) - 1);
    if (b1 & 0x01) strncat(buf, "MandatedDAP ", sizeof(buf) - strlen(buf) - 1);

    // Byte 2 (optional)
    if (privs_len >= 2) {
        uint8_t b2 = privs[1];
        if (b2 & 0x80) strncat(buf, "TrustedPath ", sizeof(buf) - strlen(buf) - 1);
        if (b2 & 0x40) strncat(buf, "AuthorizedMgmt ", sizeof(buf) - strlen(buf) - 1);
        if (b2 & 0x20) strncat(buf, "TokenVerification ", sizeof(buf) - strlen(buf) - 1);
        if (b2 & 0x10) strncat(buf, "GlobalDelete ", sizeof(buf) - strlen(buf) - 1);
        if (b2 & 0x08) strncat(buf, "GlobalLock ", sizeof(buf) - strlen(buf) - 1);
        if (b2 & 0x04) strncat(buf, "GlobalRegistry ", sizeof(buf) - strlen(buf) - 1);
        if (b2 & 0x02) strncat(buf, "FinalApplication ", sizeof(buf) - strlen(buf) - 1);
        if (b2 & 0x01) strncat(buf, "GlobalService ", sizeof(buf) - strlen(buf) - 1);
    }

    // Byte 3 (optional)
    if (privs_len >= 3) {
        uint8_t b3 = privs[2];
        if (b3 & 0x80) strncat(buf, "ReceiptGeneration ", sizeof(buf) - strlen(buf) - 1);
        if (b3 & 0x40) strncat(buf, "CipheredLoadFileDataBlock ", sizeof(buf) - strlen(buf) - 1);
        if (b3 & 0x20) strncat(buf, "ContactlessActivation ", sizeof(buf) - strlen(buf) - 1);
        if (b3 & 0x10) strncat(buf, "ContactlessSelfActivation ", sizeof(buf) - strlen(buf) - 1);
    }

    if (buf[0] == '\0') {
        snprintf(buf, sizeof(buf), "none");
    } else {
        // Trim trailing space
        size_t slen = strlen(buf);
        if (slen > 0 && buf[slen - 1] == ' ') buf[slen - 1] = '\0';
    }
    return buf;
}

// GlobalPlatform Card Specification v2.3.1 Table 11-16: key type coding.
static const char *gp_key_type_name(uint8_t key_type) {
    switch (key_type) {
        case 0x80: return "DES/TDEA";
        case 0x81: return "TDEA (RFU)";
        case 0x82: return "TDEA-CBC";
        case 0x83: return "DES-ECB";
        case 0x84: return "DES-CBC";
        case 0x85: return "TLS PSK";
        case 0x88: return "AES";
        case 0x90: return "HMAC-SHA1";
        case 0x91: return "HMAC-SHA1-160";
        case 0xA0: return "RSA public e";
        case 0xA1: return "RSA public N";
        case 0xA2: return "RSA private N";
        case 0xA3: return "RSA private d";
        case 0xA4: return "RSA CRT P";
        case 0xA5: return "RSA CRT Q";
        case 0xA6: return "RSA CRT PQ";
        case 0xA7: return "RSA CRT DP1";
        case 0xA8: return "RSA CRT DQ1";
        case 0xB0: return "ECC public";
        case 0xB1: return "ECC private";
        case 0xB2: return "ECC field P";
        case 0xB3: return "ECC field A";
        case 0xB4: return "ECC field B";
        case 0xB5: return "ECC field G";
        case 0xB6: return "ECC field N";
        case 0xB7: return "ECC field k";
        case 0xF0: return "ECC params ref";
        case 0xFF: return "Extended format";
        default:   return "Unknown";
    }
}

// Print a Key Information Template (tag E0, or its bare C0 entries).
// Each C0 value is: KID || KVN || { key type || key length } ... (basic format)
// or KID || KVN || FF || type(2) || length(2) ... (extended format, shown raw).
// Returns the number of printed entries, or -1 when the template is malformed.
static int gp_print_key_info_template(const uint8_t *data, size_t length,
                                      int kvn_filter, int kid_filter) {
    if (data == NULL) return -1;
    const uint8_t *body = data;
    size_t body_len = length;
    if (length > 0 && data[0] == 0xE0) {
        size_t outer = 0;
        uint32_t tag = 0;
        if (gp_ber_read_tlv(data, length, &outer, &tag, &body, &body_len) != PM3_SUCCESS ||
            tag != 0xE0 || outer != length)
            return -1;
    }

    PrintAndLogEx(INFO, "  KID  KVN  Component(s)");
    PrintAndLogEx(INFO, "  ---  ---  ------------------------------------------");
    int printed = 0;
    size_t offset = 0;
    while (offset < body_len) {
        uint32_t tag = 0;
        const uint8_t *value = NULL;
        size_t value_len = 0;
        if (gp_ber_read_tlv(body, body_len, &offset, &tag, &value, &value_len) != PM3_SUCCESS)
            return -1;
        if (tag != 0xC0) continue;
        if (value_len < 4) {
            PrintAndLogEx(WARNING, "  Ignoring short C0 entry: %s", sprint_hex_inrow(value, value_len));
            continue;
        }
        uint8_t kid = value[0], kvn = value[1];
        if ((kvn_filter > 0 && kvn != (uint8_t)kvn_filter) ||
            (kid_filter > 0 && kid != (uint8_t)kid_filter))
            continue;

        char components[160] = {0};
        size_t used = 0;
        if (value[2] == 0xFF) {
            snprintf(components, sizeof(components), "extended: %s",
                     sprint_hex_inrow(value + 2, value_len - 2));
        } else {
            for (size_t pos = 2; pos + 1 < value_len && used < sizeof(components); pos += 2) {
                int n = snprintf(components + used, sizeof(components) - used, "%s%s/%u",
                                 used ? ", " : "", gp_key_type_name(value[pos]), value[pos + 1]);
                if (n < 0) break;
                used += (size_t)n;
            }
            if ((value_len - 2) % 2)
                PrintAndLogEx(WARNING, "  C0 entry KID %02X has a dangling byte", kid);
        }
        PrintAndLogEx(INFO, "  " _YELLOW_("%02X") "   " _YELLOW_("%02X") "   %s", kid, kvn, components);
        printed++;
    }
    return printed;
}

static void gp_print_one_registry_entry(json_t *aidroot, const uint8_t *aid, size_t aid_len,
                                        uint8_t lcs, const uint8_t *privs, size_t privs_len,
                                        uint8_t p1) {
    const char *lcs_str = (p1 == GP_STATUS_ISD) ? gp_lcs_isd_str(lcs)
                        : (p1 == GP_STATUS_LOAD_FILES || p1 == GP_STATUS_LOAD_FILES_MODS)
                          ? gp_lcs_pkg_str(lcs) : gp_lcs_app_str(lcs);

    // sprint_hex_inrow uses a single static buffer: copy the AID text first.
    char aid_hex[65] = {0};
    snprintf(aid_hex, sizeof(aid_hex), "%s", sprint_hex_inrow(aid, aid_len));

    if (p1 == GP_STATUS_LOAD_FILES || p1 == GP_STATUS_LOAD_FILES_MODS) {
        // Load files carry no privileges; only print them when the card sends some.
        PrintAndLogEx(INFO, "  AID " _GREEN_("%-32s") " LCS: " _YELLOW_("%02X") " %-12s%s%s",
                      aid_hex, lcs, lcs_str, privs_len ? " Privs: " : "",
                      privs_len ? gp_priv_str(privs, privs_len) : "");
    } else {
        PrintAndLogEx(INFO, "  AID " _GREEN_("%-32s") " LCS: " _YELLOW_("%02X") " %-12s Privs: %s",
                      aid_hex, lcs, lcs_str, gp_priv_str(privs, privs_len));
    }

    // Prefer the full aidlist.json description; the compact local table is the
    // fallback when the resource file is unavailable.
    if (aidroot != NULL && aid_len > 0) {
        uint8_t aid_copy[16];
        size_t aid_copy_len = aid_len > sizeof(aid_copy) ? sizeof(aid_copy) : aid_len;
        memcpy(aid_copy, aid, aid_copy_len);
        PrintAIDDescriptionBuf(aidroot, aid_copy, aid_copy_len, false);
    } else {
        const char *local_name = gp_known_aid_name(aid, aid_len);
        if (local_name) PrintAndLogEx(INFO, "      " _CYAN_("%s"), local_name);
    }
}

static void gp_print_status_legacy_response(json_t *aidroot, const uint8_t *data, size_t len, uint8_t p1) {
    if (data == NULL) return;
    size_t offset = 0;
    while (offset < len) {
        size_t entry_start = offset;
        uint8_t aid_len = data[offset++];
        if (aid_len < 5 || aid_len > 16 || aid_len > len - offset ||
            len - offset - aid_len < 2) {
            PrintAndLogEx(WARNING, "  Malformed legacy GET STATUS entry at offset %zu", entry_start);
            return;
        }

        const uint8_t *aid = data + offset;
        offset += aid_len;
        uint8_t lcs = data[offset++];
        uint8_t privilege = data[offset++];
        gp_print_one_registry_entry(aidroot, aid, aid_len, lcs, &privilege, 1, p1);

        if (p1 == GP_STATUS_LOAD_FILES_MODS) {
            if (offset >= len) {
                PrintAndLogEx(WARNING, "  Missing module count at offset %zu", offset);
                return;
            }
            uint8_t module_count = data[offset++];
            for (uint8_t i = 0; i < module_count; i++) {
                if (offset >= len) {
                    PrintAndLogEx(WARNING, "  Missing module AID length at offset %zu", offset);
                    return;
                }
                uint8_t module_len = data[offset++];
                if (module_len < 5 || module_len > 16 || module_len > len - offset) {
                    PrintAndLogEx(WARNING, "  Malformed module AID at offset %zu", offset - 1);
                    return;
                }
                PrintAndLogEx(INFO, "      Module: %s",
                              sprint_hex_inrow(data + offset, module_len));
                offset += module_len;
            }
        }
    }
}



// Parse and print GET STATUS response with AID name lookup.
static void gp_print_status_response(const uint8_t *data, size_t len, uint8_t p1) {
    if (data == NULL || len == 0) return;
    // Load the AID dictionary once per listing instead of once per entry.
    json_t *aidroot = AIDSearchInit(false);
    if (data[0] != 0xE3) {
        gp_print_status_legacy_response(aidroot, data, len, p1);
        if (aidroot) AIDSearchFree(aidroot);
        return;
    }

    size_t offset = 0;
    while (offset < len) {
        size_t record_start = offset;
        uint32_t outer_tag = 0;
        const uint8_t *entry = NULL;
        size_t entry_len = 0;
        if (gp_ber_read_tlv(data, len, &offset, &outer_tag, &entry, &entry_len) != PM3_SUCCESS ||
            outer_tag != 0xE3) {
            PrintAndLogEx(WARNING, "  Malformed tagged GET STATUS record at offset %zu", record_start);
            break;
        }

        const uint8_t *aid = NULL;
        size_t aid_len = 0;
        uint8_t lcs = 0xFF;
        const uint8_t *privs = NULL;
        size_t privs_len = 0;
        const uint8_t *version = NULL;
        size_t version_len = 0;
        const uint8_t *assoc_sd = NULL;
        size_t assoc_sd_len = 0;
        // Executable Module AIDs (tag 84) belong to this record and are printed
        // after its AID line.
        const uint8_t *modules[32];
        size_t module_lens[32];
        size_t module_count = 0;

        size_t entry_offset = 0;
        while (entry_offset < entry_len) {
            uint32_t tag = 0;
            const uint8_t *value = NULL;
            size_t value_len = 0;
            size_t field_start = entry_offset;
            if (gp_ber_read_tlv(entry, entry_len, &entry_offset,
                                &tag, &value, &value_len) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "    Malformed field at entry offset %zu", field_start);
                break;
            }

            switch (tag) {
                case 0x4F:
                    if (value_len >= 5 && value_len <= 16) {
                        aid = value;
                        aid_len = value_len;
                    } else {
                        PrintAndLogEx(WARNING, "    Invalid AID length %zu", value_len);
                    }
                    break;
                case 0x9F70:
                    if (value_len == 1) lcs = value[0];
                    else PrintAndLogEx(WARNING, "    Invalid life-cycle-state length %zu", value_len);
                    break;
                case 0xC5:
                    if (value_len >= 1 && value_len <= 3) {
                        privs = value;
                        privs_len = value_len;
                    } else if (value_len != 0) {
                        PrintAndLogEx(WARNING, "    Unsupported privilege length %zu", value_len);
                    }
                    break;
                case 0x84:  // Executable Module AID
                    if (value_len >= 5 && value_len <= 16 && module_count < ARRAYLEN(modules)) {
                        modules[module_count] = value;
                        module_lens[module_count++] = value_len;
                    }
                    break;
                case 0xCC:  // Associated Security Domain AID
                    if (value_len >= 5 && value_len <= 16) {
                        assoc_sd = value;
                        assoc_sd_len = value_len;
                    }
                    break;
                case 0xCE:  // Executable Load File version number
                    version = value;
                    version_len = value_len;
                    break;
                default:
                    break;
            }
        }

        if (aid == NULL) {
            PrintAndLogEx(WARNING, "  GET STATUS record at offset %zu has no valid AID", record_start);
            continue;
        }
        gp_print_one_registry_entry(aidroot, aid, aid_len, lcs, privs, privs_len, p1);
        if (version_len > 0)
            PrintAndLogEx(INFO, "      Version: %s", sprint_hex_inrow(version, version_len));
        if (assoc_sd_len > 0 && !(aid_len == assoc_sd_len && memcmp(aid, assoc_sd, aid_len) == 0))
            PrintAndLogEx(INFO, "      Associated SD: %s", sprint_hex_inrow(assoc_sd, assoc_sd_len));
        for (size_t m = 0; m < module_count; m++)
            PrintAndLogEx(INFO, "      Module: %s", sprint_hex_inrow(modules[m], module_lens[m]));
    }
    if (aidroot) AIDSearchFree(aidroot);
}



// Decode a 2-byte CPLC date field (YDDD BCD: 1 year digit + 3 Julian day digits).
// Returns a static string like "Y3 / Day 123" or "0000" for unset.
static const char *gp_decode_cplc_date(const uint8_t *d) {
    static char buf[48];
    if (d == NULL || (d[0] == 0x00 && d[1] == 0x00) ||
        (d[0] == 0xFF && d[1] == 0xFF))
        return "not set";

    int n0 = (d[0] >> 4) & 0x0F;
    int n1 = d[0] & 0x0F;
    int n2 = (d[1] >> 4) & 0x0F;
    int n3 = d[1] & 0x0F;
    if (n0 > 9 || n1 > 9 || n2 > 9 || n3 > 9) return "invalid BCD";
    int day = n1 * 100 + n2 * 10 + n3;
    if (day < 1 || day > 366) return "invalid day";
    snprintf(buf, sizeof(buf), "year ending in %d, ordinal day %03d", n0, day);
    return buf;
}


static void gp_print_cplc(const uint8_t *cplc, size_t len) {
    if (len < 42) { PrintAndLogEx(WARNING, "CPLC too short (%zu bytes)", len); return; }
    uint16_t fab_id = (uint16_t)(((uint16_t)cplc[0] << 8) | cplc[1]);
    const char *fab_name = gp_ic_fabricator_name(fab_id);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "  %-30s| %-14s| %s", "Field", "Value", "Decoded");
    PrintAndLogEx(INFO, "  ------------------------------|---------------|------------------------------");
#define GP_CPLC_ROW2(label, off) \
    PrintAndLogEx(INFO, "  %-30s| " _YELLOW_("%-14s") "| ", (label), sprint_hex_inrow_spaces(cplc + (off), 2, 1))
#define GP_CPLC_ROW4(label, off) \
    PrintAndLogEx(INFO, "  %-30s| " _YELLOW_("%-14s") "| ", (label), sprint_hex_inrow_spaces(cplc + (off), 4, 1))
#define GP_CPLC_DATE(label, off) \
    PrintAndLogEx(INFO, "  %-30s| " _YELLOW_("%-14s") "| %s", (label), \
                  sprint_hex_inrow_spaces(cplc + (off), 2, 1), gp_decode_cplc_date(cplc + (off)))
    if (fab_name)
        PrintAndLogEx(INFO, "  %-30s| " _YELLOW_("%-14s") "| %s", "IC Fabricator",
                      sprint_hex_inrow_spaces(cplc + 0, 2, 1), fab_name);
    else
        GP_CPLC_ROW2("IC Fabricator",            0);
    GP_CPLC_ROW2("IC Type",                  2);
    GP_CPLC_ROW2("OS ID",                    4);
    GP_CPLC_DATE("OS Date",                  6);
    GP_CPLC_ROW2("OS Level",                 8);
    GP_CPLC_DATE("Card Fabrication Date",   10);
    GP_CPLC_ROW4("IC Serial Number",        12);
    GP_CPLC_ROW2("IC Batch ID",             16);
    GP_CPLC_ROW2("IC Module Fabricator",    18);
    GP_CPLC_DATE("IC Module Package Date",  20);
    GP_CPLC_ROW2("ICC Manufacturer",        22);
    GP_CPLC_DATE("IC Embedding Date",       24);
    GP_CPLC_ROW2("Pre-personalizer",        26);
    GP_CPLC_DATE("IC Pre-pers. Date",       28);
    GP_CPLC_ROW4("IC Pre-pers. Equipment",  30);
    GP_CPLC_ROW2("Personalizer",            34);
    GP_CPLC_DATE("IC Personalization Date", 36);
    GP_CPLC_ROW4("IC Perso. Equipment",     38);
    PrintAndLogEx(INFO, "  ------------------------------|---------------|------------------------------");
#undef GP_CPLC_ROW2
#undef GP_CPLC_ROW4
#undef GP_CPLC_DATE
}

//=============================================================================
// Card fingerprinting (CPLC fabricator + IC type -> cmdhfjavacard_db.h)
//=============================================================================

// Historical bytes of the last ATS (ISO/IEC 14443-4 5.2.7): after TL, T0 and
// the interface bytes T0 announces, up to TL (the CRC is not part of TL).
static bool gp_ats_historical(const uint8_t **hist, size_t *hist_len) {
    *hist = NULL;
    *hist_len = 0;
    if (gp_link.ats_len < 2) return false;
    size_t tl = gp_link.ats[0];
    if (tl < 2 || tl > gp_link.ats_len) return false;
    uint8_t t0 = gp_link.ats[1];
    size_t pos = 2 + ((t0 & 0x10) != 0) + ((t0 & 0x20) != 0) + ((t0 & 0x40) != 0);
    if (pos >= tl) return false;
    *hist = gp_link.ats + pos;
    *hist_len = tl - pos;
    return true;
}

static const char *gp_sig_confidence(uint8_t match) {
    if (match == GP_SIG_FULL) return _GREEN_("exact") " (IC type, OS ID, OS release)";
    if (match == GP_SIG_CHIP_OS) return _GREEN_("strong") " (IC type, OS ID)";
    if (match & GP_SIG_IC) return _YELLOW_("partial") " (IC type only)";
    return _YELLOW_("weak") " (fabricator only)";
}

// Combine every identifier into one verdict: CPLC IC fabricator/type, OS ID
// and OS release (JCAlgTest signatures), plus the ATS historical bytes.
static void gp_print_identification(const uint8_t *cplc, size_t cplc_len) {
    const gp_card_signature_t *sig = NULL;
    uint16_t fab = 0, ic = 0, os = 0, os_date = 0, os_level = 0;
    bool have_cplc = cplc != NULL && cplc_len >= 10;
    if (have_cplc) {
        fab = (uint16_t)((cplc[0] << 8) | cplc[1]);
        ic = (uint16_t)((cplc[2] << 8) | cplc[3]);
        os = (uint16_t)((cplc[4] << 8) | cplc[5]);
        os_date = (uint16_t)((cplc[6] << 8) | cplc[7]);
        os_level = (uint16_t)((cplc[8] << 8) | cplc[9]);
        sig = gp_card_signature_lookup(fab, ic, os, os_date, os_level);
        const char *fab_name = gp_ic_fabricator_name(fab);
        gp_print_kv("IC fabricator", _GREEN_("%s") " (%04X)", fab_name ? fab_name : "unknown", fab);
        gp_print_kv("CPLC signature", "IC %04X  OS %04X  release %04X/%04X", ic, os, os_date, os_level);
        if (sig != NULL) {
            gp_print_kv("Platform", _GREEN_("%s"), sig->platform);
            if (sig->notes) gp_print_kv("Products", "%s", sig->notes);
            gp_print_kv("Match", "%s", gp_sig_confidence(sig->match));
        } else {
            gp_print_kv("Platform", _YELLOW_("not in database"));
        }
        const char *os_name = gp_os_id_name(os);
        if (os_name != NULL && (sig == NULL || (sig->match & GP_SIG_OS) == 0))
            gp_print_kv("Card OS (from OS ID)", _GREEN_("%s"), os_name);
    }

    const uint8_t *hist = NULL;
    size_t hist_len = 0;
    if (gp_ats_historical(&hist, &hist_len)) {
        char ascii[40] = {0};
        size_t printable = 0;
        for (size_t i = 0; i < hist_len && i < sizeof(ascii) - 1; i++) {
            bool p = hist[i] >= 0x20 && hist[i] < 0x7F;
            printable += p;
            ascii[i] = p ? (char)hist[i] : '.';
        }
        if (printable * 2 >= hist_len)
            gp_print_kv("ATS historical bytes", "%s  \"%s\"", sprint_hex_inrow(hist, hist_len), ascii);
        else
            gp_print_kv("ATS historical bytes", "%s", sprint_hex_inrow(hist, hist_len));
        const gp_hist_signature_t *hs = gp_hist_signature_lookup(hist, hist_len);
        if (hs != NULL) {
            gp_print_kv("ATS signature", "%s", hs->meaning);
            if (have_cplc && strncmp(hs->meaning, "NXP", 3) == 0 && fab != 0x4790)
                PrintAndLogEx(WARNING, "  ATS claims NXP but CPLC fabricator is %04X: customised ATS or emulated card", fab);
        }
    }
    if (!have_cplc && hist_len == 0)
        gp_print_kv("Platform", _YELLOW_("unknown") " (no CPLC, no ATS)");
    if (sig != NULL && sig->match < GP_SIG_FULL && have_cplc)
        PrintAndLogEx(HINT, "Hint: several products share this signature; free memory and the applets found by "
                      "`hf javacard scan` narrow it down");
}
//=============================================================================
// OID / Card Recognition Data decoding (GPC v2.3.1 Annex H)
//=============================================================================

#define GP_OID_MAX_ARCS 24

// Decode a BER-encoded OBJECT IDENTIFIER value into numeric arcs.
static bool gp_oid_arcs(const uint8_t *oid, size_t len, uint32_t *arcs,
                        size_t capacity, size_t *count) {
    if (oid == NULL || arcs == NULL || count == NULL || len == 0 || capacity < 2)
        return false;
    *count = 0;
    uint64_t value = 0;
    bool first = true;
    for (size_t i = 0; i < len; i++) {
        if (value == 0 && oid[i] == 0x80) return false;        // non-minimal arc
        value = (value << 7) | (oid[i] & 0x7F);
        if (value > UINT32_MAX) return false;
        if (oid[i] & 0x80) continue;
        if (first) {
            uint32_t x = value < 40 ? 0 : value < 80 ? 1 : 2;
            arcs[(*count)++] = x;
            arcs[(*count)++] = (uint32_t)(value - 40U * x);
            first = false;
        } else {
            if (*count >= capacity) return false;
            arcs[(*count)++] = (uint32_t)value;
        }
        value = 0;
    }
    return (oid[len - 1] & 0x80) == 0;
}

static void gp_oid_arcs_text(const uint32_t *arcs, size_t from, size_t count,
                             char *out, size_t out_size) {
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = from; i < count && used < out_size; i++) {
        int n = snprintf(out + used, out_size - used, "%s%u", i == from ? "" : ".", arcs[i]);
        if (n < 0) break;
        used += (size_t)n;
    }
}

// Human-readable OID: numeric form plus a GlobalPlatform / Java Card meaning.
// Returns a static buffer (not re-entrant).
static const char *gp_decode_oid_string(const uint8_t *oid, size_t len) {
    static char buf[256];
    uint32_t arcs[GP_OID_MAX_ARCS];
    size_t count = 0;
    if (!gp_oid_arcs(oid, len, arcs, ARRAYLEN(arcs), &count)) {
        snprintf(buf, sizeof(buf), "(invalid OID %s)", sprint_hex_inrow(oid, len));
        return buf;
    }

    char numeric[160];
    gp_oid_arcs_text(arcs, 0, count, numeric, sizeof(numeric));

    // GlobalPlatform: {iso(1) member-body(2) us(840) 114283}
    static const uint32_t gp_prefix[] = {1, 2, 840, 114283};
    // Java Card: {iso(1) org(3) dod(6) internet(1) private(4) enterprise(1) sun(42) 2 110}
    static const uint32_t jc_prefix[] = {1, 3, 6, 1, 4, 1, 42, 2, 110};
    char tail[96] = {0};

    if (count > ARRAYLEN(gp_prefix) &&
        memcmp(arcs, gp_prefix, sizeof(gp_prefix)) == 0) {
        size_t k = ARRAYLEN(gp_prefix);
        uint32_t kind = arcs[k];
        gp_oid_arcs_text(arcs, k + 1, count, tail, sizeof(tail));
        switch (kind) {
            case 1:
                snprintf(buf, sizeof(buf), "GlobalPlatform Card Recognition Data [%s]", numeric);
                break;
            case 2:
                snprintf(buf, sizeof(buf), "GlobalPlatform %s [%s]", tail[0] ? tail : "(version?)", numeric);
                break;
            case 3:
                snprintf(buf, sizeof(buf), "GlobalPlatform card identification scheme [%s]", numeric);
                break;
            case 4:
                if (count >= k + 3)
                    snprintf(buf, sizeof(buf), "SCP%02X i=%02X [%s]", arcs[k + 1] & 0xFF, arcs[k + 2] & 0xFF, numeric);
                else
                    snprintf(buf, sizeof(buf), "Secure Channel Protocol %s [%s]", tail, numeric);
                break;
            case 5:
                snprintf(buf, sizeof(buf), "GlobalPlatform card configuration details %s [%s]",
                         tail[0] ? tail : "", numeric);
                break;
            default:
                snprintf(buf, sizeof(buf), "GlobalPlatform arc %u%s%s [%s]", kind,
                         tail[0] ? "." : "", tail, numeric);
                break;
        }
        return buf;
    }

    if (count > ARRAYLEN(jc_prefix) &&
        memcmp(arcs, jc_prefix, sizeof(jc_prefix)) == 0) {
        size_t k = ARRAYLEN(jc_prefix);
        gp_oid_arcs_text(arcs, k + 1, count, tail, sizeof(tail));
        if (arcs[k] == 1)
            snprintf(buf, sizeof(buf), "Java Card %s [%s]", tail[0] ? tail : "", numeric);
        else
            snprintf(buf, sizeof(buf), "Java Card arc %u%s%s [%s]", arcs[k],
                     tail[0] ? "." : "", tail, numeric);
        return buf;
    }

    snprintf(buf, sizeof(buf), "%s", numeric);
    return buf;
}

// Return the OID carried by an application-tagged Card Recognition Data entry
// (e.g. 64 <len> 06 <len> <oid>), or the bare value when it is not wrapped.
static bool gp_crd_inner_oid(const uint8_t *value, size_t value_len,
                             const uint8_t **oid, size_t *oid_len) {
    size_t offset = 0;
    uint32_t tag = 0;
    if (value_len > 0 && value[0] == 0x06 &&
        gp_ber_read_tlv(value, value_len, &offset, &tag, oid, oid_len) == PM3_SUCCESS &&
        tag == 0x06 && *oid_len > 0)
        return true;
    return false;
}

// Locate the Card Recognition Data body (the content of tag 73) inside a
// GET DATA 0066 response, which may or may not include the outer 66 tag.
static bool gp_crd_body(const uint8_t *buf, size_t len, const uint8_t **body, size_t *body_len) {
    const uint8_t *value = buf;
    size_t value_len = len;
    for (int depth = 0; depth < 2; depth++) {
        size_t offset = 0;
        uint32_t tag = 0;
        const uint8_t *inner = NULL;
        size_t inner_len = 0;
        if (value_len == 0 ||
            gp_ber_read_tlv(value, value_len, &offset, &tag, &inner, &inner_len) != PM3_SUCCESS)
            return false;
        if (tag == 0x73) {
            *body = inner;
            *body_len = inner_len;
            return true;
        }
        if (tag != 0x66) return false;
        value = inner;
        value_len = inner_len;
    }
    return false;
}

// Extract the advertised Secure Channel Protocol (tag 64, OID .4.<scp>.<i>).
static bool gp_crd_scp(const uint8_t *buf, size_t len, uint8_t *scp, uint8_t *scp_i) {
    const uint8_t *body = NULL;
    size_t body_len = 0;
    if (!gp_crd_body(buf, len, &body, &body_len)) return false;
    size_t offset = 0;
    while (offset < body_len) {
        uint32_t tag = 0;
        const uint8_t *value = NULL, *oid = NULL;
        size_t value_len = 0, oid_len = 0;
        if (gp_ber_read_tlv(body, body_len, &offset, &tag, &value, &value_len) != PM3_SUCCESS)
            return false;
        if (tag != 0x64 || !gp_crd_inner_oid(value, value_len, &oid, &oid_len)) continue;
        uint32_t arcs[GP_OID_MAX_ARCS];
        size_t count = 0;
        static const uint32_t prefix[] = {1, 2, 840, 114283, 4};
        if (gp_oid_arcs(oid, oid_len, arcs, ARRAYLEN(arcs), &count) && count >= 7 &&
            memcmp(arcs, prefix, sizeof(prefix)) == 0 && arcs[5] <= 0xFF && arcs[6] <= 0xFF) {
            *scp = (uint8_t)arcs[5];
            *scp_i = (uint8_t)arcs[6];
            return true;
        }
    }
    return false;
}

static void gp_decode_card_recognition_data(const uint8_t *buf, size_t len) {
    const uint8_t *body = NULL;
    size_t body_len = 0;
    if (buf == NULL || !gp_crd_body(buf, len, &body, &body_len)) {
        PrintAndLogEx(WARNING, "  Malformed Card Recognition Data: %s", sprint_hex_inrow(buf, len));
        return;
    }

    size_t offset = 0;
    while (offset < body_len) {
        uint32_t tag = 0;
        const uint8_t *value = NULL, *oid = NULL;
        size_t value_len = 0, oid_len = 0;
        if (gp_ber_read_tlv(body, body_len, &offset, &tag, &value, &value_len) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "  Malformed Card Recognition Data entry at offset %zu", offset);
            return;
        }

        const char *label;
        switch (tag) {
            case 0x06: label = "Recognition data OID"; break;
            case 0x60: label = "Card management type"; break;
            case 0x63: label = "Card identification"; break;
            case 0x64: label = "Secure channel"; break;
            case 0x65: label = "Card configuration"; break;
            case 0x66: label = "Card / chip details"; break;
            case 0x67: label = "ISD trust point cert."; break;
            case 0x68: label = "ISD certificate info"; break;
            default:   label = NULL; break;
        }

        if (tag == 0x06) {
            oid = value;
            oid_len = value_len;
        } else if (!gp_crd_inner_oid(value, value_len, &oid, &oid_len)) {
            oid = NULL;
        }

        char tag_label[32];
        if (label == NULL) {
            snprintf(tag_label, sizeof(tag_label), "Tag %X", (unsigned)tag);
            label = tag_label;
        }
        if (oid != NULL)
            gp_print_kv(label, _YELLOW_("%s"), gp_decode_oid_string(oid, oid_len));
        else
            gp_print_kv(label, "%s", sprint_hex_inrow(value, value_len));
    }
}

//=============================================================================
// SELECT ISD
//=============================================================================

static const char *gp_tlv_name(uint32_t tag) {
    switch (tag) {
        case 0x6f: return "File Control Information";
        case 0xa5: return "Proprietary FCI";
        case 0x84: case 0x4f: return "Application identifier";
        case 0x9f65: return "Maximum command data length";
        case 0x9f7f: return "Card Production Life Cycle data";
        case 0x9f70: return "Life cycle state";
        case 0x66: return "Card recognition data";
        case 0x67: return "Card capabilities";
        case 0x73: return "Security Domain management data";
        case 0xe0: return "Key information template";
        case 0xc0: return "Key information";
        case 0xe3: return "Registry entry";
        case 0xc4: return "Load file identifier";
        case 0xc5: return "Privileges";
        case 0xcc: return "Associated Security Domain";
        case 0xce: return "Version number";
        default: return "Data object";
    }
}

static void gp_print_tlv_cb(void *context, const struct tlv *t, int level, bool leaf) {
    (void)context;
    PrintAndLogEx(INFO, "%*s%s [%X, %zu bytes]%s%s", level * 4, "", gp_tlv_name(t->tag),
                  t->tag, t->len, leaf && t->len <= 24 ? ": " : "",
                  leaf && t->len <= 24 ? sprint_hex_inrow(t->value, t->len) : "");
    if (leaf && t->len > 24) print_buffer(t->value, t->len, level);
}

static bool gp_print_tlv(const uint8_t *data, size_t length) {
    struct tlvdb *db = tlvdb_parse_multi(data, length);
    if (!db) {
        PrintAndLogEx(WARNING, "Malformed GlobalPlatform BER-TLV data");
        return false;
    }
    tlvdb_visit(db, gp_print_tlv_cb, NULL, 0);
    tlvdb_free(db);
    return true;
}

typedef struct {
    uint8_t protocol;
    const uint8_t *options;
    size_t options_len;
    const uint8_t *keys;
    size_t keys_len;
} gp_scp_capability_t;

static bool gp_parse_scp_capability(const uint8_t *data, size_t length, gp_scp_capability_t *scp) {
    memset(scp, 0, sizeof(*scp));
    bool have_protocol = false, have_options = false, have_keys = false;
    size_t offset = 0;
    while (offset < length) {
        uint32_t tag;
        const uint8_t *value;
        size_t len;
        if (gp_ber_read_tlv(data, length, &offset, &tag, &value, &len)) return false;
        if (tag == 0x80) {
            if (have_protocol || len != 1) return false;
            scp->protocol = value[0];
            have_protocol = true;
        } else if (tag == 0x81) {
            if (have_options) return false;
            scp->options = value;
            scp->options_len = len;
            have_options = true;
        } else if (tag == 0x82) {
            if (have_keys || !len) return false;
            scp->keys = value;
            scp->keys_len = len;
            have_keys = true;
        }
    }
    return have_protocol && have_options;
}

static bool gp_print_capabilities(const uint8_t *data, size_t length) {
    if (!data || !length) return false;
    size_t offset = 0;
    uint32_t tag;
    const uint8_t *value;
    size_t len;
    if (data[0] == 0x67) {
        if (gp_ber_read_tlv(data, length, &offset, &tag, &value, &len) || offset != length)
            return false;
        data = value;
        length = len;
        offset = 0;
    }
    while (offset < length) {
        if (gp_ber_read_tlv(data, length, &offset, &tag, &value, &len)) {
            PrintAndLogEx(WARNING, "Malformed Card Capability Information");
            return false;
        }
        if (tag == 0xa0) {
            gp_scp_capability_t scp;
            if (!gp_parse_scp_capability(value, len, &scp)) {
                PrintAndLogEx(WARNING, "Malformed SCP capability template");
                return false;
            }
            char label[32];
            snprintf(label, sizeof(label), "SCP%02X options (i)", scp.protocol);
            gp_print_kv(label, _GREEN_("%s"), scp.options_len ? sprint_hex_inrow_spaces(scp.options, scp.options_len, 1)
                                                                  : "none listed");
            if (scp.protocol == 3 && scp.keys_len)
                gp_print_kv("SCP03 AES key sizes", "%s%s%s", scp.keys[0] & 1 ? "128 " : "",
                            scp.keys[0] & 2 ? "192 " : "", scp.keys[0] & 4 ? "256" : "");
        } else if (tag == 0x81 || tag == 0x82) {
            if (len != 3) return false;
            gp_print_kv(tag == 0x81 ? "SD privileges supported" : "App privileges supported", "%s",
                        gp_priv_str(value, len));
        } else {
            const char *name = tag == 0x83 ? "LFDB hash algorithms" :
                               tag == 0x84 ? "LFDB cipher suites" :
                               tag == 0x85 ? "Token cipher suites" :
                               tag == 0x86 ? "Receipt cipher suites" :
                               tag == 0x87 ? "DAP cipher suites" :
                               tag == 0x88 ? "Key parameter refs" : "Unknown capability";
            gp_print_kv(name, "%s [tag %X]", sprint_hex_inrow(value, len), tag);
        }
    }
    return true;
}

static int gp_select_isd(bool activate, bool leave_on, uint16_t *sw, bool verbose) {
    uint8_t resp[GP_RESP_BUF_SIZE];
    size_t resp_len = 0;

    int ret = gp_plain_apdu(activate, leave_on, 0x00, GP_INS_SELECT, 0x04, 0x00,
                             GP_ISD_AID, GP_ISD_AID_LEN, true, 0x100,
                             resp, sizeof(resp), &resp_len, sw, verbose);
    if (ret != PM3_SUCCESS) return ret;
    if (*sw == 0x9000 || (*sw & 0xFF00) == 0x6100) {
        if (verbose) {
            PrintAndLogEx(SUCCESS, "ISD selected (by explicit AID)");
            if (resp_len > 0) { PrintAndLogEx(INFO, "  FCI: %s", sprint_hex_inrow(resp, resp_len)); gp_print_tlv(resp, resp_len); }
        }
    } else if (*sw == 0x6A82) {
        uint8_t apdu[] = { 0x00, GP_INS_SELECT, 0x04, 0x00, 0x00 };
        if (verbose) PrintAndLogEx(INFO, ">>> %s", sprint_hex_inrow(apdu, sizeof(apdu)));
        ret = gp_send_apdu(activate, leave_on, apdu, sizeof(apdu), resp, sizeof(resp), &resp_len, sw, verbose);
        if (ret != PM3_SUCCESS) return ret;
        if (verbose && (*sw == 0x9000 || (*sw & 0xFF00) == 0x6100))
            PrintAndLogEx(SUCCESS, "ISD selected");
    }
    return PM3_SUCCESS;
}

//=============================================================================
// Command: hf javacard info
//=============================================================================

// Unwrap a single BER-TLV with the expected tag. When the card returned the
// bare value instead (some cards omit the tag in GET DATA responses), the
// whole buffer is returned unchanged.
static void gp_tlv_unwrap(const uint8_t *data, size_t length, uint32_t expected_tag,
                          const uint8_t **value, size_t *value_len) {
    size_t offset = 0;
    uint32_t tag = 0;
    const uint8_t *inner = NULL;
    size_t inner_len = 0;
    if (gp_ber_read_tlv(data, length, &offset, &tag, &inner, &inner_len) == PM3_SUCCESS &&
        tag == expected_tag && offset == length) {
        *value = inner;
        *value_len = inner_len;
    } else {
        *value = data;
        *value_len = length;
    }
}

static uint32_t gp_be_uint(const uint8_t *data, size_t length) {
    uint32_t value = 0;
    for (size_t i = 0; i < length && i < 4; i++) value = (value << 8) | data[i];
    return value;
}

// GET DATA on the currently selected Security Domain without secure messaging.
static bool gp_get_data_plain(uint8_t p1, uint8_t p2, uint8_t *resp, size_t resp_size,
                              size_t *resp_len, bool verbose) {
    uint16_t sw = 0;
    int ret = gp_plain_apdu(false, true, GP_CLA_PLAIN, GP_INS_GET_DATA, p1, p2,
                            NULL, 0, true, 0x100, resp, resp_size, resp_len, &sw, verbose);
    return ret == PM3_SUCCESS && sw == 0x9000 && *resp_len > 0;
}

// ---- Console layout helpers (house style of hf mfdes / hf 14a info) -------
#define GP_LABEL_WIDTH 26

static void gp_print_banner(const char *title) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--------------------- " _CYAN_("%s") " ---------------------", title);
}

static void gp_print_section(const char *title) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("%s"), title);
}

// Right-aligned "label: value" row.
static void gp_print_kv(const char *label, const char *format, ...) {
    char value[512];
    va_list args;
    va_start(args, format);
    vsnprintf(value, sizeof(value), format, args);
    va_end(args);
    PrintAndLogEx(INFO, "%*s: %s", GP_LABEL_WIDTH, label, value);
}

// Find the OID carried by a Card Recognition Data entry with the given tag.
static bool gp_crd_find_oid(const uint8_t *buf, size_t len, uint32_t want,
                            const uint8_t **oid, size_t *oid_len) {
    const uint8_t *body = NULL;
    size_t body_len = 0, offset = 0;
    if (!gp_crd_body(buf, len, &body, &body_len)) return false;
    while (offset < body_len) {
        uint32_t tag = 0;
        const uint8_t *value = NULL;
        size_t value_len = 0;
        if (gp_ber_read_tlv(body, body_len, &offset, &tag, &value, &value_len) != PM3_SUCCESS)
            return false;
        if (tag == want) return gp_crd_inner_oid(value, value_len, oid, oid_len);
    }
    return false;
}

// Text of the OID arcs that follow a known prefix, e.g. "2.3" for GP version.
static bool gp_oid_suffix(const uint8_t *oid, size_t oid_len, const uint32_t *prefix,
                          size_t prefix_count, char *out, size_t out_size) {
    uint32_t arcs[GP_OID_MAX_ARCS];
    size_t count = 0;
    if (!gp_oid_arcs(oid, oid_len, arcs, ARRAYLEN(arcs), &count) || count <= prefix_count ||
        memcmp(arcs, prefix, prefix_count * sizeof(uint32_t)) != 0)
        return false;
    gp_oid_arcs_text(arcs, prefix_count, count, out, out_size);
    return true;
}
// Print CPLC from a GET DATA 9F7F response (with or without the 9F7F header).
static void gp_print_cplc_response(const uint8_t *resp, size_t resp_len) {
    const uint8_t *cplc = NULL;
    size_t cplc_len = 0;
    gp_tlv_unwrap(resp, resp_len, 0x9F7F, &cplc, &cplc_len);
    gp_print_cplc(cplc, cplc_len);
}

// Extended Card Resources Information (tag FF21, ETSI TS 102 226 / GP Amd. C):
// 81 = installed applications, 82 = free non-volatile memory, 83 = free volatile memory.
static void gp_print_card_resources(const uint8_t *resp, size_t resp_len) {
    const uint8_t *body = NULL;
    size_t body_len = 0;
    gp_tlv_unwrap(resp, resp_len, 0xFF21, &body, &body_len);
    size_t offset = 0;
    while (offset < body_len) {
        uint32_t tag = 0;
        const uint8_t *value = NULL;
        size_t value_len = 0;
        if (gp_ber_read_tlv(body, body_len, &offset, &tag, &value, &value_len) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "  Malformed resource data: %s", sprint_hex_inrow(resp, resp_len));
            return;
        }
        uint32_t number = gp_be_uint(value, value_len);
        switch (tag) {
            case 0x81:
                gp_print_kv("Installed applications", _YELLOW_("%u"), number);
                break;
            case 0x82:
                gp_print_kv("Free non-volatile memory", _YELLOW_("%u") " bytes", number);
                break;
            case 0x83:
                gp_print_kv("Free volatile memory", _YELLOW_("%u") " bytes", number);
                break;
            default: {
                char label[24];
                snprintf(label, sizeof(label), "Resource tag %02X", (unsigned)tag);
                gp_print_kv(label, "%s", sprint_hex_inrow(value, value_len));
                break;
            }
        }
    }
}

typedef struct {
    uint8_t p1, p2;
    const char *name;
    uint8_t data[GP_RESP_BUF_SIZE];
    size_t len;
    bool ok;
} gp_info_object_t;

enum { GP_OBJ_CPLC, GP_OBJ_CRD, GP_OBJ_KEYS, GP_OBJ_CAPS, GP_OBJ_IIN, GP_OBJ_CIN,
       GP_OBJ_KDD, GP_OBJ_SEQ, GP_OBJ_CONF, GP_OBJ_RES, GP_OBJ_COUNT };

static int CmdHFJavaCardInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard info",
                  "Select the Issuer Security Domain and interrogate it without authentication.\n"
                  "Reads CPLC, Card Recognition Data, Key Information, Card Capabilities, IIN/CIN,\n"
                  "key derivation data, sequence/confirmation counters and free card resources.",
                  "hf javacard info\n"
                  "hf javacard info --raw\n"
                  "hf javacard info -v");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("r", "raw", "also print every raw GET DATA object"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool raw = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);
    clearCommandBuffer();

    uint16_t sw = 0;
    uint8_t fci[GP_RESP_BUF_SIZE];
    size_t fci_len = 0;
    int ret = gp_plain_apdu(true, true, 0x00, GP_INS_SELECT, 0x04, 0x00, GP_ISD_AID, GP_ISD_AID_LEN,
                            true, 0x100, fci, sizeof(fci), &fci_len, &sw, verbose);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "No card / field communication error");
        return ret;
    }
    if (sw != 0x9000) {
        PrintAndLogEx(WARNING, "SELECT ISD " _RED_("failed") ", SW %04X - %s", sw,
                      GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        PrintAndLogEx(HINT, "Hint: this does not look like a GlobalPlatform card; try `" _YELLOW_("hf javacard scan") "`");
        gp_drop_field();
        return PM3_ESOFT;
    }

    static gp_info_object_t objects[GP_OBJ_COUNT] = {
        [GP_OBJ_CPLC] = { 0x9F, 0x7F, "CPLC (9F7F)" },
        [GP_OBJ_CRD]  = { 0x00, 0x66, "Card Recognition Data (66)" },
        [GP_OBJ_KEYS] = { 0x00, 0xE0, "Key Information (E0)" },
        [GP_OBJ_CAPS] = { 0x00, 0x67, "Card Capabilities (67)" },
        [GP_OBJ_IIN]  = { 0x00, 0x42, "IIN (42)" },
        [GP_OBJ_CIN]  = { 0x00, 0x45, "CIN (45)" },
        [GP_OBJ_KDD]  = { 0x00, 0xCF, "Key Derivation Data (CF)" },
        [GP_OBJ_SEQ]  = { 0x00, 0xC1, "Sequence Counter (C1)" },
        [GP_OBJ_CONF] = { 0x00, 0xC2, "Confirmation Counter (C2)" },
        [GP_OBJ_RES]  = { 0xFF, 0x21, "Card Resources (FF21)" },
    };
    for (size_t i = 0; i < GP_OBJ_COUNT; i++)
        objects[i].ok = gp_get_data_plain(objects[i].p1, objects[i].p2, objects[i].data,
                                          sizeof(objects[i].data), &objects[i].len, verbose);
    gp_drop_field();

    // ---- Summary --------------------------------------------------------
    gp_print_banner("JavaCard / GlobalPlatform Information");
    const uint8_t *value = NULL, *oid = NULL;
    size_t value_len = 0, oid_len = 0;
    char text[96];

    if (objects[GP_OBJ_CPLC].ok) {
        gp_tlv_unwrap(objects[GP_OBJ_CPLC].data, objects[GP_OBJ_CPLC].len, 0x9F7F, &value, &value_len);
        gp_print_identification(value, value_len);
        if (value_len >= 16) gp_print_kv("IC serial", _YELLOW_("%s"), sprint_hex_inrow(value + 12, 4));
    } else {
        gp_print_identification(NULL, 0);
    }
    static const uint32_t gp_ver_prefix[] = {1, 2, 840, 114283, 2};
    static const uint32_t jc_ver_prefix[] = {1, 3, 6, 1, 4, 1, 42, 2, 110, 1};
    if (objects[GP_OBJ_CRD].ok) {
        const uint8_t *crd = objects[GP_OBJ_CRD].data;
        size_t crd_len = objects[GP_OBJ_CRD].len;
        uint8_t scp = 0, scp_i = 0;
        if (gp_crd_find_oid(crd, crd_len, 0x60, &oid, &oid_len) &&
            gp_oid_suffix(oid, oid_len, gp_ver_prefix, ARRAYLEN(gp_ver_prefix), text, sizeof(text)))
            gp_print_kv("GlobalPlatform", _GREEN_("%s"), text);
        if (gp_crd_find_oid(crd, crd_len, 0x66, &oid, &oid_len) &&
            gp_oid_suffix(oid, oid_len, jc_ver_prefix, ARRAYLEN(jc_ver_prefix), text, sizeof(text)))
            gp_print_kv("Java Card", _GREEN_("%s"), text);
        if (gp_crd_scp(crd, crd_len, &scp, &scp_i))
            gp_print_kv("Secure channel", _GREEN_("SCP%02X") " i=" _YELLOW_("%02X"), scp, scp_i);
    }
    if (objects[GP_OBJ_KEYS].ok) {
        gp_tlv_unwrap(objects[GP_OBJ_KEYS].data, objects[GP_OBJ_KEYS].len, 0xE0, &value, &value_len);
        size_t offset = 0, keys = 0;
        uint8_t kvns[16];
        size_t kvn_count = 0;
        uint32_t tag;
        const uint8_t *entry;
        size_t entry_len;
        while (offset < value_len &&
               gp_ber_read_tlv(value, value_len, &offset, &tag, &entry, &entry_len) == PM3_SUCCESS) {
            if (tag != 0xC0 || entry_len < 2) continue;
            keys++;
            bool seen = false;
            for (size_t k = 0; k < kvn_count; k++) seen |= kvns[k] == entry[1];
            if (!seen && kvn_count < sizeof(kvns)) kvns[kvn_count++] = entry[1];
        }
        char kvn_text[64] = {0};
        size_t used = 0;
        for (size_t k = 0; k < kvn_count && used < sizeof(kvn_text); k++)
            used += (size_t)snprintf(kvn_text + used, sizeof(kvn_text) - used, "%s%02X", k ? " " : "", kvns[k]);
        gp_print_kv("Keys", _YELLOW_("%zu") " in %zu key set(s), KVN %s", keys, kvn_count, kvn_text);
    }
    if (objects[GP_OBJ_SEQ].ok) {
        gp_tlv_unwrap(objects[GP_OBJ_SEQ].data, objects[GP_OBJ_SEQ].len, 0xC1, &value, &value_len);
        gp_print_kv("Sequence counter", _YELLOW_("%u"), gp_be_uint(value, value_len));
    }
    if (objects[GP_OBJ_RES].ok) {
        gp_tlv_unwrap(objects[GP_OBJ_RES].data, objects[GP_OBJ_RES].len, 0xFF21, &value, &value_len);
        size_t offset = 0;
        uint32_t tag, apps = 0, nvm = 0, ram = 0;
        const uint8_t *entry;
        size_t entry_len;
        while (offset < value_len &&
               gp_ber_read_tlv(value, value_len, &offset, &tag, &entry, &entry_len) == PM3_SUCCESS) {
            if (tag == 0x81) apps = gp_be_uint(entry, entry_len);
            if (tag == 0x82) nvm = gp_be_uint(entry, entry_len);
            if (tag == 0x83) ram = gp_be_uint(entry, entry_len);
        }
        gp_print_kv("Free memory", "NVM " _YELLOW_("%u") " bytes, RAM " _YELLOW_("%u") " bytes, %u app(s)",
                    nvm, ram, apps);
    }

    // ---- Details --------------------------------------------------------
    if (objects[GP_OBJ_CPLC].ok) {
        gp_print_section("Card Production Life Cycle (CPLC)");
        gp_print_cplc_response(objects[GP_OBJ_CPLC].data, objects[GP_OBJ_CPLC].len);
    } else {
        gp_print_section("Card Production Life Cycle (CPLC)");
        PrintAndLogEx(INFO, "  not available");
    }
    if (objects[GP_OBJ_CRD].ok) {
        gp_print_section("Card Recognition Data");
        gp_decode_card_recognition_data(objects[GP_OBJ_CRD].data, objects[GP_OBJ_CRD].len);
    }
    if (objects[GP_OBJ_KEYS].ok) {
        gp_print_section("Key Information");
        if (gp_print_key_info_template(objects[GP_OBJ_KEYS].data, objects[GP_OBJ_KEYS].len, 0, 0) < 0)
            PrintAndLogEx(WARNING, "  Malformed key information");
    }
    if (objects[GP_OBJ_CAPS].ok) {
        gp_print_section("Card Capabilities");
        gp_print_capabilities(objects[GP_OBJ_CAPS].data, objects[GP_OBJ_CAPS].len);
    }

    bool any_id = objects[GP_OBJ_IIN].ok || objects[GP_OBJ_CIN].ok || objects[GP_OBJ_KDD].ok ||
                  objects[GP_OBJ_SEQ].ok || objects[GP_OBJ_CONF].ok;
    if (any_id) {
        gp_print_section("Identifiers & Counters");
        static const struct { int index; uint32_t tag; const char *label; bool counter; } rows[] = {
            { GP_OBJ_IIN,  0x42, "Issuer Identification No.", false },
            { GP_OBJ_CIN,  0x45, "Card Image Number", false },
            { GP_OBJ_KDD,  0xCF, "Key Derivation Data", false },
            { GP_OBJ_SEQ,  0xC1, "Sequence counter", true },
            { GP_OBJ_CONF, 0xC2, "Confirmation counter", true },
        };
        for (size_t i = 0; i < ARRAYLEN(rows); i++) {
            const gp_info_object_t *o = &objects[rows[i].index];
            if (!o->ok) continue;
            gp_tlv_unwrap(o->data, o->len, rows[i].tag, &value, &value_len);
            if (rows[i].counter)
                gp_print_kv(rows[i].label, _YELLOW_("%s") " (%u)", sprint_hex_inrow(value, value_len),
                            gp_be_uint(value, value_len));
            else
                gp_print_kv(rows[i].label, _YELLOW_("%s"), sprint_hex_inrow(value, value_len));
        }
    }
    if (objects[GP_OBJ_RES].ok) {
        gp_print_section("Extended Card Resources");
        gp_print_card_resources(objects[GP_OBJ_RES].data, objects[GP_OBJ_RES].len);
    }

    if (raw) {
        gp_print_section("Raw GET DATA objects");
        PrintAndLogEx(INFO, "  SELECT ISD FCI: %s", sprint_hex_inrow(fci, fci_len));
        for (size_t i = 0; i < GP_OBJ_COUNT; i++)
            PrintAndLogEx(INFO, "  %-28s %s", objects[i].name,
                          objects[i].ok ? sprint_hex_inrow(objects[i].data, objects[i].len) : "(not available)");
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(HINT, "Hint: try `" _YELLOW_("hf javacard keyaudit") "` to check the key sets against known default keys");
    PrintAndLogEx(HINT, "Hint: try `" _YELLOW_("hf javacard list --auth") "` to list the registry (uses the GP test key)");
    return PM3_SUCCESS;
}

//=============================================================================// Auto-auth helper: establish a default session if none is active
//=============================================================================

static int CmdHFJavaCardAuth(const char *Cmd);

#define GP_CONFIRM_ARG arg_lit0(NULL, "confirm", "required: acknowledge that this permanently changes the card")

// Irreversible or key-affecting commands refuse to run without --confirm, so a
// typo or a copied example can never alter a card (they otherwise authenticate
// automatically with the well-known test key). Checked before any card I/O.
static bool gp_require_confirm(bool confirmed, const char *operation) {
    if (confirmed) return true;
    PrintAndLogEx(ERR, "%s permanently changes the card; nothing was sent.", operation);
    PrintAndLogEx(HINT, "Hint: re-run with " _YELLOW_("--confirm") " once you are sure");
    return false;
}

// Legacy management commands call this helper. Reuse an existing session when
// possible; otherwise try the same well-known 40..4F test key used by `auth`.
// Users needing production keys can still run `hf javacard auth ...` first.
static int gp_ensure_session(bool verbose) {
    if (gp_ctx.active) return PM3_SUCCESS;
    PrintAndLogEx(WARNING,
                  "No secure channel is active; trying automatic authentication with the well-known 404142...4F test key");
    return CmdHFJavaCardAuth(verbose ? "--verbose" : "");
}


//=============================================================================
// Shared GET STATUS collector (used by list and dump)
//=============================================================================

#define GP_STATUS_MAX_BYTES 65536

typedef struct {
    uint8_t *data;      // heap buffer, free with free()
    size_t len;
    uint16_t sw;        // last status word
    int ret;            // PM3_SUCCESS, or transport / protocol error
    uint8_t p1;         // P1 actually answered (10 may fall back to 20)
    bool legacy;        // card only answered the deprecated untagged format
    bool empty;         // 6A88: no entry of that class
} gp_status_result_t;

// Collect every block of one GET STATUS class. Requests the tagged format first,
// falls back to the deprecated format and, for P1=10, to P1=20. Uses the secure
// channel when one is active.
static void gp_collect_status(uint8_t p1, bool verbose, gp_status_result_t *out) {
    memset(out, 0, sizeof(*out));
    out->p1 = p1;
    size_t capacity = 0;
    uint8_t p2_base = 0x02;
    uint8_t p2 = p2_base | GP_STATUS_FIRST_BLOCK;
    bool retried_legacy = false, retried_packages = false;
    const uint8_t filter[] = {0x4F, 0x00};

    for (;;) {
        uint8_t block[GP_RESP_BUF_SIZE];
        size_t block_len = 0;
        uint16_t sw = 0;
        int ret = gp_ctx.active
                  ? gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_GET_STATUS, out->p1, p2, filter,
                                    sizeof(filter), true, 0x100, block, sizeof(block), &block_len, &sw, verbose)
                  : gp_plain_apdu(false, true, GP_CLA_PLAIN, GP_INS_GET_STATUS, out->p1, p2, filter,
                                  sizeof(filter), true, 0x100, block, sizeof(block), &block_len, &sw, verbose);
        out->sw = sw;
        if (ret != PM3_SUCCESS) {
            out->ret = ret;
            return;
        }
        if (sw == 0x9000 || sw == 0x6310) {
            if (out->len + block_len > GP_STATUS_MAX_BYTES) {
                PrintAndLogEx(ERR, "GET STATUS data exceeds the %u-byte safety limit", GP_STATUS_MAX_BYTES);
                out->ret = PM3_ESOFT;
                return;
            }
            if (out->len + block_len > capacity) {
                size_t grow = capacity ? capacity * 2 : 1024;
                while (grow < out->len + block_len) grow *= 2;
                uint8_t *bigger = realloc(out->data, grow);
                if (bigger == NULL) {
                    out->ret = PM3_EMALLOC;
                    return;
                }
                out->data = bigger;
                capacity = grow;
            }
            memcpy(out->data + out->len, block, block_len);
            out->len += block_len;
            if (sw == 0x9000) return;
            p2 = p2_base | GP_STATUS_NEXT_BLOCK;
        } else if (sw == 0x6A86 && p2_base == 0x02 && !retried_legacy) {
            p2_base = 0x00;
            p2 = GP_STATUS_FIRST_BLOCK;
            out->len = 0;
            out->legacy = retried_legacy = true;
        } else if ((sw == 0x6A86 || sw == 0x6A81) && out->p1 == GP_STATUS_LOAD_FILES_MODS && !retried_packages) {
            out->p1 = GP_STATUS_LOAD_FILES;   // card does not report modules
            p2 = p2_base | GP_STATUS_FIRST_BLOCK;
            out->len = 0;
            retried_packages = true;
        } else if (sw == 0x6A88) {
            out->empty = true;
            return;
        } else {
            out->ret = PM3_ESOFT;
            return;
        }
    }
}

static void gp_status_failure_hint(uint16_t sw) {
    if (sw == 0x6982 && !gp_ctx.active)
        PrintAndLogEx(HINT, "Hint: the card needs a secure channel; add `" _YELLOW_("--auth") "` or run `"
                      _YELLOW_("hf javacard auth") "` first");
}

//=============================================================================
// Command: hf javacard list
//=============================================================================

static int CmdHFJavaCardList(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard list",
                  "List the GlobalPlatform registry (ISD, applications/SSDs, load files and modules).\n"
                  "An open secure channel is reused. Without one, GET STATUS is sent in the clear unless\n"
                  "--auth is given, which first authenticates with the GP test key 404142..4F.",
                  "hf javacard list --auth\n"
                  "hf javacard list --apps\n"
                  "hf javacard list --pkgs -v");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "apps",    "list applications and SSDs only"),
        arg_lit0("p", "pkgs",    "list executable load files only"),
        arg_lit0(NULL, "auth",   "authenticate with the default test key when no session is open"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool only_apps = arg_get_lit(ctx, 1);
    bool only_pkgs = arg_get_lit(ctx, 2);
    bool auth = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);
    if (only_apps && only_pkgs) {
        PrintAndLogEx(ERR, "--apps and --pkgs are mutually exclusive");
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    bool had_session = gp_ctx.active;
    if (!had_session && auth) {
        if (gp_ensure_session(verbose) != PM3_SUCCESS) return PM3_ESOFT;
    } else if (!had_session) {
        uint16_t sw = 0;
        int ret = gp_select_isd(true, true, &sw, verbose);
        if (ret != PM3_SUCCESS || (sw != 0x9000 && (sw & 0xFF00) != 0x6100)) {
            PrintAndLogEx(ERR, "Cannot select ISD (SW=%04X)", sw);
            gp_drop_field();
            return ret == PM3_SUCCESS ? PM3_ESOFT : ret;
        }
    }

    static const uint8_t p1_values[] = {GP_STATUS_ISD, GP_STATUS_APPS_AND_SSD, GP_STATUS_LOAD_FILES_MODS};
    static const char *labels[] = {
        "Issuer Security Domain",
        "Applications & Supplementary Security Domains",
        "Executable Load Files & Modules"
    };
    int first = only_apps ? 1 : only_pkgs ? 2 : 0;
    int last = only_apps ? 2 : 3;
    int overall = PM3_SUCCESS;

    gp_print_banner("GlobalPlatform Registry");
    PrintAndLogEx(INFO, "  Access ........ %s", gp_ctx.active ? _GREEN_("secure channel") : _YELLOW_("unauthenticated"));
    for (int pi = first; pi < last; pi++) {
        gp_status_result_t st;
        gp_collect_status(p1_values[pi], verbose, &st);
        gp_print_section(labels[pi]);
        if (st.ret != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "  GET STATUS failed, SW %04X - %s", st.sw,
                          GetAPDUCodeDescription(st.sw >> 8, st.sw & 0xFF));
            gp_status_failure_hint(st.sw);
            overall = st.ret;
        } else if (st.empty || st.len == 0) {
            PrintAndLogEx(INFO, "  (none)");
        } else {
            if (verbose && st.legacy) PrintAndLogEx(INFO, "  Card used the deprecated untagged GET STATUS format");
            if (verbose && st.p1 != p1_values[pi]) PrintAndLogEx(INFO, "  Card does not report modules (P1=20 used)");
            gp_print_status_response(st.data, st.len, st.p1);
        }
        free(st.data);
        if (overall != PM3_SUCCESS) break;
    }

    if (!had_session && !gp_ctx.active) gp_drop_field();
    return overall;
}


//=============================================================================
// Command: hf javacard auth  (SCP01/SCP02/SCP03)
//=============================================================================

// Validate that a security level is supported for the given SCP version.
static bool gp_security_level_supported(int scp, uint8_t sl) {
    if (scp == 1)
        return sl == GP_SL_NO_SECURITY || sl == GP_SL_C_MAC || sl == GP_SL_C_DEC_MAC;
    if (scp == 2)
        return sl == GP_SL_NO_SECURITY || sl == GP_SL_C_MAC ||
               sl == GP_SL_C_DEC_MAC || sl == GP_SL_C_MAC_R_MAC ||
               sl == GP_SL_C_DEC_MAC_R;
    if (scp == 3)
        return sl == GP_SL_NO_SECURITY || sl == GP_SL_C_MAC ||
               sl == GP_SL_C_DEC_MAC || sl == GP_SL_C_MAC_R_MAC ||
               sl == GP_SL_C_DEC_MAC_R || sl == GP_SL_C_DEC_R_ENC;
    return false;
}

// SCP03 Amendment D v1.2 Table 5-1:
// b1 selects S8/S16, b5 selects random/pseudo-random challenge generation,
// and b7:b6 declare response-protection support. b8 and b4:b2 are reserved.
static bool gp_scp03_option_valid(uint8_t scp_i) {
    if ((scp_i & 0x8E) != 0) return false;
    return (scp_i & 0x60) != 0x40; // b7:b6 = 10 is not assigned.
}

static bool gp_scp03_option_supports_rmac(uint8_t scp_i) {
    return (scp_i & 0x60) == 0x20 || (scp_i & 0x60) == 0x60;
}

static bool gp_scp03_option_supports_renc(uint8_t scp_i) {
    return (scp_i & 0x60) == 0x60;
}

// SCP01 does not advertise an implementation option in INITIALIZE UPDATE.
// This CLI byte is limited to the implemented modified-APDU profiles, with
// bit 1 selecting three base keys and bit 5 selecting ICV encryption.
static bool gp_scp01_option_supported(uint8_t scp_i) {
    return scp_i == 0x04 || scp_i == 0x05 ||
           scp_i == 0x14 || scp_i == 0x15;
}

static bool gp_scp02_option_supported(uint8_t scp_i) {
    if (scp_i & 0x80) return false;       // b8 is reserved
    if ((scp_i & 0x04) == 0) return false; // explicit initiation only
    if (scp_i & 0x02) return false;       // unmodified APDU not implemented
    if (scp_i & 0x08) return false;       // ICV-over-AID is implicit-init only
    return true;                          // b1/b5/b6/b7 are supported
}

static bool gp_scp02_option_supports_rmac(uint8_t scp_i) {
    return (scp_i & 0x20) != 0;
}

static bool gp_parse_kdf(const char *name, gp_kdf_template_t *kdf) {
    if (name == NULL || kdf == NULL || name[0] == '\0' || strcmp(name, "auto") == 0)
        return false;
    if (strcmp(name, "none") == 0) *kdf = GP_KDF_NONE;
    else if (strcmp(name, "emv") == 0) *kdf = GP_KDF_EMV;
    else if (strcmp(name, "visa2") == 0) *kdf = GP_KDF_VISA2;
    else if (strcmp(name, "visa") == 0) *kdf = GP_KDF_VISA;
    else if (strcmp(name, "kdf3") == 0) *kdf = GP_KDF_KDF3;
    else return false;
    return true;
}


static bool gp_scp02_try_keyset(const uint8_t *enc_key, const uint8_t *mac_key,
                                 const uint8_t *dek_key, const uint8_t ssc[2],
                                 const uint8_t *host_chal, const uint8_t *card_chal,
                                 const uint8_t *card_cg,
                                 uint8_t *s_enc, uint8_t *s_mac,
                                 uint8_t *dek, uint8_t *r_mac) {
    if (gp_scp02_derive_key(enc_key, 16, GP_SCP02_DERIVE_ENC, ssc, s_enc) != PM3_SUCCESS)
        return false;
    if (gp_scp02_derive_key(mac_key, 16, GP_SCP02_DERIVE_MAC, ssc, s_mac) != PM3_SUCCESS)
        return false;
    if (gp_scp02_derive_key(dek_key, 16, GP_SCP02_DERIVE_DEK, ssc, dek) != PM3_SUCCESS)
        return false;
    if (gp_scp02_derive_key(mac_key, 16, GP_SCP02_DERIVE_RMAC, ssc, r_mac) != PM3_SUCCESS)
        return false;

    uint8_t input[16];
    uint8_t expected[8];
    uint8_t zero_iv[8] = {0};
    memcpy(input, host_chal, 8);
    memcpy(input + 8, card_chal, 8);
    bool ok = gp_mac_3des(s_enc, input, sizeof(input), zero_iv, expected) == PM3_SUCCESS &&
              gp_consttime_equal(expected, card_cg, sizeof(expected));
    gp_secure_zero(input, sizeof(input));
    gp_secure_zero(expected, sizeof(expected));
    return ok;
}


// Try to match card cryptogram with a given SCP03 card key set.
// SCP03 authentication cryptograms are derived with S-MAC, not S-ENC.
static bool gp_scp03_try_keyset(const uint8_t *enc_key, const uint8_t *mac_key,
                                 size_t key_len,
                                 const uint8_t *host_chal, size_t challenge_len,
                                 const uint8_t *card_chal, const uint8_t *card_cg,
                                 size_t cryptogram_len,
                                 uint8_t *s_enc, uint8_t *s_mac, uint8_t *r_mac) {
    if (enc_key == NULL || mac_key == NULL || host_chal == NULL ||
        card_chal == NULL || card_cg == NULL || s_enc == NULL ||
        s_mac == NULL || r_mac == NULL ||
        (challenge_len != 8 && challenge_len != 16) ||
        cryptogram_len != challenge_len)
        return false;

    uint8_t context[32];
    memcpy(context, host_chal, challenge_len);
    memcpy(context + challenge_len, card_chal, challenge_len);
    size_t context_len = challenge_len * 2;

    if (gp_scp03_kdf(enc_key, key_len, GP_SCP03_CONST_ENC,
                     context, context_len, key_len, s_enc) != PM3_SUCCESS)
        return false;
    if (gp_scp03_kdf(mac_key, key_len, GP_SCP03_CONST_MAC,
                     context, context_len, key_len, s_mac) != PM3_SUCCESS)
        return false;
    if (gp_scp03_kdf(mac_key, key_len, GP_SCP03_CONST_RMAC,
                     context, context_len, key_len, r_mac) != PM3_SUCCESS)
        return false;

    uint8_t expected[16];
    bool ok = gp_scp03_kdf(s_mac, key_len, GP_SCP03_CONST_CARD_CG,
                           context, context_len, cryptogram_len, expected) == PM3_SUCCESS &&
              gp_consttime_equal(expected, card_cg, cryptogram_len);
    gp_secure_zero(context, sizeof(context));
    gp_secure_zero(expected, sizeof(expected));
    return ok;
}


static int CmdHFJavaCardAuth(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard auth",
                  "Open a GlobalPlatform SCP01/SCP02/SCP03 secure channel.\n"
                  "SCP01/SCP02 are legacy. SCP03 supports S8/S16 and AES-128/192/256.\n"
                  "Use --show-secrets only in a controlled terminal/logging environment.",
                  "hf javacard auth -k 404142434445464748494A4B4C4D4E4F --scp 3 --sl 03\n"
                  "hf javacard auth --enc-key <hex> --mac-key <hex> --dek-key <hex> --s16\n"
                  "hf javacard auth -k <hex> --kdf kdf3 --i 55");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("k",  "key",      "<hex>", "Master key (sets ENC/MAC/DEK)"),
        arg_str0(NULL, "enc-key",  "<hex>", "Static ENC key"),
        arg_str0(NULL, "mac-key",  "<hex>", "Static MAC key"),
        arg_str0(NULL, "dek-key",  "<hex>", "Static DEK key"),
        arg_int0(NULL, "kvn",      "<dec>", "Key Version Number (default: 0, any)"),
        arg_int0(NULL, "kid",      "<dec>", "Key Identifier (SCP01 only; SCP02/03 require 0)"),
        arg_str0(NULL, "sl",       "<hex>", "Security level: 00,01,03,11,13; SCP03 also 33"),
        arg_int0(NULL, "scp",      "<dec>", "Force SCP version 1, 2, or 3"),
        arg_str0(NULL, "i",        "<hex>", "Force SCP01/02 implementation option (default: Card Recognition Data, else 05/55; +20 for R-MAC)"),
        arg_str0(NULL, "kdf",      "<name>", "auto, none, emv, visa2, visa, or kdf3"),
        arg_lit0(NULL, "s16",      "request SCP03 S16"),
        arg_lit0(NULL, "s8",       "require SCP03 S8"),
        arg_lit0(NULL, "show-secrets", "print static/session keys"),
        arg_lit0("v",  "verbose",  "verbose APDU output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t master[GP_MAX_AES_KEY_LEN] = {0};
    uint8_t static_enc[GP_MAX_AES_KEY_LEN] = {0};
    uint8_t static_mac[GP_MAX_AES_KEY_LEN] = {0};
    uint8_t static_dek[GP_MAX_AES_KEY_LEN] = {0};
    int master_len = 0, enc_len = 0, mac_len_arg = 0, dek_len = 0;
    int sl_arg, i_force;
    GP_HEX_OPTION_OR_RETURN(ctx, 7, GP_SL_C_DEC_MAC, sl_arg);
    GP_HEX_OPTION_OR_RETURN(ctx, 9, -1, i_force);
    CLIGetHexWithReturn(ctx, 1, master, &master_len);
    CLIGetHexWithReturn(ctx, 2, static_enc, &enc_len);
    CLIGetHexWithReturn(ctx, 3, static_mac, &mac_len_arg);
    CLIGetHexWithReturn(ctx, 4, static_dek, &dek_len);
    int kvn = arg_get_int_def(ctx, 5, 0);
    int kid = arg_get_int_def(ctx, 6, 0);
    int scp_force = arg_get_int_def(ctx, 8, 0);
    char kdf_name[16] = "auto";
    int kdf_name_len = (int)sizeof(kdf_name) - 1;
    CLIGetStrWithReturn(ctx, 10, (uint8_t *)kdf_name, &kdf_name_len);
    bool force_s16 = arg_get_lit(ctx, 11);
    bool force_s8 = arg_get_lit(ctx, 12);
    bool show_secrets = arg_get_lit(ctx, 13);
    bool verbose = arg_get_lit(ctx, 14);
    CLIParserFree(ctx);

    int result = PM3_ESOFT;
    uint8_t host_chal[16] = {0};
    uint8_t card_enc[GP_MAX_AES_KEY_LEN] = {0};
    uint8_t card_mac[GP_MAX_AES_KEY_LEN] = {0};
    uint8_t card_dek[GP_MAX_AES_KEY_LEN] = {0};
    uint8_t s_enc[GP_MAX_AES_KEY_LEN] = {0};
    uint8_t s_mac[GP_MAX_AES_KEY_LEN] = {0};
    uint8_t s_dek[GP_MAX_AES_KEY_LEN] = {0};
    uint8_t s_rmac[GP_MAX_AES_KEY_LEN] = {0};
    uint8_t host_cg[16] = {0};
    uint8_t ea_mac[16] = {0};
    uint8_t response[GP_RESP_BUF_SIZE] = {0};

    if (force_s16 && force_s8) {
        PrintAndLogEx(ERR, "--s8 and --s16 are mutually exclusive");
        result = PM3_EINVARG;
        goto cleanup;
    }
    if (scp_force < 0 || scp_force > 3) {
        PrintAndLogEx(ERR, "--scp must be 1, 2, or 3");
        result = PM3_EINVARG;
        goto cleanup;
    }
    if (force_s16 && scp_force != 0 && scp_force != 3) {
        PrintAndLogEx(ERR, "S16 is defined only for SCP03");
        result = PM3_EINVARG;
        goto cleanup;
    }
    if (kvn < 0 || kvn > 0xFF || kid < 0 || kid > 0xFF ||
        sl_arg < 0 || sl_arg > 0xFF || i_force > 0xFF) {
        PrintAndLogEx(ERR, "KVN, KID, security level and i must fit in one byte");
        result = PM3_EINVARG;
        goto cleanup;
    }
    if (kid != 0 && scp_force != 1) {
        PrintAndLogEx(ERR, "A non-zero --kid is valid only with an explicitly selected SCP01 session");
        result = PM3_EINVARG;
        goto cleanup;
    }

    bool auto_key = master_len == 0 && enc_len == 0 && mac_len_arg == 0 && dek_len == 0;
    if (!auto_key) {
        if (master_len > 0) {
            if (master_len != 16 && master_len != 24 && master_len != 32) {
                PrintAndLogEx(ERR, "Master key must be 16, 24, or 32 bytes");
                result = PM3_EINVARG;
                goto cleanup;
            }
            memcpy(static_enc, master, (size_t)master_len);
            memcpy(static_mac, master, (size_t)master_len);
            memcpy(static_dek, master, (size_t)master_len);
            enc_len = mac_len_arg = dek_len = master_len;
        }
        if (enc_len == 0 || mac_len_arg == 0 || dek_len == 0 ||
            enc_len != mac_len_arg || enc_len != dek_len ||
            (enc_len != 16 && enc_len != 24 && enc_len != 32)) {
            PrintAndLogEx(ERR, "ENC, MAC and DEK keys must all be present and have equal length (16/24/32)");
            result = PM3_EINVARG;
            goto cleanup;
        }
    }

    gp_kdf_template_t forced_kdf = GP_KDF_NONE;
    bool has_forced_kdf = false;
    if (kdf_name_len > 0 && strcmp(kdf_name, "auto") != 0) {
        has_forced_kdf = gp_parse_kdf(kdf_name, &forced_kdf);
        if (!has_forced_kdf) {
            PrintAndLogEx(ERR, "Unknown KDF '%s'", kdf_name);
            result = PM3_EINVARG;
            goto cleanup;
        }
    }

    clearCommandBuffer();
    gp_session_reset();
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("GlobalPlatform Secure Channel Establishment") " ---");

    uint16_t sw = 0;
    int ret = gp_select_isd(true, true, &sw, verbose);
    if (ret != PM3_SUCCESS || (sw != 0x9000 && (sw & 0xFF00) != 0x6100)) {
        PrintAndLogEx(ERR, "Cannot select ISD (SW: %04X)", sw);
        result = ret == PM3_SUCCESS ? PM3_ESOFT : ret;
        gp_drop_field();
        goto cleanup;
    }

    // The card advertises its SCP and implementation option in Card Recognition
    // Data (tag 64). Use it for SCP01/02, whose i byte is not echoed by
    // INITIALIZE UPDATE. A failure here is not fatal: defaults apply.
    uint8_t crd_scp = 0, crd_i = 0;
    bool have_crd_scp = false;
    if (i_force < 0) {
        size_t crd_len = 0;
        uint16_t crd_sw = 0;
        if (gp_plain_apdu(false, true, GP_CLA_PLAIN, GP_INS_GET_DATA, 0x00, 0x66, NULL, 0, true, 0x100,
                          response, sizeof(response), &crd_len, &crd_sw, verbose) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Card communication failed while reading Card Recognition Data");
            result = PM3_ESOFT;
            goto cleanup;
        }
        if (crd_sw == 0x9000)
            have_crd_scp = gp_crd_scp(response, crd_len, &crd_scp, &crd_i);
        if (verbose && have_crd_scp)
            PrintAndLogEx(INFO, "  Card advertises ............ SCP%02X i=%02X", crd_scp, crd_i);
    }

    size_t host_chal_len = force_s16 ? 16 : 8;
    if (gp_random_bytes(host_chal, host_chal_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Unable to generate a secure host challenge");
        gp_drop_field();
        result = PM3_ESOFT;
        goto cleanup;
    }
    if (verbose) PrintAndLogEx(INFO, "  Host challenge ............. %s",
                               sprint_hex_inrow(host_chal, host_chal_len));

    size_t response_len = 0;
    ret = gp_plain_apdu(false, true, GP_CLA_PLAIN, GP_INS_INITIALIZE_UPDATE,
                        (uint8_t)kvn, (uint8_t)kid,
                        host_chal, host_chal_len, false, 0,
                        response, sizeof(response), &response_len, &sw, verbose);
    if (ret != PM3_SUCCESS || sw != 0x9000) {
        PrintAndLogEx(ERR, "INITIALIZE UPDATE failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        gp_drop_field();
        result = ret == PM3_SUCCESS ? PM3_ESOFT : ret;
        goto cleanup;
    }
    if (response_len < 12) {
        PrintAndLogEx(ERR, "INITIALIZE UPDATE response is too short (%zu bytes)", response_len);
        gp_drop_field();
        result = PM3_ESOFT;
        goto cleanup;
    }

    int scp_detected = response[11];
    if (scp_detected != 1 && scp_detected != 2 && scp_detected != 3) {
        PrintAndLogEx(ERR, "Unsupported SCP identifier %02X", response[11]);
        gp_drop_field();
        result = PM3_ESOFT;
        goto cleanup;
    }
    if (scp_force != 0 && scp_force != scp_detected) {
        PrintAndLogEx(ERR, "Card reported SCP%02d but --scp %d was requested", scp_detected, scp_force);
        gp_drop_field();
        result = PM3_ESOFT;
        goto cleanup;
    }
    int scp_use = scp_detected;
    uint8_t sl = (uint8_t)sl_arg;
    if (!gp_security_level_supported(scp_use, sl)) {
        PrintAndLogEx(ERR, "Security level %02X is not supported for SCP%02d", sl, scp_use);
        gp_drop_field();
        result = PM3_EINVARG;
        goto cleanup;
    }

    uint8_t scp_i = 0;
    size_t cryptogram_len = 8;
    size_t expected_len = 28;
    const uint8_t *card_chal;
    const uint8_t *card_cg;
    const uint8_t *kdd = response;
    uint8_t card_kvn = response[10];
    uint8_t ssc[2] = {0};

    if (scp_use == 3) {
        if (response_len < 13) {
            PrintAndLogEx(ERR, "SCP03 INITIALIZE UPDATE response lacks the i byte");
            gp_drop_field();
            result = PM3_ESOFT;
            goto cleanup;
        }
        scp_i = response[12];
        if (!gp_scp03_option_valid(scp_i)) {
            PrintAndLogEx(ERR, "Invalid or unsupported SCP03 implementation option i=%02X", scp_i);
            gp_drop_field();
            result = PM3_ESOFT;
            goto cleanup;
        }
        if ((sl & GP_SL_R_MAC) != 0 && !gp_scp03_option_supports_rmac(scp_i)) {
            PrintAndLogEx(ERR, "SCP03 i=%02X does not advertise R-MAC support", scp_i);
            gp_drop_field();
            result = PM3_EINVARG;
            goto cleanup;
        }
        if ((sl & GP_SL_R_ENC_MAC) == GP_SL_R_ENC_MAC &&
            !gp_scp03_option_supports_renc(scp_i)) {
            PrintAndLogEx(ERR, "SCP03 i=%02X does not advertise R-ENCRYPTION support", scp_i);
            gp_drop_field();
            result = PM3_EINVARG;
            goto cleanup;
        }
        cryptogram_len = (scp_i & 0x01) ? 16 : 8;
        expected_len = 13 + 2 * cryptogram_len + ((scp_i & 0x10) ? 3 : 0);
        if (response_len != expected_len) {
            PrintAndLogEx(ERR, "Unexpected SCP03 INITIALIZE UPDATE length %zu (expected %zu for i=%02X)",
                          response_len, expected_len, scp_i);
            gp_drop_field();
            result = PM3_ESOFT;
            goto cleanup;
        }
        if ((force_s16 && cryptogram_len != 16) || (force_s8 && cryptogram_len != 8) ||
            host_chal_len != cryptogram_len) {
            PrintAndLogEx(ERR, "SCP03 mode mismatch: host challenge=%zu, card mode=S%zu",
                          host_chal_len, cryptogram_len);
            gp_drop_field();
            result = PM3_ESOFT;
            goto cleanup;
        }
        card_chal = response + 13;
        card_cg = card_chal + cryptogram_len;
    } else {
        if (response_len != 28 || host_chal_len != 8) {
            PrintAndLogEx(ERR, "SCP01/02 requires an 8-byte challenge and a 28-byte response");
            gp_drop_field();
            result = PM3_ESOFT;
            goto cleanup;
        }
        if (scp_use == 1) {
            scp_i = (uint8_t)(i_force >= 0 ? i_force
                                           : (have_crd_scp && crd_scp == 1 && gp_scp01_option_supported(crd_i)) ? crd_i : 0x05);
            if (!gp_scp01_option_supported(scp_i)) {
                PrintAndLogEx(ERR, "Unsupported SCP01 command-protection profile i=%02X", scp_i);
                gp_drop_field();
                result = PM3_EINVARG;
                goto cleanup;
            }
        } else {
            if (i_force >= 0) {
                scp_i = (uint8_t)i_force;
            } else {
                scp_i = (have_crd_scp && crd_scp == 2 && gp_scp02_option_supported(crd_i)) ? crd_i : 0x55;
                // R-MAC changes no C-MAC computation; request it on top of the
                // advertised profile (cards list the R-MAC variant in tag 67).
                if (sl & GP_SL_R_MAC) scp_i |= 0x20;
            }
            if (!gp_scp02_option_supported(scp_i)) {
                PrintAndLogEx(ERR, "Unsupported SCP02 implementation option i=%02X", scp_i);
                gp_drop_field();
                result = PM3_EINVARG;
                goto cleanup;
            }
            if ((sl & GP_SL_R_MAC) && !gp_scp02_option_supports_rmac(scp_i)) {
                PrintAndLogEx(ERR, "SCP02 security level %02X requires an i option with R-MAC support", sl);
                gp_drop_field();
                result = PM3_EINVARG;
                goto cleanup;
            }
        }
        card_chal = response + 12;
        card_cg = response + 20;
        ssc[0] = response[12];
        ssc[1] = response[13];
    }

    if (!auto_key && scp_use != 3 && enc_len != 16) {
        PrintAndLogEx(ERR, "SCP01/02 requires 16-byte TDEA keys");
        gp_drop_field();
        result = PM3_EINVARG;
        goto cleanup;
    }

    PrintAndLogEx(INFO, "  KDD ........................ %s", sprint_hex_inrow(kdd, 10));
    PrintAndLogEx(INFO, "  Card KVN ................... %02X", card_kvn);
    PrintAndLogEx(INFO, "  Protocol ................... SCP%02d i=%02X", scp_use, scp_i);
    PrintAndLogEx(INFO, "  Card challenge ............. %s",
                  sprint_hex_inrow(card_chal, cryptogram_len));
    PrintAndLogEx(INFO, "  Card cryptogram ............ %s",
                  sprint_hex_inrow(card_cg, cryptogram_len));

    gp_kdf_template_t legacy_kdfs[] = {GP_KDF_NONE, GP_KDF_EMV, GP_KDF_VISA2, GP_KDF_VISA};
    gp_kdf_template_t scp03_kdfs[] = {GP_KDF_NONE, GP_KDF_KDF3};
    const gp_kdf_template_t *kdfs = scp_use == 3 ? scp03_kdfs : legacy_kdfs;
    size_t kdf_count = scp_use == 3 ? ARRAYLEN(scp03_kdfs) : ARRAYLEN(legacy_kdfs);
    if (has_forced_kdf) {
        if ((scp_use == 3 && forced_kdf != GP_KDF_NONE && forced_kdf != GP_KDF_KDF3) ||
            (scp_use != 3 && (forced_kdf == GP_KDF_KDF3))) {
            PrintAndLogEx(ERR, "KDF %s is not valid for SCP%02d",
                          gp_kdf_template_name(forced_kdf), scp_use);
            gp_drop_field();
            result = PM3_EINVARG;
            goto cleanup;
        }
        kdfs = &forced_kdf;
        kdf_count = 1;
    }

    bool key_ok = false;
    const char *matched_key_name = NULL;
    gp_kdf_template_t matched_kdf = GP_KDF_NONE;
    size_t key_len = auto_key ? 16 : (size_t)enc_len;

    size_t key_candidates = auto_key ? GP_DEFAULT_KEYS_COUNT : 1;
    for (size_t candidate = 0; candidate < key_candidates && !key_ok; candidate++) {
        const uint8_t *base_enc = auto_key ? GP_DEFAULT_KEYS[candidate].key : static_enc;
        const uint8_t *base_mac = auto_key ? GP_DEFAULT_KEYS[candidate].key : static_mac;
        const uint8_t *base_dek = auto_key ? GP_DEFAULT_KEYS[candidate].key : static_dek;
        if (auto_key) {
            uint8_t required_flag = scp_use == 3 ? GP_DB_SCP03 : GP_DB_SCP02;
            if (!(GP_DEFAULT_KEYS[candidate].scp_flags & required_flag)) continue;
        }

        for (size_t ki = 0; ki < kdf_count && !key_ok; ki++) {
            gp_kdf_template_t kdf = kdfs[ki];
            int d1, d2, d3;
            if (scp_use == 3) {
                d1 = gp_scp03_diversify_key(base_enc, key_len, kdd, 0x01, kdf, card_enc);
                d2 = gp_scp03_diversify_key(base_mac, key_len, kdd, 0x02, kdf, card_mac);
                d3 = gp_scp03_diversify_key(base_dek, key_len, kdd, 0x03, kdf, card_dek);
                if (d1 == PM3_SUCCESS && d2 == PM3_SUCCESS && d3 == PM3_SUCCESS)
                    key_ok = gp_scp03_try_keyset(card_enc, card_mac, key_len,
                                                host_chal, cryptogram_len, card_chal, card_cg,
                                                cryptogram_len, s_enc, s_mac, s_rmac);
                if (key_ok) memcpy(s_dek, card_dek, key_len);
            } else {
                d1 = gp_diversify_3des_key(base_enc, kdd, 0x01, kdf, card_enc);
                d2 = gp_diversify_3des_key(base_mac, kdd, 0x02, kdf, card_mac);
                d3 = gp_diversify_3des_key(base_dek, kdd, 0x03, kdf, card_dek);
                if (d1 != PM3_SUCCESS || d2 != PM3_SUCCESS || d3 != PM3_SUCCESS) continue;
                if (scp_use == 1) {
                    key_ok = gp_scp01_try_keyset(card_enc, card_mac, host_chal,
                                                card_chal, card_cg, s_enc, s_mac);
                    if (key_ok) {
                        memcpy(s_dek, card_dek, 16);
                        memcpy(s_rmac, s_mac, 16);
                    }
                } else {
                    key_ok = gp_scp02_try_keyset(card_enc, card_mac, card_dek, ssc,
                                                host_chal, card_chal, card_cg,
                                                s_enc, s_mac, s_dek, s_rmac);
                }
            }
            if (key_ok) {
                matched_kdf = kdf;
                if (auto_key) matched_key_name = GP_DEFAULT_KEYS[candidate].name;
            }
        }
    }

    if (!key_ok) {
        PrintAndLogEx(ERR, "%s key(s) did not verify the card cryptogram",
                      auto_key ? "No known default" : "Supplied");
        gp_drop_field();
        result = PM3_ESOFT;
        goto cleanup;
    }

    PrintAndLogEx(SUCCESS, "  Card cryptogram ............ " _GREEN_("verified"));
    PrintAndLogEx(INFO, "  Diversification ............ %s", gp_kdf_template_name(matched_kdf));
    if (matched_key_name) PrintAndLogEx(INFO, "  Default key match .......... %s", matched_key_name);
    if (show_secrets) {
        PrintAndLogEx(WARNING, "  Sensitive key material follows");
        PrintAndLogEx(INFO, "  Static ENC ................. %s", sprint_hex_inrow(card_enc, key_len));
        PrintAndLogEx(INFO, "  Static MAC ................. %s", sprint_hex_inrow(card_mac, key_len));
        PrintAndLogEx(INFO, "  Static DEK ................. %s", sprint_hex_inrow(card_dek, key_len));
        PrintAndLogEx(INFO, "  S-ENC ...................... %s", sprint_hex_inrow(s_enc, key_len));
        PrintAndLogEx(INFO, "  S-MAC ...................... %s", sprint_hex_inrow(s_mac, key_len));
        if (scp_use != 1) PrintAndLogEx(INFO, "  S-RMAC ..................... %s", sprint_hex_inrow(s_rmac, key_len));
    }

    gp_session_reset();
    gp_ctx.scp_version = (uint8_t)scp_use;
    gp_ctx.scp_i = scp_i;
    gp_ctx.security_level = sl;
    gp_ctx.key_len = key_len;
    gp_ctx.mac_len = scp_use == 3 ? cryptogram_len : 8;
    memcpy(gp_ctx.enc_key, s_enc, key_len);
    memcpy(gp_ctx.mac_key, s_mac, key_len);
    memcpy(gp_ctx.dek_key, s_dek, key_len);
    memcpy(gp_ctx.rmac_key, s_rmac, key_len);
    memcpy(gp_ctx.ssc, ssc, sizeof(ssc));
    gp_ctx.scp02_modified_apdu = scp_use == 1 || (scp_i & 0x02) == 0;
    gp_ctx.scp02_icv_encrypt = (scp_i & 0x10) != 0;
    gp_ctx.active = true;

    uint8_t auth_context[32] = {0};
    if (scp_use == 3) {
        memcpy(auth_context, host_chal, cryptogram_len);
        memcpy(auth_context + cryptogram_len, card_chal, cryptogram_len);
        if (gp_scp03_kdf(s_mac, key_len, GP_SCP03_CONST_HOST_CG,
                         auth_context, 2 * cryptogram_len,
                         cryptogram_len, host_cg) != PM3_SUCCESS) {
            gp_drop_field();
            result = PM3_ESOFT;
            goto cleanup;
        }
    } else {
        uint8_t hcg_input[16];
        uint8_t zero_iv[8] = {0};
        memcpy(hcg_input, card_chal, 8);
        memcpy(hcg_input + 8, host_chal, 8);
        if (gp_mac_3des(s_enc, hcg_input, sizeof(hcg_input), zero_iv, host_cg) != PM3_SUCCESS) {
            gp_secure_zero(hcg_input, sizeof(hcg_input));
            gp_drop_field();
            result = PM3_ESOFT;
            goto cleanup;
        }
        gp_secure_zero(hcg_input, sizeof(hcg_input));
    }
    if (verbose) PrintAndLogEx(INFO, "  Host cryptogram ............ %s",
                               sprint_hex_inrow(host_cg, cryptogram_len));

    uint8_t ea_apdu[5 + 2 * GP_MAX_MAC_LEN] = {0};
    size_t ea_len = 0;
    ea_apdu[ea_len++] = GP_CLA_MAC;
    ea_apdu[ea_len++] = GP_INS_EXTERNAL_AUTH;
    ea_apdu[ea_len++] = sl;
    ea_apdu[ea_len++] = 0x00;
    ea_apdu[ea_len++] = (uint8_t)(2 * gp_ctx.mac_len);
    memcpy(ea_apdu + ea_len, host_cg, gp_ctx.mac_len);
    ea_len += gp_ctx.mac_len;

    if (scp_use == 3) {
        uint8_t mac_input[16 + 5 + GP_MAX_MAC_LEN] = {0};
        mac_input[16] = GP_CLA_MAC;
        mac_input[17] = GP_INS_EXTERNAL_AUTH;
        mac_input[18] = sl;
        mac_input[19] = 0x00;
        mac_input[20] = (uint8_t)(2 * gp_ctx.mac_len);
        memcpy(mac_input + 21, host_cg, gp_ctx.mac_len);
        uint8_t full_mac[16];
        if (gp_aes_cmac(s_mac, key_len, mac_input,
                        21 + gp_ctx.mac_len, full_mac) != PM3_SUCCESS) {
            gp_secure_zero(mac_input, sizeof(mac_input));
            gp_drop_field();
            result = PM3_ESOFT;
            goto cleanup;
        }
        memcpy(gp_ctx.chaining_value, full_mac, 16);
        memcpy(ea_mac, full_mac, gp_ctx.mac_len);
        gp_secure_zero(mac_input, sizeof(mac_input));
        gp_secure_zero(full_mac, sizeof(full_mac));
    } else {
        uint8_t raw[5 + 8];
        uint8_t padded[24] = {0};
        uint8_t zero_iv[8] = {0};
        raw[0] = GP_CLA_MAC;
        raw[1] = GP_INS_EXTERNAL_AUTH;
        raw[2] = sl;
        raw[3] = 0x00;
        raw[4] = 0x10;
        memcpy(raw + 5, host_cg, 8);
        size_t padded_len = gp_pad80(raw, sizeof(raw), 8, padded);
        int mret = scp_use == 1
            ? gp_full_3des_mac(s_mac, 16, padded, padded_len, zero_iv, ea_mac)
            : gp_retail_mac(s_mac, padded, padded_len, zero_iv, ea_mac);
        gp_secure_zero(raw, sizeof(raw));
        gp_secure_zero(padded, sizeof(padded));
        if (mret != PM3_SUCCESS) {
            gp_drop_field();
            result = mret;
            goto cleanup;
        }
        memcpy(gp_ctx.icv, ea_mac, 8);
        memcpy(gp_ctx.rmac_icv, ea_mac, 8);
    }

    memcpy(ea_apdu + ea_len, ea_mac, gp_ctx.mac_len);
    ea_len += gp_ctx.mac_len;
    if (verbose) PrintAndLogEx(INFO, ">>> %s", sprint_hex_inrow(ea_apdu, ea_len));

    size_t ea_resp_len = 0;
    ret = gp_send_apdu(false, true, ea_apdu, ea_len,
                       response, sizeof(response), &ea_resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS || sw != 0x9000) {
        PrintAndLogEx(ERR, "EXTERNAL AUTHENTICATE failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        gp_drop_field();
        result = ret == PM3_SUCCESS ? PM3_ESOFT : ret;
        goto cleanup;
    }

    PrintAndLogEx(SUCCESS, "SCP%02d session " _GREEN_("open") "  i=%02X SL=%02X%s",
                  scp_use, scp_i, sl,
                  scp_use == 3 ? (gp_ctx.mac_len == 16 ? " S16" : " S8") : "");
    result = PM3_SUCCESS;

cleanup:
    gp_secure_zero(master, sizeof(master));
    gp_secure_zero(static_enc, sizeof(static_enc));
    gp_secure_zero(static_mac, sizeof(static_mac));
    gp_secure_zero(static_dek, sizeof(static_dek));
    gp_secure_zero(host_chal, sizeof(host_chal));
    gp_secure_zero(card_enc, sizeof(card_enc));
    gp_secure_zero(card_mac, sizeof(card_mac));
    gp_secure_zero(card_dek, sizeof(card_dek));
    gp_secure_zero(s_enc, sizeof(s_enc));
    gp_secure_zero(s_mac, sizeof(s_mac));
    gp_secure_zero(s_dek, sizeof(s_dek));
    gp_secure_zero(s_rmac, sizeof(s_rmac));
    gp_secure_zero(host_cg, sizeof(host_cg));
    gp_secure_zero(ea_mac, sizeof(ea_mac));
    gp_secure_zero(response, sizeof(response));
    return result;

}

//=============================================================================
// Automatic secure-channel options for convenience commands
//=============================================================================

typedef struct {
    bool no_auth;
    bool reauth;
    uint8_t master[GP_MAX_AES_KEY_LEN];
    uint8_t enc[GP_MAX_AES_KEY_LEN];
    uint8_t mac[GP_MAX_AES_KEY_LEN];
    uint8_t dek[GP_MAX_AES_KEY_LEN];
    uint8_t gp_key_enc[GP_MAX_AES_KEY_LEN];
    uint8_t gp_key_mac[GP_MAX_AES_KEY_LEN];
    uint8_t gp_key_dek[GP_MAX_AES_KEY_LEN];
    int master_len;
    int enc_len;
    int mac_len;
    int dek_len;
    int gp_key_enc_len;
    int gp_key_mac_len;
    int gp_key_dek_len;
    int kvn;
    int kid;
    int security_level;
    int scp;
    int scp_i;
    char kdf[16];
    bool s16;
    bool s8;
    bool show_secrets;
} gp_auto_auth_options_t;

#define GP_AUTO_AUTH_ARG_COUNT 18
#define GP_AUTO_AUTH_ARGTABLE \
    arg_lit0(NULL, "no-auth", "do not automatically authenticate; require an existing session"), \
    arg_lit0(NULL, "reauth", "replace an existing session using the supplied/default authentication options"), \
    arg_str0("k", "key", "<hex>", "Authentication master key (sets ENC/MAC/DEK)"), \
    arg_str0(NULL, "enc-key", "<hex>", "Authentication static ENC key"), \
    arg_str0(NULL, "mac-key", "<hex>", "Authentication static MAC key"), \
    arg_str0(NULL, "dek-key", "<hex>", "Authentication static DEK key"), \
    arg_int0(NULL, "kvn", "<dec>", "Authentication Key Version Number (default 0)"), \
    arg_int0(NULL, "kid", "<dec>", "Authentication Key Identifier (SCP01 only)"), \
    arg_str0(NULL, "sl", "<hex>", "Authentication security level (default 03)"), \
    arg_int0(NULL, "scp", "<dec>", "Force authentication SCP version 1, 2, or 3"), \
    arg_str0(NULL, "scp-i", "<hex>", "Force SCP01/02 implementation option"), \
    arg_str0(NULL, "kdf", "<name>", "Authentication KDF: auto, none, emv, visa2, visa, kdf3"), \
    arg_lit0(NULL, "s16", "request SCP03 S16 authentication"), \
    arg_lit0(NULL, "s8", "require SCP03 S8 authentication"), \
    arg_lit0(NULL, "show-secrets", "print static/session keys during automatic authentication"), \
    arg_str0(NULL, "key-enc", "<hex>", "GPPro alias for --enc-key"), \
    arg_str0(NULL, "key-mac", "<hex>", "GPPro alias for --mac-key"), \
    arg_str0(NULL, "key-dek", "<hex>", "GPPro alias for --dek-key")

#define GP_PARSE_AUTO_AUTH(ctx_, base_, opts_) do { \
    memset(&(opts_), 0, sizeof(opts_)); \
    (opts_).scp_i = -1; \
    (opts_).security_level = GP_SL_C_DEC_MAC; \
    snprintf((opts_).kdf, sizeof((opts_).kdf), "auto"); \
    (opts_).no_auth = arg_get_lit((ctx_), (base_) + 0); \
    (opts_).reauth = arg_get_lit((ctx_), (base_) + 1); \
    GP_HEX_OPTION_OR_RETURN((ctx_), (base_) + 8, GP_SL_C_DEC_MAC, (opts_).security_level); \
    GP_HEX_OPTION_OR_RETURN((ctx_), (base_) + 10, -1, (opts_).scp_i); \
    CLIGetHexWithReturn((ctx_), (base_) + 2, (opts_).master, &(opts_).master_len); \
    CLIGetHexWithReturn((ctx_), (base_) + 3, (opts_).enc, &(opts_).enc_len); \
    CLIGetHexWithReturn((ctx_), (base_) + 4, (opts_).mac, &(opts_).mac_len); \
    CLIGetHexWithReturn((ctx_), (base_) + 5, (opts_).dek, &(opts_).dek_len); \
    (opts_).kvn = arg_get_int_def((ctx_), (base_) + 6, 0); \
    (opts_).kid = arg_get_int_def((ctx_), (base_) + 7, 0); \
    (opts_).scp = arg_get_int_def((ctx_), (base_) + 9, 0); \
    int _gp_kdf_len = (int)sizeof((opts_).kdf) - 1; \
    CLIGetStrWithReturn((ctx_), (base_) + 11, (uint8_t *)(opts_).kdf, &_gp_kdf_len); \
    if (_gp_kdf_len == 0) snprintf((opts_).kdf, sizeof((opts_).kdf), "auto"); \
    (opts_).s16 = arg_get_lit((ctx_), (base_) + 12); \
    (opts_).s8 = arg_get_lit((ctx_), (base_) + 13); \
    (opts_).show_secrets = arg_get_lit((ctx_), (base_) + 14); \
    CLIGetHexWithReturn((ctx_), (base_) + 15, (opts_).gp_key_enc, &(opts_).gp_key_enc_len); \
    CLIGetHexWithReturn((ctx_), (base_) + 16, (opts_).gp_key_mac, &(opts_).gp_key_mac_len); \
    CLIGetHexWithReturn((ctx_), (base_) + 17, (opts_).gp_key_dek, &(opts_).gp_key_dek_len); \
} while (0)

static bool gp_auto_auth_has_overrides(const gp_auto_auth_options_t *options) {
    if (options == NULL) return false;
    return options->master_len != 0 || options->enc_len != 0 ||
           options->mac_len != 0 || options->dek_len != 0 ||
           options->gp_key_enc_len != 0 || options->gp_key_mac_len != 0 ||
           options->gp_key_dek_len != 0 ||
           options->kvn != 0 || options->kid != 0 ||
           options->security_level != GP_SL_C_DEC_MAC ||
           options->scp != 0 || options->scp_i >= 0 ||
           strcmp(options->kdf, "auto") != 0 || options->s16 ||
           options->s8 || options->show_secrets;
}


static int gp_merge_auth_key_alias(const char *primary_name,
                                   uint8_t *primary, int *primary_len,
                                   const char *alias_name,
                                   const uint8_t *alias, int alias_len) {
    if (primary_name == NULL || primary == NULL || primary_len == NULL ||
        alias_name == NULL || alias == NULL)
        return PM3_EINVARG;
    if (alias_len == 0) return PM3_SUCCESS;
    if (*primary_len != 0) {
        if (*primary_len != alias_len ||
            !gp_consttime_equal(primary, alias, (size_t)alias_len)) {
            PrintAndLogEx(ERR, "%s and %s specify different key values",
                          primary_name, alias_name);
            return PM3_EINVARG;
        }
        return PM3_SUCCESS;
    }
    memcpy(primary, alias, (size_t)alias_len);
    *primary_len = alias_len;
    return PM3_SUCCESS;
}

static int gp_normalize_auto_auth_options(gp_auto_auth_options_t *options) {
    if (options == NULL) return PM3_EINVARG;
    int ret = gp_merge_auth_key_alias("--enc-key", options->enc, &options->enc_len,
                                      "--key-enc", options->gp_key_enc,
                                      options->gp_key_enc_len);
    if (ret == PM3_SUCCESS)
        ret = gp_merge_auth_key_alias("--mac-key", options->mac, &options->mac_len,
                                      "--key-mac", options->gp_key_mac,
                                      options->gp_key_mac_len);
    if (ret == PM3_SUCCESS)
        ret = gp_merge_auth_key_alias("--dek-key", options->dek, &options->dek_len,
                                      "--key-dek", options->gp_key_dek,
                                      options->gp_key_dek_len);
    return ret;
}

static int gp_append_command_text(char *out, size_t out_size, size_t *offset,
                                  const char *format, ...) {
    if (out == NULL || offset == NULL || format == NULL || *offset >= out_size)
        return PM3_EINVARG;
    va_list args;
    va_start(args, format);
    int written = vsnprintf(out + *offset, out_size - *offset, format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= out_size - *offset)
        return PM3_EINVARG;
    *offset += (size_t)written;
    return PM3_SUCCESS;
}

static int gp_hex_to_text(const uint8_t *data, size_t data_len,
                          char *out, size_t out_size) {
    static const char digits[] = "0123456789ABCDEF";
    if ((data == NULL && data_len != 0) || out == NULL ||
        data_len > (out_size - 1) / 2)
        return PM3_EINVARG;
    for (size_t i = 0; i < data_len; i++) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 0x0F];
    }
    out[2 * data_len] = '\0';
    return PM3_SUCCESS;
}

static int gp_append_auth_hex(char *command, size_t command_size, size_t *offset,
                              const char *option, const uint8_t *value,
                              size_t value_len) {
    if (value_len == 0) return PM3_SUCCESS;
    char hex[2 * GP_MAX_AES_KEY_LEN + 1];
    int ret = gp_hex_to_text(value, value_len, hex, sizeof(hex));
    if (ret != PM3_SUCCESS) return ret;
    return gp_append_command_text(command, command_size, offset,
                                  " %s %s", option, hex);
}

static int gp_build_auth_command(const gp_auto_auth_options_t *options,
                                 bool verbose, char *command,
                                 size_t command_size) {
    if (options == NULL || command == NULL || command_size == 0)
        return PM3_EINVARG;
    if (options->no_auth && (options->reauth || gp_auto_auth_has_overrides(options))) {
        PrintAndLogEx(ERR, "--no-auth cannot be combined with authentication options");
        return PM3_EINVARG;
    }

    size_t offset = 0;
    command[0] = '\0';
    int ret = gp_append_auth_hex(command, command_size, &offset,
                                 "--key", options->master,
                                 (size_t)options->master_len);
    if (ret == PM3_SUCCESS)
        ret = gp_append_auth_hex(command, command_size, &offset,
                                 "--enc-key", options->enc,
                                 (size_t)options->enc_len);
    if (ret == PM3_SUCCESS)
        ret = gp_append_auth_hex(command, command_size, &offset,
                                 "--mac-key", options->mac,
                                 (size_t)options->mac_len);
    if (ret == PM3_SUCCESS)
        ret = gp_append_auth_hex(command, command_size, &offset,
                                 "--dek-key", options->dek,
                                 (size_t)options->dek_len);
    if (ret != PM3_SUCCESS) return ret;

    if (options->kvn != 0)
        if ((ret = gp_append_command_text(command, command_size, &offset,
                                          " --kvn %d", options->kvn)) != PM3_SUCCESS) return ret;
    if (options->kid != 0)
        if ((ret = gp_append_command_text(command, command_size, &offset,
                                          " --kid %d", options->kid)) != PM3_SUCCESS) return ret;
    if (options->security_level != GP_SL_C_DEC_MAC)
        if ((ret = gp_append_command_text(command, command_size, &offset,
                                          " --sl %02X", options->security_level)) != PM3_SUCCESS) return ret;
    if (options->scp != 0)
        if ((ret = gp_append_command_text(command, command_size, &offset,
                                          " --scp %d", options->scp)) != PM3_SUCCESS) return ret;
    if (options->scp_i >= 0)
        if ((ret = gp_append_command_text(command, command_size, &offset,
                                          " --i %02X", options->scp_i)) != PM3_SUCCESS) return ret;
    if (strcmp(options->kdf, "auto") != 0)
        if ((ret = gp_append_command_text(command, command_size, &offset,
                                          " --kdf %s", options->kdf)) != PM3_SUCCESS) return ret;
    if (options->s16)
        if ((ret = gp_append_command_text(command, command_size, &offset,
                                          " --s16")) != PM3_SUCCESS) return ret;
    if (options->s8)
        if ((ret = gp_append_command_text(command, command_size, &offset,
                                          " --s8")) != PM3_SUCCESS) return ret;
    if (options->show_secrets)
        if ((ret = gp_append_command_text(command, command_size, &offset,
                                          " --show-secrets")) != PM3_SUCCESS) return ret;
    if (verbose)
        if ((ret = gp_append_command_text(command, command_size, &offset,
                                          " --verbose")) != PM3_SUCCESS) return ret;
    return PM3_SUCCESS;
}

// Open a secure channel only when needed. Existing sessions are preserved unless
// --reauth is requested. With no key options the established auth command uses
// the same known-key scan as `hf javacard auth` (including the GPPro 40..4F development key).
static int gp_ensure_session_auto(gp_auto_auth_options_t *options,
                                  bool verbose) {
    if (options == NULL) return PM3_EINVARG;
    int normalize_ret = gp_normalize_auto_auth_options(options);
    if (normalize_ret != PM3_SUCCESS) return normalize_ret;
    if (options->no_auth && (options->reauth || gp_auto_auth_has_overrides(options))) {
        PrintAndLogEx(ERR, "--no-auth cannot be combined with authentication options");
        return PM3_EINVARG;
    }
    if (options->no_auth) {
        if (gp_ctx.active) return PM3_SUCCESS;
        PrintAndLogEx(ERR, "No active secure channel and automatic authentication was disabled");
        return PM3_EINVARG;
    }

    if (gp_ctx.active && !options->reauth) {
        if (gp_auto_auth_has_overrides(options)) {
            PrintAndLogEx(WARNING,
                          "An SCP session is already active; authentication overrides were ignored (use --reauth)");
        }
        return PM3_SUCCESS;
    }

    if (gp_ctx.active) gp_drop_field();

    char command[512];
    int ret = gp_build_auth_command(options, verbose, command, sizeof(command));
    if (ret != PM3_SUCCESS) return ret;
    if (!gp_auto_auth_has_overrides(options)) {
        PrintAndLogEx(WARNING,
                      "No authentication keys supplied; trying the known development/default-key database (including 404142...4F)");
    }
    return CmdHFJavaCardAuth(command);
}


//=============================================================================
// Command: hf javacard delete
//=============================================================================

static int CmdHFJavaCardDelete(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard delete",
                  "Delete an Application, Security Domain, or Executable Load File by AID.\n"
                  "Uses the active secure channel, or automatically tries the well-known test key when none is open.\nThe command data is a 4F AID data object.",
                  "hf javacard delete -a A0000000030000 --confirm\n"
                  "hf javacard delete -a A0000000030000 --related --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("a", "aid", "<hex>", "AID to delete (5-16 bytes)"),
        arg_lit0("r", "related", "request deletion of related objects"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t aid[16] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 1, aid, &aid_len);
    bool cascade = arg_get_lit(ctx, 2);
    bool verbose = arg_get_lit(ctx, 3);
    bool confirmed = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (aid_len < 5 || aid_len > 16) {
        PrintAndLogEx(ERR, "AID must be 5-16 bytes");
        return PM3_EINVARG;
    }
    if (!gp_require_confirm(confirmed, "DELETE")) return PM3_EINVARG;
    PrintAndLogEx(WARNING, _RED_("WARNING:") " DELETE can permanently remove executable code and instances.");
    if (gp_ensure_session(verbose) != PM3_SUCCESS) return PM3_ESOFT;

    uint8_t data[18] = {0x4F, (uint8_t)aid_len};
    memcpy(data + 2, aid, (size_t)aid_len);

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    int ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_DELETE,
                              0x00, cascade ? 0x80 : 0x00,
                              data, (size_t)aid_len + 2, false, 0,
                              resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) return ret;
    if (!gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(ERR, "DELETE failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "DELETE accepted for " _CYAN_("%s") ", SW " _GREEN_("%04X"),
                  sprint_hex_inrow(aid, (size_t)aid_len), sw);
    if (resp_len > 0) {
        PrintAndLogEx(INFO, "  Receipt/response (%zu bytes): %s",
                      resp_len, sprint_hex_inrow(resp, resp_len));
    }
    return PM3_SUCCESS;
}



//=============================================================================
// CAP / ZIP parsing helpers (Feature 3)
//=============================================================================

#define ZIP_LOCAL_SIG       0x04034b50UL
#define ZIP_CENTRAL_SIG     0x02014b50UL
#define ZIP_EOCD_SIG        0x06054b50UL
#define ZIP_METHOD_STORED   0
#define ZIP_METHOD_DEFLATE  8
#define GP_MAX_CAP_ARCHIVE_SIZE   (32U * 1024U * 1024U)
#define GP_MAX_CAP_COMPONENT_SIZE (16U * 1024U * 1024U)

// GP component loading order (JCVM spec, Table 6-3)
static const char *GP_CAP_COMPONENT_NAMES[] = {
    "Header.cap",           // 0
    "Directory.cap",        // 1
    "Import.cap",           // 2
    "Applet.cap",           // 3
    "Class.cap",            // 4
    "Method.cap",           // 5
    "StaticField.cap",      // 6
    "Export.cap",           // 7
    "ConstantPool.cap",     // 8
    "RefLocation.cap",      // 9
    "Descriptor.cap",       // 10
    "StaticResources.capx", // 11 (always extended format, even in compact CAPs)
};
#define GP_CAP_COMPONENT_COUNT  12

static uint16_t gp_zip_le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t gp_zip_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

typedef struct {
    uint16_t flags;
    uint16_t method;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint32_t local_offset;
    const uint8_t *name;
    uint16_t name_len;
} gp_zip_entry_t;

static uint32_t gp_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFUL;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xEDB88320UL & (uint32_t)-(int32_t)(crc & 1));
    }
    return ~crc;
}

static int gp_zip_find_directory(const uint8_t *zip_data, size_t zip_len,
                                 size_t *directory_offset, size_t *directory_size,
                                 uint16_t *entry_count, size_t *eocd_offset) {
    if (zip_data == NULL || directory_offset == NULL || directory_size == NULL ||
        entry_count == NULL || eocd_offset == NULL || zip_len < 22)
        return PM3_EINVARG;
    if (zip_len > GP_MAX_CAP_ARCHIVE_SIZE) {
        PrintAndLogEx(ERR, "CAP archive exceeds %u MiB safety limit",
                      GP_MAX_CAP_ARCHIVE_SIZE / (1024U * 1024U));
        return PM3_EFILE;
    }

    size_t minimum = zip_len > 22U + 0xFFFFU ? zip_len - (22U + 0xFFFFU) : 0;
    size_t eocd = SIZE_MAX;
    for (size_t pos = zip_len - 22; ; pos--) {
        if (gp_zip_le32(zip_data + pos) == ZIP_EOCD_SIG) {
            uint16_t comment_len = gp_zip_le16(zip_data + pos + 20);
            if (pos + 22U + comment_len == zip_len) {
                eocd = pos;
                break;
            }
        }
        if (pos == minimum) break;
    }
    if (eocd == SIZE_MAX) {
        PrintAndLogEx(ERR, "CAP: valid ZIP end-of-central-directory record not found");
        return PM3_ESOFT;
    }

    uint16_t disk_number = gp_zip_le16(zip_data + eocd + 4);
    uint16_t directory_disk = gp_zip_le16(zip_data + eocd + 6);
    uint16_t disk_entries = gp_zip_le16(zip_data + eocd + 8);
    uint16_t total_entries = gp_zip_le16(zip_data + eocd + 10);
    uint32_t cd_size = gp_zip_le32(zip_data + eocd + 12);
    uint32_t cd_offset = gp_zip_le32(zip_data + eocd + 16);

    if (disk_number != 0 || directory_disk != 0 || disk_entries != total_entries) {
        PrintAndLogEx(ERR, "CAP: multi-disk ZIP archives are unsupported");
        return PM3_ESOFT;
    }
    if (total_entries == 0xFFFF || cd_size == 0xFFFFFFFFUL || cd_offset == 0xFFFFFFFFUL) {
        PrintAndLogEx(ERR, "CAP: ZIP64 archives are unsupported");
        return PM3_ESOFT;
    }
    if ((size_t)cd_offset > eocd || (size_t)cd_size > eocd - (size_t)cd_offset ||
        (size_t)cd_offset + (size_t)cd_size != eocd) {
        PrintAndLogEx(ERR, "CAP: central-directory bounds are invalid");
        return PM3_ESOFT;
    }

    *directory_offset = cd_offset;
    *directory_size = cd_size;
    *entry_count = total_entries;
    *eocd_offset = eocd;
    return PM3_SUCCESS;
}

static int gp_zip_read_central_entry(const uint8_t *zip_data, size_t zip_len,
                                     size_t directory_end, size_t *offset,
                                     gp_zip_entry_t *entry) {
    if (zip_data == NULL || offset == NULL || entry == NULL ||
        *offset > directory_end || directory_end > zip_len ||
        directory_end - *offset < 46 ||
        gp_zip_le32(zip_data + *offset) != ZIP_CENTRAL_SIG)
        return PM3_ESOFT;

    size_t pos = *offset;
    uint16_t name_len = gp_zip_le16(zip_data + pos + 28);
    uint16_t extra_len = gp_zip_le16(zip_data + pos + 30);
    uint16_t comment_len = gp_zip_le16(zip_data + pos + 32);
    size_t record_len = 46U + name_len + extra_len + comment_len;
    if (record_len > directory_end - pos) return PM3_ESOFT;

    entry->flags = gp_zip_le16(zip_data + pos + 8);
    entry->method = gp_zip_le16(zip_data + pos + 10);
    entry->crc32 = gp_zip_le32(zip_data + pos + 16);
    entry->compressed_size = gp_zip_le32(zip_data + pos + 20);
    entry->uncompressed_size = gp_zip_le32(zip_data + pos + 24);
    entry->name = zip_data + pos + 46;
    entry->name_len = name_len;
    entry->local_offset = gp_zip_le32(zip_data + pos + 42);

    if (entry->compressed_size == 0xFFFFFFFFUL ||
        entry->uncompressed_size == 0xFFFFFFFFUL ||
        entry->local_offset == 0xFFFFFFFFUL)
        return PM3_ESOFT;

    *offset = pos + record_len;
    return PM3_SUCCESS;
}

static int gp_zip_entry_data(const uint8_t *zip_data, size_t zip_len,
                             const gp_zip_entry_t *entry,
                             const uint8_t **compressed_data) {
    if (zip_data == NULL || entry == NULL || compressed_data == NULL)
        return PM3_EINVARG;
    size_t local = entry->local_offset;
    if (local > zip_len || zip_len - local < 30 ||
        gp_zip_le32(zip_data + local) != ZIP_LOCAL_SIG)
        return PM3_ESOFT;

    uint16_t local_flags = gp_zip_le16(zip_data + local + 6);
    uint16_t local_method = gp_zip_le16(zip_data + local + 8);
    uint16_t local_name_len = gp_zip_le16(zip_data + local + 26);
    uint16_t local_extra_len = gp_zip_le16(zip_data + local + 28);
    size_t data_offset = local + 30U + local_name_len + local_extra_len;

    if (local_flags != entry->flags || local_method != entry->method ||
        local_name_len != entry->name_len ||
        memcmp(zip_data + local + 30, entry->name, entry->name_len) != 0 ||
        data_offset > zip_len ||
        entry->compressed_size > zip_len - data_offset)
        return PM3_ESOFT;

    *compressed_data = zip_data + data_offset;
    return PM3_SUCCESS;
}

static int gp_cap_component_index(const uint8_t *name, size_t name_len,
                                  size_t *root_len) {
    if (name == NULL || root_len == NULL) return -1;
    size_t base = name_len;
    while (base > 0 && name[base - 1] != '/') base--;
    *root_len = base;

    for (int i = 0; i < GP_CAP_COMPONENT_COUNT; i++) {
        size_t expected = strlen(GP_CAP_COMPONENT_NAMES[i]);
        if (name_len - base != expected) continue;
        bool equal = true;
        for (size_t j = 0; j < expected; j++) {
            if (tolower((unsigned char)name[base + j]) !=
                tolower((unsigned char)GP_CAP_COMPONENT_NAMES[i][j])) {
                equal = false;
                break;
            }
        }
        if (equal) return i;
    }

    // The normative JCVM filename is RefLocation.cap. Accept the longer
    // non-standard spelling as a compatibility alias for older toolchains.
    static const char legacy_ref_location[] = "ReferenceLocation.cap";
    if (name_len - base == sizeof(legacy_ref_location) - 1) {
        bool equal = true;
        for (size_t j = 0; j < sizeof(legacy_ref_location) - 1; j++) {
            if (tolower((unsigned char)name[base + j]) !=
                tolower((unsigned char)legacy_ref_location[j])) {
                equal = false;
                break;
            }
        }
        if (equal) return 9;
    }
    return -1;
}

static int gp_cap_validate_component(int index, const uint8_t *data, size_t len) {
    static const uint8_t expected_tags[GP_CAP_COMPONENT_COUNT] = {
        0x01, 0x02, 0x04, 0x03, 0x06, 0x07,
        0x08, 0x0A, 0x05, 0x09, 0x0B, 0x0D
    };
    if (index < 0 || index >= GP_CAP_COMPONENT_COUNT || data == NULL)
        return PM3_ESOFT;

    size_t header_len;
    size_t declared;
    if (index == 11) {
        if (len < 5) return PM3_ESOFT;
        header_len = 5;
        declared = ((size_t)data[1] << 24) | ((size_t)data[2] << 16) |
                   ((size_t)data[3] << 8) | data[4];
    } else {
        if (len < 3) return PM3_ESOFT;
        header_len = 3;
        declared = ((size_t)data[1] << 8) | data[2];
    }
    if (data[0] != expected_tags[index] || declared != len - header_len) {
        PrintAndLogEx(ERR, "CAP: %s header/tag/size is inconsistent",
                      GP_CAP_COMPONENT_NAMES[index]);
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}


static int gp_zip_validate_central_directory(const uint8_t *zip_data, size_t zip_len) {
    size_t directory_offset = 0, directory_size = 0, eocd_offset = 0;
    uint16_t entry_count = 0;
    int ret = gp_zip_find_directory(zip_data, zip_len, &directory_offset,
                                    &directory_size, &entry_count, &eocd_offset);
    if (ret != PM3_SUCCESS) return ret;

    size_t offset = directory_offset;
    size_t directory_end = directory_offset + directory_size;
    for (uint16_t i = 0; i < entry_count; i++) {
        gp_zip_entry_t entry;
        ret = gp_zip_read_central_entry(zip_data, zip_len, directory_end,
                                        &offset, &entry);
        if (ret != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "CAP: malformed central-directory entry %u", i + 1);
            return ret;
        }
        if (entry.flags & 0x2041) {
            PrintAndLogEx(ERR, "CAP: encrypted ZIP entries are unsupported");
            return PM3_ESOFT;
        }
        if (entry.method != ZIP_METHOD_STORED &&
            entry.method != ZIP_METHOD_DEFLATE) {
            // Non-CAP resources can use other methods; the loader decides whether they matter.
            continue;
        }
        if (entry.uncompressed_size > GP_MAX_CAP_COMPONENT_SIZE) {
            PrintAndLogEx(ERR, "CAP: ZIP entry exceeds %u MiB safety limit",
                          GP_MAX_CAP_COMPONENT_SIZE / (1024U * 1024U));
            return PM3_EFILE;
        }

        const uint8_t *compressed = NULL;
        if (gp_zip_entry_data(zip_data, zip_len, &entry, &compressed) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "CAP: central entry %u has an invalid local header", i + 1);
            return PM3_ESOFT;
        }
        if (entry.method == ZIP_METHOD_STORED &&
            entry.compressed_size != entry.uncompressed_size) {
            PrintAndLogEx(ERR, "CAP: stored ZIP entry has unequal sizes");
            return PM3_ESOFT;
        }
    }

    if (offset != directory_end || eocd_offset != directory_end) {
        PrintAndLogEx(ERR, "CAP: central-directory size mismatch");
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}



// Parse CAP ZIP file and produce the LOAD FILE DATA BLOCK (concatenated components in order).
// Returns PM3_SUCCESS and fills *out / *out_len; caller must free(*out).
static int gp_cap_zip_parse(const uint8_t *zip_data, size_t zip_len,
                              uint8_t **out, size_t *out_len) {
    if (out == NULL || out_len == NULL) return PM3_EINVARG;
    *out = NULL;
    *out_len = 0;

    int ret = gp_zip_validate_central_directory(zip_data, zip_len);
    if (ret != PM3_SUCCESS) return ret;

    size_t directory_offset = 0, directory_size = 0, eocd_offset = 0;
    uint16_t entry_count = 0;
    ret = gp_zip_find_directory(zip_data, zip_len, &directory_offset,
                                &directory_size, &entry_count, &eocd_offset);
    if (ret != PM3_SUCCESS) return ret;

    uint8_t *component_data[GP_CAP_COMPONENT_COUNT] = {0};
    size_t component_len[GP_CAP_COMPONENT_COUNT] = {0};
    bool component_present[GP_CAP_COMPONENT_COUNT] = {0};
    uint8_t component_root[512] = {0};
    size_t component_root_len = 0;
    size_t total_len = 0;

    size_t offset = directory_offset;
    size_t directory_end = directory_offset + directory_size;
    for (uint16_t entry_no = 0; entry_no < entry_count; entry_no++) {
        gp_zip_entry_t entry;
        ret = gp_zip_read_central_entry(zip_data, zip_len, directory_end,
                                        &offset, &entry);
        if (ret != PM3_SUCCESS) goto cleanup;

        size_t root_len = 0;
        int component = gp_cap_component_index(entry.name, entry.name_len, &root_len);
        if (component < 0) continue;

        if (root_len == 0 || root_len > sizeof(component_root) ||
            root_len < 9 ||
            memcmp(entry.name + root_len - 9, "javacard/", 9) != 0) {
            PrintAndLogEx(ERR, "CAP: component is not inside a javacard/ directory");
            ret = PM3_ESOFT;
            goto cleanup;
        }
        if (component_root_len == 0) {
            memcpy(component_root, entry.name, root_len);
            component_root_len = root_len;
        } else if (root_len != component_root_len ||
                   memcmp(entry.name, component_root, root_len) != 0) {
            PrintAndLogEx(ERR, "CAP: multiple component roots/extended multi-package CAP files are not supported");
            ret = PM3_ESOFT;
            goto cleanup;
        }
        if (component_present[component]) {
            PrintAndLogEx(ERR, "CAP: duplicate %s", GP_CAP_COMPONENT_NAMES[component]);
            ret = PM3_ESOFT;
            goto cleanup;
        }
        if (entry.flags & 0x2041) {
            PrintAndLogEx(ERR, "CAP: encrypted component %s is unsupported",
                          GP_CAP_COMPONENT_NAMES[component]);
            ret = PM3_ESOFT;
            goto cleanup;
        }
        if (entry.method != ZIP_METHOD_STORED &&
            entry.method != ZIP_METHOD_DEFLATE) {
            PrintAndLogEx(ERR, "CAP: unsupported compression method %u for %s",
                          entry.method, GP_CAP_COMPONENT_NAMES[component]);
            ret = PM3_ESOFT;
            goto cleanup;
        }
        size_t minimum_component_size = component == 11 ? 5 : 3;
        if (entry.uncompressed_size < minimum_component_size ||
            entry.uncompressed_size > GP_MAX_CAP_COMPONENT_SIZE ||
            entry.uncompressed_size > SIZE_MAX - total_len ||
            total_len + entry.uncompressed_size > GP_MAX_CAP_ARCHIVE_SIZE) {
            PrintAndLogEx(ERR, "CAP: unsafe component size for %s",
                          GP_CAP_COMPONENT_NAMES[component]);
            ret = PM3_EFILE;
            goto cleanup;
        }

        const uint8_t *compressed = NULL;
        ret = gp_zip_entry_data(zip_data, zip_len, &entry, &compressed);
        if (ret != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "CAP: invalid local header for %s",
                          GP_CAP_COMPONENT_NAMES[component]);
            goto cleanup;
        }

        uint8_t *decoded = malloc(entry.uncompressed_size);
        if (decoded == NULL) {
            ret = PM3_EMALLOC;
            goto cleanup;
        }
        if (entry.method == ZIP_METHOD_STORED) {
            if (entry.compressed_size != entry.uncompressed_size) {
                free(decoded);
                ret = PM3_ESOFT;
                goto cleanup;
            }
            memcpy(decoded, compressed, entry.uncompressed_size);
        } else {
#ifdef HAVE_ZLIB
            ret = gp_zip_inflate_raw(compressed, entry.compressed_size,
                                     decoded, entry.uncompressed_size);
            if (ret != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "CAP: decompression failed for %s",
                              GP_CAP_COMPONENT_NAMES[component]);
                free(decoded);
                goto cleanup;
            }
#else
            PrintAndLogEx(ERR, "CAP: %s is deflated but this build has no zlib support",
                          GP_CAP_COMPONENT_NAMES[component]);
            free(decoded);
            ret = PM3_ESOFT;
            goto cleanup;
#endif
        }

        if (gp_crc32(decoded, entry.uncompressed_size) != entry.crc32) {
            PrintAndLogEx(ERR, "CAP: CRC mismatch for %s",
                          GP_CAP_COMPONENT_NAMES[component]);
            free(decoded);
            ret = PM3_ESOFT;
            goto cleanup;
        }
        ret = gp_cap_validate_component(component, decoded, entry.uncompressed_size);
        if (ret != PM3_SUCCESS) {
            free(decoded);
            goto cleanup;
        }

        component_data[component] = decoded;
        component_len[component] = entry.uncompressed_size;
        component_present[component] = true;
        total_len += entry.uncompressed_size;
    }

    // Header, Directory, Import, Class, Method, StaticField, ConstantPool,
    // and RefLocation are mandatory for a compact CAP file. Applet,
    // Export, Descriptor and StaticResources are optional/conditional.
    static const int mandatory[] = {0, 1, 2, 4, 5, 6, 8, 9};
    for (size_t i = 0; i < ARRAYLEN(mandatory); i++) {
        int component = mandatory[i];
        if (!component_present[component]) {
            PrintAndLogEx(ERR, "CAP: mandatory %s is missing",
                          GP_CAP_COMPONENT_NAMES[component]);
            ret = PM3_ESOFT;
            goto cleanup;
        }
    }

    uint8_t *joined = malloc(total_len);
    if (joined == NULL) {
        ret = PM3_EMALLOC;
        goto cleanup;
    }
    // Java Card VM reference install order puts Static Resources immediately
    // before the optional Descriptor component. Debug is intentionally absent.
    static const int load_order[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 10};
    size_t joined_len = 0;
    for (size_t oi = 0; oi < ARRAYLEN(load_order); oi++) {
        int component = load_order[oi];
        if (!component_present[component]) continue;
        memcpy(joined + joined_len, component_data[component], component_len[component]);
        joined_len += component_len[component];
    }

    *out = joined;
    *out_len = joined_len;
    ret = PM3_SUCCESS;

cleanup:
    for (int i = 0; i < GP_CAP_COMPONENT_COUNT; i++) {
        if (component_data[i] != NULL) {
            gp_secure_zero(component_data[i], component_len[i]);
            free(component_data[i]);
        }
    }
    return ret;
}



// Build a GlobalPlatform C4 Load File Data Block TLV wrapper.
// Caller must free *out.
static int gp_build_c4_lfdb(const uint8_t *ijc, size_t ijc_len,
                             uint8_t **out, size_t *out_len) {
    if (ijc == NULL || out == NULL || out_len == NULL) return PM3_EINVARG;
    if (ijc_len > 0xFFFF) return PM3_EINVARG;

    size_t llen = (ijc_len <= 0x7F) ? 1 : (ijc_len <= 0xFF) ? 2 : 3;
    *out_len = 1 + llen + ijc_len;
    *out = malloc(*out_len);
    if (*out == NULL) return PM3_EMALLOC;

    size_t off = 0;
    (*out)[off++] = 0xC4;
    if (ijc_len <= 0x7F) {
        (*out)[off++] = (uint8_t)ijc_len;
    } else if (ijc_len <= 0xFF) {
        (*out)[off++] = 0x81;
        (*out)[off++] = (uint8_t)ijc_len;
    } else {
        (*out)[off++] = 0x82;
        (*out)[off++] = (uint8_t)(ijc_len >> 8);
        (*out)[off++] = (uint8_t)ijc_len;
    }
    memcpy(*out + off, ijc, ijc_len);
    return PM3_SUCCESS;
}

static size_t gp_max_wrapped_command_data(void) {
    if (!gp_ctx.active || gp_ctx.security_level == GP_SL_NO_SECURITY)
        return GP_MAX_SHORT_APDU_DATA;

    bool encrypted = (gp_ctx.security_level & 0x02) != 0;
    size_t mac_len = gp_ctx.scp_version == 3 ? gp_ctx.mac_len : 8;
    if (!encrypted) return GP_MAX_SHORT_APDU_DATA - mac_len;

    size_t block_size = gp_ctx.scp_version == 3 ? 16 : 8;
    size_t available = GP_MAX_SHORT_APDU_DATA - mac_len;
    size_t encrypted_len = available - (available % block_size);
    if (encrypted_len == 0) return 0;

    // ISO 7816 padding always consumes at least one byte. SCP01 additionally
    // prepends a clear-length byte before padding.
    size_t overhead = gp_ctx.scp_version == 1 ? 2 : 1;
    return encrypted_len > overhead ? encrypted_len - overhead : 0;
}

static int gp_cap_extract_package_aid(const uint8_t *ijc, size_t ijc_len,
                                      uint8_t aid[16], size_t *aid_len) {
    if (ijc == NULL || aid == NULL || aid_len == NULL) return PM3_EINVARG;
    size_t offset = 0;
    while (offset < ijc_len) {
        if (ijc_len - offset < 3) return PM3_ESOFT;
        uint16_t payload_len = (uint16_t)(((uint16_t)ijc[offset + 1] << 8) | ijc[offset + 2]);
        size_t component_len = (size_t)payload_len + 3;
        if (component_len > ijc_len - offset) return PM3_ESOFT;
        if (ijc[offset] == 0x01) {
            if (payload_len < 10 ||
                memcmp(ijc + offset + 3, "\xDE\xCA\xFF\xED", 4) != 0)
                return PM3_ESOFT;
            uint8_t len = ijc[offset + 3 + 9];
            if (len < 5 || len > 16 || (size_t)len > payload_len - 10)
                return PM3_ESOFT;
            memcpy(aid, ijc + offset + 3 + 10, len);
            *aid_len = len;
            return PM3_SUCCESS;
        }
        offset += component_len;
    }
    return PM3_ESOFT;
}

static int gp_append_ber_tlv(uint8_t *out, size_t out_size, size_t *offset,
                             uint8_t tag, const uint8_t *value, size_t value_len) {
    if (out == NULL || offset == NULL || (value == NULL && value_len != 0))
        return PM3_EINVARG;
    size_t len_size = gp_ber_length_size(value_len);
    if (len_size == 0 || *offset > out_size ||
        1 + len_size > out_size - *offset ||
        value_len > out_size - *offset - 1 - len_size)
        return PM3_EINVARG;

    out[(*offset)++] = tag;
    size_t written = 0;
    int ret = gp_ber_write_length(out + *offset, out_size - *offset,
                                  value_len, &written);
    if (ret != PM3_SUCCESS) return ret;
    *offset += written;
    if (value_len != 0) {
        memcpy(out + *offset, value, value_len);
        *offset += value_len;
    }
    return PM3_SUCCESS;
}

// Append a GlobalPlatform LV field. AID and privilege lengths are one-byte
// values; variable parameter/token fields use BER definite-length encoding.
static int gp_append_lv(uint8_t *out, size_t out_size, size_t *offset,
                        const uint8_t *value, size_t value_len,
                        bool ber_length) {
    if (out == NULL || offset == NULL || (value == NULL && value_len != 0))
        return PM3_EINVARG;
    if (*offset > out_size) return PM3_EINVARG;

    size_t length_size = ber_length ? gp_ber_length_size(value_len) : 1;
    if (length_size == 0 || (!ber_length && value_len > UINT8_MAX) ||
        length_size > out_size - *offset ||
        value_len > out_size - *offset - length_size)
        return PM3_EINVARG;

    if (ber_length) {
        size_t written = 0;
        int ret = gp_ber_write_length(out + *offset, out_size - *offset,
                                      value_len, &written);
        if (ret != PM3_SUCCESS) return ret;
        *offset += written;
    } else {
        out[(*offset)++] = (uint8_t)value_len;
    }

    if (value_len != 0) {
        memcpy(out + *offset, value, value_len);
        *offset += value_len;
    }
    return PM3_SUCCESS;
}

static void gp_print_install_confirmation(const uint8_t *resp, size_t resp_len) {
    if (resp == NULL || resp_len == 0) return;
    if (resp_len == 1 && resp[0] == 0x00) return;
    PrintAndLogEx(INFO, "  Confirmation / receipt (%zu bytes): %s",
                  resp_len, sprint_hex_inrow(resp, resp_len));
}



//=============================================================================
// Command: hf javacard load  (INSTALL [for load] + LOAD blocks)
//=============================================================================

static int CmdHFJavaCardLoad(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard load",
                  "Load a compact CAP/JAR or flat IJC file.\n"
                  "The package AID is extracted from Header.cap; -p may be used to verify/override only when it matches.\n"
                  "INSTALL [for load] supports an optional hash, load parameters, load token, and BER-encoded DAP block.",
                  "hf javacard load -f app.cap --confirm\n"
                  "hf javacard load -f app.cap -p A000000003000001 -s A0000000030000 --confirm\n"
                  "hf javacard load -f app.cap --hash <hex> --params <hex> --token <hex> --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<path>", "Compact CAP/JAR/ZIP or flat IJC file"),
        arg_str0("p", "pkg", "<hex>", "Expected package AID (5-16 bytes)"),
        arg_str0("s", "sd", "<hex>", "Associated Security Domain AID (default: current SD)"),
        arg_str0(NULL, "hash", "<hex>", "Load File Data Block hash"),
        arg_str0(NULL, "params", "<hex>", "Load parameters"),
        arg_str0(NULL, "token", "<hex>", "Load token"),
        arg_str0(NULL, "dap", "<hex>", "DAP signature bytes"),
        arg_str0(NULL, "dap-sd", "<hex>", "DAP Security Domain AID (default: ISD)"),
        GP_AUTO_AUTH_ARGTABLE,
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_int0(NULL, "block", "<dec>", "max data bytes per LOAD block, 16-255 (default: largest that fits)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    char filename[256] = {0};
    int filename_len = sizeof(filename) - 1;
    CLIGetStrWithReturn(ctx, 1, (uint8_t *)filename, &filename_len);
    uint8_t requested_pkg[16] = {0}, sd_aid[16] = {0}, dap_sd[16] = {0};
    int requested_pkg_len = 0, sd_aid_len = 0, dap_sd_len = 0;
    uint8_t hash[255] = {0}, params[255] = {0}, token[255] = {0}, dap[255] = {0};
    int hash_len = 0, params_len = 0, token_len = 0, dap_len = 0;
    CLIGetHexWithReturn(ctx, 2, requested_pkg, &requested_pkg_len);
    CLIGetHexWithReturn(ctx, 3, sd_aid, &sd_aid_len);
    CLIGetHexWithReturn(ctx, 4, hash, &hash_len);
    CLIGetHexWithReturn(ctx, 5, params, &params_len);
    CLIGetHexWithReturn(ctx, 6, token, &token_len);
    CLIGetHexWithReturn(ctx, 7, dap, &dap_len);
    CLIGetHexWithReturn(ctx, 8, dap_sd, &dap_sd_len);
    gp_auto_auth_options_t auth_options;
    GP_PARSE_AUTO_AUTH(ctx, 9, auth_options);
    bool verbose = arg_get_lit(ctx, 9 + GP_AUTO_AUTH_ARG_COUNT);
    bool confirmed = arg_get_lit(ctx, 9 + GP_AUTO_AUTH_ARG_COUNT + 1);
    int max_block = arg_get_int_def(ctx, 9 + GP_AUTO_AUTH_ARG_COUNT + 2, 0);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "load")) return PM3_EINVARG;
    if (max_block != 0 && (max_block < 16 || max_block > 255)) {
        PrintAndLogEx(ERR, "--block must be 16-255");
        return PM3_EINVARG;
    }

    if ((requested_pkg_len != 0 && (requested_pkg_len < 5 || requested_pkg_len > 16)) ||
        (sd_aid_len != 0 && (sd_aid_len < 5 || sd_aid_len > 16)) ||
        (dap_sd_len != 0 && (dap_sd_len < 5 || dap_sd_len > 16))) {
        PrintAndLogEx(ERR, "All supplied AIDs must be 5-16 bytes");
        gp_secure_zero(&auth_options, sizeof(auth_options));
        return PM3_EINVARG;
    }
    if (dap_len == 0 && dap_sd_len != 0) {
        PrintAndLogEx(ERR, "--dap-sd requires --dap");
        gp_secure_zero(&auth_options, sizeof(auth_options));
        return PM3_EINVARG;
    }
    uint8_t *raw = NULL, *ijc_alloc = NULL, *c4 = NULL, *lfdb = NULL;
    size_t raw_len = 0, ijc_len = 0, c4_len = 0, lfdb_len = 0;
    int ret = PM3_SUCCESS;

    if (loadFile_safe(filename, "", (void **)&raw, &raw_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Cannot read file: %s", filename);
        ret = PM3_EFILE;
        goto cleanup;
    }
    if (raw_len == 0 || raw_len > GP_MAX_CAP_ARCHIVE_SIZE) {
        PrintAndLogEx(ERR, "Input is empty or exceeds the %u MiB safety limit",
                      GP_MAX_CAP_ARCHIVE_SIZE / (1024U * 1024U));
        ret = PM3_EFILE;
        goto cleanup;
    }

    const uint8_t *ijc = raw;
    ijc_len = raw_len;
    if (raw_len >= 4 && gp_zip_le32(raw) == ZIP_LOCAL_SIG) {
        ret = gp_cap_zip_parse(raw, raw_len, &ijc_alloc, &ijc_len);
        if (ret != PM3_SUCCESS) goto cleanup;
        ijc = ijc_alloc;
    }

    uint8_t package_aid[16] = {0};
    size_t package_aid_len = 0;
    ret = gp_cap_extract_package_aid(ijc, ijc_len, package_aid, &package_aid_len);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Cannot extract a valid package AID from Header.cap");
        goto cleanup;
    }
    if (requested_pkg_len != 0 &&
        ((size_t)requested_pkg_len != package_aid_len ||
         memcmp(requested_pkg, package_aid, package_aid_len) != 0)) {
        PrintAndLogEx(ERR, "Requested package AID does not match Header.cap");
        PrintAndLogEx(INFO, "  Header.cap: %s",
                      sprint_hex_inrow(package_aid, package_aid_len));
        ret = PM3_EINVARG;
        goto cleanup;
    }

    ret = gp_build_c4_lfdb(ijc, ijc_len, &c4, &c4_len);
    if (ret != PM3_SUCCESS) goto cleanup;

    if (dap_len != 0) {
        uint8_t e2_body[512] = {0};
        size_t e2_body_len = 0;
        const uint8_t *signer = dap_sd_len != 0 ? dap_sd : GP_ISD_AID;
        size_t signer_len = dap_sd_len != 0 ? (size_t)dap_sd_len : GP_ISD_AID_LEN;
        ret = gp_append_ber_tlv(e2_body, sizeof(e2_body), &e2_body_len,
                                0x4F, signer, signer_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_ber_tlv(e2_body, sizeof(e2_body), &e2_body_len,
                                    0xC3, dap, (size_t)dap_len);
        size_t e2_len_size = gp_ber_length_size(e2_body_len);
        if (ret != PM3_SUCCESS || e2_len_size == 0 ||
            e2_body_len > SIZE_MAX - c4_len - 1 - e2_len_size) {
            ret = PM3_EINVARG;
            goto cleanup;
        }

        lfdb_len = 1 + e2_len_size + e2_body_len + c4_len;
        lfdb = malloc(lfdb_len);
        if (lfdb == NULL) {
            ret = PM3_EMALLOC;
            goto cleanup;
        }
        size_t offset = 0, written = 0;
        lfdb[offset++] = 0xE2;
        ret = gp_ber_write_length(lfdb + offset, lfdb_len - offset,
                                  e2_body_len, &written);
        if (ret != PM3_SUCCESS) goto cleanup;
        offset += written;
        memcpy(lfdb + offset, e2_body, e2_body_len);
        offset += e2_body_len;
        memcpy(lfdb + offset, c4, c4_len);
    } else {
        lfdb = c4;
        lfdb_len = c4_len;
        c4 = NULL;
    }

    uint8_t install_data[768] = {0};
    size_t install_len = 0;
#define GP_APPEND_LEN_VALUE(value_, value_len_) do { \
        size_t _n = (size_t)(value_len_); \
        if (_n > 255 || install_len > sizeof(install_data) - 1 - _n) { \
            ret = PM3_EINVARG; \
            goto cleanup; \
        } \
        install_data[install_len++] = (uint8_t)_n; \
        if (_n != 0) { memcpy(install_data + install_len, (value_), _n); install_len += _n; } \
    } while (0)
    GP_APPEND_LEN_VALUE(package_aid, package_aid_len);
    GP_APPEND_LEN_VALUE(sd_aid, sd_aid_len);
    GP_APPEND_LEN_VALUE(hash, hash_len);
    GP_APPEND_LEN_VALUE(params, params_len);
    GP_APPEND_LEN_VALUE(token, token_len);
#undef GP_APPEND_LEN_VALUE

    // Validate the complete local input before touching the card. This prevents
    // an invalid CAP/archive from causing an unnecessary authentication attempt.
    ret = gp_ensure_session_auto(&auth_options, verbose);
    gp_secure_zero(&auth_options, sizeof(auth_options));
    if (ret != PM3_SUCCESS) goto cleanup;

    size_t max_command_data = gp_max_wrapped_command_data();
    if (install_len > max_command_data) {
        PrintAndLogEx(ERR, "INSTALL [for load] data (%zu bytes) exceeds secure-channel short-APDU limit (%zu)",
                      install_len, max_command_data);
        ret = PM3_EINVARG;
        goto cleanup;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("LOAD") " ---");
    PrintAndLogEx(INFO, "  File:             %s", filename);
    PrintAndLogEx(INFO, "  Package AID:      %s",
                  sprint_hex_inrow(package_aid, package_aid_len));
    PrintAndLogEx(INFO, "  IJC bytes:        %zu", ijc_len);
    PrintAndLogEx(INFO, "  Load-file block:  %zu", lfdb_len);
    clearCommandBuffer();

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_INSTALL,
                          GP_INSTALL_P1_LOAD, 0x00,
                          install_data, install_len, true, 0x100,
                          resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) goto cleanup;
    if (!gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(ERR, "INSTALL [for load] failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        ret = PM3_ESOFT;
        goto cleanup;
    }
    PrintAndLogEx(SUCCESS, "INSTALL [for load] accepted, SW " _GREEN_("%04X"), sw);
    if (resp_len > 0)
        PrintAndLogEx(INFO, "  Receipt/response: %s", sprint_hex_inrow(resp, resp_len));

    size_t block_size = gp_max_wrapped_command_data();
    if (max_block > 0 && (size_t)max_block < block_size) block_size = (size_t)max_block;
    if (verbose) PrintAndLogEx(INFO, "  LOAD block data:  %zu bytes", block_size);
    if (block_size == 0 || lfdb_len > block_size * 256U) {
        PrintAndLogEx(ERR, "Load file requires more than 256 short-APDU LOAD blocks");
        ret = PM3_EINVARG;
        goto cleanup;
    }

    size_t offset = 0;
    unsigned block = 0, slowest_block = 0;
    uint64_t slowest_ms = 0, load_started = msclock();
    while (offset < lfdb_len) {
        size_t chunk = lfdb_len - offset;
        if (chunk > block_size) chunk = block_size;
        bool last = chunk == lfdb_len - offset;
        ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_LOAD,
                              last ? 0x80 : 0x00, (uint8_t)block,
                              lfdb + offset, chunk, true, 0x100,
                              resp, sizeof(resp), &resp_len, &sw, verbose);
        if (ret != PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(ERR, "LOAD block %u: transport error (%d) after %zu/%zu bytes", block, ret, offset, lfdb_len);
            PrintAndLogEx(INFO, "  The secure channel is lost; the card discards an incomplete load file.");
            if (!gp_link.last_failure_was_reset)
                PrintAndLogEx(HINT, "Hint: the card stopped answering; check its placement and retry (autoinstall retries automatically)");
            goto cleanup;
        }
        if (!gp_sw_is_success_or_warning(sw)) {
            PrintAndLogEx(ERR, "LOAD block %u failed, SW: " _RED_("%04X") " - %s",
                          block, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
            ret = PM3_ESOFT;
            goto cleanup;
        }
        if (gp_last_exchange_ms > slowest_ms) {
            slowest_ms = gp_last_exchange_ms;
            slowest_block = block;
        }
        offset += chunk;
        block++;
        PrintAndLogEx(INPLACE, "  Loading... %zu/%zu bytes (%u block%s)",
                      offset, lfdb_len, block, block == 1 ? "" : "s");
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "LOAD complete (%u blocks, %" PRIu64 " ms; slowest block %u took %" PRIu64 " ms)",
                  block, msclock() - load_started, slowest_block, slowest_ms);

cleanup:
    gp_secure_zero(&auth_options, sizeof(auth_options));
    gp_secure_zero(hash, sizeof(hash));
    gp_secure_zero(params, sizeof(params));
    gp_secure_zero(token, sizeof(token));
    gp_secure_zero(dap, sizeof(dap));
    if (lfdb != NULL) {
        gp_secure_zero(lfdb, lfdb_len);
        free(lfdb);
    }
    if (c4 != NULL) {
        gp_secure_zero(c4, c4_len);
        free(c4);
    }
    if (ijc_alloc != NULL) {
        gp_secure_zero(ijc_alloc, ijc_len);
        free(ijc_alloc);
    }
    free(raw);
    return ret;
}



//=============================================================================
// Command: hf javacard install  (INSTALL [for install + make selectable])
//=============================================================================

static int CmdHFJavaCardInstall(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard install",
                  "Instantiate an applet from an already-loaded package.\n"
                  "By default this sends INSTALL [for install and make selectable] (P1=0C).\n"
                  "Use --install-only for P1=04; install parameters and an optional token are passed verbatim.",
                  "hf javacard install -p A000000003000001 -m A0000000030000010001 -i A0000000030000010001 --confirm\n"
                  "hf javacard install -p <aid> -m <aid> -i <aid> --priv 04 --param C900 --token <hex> --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pkg", "<hex>", "Package / Executable Load File AID"),
        arg_str1("m", "module", "<hex>", "Executable Module AID"),
        arg_str1("i", "instance", "<hex>", "New Application instance AID"),
        arg_str0(NULL, "priv", "<hex>", "Privilege bytes (1 or 3 bytes; default 00)"),
        arg_str0(NULL, "param", "<hex>", "Install parameters (default C900)"),
        arg_str0(NULL, "token", "<hex>", "Install token"),
        arg_lit0(NULL, "install-only", "send INSTALL [for install] without make-selectable"),
        GP_AUTO_AUTH_ARGTABLE,
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t pkg[16] = {0}, module[16] = {0}, instance[16] = {0};
    int pkg_len = 0, module_len = 0, instance_len = 0;
    CLIGetHexWithReturn(ctx, 1, pkg, &pkg_len);
    CLIGetHexWithReturn(ctx, 2, module, &module_len);
    CLIGetHexWithReturn(ctx, 3, instance, &instance_len);
    uint8_t privileges[3] = {0};
    int privileges_len = 0;
    CLIGetHexWithReturn(ctx, 4, privileges, &privileges_len);
    uint8_t parameters[255] = {0};
    int parameters_len = 0;
    CLIGetHexWithReturn(ctx, 5, parameters, &parameters_len);
    uint8_t token[255] = {0};
    int token_len = 0;
    CLIGetHexWithReturn(ctx, 6, token, &token_len);
    bool install_only = arg_get_lit(ctx, 7);
    gp_auto_auth_options_t auth_options;
    GP_PARSE_AUTO_AUTH(ctx, 8, auth_options);
    bool verbose = arg_get_lit(ctx, 8 + GP_AUTO_AUTH_ARG_COUNT);
    bool confirmed = arg_get_lit(ctx, 8 + GP_AUTO_AUTH_ARG_COUNT + 1);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "install")) return PM3_EINVARG;

    if (pkg_len < 5 || pkg_len > 16 ||
        module_len < 5 || module_len > 16 ||
        instance_len < 5 || instance_len > 16) {
        PrintAndLogEx(ERR, "Package, module, and instance AIDs must be 5-16 bytes");
        gp_secure_zero(&auth_options, sizeof(auth_options));
        return PM3_EINVARG;
    }
    if (privileges_len == 0) {
        privileges[0] = 0x00;
        privileges_len = 1;
    }
    if (privileges_len != 1 && privileges_len != 3) {
        PrintAndLogEx(ERR, "Privileges must contain exactly 1 or 3 bytes");
        gp_secure_zero(&auth_options, sizeof(auth_options));
        return PM3_EINVARG;
    }
    if (parameters_len == 0) {
        parameters[0] = 0xC9;
        parameters[1] = 0x00;
        parameters_len = 2;
    }
    int auth_ret = gp_ensure_session_auto(&auth_options, verbose);
    gp_secure_zero(&auth_options, sizeof(auth_options));
    if (auth_ret != PM3_SUCCESS) return auth_ret;

    uint8_t data[640] = {0};
    size_t data_len = 0;
#define GP_INSTALL_FIELD(value_, length_) do { \
        size_t _len = (size_t)(length_); \
        if (_len > 255 || data_len > sizeof(data) - 1 - _len) { \
            gp_secure_zero(token, sizeof(token)); \
            return PM3_EINVARG; \
        } \
        data[data_len++] = (uint8_t)_len; \
        if (_len != 0) { memcpy(data + data_len, (value_), _len); data_len += _len; } \
    } while (0)
    GP_INSTALL_FIELD(pkg, pkg_len);
    GP_INSTALL_FIELD(module, module_len);
    GP_INSTALL_FIELD(instance, instance_len);
    GP_INSTALL_FIELD(privileges, privileges_len);
    GP_INSTALL_FIELD(parameters, parameters_len);
    GP_INSTALL_FIELD(token, token_len);
#undef GP_INSTALL_FIELD

    size_t max_data = gp_max_wrapped_command_data();
    if (data_len > max_data) {
        PrintAndLogEx(ERR, "INSTALL data (%zu bytes) exceeds secure-channel short-APDU limit (%zu)",
                      data_len, max_data);
        gp_secure_zero(token, sizeof(token));
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("INSTALL") " ---");
    PrintAndLogEx(INFO, "  Package:  %s", sprint_hex_inrow(pkg, (size_t)pkg_len));
    PrintAndLogEx(INFO, "  Module:   %s", sprint_hex_inrow(module, (size_t)module_len));
    PrintAndLogEx(INFO, "  Instance: %s", sprint_hex_inrow(instance, (size_t)instance_len));
    clearCommandBuffer();

    uint8_t response[GP_RESP_BUF_SIZE] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;
    int ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_INSTALL,
                              install_only ? GP_INSTALL_P1_INSTALL
                                           : GP_INSTALL_P1_INSTALL_SELECTABLE,
                              0x00, data, data_len, true, 0x100,
                              response, sizeof(response), &response_len, &sw, verbose);
    gp_secure_zero(token, sizeof(token));
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "INSTALL: transport error (%d); no status word was received", ret);
        PrintAndLogEx(INFO, "  Applet constructors that allocate keys can outlast the reader's reply timeout,");
        PrintAndLogEx(INFO, "  so the instance may or may not have been created.");
        PrintAndLogEx(HINT, "Hint: check with `" _YELLOW_("hf javacard list --auth --apps") "`, then retry or delete");
        return ret;
    }
    if (!gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(ERR, "INSTALL failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "INSTALL accepted for %s, SW " _GREEN_("%04X") " (%" PRIu64 " ms)",
                  sprint_hex_inrow(instance, (size_t)instance_len), sw, gp_last_exchange_ms);
    if (response_len > 0)
        PrintAndLogEx(INFO, "  Receipt/response: %s",
                      sprint_hex_inrow(response, response_len));
    return PM3_SUCCESS;
}


//=============================================================================
// CAP-driven automatic loading and installation
//=============================================================================

#define GP_MAX_CAP_APPLETS 64

typedef struct {
    uint8_t aid[16];
    size_t aid_len;
    uint16_t install_method_offset;
} gp_cap_applet_t;

static int gp_cap_extract_applets(const uint8_t *ijc, size_t ijc_len,
                                  gp_cap_applet_t *applets,
                                  size_t applets_capacity,
                                  size_t *applet_count) {
    if (ijc == NULL || applets == NULL || applet_count == NULL)
        return PM3_EINVARG;
    *applet_count = 0;

    size_t offset = 0;
    while (offset < ijc_len) {
        if (ijc_len - offset < 3) return PM3_ESOFT;
        uint8_t tag = ijc[offset];
        size_t header_len = tag == 0x0D ? 5 : 3;
        if (ijc_len - offset < header_len) return PM3_ESOFT;
        size_t payload_len = tag == 0x0D
            ? ((size_t)ijc[offset + 1] << 24) |
              ((size_t)ijc[offset + 2] << 16) |
              ((size_t)ijc[offset + 3] << 8) |
              ijc[offset + 4]
            : ((size_t)ijc[offset + 1] << 8) | ijc[offset + 2];
        if (payload_len > ijc_len - offset - header_len) return PM3_ESOFT;

        if (tag == 0x03) {
            const uint8_t *payload = ijc + offset + header_len;
            if (payload_len < 1) return PM3_ESOFT;
            size_t count = payload[0];
            if (count > applets_capacity) {
                PrintAndLogEx(ERR, "CAP declares %zu applets; limit is %zu",
                              count, applets_capacity);
                return PM3_EINVARG;
            }
            size_t pos = 1;
            for (size_t i = 0; i < count; i++) {
                if (pos >= payload_len) return PM3_ESOFT;
                uint8_t aid_len = payload[pos++];
                if (aid_len < 5 || aid_len > 16 ||
                    (size_t)aid_len + 2 > payload_len - pos)
                    return PM3_ESOFT;
                memcpy(applets[i].aid, payload + pos, aid_len);
                applets[i].aid_len = aid_len;
                pos += aid_len;
                applets[i].install_method_offset =
                    (uint16_t)(((uint16_t)payload[pos] << 8) | payload[pos + 1]);
                pos += 2;
            }
            if (pos != payload_len) {
                PrintAndLogEx(WARNING,
                              "Applet.cap contains %zu trailing byte(s)",
                              payload_len - pos);
            }
            *applet_count = count;
            return PM3_SUCCESS;
        }
        offset += header_len + payload_len;
    }
    return PM3_SUCCESS; // library CAP: no Applet component
}

static int gp_cap_read_metadata(const char *filename,
                                uint8_t package_aid[16],
                                size_t *package_aid_len,
                                gp_cap_applet_t *applets,
                                size_t applets_capacity,
                                size_t *applet_count) {
    if (filename == NULL || package_aid == NULL || package_aid_len == NULL ||
        applets == NULL || applet_count == NULL)
        return PM3_EINVARG;

    uint8_t *raw = NULL;
    uint8_t *flat_alloc = NULL;
    size_t raw_len = 0;
    size_t flat_len = 0;
    int ret = PM3_SUCCESS;

    if (loadFile_safe(filename, "", (void **)&raw, &raw_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Cannot read file: %s", filename);
        return PM3_EFILE;
    }
    if (raw_len == 0 || raw_len > GP_MAX_CAP_ARCHIVE_SIZE) {
        ret = PM3_EFILE;
        goto cleanup;
    }

    const uint8_t *flat = raw;
    flat_len = raw_len;
    if (raw_len >= 4 && gp_zip_le32(raw) == ZIP_LOCAL_SIG) {
        ret = gp_cap_zip_parse(raw, raw_len, &flat_alloc, &flat_len);
        if (ret != PM3_SUCCESS) goto cleanup;
        flat = flat_alloc;
    }

    ret = gp_cap_extract_package_aid(flat, flat_len,
                                     package_aid, package_aid_len);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Cannot extract the package AID from Header.cap");
        goto cleanup;
    }
    ret = gp_cap_extract_applets(flat, flat_len, applets,
                                 applets_capacity, applet_count);

cleanup:
    if (flat_alloc != NULL) {
        gp_secure_zero(flat_alloc, flat_len);
        free(flat_alloc);
    }
    if (raw != NULL) {
        gp_secure_zero(raw, raw_len);
        free(raw);
    }
    return ret;
}

static int gp_append_cli_quoted(char *command, size_t command_size,
                                size_t *offset, const char *option,
                                const char *value) {
    if (command == NULL || offset == NULL || option == NULL || value == NULL)
        return PM3_EINVARG;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        if (*p == '"' || *p == '\r' || *p == '\n') {
            PrintAndLogEx(ERR, "Unsupported character in command-line path/value");
            return PM3_EINVARG;
        }
    }
    return gp_append_command_text(command, command_size, offset,
                                  " %s \"%s\"", option, value);
}

static int gp_append_cli_hex(char *command, size_t command_size,
                             size_t *offset, const char *option,
                             const uint8_t *value, size_t value_len) {
    if (value_len == 0) return PM3_SUCCESS;
    if (value_len > 255) return PM3_EINVARG;
    char hex[511];
    int ret = gp_hex_to_text(value, value_len, hex, sizeof(hex));
    if (ret != PM3_SUCCESS) return ret;
    return gp_append_command_text(command, command_size, offset,
                                  " %s %s", option, hex);
}

static bool gp_aid_equal(const uint8_t *left, size_t left_len,
                         const uint8_t *right, size_t right_len) {
    return left_len == right_len && left != NULL && right != NULL &&
           memcmp(left, right, left_len) == 0;
}

static int CmdHFJavaCardAutoInstall(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard autoinstall",
                  "Parse a compact CAP, authenticate when needed, load it, and instantiate its applet.\n"
                  "For a single-applet CAP the module and instance AIDs default to Applet.cap.\n"
                  "Multi-applet CAPs require --applet, --applet-index, or --all. Library CAPs are loaded only.\n"
                  "The Java Card normative filename RefLocation.cap is accepted "
                  "(legacy ReferenceLocation.cap is also accepted).\n"
                  "GPPro key aliases --key-enc/--key-mac/--key-dek are accepted "
                  "alongside native spellings.",
                  "hf javacard autoinstall -f app.cap --dry-run\n"
                  "hf javacard autoinstall -f app.cap --confirm\n"
                  "hf javacard autoinstall -f app.cap -k 404142434445464748494A4B4C4D4E4F --confirm\n"
                  "hf javacard autoinstall -f multi.cap --applet-index 2 --instance A000000151010201 --confirm\n"
                  "hf javacard autoinstall -f app.cap --default --params C900 --dry-run");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<path>", "Compact CAP/JAR/ZIP or flat IJC file"),
        arg_str0("a", "applet", "<hex>", "Applet/module AID to instantiate"),
        arg_int0(NULL, "applet-index", "<dec>", "1-based Applet.cap entry to instantiate"),
        arg_str0(NULL, "instance", "<hex>", "Application instance AID (default: selected applet AID)"),
        arg_lit0(NULL, "all", "instantiate every applet declared in Applet.cap"),
        arg_lit0(NULL, "load-only", "load the CAP without creating an applet instance"),
        arg_lit0(NULL, "create-only", "skip loading and only instantiate from an already-loaded package"),
        arg_lit0(NULL, "no-make-selectable", "use INSTALL [for install] rather than install-and-make-selectable"),
        arg_str0(NULL, "priv", "<hex>", "Application privilege bytes (1 or 3 bytes; default 00)"),
        arg_lit0(NULL, "default", "add Default Selected / Card Reset privilege (bit 04)"),
        arg_str0(NULL, "params", "<hex>", "Application install parameters (default C900)"),
        arg_str0(NULL, "token", "<hex>", "Application install token"),
        arg_str0("s", "sd", "<hex>", "Associated Security Domain AID for loading"),
        arg_str0(NULL, "hash", "<hex>", "Load File Data Block hash"),
        arg_str0(NULL, "load-params", "<hex>", "INSTALL [for load] parameters"),
        arg_str0(NULL, "load-token", "<hex>", "INSTALL [for load] token"),
        arg_str0(NULL, "dap", "<hex>", "DAP signature bytes"),
        arg_str0(NULL, "dap-sd", "<hex>", "DAP Security Domain AID (default ISD)"),
        arg_lit0(NULL, "dry-run", "parse the CAP and print the proposed operations without card I/O"),
        GP_AUTO_AUTH_ARGTABLE,
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_int0(NULL, "block", "<dec>", "max data bytes per LOAD block, 16-255 (passed to load)"),
        arg_int0(NULL, "retries", "<dec>", "restart LOAD this many times after a transport error (default 2)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    char filename[256] = {0};
    int filename_len = sizeof(filename) - 1;
    CLIGetStrWithReturn(ctx, 1, (uint8_t *)filename, &filename_len);
    uint8_t requested_applet[16] = {0}, instance[16] = {0}, privileges[3] = {0};
    uint8_t install_params[255] = {0}, install_token[255] = {0};
    uint8_t sd_aid[16] = {0}, hash[255] = {0}, load_params[255] = {0};
    uint8_t load_token[255] = {0}, dap[255] = {0}, dap_sd[16] = {0};
    int requested_applet_len = 0, instance_len = 0, privileges_len = 0;
    int install_params_len = 0, install_token_len = 0, sd_aid_len = 0;
    int hash_len = 0, load_params_len = 0, load_token_len = 0;
    int dap_len = 0, dap_sd_len = 0;
    CLIGetHexWithReturn(ctx, 2, requested_applet, &requested_applet_len);
    int applet_index = arg_get_int_def(ctx, 3, 0);
    CLIGetHexWithReturn(ctx, 4, instance, &instance_len);
    bool install_all = arg_get_lit(ctx, 5);
    bool load_only = arg_get_lit(ctx, 6);
    bool create_only = arg_get_lit(ctx, 7);
    bool no_make_selectable = arg_get_lit(ctx, 8);
    CLIGetHexWithReturn(ctx, 9, privileges, &privileges_len);
    bool make_default = arg_get_lit(ctx, 10);
    CLIGetHexWithReturn(ctx, 11, install_params, &install_params_len);
    CLIGetHexWithReturn(ctx, 12, install_token, &install_token_len);
    CLIGetHexWithReturn(ctx, 13, sd_aid, &sd_aid_len);
    CLIGetHexWithReturn(ctx, 14, hash, &hash_len);
    CLIGetHexWithReturn(ctx, 15, load_params, &load_params_len);
    CLIGetHexWithReturn(ctx, 16, load_token, &load_token_len);
    CLIGetHexWithReturn(ctx, 17, dap, &dap_len);
    CLIGetHexWithReturn(ctx, 18, dap_sd, &dap_sd_len);
    bool dry_run = arg_get_lit(ctx, 19);
    gp_auto_auth_options_t auth_options;
    GP_PARSE_AUTO_AUTH(ctx, 20, auth_options);
    bool verbose = arg_get_lit(ctx, 20 + GP_AUTO_AUTH_ARG_COUNT);
    bool confirmed = arg_get_lit(ctx, 20 + GP_AUTO_AUTH_ARG_COUNT + 1);
    int max_block = arg_get_int_def(ctx, 20 + GP_AUTO_AUTH_ARG_COUNT + 2, 0);
    int load_retries = arg_get_int_def(ctx, 20 + GP_AUTO_AUTH_ARG_COUNT + 3, 2);
    CLIParserFree(ctx);
    if (load_retries < 0 || load_retries > 10) {
        PrintAndLogEx(ERR, "--retries must be 0-10");
        return PM3_EINVARG;
    }
    if (!dry_run && !gp_require_confirm(confirmed, "autoinstall")) return PM3_EINVARG;

    int ret = PM3_EINVARG;
    if (load_only && create_only) {
        PrintAndLogEx(ERR, "--load-only and --create-only are mutually exclusive");
        goto cleanup;
    }
    if (install_all && (requested_applet_len != 0 || applet_index != 0 ||
                        instance_len != 0 || make_default)) {
        PrintAndLogEx(ERR, "--all cannot be combined with --applet, --applet-index, --instance, or --default");
        goto cleanup;
    }
    if (requested_applet_len != 0 && applet_index != 0) {
        PrintAndLogEx(ERR, "Use either --applet or --applet-index, not both");
        goto cleanup;
    }
    if ((requested_applet_len != 0 && (requested_applet_len < 5 || requested_applet_len > 16)) ||
        (instance_len != 0 && (instance_len < 5 || instance_len > 16)) ||
        (sd_aid_len != 0 && (sd_aid_len < 5 || sd_aid_len > 16)) ||
        (dap_sd_len != 0 && (dap_sd_len < 5 || dap_sd_len > 16))) {
        PrintAndLogEx(ERR, "All supplied AIDs must be 5-16 bytes");
        goto cleanup;
    }
    if (dap_sd_len != 0 && dap_len == 0) {
        PrintAndLogEx(ERR, "--dap-sd requires --dap");
        goto cleanup;
    }
    if (privileges_len == 0) {
        privileges[0] = 0x00;
        privileges_len = 1;
    }
    if (privileges_len != 1 && privileges_len != 3) {
        PrintAndLogEx(ERR, "Privileges must contain exactly 1 or 3 bytes");
        goto cleanup;
    }
    if (make_default) privileges[0] |= 0x04;
    if (install_params_len == 0) {
        install_params[0] = 0xC9;
        install_params[1] = 0x00;
        install_params_len = 2;
    }

    uint8_t package_aid[16] = {0};
    size_t package_aid_len = 0;
    gp_cap_applet_t applets[GP_MAX_CAP_APPLETS] = {0};
    size_t applet_count = 0;
    ret = gp_cap_read_metadata(filename, package_aid, &package_aid_len,
                               applets, ARRAYLEN(applets), &applet_count);
    if (ret != PM3_SUCCESS) goto cleanup;

    PrintAndLogEx(INFO, "--- " _CYAN_("AUTOINSTALL PLAN") " ---");
    PrintAndLogEx(INFO, "  File:        %s", filename);
    PrintAndLogEx(INFO, "  Package AID: %s",
                  sprint_hex_inrow(package_aid, package_aid_len));
    PrintAndLogEx(INFO, "  Applets:     %zu", applet_count);
    for (size_t i = 0; i < applet_count; i++) {
        PrintAndLogEx(INFO, "    [%zu] %s (install offset %04X)", i + 1,
                      sprint_hex_inrow(applets[i].aid, applets[i].aid_len),
                      applets[i].install_method_offset);
    }

    size_t selected_indices[GP_MAX_CAP_APPLETS] = {0};
    size_t selected_count = 0;
    if (!load_only && applet_count != 0) {
        if (install_all) {
            for (size_t i = 0; i < applet_count; i++) selected_indices[selected_count++] = i;
        } else if (requested_applet_len != 0) {
            for (size_t i = 0; i < applet_count; i++) {
                if (gp_aid_equal(requested_applet, (size_t)requested_applet_len,
                                 applets[i].aid, applets[i].aid_len)) {
                    selected_indices[selected_count++] = i;
                    break;
                }
            }
            if (selected_count == 0) {
                PrintAndLogEx(ERR, "Requested applet AID is not declared in Applet.cap");
                ret = PM3_EINVARG;
                goto cleanup;
            }
        } else if (applet_index != 0) {
            if (applet_index < 1 || (size_t)applet_index > applet_count) {
                PrintAndLogEx(ERR, "--applet-index must be between 1 and %zu", applet_count);
                ret = PM3_EINVARG;
                goto cleanup;
            }
            selected_indices[selected_count++] = (size_t)applet_index - 1;
        } else if (applet_count == 1) {
            selected_indices[selected_count++] = 0;
        } else {
            PrintAndLogEx(ERR,
                          "CAP contains multiple applets; choose --applet, --applet-index, or --all");
            ret = PM3_EINVARG;
            goto cleanup;
        }
    }

    if (instance_len != 0 && selected_count != 1) {
        PrintAndLogEx(ERR, "--instance requires exactly one selected applet");
        ret = PM3_EINVARG;
        goto cleanup;
    }
    for (size_t i = 0; i < selected_count; i++) {
        const gp_cap_applet_t *applet = &applets[selected_indices[i]];
        const uint8_t *instance_aid = instance_len != 0 ? instance : applet->aid;
        size_t selected_instance_len = instance_len != 0 ? (size_t)instance_len : applet->aid_len;
        PrintAndLogEx(INFO, "  Install #%zu: module=%s", i + 1,
                      sprint_hex_inrow(applet->aid, applet->aid_len));
        PrintAndLogEx(INFO, "               instance=%s",
                      sprint_hex_inrow(instance_aid, selected_instance_len));
    }
    if (applet_count == 0 && !load_only)
        PrintAndLogEx(INFO, "  No Applet.cap: library CAP will only be loaded");
    if (dry_run) {
        PrintAndLogEx(SUCCESS, "Dry run complete; no card commands were sent");
        ret = PM3_SUCCESS;
        goto cleanup;
    }

    ret = gp_ensure_session_auto(&auth_options, verbose);
    if (ret != PM3_SUCCESS) goto cleanup;

    if (!create_only) {
        char load_command[2048] = {0};
        size_t load_offset = 0;
        ret = gp_append_cli_quoted(load_command, sizeof(load_command), &load_offset,
                                   "--file", filename);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(load_command, sizeof(load_command), &load_offset,
                                    "--pkg", package_aid, package_aid_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(load_command, sizeof(load_command), &load_offset,
                                    "--sd", sd_aid, (size_t)sd_aid_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(load_command, sizeof(load_command), &load_offset,
                                    "--hash", hash, (size_t)hash_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(load_command, sizeof(load_command), &load_offset,
                                    "--params", load_params, (size_t)load_params_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(load_command, sizeof(load_command), &load_offset,
                                    "--token", load_token, (size_t)load_token_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(load_command, sizeof(load_command), &load_offset,
                                    "--dap", dap, (size_t)dap_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(load_command, sizeof(load_command), &load_offset,
                                    "--dap-sd", dap_sd, (size_t)dap_sd_len);
        if (ret == PM3_SUCCESS && max_block > 0)
            ret = gp_append_command_text(load_command, sizeof(load_command), &load_offset,
                                         " --block %d", max_block);
        if (ret == PM3_SUCCESS)
            ret = gp_append_command_text(load_command, sizeof(load_command), &load_offset,
                                         " --no-auth --confirm%s", verbose ? " --verbose" : "");
        if (ret != PM3_SUCCESS) goto cleanup;
        // A transport error mid-LOAD leaves the card with an incomplete load file
        // that it discards, and breaks the secure channel. Restart the whole load
        // in a fresh session. Card status-word errors (PM3_ESOFT) are final.
        for (int attempt = 0;; attempt++) {
            ret = CmdHFJavaCardLoad(load_command);
            if (ret == PM3_SUCCESS || ret == PM3_ESOFT || ret == PM3_EINVARG || attempt >= load_retries)
                break;
            PrintAndLogEx(WARNING, "Restarting LOAD from the first block (retry %d of %d)", attempt + 1, load_retries);
            gp_drop_field();
            msleep(300);
            ret = gp_ensure_session_auto(&auth_options, verbose);
            if (ret != PM3_SUCCESS) break;
        }
        if (ret != PM3_SUCCESS) goto cleanup;
    }

    if (load_only || applet_count == 0)
        goto success;

    for (size_t i = 0; i < selected_count; i++) {
        const gp_cap_applet_t *applet = &applets[selected_indices[i]];
        const uint8_t *instance_aid = instance_len != 0 ? instance : applet->aid;
        size_t selected_instance_len = instance_len != 0 ? (size_t)instance_len : applet->aid_len;
        char install_command[2048] = {0};
        size_t install_offset = 0;
        ret = gp_append_cli_hex(install_command, sizeof(install_command), &install_offset,
                                "--pkg", package_aid, package_aid_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(install_command, sizeof(install_command), &install_offset,
                                    "--module", applet->aid, applet->aid_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(install_command, sizeof(install_command), &install_offset,
                                    "--instance", instance_aid, selected_instance_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(install_command, sizeof(install_command), &install_offset,
                                    "--priv", privileges, (size_t)privileges_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(install_command, sizeof(install_command), &install_offset,
                                    "--param", install_params, (size_t)install_params_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_cli_hex(install_command, sizeof(install_command), &install_offset,
                                    "--token", install_token, (size_t)install_token_len);
        if (ret == PM3_SUCCESS)
            ret = gp_append_command_text(install_command, sizeof(install_command), &install_offset,
                                         " --no-auth --confirm%s%s",
                                         no_make_selectable ? " --install-only" : "",
                                         verbose ? " --verbose" : "");
        if (ret != PM3_SUCCESS) goto cleanup;
        ret = CmdHFJavaCardInstall(install_command);
        if (ret != PM3_SUCCESS) goto cleanup;
    }

success:
    PrintAndLogEx(SUCCESS, "AUTOINSTALL complete");
    ret = PM3_SUCCESS;

cleanup:
    if (ret != PM3_SUCCESS && !dry_run)
        PrintAndLogEx(FAILED, "AUTOINSTALL " _RED_("failed") " (%d); inspect the card with `"
                      _YELLOW_("hf javacard list --auth") "`", ret);
    gp_secure_zero(&auth_options, sizeof(auth_options));
    gp_secure_zero(requested_applet, sizeof(requested_applet));
    gp_secure_zero(instance, sizeof(instance));
    gp_secure_zero(privileges, sizeof(privileges));
    gp_secure_zero(install_params, sizeof(install_params));
    gp_secure_zero(install_token, sizeof(install_token));
    gp_secure_zero(hash, sizeof(hash));
    gp_secure_zero(load_params, sizeof(load_params));
    gp_secure_zero(load_token, sizeof(load_token));
    gp_secure_zero(dap, sizeof(dap));
    return ret;
}


//=============================================================================
// Command: hf javacard putkey  (PUT KEY - Feature 4)
//=============================================================================

static int CmdHFJavaCardPutKey(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard putkey",
                  "Add or replace a three-key TDEA key set.\n"
                  "Uses an active SCP01/SCP02 channel, or automatically tries the well-known test key. New key values are protected with DEK.\n"
                  "For replacement, P1 is the OLD KVN and the first data byte is the NEW KVN.",
                  "hf javacard putkey -k 404142434445464748494A4B4C4D4E4F --kvn 2 --confirm\n"
                  "hf javacard putkey -k <hex> --old-kvn 1 --kvn 2 --kid 1 --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "New 16-byte TDEA key used for ENC/MAC/DEK"),
        arg_str0(NULL, "enc", "<hex>", "New 16-byte ENC key"),
        arg_str0(NULL, "mac", "<hex>", "New 16-byte MAC key"),
        arg_str0(NULL, "dek", "<hex>", "New 16-byte DEK key"),
        arg_int1(NULL, "kvn", "<dec>", "New Key Version Number (1-127)"),
        arg_int0(NULL, "old-kvn", "<dec>", "Existing KVN to replace; 0 adds a new set"),
        arg_int0(NULL, "kid", "<dec>", "First Key Identifier (default 1; three consecutive IDs)"),
        arg_lit0(NULL, "replace", "compatibility alias: use new KVN as old KVN unless --old-kvn is set"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t same_key[16] = {0}, enc[16] = {0}, mac[16] = {0}, dek[16] = {0};
    int same_len = 0, enc_len = 0, mac_len = 0, dek_len = 0;
    CLIGetHexWithReturn(ctx, 1, same_key, &same_len);
    CLIGetHexWithReturn(ctx, 2, enc, &enc_len);
    CLIGetHexWithReturn(ctx, 3, mac, &mac_len);
    CLIGetHexWithReturn(ctx, 4, dek, &dek_len);
    int new_kvn = arg_get_int(ctx, 5);
    int old_kvn = arg_get_int_def(ctx, 6, 0);
    int first_kid = arg_get_int_def(ctx, 7, 1);
    bool replace_alias = arg_get_lit(ctx, 8);
    bool verbose = arg_get_lit(ctx, 9);
    bool confirmed = arg_get_lit(ctx, 10);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "PUT KEY")) return PM3_EINVARG;

    if (replace_alias && old_kvn == 0) old_kvn = new_kvn;
    if (new_kvn < 1 || new_kvn > 0x7F || old_kvn < 0 || old_kvn > 0x7F) {
        PrintAndLogEx(ERR, "New KVN must be 1-127 and old KVN must be 0-127");
        return PM3_EINVARG;
    }
    if (first_kid < 1 || first_kid > 0x7D) {
        PrintAndLogEx(ERR, "First KID must be 1-125 for a three-key set");
        return PM3_EINVARG;
    }

    uint8_t keyset[3][16] = {{0}};
    if (same_len == 16 && enc_len == 0 && mac_len == 0 && dek_len == 0) {
        memcpy(keyset[0], same_key, 16);
        memcpy(keyset[1], same_key, 16);
        memcpy(keyset[2], same_key, 16);
    } else if (same_len == 0 && enc_len == 16 && mac_len == 16 && dek_len == 16) {
        memcpy(keyset[0], enc, 16);
        memcpy(keyset[1], mac, 16);
        memcpy(keyset[2], dek, 16);
    } else {
        PrintAndLogEx(ERR, "Use either one 16-byte -k value or all three 16-byte --enc/--mac/--dek values");
        gp_secure_zero(keyset, sizeof(keyset));
        return PM3_EINVARG;
    }

    PrintAndLogEx(WARNING, _RED_("WARNING:") " PUT KEY modifies card authentication keys.");
    PrintAndLogEx(INFO, "  Operation: %s KVN %d, first KID %d, new KVN %d",
                  old_kvn ? "replace" : "add", old_kvn, first_kid, new_kvn);
    if (gp_ensure_session(verbose) != PM3_SUCCESS) {
        gp_secure_zero(keyset, sizeof(keyset));
        return PM3_ESOFT;
    }
    if (gp_ctx.scp_version != 1 && gp_ctx.scp_version != 2) {
        PrintAndLogEx(ERR, "TDEA PUT KEY requires an SCP01 or SCP02 session");
        gp_secure_zero(keyset, sizeof(keyset));
        return PM3_EINVARG;
    }

    uint8_t wrapped[3][16] = {{0}};
    uint8_t kcv[3][8] = {{0}};
    uint8_t zero8[8] = {0};
    int ret = PM3_SUCCESS;
    for (size_t i = 0; i < 3; i++) {
        // GPC v2.3.1 Annex E.4.6 / E.5.x: secret key components are encrypted
        // with the DEK in TDEA *ECB* mode, block by block.
        ret = gp_scp02_encrypt_key_component(gp_ctx.dek_key, keyset[i], wrapped[i]);
        if (ret != PM3_SUCCESS ||
            gp_des3_ecb_enc(keyset[i], 16, zero8, kcv[i]) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "TDEA key protection or KCV calculation failed");
            ret = PM3_ESOFT;
            goto cleanup;
        }
    }

    PrintAndLogEx(INFO, "  KCV ENC=%02X%02X%02X MAC=%02X%02X%02X DEK=%02X%02X%02X",
                  kcv[0][0], kcv[0][1], kcv[0][2],
                  kcv[1][0], kcv[1][1], kcv[1][2],
                  kcv[2][0], kcv[2][1], kcv[2][2]);

    uint8_t data[96] = {0};
    size_t data_len = 0;
    data[data_len++] = (uint8_t)new_kvn;
    for (size_t i = 0; i < 3; i++) {
        data[data_len++] = 0x80;  // DES/TDEA secret key
        data[data_len++] = 0x10;  // encrypted key component block length
        memcpy(data + data_len, wrapped[i], 16);
        data_len += 16;
        data[data_len++] = 0x03;
        memcpy(data + data_len, kcv[i], 3);
        data_len += 3;
    }

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_PUT_KEY,
                          (uint8_t)old_kvn, (uint8_t)(0x80 | first_kid),
                          data, data_len, true, 0x100,
                          resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "PUT KEY communication or secure-messaging error");
        goto cleanup;
    }
    if (!gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(ERR, "PUT KEY failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        ret = PM3_ESOFT;
        goto cleanup;
    }

    PrintAndLogEx(SUCCESS, "PUT KEY accepted: new KVN %d, SW " _GREEN_("%04X"), new_kvn, sw);
    if (resp_len > 0)
        PrintAndLogEx(INFO, "  Card response: %s", sprint_hex_inrow(resp, resp_len));
    ret = PM3_SUCCESS;

cleanup:
    gp_secure_zero(same_key, sizeof(same_key));
    gp_secure_zero(enc, sizeof(enc));
    gp_secure_zero(mac, sizeof(mac));
    gp_secure_zero(dek, sizeof(dek));
    gp_secure_zero(keyset, sizeof(keyset));
    gp_secure_zero(wrapped, sizeof(wrapped));
    gp_secure_zero(kcv, sizeof(kcv));
    return ret;
}



//=============================================================================
// Command: hf javacard setstatus  (SET STATUS - Feature 5)
//=============================================================================

static int CmdHFJavaCardSetStatus(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard setstatus",
                  "Change the life-cycle state of the card, an Application, or a Security Domain.\n"
                  "Uses the active secure channel, or automatically tries the well-known test key. This is a dangerous administrative command.\n\n"
                  "P1 target codes defined by GlobalPlatform:\n"
                  "  80 = Issuer Security Domain / card\n"
                  "  40 = Application or Security Domain by AID\n"
                  "  60 = Security Domain and its directly/indirectly associated Applications\n\n"
                  "For P1=40 or 60, the data field is the raw target AID (no length prefix).\n"
                  "P2 is the requested life-cycle state; valid transitions depend on the target and card.",
                  "hf javacard setstatus --p1 40 --state 80 -a A0000000030000 --confirm\n"
                  "hf javacard setstatus --p1 40 --state 00 -a A0000000030000 --confirm\n"
                  "hf javacard setstatus --p1 80 --state 7F --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "p1",    "<hex>", "80=card/ISD, 40=app/SD, 60=SD hierarchy"),
        arg_str1(NULL, "state", "<hex>", "Requested life-cycle state byte"),
        arg_str0("a",  "aid",   "<hex>", "Target AID (required for P1=40 or 60)"),
        arg_lit0("v",  "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int p1_val, state;
    GP_HEX_OPTION_OR_RETURN(ctx, 1, -1, p1_val);
    GP_HEX_OPTION_OR_RETURN(ctx, 2, -1, state);
    uint8_t aid[16] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 3, aid, &aid_len);
    bool verbose = arg_get_lit(ctx, 4);
    bool confirmed = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (p1_val != 0x80 && p1_val != 0x40 && p1_val != 0x60) {
        PrintAndLogEx(ERR, "P1 must be 80, 40, or 60");
        return PM3_EINVARG;
    }
    if (state < 0 || state > 0xFF) {
        PrintAndLogEx(ERR, "Life-cycle state must be one byte");
        return PM3_EINVARG;
    }
    if (p1_val == 0x80) {
        if (aid_len != 0) {
            PrintAndLogEx(ERR, "P1=80 addresses the card/ISD and must not include an AID");
            return PM3_EINVARG;
        }
    } else if (aid_len < 5 || aid_len > 16) {
        PrintAndLogEx(ERR, "P1=%02X requires a 5-16 byte target AID", p1_val);
        return PM3_EINVARG;
    }

    if (!gp_require_confirm(confirmed, "SET STATUS")) return PM3_EINVARG;
    PrintAndLogEx(WARNING, _RED_("WARNING:") " SET STATUS can make card content inaccessible or terminate it.");
    if (gp_ensure_session(verbose) != PM3_SUCCESS) return PM3_ESOFT;

    clearCommandBuffer();
    PrintAndLogEx(INFO, "--- " _CYAN_("SET STATUS") " P1=%02X P2=%02X%s%s ---",
                  p1_val, state, aid_len ? " AID=" : "",
                  aid_len ? sprint_hex_inrow(aid, (size_t)aid_len) : "");

    uint8_t resp[GP_RESP_BUF_SIZE];
    size_t resp_len = 0;
    uint16_t sw = 0;
    int ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_SET_STATUS,
                              (uint8_t)p1_val, (uint8_t)state,
                              aid_len ? aid : NULL, (size_t)aid_len, false, 0,
                              resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "SET STATUS communication or secure-messaging error");
        return ret;
    }

    if (gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(SUCCESS, "SET STATUS accepted, SW " _GREEN_("%04X"), sw);
        if (p1_val == 0x80 || p1_val == 0x60) {
            // The selected Security Domain or its hierarchy may have changed state.
            gp_drop_field();
        }
        return PM3_SUCCESS;
    }

    PrintAndLogEx(ERR, "SET STATUS failed, SW: " _RED_("%04X") " - %s",
                  sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
    return PM3_ESOFT;
}



//=============================================================================
// Short APDU parser for send -w
typedef struct {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    const uint8_t *data;
    size_t data_len;
    bool has_le;
    uint16_t le;
} gp_short_apdu_t;

static int gp_parse_short_apdu(const uint8_t *raw, size_t raw_len, gp_short_apdu_t *out) {
    if (raw == NULL || out == NULL || raw_len < 4) return PM3_EINVARG;
    memset(out, 0, sizeof(*out));
    out->cla = raw[0]; out->ins = raw[1]; out->p1 = raw[2]; out->p2 = raw[3];
    if (raw_len == 4) return PM3_SUCCESS;
    if (raw_len == 5) {
        out->has_le = true;
        out->le = raw[4] == 0x00 ? 0x100 : raw[4];
        return PM3_SUCCESS;
    }
    uint8_t lc = raw[4];
    if (lc == 0x00) {
        PrintAndLogEx(ERR, "Extended APDUs are not supported");
        return PM3_EINVARG;
    }
    if (raw_len != (size_t)(5 + lc) && raw_len != (size_t)(6 + lc)) {
        PrintAndLogEx(ERR, "Malformed short APDU: len=%zu, Lc=%u", raw_len, lc);
        return PM3_EINVARG;
    }
    out->data = raw + 5;
    out->data_len = lc;
    if (raw_len == (size_t)(6 + lc)) {
        out->has_le = true;
        out->le = raw[5 + lc] == 0x00 ? 0x100 : raw[5 + lc];
    }
    return PM3_SUCCESS;
}

// Command: hf javacard send  (raw APDU)
//=============================================================================

static int CmdHFJavaCardSend(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard send",
                  "Send a raw APDU to the card. Optionally wrap with the active session.",
                  "hf javacard send -d 00A4040008A000000151000000\n"
                  "hf javacard send -d 80F2400002 4F00 -w   -> wrapped GET STATUS");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data",    "<hex>", "Full APDU bytes"),
        arg_lit0("s", "select",  "activate field and select card first"),
        arg_lit0("k", "keep",    "keep field on after response"),
        arg_lit0("w", "wrap",    "wrap with active session C-MAC"),
        arg_lit0("t", "tlv",     "decode TLV in response"),
        arg_lit0("v", "verbose", "show APDU structure, wrapping and timing"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t apdu_raw[PM3_CMD_DATA_SIZE]; int apdu_len = 0;
    CLIGetHexWithReturn(ctx, 1, apdu_raw, &apdu_len);
    bool activate  = arg_get_lit(ctx, 2);
    bool leave_on  = arg_get_lit(ctx, 3);
    bool do_wrap   = arg_get_lit(ctx, 4);
    bool decode_tlv= arg_get_lit(ctx, 5);
    bool verbose   = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);
    if (verbose) {
        gp_short_apdu_t shown;
        if (gp_parse_short_apdu(apdu_raw, (size_t)apdu_len, &shown) == PM3_SUCCESS) {
            PrintAndLogEx(INFO, "  CLA %02X  INS %02X  P1 %02X  P2 %02X  Lc %zu  Le %s", shown.cla, shown.ins,
                          shown.p1, shown.p2, shown.data_len, shown.has_le ? "present" : "absent");
            PrintAndLogEx(INFO, "  Case %d short APDU; CLA %s, logical channel %u%s", shown.data_len ? (shown.has_le ? 4 : 3) : (shown.has_le ? 2 : 1),
                          (shown.cla & 0x80) ? "proprietary (GP)" : "interindustry",
                          shown.cla & 0x03, (shown.cla & 0x04) ? ", secure messaging bit set" : "");
        } else {
            PrintAndLogEx(INFO, "  Not a well-formed short APDU; sent as raw bytes");
        }
    }

    if (apdu_len < 4) { PrintAndLogEx(ERR, "APDU must be at least 4 bytes"); return PM3_EINVARG; }
    clearCommandBuffer();

    uint8_t resp[GP_RESP_BUF_SIZE]; size_t resp_len = 0; uint16_t sw = 0;
    if (do_wrap) {
        if (!gp_ctx.active) {
            PrintAndLogEx(ERR, "No active secure channel. Run 'hf javacard auth' first.");
            gp_drop_field();
            return PM3_EINVARG;
        }
        gp_short_apdu_t parsed;
        int ret = gp_parse_short_apdu(apdu_raw, (size_t)apdu_len, &parsed);
        if (ret != PM3_SUCCESS) { gp_drop_field(); return ret; }
        ret = gp_wrapped_apdu(activate, leave_on,
                              parsed.cla, parsed.ins, parsed.p1, parsed.p2,
                              parsed.data, parsed.data_len,
                              parsed.has_le, parsed.le,
                              resp, sizeof(resp), &resp_len, &sw, verbose);
        if (ret != PM3_SUCCESS) return ret;
    } else {
        PrintAndLogEx(INFO, ">>> %s", sprint_hex_inrow(apdu_raw, (size_t)apdu_len));
        int ret = gp_send_apdu(activate, leave_on, apdu_raw, (size_t)apdu_len, resp, sizeof(resp), &resp_len, &sw, false);
        if (ret != PM3_SUCCESS) return ret;
    }
    if (verbose) {
        PrintAndLogEx(INFO, "  Exchange took %" PRIu64 " ms", gp_last_exchange_ms);
        if (gp_link.valid)
            PrintAndLogEx(INFO, "  Link: FSC %u, FWI %u (FWT %.2f ms), listen window %.1f ms", gp_link.fsc, gp_link.fwi,
                          gp_link.fwt_fc * 1000.0 / GP_FC_HZ, gp_link.reader_timeout_etu * (double)GP_ETU_FC * 1000.0 / GP_FC_HZ);
    }

    PrintAndLogEx(SUCCESS, "<<< %s | SW: " _YELLOW_("%04X") " - %s",
                  sprint_hex_inrow(resp, resp_len), sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
    if (decode_tlv && resp_len > 0) gp_print_tlv(resp, resp_len);
    if (!leave_on) gp_drop_field();
    return PM3_SUCCESS;
}

//=============================================================================
// Command: hf javacard getdata
//=============================================================================

static int CmdHFJavaCardGetData(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard getdata",
                  "Send GET DATA. By default the ISD is selected first; use --current only when\n"
                  "a prior command intentionally kept the field and selection active.",
                  "hf javacard getdata --tag 9F7F --tlv\n"
                  "hf javacard getdata --tag 00E0 --wrap\n"
                  "hf javacard getdata --tag 0066 --current");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "tag", "<hex>", "two-byte tag"),
        arg_lit0("w", "wrap", "use the active secure channel"),
        arg_lit0(NULL, "current", "do not activate or select the ISD"),
        arg_lit0("k", "keep", "keep RF field on after the response"),
        arg_lit0("t", "tlv", "decode response TLV"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t tag[2] = {0};
    int tag_len = 0;
    CLIGetHexWithReturn(ctx, 1, tag, &tag_len);
    bool wrap = arg_get_lit(ctx, 2);
    bool current = arg_get_lit(ctx, 3);
    bool keep = arg_get_lit(ctx, 4);
    bool decode_tlv = arg_get_lit(ctx, 5);
    bool verbose = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (tag_len != 2) {
        PrintAndLogEx(ERR, "Tag must be exactly two bytes");
        return PM3_EINVARG;
    }
    if (wrap && !gp_ctx.active) {
        PrintAndLogEx(ERR, "--wrap requires an active secure channel");
        return PM3_EINVARG;
    }
    // The session lives in the currently selected security domain; selecting the
    // ISD again would end it, so a wrapped request always targets the current one
    // and leaves the field (and therefore the session) up.
    if (wrap) {
        current = true;
        keep = true;
    }

    clearCommandBuffer();
    uint16_t sw = 0;
    int ret = PM3_SUCCESS;
    if (!current) {
        ret = gp_select_isd(true, true, &sw, verbose);
        if (ret != PM3_SUCCESS || !gp_sw_is_success_or_warning(sw)) {
            gp_drop_field();
            return ret == PM3_SUCCESS ? PM3_ESOFT : ret;
        }
    }

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    if (wrap) {
        ret = gp_wrapped_apdu(false, keep, GP_CLA_PLAIN, GP_INS_GET_DATA,
                              tag[0], tag[1], NULL, 0, true, 0x100,
                              resp, sizeof(resp), &resp_len, &sw, verbose);
    } else {
        ret = gp_plain_apdu(false, keep, GP_CLA_PLAIN, GP_INS_GET_DATA,
                            tag[0], tag[1], NULL, 0, true, 0x100,
                            resp, sizeof(resp), &resp_len, &sw, verbose);
    }
    if (ret != PM3_SUCCESS) return ret;
    if (!gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(ERR, "GET DATA [%02X%02X] failed, SW: " _RED_("%04X") " - %s",
                      tag[0], tag[1], sw,
                      GetAPDUCodeDescription((uint8_t)(sw >> 8), (uint8_t)sw));
        if (keep) gp_drop_field();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "GET DATA [%02X%02X], SW %04X: %s",
                  tag[0], tag[1], sw, sprint_hex_inrow(resp, resp_len));
    if (decode_tlv && resp_len != 0) gp_print_tlv(resp, resp_len);
    return PM3_SUCCESS;
}



//=============================================================================
// Command: hf javacard kcv  (Key Check Value display - Feature 9)
//=============================================================================

static int gp_print_kcv(const char *label, const uint8_t *key, size_t key_len,
                        bool show_tdea, bool show_aes) {
    if (label == NULL || key == NULL) return PM3_EINVARG;

    char result[128] = {0};
    size_t offset = 0;
    if (show_tdea) {
        if (key_len != 16 && key_len != 24) return PM3_EINVARG;
        uint8_t zero_block[8] = {0}, encrypted[8] = {0};
        int ret = gp_des3_ecb_enc(key, key_len, zero_block, encrypted);
        if (ret != PM3_SUCCESS) return ret;
        offset += (size_t)snprintf(result + offset, sizeof(result) - offset,
                                   "TDEA-KCV=%02X%02X%02X",
                                   encrypted[0], encrypted[1], encrypted[2]);
        gp_secure_zero(encrypted, sizeof(encrypted));
    }
    if (show_aes) {
        if (key_len != 16 && key_len != 24 && key_len != 32) return PM3_EINVARG;
        uint8_t one_block[16], encrypted[16] = {0};
        memset(one_block, 0x01, sizeof(one_block));
        int ret = gp_aes_ecb_encrypt(key, key_len, one_block, encrypted);
        if (ret != PM3_SUCCESS) return ret;
        if (offset != 0)
            offset += (size_t)snprintf(result + offset, sizeof(result) - offset, "  ");
        snprintf(result + offset, sizeof(result) - offset,
                 "AES-KCV=%02X%02X%02X", encrypted[0], encrypted[1], encrypted[2]);
        gp_secure_zero(encrypted, sizeof(encrypted));
    }

    PrintAndLogEx(INFO, "  %-32s %s", label, result);
    return PM3_SUCCESS;
}



static int CmdHFJavaCardKCV(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard kcv",
                  "Calculate a GlobalPlatform key check value.\n"
                  "TDEA encrypts an all-zero block; AES encrypts a block of sixteen 01 bytes.",
                  "hf javacard kcv -k 404142434445464748494A4B4C4D4E4F --tdea\n"
                  "hf javacard kcv -k <32|48|64 hex chars> --aes\n"
                  "hf javacard kcv --all");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "16/24-byte TDEA or 16/24/32-byte AES key"),
        arg_lit0(NULL, "tdea", "interpret the key as TDEA"),
        arg_lit0(NULL, "aes", "interpret the key as AES"),
        arg_lit0(NULL, "all", "show both KCV forms for built-in 16-byte defaults"),
        arg_lit0("v", "verbose", "also analyse key structure (key option, DES parity, weak forms)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t key[GP_MAX_AES_KEY_LEN] = {0};
    int key_len = 0;
    CLIGetHexWithReturn(ctx, 1, key, &key_len);
    bool tdea = arg_get_lit(ctx, 2);
    bool aes = arg_get_lit(ctx, 3);
    bool all = arg_get_lit(ctx, 4);
    bool kcv_verbose = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);
    if (kcv_verbose && key_len > 0) {
        if (key_len == 16 || key_len == 24) {
            bool k1k2 = memcmp(key, key + 8, 8) == 0;
            bool k1k3 = key_len == 24 && memcmp(key, key + 16, 8) == 0;
            size_t bad_parity = 0;
            for (int i = 0; i < key_len; i++) {
                uint8_t b = key[i], ones = 0;
                while (b) { ones += b & 1; b >>= 1; }
                bad_parity += (ones & 1) == 0;
            }
            PrintAndLogEx(INFO, "  TDEA keying option ....... %s", key_len == 16 ? "2 (K1,K2,K1)" : (k1k3 ? "2 (K3 == K1)" : "1 (K1,K2,K3)"));
            if (k1k2) PrintAndLogEx(WARNING, "  K1 == K2: TDEA degenerates to single DES");
            PrintAndLogEx(INFO, "  DES parity ............... %s (%zu byte(s) with even parity; cards ignore parity)",
                          bad_parity ? "not odd" : "odd", bad_parity);
        }
        if (key_len == 16 || key_len == 24 || key_len == 32)
            PrintAndLogEx(INFO, "  AES key size ............. %d bits", key_len * 8);
    }

    if (all) {
        if (key_len != 0 || tdea || aes) {
            PrintAndLogEx(ERR, "--all cannot be combined with a key or algorithm selector");
            return PM3_EINVARG;
        }
        for (size_t i = 0; i < GP_DEFAULT_KEYS_COUNT; i++) {
            int ret = gp_print_kcv(GP_DEFAULT_KEYS[i].name, GP_DEFAULT_KEYS[i].key,
                                   16, true, true);
            if (ret != PM3_SUCCESS) return ret;
        }
        return PM3_SUCCESS;
    }

    if (key_len == 0) {
        PrintAndLogEx(ERR, "Provide --key or use --all");
        return PM3_EINVARG;
    }
    if (tdea == aes) {
        PrintAndLogEx(ERR, "Choose exactly one of --tdea or --aes");
        gp_secure_zero(key, sizeof(key));
        return PM3_EINVARG;
    }
    if ((tdea && key_len != 16 && key_len != 24) ||
        (aes && key_len != 16 && key_len != 24 && key_len != 32)) {
        PrintAndLogEx(ERR, "Invalid key length for the selected algorithm");
        gp_secure_zero(key, sizeof(key));
        return PM3_EINVARG;
    }

    char label[80] = {0};
    snprintf(label, sizeof(label), "%zu-byte key", (size_t)key_len);
    int ret = gp_print_kcv(label, key, (size_t)key_len, tdea, aes);
    gp_secure_zero(key, sizeof(key));
    return ret;
}



//=============================================================================
// Command: hf javacard storedata  (STORE DATA - Feature 8)
//=============================================================================

static int CmdHFJavaCardStoreData(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard storedata",
                  "Send STORE DATA in one or more short-APDU blocks.\n"
                  "P1 bit 8 is managed automatically: clear on intermediate blocks and set on the last block.\n"
                  "Other P1 format bits supplied by --p1 are preserved; P2 is the sequential block number 00-FF.",
                  "hf javacard storedata -d 9F6708AABBCCDDEEFF001122 --confirm\n"
                  "hf javacard storedata -f personalization.bin --p1 00 --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", "data", "<hex>", "Payload as hexadecimal"),
        arg_str0("f", "file", "<path>", "Payload from file"),
        arg_str0(NULL, "p1", "<hex>", "STORE DATA P1 format bits; bit 8 is automatic"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t inline_data[PM3_CMD_DATA_SIZE] = {0};
    int inline_len = 0;
    CLIGetHexWithReturn(ctx, 1, inline_data, &inline_len);
    char filename[256] = {0};
    int filename_len = sizeof(filename) - 1;
    CLIGetStrWithReturn(ctx, 2, (uint8_t *)filename, &filename_len);
    int p1_value;
    GP_HEX_OPTION_OR_RETURN(ctx, 3, 0x00, p1_value);
    bool verbose = arg_get_lit(ctx, 4);
    bool confirmed = arg_get_lit(ctx, 4 + 1);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "storedata")) return PM3_EINVARG;

    if (p1_value < 0 || p1_value > 0xFF) {
        PrintAndLogEx(ERR, "P1 must be one byte");
        return PM3_EINVARG;
    }
    if ((inline_len > 0) == (filename_len > 0)) {
        PrintAndLogEx(ERR, "Provide exactly one of --data or --file");
        return PM3_EINVARG;
    }
    if (gp_ensure_session(verbose) != PM3_SUCCESS) return PM3_ESOFT;

    uint8_t *file_data = NULL;
    const uint8_t *payload = inline_data;
    size_t payload_len = (size_t)inline_len;
    if (filename_len > 0) {
        if (loadFile_safe(filename, "", (void **)&file_data, &payload_len) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Cannot read file: %s", filename);
            return PM3_EFILE;
        }
        payload = file_data;
    }
    if (payload_len == 0) {
        free(file_data);
        PrintAndLogEx(ERR, "STORE DATA payload is empty");
        return PM3_EINVARG;
    }

    size_t block_size = gp_max_wrapped_command_data();
    if (block_size == 0 || payload_len > block_size * 256U) {
        free(file_data);
        PrintAndLogEx(ERR, "Payload requires more than 256 short-APDU STORE DATA blocks");
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    PrintAndLogEx(INFO, "--- " _CYAN_("STORE DATA") " (%zu bytes) ---", payload_len);

    size_t offset = 0;
    unsigned block = 0;
    int ret = PM3_SUCCESS;
    while (offset < payload_len) {
        size_t chunk = payload_len - offset;
        if (chunk > block_size) chunk = block_size;
        bool last = chunk == payload_len - offset;
        uint8_t p1 = (uint8_t)((p1_value & 0x7F) | (last ? 0x80 : 0x00));

        uint8_t response[GP_RESP_BUF_SIZE] = {0};
        size_t response_len = 0;
        uint16_t sw = 0;
        ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_STORE_DATA,
                              p1, (uint8_t)block,
                              payload + offset, chunk, true, 0x100,
                              response, sizeof(response), &response_len, &sw, verbose);
        if (ret != PM3_SUCCESS) break;
        if (!gp_sw_is_success_or_warning(sw)) {
            PrintAndLogEx(ERR, "STORE DATA block %u failed, SW: " _RED_("%04X") " - %s",
                          block, sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
            ret = PM3_ESOFT;
            break;
        }
        if (response_len > 0)
            PrintAndLogEx(INFO, "  Block %u response: %s",
                          block, sprint_hex_inrow(response, response_len));

        offset += chunk;
        block++;
        if (payload_len > block_size)
            PrintAndLogEx(INPLACE, "  Storing... %zu/%zu bytes", offset, payload_len);
    }
    if (payload_len > block_size) PrintAndLogEx(NORMAL, "");
    if (file_data != NULL) {
        gp_secure_zero(file_data, payload_len);
        free(file_data);
    }
    if (ret == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "STORE DATA complete (%u blocks)", block);
    return ret;
}



//=============================================================================
// Command: hf javacard perso  (INSTALL [for personalization] - Feature 8)
//=============================================================================

static int CmdHFJavaCardPerso(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard perso",
                  "Start a GlobalPlatform personalization session for an installed Application.\n"
                  "The selected Security Domain remains active so STORE DATA can follow.",
                  "hf javacard perso -i A0000000030000010001 --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("i", "instance", "<hex>", "Application instance AID (5-16 bytes)"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t instance_aid[16] = {0};
    int instance_len = 0;
    CLIGetHexWithReturn(ctx, 1, instance_aid, &instance_len);
    bool verbose = arg_get_lit(ctx, 2);
    bool confirmed = arg_get_lit(ctx, 2 + 1);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "perso")) return PM3_EINVARG;

    if (instance_len < 5 || instance_len > 16) {
        PrintAndLogEx(ERR, "Application AID must be 5-16 bytes");
        return PM3_EINVARG;
    }
    int ret = gp_ensure_session(verbose);
    if (ret != PM3_SUCCESS) return ret;

    // Table 11-47: 00 || 00 || L(AID) || AID || 00 || 00.
    uint8_t data[32] = {0};
    size_t data_len = 0;
    if (gp_append_lv(data, sizeof(data), &data_len, NULL, 0, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, NULL, 0, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, instance_aid,
                     (size_t)instance_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, NULL, 0, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, NULL, 0, false) != PM3_SUCCESS)
        return PM3_EINVARG;

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_INSTALL,
                          GP_INSTALL_P1_PERSONALIZATION, 0x00,
                          data, data_len, false, 0,
                          resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) return ret;
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "INSTALL [for personalization] failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription((uint8_t)(sw >> 8), (uint8_t)sw));
        return PM3_ESOFT;
    }

    gp_print_install_confirmation(resp, resp_len);
    PrintAndLogEx(SUCCESS, "Personalization session started for " _GREEN_("%s"),
                  sprint_hex_inrow(instance_aid, (size_t)instance_len));
    return PM3_SUCCESS;
}



//=============================================================================
// CAP file info parsing helpers (Feature 12)
//=============================================================================

// Known JavaCard API package AIDs for import resolution
static const struct { const uint8_t aid[8]; uint8_t len; const char *name; } GP_JCAPI_PKGS[] = {
    { { 0xA0,0x00,0x00,0x00,0x62,0x00,0x01 }, 7, "java.lang" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x00,0x02 }, 7, "java.io" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x00,0x03 }, 7, "java.rmi" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x01,0x01 }, 7, "javacard.framework" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x01,0x02 }, 7, "javacard.security" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x01,0x01,0x01 }, 8, "javacard.framework.service" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x02,0x01 }, 7, "javacardx.crypto" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x02,0x02 }, 7, "javacardx.biometry" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x02,0x03 }, 7, "javacardx.external" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x02,0x04 }, 7, "javacardx.biometry1toN" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x02,0x05 }, 7, "javacardx.security" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x02,0x08,0x01 }, 8, "javacardx.framework.util" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x02,0x08,0x02 }, 8, "javacardx.framework.math" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x02,0x08,0x03 }, 8, "javacardx.framework.tlv" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x02,0x08,0x04 }, 8, "javacardx.framework.string" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x02,0x09 }, 7, "javacardx.apdu" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x60,0x01 }, 7, "org.globalplatform (GP services)" },
};
#define GP_JCAPI_PKGS_COUNT  (sizeof(GP_JCAPI_PKGS) / sizeof(GP_JCAPI_PKGS[0]))

static const char *gp_jcapi_name(const uint8_t *aid, uint8_t alen) {
    for (size_t i = 0; i < GP_JCAPI_PKGS_COUNT; i++)
        if (alen == GP_JCAPI_PKGS[i].len && memcmp(aid, GP_JCAPI_PKGS[i].aid, alen) == 0)
            return GP_JCAPI_PKGS[i].name;
    return NULL;
}

// Parse a single CAP component from its raw bytes and extract info.
// Returns true if the component was recognized and parsed.
static bool gp_cap_parse_component(const char *name, const uint8_t *data, size_t len,
                                    uint8_t *pkg_aid_out, size_t *pkg_aid_len_out,
                                    uint8_t *jcapi_major_out, uint8_t *jcapi_minor_out) {
    if (name == NULL || data == NULL || len < 3) return false;
    uint16_t declared = (uint16_t)(((uint16_t)data[1] << 8) | data[2]);
    if ((size_t)declared != len - 3) {
        PrintAndLogEx(WARNING, "  %s declares %u bytes but contains %zu",
                      name, declared, len - 3);
        return false;
    }

    const uint8_t *payload = data + 3;
    size_t payload_len = len - 3;

    if (strcmp(name, "Header.cap") == 0) {
        if (data[0] != 0x01 || payload_len < 10 ||
            memcmp(payload, "\xDE\xCA\xFF\xED", 4) != 0)
            return false;

        uint8_t cap_minor = payload[4];
        uint8_t cap_major = payload[5];
        uint8_t flags = payload[6];
        uint8_t package_minor = payload[7];
        uint8_t package_major = payload[8];
        uint8_t aid_len = payload[9];
        if (aid_len < 5 || aid_len > 16 || (size_t)aid_len > payload_len - 10)
            return false;

        if (pkg_aid_out != NULL && pkg_aid_len_out != NULL) {
            memcpy(pkg_aid_out, payload + 10, aid_len);
            *pkg_aid_len_out = aid_len;
        }
        PrintAndLogEx(INFO, "  CAP format:       %u.%u flags=%02X",
                      cap_major, cap_minor, flags);
        PrintAndLogEx(INFO, "  Package version:  %u.%u", package_major, package_minor);
        PrintAndLogEx(INFO, "  Package AID:      %s",
                      sprint_hex_inrow(payload + 10, aid_len));
        return true;
    }

    if (strcmp(name, "Applet.cap") == 0) {
        if (data[0] != 0x03 || payload_len < 1) return false;
        uint8_t count = payload[0];
        size_t offset = 1;
        PrintAndLogEx(INFO, "  Applet count:     %u", count);
        for (uint8_t i = 0; i < count; i++) {
            if (offset >= payload_len) return false;
            uint8_t aid_len = payload[offset++];
            if (aid_len < 5 || aid_len > 16 ||
                (size_t)aid_len + 2 > payload_len - offset)
                return false;
            PrintAndLogEx(INFO, "  Module AID #%u:   %s", i + 1,
                          sprint_hex_inrow(payload + offset, aid_len));
            offset += aid_len;
            uint16_t install_offset = (uint16_t)(((uint16_t)payload[offset] << 8) |
                                      payload[offset + 1]);
            offset += 2;
            PrintAndLogEx(INFO, "    install method: 0x%04X", install_offset);
        }
        if (offset != payload_len)
            PrintAndLogEx(WARNING, "  Applet.cap has %zu trailing byte(s)",
                          payload_len - offset);
        return true;
    }

    if (strcmp(name, "Import.cap") == 0) {
        if (data[0] != 0x04 || payload_len < 1) return false;
        uint8_t count = payload[0];
        size_t offset = 1;
        PrintAndLogEx(INFO, "  Import count:     %u", count);
        for (uint8_t i = 0; i < count; i++) {
            if (payload_len - offset < 3) return false;
            uint8_t minor = payload[offset++];
            uint8_t major = payload[offset++];
            uint8_t aid_len = payload[offset++];
            if (aid_len < 5 || aid_len > 16 || aid_len > payload_len - offset)
                return false;

            const uint8_t *aid = payload + offset;
            const char *api_name = gp_jcapi_name(aid, aid_len);
            char aid_hex[33] = {0};
            snprintf(aid_hex, sizeof(aid_hex), "%s", sprint_hex_inrow(aid, aid_len));
            PrintAndLogEx(INFO, "  Import #%u:       %s v%u.%u%s%s%s",
                          i + 1, aid_hex, major, minor,
                          api_name ? " (" : "",
                          api_name ? api_name : "",
                          api_name ? ")" : "");
            if (i == 0 && jcapi_major_out != NULL && jcapi_minor_out != NULL) {
                *jcapi_major_out = major;
                *jcapi_minor_out = minor;
            }
            offset += aid_len;
        }
        if (offset != payload_len)
            PrintAndLogEx(WARNING, "  Import.cap has %zu trailing byte(s)",
                          payload_len - offset);
        return true;
    }

    return true;
}



//=============================================================================
// Command: hf javacard capinfo  (Feature 12)
//=============================================================================

static int CmdHFJavaCardCapInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard capinfo",
                  "Inspect a compact Java Card CAP archive or flat IJC load image.\n"
                  "ZIP archives are validated through their central directory, CRCs, component tags, sizes, and mandatory components.\n"
                  "Extended multi-package CAP files are detected and rejected because this loader only emits compact CAP load images.",
                  "hf javacard capinfo -f applet.cap\n"
                  "hf javacard capinfo -f applet.ijc");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<path>", "CAP/JAR/ZIP or IJC file"),
        arg_lit0("v", "verbose", "hex-dump every component"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    char filename[256] = {0};
    int filename_len = sizeof(filename) - 1;
    CLIGetStrWithReturn(ctx, 1, (uint8_t *)filename, &filename_len);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (loadFile_safe(filename, "", (void **)&raw, &raw_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Cannot read file: %s", filename);
        return PM3_EFILE;
    }
    if (raw_len == 0 || raw_len > GP_MAX_CAP_ARCHIVE_SIZE) {
        PrintAndLogEx(ERR, "File is empty or exceeds the %u MiB safety limit",
                      GP_MAX_CAP_ARCHIVE_SIZE / (1024U * 1024U));
        free(raw);
        return PM3_EFILE;
    }

    bool is_zip = raw_len >= 4 && gp_zip_le32(raw) == ZIP_LOCAL_SIG;
    uint8_t *flat_alloc = NULL;
    const uint8_t *flat = raw;
    size_t flat_len = raw_len;
    int ret = PM3_SUCCESS;

    PrintAndLogEx(INFO, "--- " _CYAN_("CAP File Information") " ---");
    PrintAndLogEx(INFO, "  File:             %s", filename);
    PrintAndLogEx(INFO, "  Container:        %s (%zu bytes)",
                  is_zip ? "ZIP/JAR compact CAP" : "flat IJC", raw_len);

    if (is_zip) {
        ret = gp_cap_zip_parse(raw, raw_len, &flat_alloc, &flat_len);
        if (ret != PM3_SUCCESS) {
            free(raw);
            return ret;
        }
        flat = flat_alloc;
        PrintAndLogEx(INFO, "  Load image size:  %zu bytes", flat_len);
    }

    bool seen[13] = {0};
    uint8_t package_aid[16] = {0};
    size_t package_aid_len = 0;
    uint8_t jcapi_major = 0, jcapi_minor = 0;
    size_t offset = 0;
    size_t component_count = 0;

    while (offset < flat_len) {
        if (flat_len - offset < 3) {
            PrintAndLogEx(ERR, "Truncated CAP component header at offset %zu", offset);
            ret = PM3_ESOFT;
            goto cleanup;
        }
        uint8_t tag = flat[offset];
        size_t header_len = tag == 0x0D ? 5 : 3;
        if (flat_len - offset < header_len) {
            PrintAndLogEx(ERR, "Truncated extended CAP component header at offset %zu", offset);
            ret = PM3_ESOFT;
            goto cleanup;
        }
        size_t payload_len = tag == 0x0D
            ? ((size_t)flat[offset + 1] << 24) |
              ((size_t)flat[offset + 2] << 16) |
              ((size_t)flat[offset + 3] << 8) |
              flat[offset + 4]
            : ((size_t)flat[offset + 1] << 8) | flat[offset + 2];
        if (payload_len > SIZE_MAX - header_len) {
            ret = PM3_ESOFT;
            goto cleanup;
        }
        size_t component_len = payload_len + header_len;
        if (component_len > flat_len - offset) {
            PrintAndLogEx(ERR, "CAP component tag %02X overruns the file at offset %zu",
                          tag, offset);
            ret = PM3_ESOFT;
            goto cleanup;
        }

        const char *name = NULL;
        int known_index = -1;
        switch (tag) {
            case 0x01: name = "Header.cap"; known_index = 0; break;
            case 0x02: name = "Directory.cap"; known_index = 1; break;
            case 0x03: name = "Applet.cap"; known_index = 3; break;
            case 0x04: name = "Import.cap"; known_index = 2; break;
            case 0x05: name = "ConstantPool.cap"; known_index = 8; break;
            case 0x06: name = "Class.cap"; known_index = 4; break;
            case 0x07: name = "Method.cap"; known_index = 5; break;
            case 0x08: name = "StaticField.cap"; known_index = 6; break;
            case 0x09: name = "RefLocation.cap"; known_index = 9; break;
            case 0x0A: name = "Export.cap"; known_index = 7; break;
            case 0x0B: name = "Descriptor.cap"; known_index = 10; break;
            case 0x0C: name = "Debug.cap"; known_index = 12; break;
            case 0x0D: name = "StaticResources.capx"; known_index = 11; break;
            default: name = "Unknown"; break;
        }

        if (known_index >= 0) {
            if (seen[known_index]) {
                PrintAndLogEx(ERR, "Duplicate %s in flat load image", name);
                ret = PM3_ESOFT;
                goto cleanup;
            }
            seen[known_index] = true;
        }
        PrintAndLogEx(INFO, "  Component %-23s tag=%02X payload=%zu",
                      name, tag, payload_len);
        if (verbose) print_buffer_with_offset(flat + offset, component_len, (int)offset, true);

        if ((tag == 0x01 || tag == 0x03 || tag == 0x04) &&
            !gp_cap_parse_component(name, flat + offset, component_len,
                                    package_aid, &package_aid_len,
                                    &jcapi_major, &jcapi_minor)) {
            PrintAndLogEx(ERR, "Malformed %s", name);
            ret = PM3_ESOFT;
            goto cleanup;
        }

        component_count++;
        offset += component_len;
    }

    static const int mandatory[] = {0, 1, 2, 4, 5, 6, 8, 9};
    for (size_t i = 0; i < ARRAYLEN(mandatory); i++) {
        if (!seen[mandatory[i]]) {
            PrintAndLogEx(ERR, "Mandatory %s is missing",
                          GP_CAP_COMPONENT_NAMES[mandatory[i]]);
            ret = PM3_ESOFT;
            goto cleanup;
        }
    }

    PrintAndLogEx(INFO, "  Components:       %zu", component_count);
    if (jcapi_major != 0)
        PrintAndLogEx(INFO, "  First import:      v%u.%u", jcapi_major, jcapi_minor);
    if (package_aid_len != 0) {
        const char *known = gp_known_aid_name(package_aid, package_aid_len);
        if (known != NULL)
            PrintAndLogEx(INFO, "  Package name:      %s", known);
    }
    PrintAndLogEx(SUCCESS, "CAP/IJC structure is internally consistent");

cleanup:
    if (flat_alloc != NULL) {
        gp_secure_zero(flat_alloc, flat_len);
        free(flat_alloc);
    }
    free(raw);
    return ret;
}



//=============================================================================
// Command: hf javacard extradite  (INSTALL [for extradition] - Feature 13)
//=============================================================================

static int CmdHFJavaCardExtradite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard extradite",
                  "Issue INSTALL [for extradition] to associate an Application or Executable Load File\n"
                  "with another Security Domain. Acceptance and reversibility are card-policy dependent.",
                  "hf javacard extradite -i A0000000030000010001 -s A000000003000002 --confirm\n"
                  "hf javacard extradite -i A0000000030000010001 -s A000000003000002 --token <hex> --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("i", "instance", "<hex>", "Application or Executable Load File AID"),
        arg_str1("s", "sd",       "<hex>", "target Security Domain AID"),
        arg_str0(NULL, "params",  "<hex>", "raw extradition parameter TLVs"),
        arg_str0(NULL, "token",   "<hex>", "extradition token"),
        arg_lit0("v", "verbose",  "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t target[16] = {0}, sd[16] = {0};
    uint8_t params[192] = {0}, token[192] = {0};
    int target_len = 0, sd_len = 0, params_len = 0, token_len = 0;
    CLIGetHexWithReturn(ctx, 1, target, &target_len);
    CLIGetHexWithReturn(ctx, 2, sd, &sd_len);
    CLIGetHexWithReturn(ctx, 3, params, &params_len);
    CLIGetHexWithReturn(ctx, 4, token, &token_len);
    bool verbose = arg_get_lit(ctx, 5);
    bool confirmed = arg_get_lit(ctx, 5 + 1);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "extradite")) return PM3_EINVARG;

    if (target_len < 5 || target_len > 16 || sd_len < 5 || sd_len > 16) {
        PrintAndLogEx(ERR, "Both AIDs must be 5-16 bytes");
        return PM3_EINVARG;
    }

    int ret = gp_ensure_session(verbose);
    if (ret != PM3_SUCCESS) goto cleanup;

    // Table 11-45:
    // L(SD) SD || 00 || L(target) target || 00 ||
    // BER-L(params) params || BER-L(token) token.
    uint8_t data[GP_MAX_SHORT_APDU_DATA] = {0};
    size_t data_len = 0;
    if (gp_append_lv(data, sizeof(data), &data_len, sd, (size_t)sd_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, NULL, 0, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, target, (size_t)target_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, NULL, 0, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, params, (size_t)params_len, true) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, token, (size_t)token_len, true) != PM3_SUCCESS ||
        data_len > gp_max_wrapped_command_data()) {
        PrintAndLogEx(ERR, "INSTALL [for extradition] data does not fit a short protected APDU");
        ret = PM3_EINVARG;
        goto cleanup;
    }

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_INSTALL,
                          GP_INSTALL_P1_EXTRADITION, 0x00,
                          data, data_len, false, 0,
                          resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) goto cleanup;
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "INSTALL [for extradition] failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription((uint8_t)(sw >> 8), (uint8_t)sw));
        ret = PM3_ESOFT;
        goto cleanup;
    }

    gp_print_install_confirmation(resp, resp_len);
    PrintAndLogEx(SUCCESS, "Extradition request accepted: %s -> %s",
                  sprint_hex_inrow(target, (size_t)target_len),
                  sprint_hex_inrow(sd, (size_t)sd_len));
    ret = PM3_SUCCESS;

cleanup:
    gp_secure_zero(params, sizeof(params));
    gp_secure_zero(token, sizeof(token));
    return ret;
}



//=============================================================================
// Card Lifecycle Management commands
//=============================================================================

static int CmdHFJavaCardLockCard(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard lock-card",
                  "Transition the card/ISD to CARD_LOCKED (P1=80, P2=7F).\n"
                  "CARD_LOCKED is not the same as TERMINATED, but recovery depends on card policy and keys.",
                  "hf javacard lock-card --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    bool confirmed = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "lock-card")) return PM3_EINVARG;

    PrintAndLogEx(WARNING, _RED_("DANGER:") " This requests CARD_LOCKED and may make all content unavailable.");
    PrintAndLogEx(WARNING, "Recovery is card-dependent; do not use this as a reversible test.");
    if (gp_ensure_session(verbose) != PM3_SUCCESS) return PM3_ESOFT;

    uint8_t resp[GP_RESP_BUF_SIZE];
    size_t resp_len = 0;
    uint16_t sw = 0;
    int ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_SET_STATUS,
                              0x80, 0x7F, NULL, 0, false, 0,
                              resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) {
        gp_drop_field();
        return ret;
    }
    if (gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(SUCCESS, "Card/ISD entered " _RED_("CARD_LOCKED") " (SW %04X)", sw);
        gp_drop_field();
        return PM3_SUCCESS;
    }
    PrintAndLogEx(ERR, "SET STATUS failed, SW: " _RED_("%04X") " - %s",
                  sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
    return PM3_ESOFT;
}



static int CmdHFJavaCardSecureCard(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard secure-card",
                  "Transition the Issuer Security Domain to the SECURED life-cycle state.\n"
                  "This transition is card-policy controlled and may be irreversible.",
                  "hf javacard secure-card --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    bool confirmed = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "secure-card")) return PM3_EINVARG;

    PrintAndLogEx(WARNING, _YELLOW_("WARNING:") " Requesting the SECURED life-cycle transition.");
    int ret = gp_ensure_session(verbose);
    if (ret != PM3_SUCCESS) return ret;

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_SET_STATUS,
                          GP_STATUS_ISD, 0x0F, NULL, 0, false, 0,
                          resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret == PM3_SUCCESS && sw != 0x9000) {
        PrintAndLogEx(ERR, "SET STATUS failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription((uint8_t)(sw >> 8), (uint8_t)sw));
        ret = PM3_ESOFT;
    } else if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Issuer Security Domain is now " _GREEN_("SECURED"));
    }

    // A life-cycle transition may change the card's secure-channel policy.
    gp_drop_field();
    return ret;
}



static int CmdHFJavaCardLockApplet(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard lock-applet",
                  "Ask the current Security Domain to disable selection of an Application or Security Domain.\n"
                  "GlobalPlatform SET STATUS uses P1=40, P2=80 and the raw target AID.",
                  "hf javacard lock-applet -a A0000000030000 --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("a", "aid", "<hex>", "Application or Security Domain AID (5-16 bytes)"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t aid[16] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 1, aid, &aid_len);
    bool verbose = arg_get_lit(ctx, 2);
    bool confirmed = arg_get_lit(ctx, 2 + 1);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "lock-applet")) return PM3_EINVARG;

    if (aid_len < 5 || aid_len > 16) {
        PrintAndLogEx(ERR, "AID must be 5-16 bytes");
        return PM3_EINVARG;
    }
    PrintAndLogEx(WARNING, _YELLOW_("WARNING:") " Disabling selection of " _CYAN_("%s"),
                  sprint_hex_inrow(aid, (size_t)aid_len));
    if (gp_ensure_session(verbose) != PM3_SUCCESS) return PM3_ESOFT;

    uint8_t resp[GP_RESP_BUF_SIZE];
    size_t resp_len = 0;
    uint16_t sw = 0;
    int ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_SET_STATUS,
                              0x40, 0x80, aid, (size_t)aid_len, false, 0,
                              resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) return ret;
    if (gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(SUCCESS, "Selection disabled for " _CYAN_("%s") " (SW %04X)",
                      sprint_hex_inrow(aid, (size_t)aid_len), sw);
        return PM3_SUCCESS;
    }
    PrintAndLogEx(ERR, "SET STATUS failed, SW: " _RED_("%04X") " - %s",
                  sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
    return PM3_ESOFT;
}



static int CmdHFJavaCardUnlockApplet(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard unlock-applet",
                  "Ask the current Security Domain to restore the Application or Security Domain state.\n"
                  "GlobalPlatform SET STATUS uses P1=40, P2=00 and the raw target AID.",
                  "hf javacard unlock-applet -a A0000000030000 --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("a", "aid", "<hex>", "Application or Security Domain AID (5-16 bytes)"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t aid[16] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 1, aid, &aid_len);
    bool verbose = arg_get_lit(ctx, 2);
    bool confirmed = arg_get_lit(ctx, 2 + 1);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "unlock-applet")) return PM3_EINVARG;

    if (aid_len < 5 || aid_len > 16) {
        PrintAndLogEx(ERR, "AID must be 5-16 bytes");
        return PM3_EINVARG;
    }
    if (gp_ensure_session(verbose) != PM3_SUCCESS) return PM3_ESOFT;

    uint8_t resp[GP_RESP_BUF_SIZE];
    size_t resp_len = 0;
    uint16_t sw = 0;
    int ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_SET_STATUS,
                              0x40, 0x00, aid, (size_t)aid_len, false, 0,
                              resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) return ret;
    if (gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(SUCCESS, "State restored for " _CYAN_("%s") " (SW %04X)",
                      sprint_hex_inrow(aid, (size_t)aid_len), sw);
        return PM3_SUCCESS;
    }
    PrintAndLogEx(ERR, "SET STATUS failed, SW: " _RED_("%04X") " - %s",
                  sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
    return PM3_ESOFT;
}



static int CmdHFJavaCardRenameISD(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard rename-isd",
                  "Send the vendor-specific STORE DATA P1=90 ISD-AID rename command used by some cards.\n"
                  "This is not a portable GlobalPlatform command and may permanently make the old AID unusable.",
                  "hf javacard rename-isd -a A0000001510000FF --vendor-command --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("a", "aid", "<hex>", "new ISD AID (5-16 bytes)"),
        arg_lit0(NULL, "vendor-command", "acknowledge use of a non-standard, potentially irreversible command"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t new_aid[16] = {0};
    int new_aid_len = 0;
    CLIGetHexWithReturn(ctx, 1, new_aid, &new_aid_len);
    bool acknowledged = arg_get_lit(ctx, 2);
    bool verbose = arg_get_lit(ctx, 3);
    bool confirmed = arg_get_lit(ctx, 3 + 1);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "rename-isd")) return PM3_EINVARG;

    if (new_aid_len < 5 || new_aid_len > 16) {
        PrintAndLogEx(ERR, "AID must be 5-16 bytes");
        return PM3_EINVARG;
    }
    if (!acknowledged) {
        PrintAndLogEx(ERR, "This operation is vendor-specific; repeat with --vendor-command after checking card documentation");
        return PM3_EINVARG;
    }

    int ret = gp_ensure_session(verbose);
    if (ret != PM3_SUCCESS) return ret;

    uint8_t data[18] = {0};
    size_t data_len = 0;
    data[data_len++] = 0x4F;
    data[data_len++] = (uint8_t)new_aid_len;
    memcpy(data + data_len, new_aid, (size_t)new_aid_len);
    data_len += (size_t)new_aid_len;

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_STORE_DATA,
                          0x90, 0x00, data, data_len, false, 0,
                          resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret == PM3_SUCCESS && sw != 0x9000) {
        PrintAndLogEx(ERR, "Vendor rename command failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription((uint8_t)(sw >> 8), (uint8_t)sw));
        ret = PM3_ESOFT;
    } else if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Card accepted new ISD AID " _GREEN_("%s"),
                      sprint_hex_inrow(new_aid, (size_t)new_aid_len));
    }
    gp_drop_field();
    return ret;
}



static int CmdHFJavaCardMakeDefault(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard make-default",
                  "Set CardReset privilege on an installed Application using INSTALL [for make selectable].\n"
                  "Optional make-selectable parameters and token are supported.",
                  "hf javacard make-default -a A0000000030000 --confirm\n"
                  "hf javacard make-default -a <aid> --token <hex> --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("a", "aid", "<hex>", "Application AID (5-16 bytes)"),
        arg_str0(NULL, "params", "<hex>", "raw make-selectable parameter TLVs"),
        arg_str0(NULL, "token", "<hex>", "make-selectable token"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t aid[16] = {0}, params[192] = {0}, token[192] = {0};
    int aid_len = 0, params_len = 0, token_len = 0;
    CLIGetHexWithReturn(ctx, 1, aid, &aid_len);
    CLIGetHexWithReturn(ctx, 2, params, &params_len);
    CLIGetHexWithReturn(ctx, 3, token, &token_len);
    bool verbose = arg_get_lit(ctx, 4);
    bool confirmed = arg_get_lit(ctx, 4 + 1);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "make-default")) return PM3_EINVARG;

    if (aid_len < 5 || aid_len > 16) {
        PrintAndLogEx(ERR, "Application AID must be 5-16 bytes");
        return PM3_EINVARG;
    }

    int ret = gp_ensure_session(verbose);
    if (ret != PM3_SUCCESS) goto cleanup;

    const uint8_t card_reset_privilege = 0x04;
    uint8_t data[GP_MAX_SHORT_APDU_DATA] = {0};
    size_t data_len = 0;
    if (gp_append_lv(data, sizeof(data), &data_len, NULL, 0, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, NULL, 0, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, aid, (size_t)aid_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, &card_reset_privilege, 1, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, params, (size_t)params_len, true) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, token, (size_t)token_len, true) != PM3_SUCCESS ||
        data_len > gp_max_wrapped_command_data()) {
        PrintAndLogEx(ERR, "INSTALL data does not fit a short protected APDU");
        ret = PM3_EINVARG;
        goto cleanup;
    }

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_INSTALL,
                          GP_INSTALL_P1_MAKE_SELECTABLE, 0x00,
                          data, data_len, false, 0,
                          resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) goto cleanup;
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "INSTALL [for make selectable] failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription((uint8_t)(sw >> 8), (uint8_t)sw));
        ret = PM3_ESOFT;
        goto cleanup;
    }

    gp_print_install_confirmation(resp, resp_len);
    PrintAndLogEx(SUCCESS, "Default-selected Application set to " _GREEN_("%s"),
                  sprint_hex_inrow(aid, (size_t)aid_len));
    ret = PM3_SUCCESS;

cleanup:
    gp_secure_zero(params, sizeof(params));
    gp_secure_zero(token, sizeof(token));
    return ret;
}



static int CmdHFJavaCardDeleteKey(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard delete-key",
                  "Delete keys using GlobalPlatform DELETE key references D2 (KVN) and/or D0 (KID).\n"
                  "At least one selector is required. Deleting the last usable key can permanently lock out management.",
                  "hf javacard delete-key --kvn 2 --confirm\n"
                  "hf javacard delete-key --kvn 2 --kid 1 --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "kvn", "<dec>", "Key Version Number (1-127)"),
        arg_int0(NULL, "kid", "<dec>", "Key Identifier (1-127)"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int kvn = arg_get_int_def(ctx, 1, 0);
    int kid = arg_get_int_def(ctx, 2, 0);
    bool verbose = arg_get_lit(ctx, 3);
    bool confirmed = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if ((kvn == 0 && kid == 0) || kvn < 0 || kvn > 0x7F || kid < 0 || kid > 0x7F) {
        PrintAndLogEx(ERR, "Specify --kvn and/or --kid in the range 1-127");
        return PM3_EINVARG;
    }
    if (!gp_require_confirm(confirmed, "DELETE KEY")) return PM3_EINVARG;
    PrintAndLogEx(WARNING, _RED_("WARNING:") " Deleting the last usable key can make card management unrecoverable.");
    if (gp_ensure_session(verbose) != PM3_SUCCESS) return PM3_ESOFT;

    uint8_t data[6] = {0};
    size_t data_len = 0;
    if (kid != 0) {
        data[data_len++] = 0xD0;
        data[data_len++] = 0x01;
        data[data_len++] = (uint8_t)kid;
    }
    if (kvn != 0) {
        data[data_len++] = 0xD2;
        data[data_len++] = 0x01;
        data[data_len++] = (uint8_t)kvn;
    }

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    int ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_DELETE,
                              0x00, 0x00, data, data_len, false, 0,
                              resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) return ret;
    if (!gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(ERR, "DELETE key failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "Key deletion accepted, SW " _GREEN_("%04X"), sw);
    return PM3_SUCCESS;
}



//=============================================================================
// Command: hf javacard select  (SELECT arbitrary AID)
//=============================================================================

static int CmdHFJavaCardSelect(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard select",
                  "SELECT an arbitrary AID by name and optionally decode its FCI/FCP response.",
                  "hf javacard select -a A0000000030000 --tlv\n"
                  "hf javacard select -a D276000124010304 --p2 0C --keep");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("a", "aid", "<hex>", "AID to select (4-16 bytes)"),
        arg_str0(NULL, "p2", "<hex>", "SELECT P2 (default 00)"),
        arg_lit0("k", "keep", "keep the RF field on after SELECT"),
        arg_lit0("t", "tlv", "decode FCI/FCP TLV response"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t aid[16] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 1, aid, &aid_len);
    int p2;
    GP_HEX_OPTION_OR_RETURN(ctx, 2, 0x00, p2);
    bool keep = arg_get_lit(ctx, 3);
    bool decode_tlv = arg_get_lit(ctx, 4);
    bool verbose = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (aid_len < 4 || aid_len > 16 || p2 < 0 || p2 > 0xFF) {
        PrintAndLogEx(ERR, "AID must be 4-16 bytes and P2 must be 00-FF");
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    int ret = gp_plain_apdu(true, keep, 0x00, GP_INS_SELECT, 0x04, (uint8_t)p2,
                            aid, (size_t)aid_len, true, 0x100,
                            resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) return ret;

    const char *known = gp_known_aid_name(aid, (size_t)aid_len);
    if (known) PrintAndLogEx(INFO, "  Known AID: %s", known);

    if (!gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(ERR, "SELECT failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription((uint8_t)(sw >> 8), (uint8_t)sw));
        if (keep) gp_drop_field();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Selected " _GREEN_("%s") " (SW %04X)",
                  sprint_hex_inrow(aid, (size_t)aid_len), sw);
    if (resp_len != 0) {
        print_buffer_with_offset(resp, resp_len, 0, true);
        if (decode_tlv) gp_print_tlv(resp, resp_len);
    }
    return PM3_SUCCESS;
}



//=============================================================================
// Command: hf javacard challenge  (GET CHALLENGE)
//=============================================================================

static int CmdHFJavaCardChallenge(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard challenge",
                  "Collect GET CHALLENGE responses. By default the ISD is selected first.\n"
                  "Use --aid to select another Application, or --current only when a prior command kept the field on.",
                  "hf javacard challenge -l 16 -n 8\n"
                  "hf javacard challenge -a A0000000030000 --count 4\n"
                  "hf javacard challenge --current --keep");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("a", "aid", "<hex>", "AID to select before GET CHALLENGE"),
        arg_lit0(NULL, "current", "use the currently selected Application without activating/resetting the card"),
        arg_int0("l", "len", "<dec>", "challenge length, 1-256 bytes (default 8)"),
        arg_int0("n", "count", "<dec>", "number of challenges, 1-64 (default 1)"),
        arg_lit0("k", "keep", "keep the RF field on after the final response"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t aid[16] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 1, aid, &aid_len);
    bool current = arg_get_lit(ctx, 2);
    int challenge_len = arg_get_int_def(ctx, 3, 8);
    int count = arg_get_int_def(ctx, 4, 1);
    bool keep = arg_get_lit(ctx, 5);
    bool verbose = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (current && aid_len != 0) {
        PrintAndLogEx(ERR, "--current and --aid are mutually exclusive");
        return PM3_EINVARG;
    }
    if (aid_len != 0 && (aid_len < 4 || aid_len > 16)) {
        PrintAndLogEx(ERR, "AID must be 4-16 bytes");
        return PM3_EINVARG;
    }
    if (challenge_len < 1 || challenge_len > 256 || count < 1 || count > 64) {
        PrintAndLogEx(ERR, "Length must be 1-256 and count must be 1-64");
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    int ret = PM3_SUCCESS;
    uint16_t sw = 0;

    if (!current) {
        if (aid_len == 0) {
            ret = gp_select_isd(true, true, &sw, verbose);
        } else {
            uint8_t select_resp[GP_RESP_BUF_SIZE] = {0};
            size_t select_len = 0;
            ret = gp_plain_apdu(true, true, 0x00, GP_INS_SELECT, 0x04, 0x00,
                                aid, (size_t)aid_len, true, 0x100,
                                select_resp, sizeof(select_resp), &select_len, &sw, verbose);
        }
        if (ret != PM3_SUCCESS || !gp_sw_is_success_or_warning(sw)) {
            PrintAndLogEx(ERR, "Target selection failed (SW %04X)", sw);
            gp_drop_field();
            return ret == PM3_SUCCESS ? PM3_ESOFT : ret;
        }
    }

    for (int i = 0; i < count; i++) {
        uint8_t resp[GP_RESP_BUF_SIZE] = {0};
        size_t resp_len = 0;
        bool leave_on = keep || i + 1 < count;
        ret = gp_plain_apdu(false, leave_on, 0x00, 0x84, 0x00, 0x00,
                            NULL, 0, true, (uint16_t)challenge_len,
                            resp, sizeof(resp), &resp_len, &sw, verbose);
        if (ret != PM3_SUCCESS) {
            gp_drop_field();
            return ret;
        }
        if (sw != 0x9000 || resp_len != (size_t)challenge_len) {
            if (sw != 0x9000)
                PrintAndLogEx(ERR, "GET CHALLENGE #%d refused, SW %04X - %s", i + 1, sw,
                              GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
            else
                PrintAndLogEx(ERR, "GET CHALLENGE #%d returned %zu byte(s), expected %d", i + 1, resp_len, challenge_len);
            if (i == 0 && (sw == 0x6E00 || sw == 0x6D00))
                PrintAndLogEx(HINT, "Hint: the selected application does not implement GET CHALLENGE; try `"
                              _YELLOW_("-a <aid>") "` of another applet");
            if (leave_on) gp_drop_field();
            return PM3_ESOFT;
        }
        PrintAndLogEx(SUCCESS, "Challenge[%d]: " _YELLOW_("%s"),
                      i + 1, sprint_hex_inrow(resp, resp_len));
    }
    return PM3_SUCCESS;
}



//=============================================================================
// Command: hf javacard getkey  (GET KEY info)
//=============================================================================

static int CmdHFJavaCardGetKey(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard getkey",
                  "Read the GlobalPlatform Key Information Template (GET DATA 00E0).\n"
                  "The card may expose it in clear, require an authenticated session, or not expose it.",
                  "hf javacard getkey\n"
                  "hf javacard getkey --kvn 1 --kid 2");
    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "kvn", "<dec>", "Filter by Key Version Number (0=all)"),
        arg_int0(NULL, "kid", "<dec>", "Filter by Key Identifier (0=all)"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int kvn = arg_get_int_def(ctx, 1, 0);
    int kid = arg_get_int_def(ctx, 2, 0);
    bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (kvn < 0 || kvn > 0xFF || kid < 0 || kid > 0xFF) {
        PrintAndLogEx(ERR, "KVN and KID filters must be one byte");
        return PM3_EINVARG;
    }
    clearCommandBuffer();

    bool had_session = gp_ctx.active;
    uint16_t sw = 0;
    int ret;
    if (!had_session) {
        ret = gp_select_isd(true, true, &sw, verbose);
        if (ret != PM3_SUCCESS || !gp_sw_is_success_or_warning(sw)) {
            gp_drop_field();
            return ret == PM3_SUCCESS ? PM3_ESOFT : ret;
        }
    }

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    if (had_session) {
        ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_GET_DATA,
                              0x00, 0xE0, NULL, 0, true, 0x100,
                              resp, sizeof(resp), &resp_len, &sw, verbose);
    } else {
        ret = gp_plain_apdu(false, true, GP_CLA_PLAIN, GP_INS_GET_DATA,
                            0x00, 0xE0, NULL, 0, true, 0x100,
                            resp, sizeof(resp), &resp_len, &sw, verbose);
    }
    if (ret != PM3_SUCCESS) {
        if (!had_session) gp_drop_field();
        return ret;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Key Information Template") " ---");

    if (!gp_sw_is_success_or_warning(sw)) {
        if (sw == 0x6A88)
            PrintAndLogEx(WARNING, "Key information is not available for the current security state");
        else
            PrintAndLogEx(ERR, "GET DATA 00E0 failed, SW: " _RED_("%04X") " - %s",
                          sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        if (!had_session) gp_drop_field();
        return PM3_ESOFT;
    }

    int matched = gp_print_key_info_template(resp, resp_len, kvn, kid);
    if (matched < 0) {
        PrintAndLogEx(ERR, "Malformed E0 Key Information Template");
        if (!had_session) gp_drop_field();
        return PM3_ESOFT;
    }
    if (matched == 0) PrintAndLogEx(INFO, "  (no matching entries)");
    PrintAndLogEx(INFO, "  Note: GET DATA 00E0 exposes key types/lengths only; GlobalPlatform defines no KCV here.");
    if (verbose && resp_len > 0) {
        PrintAndLogEx(INFO, "Raw template (%zu bytes):", resp_len);
        print_buffer_with_offset(resp, resp_len, 0, true);
    }
    if (!had_session) gp_drop_field();
    return PM3_SUCCESS;
}



//=============================================================================
// Command: hf javacard dump  (comprehensive card dump)
//=============================================================================

static void gp_json_write_hex(FILE *fp, const uint8_t *data, size_t len) {
    static const char HEX[] = "0123456789ABCDEF";
    fputc('"', fp);
    for (size_t i = 0; i < len; i++) {
        fputc(HEX[data[i] >> 4], fp);
        fputc(HEX[data[i] & 0x0F], fp);
    }
    fputc('"', fp);
}

static int CmdHFJavaCardDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard dump",
                  "Collect a read-only GlobalPlatform diagnostic report: SELECT FCI, every GET DATA object\n"
                  "this tool knows (CPLC, CRD, key info, capabilities, IIN/CIN, KDD, counters, resources)\n"
                  "and all GET STATUS classes. An open secure channel is reused; --auth opens one with the\n"
                  "GP test key 404142..4F. Nothing on the card is changed.",
                  "hf javacard dump\n"
                  "hf javacard dump --auth -o card_dump.json");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("o", "out", "<file>", "write a machine-readable JSON report"),
        arg_lit0(NULL, "auth", "authenticate with the default test key when no session is open"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    char outfile[256] = {0};
    int outfile_len = sizeof(outfile) - 1;
    CLIGetStrWithReturn(ctx, 1, (uint8_t *)outfile, &outfile_len);
    bool auth = arg_get_lit(ctx, 2);
    bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);
    clearCommandBuffer();

    typedef struct {
        const char *name;
        uint8_t p1, p2;
        uint8_t response[GP_RESP_BUF_SIZE];
        size_t response_len;
        uint16_t sw;
        int ret;
    } dump_item_t;
    static dump_item_t items[] = {
        { .name = "cplc",                  .p1 = 0x9F, .p2 = 0x7F },
        { .name = "card_recognition_data", .p1 = 0x00, .p2 = 0x66 },
        { .name = "key_information",       .p1 = 0x00, .p2 = 0xE0 },
        { .name = "card_capabilities",     .p1 = 0x00, .p2 = 0x67 },
        { .name = "iin",                   .p1 = 0x00, .p2 = 0x42 },
        { .name = "cin",                   .p1 = 0x00, .p2 = 0x45 },
        { .name = "key_derivation_data",   .p1 = 0x00, .p2 = 0xCF },
        { .name = "sequence_counter",      .p1 = 0x00, .p2 = 0xC1 },
        { .name = "confirmation_counter",  .p1 = 0x00, .p2 = 0xC2 },
        { .name = "card_resources",        .p1 = 0xFF, .p2 = 0x21 },
    };
    enum { D_CPLC, D_CRD, D_KEYS, D_CAPS };

    static const uint8_t status_p1[] = {
        GP_STATUS_ISD, GP_STATUS_APPS_AND_SSD, GP_STATUS_LOAD_FILES, GP_STATUS_LOAD_FILES_MODS
    };
    static const char *status_names[] = {
        "isd", "applications_and_security_domains", "load_files", "load_files_and_modules"
    };
    static const char *status_titles[] = {
        "Issuer Security Domain", "Applications & Supplementary Security Domains",
        "Executable Load Files", "Executable Load Files & Modules"
    };
    gp_status_result_t status[ARRAYLEN(status_p1)];
    memset(status, 0, sizeof(status));

    bool had_session = gp_ctx.active;
    uint8_t select_fci[GP_RESP_BUF_SIZE] = {0};
    size_t select_fci_len = 0;
    uint16_t select_sw = 0x9000;
    int ret = PM3_SUCCESS;

    if (!had_session) {
        ret = gp_plain_apdu(true, true, 0x00, GP_INS_SELECT, 0x04, 0x00, GP_ISD_AID, GP_ISD_AID_LEN, true, 0x100,
                            select_fci, sizeof(select_fci), &select_fci_len, &select_sw, verbose);
        if (ret != PM3_SUCCESS || !gp_sw_is_success_or_warning(select_sw)) {
            PrintAndLogEx(ERR, "SELECT ISD failed, SW %04X", select_sw);
            gp_drop_field();
            return ret == PM3_SUCCESS ? PM3_ESOFT : ret;
        }
        if (auth && gp_ensure_session(verbose) != PM3_SUCCESS) {
            gp_drop_field();
            return PM3_ESOFT;
        }
    }

    for (size_t i = 0; i < ARRAYLEN(items); i++) {
        items[i].response_len = 0;
        items[i].sw = 0;
        items[i].ret = gp_ctx.active
                       ? gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_GET_DATA, items[i].p1, items[i].p2,
                                         NULL, 0, true, 0x100, items[i].response, sizeof(items[i].response),
                                         &items[i].response_len, &items[i].sw, verbose)
                       : gp_plain_apdu(false, true, GP_CLA_PLAIN, GP_INS_GET_DATA, items[i].p1, items[i].p2,
                                       NULL, 0, true, 0x100, items[i].response, sizeof(items[i].response),
                                       &items[i].response_len, &items[i].sw, verbose);
        if (items[i].ret != PM3_SUCCESS) {
            ret = items[i].ret;
            goto done;
        }
    }
    for (size_t c = 0; c < ARRAYLEN(status_p1); c++) {
        gp_collect_status(status_p1[c], verbose, &status[c]);
        if (status[c].ret != PM3_SUCCESS && status[c].ret != PM3_ESOFT) {
            ret = status[c].ret;   // transport error: stop
            goto done;
        }
    }

    // ---- Report -------------------------------------------------------------
    gp_print_banner("GlobalPlatform Diagnostic Dump");
    gp_print_kv("Secure channel", "%s", gp_ctx.active
                ? (had_session ? _GREEN_("existing session") : _GREEN_("opened with default key"))
                : _YELLOW_("not used"));
    if (select_fci_len) gp_print_kv("ISD FCI", "%s", sprint_hex_inrow(select_fci, select_fci_len));

    gp_print_section("Objects read");
    PrintAndLogEx(INFO, "  %-34s %-4s  %s", "Object", "SW", "Bytes");
    PrintAndLogEx(INFO, "  ---------------------------------- ----  -----");
    for (size_t i = 0; i < ARRAYLEN(items); i++) {
        bool ok = gp_sw_is_success_or_warning(items[i].sw);
        PrintAndLogEx(ok ? SUCCESS : INFO, "  GET DATA %02X%02X %-21s %04X  %zu", items[i].p1, items[i].p2,
                      items[i].name, items[i].sw, items[i].response_len);
    }
    for (size_t c = 0; c < ARRAYLEN(status_p1); c++) {
        bool ok = status[c].ret == PM3_SUCCESS;
        PrintAndLogEx(ok ? SUCCESS : INFO, "  GET STATUS %02X %-21s %04X  %zu%s", status_p1[c], status_names[c],
                      status[c].sw, status[c].len, status[c].legacy ? " (legacy format)" : "");
    }

    if (gp_sw_is_success_or_warning(items[D_CPLC].sw)) {
        const uint8_t *cplc = NULL;
        size_t cplc_len = 0;
        gp_tlv_unwrap(items[D_CPLC].response, items[D_CPLC].response_len, 0x9F7F, &cplc, &cplc_len);
        gp_print_section("Card Production Life Cycle (CPLC)");
        gp_print_cplc(cplc, cplc_len);
        gp_print_section("Card Identification");
        gp_print_identification(cplc, cplc_len);
    }
    if (gp_sw_is_success_or_warning(items[D_CRD].sw)) {
        gp_print_section("Card Recognition Data");
        gp_decode_card_recognition_data(items[D_CRD].response, items[D_CRD].response_len);
    }
    if (gp_sw_is_success_or_warning(items[D_KEYS].sw)) {
        gp_print_section("Key Information");
        if (gp_print_key_info_template(items[D_KEYS].response, items[D_KEYS].response_len, 0, 0) < 0)
            PrintAndLogEx(WARNING, "  Malformed key information");
    }
    if (gp_sw_is_success_or_warning(items[D_CAPS].sw)) {
        gp_print_section("Card Capabilities");
        gp_print_capabilities(items[D_CAPS].response, items[D_CAPS].response_len);
    }
    for (size_t c = 0; c < ARRAYLEN(status_p1); c++) {
        gp_print_section(status_titles[c]);
        if (status[c].ret != PM3_SUCCESS) {
            PrintAndLogEx(INFO, "  not available, SW %04X - %s", status[c].sw,
                          GetAPDUCodeDescription(status[c].sw >> 8, status[c].sw & 0xFF));
        } else if (status[c].empty || status[c].len == 0) {
            PrintAndLogEx(INFO, "  (none)");
        } else {
            gp_print_status_response(status[c].data, status[c].len, status[c].p1);
        }
    }
    if (!gp_ctx.active) gp_status_failure_hint(status[0].sw);

    if (outfile_len > 0) {
        FILE *fp = fopen(outfile, "wb");
        if (fp == NULL) {
            PrintAndLogEx(ERR, "Cannot create JSON report: %s", outfile);
            ret = PM3_EFILE;
            goto done;
        }
        fprintf(fp, "{\n");
        fprintf(fp, "  \"schema\": \"proxmark3.globalplatform.dump.v2\",\n");
        fprintf(fp, "  \"secure_channel_active\": %s,\n", gp_ctx.active ? "true" : "false");
        fprintf(fp, "  \"scp_version\": %u,\n", (unsigned)(gp_ctx.active ? gp_ctx.scp_version : 0));
        fprintf(fp, "  \"select\": {\"sw\": \"%04X\", \"data\": ", select_sw);
        gp_json_write_hex(fp, select_fci, select_fci_len);
        fprintf(fp, "},\n  \"get_data\": {\n");
        for (size_t i = 0; i < ARRAYLEN(items); i++) {
            fprintf(fp, "    \"%s\": {\"p1p2\": \"%02X%02X\", \"sw\": \"%04X\", \"data\": ",
                    items[i].name, items[i].p1, items[i].p2, items[i].sw);
            gp_json_write_hex(fp, items[i].response, items[i].response_len);
            fprintf(fp, "}%s\n", i + 1 == ARRAYLEN(items) ? "" : ",");
        }
        fprintf(fp, "  },\n  \"get_status\": {\n");
        for (size_t c = 0; c < ARRAYLEN(status_p1); c++) {
            fprintf(fp, "    \"%s\": {\"p1\": \"%02X\", \"sw\": \"%04X\", \"legacy_format\": %s, \"data\": ",
                    status_names[c], status[c].p1, status[c].sw, status[c].legacy ? "true" : "false");
            gp_json_write_hex(fp, status[c].data, status[c].len);
            fprintf(fp, "}%s\n", c + 1 == ARRAYLEN(status_p1) ? "" : ",");
        }
        fprintf(fp, "  }\n}\n");
        if (fclose(fp) != 0) {
            PrintAndLogEx(ERR, "Failed while closing JSON report: %s", outfile);
            ret = PM3_EFILE;
            goto done;
        }
        PrintAndLogEx(SUCCESS, "JSON report saved to " _YELLOW_("%s"), outfile);
    }

done:
    for (size_t c = 0; c < ARRAYLEN(status_p1); c++) free(status[c].data);
    if (!had_session) gp_drop_field();
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, "Diagnostic dump complete");
    }
    return ret;
}


//=============================================================================
// Command: hf javacard fuzz  (INS fuzzer)
//=============================================================================

static int CmdHFJavaCardFuzz(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard fuzz",
                  "Probe INS values on a selected AID. The command is intentionally gated because arbitrary\n"
                  "APDUs can alter life-cycle state, keys, content, or personalization data.",
                  "hf javacard fuzz --unsafe --cla 80 --ins-start 00 --ins-end 7F\n"
                  "hf javacard fuzz --unsafe --include-management -a <aid>");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("a", "aid", "<hex>", "AID to select first (default ISD)"),
        arg_str0(NULL, "cla", "<hex>", "CLA byte (default 80)"),
        arg_str0(NULL, "ins-start", "<hex>", "first INS (default 00)"),
        arg_str0(NULL, "ins-end", "<hex>", "last INS (default FF)"),
        arg_lit0(NULL, "unsafe", "acknowledge that fuzzing can irreversibly modify the card"),
        arg_lit0(NULL, "include-management", "also send known GP management INS values"),
        arg_lit0("v", "verbose", "show unsupported responses and response data"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t aid[16] = {0};
    int aid_len = 0;
    CLIGetHexWithReturn(ctx, 1, aid, &aid_len);
    int cla, first, last;
    GP_HEX_OPTION_OR_RETURN(ctx, 2, 0x80, cla);
    GP_HEX_OPTION_OR_RETURN(ctx, 3, 0x00, first);
    GP_HEX_OPTION_OR_RETURN(ctx, 4, 0xFF, last);
    bool unsafe = arg_get_lit(ctx, 5);
    bool include_management = arg_get_lit(ctx, 6);
    bool verbose = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if (!unsafe) {
        PrintAndLogEx(ERR, "Fuzzing is disabled unless --unsafe is supplied");
        return PM3_EINVARG;
    }
    if (cla < 0 || cla > 0xFF || first < 0 || first > 0xFF ||
        last < 0 || last > 0xFF || first > last ||
        (aid_len != 0 && (aid_len < 4 || aid_len > 16))) {
        PrintAndLogEx(ERR, "Invalid CLA, INS range, or AID");
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    uint16_t sw = 0;
    int ret;
    if (aid_len == 0) {
        ret = gp_select_isd(true, true, &sw, false);
    } else {
        uint8_t select_resp[GP_RESP_BUF_SIZE] = {0};
        size_t select_len = 0;
        ret = gp_plain_apdu(true, true, 0x00, GP_INS_SELECT, 0x04, 0x00,
                            aid, (size_t)aid_len, true, 0x100,
                            select_resp, sizeof(select_resp), &select_len, &sw, false);
    }
    if (ret != PM3_SUCCESS || !gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(ERR, "Target selection failed (SW %04X)", sw);
        gp_drop_field();
        return ret == PM3_SUCCESS ? PM3_ESOFT : ret;
    }

    // INS values that can change persistent state, consume retry counters
    // (failed EXTERNAL AUTHENTICATE / VERIFY can block or terminate a card),
    // or erase content. They are skipped unless --include-management is given.
    static const uint8_t management_ins[] = {
        GP_INS_INITIALIZE_UPDATE, GP_INS_EXTERNAL_AUTH, GP_INS_SET_STATUS,
        GP_INS_PUT_KEY, GP_INS_STORE_DATA, GP_INS_DELETE, GP_INS_INSTALL, GP_INS_LOAD,
        0x04, // DEACTIVATE FILE
        0x0E, // ERASE BINARY
        0x0F, // ERASE BINARY (odd)
        0x20, // VERIFY (PIN retry counter)
        0x21, // VERIFY (odd)
        0x24, // CHANGE REFERENCE DATA
        0x2C, // RESET RETRY COUNTER
        0x44, // ACTIVATE FILE
        0x46, // GENERATE ASYMMETRIC KEY PAIR
        0x47, // GENERATE ASYMMETRIC KEY PAIR (odd)
        0x86, // GENERAL AUTHENTICATE
        0x87, // GENERAL AUTHENTICATE (odd)
        0x88, // INTERNAL AUTHENTICATE (may advance counters)
        0xD0, // WRITE BINARY
        0xD2, // WRITE RECORD
        0xD6, // UPDATE BINARY
        0xD7, // UPDATE BINARY (odd)
        0xDA, // PUT DATA
        0xDB, // PUT DATA (odd)
        0xDC, // UPDATE RECORD
        0xE0, // CREATE FILE
        0xE2, // APPEND RECORD / STORE DATA
        0xEE, // DELETE DATA / MANAGE ATTRIBUTES
        0xFE, // TERMINATE CARD USAGE
    };
    size_t interesting = 0, skipped = 0, invalid = 0;
    for (int ins = first; ins <= last; ins++) {
        // ISO/IEC 7816-3: 6X and 9X are not valid INS codes (they collide with SW1).
        if ((ins & 0xF0) == 0x60 || (ins & 0xF0) == 0x90) {
            invalid++;
            continue;
        }
        bool management = false;
        for (size_t i = 0; i < ARRAYLEN(management_ins); i++)
            management |= (uint8_t)ins == management_ins[i];
        if (management && !include_management) {
            skipped++;
            continue;
        }

        uint8_t resp[GP_RESP_BUF_SIZE] = {0};
        size_t resp_len = 0;
        ret = gp_plain_apdu(false, true, (uint8_t)cla, (uint8_t)ins, 0x00, 0x00,
                            NULL, 0, true, 0x100,
                            resp, sizeof(resp), &resp_len, &sw, false);
        if (ret != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Transport failed at INS %02X", ins);
            gp_drop_field();
            return ret;
        }

        if (sw == 0x6D00 || sw == 0x6E00) {
            if (verbose) PrintAndLogEx(INFO, "INS %02X -> %04X", ins, sw);
            continue;
        }
        interesting++;
        PrintAndLogEx(INFO, "INS " _YELLOW_("%02X") " -> %04X (%s)%s",
                      ins, sw,
                      GetAPDUCodeDescription((uint8_t)(sw >> 8), (uint8_t)sw),
                      resp_len ? "" : " [no data]");
        if (verbose && resp_len)
            PrintAndLogEx(INFO, "    %s", sprint_hex_inrow(resp, resp_len));
    }

    PrintAndLogEx(INFO, "Fuzz complete: %zu interesting, %zu state-changing INS skipped, %zu invalid INS skipped",
                  interesting, skipped, invalid);
    gp_drop_field();
    return PM3_SUCCESS;
}



//=============================================================================
// Command: hf javacard putkey-aes  (PUT KEY with AES keys for SCP03)
//=============================================================================

static int CmdHFJavaCardPutKeyAES(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard putkey-aes",
                  "Add or replace a three-key AES key set for SCP03.\n"
                  "Requires an already-open SCP03 secure channel. Key data is encrypted with static Key-DEK.\n"
                  "AES-128, AES-192, and AES-256 are supported; all three new keys must have equal length.",
                  "hf javacard putkey-aes -k 404142434445464748494A4B4C4D4E4F --kvn 2 --confirm\n"
                  "hf javacard putkey-aes -k <hex> --old-kvn 1 --kvn 2 --kid 1 --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "New AES key used for ENC/MAC/DEK (16, 24, or 32 bytes)"),
        arg_str0(NULL, "enc", "<hex>", "New AES ENC key (16, 24, or 32 bytes)"),
        arg_str0(NULL, "mac", "<hex>", "New AES MAC key (16, 24, or 32 bytes)"),
        arg_str0(NULL, "dek", "<hex>", "New AES DEK key (16, 24, or 32 bytes)"),
        arg_int1(NULL, "kvn", "<dec>", "New Key Version Number (1-127)"),
        arg_int0(NULL, "old-kvn", "<dec>", "Existing KVN to replace; 0 adds a new set"),
        arg_int0(NULL, "kid", "<dec>", "First Key Identifier (default 1; three consecutive IDs)"),
        arg_lit0(NULL, "replace", "compatibility alias: use new KVN as old KVN unless --old-kvn is set"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t same_key[32] = {0}, enc[32] = {0}, mac[32] = {0}, dek[32] = {0};
    int same_len = 0, enc_len = 0, mac_len = 0, dek_len = 0;
    CLIGetHexWithReturn(ctx, 1, same_key, &same_len);
    CLIGetHexWithReturn(ctx, 2, enc, &enc_len);
    CLIGetHexWithReturn(ctx, 3, mac, &mac_len);
    CLIGetHexWithReturn(ctx, 4, dek, &dek_len);
    int new_kvn = arg_get_int(ctx, 5);
    int old_kvn = arg_get_int_def(ctx, 6, 0);
    int first_kid = arg_get_int_def(ctx, 7, 1);
    bool replace_alias = arg_get_lit(ctx, 8);
    bool verbose = arg_get_lit(ctx, 9);
    bool confirmed = arg_get_lit(ctx, 10);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "PUT KEY")) return PM3_EINVARG;

    if (replace_alias && old_kvn == 0) old_kvn = new_kvn;
    if (new_kvn < 1 || new_kvn > 0x7F || old_kvn < 0 || old_kvn > 0x7F) {
        PrintAndLogEx(ERR, "New KVN must be 1-127 and old KVN must be 0-127");
        return PM3_EINVARG;
    }
    if (first_kid < 1 || first_kid > 0x7D) {
        PrintAndLogEx(ERR, "First KID must be 1-125 for a three-key set");
        return PM3_EINVARG;
    }

    size_t key_len = 0;
    uint8_t keyset[3][32] = {{0}};
    if ((same_len == 16 || same_len == 24 || same_len == 32) &&
        enc_len == 0 && mac_len == 0 && dek_len == 0) {
        key_len = (size_t)same_len;
        memcpy(keyset[0], same_key, key_len);
        memcpy(keyset[1], same_key, key_len);
        memcpy(keyset[2], same_key, key_len);
    } else if (same_len == 0 && enc_len == mac_len && mac_len == dek_len &&
               (enc_len == 16 || enc_len == 24 || enc_len == 32)) {
        key_len = (size_t)enc_len;
        memcpy(keyset[0], enc, key_len);
        memcpy(keyset[1], mac, key_len);
        memcpy(keyset[2], dek, key_len);
    } else {
        PrintAndLogEx(ERR, "Use one 16/24/32-byte -k value or three equal-length --enc/--mac/--dek values");
        gp_secure_zero(keyset, sizeof(keyset));
        return PM3_EINVARG;
    }

    PrintAndLogEx(WARNING, _RED_("WARNING:") " PUT KEY modifies SCP03 authentication keys.");
    PrintAndLogEx(INFO, "  Operation: %s KVN %d, first KID %d, new KVN %d, AES-%zu",
                  old_kvn ? "replace" : "add", old_kvn, first_kid, new_kvn, key_len * 8);
    if (gp_ensure_session(verbose) != PM3_SUCCESS) {
        gp_secure_zero(keyset, sizeof(keyset));
        return PM3_ESOFT;
    }
    if (gp_ctx.scp_version != 3) {
        PrintAndLogEx(ERR, "AES PUT KEY requires an SCP03 session");
        gp_secure_zero(keyset, sizeof(keyset));
        return PM3_EINVARG;
    }

    uint8_t data[160] = {0};
    size_t data_len = 0;
    uint8_t kcv[3][3] = {{0}};
    int ret = PM3_SUCCESS;
    data[data_len++] = (uint8_t)new_kvn;
    for (size_t i = 0; i < 3; i++) {
        size_t component_len = 0;
        ret = gp_scp03_build_key_component(gp_ctx.dek_key, gp_ctx.key_len, keyset[i], key_len,
                                           data + data_len, sizeof(data) - data_len, &component_len);
        if (ret != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "AES key protection failed");
            goto cleanup;
        }
        memcpy(kcv[i], data + data_len + component_len - 3, 3);
        data_len += component_len;
    }

    PrintAndLogEx(INFO, "  KCV ENC=%02X%02X%02X MAC=%02X%02X%02X DEK=%02X%02X%02X",
                  kcv[0][0], kcv[0][1], kcv[0][2],
                  kcv[1][0], kcv[1][1], kcv[1][2],
                  kcv[2][0], kcv[2][1], kcv[2][2]);
    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_PUT_KEY,
                          (uint8_t)old_kvn, (uint8_t)(0x80 | first_kid),
                          data, data_len, true, 0x100,
                          resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "PUT KEY communication or secure-messaging error");
        goto cleanup;
    }
    if (!gp_sw_is_success_or_warning(sw)) {
        PrintAndLogEx(ERR, "PUT KEY failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
        ret = PM3_ESOFT;
        goto cleanup;
    }

    PrintAndLogEx(SUCCESS, "PUT KEY accepted: AES-%zu new KVN %d, SW " _GREEN_("%04X"),
                  key_len * 8, new_kvn, sw);
    if (resp_len > 0)
        PrintAndLogEx(INFO, "  Card response: %s", sprint_hex_inrow(resp, resp_len));
    ret = PM3_SUCCESS;

cleanup:
    gp_secure_zero(same_key, sizeof(same_key));
    gp_secure_zero(enc, sizeof(enc));
    gp_secure_zero(mac, sizeof(mac));
    gp_secure_zero(dek, sizeof(dek));
    gp_secure_zero(keyset, sizeof(keyset));
    gp_secure_zero(data, sizeof(data));
    gp_secure_zero(kcv, sizeof(kcv));
    return ret;
}



//=============================================================================
// Command: hf javacard registryupdate  (INSTALL [for registry update])
//=============================================================================

static int CmdHFJavaCardRegistryUpdate(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard registryupdate",
                  "Issue INSTALL [for registry update]. Privileges, registry parameter TLVs,\n"
                  "an optional simultaneous extradition target, and a delegated-management token are supported.",
                  "hf javacard registryupdate -i A0000000030000010001 --priv 04 --confirm\n"
                  "hf javacard registryupdate -i A0000000030000010001 --sd A000000003000002 --confirm\n"
                  "hf javacard registryupdate --open --params D90101 --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("i", "instance", "<hex>", "Application AID; omit only with --open"),
        arg_lit0(NULL, "open", "apply parameter TLVs to OPEN (irreversible restrictions may result)"),
        arg_str0("s", "sd", "<hex>", "new associated Security Domain AID (optional extradition)"),
        arg_str0(NULL, "priv", "<hex>", "replacement privileges: exactly 1 or 3 bytes"),
        arg_str0(NULL, "params", "<hex>", "raw registry-update parameter TLVs"),
        arg_str0(NULL, "token", "<hex>", "registry-update token"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t app[16] = {0}, sd[16] = {0}, priv[3] = {0};
    uint8_t params[192] = {0}, token[192] = {0};
    int app_len = 0, sd_len = 0, priv_len = 0, params_len = 0, token_len = 0;
    CLIGetHexWithReturn(ctx, 1, app, &app_len);
    bool update_open = arg_get_lit(ctx, 2);
    CLIGetHexWithReturn(ctx, 3, sd, &sd_len);
    CLIGetHexWithReturn(ctx, 4, priv, &priv_len);
    CLIGetHexWithReturn(ctx, 5, params, &params_len);
    CLIGetHexWithReturn(ctx, 6, token, &token_len);
    bool verbose = arg_get_lit(ctx, 7);
    bool confirmed = arg_get_lit(ctx, 7 + 1);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "registryupdate")) return PM3_EINVARG;

    if (update_open == (app_len != 0)) {
        PrintAndLogEx(ERR, "Specify exactly one of --instance or --open");
        return PM3_EINVARG;
    }
    if (app_len != 0 && (app_len < 5 || app_len > 16)) {
        PrintAndLogEx(ERR, "Application AID must be 5-16 bytes");
        return PM3_EINVARG;
    }
    if (sd_len != 0 && (sd_len < 5 || sd_len > 16)) {
        PrintAndLogEx(ERR, "Security Domain AID must be 5-16 bytes");
        return PM3_EINVARG;
    }
    if (priv_len != 0 && priv_len != 1 && priv_len != 3) {
        PrintAndLogEx(ERR, "Privileges must be absent, 1 byte, or 3 bytes");
        return PM3_EINVARG;
    }
    if (sd_len == 0 && priv_len == 0 && params_len == 0) {
        PrintAndLogEx(ERR, "No registry modification was requested");
        return PM3_EINVARG;
    }
    if (update_open && params_len == 0) {
        PrintAndLogEx(ERR, "--open requires registry-update parameter TLVs");
        return PM3_EINVARG;
    }

    int ret = gp_ensure_session(verbose);
    if (ret != PM3_SUCCESS) goto cleanup;

    // Table 11-46:
    // L(SD) SD || 00 || L(Application) Application || L(priv) priv ||
    // BER-L(parameters) parameters || BER-L(token) token.
    uint8_t data[GP_MAX_SHORT_APDU_DATA] = {0};
    size_t data_len = 0;
    if (gp_append_lv(data, sizeof(data), &data_len, sd, (size_t)sd_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, NULL, 0, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, app, (size_t)app_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, priv, (size_t)priv_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, params, (size_t)params_len, true) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, token, (size_t)token_len, true) != PM3_SUCCESS ||
        data_len > gp_max_wrapped_command_data()) {
        PrintAndLogEx(ERR, "Registry-update data does not fit a short protected APDU");
        ret = PM3_EINVARG;
        goto cleanup;
    }

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_INSTALL,
                          GP_INSTALL_P1_REGISTRY_UPDATE, 0x00,
                          data, data_len, false, 0,
                          resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) goto cleanup;
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "INSTALL [for registry update] failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription((uint8_t)(sw >> 8), (uint8_t)sw));
        ret = PM3_ESOFT;
        goto cleanup;
    }

    gp_print_install_confirmation(resp, resp_len);
    PrintAndLogEx(SUCCESS, "Registry update " _GREEN_("accepted"));
    ret = PM3_SUCCESS;

cleanup:
    gp_secure_zero(params, sizeof(params));
    gp_secure_zero(token, sizeof(token));
    return ret;
}



//=============================================================================
// Command: hf javacard createsd  (Create a new Supplementary Security Domain)
//=============================================================================

static int CmdHFJavaCardCreateSD(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard createsd",
                  "Install and make selectable a Supplementary Security Domain implementation.\n"
                  "The SecurityDomain privilege must be present. Optional install parameters and token are supported.",
                  "hf javacard createsd -p A000000003000001 -m A000000003000001 -i A000000003000002 --confirm\n"
                  "hf javacard createsd -p <pkg> -m <module> -i <instance> --priv C00000 --token <hex> --confirm");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pkg",      "<hex>", "Executable Load File AID"),
        arg_str1("m", "module",   "<hex>", "Executable Module AID"),
        arg_str1("i", "instance", "<hex>", "new Security Domain instance AID"),
        arg_str0(NULL, "priv",    "<hex>", "privileges, 1 or 3 bytes (default 80)"),
        arg_str0(NULL, "params",  "<hex>", "raw install parameter TLVs (default C900)"),
        arg_str0(NULL, "token",   "<hex>", "install token"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        GP_CONFIRM_ARG,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t pkg[16] = {0}, module[16] = {0}, instance[16] = {0};
    uint8_t priv[3] = {0x80, 0, 0}, params[192] = {0}, token[192] = {0};
    int pkg_len = 0, module_len = 0, instance_len = 0;
    int priv_len = 0, params_len = 0, token_len = 0;
    CLIGetHexWithReturn(ctx, 1, pkg, &pkg_len);
    CLIGetHexWithReturn(ctx, 2, module, &module_len);
    CLIGetHexWithReturn(ctx, 3, instance, &instance_len);
    CLIGetHexWithReturn(ctx, 4, priv, &priv_len);
    CLIGetHexWithReturn(ctx, 5, params, &params_len);
    CLIGetHexWithReturn(ctx, 6, token, &token_len);
    bool verbose = arg_get_lit(ctx, 7);
    bool confirmed = arg_get_lit(ctx, 7 + 1);
    CLIParserFree(ctx);
    if (!gp_require_confirm(confirmed, "createsd")) return PM3_EINVARG;

    if (pkg_len < 5 || pkg_len > 16 || module_len < 5 || module_len > 16 ||
        instance_len < 5 || instance_len > 16) {
        PrintAndLogEx(ERR, "Package, module, and instance AIDs must be 5-16 bytes");
        return PM3_EINVARG;
    }
    if (priv_len == 0) {
        priv[0] = 0x80;
        priv_len = 1;
    }
    if (priv_len != 1 && priv_len != 3) {
        PrintAndLogEx(ERR, "Privileges must be 1 or 3 bytes");
        return PM3_EINVARG;
    }
    if ((priv[0] & 0x80) == 0) {
        PrintAndLogEx(ERR, "The SecurityDomain privilege (byte 1 bit 8) is required");
        return PM3_EINVARG;
    }
    if (params_len == 0) {
        params[0] = 0xC9;
        params[1] = 0x00;
        params_len = 2;
    }

    int ret = gp_ensure_session(verbose);
    if (ret != PM3_SUCCESS) goto cleanup;

    uint8_t data[GP_MAX_SHORT_APDU_DATA] = {0};
    size_t data_len = 0;
    if (gp_append_lv(data, sizeof(data), &data_len, pkg, (size_t)pkg_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, module, (size_t)module_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, instance, (size_t)instance_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, priv, (size_t)priv_len, false) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, params, (size_t)params_len, true) != PM3_SUCCESS ||
        gp_append_lv(data, sizeof(data), &data_len, token, (size_t)token_len, true) != PM3_SUCCESS ||
        data_len > gp_max_wrapped_command_data()) {
        PrintAndLogEx(ERR, "INSTALL data does not fit a short protected APDU");
        ret = PM3_EINVARG;
        goto cleanup;
    }

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    ret = gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_INSTALL,
                          GP_INSTALL_P1_INSTALL_SELECTABLE, 0x00,
                          data, data_len, false, 0,
                          resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) goto cleanup;
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "CREATE SD failed, SW: " _RED_("%04X") " - %s",
                      sw, GetAPDUCodeDescription((uint8_t)(sw >> 8), (uint8_t)sw));
        ret = PM3_ESOFT;
        goto cleanup;
    }

    gp_print_install_confirmation(resp, resp_len);
    PrintAndLogEx(SUCCESS, "Security Domain installed: " _GREEN_("%s"),
                  sprint_hex_inrow(instance, (size_t)instance_len));
    ret = PM3_SUCCESS;

cleanup:
    gp_secure_zero(params, sizeof(params));
    gp_secure_zero(token, sizeof(token));
    return ret;
}



//=============================================================================
// Command: hf javacard script  (run a .gp script file)
//=============================================================================

// A script line is sensitive when it can carry key material or tokens. Such
// lines are never echoed to the console/log.
static bool gp_command_is_sensitive(const char *command) {
    static const char *const prefixes[] = { "auth", "putkey", "keyaudit" };
    for (size_t i = 0; i < ARRAYLEN(prefixes); i++)
        if (strncmp(command, prefixes[i], strlen(prefixes[i])) == 0) return true;
    static const char *const options[] = {
        "--key", "--enc", "--mac", "--dek", "--token", "--load-token", "--show-secrets", "-k"
    };
    for (const char *p = command; *p; p++) {
        if (p != command && !isspace((unsigned char)p[-1])) continue;
        for (size_t i = 0; i < ARRAYLEN(options); i++) {
            size_t n = strlen(options[i]);
            if (strncmp(p, options[i], n) == 0 &&
                (p[n] == '\0' || isspace((unsigned char)p[n]) || p[n] == '=' || p[n] == '-'))
                return true;
        }
    }
    return false;
}

static int CmdHFJavaCardScript(const char *Cmd) {
    static bool script_active = false;
    if (script_active) {
        PrintAndLogEx(ERR, "Nested javacard scripts are not allowed");
        return PM3_EINVARG;
    }

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard script",
                  "Execute one 'hf javacard' subcommand per line.\n"
                  "Leading/trailing whitespace and full-line # or // comments are accepted.\n"
                  "Sensitive key-bearing commands are redacted from logs.",
                  "hf javacard script -f deploy.gp\n"
                  "hf javacard script -f deploy.gp --ignore-errors");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<path>", "script file"),
        arg_lit0(NULL, "ignore-errors", "continue after failed commands, but return failure at the end"),
        arg_lit0("v", "verbose", "show each non-sensitive command"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    char filename[512] = {0};
    int filename_len = (int)sizeof(filename) - 1;
    CLIGetStrWithReturn(ctx, 1, (uint8_t *)filename, &filename_len);
    bool ignore_errors = arg_get_lit(ctx, 2);
    bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        PrintAndLogEx(ERR, "Cannot open script: %s", filename);
        return PM3_EFILE;
    }

    script_active = true;
    int result = PM3_SUCCESS;
    size_t line_number = 0, executed = 0, errors = 0;
    char line[1024];

    while (fgets(line, sizeof(line), fp) != NULL) {
        line_number++;
        size_t length = strlen(line);

        if (length == sizeof(line) - 1 && line[length - 1] != '\n' && !feof(fp)) {
            int ch;
            while ((ch = fgetc(fp)) != '\n' && ch != EOF) {}
            if (ferror(fp)) {
                PrintAndLogEx(ERR, "I/O error while reading script line %zu", line_number);
                result = PM3_EFILE;
                errors++;
                break;
            }
            PrintAndLogEx(ERR, "Script line %zu exceeds %zu bytes", line_number, sizeof(line) - 2);
            errors++;
            if (result == PM3_SUCCESS) result = PM3_EINVARG;
            if (!ignore_errors || ch == EOF) break;
            continue;
        }

        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r' ||
                              isspace((unsigned char)line[length - 1])))
            line[--length] = '\0';

        char *command = line;
        while (*command != '\0' && isspace((unsigned char)*command)) command++;
        if (*command == '\0' || *command == '#' ||
            (command[0] == '/' && command[1] == '/'))
            continue;

        // Reject direct or prefixed recursion.
        const char *subcommand = command;
        if (strncmp(subcommand, "hf javacard ", 12) == 0) subcommand += 12;
        while (*subcommand && isspace((unsigned char)*subcommand)) subcommand++;
        if (strncmp(subcommand, "script", 6) == 0 &&
            (subcommand[6] == '\0' || isspace((unsigned char)subcommand[6]))) {
            PrintAndLogEx(ERR, "Nested script command at line %zu is not allowed", line_number);
            errors++;
            if (result == PM3_SUCCESS) result = PM3_EINVARG;
            if (!ignore_errors) break;
            continue;
        }

        bool sensitive = gp_command_is_sensitive(subcommand);

        if (verbose) {
            if (sensitive)
                PrintAndLogEx(INFO, "[%zu] hf javacard <sensitive command redacted>", line_number);
            else
                PrintAndLogEx(INFO, "[%zu] hf javacard %s", line_number, subcommand);
        }

        int command_result = CmdHFJavaCard(subcommand);
        executed++;
        if (command_result != PM3_SUCCESS) {
            errors++;
            if (result == PM3_SUCCESS) result = command_result;
            if (sensitive)
                PrintAndLogEx(ERR, "Line %zu failed (sensitive command redacted)", line_number);
            else
                PrintAndLogEx(ERR, "Line %zu failed: %s", line_number, subcommand);
            if (!ignore_errors) break;
        }
    }

    if (ferror(fp) && result == PM3_SUCCESS) {
        PrintAndLogEx(ERR, "I/O error while reading script");
        result = PM3_EFILE;
    }
    fclose(fp);
    script_active = false;

    PrintAndLogEx(INFO, "Script complete: %zu command(s), %zu error(s)", executed, errors);
    return result;
}



//=============================================================================
// Lua-accessible GP primitives (Feature 14)
// Exposed via cmdhfjavacard.h for scripting.c to register.
//=============================================================================

// Send a raw hex APDU, return response hex + SW as a 2-element array on Lua stack.
// Lua: resp_hex, sw = core.gp_send("84CA009F00")
int CmdHFJavaCard_lua_send(lua_State *L) {
    if (!lua_isstring(L, 1)) {
        lua_pushnil(L);
        lua_pushstring(L, "expected a hexadecimal APDU string");
        return 2;
    }

    size_t text_len = 0;
    const char *text = lua_tolstring(L, 1, &text_len);
    if (text == NULL || text_len == 0 || text_len > PM3_CMD_DATA_SIZE * 3) {
        lua_pushnil(L);
        lua_pushstring(L, "invalid APDU string length");
        return 2;
    }

    uint8_t apdu[PM3_CMD_DATA_SIZE] = {0};
    size_t apdu_len = 0;
    if (gp_parse_hex_string(text, apdu, sizeof(apdu), &apdu_len) != PM3_SUCCESS ||
        apdu_len < 4) {
        lua_pushnil(L);
        lua_pushstring(L, "invalid hexadecimal APDU");
        return 2;
    }

    bool activate = lua_gettop(L) >= 2 && lua_toboolean(L, 2);
    bool leave_on = lua_gettop(L) >= 3 && lua_toboolean(L, 3);

    uint8_t resp[GP_RESP_BUF_SIZE] = {0};
    size_t resp_len = 0;
    uint16_t sw = 0;
    int ret = gp_send_apdu(activate, leave_on, apdu, apdu_len,
                           resp, sizeof(resp), &resp_len, &sw, false);
    if (ret != PM3_SUCCESS) {
        lua_pushnil(L);
        lua_pushfstring(L, "communication error (%d)", ret);
        return 2;
    }

    char hex_resp[GP_RESP_BUF_SIZE * 2 + 1] = {0};
    for (size_t i = 0; i < resp_len; i++)
        snprintf(hex_resp + i * 2, sizeof(hex_resp) - i * 2, "%02X", resp[i]);

    lua_pushlstring(L, hex_resp, resp_len * 2);
    lua_pushinteger(L, (lua_Integer)sw);
    return 2;
}



// Open a GP session. Returns true/false + error message.
// Lua: ok, msg = core.gp_auth("404142434445464748494A4B4C4D4E4F", 2, 3)
int CmdHFJavaCard_lua_auth(lua_State *L) {
    if (!lua_isstring(L, 1)) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "expected a hexadecimal key");
        return 2;
    }

    size_t text_len = 0;
    const char *text = lua_tolstring(L, 1, &text_len);
    uint8_t key[GP_MAX_AES_KEY_LEN] = {0};
    size_t key_len = 0;
    if (text == NULL ||
        gp_parse_hex_string(text, key, sizeof(key), &key_len) != PM3_SUCCESS ||
        (key_len != 16 && key_len != 24 && key_len != 32)) {
        gp_secure_zero(key, sizeof(key));
        lua_pushboolean(L, 0);
        lua_pushstring(L, "key must contain 16, 24, or 32 bytes");
        return 2;
    }

    int scp = lua_gettop(L) >= 2 ? (int)lua_tointeger(L, 2) : 0;
    int security_level = lua_gettop(L) >= 3 ? (int)lua_tointeger(L, 3) : 0x03;
    if (scp < 0 || scp > 3 || security_level < 0 || security_level > 0xFF) {
        gp_secure_zero(key, sizeof(key));
        lua_pushboolean(L, 0);
        lua_pushstring(L, "invalid SCP version or security level");
        return 2;
    }

    char key_hex[GP_MAX_AES_KEY_LEN * 2 + 1] = {0};
    for (size_t i = 0; i < key_len; i++)
        snprintf(key_hex + i * 2, sizeof(key_hex) - i * 2, "%02X", key[i]);

    char command[192] = {0};
    int written;
    if (scp != 0) {
        written = snprintf(command, sizeof(command),
                           "auth -k %s --scp %d --sl %02X",
                           key_hex, scp, (unsigned)security_level);
    } else {
        written = snprintf(command, sizeof(command),
                           "auth -k %s --sl %02X",
                           key_hex, (unsigned)security_level);
    }

    gp_secure_zero(key, sizeof(key));
    gp_secure_zero(key_hex, sizeof(key_hex));
    if (written < 0 || (size_t)written >= sizeof(command)) {
        gp_secure_zero(command, sizeof(command));
        lua_pushboolean(L, 0);
        lua_pushstring(L, "authentication command too long");
        return 2;
    }

    int ret = CmdHFJavaCard(command);
    gp_secure_zero(command, sizeof(command));
    lua_pushboolean(L, ret == PM3_SUCCESS);
    lua_pushstring(L, ret == PM3_SUCCESS ? "ok" : "authentication failed");
    return 2;
}



// Return session info to Lua.
// Lua: active, scp_ver = core.gp_session()
int CmdHFJavaCard_lua_session(lua_State *L) {
    lua_pushboolean(L, gp_ctx.active ? 1 : 0);
    lua_pushinteger(L, (lua_Integer)gp_ctx.scp_version);
    return 2;
}

//=============================================================================
// Command: hf javacard scan  (read-only AID discovery)
//=============================================================================

// Extra probe targets that are not in the compact name table.
static const struct { uint8_t aid[16]; uint8_t len; const char *name; } GP_SCAN_EXTRA[] = {
    { { 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00 }, 7, "GP ISD (short AID)" },
    { { 0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50, 0x41 }, 8, "GP SSD module" },
    { { 0xA0, 0x00, 0x00, 0x00, 0x18, 0x43, 0x4D, 0x00 }, 8, "GP Card Manager (legacy)" },
    { { 0xA0, 0x00, 0x00, 0x03, 0x08 }, 5, "PIV (RID only)" },
    { { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 }, 7, "NFC Forum Type 4 NDEF" },
    { { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01 }, 8, "Yubico OTP" },
    { { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01 }, 7, "Yubico OATH" },
    { { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17 }, 8, "Yubico management" },
    { { 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01 }, 8, "FIDO U2F / CTAP" },
    { { 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00 }, 16, "IDPrime / MS minidriver" },
    { { 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 }, 12, "PKCS#15" },
    { { 0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31 }, 14, "EMV PSE (1PAY.SYS.DDF01)" },
    { { 0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31 }, 14, "EMV PPSE (2PAY.SYS.DDF01)" },
    { { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 }, 7, "ICAO eMRTD (LDS)" },
    { { 0xD2, 0x76, 0x00, 0x01, 0x18, 0x00, 0x02, 0xFF, 0x34, 0x83, 0x83, 0x36, 0x44, 0x01 }, 14, "Ledger / BTChip" },
    { { 0x53, 0x61, 0x74, 0x6F, 0x43, 0x68, 0x69, 0x70 }, 8, "Satochip" },
    { { 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01 }, 8, "Keycard / Status wallet" },
    { { 0xF0, 0x00, 0x00, 0x00, 0x01 }, 5, "Vendor test RID F000000001" },
};

static int gp_scan_one(json_t *aidroot, const uint8_t *aid, size_t aid_len, const char *name,
                       bool first, bool verbose, size_t *found) {
    uint8_t resp[GP_RESP_BUF_SIZE];
    size_t resp_len = 0;
    uint16_t sw = 0;
    int ret = gp_plain_apdu(first, true, 0x00, GP_INS_SELECT, 0x04, 0x00, aid, aid_len, true, 0x100,
                            resp, sizeof(resp), &resp_len, &sw, verbose);
    if (ret != PM3_SUCCESS) return ret;
    // Only these status words mean the AID was selected. Anything else (6A82,
    // 6999, and 6D00/6E00 when the JCRE forwards an unknown SELECT to the
    // currently selected applet) means the AID is absent.
    bool selected = sw == 0x9000 || (sw & 0xFF00) == 0x6100;
    bool locked = sw == 0x6283;
    if (!selected && !locked) {
        if (verbose) PrintAndLogEx(INFO, "  %-32s %04X  %-9s %s", sprint_hex_inrow(aid, aid_len), sw, "absent", name);
        return PM3_SUCCESS;
    }
    (*found)++;
    char aid_hex[40];
    snprintf(aid_hex, sizeof(aid_hex), "%-32s", sprint_hex_inrow(aid, aid_len));
    PrintAndLogEx(SUCCESS, "  " _GREEN_("%s") " %04X  %s %s", aid_hex, sw,
                  locked ? _YELLOW_("locked   ") : _GREEN_("selected "), name);
    if (resp_len > 0)
        PrintAndLogEx(INFO, "      FCI (%zu): %s", resp_len, sprint_hex_inrow(resp, resp_len > 48 ? 48 : resp_len));
    if (aidroot) {
        uint8_t copy[16];
        memcpy(copy, aid, aid_len);
        PrintAIDDescriptionBuf(aidroot, copy, aid_len, false);
    }
    return PM3_SUCCESS;
}

static int CmdHFJavaCardScan(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard scan",
                  "Discover applets by SELECTing well-known AIDs (read-only, no authentication).\n"
                  "Probes the GlobalPlatform, identity, FIDO, wallet, NDEF and payment AIDs this tool knows,\n"
                  "and optionally every application instance listed in an authenticated registry.",
                  "hf javacard scan\n"
                  "hf javacard scan -a D2760001240103040000000000000000\n"
                  "hf javacard scan --registry\n"
                  "hf javacard scan -v");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("a", "aid", "<hex>", "additional AID to probe (5-16 bytes)"),
        arg_lit0(NULL, "registry", "also probe instances from GET STATUS (uses an existing or default-key session)"),
        arg_lit0("v", "verbose", "show every probe, including absent AIDs"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t extra[16] = {0};
    int extra_len = 0;
    CLIGetHexWithReturn(ctx, 1, extra, &extra_len);
    bool from_registry = arg_get_lit(ctx, 2);
    bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);
    if (extra_len != 0 && (extra_len < 5 || extra_len > 16)) {
        PrintAndLogEx(ERR, "AID must be 5-16 bytes");
        return PM3_EINVARG;
    }

    // Registry instances first (needs a secure channel; selecting ends it).
    uint8_t registry[4096];
    size_t registry_len = 0;
    if (from_registry) {
        if (gp_ensure_session(false) != PM3_SUCCESS) return PM3_ESOFT;
        uint8_t resp[GP_RESP_BUF_SIZE];
        uint8_t p2 = 0x02;
        uint16_t sw = 0;
        do {
            size_t resp_len = 0;
            const uint8_t filter[] = {0x4F, 0x00};
            if (gp_wrapped_apdu(false, true, GP_CLA_PLAIN, GP_INS_GET_STATUS, GP_STATUS_APPS_AND_SSD, p2,
                                filter, sizeof(filter), true, 0x100, resp, sizeof(resp), &resp_len, &sw,
                                false) != PM3_SUCCESS)
                break;
            if (sw != 0x9000 && sw != 0x6310) break;
            if (resp_len > sizeof(registry) - registry_len) break;
            memcpy(registry + registry_len, resp, resp_len);
            registry_len += resp_len;
            p2 = 0x03;
        } while (sw == 0x6310);
        gp_drop_field();
    }

    gp_print_banner("JavaCard AID Scan");
    PrintAndLogEx(INFO, "  %-32s %-4s  %-9s %s", "AID", "SW", "State", "Name");
    PrintAndLogEx(INFO, "  -------------------------------- ----  --------- -------------------------");
    json_t *aidroot = AIDSearchInit(false);
    size_t found = 0, probed = 0;
    bool first = true;
    int ret = PM3_SUCCESS;

#define GP_SCAN(aid_, len_, name_) do { \
        ret = gp_scan_one(aidroot, (aid_), (len_), (name_), first, verbose, &found); \
        first = false; probed++; \
        if (ret != PM3_SUCCESS) goto out; \
    } while (0)

    if (extra_len) GP_SCAN(extra, (size_t)extra_len, "user supplied");
    size_t offset = 0;
    while (offset < registry_len) {
        uint32_t tag;
        const uint8_t *entry, *aid;
        size_t entry_len, aid_len;
        if (gp_ber_read_tlv(registry, registry_len, &offset, &tag, &entry, &entry_len) != PM3_SUCCESS) break;
        size_t inner = 0;
        uint32_t inner_tag;
        if (tag == 0xE3 && gp_ber_read_tlv(entry, entry_len, &inner, &inner_tag, &aid, &aid_len) == PM3_SUCCESS &&
            inner_tag == 0x4F && aid_len >= 5 && aid_len <= 16)
            GP_SCAN(aid, aid_len, "registry instance");
    }
    for (size_t i = 0; i < GP_KNOWN_AIDS_COUNT; i++)
        GP_SCAN(GP_KNOWN_AIDS[i].aid, GP_KNOWN_AIDS[i].aid_len, GP_KNOWN_AIDS[i].name);
    for (size_t i = 0; i < ARRAYLEN(GP_SCAN_EXTRA); i++)
        GP_SCAN(GP_SCAN_EXTRA[i].aid, GP_SCAN_EXTRA[i].len, GP_SCAN_EXTRA[i].name);
#undef GP_SCAN

out:
    if (aidroot) AIDSearchFree(aidroot);
    gp_drop_field();
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Probed " _YELLOW_("%zu") " AID(s), " _GREEN_("%zu") " selectable", probed, found);
    if (!from_registry)
        PrintAndLogEx(HINT, "Hint: add `" _YELLOW_("--registry") "` to also probe every installed instance");
    return ret;
}

//=============================================================================
// Command: hf javacard keyaudit  (offline default-key check per key set)
//=============================================================================

// Check every default key and diversification against one INITIALIZE UPDATE
// response. Returns true with the matching name/KDF. Never contacts the card.
static bool gp_match_default_key(int scp, uint8_t scp_i, const uint8_t *resp, size_t resp_len,
                                 const uint8_t *host_chal, const char **name, gp_kdf_template_t *kdf_out) {
    if (resp_len < 28) return false;
    const uint8_t *kdd = resp;
    size_t clen = 8;
    const uint8_t *card_chal = resp + 12, *card_cg = resp + 20;
    uint8_t ssc[2] = { resp[12], resp[13] };
    if (scp == 3) {
        clen = (scp_i & 0x01) ? 16 : 8;
        if (resp_len < 13 + 2 * clen) return false;
        card_chal = resp + 13;
        card_cg = card_chal + clen;
    }
    static const gp_kdf_template_t legacy[] = {GP_KDF_NONE, GP_KDF_EMV, GP_KDF_VISA2, GP_KDF_VISA};
    static const gp_kdf_template_t aes[] = {GP_KDF_NONE, GP_KDF_KDF3};
    const gp_kdf_template_t *kdfs = scp == 3 ? aes : legacy;
    size_t kdf_count = scp == 3 ? ARRAYLEN(aes) : ARRAYLEN(legacy);
    uint8_t e[32], m[32], d[32], s1[32], s2[32], s3[32], s4[32];
    bool ok = false;
    for (size_t k = 0; k < GP_DEFAULT_KEYS_COUNT && !ok; k++) {
        if (!(GP_DEFAULT_KEYS[k].scp_flags & (scp == 3 ? GP_DB_SCP03 : GP_DB_SCP02))) continue;
        const uint8_t *key = GP_DEFAULT_KEYS[k].key;
        for (size_t j = 0; j < kdf_count && !ok; j++) {
            if (scp == 3) {
                if (gp_scp03_diversify_key(key, 16, kdd, 1, kdfs[j], e) ||
                    gp_scp03_diversify_key(key, 16, kdd, 2, kdfs[j], m)) continue;
                ok = gp_scp03_try_keyset(e, m, 16, host_chal, clen, card_chal, card_cg, clen, s1, s2, s3);
            } else {
                if (gp_diversify_3des_key(key, kdd, 1, kdfs[j], e) ||
                    gp_diversify_3des_key(key, kdd, 2, kdfs[j], m) ||
                    gp_diversify_3des_key(key, kdd, 3, kdfs[j], d)) continue;
                ok = scp == 1 ? gp_scp01_try_keyset(e, m, host_chal, card_chal, card_cg, s1, s2)
                              : gp_scp02_try_keyset(e, m, d, ssc, host_chal, card_chal, card_cg, s1, s2, s3, s4);
            }
            if (ok) {
                *name = GP_DEFAULT_KEYS[k].name;
                *kdf_out = kdfs[j];
            }
        }
    }
    gp_secure_zero(e, sizeof(e)); gp_secure_zero(m, sizeof(m)); gp_secure_zero(d, sizeof(d));
    gp_secure_zero(s1, sizeof(s1)); gp_secure_zero(s2, sizeof(s2));
    gp_secure_zero(s3, sizeof(s3)); gp_secure_zero(s4, sizeof(s4));
    return ok;
}

static int CmdHFJavaCardKeyAudit(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard keyaudit",
                  "Check each key set on the card against the built-in default keys.\n"
                  "For every KVN reported by GET DATA 00E0 one INITIALIZE UPDATE is sent and the card\n"
                  "cryptogram is verified offline. EXTERNAL AUTHENTICATE is never sent, so failed\n"
                  "authentication counters are never touched (the SCP sequence counter may advance).",
                  "hf javacard keyaudit\n"
                  "hf javacard keyaudit --kvn 1\n"
                  "hf javacard keyaudit -v");
    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "kvn", "<dec>", "audit only this Key Version Number"),
        arg_lit0("v", "verbose", "verbose APDU output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int only_kvn = arg_get_int_def(ctx, 1, -1);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);
    if (only_kvn > 0xFF) {
        PrintAndLogEx(ERR, "KVN must be 0-255");
        return PM3_EINVARG;
    }
    if (gp_ctx.active) PrintAndLogEx(WARNING, "The active secure channel will be closed");
    gp_drop_field();
    clearCommandBuffer();

    uint16_t sw = 0;
    int ret = gp_select_isd(true, true, &sw, verbose);
    if (ret != PM3_SUCCESS || sw != 0x9000) {
        PrintAndLogEx(ERR, "Cannot select the ISD (SW %04X)", sw);
        gp_drop_field();
        return ret == PM3_SUCCESS ? PM3_ESOFT : ret;
    }

    uint8_t kvns[32];
    size_t kvn_count = 0;
    if (only_kvn >= 0) {
        kvns[kvn_count++] = (uint8_t)only_kvn;
    } else {
        uint8_t resp[GP_RESP_BUF_SIZE];
        size_t resp_len = 0;
        if (gp_get_data_plain(0x00, 0xE0, resp, sizeof(resp), &resp_len, verbose)) {
            const uint8_t *body;
            size_t body_len, offset = 0;
            gp_tlv_unwrap(resp, resp_len, 0xE0, &body, &body_len);
            uint32_t tag;
            const uint8_t *entry;
            size_t entry_len;
            while (offset < body_len &&
                   gp_ber_read_tlv(body, body_len, &offset, &tag, &entry, &entry_len) == PM3_SUCCESS) {
                if (tag != 0xC0 || entry_len < 2) continue;
                bool seen = false;
                for (size_t i = 0; i < kvn_count; i++) seen |= kvns[i] == entry[1];
                if (!seen && kvn_count < sizeof(kvns)) kvns[kvn_count++] = entry[1];
            }
        }
        if (kvn_count == 0) kvns[kvn_count++] = 0x00;  // "any / default key set"
    }

    gp_print_banner("GlobalPlatform Key Audit");
    PrintAndLogEx(INFO, "  KVN  SCP     Result");
    PrintAndLogEx(INFO, "  ---  ------  ----------------------------------------------");
    size_t weak = 0;
    for (size_t i = 0; i < kvn_count; i++) {
        uint8_t host_chal[8], resp[GP_RESP_BUF_SIZE];
        size_t resp_len = 0;
        if (gp_random_bytes(host_chal, sizeof(host_chal)) != PM3_SUCCESS) { ret = PM3_ESOFT; break; }
        ret = gp_plain_apdu(false, true, GP_CLA_PLAIN, GP_INS_INITIALIZE_UPDATE, kvns[i], 0x00,
                            host_chal, sizeof(host_chal), false, 0, resp, sizeof(resp), &resp_len, &sw, verbose);
        if (ret != PM3_SUCCESS) break;
        if (sw != 0x9000 || resp_len < 12) {
            PrintAndLogEx(INFO, "  %02X   -       INITIALIZE UPDATE refused, SW %04X - %s", kvns[i], sw,
                          GetAPDUCodeDescription(sw >> 8, sw & 0xFF));
            continue;
        }
        int scp = resp[11];
        uint8_t scp_i = scp == 3 && resp_len > 12 ? resp[12] : 0x55;
        const char *name = NULL;
        gp_kdf_template_t kdf = GP_KDF_NONE;
        if (scp != 1 && scp != 2 && scp != 3) {
            PrintAndLogEx(INFO, "  %02X   ?%02X     unsupported SCP identifier", kvns[i], scp);
        } else if (scp == 3 && (scp_i & 0x01)) {
            PrintAndLogEx(INFO, "  %02X   SCP03   S16 key set: rerun `hf javacard auth --s16` to test", resp[10]);
        } else if (gp_match_default_key(scp, scp_i, resp, resp_len, host_chal, &name, &kdf)) {
            weak++;
            PrintAndLogEx(WARNING, "  %02X   SCP%02d   " _RED_("DEFAULT KEY") " %s, diversification %s",
                          resp[10], scp, name, gp_kdf_template_name(kdf));
        } else {
            PrintAndLogEx(SUCCESS, "  %02X   SCP%02d   " _GREEN_("no known default key"), resp[10], scp);
        }
        // Each INITIALIZE UPDATE needs a fresh selection of the ISD.
        if (i + 1 < kvn_count) {
            ret = gp_select_isd(false, true, &sw, verbose);
            if (ret != PM3_SUCCESS) break;
        }
    }
    gp_drop_field();
    PrintAndLogEx(NORMAL, "");
    if (weak)
        PrintAndLogEx(WARNING, _RED_("%zu") " key set(s) use publicly known keys: anyone can manage this card", weak);
    else if (ret == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "No key set matched the built-in default-key list");
    return ret;
}

//=============================================================================
// Command: hf javacard session  (secure-channel status / close)
//=============================================================================

static const char *gp_sl_name(uint8_t sl) {
    switch (sl) {
        case GP_SL_NO_SECURITY: return "no security";
        case GP_SL_C_MAC:       return "C-MAC";
        case GP_SL_C_DEC_MAC:   return "C-DECRYPTION + C-MAC";
        case GP_SL_C_MAC_R_MAC: return "C-MAC + R-MAC";
        case GP_SL_C_DEC_MAC_R: return "C-DECRYPTION + C-MAC + R-MAC";
        case GP_SL_C_DEC_R_ENC: return "C-DECRYPTION + C-MAC + R-ENCRYPTION + R-MAC";
        default:                return "non-standard";
    }
}

static int CmdHFJavaCardSession(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard session",
                  "Show the state of the client-side secure channel, or close it.",
                  "hf javacard session\n"
                  "hf javacard session --close");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("c", "close", "close the session and switch the RF field off"),
        arg_lit0("v", "verbose", "also show chaining state and transport statistics (never keys)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool close_session = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    gp_print_banner("Secure Channel Session");
    if (gp_link.valid) {
        gp_print_kv("ISO-DEP link", "FSC %u, FWI %u (FWT %.2f ms), SFGI %u", gp_link.fsc, gp_link.fwi,
                    gp_link.fwt_fc * 1000.0 / GP_FC_HZ, gp_link.sfgi);
        gp_print_kv("Reader listen window", "%.2f ms (59 x (FWT+dFWT), firmware-capped)",
                    gp_link.reader_timeout_etu * (double)GP_ETU_FC * 1000.0 / GP_FC_HZ);
        gp_print_kv("Device idle deadline", "%u ms (derived from WTX limits)", gp_link.client_idle_ms);
    }
    if (!gp_ctx.active) {
        gp_print_kv("State", _YELLOW_("closed"));
        PrintAndLogEx(HINT, "Hint: open one with `" _YELLOW_("hf javacard auth") "`");
        return PM3_SUCCESS;
    }
    gp_print_kv("State", _GREEN_("open"));
    gp_print_kv("Protocol", "SCP%02u i=%02X%s", gp_ctx.scp_version, gp_ctx.scp_i,
                gp_ctx.scp_version == 3 ? (gp_ctx.mac_len == 16 ? " (S16)" : " (S8)") : "");
    gp_print_kv("Security level", "%02X (%s)", gp_ctx.security_level, gp_sl_name(gp_ctx.security_level));
    gp_print_kv("Session keys", "%s-%zu", gp_ctx.scp_version == 3 ? "AES" : "TDEA", gp_ctx.key_len * 8);
    if (gp_ctx.scp_version == 3)
        gp_print_kv("Command counter", "%s", sprint_hex_inrow(gp_ctx.enc_counter + 12, 4));
    else
        gp_print_kv("Sequence counter", "%02X%02X", gp_ctx.ssc[0], gp_ctx.ssc[1]);
    if (verbose) {
        gp_print_kv("Modified APDU (SCP01/02)", "%s", gp_ctx.scp02_modified_apdu ? "yes" : "no");
        if (gp_ctx.scp_version == 3)
            gp_print_kv("MAC chaining value", "%s", sprint_hex_inrow(gp_ctx.chaining_value, 16));
        else
            gp_print_kv("C-MAC ICV", "%s", sprint_hex_inrow(gp_ctx.icv, 8));
        if (gp_ctx.security_level & GP_SL_R_MAC)
            gp_print_kv("R-MAC ICV", "%s", sprint_hex_inrow(gp_ctx.rmac_icv, 8));
        gp_print_kv("Last / slowest exchange", "%" PRIu64 " ms / %" PRIu64 " ms", gp_last_exchange_ms, gp_max_exchange_ms);
    }
    if (close_session) {
        gp_drop_field();
        PrintAndLogEx(SUCCESS, "Session closed and field switched off");
    }
    return PM3_SUCCESS;
}

//=============================================================================
// Offline regression tests
//=============================================================================

static struct {
    size_t calls;
    bool kept_field;
    bool dropped;
    bool corrupt;
    bool missing;
} gp_test_transport;

static void gp_test_field_off(void) {
    gp_test_transport.dropped = true;
}

static int gp_test_exchange(const uint8_t *command, int command_len, bool activate, bool keep,
                             uint8_t *response, int capacity, int *length) {
    const uint8_t result[] = {1, 2, 3, 0x43, 0x73, 0x5d, 0xeb, 0x68, 0xa0, 0x26, 0xfe, 0x90, 0};
    gp_test_transport.calls++;
    gp_test_transport.kept_field = keep;
    if (activate || command_len != 14 || command[0] != 0x84 || capacity < (int)sizeof(result))
        return PM3_ESOFT;
    memcpy(response, result, sizeof(result));
    *length = sizeof(result);
    if (gp_test_transport.corrupt) response[3] ^= 1;
    if (gp_test_transport.missing) {
        response[3] = 0x90;
        response[4] = 0;
        *length = 5;
    }
    return PM3_SUCCESS;
}

static struct {size_t mode, calls; bool matched;} gp_plain_fixture;

static int gp_test_plain_exchange(const uint8_t *command, int command_len, bool activate, bool keep,
                                   uint8_t *response, int capacity, int *length) {
    size_t step = gp_plain_fixture.calls++, mode = gp_plain_fixture.mode;
    gp_plain_fixture.matched &= !activate && keep && command_len == 5 &&
                               command[1] == (step && mode != 3 && mode != 5 ? 0xc0 : 0xca);
    uint16_t sw = 0x9000;
    uint8_t body[2] = {step ? 0xbb : 0xaa, 0xbb};
    size_t body_len = 0;
    if (mode == 6) sw = 0x6101;
    else if (mode == 5) sw = 0x6c02;
    else if (mode == 3) {
        sw = step ? 0x9000 : 0x6c02;
        if (step) { gp_plain_fixture.matched &= command[4] == 2; body[0] = 0xaa; body_len = 2; }
    } else if (mode == 4) {
        sw = step == 0 ? 0x6102 : step == 1 ? 0x6c01 : 0x9000;
        if (step == 2) { gp_plain_fixture.matched &= command[4] == 1; body_len = 1; }
    } else if (mode != 8) {
        sw = step ? 0x9000 : 0x6101;
        body_len = mode == 2 && !step ? 0 : 1;
    }
    if (mode == 7 && step) return PM3_ETIMEOUT;
    if (capacity < (int)body_len + 2) return PM3_EOVFLOW;
    memcpy(response, body, body_len);
    response[body_len] = sw >> 8;
    response[body_len + 1] = sw & 255;
    *length = body_len + 2;
    return PM3_SUCCESS;
}

static int CmdHFJavaCardTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf javacard test", "Run offline JavaCard/GlobalPlatform regression tests; no APDUs are sent.", "hf javacard test");
    void *argtable[] = {arg_param_begin, arg_lit0("v", "verbose", "list every table-driven case"), arg_param_end};
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    size_t failures = 0, count = 0;
    uint8_t key[32], data[64];
    for (size_t i = 0; i < sizeof(key); i++) key[i] = i;
    for (size_t i = 0; i < sizeof(data); i++) data[i] = i;
    // Expected values independently generated with OpenSSL CMAC.
    static const struct {size_t key_len, data_len; const char *expected;} cmac[] = {
        {16, 0, "97DD6E5A882CBD564C39AE7D1C5A31AA"},
        {16, 16, "7BCFBBCA7A2EA68B966FC5399F74809E"},
        {16, 17, "DBAB59423FBEC5A7BE32C48CE1A80E33"},
        {16, 40, "29146CA62A432AD98F98C34F23D2091A"},
        {24, 0, "EC12390EA0A7ED15D9D37A6ECA1FC990"},
        {24, 16, "F81BDE0069A6E389573BF04E7CDE688C"},
        {24, 17, "B44B5537487FF252C3F5E315ADDDD28A"},
        {24, 40, "8C0A63AF32CF900476BED1DF4C638156"},
        {32, 0, "6BF0A293D8CBA0101F0089727691B7FB"},
        {32, 16, "59EE3F3B5F83E290CAE26DAD29BBA32D"},
        {32, 17, "2F27D64C9702142DAA1A79049EA199AC"},
        {32, 40, "7BAE7A94C624D7AA58A7D2541EB8002B"},
    };
    for (size_t i = 0; i < ARRAYLEN(cmac); i++) {
        uint8_t expected[16], actual[16];
        size_t length;
        bool passed = gp_parse_hex_string(cmac[i].expected, expected, sizeof(expected), &length) == 0 && length == 16 &&
                      gp_aes_cmac(key, cmac[i].key_len, data, cmac[i].data_len, actual) == 0 &&
                      gp_consttime_equal(actual, expected, sizeof(expected));
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "CMAC %zu-bit/%zu-byte test ( %s )", cmac[i].key_len * 8, cmac[i].data_len, passed ? "ok" : "fail");
    }
    static const struct {uint8_t scp; size_t length; const char *expected;} wrapped[] = {
        {1, 2, "84F2800210AE919F36D0299B9F96357219423931CF"},
        {1, 7, "84F2800210B0890F1020000C83953781459D5619C5"},
        {2, 2, "84F28002103B3722009346F6FE96357219423931CF"},
        {2, 8, "84F2800218F1D75E4F0D37C22C0ACD159AF64E529EBDA2EA48971D6BFB"},
    };
    gp_session_t saved = gp_ctx;
    for (size_t i = 0; i < ARRAYLEN(wrapped); i++) {
        gp_session_reset();
        gp_ctx.active = true;
        gp_ctx.scp_version = wrapped[i].scp;
        gp_ctx.scp02_modified_apdu = true;
        gp_ctx.security_level = GP_SL_C_DEC_MAC;
        for (size_t j = 0; j < 16; j++) gp_ctx.enc_key[j] = gp_ctx.mac_key[j] = 0x40 + j;
        uint8_t expected[64], actual[GP_MAX_WRAPPED_APDU];
        size_t expected_len = 0, actual_len = 0;
        bool passed = gp_parse_hex_string(wrapped[i].expected, expected, sizeof(expected), &expected_len) == 0 &&
                      gp_scp02_wrap(0x80, 0xf2, 0x80, 2, data, wrapped[i].length, actual, &actual_len) == 0 &&
                      actual_len == expected_len && gp_consttime_equal(actual, expected, expected_len);
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "SCP%02u encrypted command test %zu ( %s )", wrapped[i].scp, i + 1, passed ? "ok" : "fail");
    }
    gp_exchange_fn saved_exchange = gp_exchange;
    void (*saved_field_off)(void) = gp_field_off;
    gp_exchange = gp_test_exchange;
    gp_field_off = gp_test_field_off;
    for (size_t i = 0; i < 4; i++) {
        gp_session_reset();
        memset(&gp_test_transport, 0, sizeof(gp_test_transport));
        gp_test_transport.corrupt = i == 2;
        gp_test_transport.missing = i == 3;
        gp_ctx.active = true;
        gp_ctx.scp_version = 2;
        gp_ctx.scp02_modified_apdu = true;
        gp_ctx.security_level = GP_SL_C_MAC_R_MAC;
        for (size_t j = 0; j < 16; j++) gp_ctx.mac_key[j] = gp_ctx.rmac_key[j] = j;
        uint8_t response[32];
        size_t length = 0;
        uint16_t sw = 0;
        int res = gp_wrapped_apdu(false, i == 1, 0x80, 0xca, 0x9f, 0x7f, NULL, 0,
                                   true, 256, response, sizeof(response), &length, &sw, false);
        bool passed = gp_test_transport.calls == 1 && gp_test_transport.kept_field &&
                      gp_test_transport.dropped == (i != 1) && gp_ctx.active == (i == 1);
        if (i < 2)
            passed &= res == 0 && sw == 0x9000 && length == 3 && response[0] == 1 && response[2] == 3;
        else
            passed &= res == PM3_ESOFT;
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Response authentication before field release test %zu ( %s )", i + 1, passed ? "ok" : "fail");
    }
    gp_exchange = gp_test_plain_exchange;
    for (size_t mode = 0; mode < 10; mode++) {
        memset(&gp_test_transport, 0, sizeof(gp_test_transport));
        gp_plain_fixture.mode = mode;
        gp_plain_fixture.calls = 0;
        gp_plain_fixture.matched = true;
        uint8_t response[12];
        memset(response, 0xa5, sizeof(response));
        size_t capacity = mode == 1 ? 2 : mode == 2 || mode == 9 ? 3 : 8;
        size_t length = 99;
        uint16_t sw = 0;
        int res = gp_plain_apdu(false, false, 0x80, 0xca, 0, 0, NULL, 0, true, 256,
                                 response + 1, capacity, &length, &sw, false);
        int expected = mode == 1 || mode == 6 || mode == 9 ? PM3_EOVFLOW :
                       mode == 5 ? PM3_EWRONGANSWER : mode == 7 ? PM3_ETIMEOUT : PM3_SUCCESS;
        size_t calls = mode == 1 || mode == 8 ? 1 : mode == 4 ? 3 : mode == 6 ? 33 : 2;
        size_t expected_len = mode == 0 || mode == 3 ? 2 : mode == 2 || mode == 4 ? 1 : 0;
        bool passed = res == expected && length == expected_len && gp_plain_fixture.matched &&
                      gp_plain_fixture.calls == calls && gp_test_transport.dropped &&
                      response[0] == 0xa5 && response[capacity + 1] == 0xa5;
        if (!expected && length) passed &= response[1] == (mode == 2 || mode == 4 ? 0xbb : 0xaa);
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Plain APDU chaining test %zu ( %s )", mode + 1, passed ? "ok" : "fail");
    }
    gp_exchange = gp_test_exchange;
    memset(&gp_test_transport, 0, sizeof(gp_test_transport));
    gp_session_reset();
    gp_ctx.active = true;
    gp_ctx.scp_version = 3;
    gp_ctx.key_len = 16;
    gp_ctx.mac_len = 8;
    gp_ctx.security_level = GP_SL_C_DEC_MAC;
    uint8_t oversized_data[255] = {0}, oversized_response[32];
    size_t oversized_length;
    uint16_t oversized_sw;
    int oversized_result = gp_wrapped_apdu(false, true, 0x80, 0xf2, 0x80, 2,
                                            oversized_data, sizeof(oversized_data), true, 256,
                                            oversized_response, sizeof(oversized_response), &oversized_length, &oversized_sw, false);
    failures += !(oversized_result == PM3_EINVARG && !gp_ctx.active && gp_test_transport.dropped && !gp_test_transport.calls);
    count++;
    gp_exchange = saved_exchange;
    gp_field_off = saved_field_off;
    gp_ctx = saved;
    gp_secure_zero(&saved, sizeof(saved));
    static const struct {const char *text; int expected;} hexadecimal[] = {
        {"00", 0}, {"11", 0x11}, {"55", 0x55}, {"75", 0x75}, {"FF", 255},
        {"0x80", 0x80}, {"f", 15}, {"-1", -1}, {"100", -1}, {"GG", -1}, {"", -1},
    };
    for (size_t i = 0; i < ARRAYLEN(hexadecimal); i++) {
        int value = -1;
        bool valid = gp_parse_hex_byte(hexadecimal[i].text, &value);
        bool passed = hexadecimal[i].expected < 0 ? !valid : valid && value == hexadecimal[i].expected;
        failures += !passed; count++;
        if (verbose || !passed)
            PrintAndLogEx(passed ? SUCCESS : FAILED, "Hex byte \"%s\" ( %s )", hexadecimal[i].text, passed ? "ok" : "fail");
    }
    static const struct {const char *hex; bool valid;} capabilities[] = {
        {"800102810415355575", true}, {"800103810170820107", true},
        {"8001028100", true}, {"800202008100", false}, {"800102", false},
        {"800102810180", true}, {"800102810155800103", false},
        {"8001028181041555", false},
    };
    for (size_t i = 0; i < ARRAYLEN(capabilities); i++) {
        uint8_t bytes[32];
        size_t length;
        gp_scp_capability_t scp;
        bool valid = gp_parse_hex_string(capabilities[i].hex, bytes, sizeof(bytes), &length) == 0 &&
                     gp_parse_scp_capability(bytes, length, &scp);
        failures += valid != capabilities[i].valid; count++;
        if (verbose || valid != capabilities[i].valid)
            PrintAndLogEx(valid == capabilities[i].valid ? SUCCESS : FAILED, "SCP capability %s ( %s )",
                          capabilities[i].hex, valid == capabilities[i].valid ? "ok" : "fail");
    }
    static const struct {const char *hex; bool valid;} apdus[] = {
        {"00a40400", true}, {"00c0000000", true}, {"80ca9f7f00", true},
        {"80f24000024f00", true}, {"80f24000024f0000", true},
        {"80f2", false}, {"80f24000034f00", false}, {"80f24000000001", false},
    };
    for (size_t i = 0; i < ARRAYLEN(apdus); i++) {
        uint8_t bytes[32];
        size_t length;
        gp_short_apdu_t apdu;
        bool valid = gp_parse_hex_string(apdus[i].hex, bytes, sizeof(bytes), &length) == 0 &&
                     gp_parse_short_apdu(bytes, length, &apdu) == 0;
        failures += valid != apdus[i].valid; count++;
        if (verbose || valid != apdus[i].valid)
            PrintAndLogEx(valid == apdus[i].valid ? SUCCESS : FAILED, "Short APDU %s ( %s )",
                          apdus[i].hex, valid == apdus[i].valid ? "ok" : "fail");
    }

    // PUT KEY components. Expected values independently computed with .NET
    // TripleDES/AES (DEK = 40..4F, key = 00..0F).
    {
        uint8_t dek[16], clear[16], out[48], expected[48];
        size_t out_len = 0, expected_len = 0;
        for (size_t i = 0; i < 16; i++) { dek[i] = 0x40 + i; clear[i] = i; }
        bool passed = gp_scp02_encrypt_key_component(dek, clear, out) == PM3_SUCCESS &&
                      gp_parse_hex_string("F1D75E4F0D37C22CB8D54E6253BB40B1", expected, sizeof(expected), &expected_len) == 0 &&
                      gp_consttime_equal(out, expected, 16);
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "PUT KEY TDEA-ECB component ( %s )", passed ? "ok" : "fail");
        passed = gp_scp03_build_key_component(dek, 16, clear, 16, out, sizeof(out), &out_len) == PM3_SUCCESS &&
                 gp_parse_hex_string("881110" "3D0FA4B855D2A5AA4954B8B5DF582A3A" "03C35280",
                                     expected, sizeof(expected), &expected_len) == 0 &&
                 out_len == expected_len && gp_consttime_equal(out, expected, expected_len);
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "PUT KEY AES component format ( %s )", passed ? "ok" : "fail");
        gp_secure_zero(out, sizeof(out));
    }

    // OID arcs and Card Recognition Data (real JCOP3 P60 response).
    {
        uint8_t bytes[96];
        size_t length = 0, oid_count = 0;
        uint32_t arcs[GP_OID_MAX_ARCS];
        static const uint32_t want[] = {1, 2, 840, 114283, 4, 2, 85};
        bool passed = gp_parse_hex_string("2A864886FC6B040255", bytes, sizeof(bytes), &length) == 0 &&
                      gp_oid_arcs(bytes, length, arcs, ARRAYLEN(arcs), &oid_count) &&
                      oid_count == ARRAYLEN(want) && memcmp(arcs, want, sizeof(want)) == 0;
        // Non-minimal arc and truncated OID must be rejected.
        passed &= gp_parse_hex_string("2A8086", bytes, sizeof(bytes), &length) == 0 &&
                  !gp_oid_arcs(bytes, length, arcs, ARRAYLEN(arcs), &oid_count);
        passed &= gp_parse_hex_string("2A86", bytes, sizeof(bytes), &length) == 0 &&
                  !gp_oid_arcs(bytes, length, arcs, ARRAYLEN(arcs), &oid_count);
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "OID decoding ( %s )", passed ? "ok" : "fail");

        uint8_t scp = 0, scp_i = 0;
        passed = gp_parse_hex_string("664D734B06072A864886FC6B01600B06092A864886FC6B020203630906072A864886FC6B03"
                                     "640B06092A864886FC6B040255650D060B2A864886FC6B0507020000660C060A2B060104012A026E0103",
                                     bytes, sizeof(bytes), &length) == 0 &&
                 gp_crd_scp(bytes, length, &scp, &scp_i) && scp == 2 && scp_i == 0x55;
        passed &= !gp_crd_scp(bytes, 10, &scp, &scp_i);   // truncated CRD
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Card Recognition Data SCP extraction ( %s )", passed ? "ok" : "fail");
    }

    // BER long-form lengths (key information templates > 127 bytes use 81 xx).
    {
        uint8_t bytes[3 + 128] = {0xE0, 0x81, 0x80};
        size_t offset = 0, value_len = 0;
        uint32_t tag = 0;
        const uint8_t *value = NULL;
        bool passed = gp_ber_read_tlv(bytes, sizeof(bytes), &offset, &tag, &value, &value_len) == PM3_SUCCESS &&
                      tag == 0xE0 && value_len == 128 && value == bytes + 3 && offset == sizeof(bytes);
        offset = 0;
        passed &= gp_ber_read_tlv(bytes, sizeof(bytes) - 1, &offset, &tag, &value, &value_len) != PM3_SUCCESS; // over-read
        bytes[2] = 0x03;                                                                            // non-minimal
        offset = 0;
        passed &= gp_ber_read_tlv(bytes, sizeof(bytes), &offset, &tag, &value, &value_len) != PM3_SUCCESS;
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "BER long-form length ( %s )", passed ? "ok" : "fail");
    }

    // Script redaction of commands that can carry key material.
    {
        static const struct {const char *line; bool sensitive;} lines[] = {
            {"auth -k 404142434445464748494A4B4C4D4E4F", true},
            {"putkey-aes --kvn 2", true},
            {"keyaudit", true},
            {"kcv -k 404142434445464748494A4B4C4D4E4F --tdea", true},
            {"select -a A000000151000000 --enc=00", true},
            {"info", false},
            {"getkey --kvn 1", false},
            {"list --apps", false},
            {"getdata --tag 00E0", false},
        };
        bool passed = true;
        for (size_t i = 0; i < ARRAYLEN(lines); i++)
            passed &= gp_command_is_sensitive(lines[i].line) == lines[i].sensitive;
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Script secret redaction ( %s )", passed ? "ok" : "fail");
    }

    // Fingerprint database: lookups must pick the most specific signature.
    {
        static const struct {
            uint16_t fab, ic, os, date, level;
            const char *platform;   // NULL = no match expected
            uint8_t match;
        } cases[] = {
            { 0x4790, 0xD321, 0x4700, 0x0000, 0x0000, "NXP JCOP4 P71D321", GP_SIG_CHIP_OS },  // card under test
            { 0x4790, 0x5167, 0x4791, 0x2081, 0x3B00, "NXP JCOP 2.4.2 R2", GP_SIG_FULL },     // J2D081
            { 0x4790, 0x5167, 0x4791, 0x2348, 0x4000, "NXP JCOP 2.4.2 R3", GP_SIG_FULL },     // same chip, later OS
            { 0x4790, 0x0503, 0x8211, 0x9999, 0x0001, "NXP JCOP3 P60", GP_SIG_IC },           // unknown J3H release
            { 0x4790, 0x1234, 0x4700, 0x0000, 0x0000, "NXP SmartMX", 0 },                     // vendor fallback
            { 0x1111, 0x2222, 0x3333, 0x0000, 0x0000, NULL, 0 },
        };
        bool passed = true;
        for (size_t i = 0; i < ARRAYLEN(cases); i++) {
            const gp_card_signature_t *s = gp_card_signature_lookup(cases[i].fab, cases[i].ic, cases[i].os,
                                                                    cases[i].date, cases[i].level);
            bool ok = cases[i].platform == NULL ? s == NULL
                      : s != NULL && strcmp(s->platform, cases[i].platform) == 0 && s->match == cases[i].match;
            if (verbose || !ok)
                PrintAndLogEx(ok ? SUCCESS : FAILED, "CPLC signature %04X/%04X/%04X ( %s )",
                              cases[i].fab, cases[i].ic, cases[i].os, ok ? "ok" : "fail");
            passed &= ok;
        }
        passed &= gp_os_id_name(0x1291) != NULL && gp_os_id_name(0xBEEF) == NULL;
        static const uint8_t jcop_default[] = {0x00, 0x73, 0xC8, 0x40, 0x00, 0x00, 0x90, 0x00};
        static const uint8_t p71[] = {0x00, 0x31, 0xC1, 0x73, 0xC8, 0x40, 0x00, 0x52, 0xA5, 0x10, 0x00, 0x90, 0x00};
        static const uint8_t j3r[] = {'J', '3', 'R', '1', '8', '0', '-', '2', '5', '5'};
        const gp_hist_signature_t *h1 = gp_hist_signature_lookup(jcop_default, sizeof(jcop_default));
        const gp_hist_signature_t *h2 = gp_hist_signature_lookup(p71, sizeof(p71));
        const gp_hist_signature_t *h3 = gp_hist_signature_lookup(j3r, sizeof(j3r));
        passed &= h1 != NULL && h1->len == 8;
        passed &= h2 != NULL && h2->len == 9;                       // longest prefix beats PN65 / wearable
        passed &= h3 != NULL && strstr(h3->meaning, "J3R") != NULL;
        passed &= gp_hist_signature_lookup(jcop_default, 4) == NULL; // truncated history must not match
        // ATS -> historical bytes, with TA/TB/TC present (card under test).
        static const uint8_t ats[] = {0x0D, 0x78, 0x77, 0x71, 0x02, 0x00, 0x73, 0xC8, 0x40, 0x00, 0x00, 0x90, 0x00};
        gp_link_t saved_link = gp_link;
        gp_link_from_ats(ats, sizeof(ats));
        const uint8_t *hist = NULL;
        size_t hist_len = 0;
        passed &= gp_ats_historical(&hist, &hist_len) && hist_len == 8 && memcmp(hist, jcop_default, 8) == 0;
        passed &= gp_link.fsc == 256 && gp_link.fwi == 7 && gp_link.sfgi == 1;
        gp_link = saved_link;
        failures += !passed; count++;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Fingerprint database and ATS parsing ( %s )", passed ? "ok" : "fail");
    }

    PrintAndLogEx(failures ? FAILED : SUCCESS, "JavaCard tests: %zu cases, %zu failures", count, failures);
    return failures ? PM3_ESOFT : PM3_SUCCESS;
}

//=============================================================================
// Command table
//=============================================================================

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"--------",   CmdHelp,                 AlwaysAvailable, "------- " _CYAN_("JavaCard / GlobalPlatform") " -------"},
    {"help",       CmdHelp,                 AlwaysAvailable, "This help"},
    {"test",       CmdHFJavaCardTest,       AlwaysAvailable, "Run offline parsing and secure-message regression tests"},
    {"info",       CmdHFJavaCardInfo,       AlwaysAvailable, "Interrogate card: CPLC, key info, capabilities"},
    {"list",       CmdHFJavaCardList,       AlwaysAvailable, "List GP registry (ISD / apps / packages) with AID lookup"},
    {"auth",       CmdHFJavaCardAuth,       AlwaysAvailable, "Open SCP01/02/03 secure channel (SCP01/02 legacy)"},
    {"session",    CmdHFJavaCardSession,    AlwaysAvailable, "Show or close the current secure channel"},
    {"keyaudit",   CmdHFJavaCardKeyAudit,   AlwaysAvailable, "Check every key set against known default keys (offline)"},
    {"scan",       CmdHFJavaCardScan,       AlwaysAvailable, "Discover applets by SELECTing well-known AIDs (read-only)"},
    {"delete",     CmdHFJavaCardDelete,     AlwaysAvailable, "Delete an applet or package from the card"},
    {"load",       CmdHFJavaCardLoad,       AlwaysAvailable, "Load a CAP/IJC; automatically authenticate unless --no-auth"},
    {"install",    CmdHFJavaCardInstall,    AlwaysAvailable, "Instantiate an applet; automatically authenticate unless --no-auth"},
    {"autoinstall",CmdHFJavaCardAutoInstall,AlwaysAvailable, "Parse, authenticate, load, and install a CAP in one command"},
    {"putkey",     CmdHFJavaCardPutKey,     AlwaysAvailable, "Add or replace a key set on the card (PUT KEY)"},
    {"setstatus",  CmdHFJavaCardSetStatus,  AlwaysAvailable, "Change lifecycle state of ISD / app / package (SET STATUS)"},
    {"send",       CmdHFJavaCardSend,       AlwaysAvailable, "Send a raw APDU (optionally session-wrapped)"},
    {"getdata",    CmdHFJavaCardGetData,    AlwaysAvailable, "GET DATA by tag (CPLC, key info, card data, ...)"},
    {"kcv",        CmdHFJavaCardKCV,        AlwaysAvailable, "Display Key Check Value (KCV) for a key or all known defaults"},
    {"storedata",  CmdHFJavaCardStoreData,  AlwaysAvailable, "Send STORE DATA block(s) to personalize an applet"},
    {"perso",      CmdHFJavaCardPerso,      AlwaysAvailable, "INSTALL [for personalization] of an applet instance"},
    {"capinfo",    CmdHFJavaCardCapInfo,    AlwaysAvailable, "Parse a CAP/IJC file and display metadata (no card needed)"},
    {"extradite",      CmdHFJavaCardExtradite,      AlwaysAvailable, "Move an applet to another Security Domain (extradition)"},
    {"registryupdate", CmdHFJavaCardRegistryUpdate,  AlwaysAvailable, "Update installed applet privileges/parameters (INSTALL [for registry update])"},
    {"createsd",       CmdHFJavaCardCreateSD,        AlwaysAvailable, "Create a new Supplementary Security Domain (SSD)"},
    {"script",         CmdHFJavaCardScript,          AlwaysAvailable, "Execute a GP script file (.gp) line by line"},
    {"--------",   CmdHelp,                  AlwaysAvailable, "------- " _CYAN_("Card Lifecycle Management") " -------"},
    {"secure-card",  CmdHFJavaCardSecureCard,  AlwaysAvailable, "Transition ISD to SECURED state"},
    {"lock-card",    CmdHFJavaCardLockCard,    AlwaysAvailable, _RED_("DANGER") " -- Lock the card permanently (SET STATUS ISD->LOCKED)"},
    {"lock-applet",  CmdHFJavaCardLockApplet,  AlwaysAvailable, "Lock an applet (prevent selection)"},
    {"unlock-applet",CmdHFJavaCardUnlockApplet,AlwaysAvailable, "Unlock a locked applet"},
    {"make-default", CmdHFJavaCardMakeDefault, AlwaysAvailable, "Make an applet Default Selected"},
    {"rename-isd",   CmdHFJavaCardRenameISD,   AlwaysAvailable, _RED_("DANGER") " -- Rename the Issuer Security Domain AID"},
    {"delete-key",   CmdHFJavaCardDeleteKey,   AlwaysAvailable, _RED_("DANGER") " -- Delete a key set by version number"},
    {"--------",    CmdHelp,                    AlwaysAvailable, "------- " _CYAN_("Card Interrogation") " -------"},
    {"select",      CmdHFJavaCardSelect,         AlwaysAvailable, "SELECT an arbitrary AID and show FCI response"},
    {"challenge",   CmdHFJavaCardChallenge,      AlwaysAvailable, "GET CHALLENGE from card RNG"},
    {"getkey",      CmdHFJavaCardGetKey,         AlwaysAvailable, "GET KEY: show key slot info and KCVs"},
    {"dump",        CmdHFJavaCardDump,           AlwaysAvailable, "Comprehensive card dump (info + keys + registry)"},
    {"putkey-aes",  CmdHFJavaCardPutKeyAES,      AlwaysAvailable, _RED_("DANGER") " -- PUT KEY (AES/SCP03) - add or replace AES key set"},
    {"fuzz",        CmdHFJavaCardFuzz,           AlwaysAvailable, _RED_("DANGER") " -- Fuzz INS byte space on ISD or selected AID"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFJavaCard(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
