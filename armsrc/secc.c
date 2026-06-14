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
// HID Config Card (JCOP / GlobalPlatform SCP02) simulation helpers.
// Handles I-block dispatch for tagType=16 in SimulateIso14443aTag and the
// A0 D4 jam logic for SniffIso14443a.
//-----------------------------------------------------------------------------

#include "secc.h"

#include <string.h>
#include "proxmark3_arm.h"
#include "dbprint.h"
#include "BigBuf.h"            // DMA_BUFFER_SIZE, MAX_PARITY_SIZE
#include "crc16.h"             // AddCrc14A, CheckCrc14A
#include "fpgaloader.h"        // FpgaWriteConfWord, FpgaSetupSscDma
#include "desfire_crypto.h"    // tdes_nxp_send
#include "mbedtls/des.h"       // mbedtls_des_*, mbedtls_des3_*
#include "iso14443a.h"         // ReaderTransmit, ReaderReceive, iso14a_get/set_timeout, iso14a_get/toggle_pcb_blocknum, MAX_ISO14A_TIMEOUT
#include "appmain.h"           // tearoff_hook, send_wtx
#include "util.h"              // data_available, BUTTON_PRESS
#include "cmd.h"               // reply_ng
#include "pm3_cmd.h"           // CMD_HF_HIDCONFIG_SIM, CMD_HF_HIDCONFIG_SNIFF
#include "dbprint.h"           // Dbprintf, LED_*
#include "ticks.h"             // WDT_HIT
#include "protocols.h"         // ISO14443A_CMD_* constants

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

// Fixed card challenge used in SCP02 INITIALIZE UPDATE responses (CC portion only).
static const uint8_t s_card_challenge[6] = {0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

// ---------------------------------------------------------------------------
// Custom APDU response table and SCP02 key (loaded from payload)
// ---------------------------------------------------------------------------

static hid_apdu_entry_t s_apdu_table[HID_APDU_MAX_ENTRIES];
static uint8_t s_apdu_count = 0;
static uint8_t s_scp02_key[16] = {0};

// Per-card key diversification data emitted in INITIALIZE UPDATE and used to
// derive card-specific static ENC/MAC/DEK keys via VISA-2. All-zero disables
// diversification (s_scp02_key is used directly as the static base key).
static uint8_t s_kdd[10] = {0};

// Key Version Number emitted in the INIT UPDATE response (GP KVN).
static uint8_t s_kvn = 0x01;

// Default response for unmatched APDUs (loaded from JSON "DefaultResponse").
// When s_default_resp_len == 0 the handler falls back to the legacy 90 00 reply.
static uint8_t s_default_resp[HID_APDU_MAX_RESP] = {0};
static uint8_t s_default_resp_len = 0;

// SCP02 session state — updated on each INITIALIZE UPDATE.
static uint16_t s_seq_counter = 0;
static uint8_t  s_host_challenge[8] = {0};

// Jam config — set by SniffHIDConfigCard before entering sniff loop.
// Length 0 means "use built-in default".
static uint8_t s_jam_apdu[HID_JAM_MAX_APDU];
static uint8_t s_jam_apdu_len = 0;
static uint8_t s_jam_resp[HID_JAM_MAX_RESP];
static uint8_t s_jam_resp_len = 0;

static const uint8_t s_jam_apdu_default[5] = {0xA0, 0xD4, 0x00, 0x00, 0x00};
static const uint8_t s_jam_resp_default[4] = {0x00, 0x00, 0x90, 0x00};

void hid_config_card_set_apdu_table(const hid_apdu_entry_t *table, uint8_t count) {
    s_apdu_count = (count > HID_APDU_MAX_ENTRIES) ? HID_APDU_MAX_ENTRIES : count;
    memcpy(s_apdu_table, table, s_apdu_count * sizeof(hid_apdu_entry_t));
}

static void hid_config_card_set_default_resp(const uint8_t *resp, uint8_t len) {
    s_default_resp_len = (len > HID_APDU_MAX_RESP) ? HID_APDU_MAX_RESP : len;
    if (s_default_resp_len)
        memcpy(s_default_resp, resp, s_default_resp_len);
}

static void hid_config_card_set_scp02_key(const uint8_t *key, const uint8_t *kdd, uint8_t kvn) {
    memcpy(s_scp02_key, key, 16);
    memcpy(s_kdd, kdd, 10);
    s_kvn = kvn;
    s_seq_counter = 0;
}

// ---------------------------------------------------------------------------
// Internal crypto helpers
// ---------------------------------------------------------------------------

// Derive the per-card static base key for the given SCP02 key type:
//   type=0x01 -> K_ENC, 0x02 -> K_MAC, 0x03 -> K_DEK
// VISA-2 diversification block (NIST SP800-108 style, but fixed JCOP layout):
//   d = KDD[0:2] || KDD[4:8] || F0 || type || KDD[0:2] || KDD[4:8] || 0F || type
// The diversified key is 3DES-ECB( master, d ) over the two 8-byte halves.
// When s_kdd is all zero we return s_scp02_key directly (legacy "no
// diversification" mode - works with test cards that share a common master).
static void scp02_get_base_key(uint8_t type, uint8_t *out16) {
    bool kdd_zero = true;
    for (int i = 0; i < 10; i++) {
        if (s_kdd[i]) { kdd_zero = false; break; }
    }
    if (kdd_zero) {
        memcpy(out16, s_scp02_key, 16);
        return;
    }

    uint8_t block[16];
    memcpy(block,      s_kdd,     2);
    memcpy(block + 2,  s_kdd + 4, 4);
    block[6]  = 0xF0;
    block[7]  = type;
    memcpy(block + 8,  s_kdd,     2);
    memcpy(block + 10, s_kdd + 4, 4);
    block[14] = 0x0F;
    block[15] = type;

    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);
    mbedtls_des3_set2key_enc(&ctx, s_scp02_key);
    mbedtls_des3_crypt_ecb(&ctx, block,     out16);
    mbedtls_des3_crypt_ecb(&ctx, block + 8, out16 + 8);
    mbedtls_des3_free(&ctx);
}

// Derive a 16-byte SCP02 session key using 3DES-CBC with null IV.
// base_key16 is the diversified per-card static key (from scp02_get_base_key).
// constant0/constant1 select the key type (0x01,0x82=S-ENC; 0x01,0x01=S-MAC;
// 0x01,0x81=DEK). The session counter is from the current INIT UPDATE.
static void derive_scp02_session_key(const uint8_t *base_key16, uint8_t c0, uint8_t c1, uint16_t sc, uint8_t *out16) {
    uint8_t deriv[16] = {c0, c1, (uint8_t)(sc >> 8), (uint8_t)(sc & 0xFF),
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                        };
    uint8_t iv[8] = {0};
    tdes_nxp_send(deriv, out16, 16, base_key16, iv, 2);
}

// Retail MAC (ISO 9797-1 Algorithm 3): single-DES for all-but-last blocks,
// full 3DES for the final block.  data_len must be a multiple of 8.
static void scp02_retail_mac(const uint8_t *key16, const uint8_t *data, size_t n_blocks, uint8_t *out8) {
    mbedtls_des_context  des_ctx;
    mbedtls_des3_context des3_ctx;
    mbedtls_des_init(&des_ctx);
    mbedtls_des3_init(&des3_ctx);
    mbedtls_des_setkey_enc(&des_ctx, key16);
    mbedtls_des3_set2key_enc(&des3_ctx, key16);

    uint8_t x[8] = {0};
    uint8_t tmp[8];

    for (size_t i = 0; i < n_blocks - 1; i++) {
        for (int j = 0; j < 8; j++) tmp[j] = data[i * 8 + j] ^ x[j];
        mbedtls_des_crypt_ecb(&des_ctx, tmp, x);
    }
    for (int j = 0; j < 8; j++) tmp[j] = data[(n_blocks - 1) * 8 + j] ^ x[j];
    mbedtls_des3_crypt_ecb(&des3_ctx, tmp, out8);

    mbedtls_des_free(&des_ctx);
    mbedtls_des3_free(&des3_ctx);
}

// Full 3DES-CBC-MAC: every block (including intermediate) uses full 3DES.
// data_len must be a multiple of 8.
static void scp02_full_3des_cbc_mac(const uint8_t *key16, const uint8_t *data, size_t n_blocks, uint8_t *out8) {
    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);
    mbedtls_des3_set2key_enc(&ctx, key16);

    uint8_t x[8] = {0};
    uint8_t tmp[8];

    for (size_t i = 0; i < n_blocks; i++) {
        for (int j = 0; j < 8; j++) tmp[j] = data[i * 8 + j] ^ x[j];
        mbedtls_des3_crypt_ecb(&ctx, tmp, x);
    }
    memcpy(out8, x, 8);
    mbedtls_des3_free(&ctx);
}

// ---------------------------------------------------------------------------
// SCP02 cryptogram computation
// ---------------------------------------------------------------------------

// Card cryptogram = full-3DES-CBC-MAC(S-ENC, HC(8) || SC(2)||CC(6) || 80 00*7)
static void compute_card_cryptogram(const uint8_t *host_challenge, uint8_t *out) {
    uint8_t k_enc[16];
    scp02_get_base_key(0x01, k_enc);
    uint8_t s_enc[16];
    derive_scp02_session_key(k_enc, 0x01, 0x82, s_seq_counter, s_enc);

    uint8_t data[24];
    memcpy(data, host_challenge, 8);
    data[8]  = (uint8_t)(s_seq_counter >> 8);
    data[9]  = (uint8_t)(s_seq_counter & 0xFF);
    memcpy(data + 10, s_card_challenge, 6);
    data[16] = 0x80;
    memset(data + 17, 0x00, 7);

    scp02_full_3des_cbc_mac(s_enc, data, 3, out);
}

// Host cryptogram = full-3DES-CBC-MAC(S-ENC, SC(2)||CC(6)||HC(8) || 80 00*7)
static void compute_host_cryptogram(const uint8_t *s_enc, uint8_t *out) {
    uint8_t data[24];
    data[0] = (uint8_t)(s_seq_counter >> 8);
    data[1] = (uint8_t)(s_seq_counter & 0xFF);
    memcpy(data + 2, s_card_challenge, 6);
    memcpy(data + 8, s_host_challenge, 8);
    data[16] = 0x80;
    memset(data + 17, 0x00, 7);

    scp02_full_3des_cbc_mac(s_enc, data, 3, out);
}

// C-MAC = Retail-MAC(S-MAC, {84 82 sec_level 00 10 || HostCrypto(8) || 80 00 00})
static void compute_ext_auth_cmac(const uint8_t *s_mac, uint8_t sec_level,
                                  const uint8_t *host_crypto, uint8_t *out) {
    uint8_t data[16];
    data[0] = 0x84;
    data[1] = 0x82;
    data[2] = sec_level;
    data[3] = 0x00;
    data[4] = 0x10;
    memcpy(data + 5, host_crypto, 8);
    data[13] = 0x80;
    data[14] = 0x00;
    data[15] = 0x00;

    scp02_retail_mac(s_mac, data, 2, out);
}

// ---------------------------------------------------------------------------
// I-block handler (called from SimulateIso14443aTag for tagType=16)
// ---------------------------------------------------------------------------

bool hid_config_card_handle_iblock(const uint8_t *cmd, int len, tag_response_info_t *ri) {
    uint8_t pcb = cmd[0];
    bool has_cid = (pcb & 0x08) != 0;

    // Payload starts after PCB [+ CID]
    int off = has_cid ? 2 : 1;  // offset to APDU CLA byte

    // Echo PCB and mirror CID from the reader frame.
    ri->response[0] = pcb;
    if (has_cid)
        ri->response[1] = cmd[1]; // mirror CID byte from reader

    // Base pointer for APDU payload in the response (after PCB [CID])
    uint8_t *rsp = &ri->response[off];

    // ----- Check custom APDU table first (overrides hardcoded responses) -----
    // cmd[off] is the start of the APDU payload; len includes trailing CRC (2 bytes).
    // apdu_mask bit i=1 → exact match; bit i=0 → wildcard:
    //   apdu[i]=0x00 → any single byte (**); apdu[i]=0x01 → length-prefix skip (##).
    for (int i = 0; i < s_apdu_count; i++) {
        if (s_apdu_table[i].apdu_len == 0)
            continue;
        bool match = true;
        int recv_pos = 0;
        for (int j = 0; j < (int)s_apdu_table[i].apdu_len && match; j++) {
            bool is_exact = (s_apdu_table[i].apdu_mask[j / 8] & (1u << (j % 8))) != 0;
            if (off + recv_pos >= len - 2) { match = false; break; }
            if (is_exact) {
                if (cmd[off + recv_pos] != s_apdu_table[i].apdu[j])
                    match = false;
                recv_pos++;
            } else if (s_apdu_table[i].apdu[j] == 0x01) {
                // ## : read length byte, skip 1 + N bytes total
                uint8_t payload_len = cmd[off + recv_pos];
                recv_pos += 1 + payload_len;
            } else {
                // ** : skip one byte
                recv_pos++;
            }
        }
        if (match) {
            memcpy(rsp, s_apdu_table[i].resp, s_apdu_table[i].resp_len);
            ri->response_n = off + s_apdu_table[i].resp_len;
            return true;
        }
    }

    // SELECT AID, A0 D4, and other generic APDUs are now handled exclusively
    // by the JSON APDUResponses table (above) and the DefaultResponse
    // fall-through (below). Only SCP02 crypto handlers stay hardcoded.

    // ----- INITIALIZE UPDATE (INS=0x50) -----
    // CID frame: INS at cmd[3], host challenge at cmd[off+5] (after CLA INS P1 P2 Lc)
    if (has_cid && len >= 17 && cmd[3] == 0x50) {
        s_seq_counter++;
        memcpy(s_host_challenge, &cmd[off + 5], 8);

        uint8_t cryptogram[8];
        compute_card_cryptogram(s_host_challenge, cryptogram);

        memcpy(rsp, s_kdd, 10);                          // key diversification data
        rsp[10] = s_kvn;                                 // key version number
        rsp[11] = 0x02;                                  // SCP02
        rsp[12] = (uint8_t)(s_seq_counter >> 8);         // SC high
        rsp[13] = (uint8_t)(s_seq_counter & 0xFF);       // SC low
        memcpy(rsp + 14, s_card_challenge, 6);           // CC
        memcpy(rsp + 20, cryptogram, 8);                 // card cryptogram
        rsp[28] = 0x90;
        rsp[29] = 0x00;
        ri->response_n = off + 30;
        return true;
    }

    // ----- EXTERNAL AUTHENTICATE (INS=0x82) -----
    // CID frame: sec_level at cmd[off+2], HostCrypto(8) at cmd[off+5], C-MAC(8) at cmd[off+13]
    if (has_cid && len >= 25 && cmd[3] == 0x82) {
        uint8_t sec_level          = cmd[off + 2];
        const uint8_t *host_crypto = &cmd[off + 5];
        const uint8_t *cmac_recv   = &cmd[off + 13];

        uint8_t k_enc[16], k_mac[16];
        scp02_get_base_key(0x01, k_enc);
        scp02_get_base_key(0x02, k_mac);

        uint8_t s_enc[16], s_mac[16];
        derive_scp02_session_key(k_enc, 0x01, 0x82, s_seq_counter, s_enc);
        derive_scp02_session_key(k_mac, 0x01, 0x01, s_seq_counter, s_mac);

        uint8_t host_crypto_exp[8];
        compute_host_cryptogram(s_enc, host_crypto_exp);

        uint8_t cmac_exp[8];
        compute_ext_auth_cmac(s_mac, sec_level, host_crypto, cmac_exp);

        if (memcmp(host_crypto_exp, host_crypto, 8) != 0 ||
                memcmp(cmac_exp, cmac_recv, 8) != 0) {
            rsp[0] = 0x63;
            rsp[1] = 0x00;  // Authentication failed
        } else {
            rsp[0] = 0x90;
            rsp[1] = 0x00;
        }
        ri->response_n = off + 2;
        return true;
    }

    // ----- All other APDUs: configured DefaultResponse, or 90 00 if none -----
    if (s_default_resp_len > 0) {
        memcpy(rsp, s_default_resp, s_default_resp_len);
        ri->response_n = off + s_default_resp_len;
    } else {
        rsp[0] = 0x90;
        rsp[1] = 0x00;
        ri->response_n = off + 2;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Sniff jam handler (called from SniffIso14443a when param bit 2 is set)
// ---------------------------------------------------------------------------

bool hid_config_card_jam(const uint8_t *cmd, int len, uint8_t *dma_buf) {
    uint8_t pcb = cmd[0];

    // Only act on I-blocks (bits 7:6 == 00)
    if ((pcb & 0xC0) != 0x00)
        return false;

    int off = (pcb & 0x08) ? 2 : 1; // skip CID if present

    // Select active APDU pattern and response (custom or default)
    const uint8_t *match = (s_jam_apdu_len > 0) ? s_jam_apdu : s_jam_apdu_default;
    int match_len = (s_jam_apdu_len > 0) ? (int)s_jam_apdu_len : (int)sizeof(s_jam_apdu_default);
    const uint8_t *resp_data = (s_jam_resp_len > 0) ? s_jam_resp : s_jam_resp_default;
    int resp_data_len = (s_jam_resp_len > 0) ? (int)s_jam_resp_len : (int)sizeof(s_jam_resp_default);

    if (len < off + match_len + 2) // off + APDU pattern + 2-byte CRC
        return false;

    if (memcmp(cmd + off, match, match_len) != 0)
        return false;

    // Build jam response: PCB [CID] <resp_data> CRC CRC
    uint8_t resp[2 + HID_JAM_MAX_RESP + 2]; // PCB + optional CID + payload + CRC
    int rlen = 0;
    resp[rlen++] = pcb;
    if (pcb & 0x08) resp[rlen++] = cmd[1]; // mirror CID
    memcpy(resp + rlen, resp_data, resp_data_len);
    rlen += resp_data_len;
    AddCrc14A(resp, rlen);
    rlen += 2;

    EmSendCmdEx(resp, rlen, false);

    // Restore sniffer FPGA mode and re-arm DMA
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_SNIFFER);
    FpgaSetupSscDma(dma_buf, DMA_BUFFER_SIZE);

    return true;
}

// ---------------------------------------------------------------------------
// CID-aware ISO 14443-4 APDU exchange for HID Config Card reader interaction.
// Sends I-blocks with PCB=0x0A (CID present, CID=0) as negotiated in RATS.
// Strips PCB+CID from received responses before returning.
// API mirrors iso14_apdu().
// ---------------------------------------------------------------------------

int hid_config_card_iso14_apdu(uint8_t *cmd, uint16_t cmd_len, bool send_chaining, void *data, uint16_t data_len, uint8_t *res) {
    uint8_t parity[MAX_PARITY_SIZE] = {0};
    uint8_t *real_cmd = BigBuf_calloc(cmd_len + 5); // PCB(1) + CID(1) + APDU + CRC(2)

    if (cmd_len) {
        real_cmd[0] = 0x0A; // I-block, CID present (bit 3), block number in bit 0
        if (send_chaining)
            real_cmd[0] |= 0x10;
        real_cmd[0] |= iso14a_get_pcb_blocknum();
        real_cmd[1] = 0x00; // CID = 0 (as negotiated in RATS)
        memcpy(real_cmd + 2, cmd, cmd_len);
    } else {
        real_cmd[0] = 0xAA; // R-block ACK + CID present
        real_cmd[0] |= iso14a_get_pcb_blocknum();
        real_cmd[1] = 0x00; // CID = 0
    }
    AddCrc14A(real_cmd, cmd_len + 2); // PCB + CID + APDU

    ReaderTransmit(real_cmd, cmd_len + 4, NULL); // PCB(1) + CID(1) + APDU + CRC(2)

    if (tearoff_hook() == PM3_ETEAROFF) {
        BigBuf_free();
        return -1;
    }

    size_t len = ReaderReceive(data, data_len, parity);
    uint8_t *data_bytes = (uint8_t *)data;

    if (len == 0) {
        BigBuf_free();
        return 0;
    }

    uint32_t save_timeout = iso14a_get_timeout();

    // S-Block WTX
    while (len && ((data_bytes[0] & 0xF2) == 0xF2)) {
        if (BUTTON_PRESS() || data_available()) {
            BigBuf_free();
            return -3;
        }
        send_wtx(38);
        data_bytes[1] &= 0x3F;
        iso14a_set_timeout(MAX(data_bytes[1] * save_timeout, MAX_ISO14A_TIMEOUT));
        AddCrc14A(data_bytes, len - 2);
        ReaderTransmit(data_bytes, len, NULL);
        len = ReaderReceive(data_bytes, data_len, parity);
    }

    iso14a_set_timeout(save_timeout);

    // Toggle block number on valid I-block or R(ACK)
    if (len >= 3
            && ((data_bytes[0] & 0xC0) == 0 || (data_bytes[0] & 0xD0) == 0x80)
            && (data_bytes[0] & 0x01) == iso14a_get_pcb_blocknum()) {
        iso14a_toggle_pcb_blocknum();
    }

    if (res)
        *res = data_bytes[0];

    if (len >= 3 && !CheckCrc14A(data_bytes, len)) {
        BigBuf_free();
        return -1;
    }

    if (len) {
        // Strip PCB and CID from the front of the response
        int header_len = ((data_bytes[0] & 0x08) != 0) ? 2 : 1;
        len -= header_len;
        memmove(data_bytes, data_bytes + header_len, len);
    }

    BigBuf_free();
    return len;
}

// ---------------------------------------------------------------------------
// Full HID Config Card simulation (own loop, no iso14443a.c hooks)
// ---------------------------------------------------------------------------

void SimulateHIDConfigCard(const hid_sim_payload_t *payload) {
    hid_config_card_set_apdu_table(payload->apdu_table, payload->apdu_count);
    hid_config_card_set_default_resp(payload->default_resp, payload->default_resp_len);
    hid_config_card_set_scp02_key(payload->scp02_key, payload->kdd, payload->kvn ? payload->kvn : 0x01);

    // Command buffers
    uint8_t receivedCmd[MAX_FRAME_SIZE];
    uint8_t receivedCmdPar[MAX_PARITY_SIZE];

    BigBuf_free_keep_EM();

#define HID_SIM_DYNAMIC_RESPONSE_SIZE 64
#define HID_SIM_DYNAMIC_MODULATION_SIZE 512
    uint8_t *dyn_resp = BigBuf_calloc(HID_SIM_DYNAMIC_RESPONSE_SIZE);
    uint8_t *dyn_mod  = BigBuf_calloc(HID_SIM_DYNAMIC_MODULATION_SIZE);
    if (dyn_resp == NULL || dyn_mod == NULL) {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_HIDCONFIG_SIM, PM3_EMALLOC, NULL, 0);
        return;
    }
    tag_response_info_t dynamic_response_info = {
        .response   = dyn_resp,
        .response_n = 0,
        .modulation   = dyn_mod,
        .modulation_n = 0
    };

    // Build flags: use provided UID, override ATQA/SAK/ATS with HID values.
    uint16_t flags = payload->flags | FLAG_ATS_IN_DATA | FLAG_ATQA_IN_DATA | FLAG_SAK_IN_DATA;
    uint8_t  uid[10];
    memcpy(uid, payload->uid, sizeof(uid));

    uint16_t atqa_val = ((uint16_t)payload->atqa[0] << 8) | payload->atqa[1];
    iso14a_set_atqa_sak_override(atqa_val, payload->sak);

    tag_response_info_t *responses;
    uint32_t cuid;
    uint8_t  pages;

    if (SimulateIso14443aInit(4, flags, uid,
                              (uint8_t *)payload->ats, payload->ats_len,
                              &responses, &cuid, &pages, NULL) == false) {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_HIDCONFIG_SIM, PM3_EINIT, NULL, 0);
        return;
    }

    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);
    iso14a_set_timeout(201400);

    int len = 0;
    clear_trace();
    set_tracing(true);
    LED_A_ON();

    uint8_t cardINTERACTIONS = 0;
    bool finished = false;

    while (finished == false) {
        WDT_HIT();
        tag_response_info_t *p_response = NULL;

        if (GetIso14443aCommandFromReader(receivedCmd, sizeof(receivedCmd), receivedCmdPar, &len) == false) {
            finished = true;
            break;
        }

        dynamic_response_info.response_n = 0;
        dynamic_response_info.modulation_n = 0;

        if (receivedCmd[0] == ISO14443A_CMD_REQA && len == 1) {
            p_response = &responses[RESP_INDEX_ATQA];
        } else if (receivedCmd[0] == ISO14443A_CMD_WUPA && len == 1) {
            p_response = &responses[RESP_INDEX_ATQA];
        } else if (receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 2) {
            p_response = &responses[RESP_INDEX_UIDC1];
        } else if (receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && len == 9) {
            p_response = &responses[RESP_INDEX_SAKC1];
        } else if (receivedCmd[0] == ISO14443A_CMD_RATS && len == 4) {
            p_response = &responses[RESP_INDEX_ATS];
        } else if (receivedCmd[0] == ISO14443A_CMD_HALT && len == 4) {
            p_response = NULL;
        } else {
            // ISO 14443-4 I-block dispatch — HID-specific handling
            switch (receivedCmd[0]) {
                case 0x02:
                case 0x03:
                case 0x0A:
                case 0x0B: {
                    hid_config_card_handle_iblock(receivedCmd, len, &dynamic_response_info);
                    if (dynamic_response_info.response_n > 0) {
                        // Mirror CID from reader frame when CID bit is set in PCB
                        if (receivedCmd[0] & 0x08)
                            dynamic_response_info.response[1] = receivedCmd[1];
                        AddCrc14A(dynamic_response_info.response, dynamic_response_info.response_n);
                        dynamic_response_info.response_n += 2;
                        if (prepare_tag_modulation(&dynamic_response_info, HID_SIM_DYNAMIC_MODULATION_SIZE))
                            p_response = &dynamic_response_info;
                    }
                    cardINTERACTIONS++;
                    if (payload->exitAfter > 0 && cardINTERACTIONS >= payload->exitAfter)
                        finished = true;
                    break;
                }
                default:
                    break;
            }
        }

        if (p_response != NULL)
            EmSendPrecompiledCmd(p_response);
    }

    set_tracing(false);
    LED_A_OFF();
    BigBuf_free_keep_EM();
    reply_ng(CMD_HF_HIDCONFIG_SIM, PM3_SUCCESS, NULL, 0);
}

// ---------------------------------------------------------------------------
// HID Config Card sniff with optional A0 D4 jamming
// ---------------------------------------------------------------------------

void SniffHIDConfigCard(const hid_sniff_payload_t *payload) {
    // Configure jam pattern and response before entering the sniff loop.
    if (payload->apdu_len > 0 && payload->apdu_len <= HID_JAM_MAX_APDU) {
        memcpy(s_jam_apdu, payload->apdu, payload->apdu_len);
        s_jam_apdu_len = payload->apdu_len;
    } else {
        s_jam_apdu_len = 0; // use default A0 D4 00 00 00
    }
    if (payload->resp_len > 0 && payload->resp_len <= HID_JAM_MAX_RESP) {
        memcpy(s_jam_resp, payload->resp, payload->resp_len);
        s_jam_resp_len = payload->resp_len;
    } else {
        s_jam_resp_len = 0; // use default 00 00 90 00
    }
    // Delegate to SniffIso14443a.
    // When param bit 0x04 is set, SniffIso14443a calls hid_config_card_jam()
    // inline after each decoded reader frame (see iso14443a.c).
    SniffIso14443a(payload->param);
}
