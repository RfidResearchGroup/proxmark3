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
#include "iso14443a.h"         // ReaderTransmit, ReaderReceive, iso14a_get/set_timeout, iso14_pcb_blocknum, MAX_ISO14A_TIMEOUT
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

// Fixed card challenge used in SCP02 INITIALIZE UPDATE responses.
static const uint8_t hid_cc[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

// ---------------------------------------------------------------------------
// Custom APDU response table and SCP02 key (loaded from payload)
// ---------------------------------------------------------------------------

static hid_apdu_entry_t s_apdu_table[HID_APDU_MAX_ENTRIES];
static uint8_t s_apdu_count = 0;
static uint8_t s_scp02_key[16] = {0};

void hid_config_card_set_apdu_table(const hid_apdu_entry_t *table, uint8_t count) {
    s_apdu_count = (count > HID_APDU_MAX_ENTRIES) ? HID_APDU_MAX_ENTRIES : count;
    memcpy(s_apdu_table, table, s_apdu_count * sizeof(hid_apdu_entry_t));
}

static void hid_config_card_set_scp02_key(const uint8_t *key) {
    memcpy(s_scp02_key, key, 16);
}

// ---------------------------------------------------------------------------
// Internal crypto
// ---------------------------------------------------------------------------

// Compute GlobalPlatform SCP02 card cryptogram.
// card_cryptogram = Retail_MAC(S-ENC, host_challenge || card_challenge || 0x80 || 0x00*7)
// Uses hardcoded master key 404142...4F and SN = 0x0001.
static void compute_card_cryptogram(const uint8_t *host_challenge, uint8_t *out) {
    static const uint8_t SN[2] = {0x00, 0x01};

    // Derive S-ENC: 3DES-CBC(K, zero_IV, {0x01, 0x82, SN0, SN1, 0x00*12})
    uint8_t s_enc[16];
    {
        uint8_t deriv[16] = {0x01, 0x82, SN[0], SN[1], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        uint8_t iv[8] = {0};
        tdes_nxp_send(deriv, s_enc, 16, s_scp02_key, iv, 2);
    }

    // Retail MAC over HC || CC || 0x80 || 0x00*7
    mbedtls_des_context  des_ctx;
    mbedtls_des3_context des3_ctx;
    mbedtls_des_init(&des_ctx);
    mbedtls_des3_init(&des3_ctx);
    mbedtls_des_setkey_enc(&des_ctx, s_enc);
    mbedtls_des3_set2key_enc(&des3_ctx, s_enc);

    uint8_t x[8] = {0};
    uint8_t tmp[8];

    // Block 1: host challenge
    for (int i = 0; i < 8; i++) tmp[i] = host_challenge[i] ^ x[i];
    mbedtls_des_crypt_ecb(&des_ctx, tmp, x);

    // Block 2: card challenge
    for (int i = 0; i < 8; i++) tmp[i] = hid_cc[i] ^ x[i];
    mbedtls_des_crypt_ecb(&des_ctx, tmp, x);

    // Block 3: 0x80 || 0x00*7 (ISO 9797-1 Method 2 padding)
    tmp[0] = 0x80 ^ x[0];
    for (int i = 1; i < 8; i++) tmp[i] = x[i];
    mbedtls_des3_crypt_ecb(&des3_ctx, tmp, out);

    mbedtls_des_free(&des_ctx);
    mbedtls_des3_free(&des3_ctx);
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
    for (int i = 0; i < s_apdu_count; i++) {
        if (s_apdu_table[i].apdu_len == 0)
            continue;
        if (len - off < (int)(s_apdu_table[i].apdu_len + 2))
            continue;
        if (memcmp(&cmd[off], s_apdu_table[i].apdu, s_apdu_table[i].apdu_len) == 0) {
            memcpy(rsp, s_apdu_table[i].resp, s_apdu_table[i].resp_len);
            ri->response_n = off + s_apdu_table[i].resp_len;
            return true;
        }
    }

    // ----- SELECT AID (INS=0xA4, P1=0x04) -----
    // no-CID frame: off=1, INS at cmd[2], Lc at cmd[4+1]=cmd[5], AID[6] at cmd[1+5+6]=cmd[12]
    // CID frame:    off=2, INS at cmd[3], Lc at cmd[3+3]=cmd[6], AID[6] at cmd[2+5+6]=cmd[13]
    if (!has_cid && len >= 17 && cmd[2] == 0xA4 && cmd[3] == 0x04 && cmd[5] == 0x0A) {
        if (cmd[12] == 0x17) {
            rsp[0] = 0x6A; rsp[1] = 0x82; // File Not Found
        } else {
            rsp[0] = 0x90; rsp[1] = 0x00;
        }
        ri->response_n = off + 2;
        return true;
    }

    if (has_cid && len >= 18 && cmd[3] == 0xA4 && cmd[4] == 0x04 && cmd[6] == 0x0A) {
        if (cmd[13] == 0x17) {
            rsp[0] = 0x6A; rsp[1] = 0x82; // File Not Found
        } else {
            rsp[0] = 0x90; rsp[1] = 0x00;
        }
        ri->response_n = off + 2;
        return true;
    }

    // ----- A0 D4 00 00 00 (HID proprietary) -----
    if (has_cid && len == 9 &&
            cmd[2] == 0xA0 && cmd[3] == 0xD4 &&
            cmd[4] == 0x00 && cmd[5] == 0x00 && cmd[6] == 0x00) {
        rsp[0] = 0x00; rsp[1] = 0x00; rsp[2] = 0x90; rsp[3] = 0x00;
        ri->response_n = off + 4;
        return true;
    }

    // ----- INITIALIZE UPDATE (INS=0x50) -----
    // CID frame: INS at cmd[3], host challenge at cmd[off+4] = cmd[6]
    if (has_cid && len >= 17 && cmd[3] == 0x50) {
        uint8_t cryptogram[8];
        compute_card_cryptogram(&cmd[off + 4], cryptogram);

        memset(rsp, 0x00, 10);          // key diversification data
        rsp[10] = 0xFF;                  // key version (JCOP factory default)
        rsp[11] = 0x02;                  // SCP02
        memcpy(rsp + 12, hid_cc, 8);    // card challenge
        memcpy(rsp + 20, cryptogram, 8); // card cryptogram
        rsp[28] = 0x90;
        rsp[29] = 0x00;
        ri->response_n = off + 30;
        return true;
    }

    // ----- EXTERNAL AUTH and all other APDUs: generic 90 00 -----
    rsp[0] = 0x90; rsp[1] = 0x00;
    ri->response_n = off + 2;
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

    if (len < off + 7)
        return false;

    if (cmd[off]     != 0xA0 || cmd[off + 1] != 0xD4 ||
            cmd[off + 2] != 0x00 || cmd[off + 3] != 0x00 || cmd[off + 4] != 0x00)
        return false;

    // Build jam response: PCB [CID] 00 00 90 00 CRC CRC
    uint8_t resp[8];
    int rlen = 0;
    resp[rlen++] = pcb;
    if (pcb & 0x08) resp[rlen++] = cmd[1]; // mirror CID
    resp[rlen++] = 0x00;
    resp[rlen++] = 0x00;
    resp[rlen++] = 0x90;
    resp[rlen++] = 0x00;
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
        real_cmd[0] |= iso14_pcb_blocknum;
        real_cmd[1] = 0x00; // CID = 0 (as negotiated in RATS)
        memcpy(real_cmd + 2, cmd, cmd_len);
    } else {
        real_cmd[0] = 0xAA; // R-block ACK + CID present
        real_cmd[0] |= iso14_pcb_blocknum;
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
            && (data_bytes[0] & 0x01) == iso14_pcb_blocknum) {
        iso14_pcb_blocknum ^= 1;
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
    hid_config_card_set_scp02_key(payload->scp02_key);

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

    // ATQA override: stored big-endian in payload, SimulateIso14443aInit takes uint16
    uint16_t atqa_val = ((uint16_t)payload->atqa[0] << 8) | payload->atqa[1];
    uint8_t  sak_val  = payload->sak;

    tag_response_info_t *responses;
    uint32_t cuid;
    uint8_t  pages;

    if (SimulateIso14443aInit(4, flags, uid,
                              (uint8_t *)payload->ats, payload->ats_len,
                              atqa_val, sak_val,
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

void SniffHIDConfigCard(uint8_t param) {
    bool do_jam = (param & 0x04) != 0;

    // For non-jam sniff, delegate entirely to the standard sniffer.
    if (!do_jam) {
        SniffIso14443a(param);
        return;
    }

    // Jam mode: own sniff loop with hid_config_card_jam() called inline.
    BigBuf_free();
    BigBuf_Clear_ext(false);

    uint8_t *receivedCmd    = BigBuf_calloc(MAX_FRAME_SIZE);
    uint8_t *receivedCmdPar = BigBuf_calloc(MAX_PARITY_SIZE);
    uint8_t *receivedResp   = BigBuf_calloc(MAX_FRAME_SIZE);
    uint8_t *receivedRespPar = BigBuf_calloc(MAX_PARITY_SIZE);

    Demod14aInit(receivedResp, MAX_FRAME_SIZE, receivedRespPar);
    Uart14aInit(receivedCmd,   MAX_FRAME_SIZE, receivedCmdPar);

    dmabuf8_t *dma = get_dma8();
    uint8_t *data = dma->buf;

    if (FpgaSetupSscDma((uint8_t *)dma->buf, DMA_BUFFER_SIZE) == false) {
        BigBuf_free();
        return;
    }

    bool triggered = !(param & 0x03);
    uint32_t rx_samples = 0;
    bool TagIsActive    = false;
    bool ReaderIsActive = false;
    uint8_t previous_data = 0;
    int maxDataLen = 0, dataLen;
    uint16_t checker = 12000;

    tUart14a *uart = GetUart14a();
    tDemod14a *demod = GetDemod14a();

    clear_trace();
    set_tracing(true);
    LED_A_ON();

    while (BUTTON_PRESS() == false) {
        WDT_HIT();

        if (checker-- == 0) {
            if (data_available()) break;
            checker = 12000;
        }

        int readBufDataP = data - dma->buf;
        int dmaBufDataP  = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR;
        dataLen = (readBufDataP <= dmaBufDataP)
                  ? dmaBufDataP - readBufDataP
                  : DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP;

        if (dataLen > maxDataLen) {
            maxDataLen = dataLen;
            if (dataLen > (9 * DMA_BUFFER_SIZE / 10)) break;
        }
        if (dataLen < 1) continue;

        if (AT91C_BASE_PDC_SSC->PDC_RCR == 0) {
            AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t)dma->buf;
            AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
        }
        if (AT91C_BASE_PDC_SSC->PDC_RNCR == 0) {
            AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t)dma->buf;
            AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
        }

        LED_A_OFF();

        if (rx_samples & 0x01) {
            if (!TagIsActive) {
                uint8_t readerdata = (previous_data & 0xF0) | (*data >> 4);
                if (MillerDecoding(readerdata, (rx_samples - 1) * 4)) {
                    LED_C_ON();
                    if (!triggered && (param & 0x02) && uart->len == 1 && uart->bitCount == 7)
                        triggered = true;
                    if (triggered) {
                        if (!LogTrace(receivedCmd, uart->len,
                                      uart->startTime * 16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
                                      uart->endTime   * 16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
                                      uart->parity, true))
                            break;
                    }
                    if (uart->len >= 8) {
                        if (hid_config_card_jam(receivedCmd, uart->len, (uint8_t *)dma->buf))
                            data = dma->buf;
                    }
                    Uart14aReset();
                    Demod14aReset();
                    LED_B_OFF();
                }
                ReaderIsActive = (uart->state != STATE_14A_UNSYNCD);
            }

            if (!ReaderIsActive) {
                uint8_t tagdata = (previous_data << 4) | (*data & 0x0F);
                if (ManchesterDecoding(tagdata, 0, (rx_samples - 1) * 4)) {
                    LED_B_ON();
                    if (!LogTrace(receivedResp, demod->len,
                                  demod->startTime * 16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
                                  demod->endTime   * 16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
                                  demod->parity, false))
                        break;
                    if (!triggered && (param & 0x01))
                        triggered = true;
                    Uart14aReset();
                    Demod14aReset();
                    LED_C_OFF();
                }
                TagIsActive = (demod->state != DEMOD_14A_UNSYNCD);
            }
        }

        previous_data = *data;
        rx_samples++;
        if (data == dma->buf + DMA_BUFFER_SIZE)
            data = dma->buf;
        else
            data++;
    }

    FpgaDisableSscDma();
    set_tracing(false);
    LEDsoff();
    BigBuf_free();
}
