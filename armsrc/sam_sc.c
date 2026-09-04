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
// HID Artemis SAM secure-channel transport (see sam_sc.h for design notes).
//-----------------------------------------------------------------------------
#include "sam_sc.h"

#include <string.h>
#include "BigBuf.h"
#include "appmain.h"
#include "cmd.h"
#include "dbprint.h"
#include "i2c.h"          // ISO7816_MAX_FRAME, I2C_Reset_EnterMainProgram
#include "proxmark3_arm.h"
#include "sam_common.h"
#include "ticks_apis.h"
#include "util.h"         // LED_D_ON, LEDsoff
#include "iclass.h"       // select_iclass_tag, picopass_hdr_t
#include "crc16.h"        // AddCrc
#include "protocols.h"    // ICLASS_CMD_UPDATE
#include "iso15693.h"     // Iso15693InitReader
#include "iso14443a.h"    // iso14443a_select_card, iso14_apdu
#include "fpga_apis.h"    // switch_off

// Tracks whether the SIM module has been initialised since the last reset.
// Set true after the first successful sam_sc_handler() invocation; cleared by
// sam_sc_session_invalidate() (called from any other firmware path that takes
// over the SIM module - currently a manual hook left for future wiring) and
// by SAM_SC_FLAG_FORCE_RESET / SAM_SC_FLAG_RELEASE.
static bool s_sam_sc_session_active = false;

#define SAM_SC_CARD_API_MAX_ITERATIONS 128

void sam_sc_session_invalidate(void) {
    s_sam_sc_session_active = false;
}

static int sam_sc_snmp_loader_exchange(const uint8_t *snmp, uint16_t snmp_len,
                                       uint8_t *response, uint16_t *response_len) {
    if (snmp == NULL || response == NULL || response_len == NULL ||
            (uint32_t)snmp_len + 7 > ISO7816_MAX_FRAME)
        return PM3_EINVARG;

    uint16_t apdu_len = 0;
    response[apdu_len++] = 0xa0; // PUT DATA, final/only fragment
    response[apdu_len++] = 0xda;
    response[apdu_len++] = 0x80; // SnmpLoader extended form
    response[apdu_len++] = 0x00;
    response[apdu_len++] = 0x00; // extended Lc marker
    response[apdu_len++] = (uint8_t)(snmp_len >> 8);
    response[apdu_len++] = (uint8_t)snmp_len;
    memcpy(response + apdu_len, snmp, snmp_len);
    apdu_len += snmp_len;

    if (g_dbglevel >= DBG_INFO) {
        DbpString("SAM SNMP PUT DATA APDU:");
        Dbhexdump(apdu_len, response, false);
    }
    if (!sam_rxtx(response, apdu_len, response, response_len))
        return PM3_ECARDEXCHANGE;
    if (g_dbglevel >= DBG_INFO) {
        DbpString("SAM SNMP PUT DATA response:");
        Dbhexdump(*response_len, response, false);
    }
    if (*response_len < 2)
        return PM3_ECARDEXCHANGE;

    const uint16_t put_sw = ((uint16_t)response[*response_len - 2] << 8) | response[*response_len - 1];
    if (put_sw != 0x9000 && put_sw != 0x6800 && put_sw != 0x6883)
        return PM3_ECARDEXCHANGE;

    const uint8_t get_data[] = {0xa0, 0xca, 0x80, 0x00, 0x00, 0xff, 0xff};
    if (g_dbglevel >= DBG_INFO) {
        DbpString("SAM SNMP GET DATA APDU:");
        Dbhexdump(sizeof(get_data), get_data, false);
    }
    if (!sam_rxtx(get_data, sizeof(get_data), response, response_len))
        return PM3_ECARDEXCHANGE;
    if (g_dbglevel >= DBG_INFO) {
        DbpString("SAM SNMP GET DATA response:");
        Dbhexdump(*response_len, response, false);
    }
    return (*response_len >= 2) ? PM3_SUCCESS : PM3_ECARDEXCHANGE;
}

// Read one definite-length BER TLV.  Card API requests in the field
// use both normal short lengths and the non-canonical 0x82 00 xx spelling, so
// this intentionally accepts all three definite forms used by the SAM.
static int sam_sc_read_tlv(const uint8_t *buf, uint16_t buf_len,
                           uint8_t *tag, const uint8_t **value,
                           uint16_t *value_len, uint16_t *consumed) {
    if (buf == NULL || tag == NULL || value == NULL || value_len == NULL || consumed == NULL || buf_len < 2)
        return PM3_EINVARG;

    uint16_t off = 0;
    *tag = buf[off++];
    uint8_t first_len = buf[off++];
    uint16_t len = 0;
    if (first_len < 0x80) {
        len = first_len;
    } else if (first_len == 0x81) {
        if (off >= buf_len) return PM3_EINVARG;
        len = buf[off++];
    } else if (first_len == 0x82) {
        if ((uint32_t)off + 1 >= buf_len) return PM3_EINVARG;
        len = ((uint16_t)buf[off] << 8) | buf[off + 1];
        off += 2;
    } else {
        return PM3_EINVARG;
    }
    if ((uint32_t)off + len > buf_len) return PM3_EINVARG;

    *value = buf + off;
    *value_len = len;
    *consumed = (uint16_t)(off + len);
    return PM3_SUCCESS;
}

// A completed Grace request can carry either a BD success envelope or a BE
// error envelope.  Both follow the five- or six-byte routing tail and must be
// forwarded to the host unchanged; treating BE as an invalid transport reply
// hides the SAM's actual error from the secure-channel client.
static uint16_t sam_sc_reply_offset(const uint8_t *response, uint16_t response_len) {
    uint16_t bd = sam_bd_offset(response, response_len);
    if (bd != 0) return bd;

    for (uint16_t ofs = SAM_RX_ASN1_PREFIX_LENGTH;
            ofs <= (uint16_t)(SAM_RX_ASN1_PREFIX_LENGTH + 1);
            ofs++) {
        if (ofs < response_len && response[ofs] == 0xbe)
            return ofs;
    }
    return 0;
}

// Build/send one continuation to a ProcessCardApi request.  Card API
// traffic is routed through the external-app endpoint (0x14), not the normal
// host endpoint (0x44) used for SC wrapped commands.
static int sam_sc_send_card_api_continuation(uint8_t sc_flag,
                                             const uint8_t *payload,
                                             uint16_t payload_len,
                                             uint8_t *response,
                                             uint16_t *response_len) {
    return sam_send_payload_ex(0x14, 0x0a, 0x14, sc_flag,
                               payload, &payload_len, response, response_len);
}

// Card API continuation for an HF transceive result:
//   BD <L> A0 <L> A0 <L> 80 <L> <APDU response> 81 02 00 00

static uint8_t sam_sc_ber_len_size(uint16_t len) {
    return len < 0x80 ? 1 : (len < 0x100 ? 2 : 3);
}

static uint16_t sam_sc_emit_ber_len(uint8_t *out, uint16_t len) {
    if (len < 0x80) {
        out[0] = (uint8_t)len;
        return 1;
    }
    if (len < 0x100) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)len;
    return 3;
}

static uint16_t sam_sc_copy_payload_nfc2sam(uint8_t *out, uint16_t out_size,
                                            const uint8_t *nfc, uint16_t nfc_len) {
    if (out == NULL || nfc == NULL || nfc_len == 0) return 0;

    const uint16_t inner_len = (uint16_t)(1 + sam_sc_ber_len_size(nfc_len) + nfc_len + 4);
    const uint16_t middle_len = (uint16_t)(1 + sam_sc_ber_len_size(inner_len) + inner_len);
    const uint16_t outer_len = (uint16_t)(1 + sam_sc_ber_len_size(middle_len) + middle_len);
    const uint16_t total_len = (uint16_t)(1 + sam_sc_ber_len_size(outer_len) + outer_len);
    if (total_len > out_size) return 0;

    uint16_t o = 0;
    out[o++] = 0xbd;
    o += sam_sc_emit_ber_len(out + o, outer_len);
    out[o++] = 0xa0;
    o += sam_sc_emit_ber_len(out + o, middle_len);
    out[o++] = 0xa0;
    o += sam_sc_emit_ber_len(out + o, inner_len);
    out[o++] = 0x80;
    o += sam_sc_emit_ber_len(out + o, nfc_len);
    memcpy(out + o, nfc, nfc_len);
    o += nfc_len;
    out[o++] = 0x81;
    out[o++] = 0x02;
    out[o++] = 0x00;
    out[o++] = 0x00;
    return o;
}

static int sam_sc_card_api_loop(uint8_t *response, uint16_t *response_len,
                                bool prevent_epurse_update) {
    if (response == NULL || response_len == NULL) return PM3_EINVARG;

    uint8_t *continuation = BigBuf_calloc(ISO7816_MAX_FRAME);
    if (continuation == NULL) return PM3_EMALLOC;

    int res = PM3_SUCCESS;
    int card_transport = -1;
    for (uint8_t iteration = 0; iteration < SAM_SC_CARD_API_MAX_ITERATIONS; iteration++) {
        // Grace SAMs mirror either a five- or six-byte routing tail before
        // their Card API A1 node.  Do not use the legacy 0x61 flag at a fixed
        // offset to detect it: newer Grace replies place a routing byte there.
        uint16_t api_offset = sam_rx_prefix_len(response, *response_len);
        if (*response_len <= api_offset || response[api_offset] != 0xa1) break;

        const uint8_t sc_flag = response[api_offset - 1];
        const uint8_t *api = response + api_offset;
        const uint16_t api_len = (uint16_t)(*response_len - api_offset);
        uint8_t root_tag, child_tag, op_tag;
        const uint8_t *root, *child, *op_value;
        uint16_t root_len, root_used, child_len, child_used, op_len, op_used;

        if (sam_sc_read_tlv(api, api_len, &root_tag, &root, &root_len, &root_used) != PM3_SUCCESS ||
                root_tag != 0xa1 ||
                sam_sc_read_tlv(root, root_len, &child_tag, &child, &child_len, &child_used) != PM3_SUCCESS) {
            res = PM3_ECARDEXCHANGE;
            break;
        }

        uint16_t continuation_len = 0;
        if ((child_tag == 0x82 || child_tag == 0x83) && child_len == 0) {
            // samCommandTurnRfFieldOff / samCommandTurnRfFieldOn.  The SAM
            // expects the same empty samResponse acknowledgement for each.
            // An RF-on request only arms the field for a later scan/transceive;
            // that operation selects the card and configures the appropriate
            // reader mode, so there is no PM3 field transition to make here.
            if (child_tag == 0x82)
                switch_off();
            static const uint8_t rf_off_ack[] = {0xbd, 0x02, 0x8a, 0x00};
            memcpy(continuation, rf_off_ack, sizeof(rf_off_ack));
            continuation_len = sizeof(rf_off_ack);
        } else {
            if (sam_sc_read_tlv(child, child_len, &op_tag, &op_value, &op_len, &op_used) != PM3_SUCCESS ||
                    op_tag != 0x80) {
                res = PM3_ECARDEXCHANGE;
                break;
            }

            if (child_tag == 0xa0 && op_len == 1 &&
                    (op_value[0] == 0x04 || op_value[0] == 0x02)) {
                // samCommandScanFieldForCard
                card_transport = op_value[0];
                if (op_value[0] == 0x02) {
                    iso14a_card_select_t card_info;
                    memset(&card_info, 0, sizeof(card_info));
                    iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
                    bool selected = iso14443a_select_card(NULL, &card_info,
                                                          NULL, true, 0, false);
                    switch_clock_to_ticks();
                    if (selected == false || card_info.uidlen == 0 || card_info.uidlen > 10) {
                        static const uint8_t no_card[] = {0xbd, 0x02, 0x8a, 0x00};
                        memcpy(continuation, no_card, sizeof(no_card));
                        continuation_len = sizeof(no_card);
                    } else {
                        // SelectedCardInfo / SetDetectedCardInfo.
                        uint16_t o = 0;
                        continuation[o++] = 0xbd;
                        continuation[o++] = 0;
                        continuation[o++] = 0xa0;
                        continuation[o++] = 0;
                        continuation[o++] = 0xa1;
                        continuation[o++] = 0;
                        continuation[o++] = 0x81;
                        continuation[o++] = 0x01;
                        continuation[o++] = 0x14;
                        continuation[o++] = 0xa2;
                        continuation[o++] = 0;
                        continuation[o++] = 0x80;
                        continuation[o++] = 0x02;
                        continuation[o++] = 0x00;
                        continuation[o++] = 0x02;
                        continuation[o++] = 0x81;
                        continuation[o++] = card_info.uidlen;
                        memcpy(continuation + o, card_info.uid, card_info.uidlen);
                        o += card_info.uidlen;
                        continuation[o++] = 0x82;
                        continuation[o++] = 0x02;
                        memcpy(continuation + o, card_info.atqa, 2);
                        o += 2;
                        continuation[o++] = 0x83;
                        continuation[o++] = 0x01;
                        continuation[o++] = card_info.sak;
                        // Back-patch the four nested TLV length bytes now that the
                        // total length `o` is known.  Each holds "bytes remaining
                        // after this length byte", i.e. o minus the offset just
                        // past it:
                        //   [1]  BD outer   (payload starts at index 2)  -> o-2
                        //   [3]  A0 wrapper (starts at index 4)          -> o-4
                        //   [5]  A1 samResp (starts at index 6)          -> o-6
                        //   [10] A2 cardInfo(starts at index 11)         -> o-11
                        continuation[1] = (uint8_t)(o - 2);
                        continuation[3] = (uint8_t)(o - 4);
                        continuation[5] = (uint8_t)(o - 6);
                        continuation[10] = (uint8_t)(o - 11);
                        continuation_len = o;
                    }
                } else {
                    // Picopass SelectedCardInfo continuation.
                    picopass_hdr_t card_info;
                    uint32_t eof_time = 0;
                    memset(&card_info, 0, sizeof(card_info));
                    Iso15693InitReader();
                    bool selected = select_iclass_tag(&card_info, false, &eof_time, false);
                    switch_clock_to_ticks();
                    if (selected == false) {
                        static const uint8_t no_card[] = {0xbd, 0x02, 0x8a, 0x00};
                        memcpy(continuation, no_card, sizeof(no_card));
                        continuation_len = sizeof(no_card);
                    } else {
                        static const uint8_t prefix[] = {
                            0xbd, 0x17, 0xa0, 0x15, 0xa1, 0x13,
                            0x81, 0x01, 0x14, 0xa2, 0x0e,
                            0x80, 0x02, 0x00, 0x04, 0x81, 0x08
                        };
                        memcpy(continuation, prefix, sizeof(prefix));
                        memcpy(continuation + sizeof(prefix), card_info.csn, sizeof(card_info.csn));
                        continuation_len = sizeof(prefix) + sizeof(card_info.csn);
                    }
                }
            } else if (child_tag == 0xa1 && op_len > 0) {
                uint8_t nfc_rx[ISO7816_MAX_FRAME] = {0};
                uint16_t nfc_rx_len = 0;
                bool iso14a;
                if (card_transport == 0x02) {
                    iso14a = true;
                } else if (card_transport == 0x04) {
                    iso14a = false;
                } else {
                    iso14a = false;
                    uint16_t child_off = op_used;
                    while (child_off < child_len) {
                        uint8_t arg_tag;
                        const uint8_t *arg_value;
                        uint16_t arg_len, arg_used;
                        if (sam_sc_read_tlv(child + child_off, (uint16_t)(child_len - child_off),
                                            &arg_tag, &arg_value, &arg_len, &arg_used) != PM3_SUCCESS)
                            break;
                        if (arg_tag == 0x81 && arg_len == 2 &&
                                arg_value[0] == 0x02 && arg_value[1] == 0x02) {
                            iso14a = true;
                            break;
                        }
                        child_off += arg_used;
                    }
                }
                if (iso14a) {
                    switch_clock_to_countsspclk();
                    //Keep absolute transfer scheduler in the same time base; so it doesn't wait on a stale timestamp from the preceding Card-API APDU.
                    iso14a_rebase_transfer_time();
                    int apdu_len = iso14_apdu((uint8_t *)op_value, op_len, false,
                                              nfc_rx, sizeof(nfc_rx), NULL);
                    switch_clock_to_ticks();
                    if (apdu_len >= 2) {
                        nfc_rx_len = (uint16_t)(apdu_len - 2);
                        res = PM3_SUCCESS;
                    } else {
                        res = PM3_ECARDEXCHANGE;
                    }
                } else {
                    uint32_t start_time = GetCountSspClk();
                    uint32_t eof_time = start_time + DELAY_ICLASS_VICC_TO_VCD_READER;
                    bool is_update = ((op_value[0] & 0x0f) == ICLASS_CMD_UPDATE);
                    bool fake_epurse = prevent_epurse_update && is_update && op_len >= 10 &&
                                       op_value[0] == 0x87 && op_value[1] == 0x02;

                    if (fake_epurse) {
                        // The SAM expects the anti-tear e-purse response with the
                        // two 32-bit halves exchanged.
                        memcpy(nfc_rx, op_value + 6, 4);
                        memcpy(nfc_rx + 4, op_value, 4);
                        AddCrc(nfc_rx, 8);
                        nfc_rx_len = 10;
                    } else {
                        switch_clock_to_countsspclk();
                        // Match the established SAM relay tolerance for the
                        // short authentication frames.  A CHECK response is only
                        // four bytes and can be missed by a single 380-us wait;
                        // retrying a read/auth command is safe.  Never retransmit
                        // an actual UPDATE, however: it may already have modified
                        // the e-purse even when its response was lost.
                        uint8_t tries = is_update ? 1 : 3;
                        uint16_t timeout = is_update ? ICLASS_READER_TIMEOUT_UPDATE : ICLASS_READER_TIMEOUT_ACTALL;
                        nfc_rx_len = 0;
                        do {
                            iclass_send_as_reader((uint8_t *)op_value, op_len, &start_time, &eof_time, false);
                            res = GetIso15693AnswerFromTag(nfc_rx, sizeof(nfc_rx), timeout, &eof_time,
                                                           false, true, &nfc_rx_len);
                            if (res == PM3_SUCCESS && nfc_rx_len > 0) break;
                            start_time = eof_time + ((DELAY_ICLASS_VICC_TO_VCD_READER +
                                                      DELAY_ISO15693_VCD_TO_VICC_READER +
                                                      (8 * 8 * 8 * 16)) * 2);
                        } while (--tries > 0);
                        switch_clock_to_ticks();
                    }
                }

                if (res == PM3_SUCCESS && nfc_rx_len > 0) {
                    continuation_len = sam_sc_copy_payload_nfc2sam(continuation, ISO7816_MAX_FRAME,
                                                                   nfc_rx, nfc_rx_len);
                    if (continuation_len == 0)
                        res = PM3_ECARDEXCHANGE;
                } else {
                    static const uint8_t transceive_failed[] = {
                        0xbd, 0x0a, 0xa0, 0x08, 0x8a, 0x00,
                        0x68, 0x00, 0x81, 0x02, 0x64, 0x01
                    };
                    memcpy(continuation, transceive_failed, sizeof(transceive_failed));
                    continuation_len = sizeof(transceive_failed);
                    res = PM3_SUCCESS; // failure was reported to the SAM
                }
            } else {
                res = PM3_ECARDEXCHANGE;
                break;
            }
        }

        if (res != PM3_SUCCESS) break;
        res = sam_sc_send_card_api_continuation(sc_flag, continuation, continuation_len,
                                                response, response_len);
        if (res != PM3_SUCCESS) break;
    }

    // A Card API request that remains outstanding after the bounded loop would
    // otherwise be returned to the host as though it were a final SC response.
    if (res == PM3_SUCCESS) {
        uint16_t api_offset = sam_rx_prefix_len(response, *response_len);
        if (*response_len > api_offset && response[api_offset] == 0xa1) {
            res = PM3_ECARDEXCHANGE;
        }
    }

    return res;
}

void sam_sc_handler(const PacketCommandNG *c) {

    if (c == NULL || c->length < SAM_SC_HEADER_LEN) {
        reply_ng(CMD_HF_SAM_SC, PM3_EINVARG, NULL, 0);
        return;
    }

    const uint8_t *body = c->data.asBytes;
    const uint8_t flags        = body[SAM_SC_OFF_FLAGS];
    const uint8_t addr_src     = body[SAM_SC_OFF_ADDR_SRC];
    const uint8_t addr_dest    = body[SAM_SC_OFF_ADDR_DEST];
    const uint8_t addr_reply   = body[SAM_SC_OFF_ADDR_REPLY];
    const uint8_t scFlag       = body[SAM_SC_OFF_SCFLAG];
    const bool snmp_loader = addr_src == SAM_SC_ADDR_SNMP_LOADER &&
                             addr_dest == SAM_SC_ADDR_SNMP_LOADER &&
                             addr_reply == SAM_SC_ADDR_SNMP_LOADER;

    const bool force_reset = !!(flags & SAM_SC_FLAG_FORCE_RESET);
    const bool release     = !!(flags & SAM_SC_FLAG_RELEASE);
    const bool hf_relay    = !!(flags & SAM_SC_FLAG_HF_RELAY);
    const bool hf_select   = !!(flags & SAM_SC_FLAG_HF_SELECT);
    const bool hf_off      = !!(flags & SAM_SC_FLAG_HF_OFF);
    const bool card_api    = !!(flags & SAM_SC_FLAG_CARD_API);
    const bool prevent_epurse_update = !!(flags & SAM_SC_FLAG_PREVENT_EPURSE_UPDATE);
    // HF_SELECT / HF_OFF are management ops that carry no SAM payload.
    const bool no_payload  = !!(flags & SAM_SC_FLAG_NO_PAYLOAD) || hf_select || hf_off;

    const uint8_t *payload     = body + SAM_SC_HEADER_LEN;
    uint16_t payload_len       = (uint16_t)(c->length - SAM_SC_HEADER_LEN);

    if (no_payload) {
        // Caller is just managing session state (open/close/arm/disarm)
        payload_len = 0;
    } else if (payload_len == 0) {
        reply_ng(CMD_HF_SAM_SC, PM3_EINVARG, NULL, 0);
        return;
    }

    LED_D_ON();
    set_tracing(true);

    int res = PM3_SUCCESS;

    // Reset the SAM only if the caller asked for it OR this is the first SC
    // op since boot / since the previous session was released. Crucially
    // this dispatcher does NOT reset on every call the way sam_picopass_get_pacs
    // does, so the SAM-side session-flag binding established by ContinueAuth
    // survives across multiple CMD_HF_SAM_SC invocations.
    //
    // A module reset can leave an ATR pending and returns the module UART to
    // its default rate. Consume the ATR first: besides preventing it from
    // colliding with the warmup APDU, GetATR() restores the cached PPS rate so
    // the module and SAM are synchronized again. This mirrors the direct
    // PICOPASS SAM path.
    //
    // Then issue a sam_get_version() warmup ping. Without it, the first real
    // sam_send_payload_ex() after I2C_Reset can time out while the 8051<->SAM
    // UART link settles. Do not enter a session when either stage fails.
    //
    // NOTE: HF_SELECT / HF_OFF must NOT trigger a reset - they run inside an
    // already-open SC session and a reset would wipe the SAM-side session-flag
    // binding. They pass neither force_reset nor a cleared session flag.
    if (force_reset || s_sam_sc_session_active == false) {
        // A forced reset may replace an otherwise valid active session. Do not
        // leave it marked live if ATR recovery or the warmup subsequently
        // fails.
        s_sam_sc_session_active = false;
        I2C_Reset_EnterMainProgram();
        StartTicks();
#if SAM_SC_FORCE_T1_TA1_95
        sc_request_sam_t1_profile();
#endif
        smart_card_atr_t card;
        if (GetATR(&card, false) == false) {
            res = PM3_ECARDEXCHANGE;
            goto out;
        }
        res = sam_get_version(false);
        if (res != PM3_SUCCESS) {
            goto out;
        }
        s_sam_sc_session_active = true;
    }

    // ---- HF_OFF: disarm the field (no SAM traffic) ----
    if (hf_off) {
        switch_off();
        reply_ng(CMD_HF_SAM_SC, PM3_SUCCESS, NULL, 0);
        goto done;
    }

    // ---- HF_SELECT: energize field + select an iCLASS tag, return CSN/AIA ----
    // Leaves the field ON so subsequent relay-bearing scsend calls can drive
    // the same card. Reply layout matches the normal path: [scFlag][payload],
    // here [0x00][CSN(8)][AIA(8)].
    if (hf_select) {
        picopass_hdr_t card_info;
        memset(&card_info, 0, sizeof(card_info));
        uint32_t eof_time = 0;

        // implicit StartSspClk() happens inside select_iclass_tag
        Iso15693InitReader();
        if (select_iclass_tag(&card_info, false, &eof_time, false) == false) {
            switch_clock_to_ticks();
            reply_ng(CMD_HF_SAM_SC, PM3_ECARDEXCHANGE, NULL, 0);
            goto done;
        }
        uint8_t aia[8];
        bool got_aia = false;
        static const uint8_t read_aia[] = {0x0c, 0x05, 0xde, 0x64};
        uint8_t aia_rx[10];
        uint16_t aia_rx_len = 0;
        uint32_t start_time = GetCountSspClk();
        uint8_t tries = 3;
        do {
            iclass_send_as_reader((uint8_t *)read_aia, sizeof(read_aia),
                                  &start_time, &eof_time, false);
            res = GetIso15693AnswerFromTag(aia_rx, sizeof(aia_rx),
                                           ICLASS_READER_TIMEOUT_ACTALL,
                                           &eof_time, false, true, &aia_rx_len);
            if (res == PM3_SUCCESS && aia_rx_len == sizeof(aia_rx)) {
                memcpy(aia, aia_rx, sizeof(aia));
                got_aia = true;
                break;
            }
            start_time = eof_time + ((DELAY_ICLASS_VICC_TO_VCD_READER +
                                      DELAY_ISO15693_VCD_TO_VICC_READER +
                                      (8 * 8 * 8 * 16)) * 2);
        } while (--tries > 0);

        // Return to ticks so the next SAM I2C exchange has the right clock.
        switch_clock_to_ticks();

        uint8_t out[17];
        out[0] = 0x00;   // scFlag placeholder (no SAM traffic on this op)
        memcpy(out + 1, card_info.csn, 8);
        if (got_aia) memcpy(out + 9, aia, sizeof(aia));
        reply_ng(CMD_HF_SAM_SC, PM3_SUCCESS, out, got_aia ? sizeof(out) : 9);
        goto done;
    }

    if (no_payload == false) {
        if (hf_relay && card_api == false) {
            picopass_hdr_t hdr;
            memset(&hdr, 0, sizeof(hdr));
            uint32_t eof_time = 0;
            Iso15693InitReader();
            if (select_iclass_tag(&hdr, false, &eof_time, false) == false) {
                if (g_dbglevel >= DBG_INFO) {
                    DbpString("SC relay: re-select FAILED (no card in field)");
                }
                switch_clock_to_ticks();
                reply_ng(CMD_HF_SAM_SC, PM3_ECARDEXCHANGE, NULL, 0);
                goto done;
            }
            if (g_dbglevel >= DBG_INFO) {
                DbpString("SC relay: re-selected card CSN: ");
                Dbhexdump(8, hdr.csn, false);
            }
            // Back to ticks for the SAM I2C exchange; the relay loop switches to
            // countsspclk itself when it starts driving HF.
            switch_clock_to_ticks();
        }

        uint8_t *response = BigBuf_calloc(ISO7816_MAX_FRAME);
        if (response == NULL) {
            res = PM3_EMALLOC;
            goto out;
        }
        uint16_t response_len = ISO7816_MAX_FRAME;

        if (snmp_loader) {
            res = sam_sc_snmp_loader_exchange(payload, payload_len, response, &response_len);
        } else {
            res = sam_send_payload_ex(
                      addr_src, addr_dest, addr_reply, scFlag,
                      payload, &payload_len,
                      response, &response_len
                  );
        }

        if (res == PM3_SUCCESS && card_api) {
            res = sam_sc_card_api_loop(response, &response_len, prevent_epurse_update);
        } else if (res == PM3_SUCCESS && hf_relay && sam_relay_pending(response, response_len)) {
            uint8_t *sam_tx = BigBuf_calloc(ISO7816_MAX_FRAME);
            if (sam_tx == NULL) {
                res = PM3_EMALLOC;
            } else {
                res = sam_relay_iso15_loop(
                          sam_tx, response, &response_len,
                          /* shallow_mod          */ false,
                          /* break_on_nr_mac      */ false,
                          /* prevent_epurse_update*/ false,
                          NULL, NULL, NULL
                      );
            }
        }

        if (res != PM3_SUCCESS) {
            // Whatever happened on the wire, the session may be in an
            // inconsistent state. Mark dirty so the next call re-opens.
            s_sam_sc_session_active = false;
        }

        if (release) {
            // Caller requested an explicit teardown after this op (typically
            // after a samCommandSecureChannelTerminate). Do a full reset to
            // bring the SAM back to a clean idle state.
            I2C_Reset_EnterMainProgram();
            s_sam_sc_session_active = false;
        }

        if (snmp_loader && res == PM3_SUCCESS) {
            reply_ng(CMD_HF_SAM_SC, PM3_SUCCESS, response, response_len);
            // Reformat the buffer for the host: prepend the SAM-assigned scFlag,
            // then the SAM payload.  Grace SAMs mirror either a five- or six-byte
            // routing tail; deriving both positions from the BD success or BE
            // error response node avoids exposing the final routing byte as part
            // of the payload.
            // memmove is safe across the overlapping ranges.
        } else if (res == PM3_SUCCESS) {
            uint16_t reply_offset = sam_sc_reply_offset(response, response_len);
            if (reply_offset == 0) {
                // sam_send_payload_ex succeeded but the response has no valid
                // routing tail plus SAM response node.
                reply_ng(CMD_HF_SAM_SC, PM3_ECARDEXCHANGE, NULL, 0);
            } else {
                uint8_t sc_flag = response[reply_offset - 1];
                uint16_t sam_payload_len = (uint16_t)(response_len - reply_offset);
                memmove(response + 1, response + reply_offset, sam_payload_len);
                response[0] = sc_flag;
                response_len = (uint16_t)(1 + sam_payload_len);
                reply_ng(CMD_HF_SAM_SC, PM3_SUCCESS, response, response_len);
            }
        } else {
            // sam_send_payload_ex failed. Propagate the error; no payload.
            reply_ng(CMD_HF_SAM_SC, res, NULL, 0);
        }

        BigBuf_free();
        goto done;
    }

    // SAM_SC_FLAG_NO_PAYLOAD path: caller wants to manage session state only.
    if (release) {
        I2C_Reset_EnterMainProgram();
        s_sam_sc_session_active = false;
    }

out:
    reply_ng(CMD_HF_SAM_SC, res, NULL, 0);

done:
    set_tracing(false);
    LEDsoff();
}
