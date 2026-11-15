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
// Routines to support MFC <-> SAM communication
// The SAM runs Crypto1 itself. Frame handling follows Seader (bettse/seader,
// GPLv3) hf_interface_fal/hf.c plugin_hf_mfc_transmit.
//-----------------------------------------------------------------------------
#include <string.h>
#include "sam_mfc.h"
#include "sam_common.h"
#include "sam_sc.h"
#include "iclass.h"

#include "proxmark3_arm.h"
#include "cmd.h"
#include "util.h"          // switch_clock_to_ticks / _countsspclk
#include "iso14443a.h"
#include "BigBuf.h"
#include "commonutil.h"
#include "ticks_apis.h"
#include "dbprint.h"
#include "i2c.h"
#include "fpga_loader.h"
#include "fpga_apis.h"
#include "pm3_cmd.h"

// nfcSend formats. Plain: bytes as is, parity generated, CRC already in the
// data. Bits: air order stream with the SAM's own parity bits.
static bool sam_mfc_format_plain(const uint8_t *f) {
    return (f[0] == 0x00 && f[1] == 0xC0 && f[2] == 0x00);
}

static bool sam_mfc_format_bits(const uint8_t *f) {
    return (f[0] == 0x00 && f[1] == 0x00 && (f[2] == 0x40 || f[2] == 0x24 || f[2] == 0x44));
}

/**
 * @brief Sends a request to the SAM and relays MIFARE Classic frames to the card.
 *
 * If no request data provided, sends a request to get PACS data.
 */
static int sam_send_request_mfc(const uint8_t *const request, const uint8_t request_len, uint8_t *response, uint8_t *response_len) {

    int res = PM3_SUCCESS;

    uint8_t *buf1 = BigBuf_calloc(ISO7816_MAX_FRAME);
    uint8_t *buf2 = BigBuf_calloc(ISO7816_MAX_FRAME);
    uint8_t *frame = BigBuf_calloc(MAX_FRAME_SIZE);
    uint8_t *par = BigBuf_calloc(MAX_PARITY_SIZE);
    uint8_t *packed = BigBuf_calloc(MAX_FRAME_SIZE + (MAX_FRAME_SIZE / 8) + 1);
    if (buf1 == NULL || buf2 == NULL || frame == NULL || par == NULL || packed == NULL) {
        res = PM3_EMALLOC;
        goto out;
    }

    uint8_t *sam_tx_buf = buf1;
    uint16_t sam_tx_len;

    uint8_t *sam_rx_buf = buf2;
    uint16_t sam_rx_len;

    uint8_t *nfc_tx_buf = buf1;
    uint16_t nfc_tx_len;

    if (request_len > 0) {
        sam_tx_len = request_len;
        memcpy(sam_tx_buf, request, sam_tx_len);
    } else {
        // send get pacs
        static const uint8_t payload[] = {
            0xa0, 19, // <- SAM command
            0xBE, 17, // <- samCommandGetContentElement2
            0x80, 1,
            0x04, // <- implicitFormatPhysicalAccessBits
            0x84, 12,
            0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xE4, 0x38, 0x01, 0x01, 0x02, 0x04 // <- SoRootOID
        };

        sam_tx_len = sizeof(payload);
        memcpy(sam_tx_buf, payload, sam_tx_len);
    }

    sam_send_payload(
        0x44, 0x0a, 0x44,
        sam_tx_buf, &sam_tx_len,
        sam_rx_buf, &sam_rx_len
    );

    // tag <-> SAM exchange
    while (sam_relay_pending(sam_rx_buf, sam_rx_len)) {

        uint8_t format[3] = {0};
        bool has_format = sam_nfc_send_format(sam_rx_buf, sam_rx_len, format);
        nfc_tx_len = sam_copy_payload_sam2nfc(nfc_tx_buf, sam_rx_buf, sam_rx_len);

        uint8_t *answer = NULL;
        uint16_t answer_len = 0;
        uint16_t rf_status = SAM_RF_STATUS_PROTOCOL;

        switch_clock_to_countsspclk();

        if (has_format && sam_mfc_format_plain(format) && nfc_tx_len > 0 && nfc_tx_len <= MAX_FRAME_SIZE) {

            ReaderTransmit(nfc_tx_buf, nfc_tx_len, NULL);
            answer_len = ReaderReceive(frame, MAX_FRAME_SIZE, par);
            answer = frame;
            rf_status = (answer_len) ? SAM_RF_STATUS_OK : SAM_RF_STATUS_TIMEOUT;

        } else if (has_format && sam_mfc_format_bits(format) && nfc_tx_len > 1 && nfc_tx_len <= MAX_FRAME_SIZE) {

            uint16_t n = iso14a_air_bits_unpack(nfc_tx_buf, nfc_tx_len, frame, par);
            ReaderTransmitPar(frame, n, par, NULL);

            uint16_t len = ReaderReceive(frame, MAX_FRAME_SIZE, par);
            if (len) {
                // Seader hands back len + len / 8 + 1 bytes, zero padded
                answer_len = len + (len / 8) + 1;
                memset(packed, 0, answer_len);
                iso14a_air_bits_pack(frame, par, len, packed);
                answer = packed;
                rf_status = SAM_RF_STATUS_OK;
            } else {
                rf_status = SAM_RF_STATUS_TIMEOUT;
            }

        } else if (g_dbglevel >= DBG_ERROR) {
            Dbprintf("MFC relay: unhandled format %02x%02x%02x", format[0], format[1], format[2]);
        }

        switch_clock_to_ticks();

        // the nfcRx must stay within short form ASN.1 lengths
        if (answer_len > 117) {
            answer_len = 0;
            rf_status = SAM_RF_STATUS_PROTOCOL;
        }

        sam_tx_len = sam_copy_payload_nfc2sam_status(sam_tx_buf, answer, (uint8_t)answer_len, rf_status);

        sam_send_payload(0x14, 0x0a, 0x14, sam_tx_buf, &sam_tx_len, sam_rx_buf, &sam_rx_len);

        if (sam_relay_complete(sam_rx_buf, sam_rx_len)) {
            break;
        }
    }

    // the SAM waits for an ack once it switched the field off
    if (sam_relay_complete(sam_rx_buf, sam_rx_len)) {
        static const uint8_t hfack[] = {
            0xbd, 0x04, 0xa0, 0x02, 0x82, 0x00
        };

        sam_tx_len = sizeof(hfack);
        memcpy(sam_tx_buf, hfack, sam_tx_len);

        sam_send_payload(
            0x14, 0x0a, 0x00,
            sam_tx_buf, &sam_tx_len,
            sam_rx_buf, &sam_rx_len
        );
    }

    uint16_t plen = 0;
    uint16_t ofs = sam_response_payload(sam_rx_buf, sam_rx_len, &plen);

    if (request_len == 0) {
        if (
            !(sam_rx_buf[ofs] == 0xbd && sam_rx_buf[ofs + 2] == 0x8a && sam_rx_buf[ofs + 4] == 0x03) &&
            !(sam_rx_buf[ofs] == 0xbd && sam_rx_buf[ofs + 2] == 0xb3 && sam_rx_buf[ofs + 4] == 0xa0)
        ) {
            if (g_dbglevel >= DBG_ERROR) {
                Dbprintf("No PACS data in SAM response");
            }
            res = PM3_ESOFT;
        }
    }

    *response_len = (uint8_t)plen;
    memcpy(response, sam_rx_buf + ofs, *response_len);

out:
    BigBuf_free();
    return res;
}

/**
 * @brief Retrieves PACS data from a MIFARE Classic card using SAM.
 *
 * This function is called by appmain.c
 *
 * @return Status code indicating success or failure of the operation.
 */
int sam_mfc_get_pacs(PacketCommandNG *c) {
    const uint8_t flags = c->data.asBytes[0];
    const bool disconnectAfter = !!(flags & BITMASK(0));
    const bool skipDetect = !!(flags & BITMASK(1));
    const bool extReply = !!(flags & BITMASK(2));

    uint8_t *cmd = c->data.asBytes + 1;
    uint16_t cmd_len = c->length - 1;

    int res = PM3_EFAILED;
    uint8_t sam_response[ISO7816_MAX_FRAME] = { 0x00 };
    uint8_t sam_response_len = 0;

    clear_trace();
    sam_capture_reset();
    sam_sc_session_invalidate();
    I2C_Reset_EnterMainProgram();

    set_tracing(true);
    StartTicks();

    smart_card_atr_t card;
    if (GetATR(&card, false) == false) {
        if (g_dbglevel >= DBG_ERROR) {
            DbpString("SAM: no ATR - is a SAM in the slot?");
        }
        goto err;
    }

    // step 1: ping SAM
    sam_get_version(false);

    if (skipDetect == false) {
        // step 2: get card information, no RATS
        iso14a_card_select_t card_a_info;

        // implicit StartSspClk() happens here
        iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
        if (iso14443a_select_card(NULL, &card_a_info, NULL, true, 0, true) == 0) {
            goto err;
        }

        switch_clock_to_ticks();

        sam_capture_uid(card_a_info.uid, card_a_info.uidlen);

        // step 3: SamCommand CardDetected
        sam_set_card_detected_iso14a(&card_a_info, false);
    }

    // step 4: SamCommand RequestPACS, relay NFC communication
    res = sam_send_request_mfc(cmd, cmd_len, sam_response, &sam_response_len);
    if (res != PM3_SUCCESS) {
        goto err;
    }

    if (g_dbglevel >= DBG_INFO) {
        print_result("Response data", sam_response, sam_response_len);
    }

    sam_reply_pacs(CMD_HF_SAM_MFC, extReply && (cmd_len == 0), sam_response, sam_response_len);
    goto off;

err:
    res = PM3_ENOPACS;
    reply_ng(CMD_HF_SAM_MFC, res, NULL, 0);

off:
    if (disconnectAfter) {
        switch_off();
    }
    set_tracing(false);
    StopTicks();
    BigBuf_free();
    return res;
}
