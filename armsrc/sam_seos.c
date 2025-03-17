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
// Routines to support SEOS <-> SAM communication
// communication and ASN.1 messages based on https://github.com/bettse/seader/blob/main/seader.asn1
//-----------------------------------------------------------------------------
#include "sam_seos.h"
#include "sam_common.h"
#include "iclass.h"

#include "proxmark3_arm.h"
#include "iso14443a.h"

#include "iclass.h"
#include "crc16.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "cmd.h"
#include "commonutil.h"
#include "ticks.h"
#include "dbprint.h"
#include "i2c.h"
#include "protocols.h"
#include "optimized_cipher.h"
#include "fpgaloader.h"
#include "pm3_cmd.h"

#include "cmd.h"


/**
 * @brief Sets the card detected status for the SAM (Secure Access Module).
 *
 * This function informs that a card has been detected by the reader and
 * initializes SAM communication with the card.
 *
 * @param card_select Pointer to the descriptor of the detected card.
 * @return Status code indicating success or failure of the operation.
 */
static int sam_set_card_detected_seos(iso14a_card_select_t *card_select) {
    int res = PM3_SUCCESS;
    if (g_dbglevel >= DBG_DEBUG)
        DbpString("start sam_set_card_detected");

    uint8_t   *request = BigBuf_malloc(ISO7816_MAX_FRAME);
    uint16_t request_len = ISO7816_MAX_FRAME;

    uint8_t   *response = BigBuf_malloc(ISO7816_MAX_FRAME);
    uint16_t response_len = ISO7816_MAX_FRAME;

    const uint8_t payload[] = {
        0xa0, 8, // <- SAM command
        0xad, 6, // <- set detected card
        0xa0, 4, // <- detected card details
        0x80, 2, // <- protocol
        0x00, 0x02 // <- ISO14443A
    };

    memcpy(request, payload, sizeof(payload));
    sam_append_asn1_node(request, request + 4, 0x81, card_select->uid, card_select->uidlen);
    sam_append_asn1_node(request, request + 4, 0x82, card_select->atqa, 2);
    sam_append_asn1_node(request, request + 4, 0x83, &card_select->sak, 1);
    request_len = request[1] + 2;

    sam_send_payload(
        0x44, 0x0a, 0x44,
        request,
        &request_len,
        response,
        &response_len
    );

    // resp:
    // c1 64 00 00 00
    //    bd 02 <- response
    //     8a 00 <- empty response (accepted)
    // 90 00

    if (response[5] != 0xbd) {
        if (g_dbglevel >= DBG_ERROR)
            Dbprintf("Invalid SAM response");
        goto error;
    } else {
        // uint8_t * sam_response_an = sam_find_asn1_node(response + 5, 0x8a);
        // if(sam_response_an == NULL){
        //     if (g_dbglevel >= DBG_ERROR)
        //         Dbprintf("Invalid SAM response");
        //     goto error;
        // }
        goto out;
    }
error:
    res = PM3_ESOFT;

out:
    BigBuf_free();

    if (g_dbglevel >= DBG_DEBUG)
        DbpString("end sam_set_card_detected");
    return res;
}

/**
 * @brief Sends a request to the SAM and retrieves the response.
 *
 * Unpacks request to the SAM and relays ISO14A traffic to the card.
 * If no request data provided, sends a request to get PACS data.
 *
 * @param request Pointer to the buffer containing the request to be sent to the SAM.
 * @param request_len Length of the request to be sent to the SAM.
 * @param response Pointer to the buffer where the retreived data will be stored.
 * @param response_len Pointer to the variable where the length of the retreived data will be stored.
 * @return Status code indicating success or failure of the operation.
 */
static int sam_send_request_iso14a(const uint8_t *const request, const uint8_t request_len, uint8_t *response, uint8_t *response_len) {
    int res = PM3_SUCCESS;
    if (g_dbglevel >= DBG_DEBUG)
        DbpString("start sam_send_request_iso14a");

    uint8_t *buf1 = BigBuf_malloc(ISO7816_MAX_FRAME);
    uint8_t *buf2 = BigBuf_malloc(ISO7816_MAX_FRAME);
    if (buf1 == NULL || buf2 == NULL) {
        res = PM3_EMALLOC;
        goto out;
    }

    uint8_t *sam_tx_buf = buf1;
    uint16_t sam_tx_len;

    uint8_t *sam_rx_buf = buf2;
    uint16_t sam_rx_len;

    uint8_t *nfc_tx_buf = buf1;
    uint16_t nfc_tx_len;

    uint8_t *nfc_rx_buf = buf2;
    uint16_t nfc_rx_len;

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

    if (sam_rx_buf[1] == 0x61) { // commands to be relayed to card starts with 0x61
        // tag <-> SAM exchange starts here
        while (sam_rx_buf[1] == 0x61) {
            switch_clock_to_countsspclk();
            nfc_tx_len = sam_copy_payload_sam2nfc(nfc_tx_buf, sam_rx_buf);

            nfc_rx_len = iso14_apdu(
                             nfc_tx_buf,
                             nfc_tx_len,
                             false,
                             nfc_rx_buf,
                             ISO7816_MAX_FRAME,
                             NULL
                         );

            switch_clock_to_ticks();
            sam_tx_len = sam_copy_payload_nfc2sam(sam_tx_buf, nfc_rx_buf, nfc_rx_len - 2);

            sam_send_payload(
                0x14, 0x0a, 0x14,
                sam_tx_buf, &sam_tx_len,
                sam_rx_buf, &sam_rx_len
            );

            // last SAM->TAG
            // c1 61 c1 00 00 a1 02 >>82<< 00 90 00
            if (sam_rx_buf[7] == 0x82) {
                // tag <-> SAM exchange ends here
                break;
            }

        }

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

    // resp for SamCommandGetContentElement:
    // c1 64 00 00 00
    // bd 09
    //    8a 07
    //        03 05 <- include tag for pm3 client
    //           06 85 80 6d c0 <- decoded PACS data
    // 90 00

    // resp for samCommandGetContentElement2:
    // c1 64 00 00 00
    // bd 1e
    //    b3 1c
    //       a0 1a
    //          80 05
    //             06 85 80 6d c0
    //           81 0e
    //              2b 06 01 04 01 81 e4 38 01 01 02 04 3c ff
    //           82 01
    //              07
    // 90 00
    if (request_len == 0) {
        if (
            !(sam_rx_buf[5] == 0xbd && sam_rx_buf[5 + 2] == 0x8a && sam_rx_buf[5 + 4] == 0x03)
            &&
            !(sam_rx_buf[5] == 0xbd && sam_rx_buf[5 + 2] == 0xb3 && sam_rx_buf[5 + 4] == 0xa0)
        ) {
            if (g_dbglevel >= DBG_ERROR)
                Dbprintf("No PACS data in SAM response");
            res = PM3_ESOFT;
        }
    }

    *response_len = sam_rx_buf[5 + 1] + 2;
    memcpy(response, sam_rx_buf + 5, *response_len);

    goto out;

out:
    BigBuf_free();
    return res;
}

/**
 * @brief Retrieves PACS data from SEOS card using SAM.
 *
 * This function is called by appmain.c
 * It sends a request to the SAM to get the PACS data from the SEOS card.
 * The PACS data is then returned to the PM3 client.
 *
 * @return Status code indicating success or failure of the operation.
 */
int sam_seos_get_pacs(PacketCommandNG *c) {
    const uint8_t flags = c->data.asBytes[0];
    const bool disconnectAfter = !!(flags & BITMASK(0));
    const bool skipDetect = !!(flags & BITMASK(1));

    uint8_t *cmd = c->data.asBytes + 1;
    uint16_t cmd_len = c->length - 1;


    int res = PM3_EFAILED;

    clear_trace();
    I2C_Reset_EnterMainProgram();

    set_tracing(true);
    StartTicks();

    // step 1: ping SAM
    sam_get_version();

    if (!skipDetect) {
        // step 2: get card information
        iso14a_card_select_t card_a_info;

        // implicit StartSspClk() happens here
        iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
        if (!iso14443a_select_card(NULL, &card_a_info, NULL, true, 0, false)) {
            goto err;
        }

        switch_clock_to_ticks();

        // step 3: SamCommand CardDetected
        sam_set_card_detected_seos(&card_a_info);
    }

    // step 3: SamCommand RequestPACS, relay NFC communication
    uint8_t sam_response[ISO7816_MAX_FRAME] = { 0x00 };
    uint8_t sam_response_len = 0;
    res = sam_send_request_iso14a(cmd, cmd_len, sam_response, &sam_response_len);
    if (res != PM3_SUCCESS) {
        goto err;
    }
    if (g_dbglevel >= DBG_INFO)
        print_result("Response data", sam_response, sam_response_len);

    goto out;
    goto off;

err:
    res = PM3_ENOPACS;
    reply_ng(CMD_HF_SAM_SEOS, res, NULL, 0);
    goto off;
out:
    reply_ng(CMD_HF_SAM_SEOS, PM3_SUCCESS, sam_response, sam_response_len);
    goto off;
off:
    if (disconnectAfter) {
        switch_off();
    }
    set_tracing(false);
    StopTicks();
    BigBuf_free();
    return res;
}
