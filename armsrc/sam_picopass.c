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
// Routines to support Picopass <-> SAM communication
//-----------------------------------------------------------------------------
#include "sam_picopass.h"
#include "sam_common.h"
#include "iclass.h"
#include "crc16.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "cmd.h"
#include "commonutil.h"
#include "ticks.h"
#include "dbprint.h"
#include "i2c.h"
#include "iso15693.h"
#include "protocols.h"
#include "optimized_cipher.h"
#include "fpgaloader.h"
#include "pm3_cmd.h"

/**
 * @brief Sends a request to the SAM and retrieves the response.
 *
 * Unpacks request to the SAM and relays ISO15 traffic to the card.
 * If no request data provided, sends a request to get PACS data.
 *
 * @param request Pointer to the buffer containing the request to be sent to the SAM.
 * @param request_len Length of the request to be sent to the SAM.
 * @param response Pointer to the buffer where the retreived data will be stored.
 * @param response_len Pointer to the variable where the length of the retreived data will be stored.
 * @return Status code indicating success or failure of the operation.
 */
static int sam_send_request_iso15(const uint8_t *const request, const uint8_t request_len, uint8_t *response, uint8_t *response_len, const bool shallow_mod, const bool break_on_nr_mac, const bool prevent_epurse_update) {
    int res = PM3_SUCCESS;
    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("start sam_send_request_iso14a");
    }

    uint8_t *buf1 = BigBuf_calloc(ISO7816_MAX_FRAME);
    uint8_t *buf2 = BigBuf_calloc(ISO7816_MAX_FRAME);
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
        switch_clock_to_countsspclk();
        // tag <-> SAM exchange starts here

        while (sam_rx_buf[1] == 0x61) {
            uint32_t start_time = GetCountSspClk();
            uint32_t eof_time = start_time + DELAY_ICLASS_VICC_TO_VCD_READER;

            nfc_tx_len = sam_copy_payload_sam2nfc(nfc_tx_buf, sam_rx_buf);

            bool is_cmd_check = ((nfc_tx_buf[0] & 0x0F) == ICLASS_CMD_CHECK);

            if (is_cmd_check && break_on_nr_mac) {

                memcpy(response, nfc_tx_buf, nfc_tx_len);
                *response_len = nfc_tx_len;

                if (g_dbglevel >= DBG_INFO) {
                    DbpString("NR-MAC: ");
                    Dbhexdump((*response_len) - 1, response + 1, false);
                }
                res = PM3_SUCCESS;
                goto out;
            }

            bool is_cmd_update = ((nfc_tx_buf[0] & 0x0F) == ICLASS_CMD_UPDATE);

            if (is_cmd_update && prevent_epurse_update && nfc_tx_buf[0] == 0x87 && nfc_tx_buf[1] == 0x02) {
                // block update(2) command and fake the response to prevent update of epurse

                // NFC TX BUFFERS PREPARED BY SAM LOOKS LIKE:
                // 87 02 #1(C9 FD FF FF) #2(FF FF FF FF) F4 BF 98 E2

                // NFC RX BUFFERS EXPECTED BY SAM WOULD LOOK LIKE:
                // #2(FF FF FF FF) #1(C9 FD FF FF) 3A 47

                memcpy(nfc_rx_buf + 0, nfc_tx_buf + 6, 4);
                memcpy(nfc_rx_buf + 4, nfc_tx_buf + 0, 4);
                AddCrc(nfc_rx_buf, 8);
                nfc_rx_len = 10;

                if (g_dbglevel >= DBG_INFO) {
                    DbpString("FAKE EPURSE UPDATE RESPONSE: ");
                    Dbhexdump(nfc_rx_len, nfc_rx_buf, false);
                }

            } else {
                if (g_dbglevel >= DBG_INFO) {
                    DbpString("ISO15 TAG REQUEST: ");
                    Dbhexdump(nfc_tx_len, nfc_tx_buf, false);
                }

                int tries = 3;
                nfc_rx_len = 0;
                while (tries-- > 0) {
                    iclass_send_as_reader(nfc_tx_buf, nfc_tx_len, &start_time, &eof_time, shallow_mod);
                    uint16_t timeout = is_cmd_update ? ICLASS_READER_TIMEOUT_UPDATE : ICLASS_READER_TIMEOUT_ACTALL;

                    res = GetIso15693AnswerFromTag(nfc_rx_buf, ISO7816_MAX_FRAME, timeout, &eof_time, false, true, &nfc_rx_len);
                    if (res == PM3_SUCCESS && nfc_rx_len > 0) {
                        break;
                    }

                    start_time = eof_time + ((DELAY_ICLASS_VICC_TO_VCD_READER + DELAY_ISO15693_VCD_TO_VICC_READER + (8 * 8 * 8 * 16)) * 2);
                }


                if (res != PM3_SUCCESS) {
                    res = PM3_ECARDEXCHANGE;
                    goto out;
                }

                if (g_dbglevel >= DBG_INFO) {
                    DbpString("ISO15 TAG RESPONSE: ");
                    Dbhexdump(nfc_rx_len, nfc_rx_buf, false);
                }
            }


            switch_clock_to_ticks();
            sam_tx_len = sam_copy_payload_nfc2sam(sam_tx_buf, nfc_rx_buf, nfc_rx_len);

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

            switch_clock_to_countsspclk();

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

        if (!(sam_rx_buf[5] == 0xbd && sam_rx_buf[5 + 2] == 0x8a && sam_rx_buf[5 + 4] == 0x03) &&
                !(sam_rx_buf[5] == 0xbd && sam_rx_buf[5 + 2] == 0xb3 && sam_rx_buf[5 + 4] == 0xa0)) {

            if (g_dbglevel >= DBG_ERROR) {
                Dbprintf("No PACS data in SAM response");
            }
            res = PM3_ESOFT;
        }
    }

    if (sam_rx_buf[6] == 0x81 && sam_rx_buf[8] == 0x8a && sam_rx_buf[9] == 0x81) { //check if the response is an SNMP message
        *response_len = sam_rx_buf[5 + 2] + 3;
    } else { //if not, use the old logic
        *response_len = sam_rx_buf[5 + 1] + 2;
    }

    if (sam_rx_buf[5] == 0xBD && sam_rx_buf[4] != 0x00) { //secure channel flag is not 0x00
        Dbprintf(_YELLOW_("Secure channel flag set to: ")"%02x", sam_rx_buf[4]);
    }

    memcpy(response, sam_rx_buf + 5, *response_len);

    goto out;

out:
    BigBuf_free();
    return res;
}


/**
 * @brief Emulates iClass card responses to the SAM using data from emulator memory.
 *
 * Instead of relaying NFC traffic to a real card, generates card responses
 * from dump data loaded into BigBuf emulator memory. Handles READ, CHECK,
 * READCHECK, READ4, UPDATE, and PAGESEL commands.
 *
 * @param request Pointer to the initial request to send to the SAM.
 * @param request_len Length of the initial request.
 * @param response Pointer to the buffer where the SAM's final response will be stored.
 * @param response_len Pointer to the variable where the response length will be stored.
 * @param break_on_nr_mac If true, return the Nr-MAC instead of completing authentication.
 * @param prevent_epurse_update If true, fake the epurse update response.
 * @return Status code indicating success or failure of the operation.
 */
static int sam_send_request_emulated(const uint8_t *const request, const uint8_t request_len, uint8_t *response, uint8_t *response_len, const bool break_on_nr_mac, const bool prevent_epurse_update) {
    int res = PM3_SUCCESS;

    uint8_t *emulator = BigBuf_get_EM_addr();

    // Pre-compute cipher states for KD and KC from dump blocks 2, 3, 4
    uint8_t *epurse = emulator + (8 * 2);
    uint8_t *kd = emulator + (8 * 3);
    uint8_t *kc = emulator + (8 * 4);

    if (g_dbglevel >= DBG_DEBUG) {
        Dbprintf("Emulate: epurse (blk2): %02x%02x%02x%02x%02x%02x%02x%02x",
                 epurse[0], epurse[1], epurse[2], epurse[3],
                 epurse[4], epurse[5], epurse[6], epurse[7]);
        Dbprintf("Emulate: KD    (blk3): %02x%02x%02x%02x%02x%02x%02x%02x",
                 kd[0], kd[1], kd[2], kd[3], kd[4], kd[5], kd[6], kd[7]);
        Dbprintf("Emulate: KC    (blk4): %02x%02x%02x%02x%02x%02x%02x%02x",
                 kc[0], kc[1], kc[2], kc[3], kc[4], kc[5], kc[6], kc[7]);
    }

    State_t cipher_state_KD = opt_doTagMAC_1(epurse, kd);
    State_t cipher_state_KC = opt_doTagMAC_1(epurse, kc);
    State_t *cipher_state = &cipher_state_KD;
    uint8_t *diversified_key = kd;

    uint8_t *buf1 = BigBuf_calloc(ISO7816_MAX_FRAME);
    uint8_t *buf2 = BigBuf_calloc(ISO7816_MAX_FRAME);
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
        static const uint8_t payload[] = {
            0xa0, 19,
            0xBE, 17,
            0x80, 1,
            0x04,
            0x84, 12,
            0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xE4, 0x38, 0x01, 0x01, 0x02, 0x04
        };

        sam_tx_len = sizeof(payload);
        memcpy(sam_tx_buf, payload, sam_tx_len);
    }

    sam_send_payload(
        0x44, 0x0a, 0x44,
        sam_tx_buf, &sam_tx_len,
        sam_rx_buf, &sam_rx_len
    );

    if (g_dbglevel >= DBG_INFO) {
        Dbprintf("Emulate: initial SAM resp[1]=%02x rx_len=%u", sam_rx_buf[1], sam_rx_len);
    }

    if (sam_rx_buf[1] == 0x61) {
        while (sam_rx_buf[1] == 0x61) {
            nfc_tx_len = sam_copy_payload_sam2nfc(nfc_tx_buf, sam_rx_buf);

            if (g_dbglevel >= DBG_INFO) {
                Dbprintf("Emulate: SAM NFC cmd [%u]: %02x %02x ...", nfc_tx_len,
                         nfc_tx_len > 0 ? nfc_tx_buf[0] : 0,
                         nfc_tx_len > 1 ? nfc_tx_buf[1] : 0);
            }

            uint8_t cmd = nfc_tx_buf[0] & 0x0F;
            uint8_t block = nfc_tx_buf[1];

            bool is_cmd_check = (cmd == ICLASS_CMD_CHECK);

            if (is_cmd_check && break_on_nr_mac) {
                memcpy(response, nfc_tx_buf, nfc_tx_len);
                *response_len = nfc_tx_len;
                res = PM3_SUCCESS;
                goto out;
            }

            bool is_cmd_update = (cmd == ICLASS_CMD_UPDATE);

            if (is_cmd_update && prevent_epurse_update && nfc_tx_buf[0] == 0x87 && block == 0x02) {
                // Fake epurse update: swap the two halves of the new epurse value
                memcpy(nfc_rx_buf + 0, nfc_tx_buf + 6, 4);
                memcpy(nfc_rx_buf + 4, nfc_tx_buf + 0, 4);
                AddCrc(nfc_rx_buf, 8);
                nfc_rx_len = 10;
            } else {
                // Generate card response from dump data
                switch (cmd) {
                    case ICLASS_CMD_READCHECK: {
                        // Select debit (0x88) or credit (0x18) key
                        if (nfc_tx_buf[0] == (0x80 | ICLASS_CMD_READCHECK)) {
                            cipher_state = &cipher_state_KD;
                            diversified_key = kd;
                        } else {
                            cipher_state = &cipher_state_KC;
                            diversified_key = kc;
                        }
                        // Return block data (epurse) without CRC
                        memcpy(nfc_rx_buf, emulator + (block * 8), 8);
                        nfc_rx_len = 8;
                        break;
                    }
                    case ICLASS_CMD_CHECK: {
                        // Compute tag MAC response: nfc_tx_buf[1..4] is the reader Nr
                        uint8_t mac[4] = {0};
                        if (g_dbglevel >= DBG_EXTENDED) {
                            Dbprintf("Emulate: CHECK NR=%02x%02x%02x%02x MAC_r=%02x%02x%02x%02x",
                                     nfc_tx_buf[1], nfc_tx_buf[2], nfc_tx_buf[3], nfc_tx_buf[4],
                                     nfc_tx_buf[5], nfc_tx_buf[6], nfc_tx_buf[7], nfc_tx_buf[8]);
                            uint8_t mac_r_verify[4] = {0};
                            opt_doReaderMAC_2(*cipher_state, nfc_tx_buf + 1, mac_r_verify, diversified_key);
                            Dbprintf("Emulate: KD reader verify: calc=%02x%02x%02x%02x sam=%02x%02x%02x%02x %s",
                                     mac_r_verify[0], mac_r_verify[1], mac_r_verify[2], mac_r_verify[3],
                                     nfc_tx_buf[5], nfc_tx_buf[6], nfc_tx_buf[7], nfc_tx_buf[8],
                                     (memcmp(mac_r_verify, nfc_tx_buf + 5, 4) == 0) ? "(KD OK)" : "(KD MISMATCH)");
                        }
                        opt_doTagMAC_2(*cipher_state, nfc_tx_buf + 1, mac, diversified_key);
                        if (g_dbglevel >= DBG_DEBUG) {
                            Dbprintf("Emulate: TAG  MAC=%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3]);
                        }
                        memcpy(nfc_rx_buf, mac, 4);
                        nfc_rx_len = 4;  // iClass CHECK response: 4 bytes MAC, no CRC
                        break;
                    }
                    case ICLASS_CMD_READ_OR_IDENTIFY: {
                        // Key blocks 3 and 4 always return 0xFF
                        if (block == 3 || block == 4) {
                            memset(nfc_rx_buf, 0xFF, 8);
                        } else {
                            memcpy(nfc_rx_buf, emulator + (block * 8), 8);
                        }
                        AddCrc(nfc_rx_buf, 8);
                        nfc_rx_len = 10;
                        break;
                    }
                    case ICLASS_CMD_READ4: {
                        // Read 4 consecutive blocks (32 bytes + CRC)
                        memcpy(nfc_rx_buf, emulator + (block * 8), 32);
                        AddCrc(nfc_rx_buf, 32);
                        nfc_rx_len = 34;
                        break;
                    }
                    case ICLASS_CMD_UPDATE: {
                        // Acknowledge write: echo back data field + CRC
                        memcpy(nfc_rx_buf, nfc_tx_buf + 2, 8);
                        AddCrc(nfc_rx_buf, 8);
                        nfc_rx_len = 10;
                        break;
                    }
                    case ICLASS_CMD_PAGESEL: {
                        // Respond with config block of the selected page
                        memcpy(nfc_rx_buf, emulator + (1 * 8), 8);
                        AddCrc(nfc_rx_buf, 8);
                        nfc_rx_len = 10;
                        break;
                    }
                    default: {
                        if (g_dbglevel >= DBG_ERROR) {
                            Dbprintf("Emulate: unhandled NFC cmd %02x", nfc_tx_buf[0]);
                        }
                        res = PM3_ECARDEXCHANGE;
                        goto out;
                    }
                }

                if (g_dbglevel >= DBG_INFO) {
                    Dbprintf("Emulate: NFC resp [%u]: %02x %02x ...", nfc_rx_len,
                             nfc_rx_len > 0 ? nfc_rx_buf[0] : 0,
                             nfc_rx_len > 1 ? nfc_rx_buf[1] : 0);
                }
            }

            sam_tx_len = sam_copy_payload_nfc2sam(sam_tx_buf, nfc_rx_buf, nfc_rx_len);

            sam_send_payload(
                0x14, 0x0a, 0x14,
                sam_tx_buf, &sam_tx_len,
                sam_rx_buf, &sam_rx_len
            );

            if (g_dbglevel >= DBG_DEBUG) {
                Dbprintf("Emulate: SAM rx[1]=%02x rx[7]=%02x", sam_rx_buf[1], sam_rx_buf[7]);
            }

            if (sam_rx_buf[7] == 0x82) {
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

    if (g_dbglevel >= DBG_INFO) {
        DbpString("Emulate: final SAM response: ");
        Dbhexdump(sam_rx_len, sam_rx_buf, false);
    }

    if (request_len == 0) {
        if (!(sam_rx_buf[5] == 0xbd && sam_rx_buf[5 + 2] == 0x8a && sam_rx_buf[5 + 4] == 0x03) &&
                !(sam_rx_buf[5] == 0xbd && sam_rx_buf[5 + 2] == 0xb3 && sam_rx_buf[5 + 4] == 0xa0)) {

            if (g_dbglevel >= DBG_ERROR) {
                Dbprintf("No PACS data in SAM response");
            }
            if (g_dbglevel >= DBG_INFO) {
                Dbhexdump(sam_rx_len > 16 ? 16 : sam_rx_len, sam_rx_buf, false);
            }
            res = PM3_ESOFT;
        }
    }

    if (sam_rx_buf[6] == 0x81 && sam_rx_buf[8] == 0x8a && sam_rx_buf[9] == 0x81) {
        *response_len = sam_rx_buf[5 + 2] + 3;
    } else {
        *response_len = sam_rx_buf[5 + 1] + 2;
    }

    if (sam_rx_buf[5] == 0xBD && sam_rx_buf[4] != 0x00) {
        Dbprintf(_YELLOW_("Secure channel flag set to: ")"%02x", sam_rx_buf[4]);
    }

    memcpy(response, sam_rx_buf + 5, *response_len);

    goto out;

out:
    BigBuf_free();
    return res;
}


/**
 * @brief Sets the card detected status for the SAM (Secure Access Module).
 *
 * This function informs that a card has been detected by the reader and
 * initializes SAM communication with the card.
 *
 * @param card_select Pointer to the descriptor of the detected card.
 * @return Status code indicating success or failure of the operation.
 */
static int sam_set_card_detected_picopass(const picopass_hdr_t *card_select) {
    int res = PM3_SUCCESS;
    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("start sam_set_card_detected");
    }
    uint8_t *response = BigBuf_calloc(ISO7816_MAX_FRAME);
    uint16_t response_len = ISO7816_MAX_FRAME;

    // a0 12
    //    ad 10
    //       a0 0e
    //          80 02
    //             00 04 <- Picopass
    //          81 08
    //             9b fc a4 00 fb ff 12 e0  <- CSN

    uint8_t payload[] = {
        0xa0, 18, // <- SAM command
        0xad, 16, // <- set detected card
        0xa0, 4 + 10,
        0x80, 2, // <- protocol
        0x00, 0x04, // <- Picopass
        0x81, 8, // <- CSN
        card_select->csn[0], card_select->csn[1], card_select->csn[2], card_select->csn[3],
        card_select->csn[4], card_select->csn[5], card_select->csn[6], card_select->csn[7]
    };
    uint16_t payload_len = sizeof(payload);

    sam_send_payload(
        0x44, 0x0a, 0x44,
        payload,
        &payload_len,
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
    // Use BigBuf_free_keep_EM() so the emulator memory is preserved for emulate-from-file mode.
    // sam_send_request_iso15 / sam_send_request_emulated will allocate below the EM area.
    BigBuf_free_keep_EM();

    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("end sam_set_card_detected");
    }
    return res;
}


/**
 * @brief Retrieves PACS data from PICOPASS card using SAM.
 *
 * This function is called by appmain.c
 * It sends a request to the SAM to get the PACS data from the PICOPASS card.
 * The PACS data is then returned to the PM3 client.
 *
 * @return Status code indicating success or failure of the operation.
 */
int sam_picopass_get_pacs(PacketCommandNG *c) {
    const uint8_t flags = c->data.asBytes[0];
    const bool disconnectAfter = !!(flags & BITMASK(0));
    const bool skipDetect = !!(flags & BITMASK(1));
    const bool breakOnNrMac = !!(flags & BITMASK(2));
    const bool preventEpurseUpdate = !!(flags & BITMASK(3));
    const bool shallow_mod = !!(flags & BITMASK(4));
    const bool info = !!(flags & BITMASK(5));
    const bool emulate_from_file = !!(flags & BITMASK(6));

    uint8_t *cmd = c->data.asBytes + 1;
    uint16_t cmd_len = c->length - 1;

    int res = PM3_EFAILED;
    uint8_t sam_response[ISO7816_MAX_FRAME] = { 0x00 };
    uint8_t sam_response_len = 0;

    clear_trace();
    I2C_Reset_EnterMainProgram();

    set_tracing(true);
    StartTicks();

    // step 1: ping SAM
    sam_get_version(info);

    if (info) {
        sam_get_serial_number();
        goto out;
    }

    if (emulate_from_file) {
        // Use dump data from emulator memory instead of a real card
        picopass_hdr_t card_a_info;
        uint8_t *em = BigBuf_get_EM_addr();
        memcpy(&card_a_info, em, sizeof(picopass_hdr_t));

        if (g_dbglevel >= DBG_INFO) {
            Dbprintf("Emulate: CSN %02x%02x%02x%02x%02x%02x%02x%02x",
                     card_a_info.csn[0], card_a_info.csn[1],
                     card_a_info.csn[2], card_a_info.csn[3],
                     card_a_info.csn[4], card_a_info.csn[5],
                     card_a_info.csn[6], card_a_info.csn[7]);
        }

        // step 2: SamCommand CardDetected using CSN from dump
        sam_set_card_detected_picopass(&card_a_info);

        // step 3: SamCommand RequestPACS, emulate NFC communication from dump
        res = sam_send_request_emulated(cmd, cmd_len, sam_response, &sam_response_len, breakOnNrMac, preventEpurseUpdate);
    } else {
        if (skipDetect == false) {
            // step 2: get card information
            picopass_hdr_t card_a_info;
            uint32_t eof_time = 0;

            // implicit StartSspClk() happens here
            Iso15693InitReader();
            if (select_iclass_tag(&card_a_info, false, &eof_time, shallow_mod) == false) {
                goto err;
            }

            switch_clock_to_ticks();

            // step 3: SamCommand CardDetected
            sam_set_card_detected_picopass(&card_a_info);
        }

        // step 3: SamCommand RequestPACS, relay NFC communication
        res = sam_send_request_iso15(cmd, cmd_len, sam_response, &sam_response_len, shallow_mod, breakOnNrMac, preventEpurseUpdate);
    }
    if (res != PM3_SUCCESS) {
        goto err;
    }

    if (g_dbglevel >= DBG_INFO) {
        print_result("Response data", sam_response, sam_response_len);
    }

    goto out;

err:
    res = PM3_ENOPACS;
    reply_ng(CMD_HF_SAM_PICOPASS, res, NULL, 0);
    goto off;

out:
    reply_ng(CMD_HF_SAM_PICOPASS, PM3_SUCCESS, sam_response, sam_response_len);

off:
    if (disconnectAfter) {
        switch_off();
    }
    set_tracing(false);
    StopTicks();
    BigBuf_free();
    return res;
}
