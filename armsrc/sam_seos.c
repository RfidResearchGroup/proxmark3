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
static int sam_set_card_detected(iso14a_card_select_t * card_select){
    int res = PM3_SUCCESS;
    if (g_dbglevel >= DBG_DEBUG)
        DbpString("start sam_set_card_detected");

    if(card_select ->uidlen != 4)
        return PM3_EFAILED;

    uint8_t  * response = BigBuf_malloc(ISO7816_MAX_FRAME);
    uint16_t response_len = ISO7816_MAX_FRAME;

    uint8_t payload[] = {
        0xa0, (2+(2+(4*2 +2+4+2+1))), // <- SAM command
         0xad, (2+(4*2 +2+4+2+1)), // <- set detected card
          0xa0, (4*2 +2+4+2+1),
           0x80, 2, // <- protocol
            0x00, 0x02, // <- ISO14443A
           0x81, card_select->uidlen, // <- CSN
            card_select->uid[0], card_select->uid[1], card_select->uid[2], card_select->uid[3],
           0x82, 2, // <- ATQA
            card_select->atqa[0], card_select->atqa[1],
           0x83, 1, // <- SAK 
            card_select->sak
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
    
    if(response[5] != 0xbd){
        if (g_dbglevel >= DBG_ERROR)
            Dbprintf("Invalid SAM response");
        goto error;
    }else{
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
 * @brief Copies the payload from an NFC buffer to a SAM buffer.
 *
 * Wraps received data from NFC into an ASN1 tree, so it can be transmitted to the SAM .
 *
 * @param sam_tx Pointer to the SAM transmit buffer.
 * @param nfc_rx Pointer to the NFC receive buffer.
 * @param nfc_len Length of the data to be copied from the NFC buffer.
 *
 * @return Length of SAM APDU to be sent.
 */
inline static uint16_t sam_seos_copy_payload_nfc2sam(uint8_t *sam_tx, uint8_t * nfc_rx, uint8_t nfc_len){
    // NFC resp:
    // 6f 0c 84 0a a0 00 00 04 40 00 01 01 00 01 90 00 fb e3

    // SAM req:
    // bd 1c
    //    a0 1a
    //       a0 18
    //          80 12
    //             6f 0c 84 0a a0 00 00 04 40 00 01 01 00 01 90 00 fb e3
    //          81 02
    //             00 00

    sam_tx[0] = 0xBD;

    sam_tx[2] = 0xA0;

    sam_tx[4] = 0xA0;

    sam_tx[6] = 0x80;
    sam_tx[7] = nfc_len;
    memcpy(sam_tx+8, nfc_rx, nfc_len);

    sam_tx[8+nfc_len] = 0x81;
    sam_tx[9+nfc_len] = 0x02;
    sam_tx[10+nfc_len] = 0x00;
    sam_tx[11+nfc_len] = 0x00;

    // fix lengths
    sam_tx[5] = 2 + nfc_len + 4;
    sam_tx[3] = sam_tx[5] + 2;
    sam_tx[1] = sam_tx[3] + 2;
    return sam_tx[1] + 2;
}

/**
 * @brief Copies the payload from the SAM receive buffer to the NFC transmit buffer.
 *
 * Unpacks data to be transmitted from ASN1 tree in APDU received from SAM.
 *
 * @param nfc_tx_buf Pointer to the buffer where the NFC transmit data will be stored.
 * @param sam_rx_buf Pointer to the buffer containing the data received from the SAM.
 * @return Length of NFC APDU to be sent.
 */
inline static uint16_t sam_seos_copy_payload_sam2nfc(uint8_t * nfc_tx_buf, uint8_t * sam_rx_buf){
    // SAM resp:
    // c1 61 c1 00 00
    //  a1 21 <- nfc command
    //    a1 1f <- nfc send
    //       80 10 <- data
    //          00 a4 04 00 0a a0 00 00 04 40 00 01 01 00 01 00
    //       81 02 <- protocol
    //          02 02
    //       82 02 <- timeout
    //          01 2e
    //       85 03 <- format
    //          06 c0 00
    //  90 00

    // NFC req:
    // 00 a4 04 00 0a a0 00 00 04 40 00 01 01 00 01 00

    // copy data out of c1->a1>->a1->80 node
    uint16_t nfc_tx_len = (uint8_t) *(sam_rx_buf + 10);
    memcpy(nfc_tx_buf, sam_rx_buf+11, nfc_tx_len);
    return nfc_tx_len;
}

/**
 * @brief Copies the payload from the SAM receive buffer to the NFC transmit buffer.
 *
 * Unpacks data to be transmitted from ASN1 tree in APDU received from SAM.
 *
 * @param pacs Pointer to the buffer where the decoded PACS data will be stored.
 * @param pacs_len Pointer to the variable where the length of the PACS data will be stored.
 * @return Status code indicating success or failure of the operation.
 */
static int sam_request_pacs(uint8_t * pacs, uint8_t * pacs_len){
    int res = PM3_SUCCESS;
    if (g_dbglevel >= DBG_DEBUG)
        DbpString("start sam_request_pacs");

    uint8_t buf1[ISO7816_MAX_FRAME] = {0};
    uint8_t buf2[ISO7816_MAX_FRAME] = {0};

    uint8_t * sam_tx_buf = buf1;
    uint16_t sam_tx_len;

    uint8_t * sam_rx_buf = buf2;
    uint16_t sam_rx_len;

    uint8_t * nfc_tx_buf = buf1;
    uint16_t nfc_tx_len;

    uint8_t * nfc_rx_buf = buf2;
    uint16_t nfc_rx_len;

    // send get pacs
    static const uint8_t payload[] = {
        0xa0, 5, // <- SAM command
         0xa1, 3, // <- get PACS
          0x80, 1,
           0x04
    };
    sam_tx_len = sizeof(payload);
    memcpy(sam_tx_buf, payload, sam_tx_len);

    sam_send_payload(
        0x44, 0x0a, 0x44,
        sam_tx_buf, &sam_tx_len,
        sam_rx_buf, &sam_rx_len
    );

    // tag <-> SAM exchange starts here
    for(int i = 0; i < 20; i++){
        switch_clock_to_countsspclk();
        nfc_tx_len = sam_seos_copy_payload_sam2nfc(nfc_tx_buf, sam_rx_buf);

        nfc_rx_len = iso14_apdu(
            nfc_tx_buf,
            nfc_tx_len,
            false,
            nfc_rx_buf,
            ISO7816_MAX_FRAME,
            NULL
        );

        switch_clock_to_ticks();
        sam_tx_len = sam_seos_copy_payload_nfc2sam(sam_tx_buf, nfc_rx_buf, nfc_rx_len-2);

        sam_send_payload(
            0x14, 0x0a, 0x14,
            sam_tx_buf, &sam_tx_len,
            sam_rx_buf, &sam_rx_len
        );

        // last SAM->TAG 
        // c1 61 c1 00 00 a1 02 >>82<< 00 90 00
        if(sam_rx_buf[7] == 0x82){
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

    // resp:
    // c1 64 00 00 00
    // bd 09
    //    8a 07
    //        03 05 <- include tag for pm3 client
    //           06 85 80 6d c0 <- decoded PACS data
    // 90 00
    if(sam_rx_buf[5+2] != 0x8a && sam_rx_buf[5+4] != 0x03){
        if (g_dbglevel >= DBG_ERROR)
            Dbprintf("Invalid SAM response");
        goto err;
    }
    *pacs_len = sam_rx_buf[5+5] +2;
    memcpy(pacs, sam_rx_buf+5+4, *pacs_len);
    res=PM3_SUCCESS;

    goto out;

    err:
        res=PM3_ESOFT;
    out:
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
int sam_seos_get_pacs(void){
    int res = PM3_EFAILED;

    clear_trace();
    I2C_Reset_EnterMainProgram();

    set_tracing(true);
    StartTicks();

    // step 1: ping SAM
    sam_get_version();

    // step 2: get card information
    iso14a_card_select_t card_a_info;

    // implicit StartSspClk() happens here
    iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
    if (!iso14443a_select_card(NULL, &card_a_info, NULL, true, 0, false)){
        goto err;
    }

    switch_clock_to_ticks();

    // step 3: SamCommand CardDetected
    sam_set_card_detected(&card_a_info);

    // step 3: SamCommand RequestPACS, relay NFC communication

    uint8_t pacs[10] = { 0x00 };
    uint8_t pacs_len = 0;
    res = sam_request_pacs(pacs, &pacs_len);
    if(res != PM3_SUCCESS){
        goto err;
    }
    if (g_dbglevel >= DBG_INFO)
        print_result("PACS data", pacs, pacs_len);

    sam_send_ack();

    goto out;
    goto off;

    err:
        res = PM3_ENOPACS;
        reply_ng(CMD_HF_SAM_SEOS, res, NULL, 0);
        goto off;
    out:
        reply_ng(CMD_HF_SAM_SEOS, PM3_SUCCESS, pacs, pacs_len);
        goto off;
    off:
        switch_off();
        set_tracing(false);
        StopTicks();
        BigBuf_free();
        return res;
}