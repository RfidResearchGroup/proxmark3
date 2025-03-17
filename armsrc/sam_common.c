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
//-----------------------------------------------------------------------------


#include <string.h>
#include "sam_common.h"
#include "iclass.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "commonutil.h"
#include "ticks.h"
#include "dbprint.h"
#include "i2c.h"
#include "iso15693.h"
#include "protocols.h"


/**
 * @brief Transmits data to and receives data from a HID®'s iCLASS® SE™ Processor.
 *
 * This function sends a specified number of bytes to the SAM and receives a response.
 *
 * @param data Pointer to the data to be transmitted.
 * @param n Number of bytes to be transmitted.
 * @param resp Pointer to the buffer where the response will be stored.
 * @param resplen Pointer to the variable where the length of the response will be stored.
 * @return Status code indicating success or failure of the operation.
 */
int sam_rxtx(const uint8_t *data, uint16_t n, uint8_t *resp, uint16_t *resplen) {
    bool res = I2C_BufferWrite(data, n, I2C_DEVICE_CMD_SEND_T0, I2C_DEVICE_ADDRESS_MAIN);
    if (res == false) {
        DbpString("failed to send to SIM CARD");
        goto out;
    }

    *resplen = ISO7816_MAX_FRAME;

    res = sc_rx_bytes(resp, resplen, SIM_WAIT_DELAY);
    if (res == false) {
        DbpString("failed to receive from SIM CARD");
        goto out;
    }

    if (*resplen < 2) {
        DbpString("received too few bytes from SIM CARD");
        res = false;
        goto out;
    }

    uint16_t more_len = 0;

    if (resp[*resplen - 2] == 0x61 || resp[*resplen - 2] == 0x9F) {
        more_len = resp[*resplen - 1];
    } else {
        // we done, return
        goto out;
    }

    // Don't discard data we already received except the SW code.
    // If we only received 1 byte, this is the echo of INS, we discard it.
    *resplen -= 2;
    if (*resplen == 1) {
        *resplen = 0;
    }

    uint8_t cmd_getresp[] = {0x00, ISO7816_GET_RESPONSE, 0x00, 0x00, more_len};

    res = I2C_BufferWrite(cmd_getresp, sizeof(cmd_getresp), I2C_DEVICE_CMD_SEND_T0, I2C_DEVICE_ADDRESS_MAIN);
    if (res == false) {
        DbpString("failed to send to SIM CARD 2");
        goto out;
    }

    more_len = 255 - *resplen;

    res = sc_rx_bytes(resp + *resplen, &more_len, SIM_WAIT_DELAY);
    if (res == false) {
        DbpString("failed to receive from SIM CARD 2");
        goto out;
    }

    *resplen += more_len;

out:
    return res;
}


static inline void swap_clock_counters(volatile unsigned int *a, unsigned int *b) {
    unsigned int c = *a;
    *a = *b;
    *b = c;
}

/**
 * @brief Swaps the timer counter values.
 *
 * AT91SAM7S512 has a single Timer-Counter, that is reused in clocks Ticks
 * and CountSspClk. This function stops the current clock and restores previous
 * values. It is used to switch between different clock sources.
 * It probably makes communication timing off, but at least makes it work.
 */
static void swap_clocks(void) {
    static unsigned int tc0, tc1, tc2 = 0;
    StopTicks();
    swap_clock_counters(&(AT91C_BASE_TC0->TC_CV), &tc0);
    swap_clock_counters(&(AT91C_BASE_TC1->TC_CV), &tc1);
    swap_clock_counters(&(AT91C_BASE_TC2->TC_CV), &tc2);
}

void switch_clock_to_ticks(void) {
    swap_clocks();
    StartTicks();
}

void switch_clock_to_countsspclk(void) {
    swap_clocks();
    StartCountSspClk();
}


/**
 * @brief Sends a payload to the SAM
 *
 * This function prepends the payload with the necessary APDU and application
 * headers and sends it to the SAM.
 *
 * @param addr_src 0x14 for command from NFC, 0x44 for command from application
 * @param addr_dest 0x0A for command to SAM
 * @param addr_reply same as add_src or 0x00 if no reply is expected
 * @param payload Pointer to the data to be sent.
 * @param payload_len Length of the data to be sent.
 * @param response Pointer to the buffer where the response will be stored.
 * @param response_len Pointer to the variable where the length of the response will be stored.
 * @param length Length of the data to be sent.
 * @return Status code indicating success or failure of the operation.
 */
int sam_send_payload(
    const uint8_t addr_src,
    const uint8_t addr_dest,
    const uint8_t addr_reply,

    const uint8_t *const payload,
    const uint16_t *payload_len,

    uint8_t *response,
    uint16_t *response_len
) {
    int res = PM3_SUCCESS;

    uint8_t *buf = response;

    buf[0] = 0xA0; // CLA
    buf[1] = 0xDA; // INS (PUT DATA)
    buf[2] = 0x02; // P1 (TLV format?)
    buf[3] = 0x63; // P2
    buf[4] = SAM_TX_ASN1_PREFIX_LENGTH + (uint8_t) * payload_len; // LEN

    buf[5] = addr_src;
    buf[6] = addr_dest;
    buf[7] = addr_reply;

    buf[8] = 0x00;
    buf[9] = 0x00;
    buf[10] = 0x00;

    memcpy(
        &buf[11],
        payload,
        *payload_len
    );

    uint16_t length = SAM_TX_ASN1_PREFIX_LENGTH + SAM_TX_APDU_PREFIX_LENGTH + (uint8_t) * payload_len;

    LogTrace(buf, length, 0, 0, NULL, true);
    if (g_dbglevel >= DBG_INFO) {
        DbpString("SAM REQUEST APDU: ");
        Dbhexdump(length, buf, false);
    }

    if (sam_rxtx(buf, length, response, response_len) == false) {
        if (g_dbglevel >= DBG_ERROR)
            DbpString("SAM ERROR");
        res = PM3_ECARDEXCHANGE;
        goto out;
    }

    LogTrace(response, *response_len, 0, 0, NULL, false);
    if (g_dbglevel >= DBG_INFO) {
        DbpString("SAM RESPONSE APDU: ");
        Dbhexdump(*response_len, response, false);
    }

out:
    return res;
}


/**
 * @brief Retreives SAM firmware version.
 *
 * Used just as ping or sanity check here.
 *
 * @return Status code indicating success or failure of the operation.
 */
int sam_get_version(void) {
    int res = PM3_SUCCESS;

    if (g_dbglevel >= DBG_DEBUG)
        DbpString("start sam_get_version");

    uint8_t   *response =  BigBuf_malloc(ISO7816_MAX_FRAME);
    uint16_t response_len = ISO7816_MAX_FRAME;

    uint8_t payload[] = {
        0xa0, 0x02, // <- SAM command
        0x82, 0x00 // <- get version
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
    //    bd 11 <- SAM response
    //     8a 0f <- get version response
    //      80 02
    //       01 29 <- version
    //      81 06
    //       68 3d 05 20 26 b6 <- build ID
    //      82 01
    //       01
    // 90 00
    if (g_dbglevel >= DBG_DEBUG)
        DbpString("end sam_get_version");

    if (response[5] != 0xbd) {
        Dbprintf("Invalid SAM response");
        goto error;
    } else {
        uint8_t *sam_response_an = sam_find_asn1_node(response + 5, 0x8a);
        if (sam_response_an == NULL) {
            if (g_dbglevel >= DBG_ERROR)
                DbpString("SAM get response failed");
            goto error;
        }
        uint8_t *sam_version_an = sam_find_asn1_node(sam_response_an, 0x80);
        if (sam_version_an == NULL) {
            if (g_dbglevel >= DBG_ERROR)
                DbpString("SAM get version failed");
            goto error;
        }
        uint8_t *sam_build_an = sam_find_asn1_node(sam_response_an, 0x81);
        if (sam_build_an == NULL) {
            if (g_dbglevel >= DBG_ERROR)
                DbpString("SAM get firmware ID failed");
            goto error;
        }
        if (g_dbglevel >= DBG_INFO) {
            DbpString("SAM get version successful");
            Dbprintf("Firmware version: %X.%X", sam_version_an[2], sam_version_an[3]);
            Dbprintf("Firmware ID: ");
            Dbhexdump(sam_build_an[1], sam_build_an + 2, false);
        }
        goto out;
    }

error:
    res = PM3_ESOFT;

out:
    BigBuf_free();

    if (g_dbglevel >= DBG_DEBUG)
        DbpString("end sam_get_version");

    return res;
}



/**
 * @brief Finds an ASN.1 node of a specified type within a given root node.
 *
 * This function searches through a single level of  the ASN.1 structure starting
 * from the root node to find a node of the specified type.
 *
 * @param root Pointer to the root node of the ASN.1 structure.
 * @param type The type of the ASN.1 node to find.
 * @return Pointer to the ASN.1 node of the specified type if found, otherwise NULL.
 */
uint8_t *sam_find_asn1_node(const uint8_t *root, const uint8_t type) {
    const uint8_t *end = (uint8_t *) root + *(root + 1);
    uint8_t *current = (uint8_t *) root + 2;
    while (current < end) {
        if (*current == type) {
            return current;
        } else {
            current += 2 + *(current + 1);
        }
    }
    return NULL;
}

/**
 * @brief Appends an ASN.1 node to the end of a given node.
 *
 * This function appends an ASN.1 node of a specified type and length to the end of
 * the ASN.1 structure at specified node level.
 *
 * It is the most naive solution that does not handle the case where the node to append is
 * not the last node at the same level. It also does not also care about proper
 * order of the nodes.
 *
 * @param root Pointer to the root node of the ASN.1 structure.
 * @param root Pointer to the node to be appended of the ASN.1 structure.
 * @param type The type of the ASN.1 node to append.
 * @param data Pointer to the data to be appended.
 * @param len The length of the data to be appended.
 */
void sam_append_asn1_node(const uint8_t *root, const uint8_t *node, uint8_t type, const uint8_t *const data, uint8_t len) {
    uint8_t *end = (uint8_t *) root + *(root + 1) + 2;

    *(end) = type;
    *(end + 1) = len;
    memcpy(end + 2, data, len);

    for (uint8_t *current = (uint8_t *) root; current <= node; current += 2) {
        *(current + 1) += 2 + len;
    };
    return;
}

void sam_send_ack(void) {
    uint8_t   *response = BigBuf_malloc(ISO7816_MAX_FRAME);
    uint16_t response_len = ISO7816_MAX_FRAME;

    uint8_t payload[] = {
        0xa0, 0
    };
    uint16_t payload_len = sizeof(payload);

    sam_send_payload(
        0x44, 0x0a, 0x00,
        payload,
        &payload_len,
        response,
        &response_len
    );

    BigBuf_free();
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
uint16_t sam_copy_payload_nfc2sam(uint8_t *sam_tx, uint8_t *nfc_rx, uint8_t nfc_len) {
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

    const uint8_t payload[] = {
        0xbd, 4,
        0xa0, 2,
        0xa0, 0
    };

    const uint8_t tag81[] = {
        0x00, 0x00
    };

    memcpy(sam_tx, payload, sizeof(payload));

    sam_append_asn1_node(sam_tx, sam_tx + 4, 0x80, nfc_rx, nfc_len);
    sam_append_asn1_node(sam_tx, sam_tx + 4, 0x81, tag81, sizeof(tag81));

    return sam_tx[1] + 2; // length of the ASN1 tree
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
uint16_t sam_copy_payload_sam2nfc(uint8_t *nfc_tx_buf, uint8_t *sam_rx_buf) {
    // SAM resp:
    // c1 61 c1 00 00
    //  a1 10 <- nfc command
    //    a1 0e <- nfc send
    //       80 10 <- data
    //          00 a4 04 00 0a a0 00 00 04 40 00 01 01 00 01 00
    //       81 02 <- protocol
    //          00 04
    //       82 02 <- timeout
    //          01 F4
    //  90 00

    // NFC req:
    // 0C  05  DE  64

    // copy data out of c1->a1>->a1->80 node
    uint16_t nfc_tx_len = (uint8_t) * (sam_rx_buf + 10);
    memcpy(nfc_tx_buf, sam_rx_buf + 11, nfc_tx_len);
    return nfc_tx_len;
}
