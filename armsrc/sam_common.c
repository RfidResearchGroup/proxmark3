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
#include "util.h"          // switch_clock_to_ticks / _countsspclk
#include "iclass.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "commonutil.h"
#include "ticks_apis.h"
#include "dbprint.h"
#include "i2c.h"
#include "iso15693.h"
#include "protocols.h"
#include "crc16.h"
#include "cmd.h"


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
/*
 * Offset of the 0xBD response node inside a SAM reply.
 *
 * Ahead of it sits a routing tail that is either 5 or 6 bytes long: the request
 * header we build is always 6 (FROM, TO, REPLY-TO, 0x00, 0x00, scFlag), and
 * some SAMs mirror all of it while others drop a byte.  A HID iCLASS SE "Grace"
 * part answers
 *
 *     0a 44 00 00 00 00 | bd 11 8a 0f 80 02 01 29 ...
 *
 * where SAM_RX_ASN1_PREFIX_LENGTH on its own lands one byte short and every
 * caller then rejects a perfectly good response.
 *
 * Only those two offsets are ever considered, deliberately: 0xBD occurs inside
 * SAM payloads as well, so an open ended search would eventually latch onto the
 * wrong one.  Returns 0 when neither holds it, which is never a valid offset.
 */
uint16_t sam_bd_offset(const uint8_t *response, uint16_t response_len) {

    uint16_t fallback = 0;

    for (uint16_t ofs = SAM_RX_ASN1_PREFIX_LENGTH;
            ofs <= (uint16_t)(SAM_RX_ASN1_PREFIX_LENGTH + 1);
            ofs++) {

        if ((uint16_t)(ofs + 1) >= response_len) {
            break;
        }
        if (response[ofs] != 0xBD) {
            continue;
        }

        // A 0xBD in the right place accounts for the rest of the frame exactly:
        // tag, length byte, that many bytes of contents, then SW1 SW2.  This is
        // what tells a real response node apart from a 0xBD that happens to sit
        // in the routing tail - without it a SAM whose scFlag were 0xBD would
        // resolve to the wrong offset.
        // Length is short form, or long form with one length byte (0x81 <len>),
        // which is what an SNMP shaped reply over 127 bytes uses.
        uint16_t hdr = 2;
        uint16_t node_len = response[ofs + 1];
        if (node_len == 0x81) {
            if ((uint16_t)(ofs + 2) >= response_len) {
                continue;
            }
            hdr = 3;
            node_len = response[ofs + 2];
        }

        if ((uint16_t)(ofs + hdr + node_len + 2) == response_len) {
            return ofs;
        }
        if (fallback == 0) {
            fallback = ofs;
        }
    }

    // Nothing accounted for the whole frame; hand back a plain 0xBD match if
    // there was one, so a caller that only wants the tag still works.
    return fallback;
}

/*
 * Locate the SAM's response node and work out how many bytes from there make up
 * the reply to forward.
 *
 * This arithmetic used to be written out three times - twice in sam_picopass.c,
 * once in sam_seos.c - each with a hardcoded 5 byte routing tail and no bounds
 * checks at all, so a short or truncated frame walked off the end of the
 * buffer.  One copy, one place to be wrong.
 *
 * Returns the offset of the response node.  *payload_len gets the length from
 * that offset, clamped to what actually arrived, or 0 if the frame is too short
 * to hold anything.
 */
// How many bytes of routing tail this SAM puts in front of the ASN.1 payload.
// A Grace SAM uses 6 where SAM_RX_ASN1_PREFIX_LENGTH says 5, so pick the one
// whose node length accounts for the frame exactly: tag, length, contents,
// SW1 SW2.
uint16_t sam_rx_prefix_len(const uint8_t *rx, uint16_t rx_len) {

    uint16_t fallback = 0;

    for (uint16_t ofs = SAM_RX_ASN1_PREFIX_LENGTH;
            ofs <= (uint16_t)(SAM_RX_ASN1_PREFIX_LENGTH + 1);
            ofs++) {

        if ((uint16_t)(ofs + 1) >= rx_len) {
            break;
        }
        if ((rx[ofs] != 0xa1) && (rx[ofs] != 0xbd)) {
            continue;
        }
        if ((uint16_t)(ofs + 2 + rx[ofs + 1] + 2) == rx_len) {
            return ofs;
        }
        if (fallback == 0) {
            fallback = ofs;
        }
    }

    return (fallback != 0) ? fallback : (uint16_t)SAM_RX_ASN1_PREFIX_LENGTH;
}

// The SAM asks for a card exchange with an a1 node holding an 80 <len> APDU.
// Older SAMs flagged it with 0x61 in the routing tail, which is where the
// fixed sam_rx_buf[1] test came from - a Grace SAM puts 0x14 there instead, so
// key off the ASN.1 node, which both generations agree on.
bool sam_relay_pending(const uint8_t *rx, uint16_t rx_len) {

    uint16_t p = sam_rx_prefix_len(rx, rx_len);
    if ((uint16_t)(p + 4) >= rx_len) {
        return false;
    }
    return ((rx[p] == 0xa1) && (rx[p + 2] == 0xa1) && (rx[p + 4] == 0x80));
}

// The tag <-> SAM relay ends on an a1 02 82 00 node. The routing tail is 5 or
// 6 bytes depending on the SAM - the same reason sam_bd_offset() searches - so
// anchor on the node rather than indexing a fixed offset 7.
bool sam_relay_complete(const uint8_t *rx, uint16_t rx_len) {

    uint16_t ofs = sam_rx_prefix_len(rx, rx_len);
    if ((uint16_t)(ofs + 2) >= rx_len) {
        return false;
    }
    return ((rx[ofs] == 0xa1) && (rx[ofs + 2] == 0x82));
}

uint16_t sam_response_payload(const uint8_t *rx, uint16_t rx_len, uint16_t *payload_len) {

    uint16_t ofs = sam_bd_offset(rx, rx_len);
    if (ofs == 0) {
        ofs = SAM_RX_ASN1_PREFIX_LENGTH;
    }

    *payload_len = 0;

    // An SNMP shaped reply over 127 bytes carries a long form length,
    // bd 81 <len>. Read it from the length byte itself rather than matching one
    // known inner tag, or any other node in that form parses as 0x81 + 2.
    if (((uint16_t)(ofs + 2) < rx_len) && (rx[ofs + 1] == 0x81)) {

        *payload_len = (uint16_t)(rx[ofs + 2] + 3);

    } else if ((uint16_t)(ofs + 1) < rx_len) {

        *payload_len = (uint16_t)(rx[ofs + 1] + 2);
    }

    // never hand back more than arrived
    if ((uint16_t)(ofs + *payload_len) > rx_len) {
        *payload_len = (rx_len > ofs) ? (uint16_t)(rx_len - ofs) : 0;
    }

    return ofs;
}

int sam_rxtx(const uint8_t *data, uint16_t n, uint8_t *resp, uint16_t *resplen) {
    // Whatever protocol GetATR()/PPS left the card on, rather than an assumed
    // T=0. Resolved once per exchange so the GET RESPONSE round below cannot
    // end up on a different protocol than the command it belongs to.
    const uint8_t active_cmd = sc_active_device_cmd();
    const bool t1 = (active_cmd == I2C_DEVICE_CMD_SEND_T1);
    // Use the v4.65+ compatibility T=0 opcode when available. Grace responses
    // still assemble their 61xx/9Fxx continuations below on the PM3: they may
    // carry material response data before the continuation status. T=1 already
    // returns its whole APDU response through the module's block layer.
#if SAM_T0_AUTORESP
    const uint8_t dev_cmd = (active_cmd == I2C_DEVICE_CMD_SEND_T0)
                            ? I2C_DEVICE_CMD_SEND_T0_AUTORESP
                            : active_cmd;
#else
    const uint8_t dev_cmd = active_cmd;
#endif

    uint32_t tx_start = GetTicks();
    bool res = I2C_BufferWrite(data, n, dev_cmd, I2C_DEVICE_ADDRESS_MAIN);
    sc_log_trace_span(data, n, true, tx_start);

    if (res == false) {
        DbpString("failed to send to SIM CARD");
        goto out;
    }

    *resplen = ISO7816_MAX_FRAME;

    res = sc_rx_bytes(resp, resplen, SIM_WAIT_DELAY);

    if (res == false) {
        for (uint8_t attempt = 1; attempt <= 15; attempt++) {
            SpinDelay(200);
            *resplen = ISO7816_MAX_FRAME;
            res = sc_rx_bytes(resp, resplen, SIM_WAIT_DELAY);
            if (res) {
                if (g_dbglevel >= DBG_INFO)
                    Dbprintf("SAM slow first-reply recovered after %u re-poll(s)", attempt);
                break;
            }
        }
    }

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

        // The GET RESPONSE round below is ours, not the caller's, so log both
        // halves of it. Without this the trace shows a case 3 command coming
        // back with a full data answer, which T=0 cannot do.
        sc_log_trace(resp, *resplen, false);
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

    // Grace T=1 exchanges use extended APDUs.  The normal short T=0 GET
    // RESPONSE is invalid on that path, so use an extended Le when a T=1
    // response explicitly asks for more data.
    uint8_t cmd_getresp_t0[] = {0x00, ISO7816_GET_RESPONSE, 0x00, 0x00, more_len};
    uint16_t want = more_len ? more_len : 256;
    uint8_t cmd_getresp_t1[] = {0x00, ISO7816_GET_RESPONSE, 0x00, 0x00,
                                0x00, (uint8_t)(want >> 8), (uint8_t)want
                               };
    const uint8_t *cmd_getresp = t1 ? cmd_getresp_t1 : cmd_getresp_t0;
    const uint16_t cmd_getresp_len = t1 ? sizeof(cmd_getresp_t1) : sizeof(cmd_getresp_t0);

    tx_start = GetTicks();
    res = I2C_BufferWrite(cmd_getresp, cmd_getresp_len, active_cmd, I2C_DEVICE_ADDRESS_MAIN);
    sc_log_trace_span(cmd_getresp, cmd_getresp_len, true, tx_start);

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
    return sam_send_payload_ex(addr_src, addr_dest, addr_reply, 0x00,
                               payload, payload_len,
                               response, response_len);
}

int sam_send_payload_ex(
    const uint8_t addr_src,
    const uint8_t addr_dest,
    const uint8_t addr_reply,
    const uint8_t scFlag,

    const uint8_t *const payload,
    const uint16_t *payload_len,

    uint8_t *response,
    uint16_t *response_len
) {
    int res = PM3_SUCCESS;

    uint8_t *buf = response;
    const uint16_t inner_len = (uint16_t)(SAM_TX_ASN1_PREFIX_LENGTH + *payload_len);
    const bool t1 = (sc_active_device_cmd() == I2C_DEVICE_CMD_SEND_T1);
    uint16_t payload_offset = SAM_TX_APDU_PREFIX_LENGTH;

    if ((uint32_t)inner_len + (t1 ? 9u : 5u) > ISO7816_MAX_FRAME) {
        return PM3_EINVARG;
    }
    if (!t1 && inner_len > 0xff) {
        return PM3_EINVARG;
    }

    buf[0] = 0xA0; // CLA
    buf[1] = 0xDA; // INS (PUT DATA)
    buf[2] = 0x02; // P1 (TLV format?)
    buf[3] = 0x63; // P2
    if (t1) {
        // The Artemis T=1 service accepts Grace in extended APDU form.  This
        // matches the working ACR39U exchange: 00 <Lc-hi> <Lc-lo> ... 0000.
        buf[4] = 0x00;
        buf[5] = (uint8_t)(inner_len >> 8);
        buf[6] = (uint8_t)inner_len;
        payload_offset = 7;
    } else {
        buf[4] = (uint8_t)inner_len;
    }

    // Grace routing header: FROM, TO, REPLY-TO, 0x00, 0x00, scFlag
    buf[payload_offset] = addr_src;
    buf[payload_offset + 1] = addr_dest;
    buf[payload_offset + 2] = addr_reply;

    buf[payload_offset + 3] = 0x00;
    buf[payload_offset + 4] = 0x00;
    buf[payload_offset + 5] = scFlag;

    memcpy(
        &buf[payload_offset + SAM_TX_ASN1_PREFIX_LENGTH],
        payload,
        *payload_len
    );

    uint16_t length = (uint16_t)(payload_offset + inner_len);
    if (t1) {
        buf[length++] = 0x00; // extended Le = 65536 (maximum response)
        buf[length++] = 0x00;
    }

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

    sc_log_trace(response, *response_len, false);
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
int sam_get_version(bool info) {
    int res = PM3_SUCCESS;

    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("start sam_get_version");
    }

    uint8_t *response = BigBuf_calloc(ISO7816_MAX_FRAME);
    uint16_t response_len = ISO7816_MAX_FRAME;
    if (response == NULL) {
        res = PM3_EMALLOC;
        goto out;
    }

    uint8_t payload[] = {
        0xa0, // <- SAM command
        0x02, // <- Length
        0x82, 0x00 // <- get version
    };
    uint16_t payload_len = sizeof(payload);

    int exchange = sam_send_payload(
                       0x44, 0x0a, 0x44,
                       payload,
                       &payload_len,
                       response,
                       &response_len
                   );

    if (exchange != PM3_SUCCESS) {
        res = exchange;
        goto out;
    }

    // The Artemis T=1 endpoint accepts the extended GetVersion warmup with a
    // bare 9000 (unlike the T=0 endpoint, it does not return the version TLV).
    // It is only a link-settling ping here, so a successful status is enough;
    // the following InitAuth exchange performs the actual authentication.
    if ((sc_active_device_cmd() == I2C_DEVICE_CMD_SEND_T1) &&
            (response_len >= 2) &&
            (response[response_len - 2] == 0x90) &&
            (response[response_len - 1] == 0x00)) {
        goto out;
    }

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
    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("end sam_get_version");
    }

    uint16_t bd = sam_bd_offset(response, response_len);
    if (bd == 0) {
        Dbprintf("Invalid SAM response");
        goto error;
    } else {
        uint8_t *sam_response_an = sam_find_asn1_node(response + bd, 0x8a);
        if (sam_response_an == NULL) {
            if (g_dbglevel >= DBG_ERROR) DbpString("SAM get response failed");
            goto error;
        }
        uint8_t *sam_version_an = sam_find_asn1_node(sam_response_an, 0x80);
        if (sam_version_an == NULL) {
            if (g_dbglevel >= DBG_ERROR) DbpString(_RED_("SAM: get version failed"));
            goto error;
        }
        uint8_t *sam_build_an = sam_find_asn1_node(sam_response_an, 0x81);
        if (sam_build_an == NULL) {
            if (g_dbglevel >= DBG_ERROR) DbpString(_RED_("SAM: get firmware ID failed"));
            goto error;
        }
        if (g_dbglevel >= DBG_INFO || info) {
            DbpString(_BLUE_("-- SAM Information --"));
            Dbprintf(_YELLOW_("Firmware version: ")"%d.%d", sam_version_an[2], sam_version_an[3]);
            Dbprintf(_YELLOW_("Firmware ID: "));
            Dbhexdump(sam_build_an[1], sam_build_an + 2, false);
        }
        goto out;
    }

error:
    res = PM3_ESOFT;

out:
    BigBuf_free_keep_EM();

    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("end sam_get_version");
    }

    return res;
}

int sam_get_serial_number(void) {
    int res = PM3_SUCCESS;

    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("start sam_get_serial_number");
    }

    uint8_t *response = BigBuf_calloc(ISO7816_MAX_FRAME);
    uint16_t response_len = ISO7816_MAX_FRAME;
    if (response == NULL) {
        res = PM3_EMALLOC;
        goto out;
    }

    uint8_t payload[] = {
        0xa0, // <- SAM command
        0x02, // <- Length
        0x96, 0x00 // <- get serial number
    };
    uint16_t payload_len = sizeof(payload);

    sam_send_payload(
        0x44, 0x0a, 0x44,
        payload,
        &payload_len,
        response,
        &response_len
    );

    //resp:
    //c1 64 00 00 00
    //   bd 0e <- SAM response
    //    8a 0c <- get serial number response
    //      61 01 13 51 22 66 6e 15 3e 1b ff ff
    //90 00

    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("end sam_get_serial_number");
    }

    uint16_t bd = sam_bd_offset(response, response_len);
    if (bd == 0) {
        Dbprintf("Invalid SAM response");
        goto error;
    } else {
        uint8_t *sam_response_an = sam_find_asn1_node(response + bd, 0x8a);
        if (sam_response_an == NULL) {
            if (g_dbglevel >= DBG_ERROR) DbpString(_RED_("SAM: get response failed"));
            goto error;
        }
        uint8_t *sam_serial_an = sam_response_an + 2;

        Dbprintf(_YELLOW_("Serial Number: "));
        Dbhexdump(sam_response_an[1], sam_serial_an, false);

        goto out;
    }

error:
    res = PM3_ESOFT;

out:
    BigBuf_free_keep_EM();

    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("end sam_get_serial_number");
    }

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
    uint8_t *response = BigBuf_calloc(ISO7816_MAX_FRAME);
    uint16_t response_len = ISO7816_MAX_FRAME;
    if (response == NULL) {
        if (g_dbglevel >= DBG_ERROR) DbpString(_RED_("SAM: failed to allocate buffer"));
        BigBuf_free();
        return;
    }

    uint8_t payload[] = { 0xa0, 0 };
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
int sam_relay_iso15_loop(
    uint8_t *sam_tx_buf,
    uint8_t *sam_rx_buf,
    uint16_t *sam_rx_len,
    bool shallow_mod,
    bool break_on_nr_mac,
    bool prevent_epurse_update,
    uint8_t *nr_mac_out,
    uint16_t *nr_mac_len_out,
    bool *got_nr_mac
) {
    int res = PM3_SUCCESS;

    if (got_nr_mac != NULL) {
        *got_nr_mac = false;
    }

    // Nothing to relay - the SAM answered directly (final response already in
    // sam_rx_buf). This is the normal case for SAM-internal commands.
    if (sam_relay_pending(sam_rx_buf, *sam_rx_len) == false) {
        return PM3_SUCCESS;
    }

    // The two scratch buffers double as the NFC tx/rx buffers, exactly as
    // sam_send_request_iso15 does.
    uint8_t *nfc_tx_buf = sam_tx_buf;
    uint8_t *nfc_rx_buf = sam_rx_buf;
    uint16_t nfc_tx_len;
    uint16_t nfc_rx_len;
    uint16_t sam_tx_len;

    switch_clock_to_countsspclk();

    // tag <-> SAM exchange starts here
    while (sam_relay_pending(sam_rx_buf, *sam_rx_len)) {
        uint32_t start_time = GetCountSspClk();
        uint32_t eof_time = start_time + DELAY_ICLASS_VICC_TO_VCD_READER;

        nfc_tx_len = sam_copy_payload_sam2nfc(nfc_tx_buf, sam_rx_buf, *sam_rx_len);

        // PAGESEL (0x84) substitution for 2K PicoPass cards. A 2K card has a
        // single book/page and does not answer PAGESEL, but the encode-side SAM
        // emits it to select the page before writing. PAGESEL returns the page
        // config block (block 1), so we send a READ of block 1 instead: the 2K
        // card answers that, and the SAM gets the config it expects and moves on
        // to auth/write. (16K cards answer PAGESEL natively; substituting a
        // block-1 read for PAGESEL-page-0 is equivalent there too.)
        if (nfc_tx_len >= 2 && (nfc_tx_buf[0] & 0x0F) == ICLASS_CMD_PAGESEL) {
            if (g_dbglevel >= DBG_INFO) {
                DbpString("PAGESEL on 2K card - substituting READ block 1");
            }
            nfc_tx_buf[0] = ICLASS_CMD_READ_OR_IDENTIFY;   // 0x0C
            nfc_tx_buf[1] = 0x01;                          // block 1 = config
            // iCLASS command CRC covers the block byte only, not the opcode
            // (see iclass.c: read_conf = 0C 01 FA 22, AddCrc(c + 1, 1)).
            AddCrc(nfc_tx_buf + 1, 1);
            nfc_tx_len = 4;
        }

        bool is_cmd_check = ((nfc_tx_buf[0] & 0x0F) == ICLASS_CMD_CHECK);

        if (is_cmd_check && break_on_nr_mac) {
            if (nr_mac_out != NULL && nr_mac_len_out != NULL) {
                memcpy(nr_mac_out, nfc_tx_buf, nfc_tx_len);
                *nr_mac_len_out = nfc_tx_len;
            }
            if (got_nr_mac != NULL) {
                *got_nr_mac = true;
            }
            if (g_dbglevel >= DBG_INFO) {
                DbpString("NR-MAC: ");
                Dbhexdump(nfc_tx_len - 1, nfc_tx_buf + 1, false);
            }
            return PM3_SUCCESS;
        }

        bool is_cmd_update = ((nfc_tx_buf[0] & 0x0F) == ICLASS_CMD_UPDATE);

        if (is_cmd_update && prevent_epurse_update && nfc_tx_buf[0] == 0x87 && nfc_tx_buf[1] == 0x02) {
            // block update(2) command and fake the response to prevent update of epurse
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
                return PM3_ECARDEXCHANGE;
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
            sam_rx_buf, sam_rx_len
        );

        // last SAM->TAG
        // c1 61 c1 00 00 a1 02 >>82<< 00 90 00
        if (sam_relay_complete(sam_rx_buf, *sam_rx_len)) {
            // tag <-> SAM exchange ends here
            break;
        }

        switch_clock_to_countsspclk();
    }

    // The loop can exit two ways:
    //   (a) it broke on the a1 02 82 00 (TurnRfFieldOff) marker - which is
    //       itself a 0x61 frame, so sam_rx_buf[1] is still 0x61 here. The SAM is
    //       waiting for an ack; the SAM's reply to that ack is the final
    //       application response, left in sam_rx_buf. (PACS-read pattern.)
    //   (b) the while condition went false because the SAM already returned a
    //       non-0x61 final response (e.g. a Path B bd/b3 result to an
    //       interpreter command). That response is ALREADY in sam_rx_buf -
    //       sending the ack now would overwrite it with a bare 90 00.
    // So only ack in case (a).
    if (sam_relay_pending(sam_rx_buf, *sam_rx_len)) {
        static const uint8_t hfack[] = {
            0xbd, 0x04, 0xa0, 0x02, 0x82, 0x00
        };

        sam_tx_len = sizeof(hfack);
        memcpy(sam_tx_buf, hfack, sam_tx_len);

        sam_send_payload(
            0x14, 0x0a, 0x00,
            sam_tx_buf, &sam_tx_len,
            sam_rx_buf, sam_rx_len
        );
    }

    // When the loop exits on a non-0x61 final response, its last statement was
    // switch_clock_to_countsspclk() (end of the iteration, before the while
    // re-check) - so the clock is left in CountSspClk mode. Restore Ticks so the
    // caller's next SAM I2C exchange (e.g. the Terminate in scclose) has the
    // timer the SIM link needs for its receive timeout; otherwise it hangs.
    switch_clock_to_ticks();

    return PM3_SUCCESS;
}

uint16_t sam_copy_payload_sam2nfc(uint8_t *nfc_tx_buf, uint8_t *sam_rx_buf, uint16_t sam_rx_len) {
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

    // copy data out of the a1->a1->80 node, which sits after a routing tail
    // that is 5 bytes on some SAMs and 6 on others
    uint16_t p = sam_rx_prefix_len(sam_rx_buf, sam_rx_len);
    if ((uint16_t)(p + 5) >= sam_rx_len) {
        return 0;
    }

    uint16_t nfc_tx_len = sam_rx_buf[p + 5];
    if ((uint16_t)(p + 6 + nfc_tx_len) > sam_rx_len) {
        return 0;
    }

    memcpy(nfc_tx_buf, sam_rx_buf + p + 6, nfc_tx_len);
    return nfc_tx_len;
}

/**
 * @brief Sets the card detected status for the SAM (Secure Access Module).
 *
 * This function informs that a card has been detected by the reader and
 * initializes SAM communication with the card.
 *
 * @param card_select Pointer to the descriptor of the detected card.
 * @param with_atqa Include the ATQA node. Seader leaves it out for MIFARE Classic.
 * @return Status code indicating success or failure of the operation.
 */
int sam_set_card_detected_iso14a(const iso14a_card_select_t *card_select, bool with_atqa) {
    int res = PM3_SUCCESS;
    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("start sam_set_card_detected");
    }

    uint8_t *request = BigBuf_calloc(ISO7816_MAX_FRAME);
    uint16_t request_len = ISO7816_MAX_FRAME;

    uint8_t *response = BigBuf_calloc(ISO7816_MAX_FRAME);
    uint16_t response_len = ISO7816_MAX_FRAME;
    if (request == NULL || response == NULL) {
        res = PM3_EMALLOC;
        goto out;
    }

    const uint8_t payload[] = {
        0xa0, 8, // <- SAM command
        0xad, 6, // <- set detected card
        0xa0, 4, // <- detected card details
        0x80, 2, // <- protocol
        0x00, 0x02 // <- ISO14443A
    };

    memcpy(request, payload, sizeof(payload));
    sam_append_asn1_node(request, request + 4, 0x81, card_select->uid, card_select->uidlen);
    if (with_atqa) {
        sam_append_asn1_node(request, request + 4, 0x82, card_select->atqa, 2);
    }
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

    if (sam_bd_offset(response, response_len) == 0) {
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

    if (g_dbglevel >= DBG_DEBUG) {
        DbpString("end sam_set_card_detected");
    }
    return res;
}

// Plaintext seen on the air during a SAM conversation, for the extended reply.
#define SAM_CAP_FIRST_BLOCK 6
#define SAM_CAP_BLOCKS      (SAM_EXT_SIO_MAX / 8)

static struct {
    uint8_t uid[10];
    uint8_t uid_len;
    uint8_t data[SAM_EXT_SIO_MAX];
    uint16_t len;           // DESFire: bytes captured
    uint32_t block_map;     // iCLASS: bit n set when block 6 + n was captured
    bool desfire_more;      // DESFire: last read answered 91 AF
} sam_cap;

void sam_capture_reset(void) {
    memset(&sam_cap, 0, sizeof(sam_cap));
}

void sam_capture_uid(const uint8_t *uid, uint8_t uid_len) {
    sam_cap.uid_len = MIN(uid_len, sizeof(sam_cap.uid));
    memcpy(sam_cap.uid, uid, sam_cap.uid_len);
}

// iCLASS READ / READ4 answers from block 6 on. rx is the tag answer.
void sam_capture_iclass(const uint8_t *tx, uint16_t tx_len, const uint8_t *rx, uint16_t rx_len) {

    if (tx_len < 2) {
        return;
    }

    uint8_t blocks;
    if ((tx[0] & 0x0F) == ICLASS_CMD_READ_OR_IDENTIFY && rx_len >= 8) {
        blocks = 1;
    } else if ((tx[0] & 0x0F) == ICLASS_CMD_READ4 && rx_len >= 32) {
        blocks = 4;
    } else {
        return;
    }

    for (uint8_t i = 0; i < blocks; i++) {
        uint16_t blk = tx[1] + i;
        if (blk < SAM_CAP_FIRST_BLOCK || blk >= SAM_CAP_FIRST_BLOCK + SAM_CAP_BLOCKS) {
            continue;
        }
        uint8_t n = blk - SAM_CAP_FIRST_BLOCK;
        memcpy(sam_cap.data + (n * 8), rx + (i * 8), 8);
        sam_cap.block_map |= (1u << n);
    }
}

// DESFire ReadData of file 0x0F (what Seader keys on) plus its 91 AF continuations.
// rx is the R-APDU, SW included.
void sam_capture_desfire(const uint8_t *tx, uint16_t tx_len, const uint8_t *rx, uint16_t rx_len) {

    static const uint8_t read_sio[] = { 0x90, 0xBD, 0x00, 0x00, 0x07, 0x0F, 0x00, 0x00, 0x00 };
    static const uint8_t read_more[] = { 0x90, 0xAF, 0x00, 0x00, 0x00 };

    if (rx_len < 2) {
        sam_cap.desfire_more = false;
        return;
    }

    bool first = (tx_len == 13 && memcmp(tx, read_sio, sizeof(read_sio)) == 0 && rx_len > 2 && rx[0] == 0x30);
    bool more = (sam_cap.desfire_more && tx_len == sizeof(read_more) && memcmp(tx, read_more, sizeof(read_more)) == 0);

    if (first) {
        sam_cap.len = 0;
    }

    if (first || more) {
        uint16_t n = MIN((uint16_t)(rx_len - 2), (uint16_t)(sizeof(sam_cap.data) - sam_cap.len));
        memcpy(sam_cap.data + sam_cap.len, rx, n);
        sam_cap.len += n;
    }

    sam_cap.desfire_more = (first || more) && rx[rx_len - 2] == 0x91 && rx[rx_len - 1] == 0xAF;
}

// DER length of the SIO at p, tag and length bytes included. 0 if unusable.
static uint16_t sam_sio_der_len(const uint8_t *p, uint16_t avail) {
    if (avail < 2 || p[0] != 0x30) {
        return 0;
    }
    uint16_t len;
    if (p[1] < 0x80) {
        len = p[1] + 2;
    } else if (p[1] == 0x81 && avail >= 3) {
        len = p[2] + 3;
    } else {
        return 0;
    }
    return (len <= avail) ? len : 0;
}

// The iCLASS SIO is the lowest captured block holding a SEQUENCE whose length
// is covered by contiguous captured blocks. Moves it to offset 0.
static uint16_t sam_capture_iclass_sio(uint8_t *start_block) {
    for (uint8_t n = 0; n < SAM_CAP_BLOCKS; n++) {
        if ((sam_cap.block_map & (1u << n)) == 0) {
            continue;
        }

        uint8_t run = 0;
        while ((n + run) < SAM_CAP_BLOCKS && (sam_cap.block_map & (1u << (n + run)))) {
            run++;
        }

        uint16_t len = sam_sio_der_len(sam_cap.data + (n * 8), run * 8);
        if (len) {
            memmove(sam_cap.data, sam_cap.data + (n * 8), len);
            *start_block = SAM_CAP_FIRST_BLOCK + n;
            return len;
        }
    }
    return 0;
}

// Sends the PACS reply, extended with UID and SIO when asked for. Falls back to
// the plain SAM response if the extended one cannot be built.
void sam_reply_pacs(uint16_t cmd, bool ext, const uint8_t *sam, uint8_t sam_len) {

    if (ext == false) {
        reply_ng(cmd, PM3_SUCCESS, sam, sam_len);
        return;
    }

    sam_ext_reply_hdr_t hdr = {0};
    hdr.magic = SAM_EXT_REPLY_MAGIC;
    hdr.uid_len = sam_cap.uid_len;
    memcpy(hdr.uid, sam_cap.uid, sam_cap.uid_len);

    uint16_t sio_len = 0;
    if (sam_cap.block_map) {
        sio_len = sam_capture_iclass_sio(&hdr.sio_start);
    } else if (sam_cap.len) {
        sio_len = sam_sio_der_len(sam_cap.data, sam_cap.len);
    }
    hdr.sio_len = (uint8_t)sio_len;
    hdr.sam_len = sam_len;

    uint16_t n = sizeof(hdr) + sio_len + sam_len;
    uint8_t *buf = BigBuf_calloc(n);
    if (buf == NULL) {
        reply_ng(cmd, PM3_SUCCESS, sam, sam_len);
        return;
    }

    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), sam_cap.data, sio_len);
    memcpy(buf + sizeof(hdr) + sio_len, sam, sam_len);
    reply_ng(cmd, PM3_SUCCESS, buf, n);
}
