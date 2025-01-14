// //-----------------------------------------------------------------------------
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
// The main i2c code, for communications with smart card module
//-----------------------------------------------------------------------------

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
#include "i2c_direct.h"

static uint8_t fci_template[] = {0x02, 0x6f, 0x5e, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xa5, 0x53, 0x50, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x9f, 0x38, 0x18, 0x9f, 0x66, 0x04, 0x9f, 0x02, 0x06, 0x9f, 0x03, 0x06, 0x9f, 0x1a, 0x02, 0x95, 0x05, 0x5f, 0x2a, 0x02, 0x9a, 0x03, 0x9c, 0x01, 0x9f, 0x37, 0x04, 0x5f, 0x2d, 0x02, 0x65, 0x6e, 0x9f, 0x11, 0x01, 0x01, 0x9f, 0x12, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0xbf, 0x0c, 0x13, 0x9f, 0x5a, 0x05, 0x31, 0x08, 0x26, 0x08, 0x26, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0xd8, 0x15};

static uint8_t pay1_response[] = { 0x6F, 0x1E, 0x84, 0x0E, 0x31, 0x50, 0x41, 0x59 };
static uint8_t pay2_response[] = { 0x03, 0x6f, 0x3e, 0x84, 0x0e, 0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x2c, 0xbf, 0x0c, 0x29, 0x61, 0x27, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x50, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x63, 0x04, 0xdf, 0x20, 0x01, 0x80, 0x90, 0x00, 0x07, 0x9d};

void SmartCardDirectSend(uint8_t prepend, const smart_card_raw_t *p, uint8_t *output, uint16_t *olen) {
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
            Dbprintf("SmartCardDirectSend: I2C_BufferWrite failed\n");
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

        SmartCardDirectSend(prepend, payload, output, olen);
    } else if (len == 2) {
        Dbprintf("***** BAD response from card (response unsupported)...");
        Dbhexdump(3, &resp[0], false);
        resp[0] = prepend;
        resp[1] = 0x6a;
        resp[2] =0x82;
        AddCrc14A(resp, 3);

        //Dbhexdump(5, &resp[0], false); // special print
        //EmSendCmd(&resp[0], 5);
        memcpy(output, resp, 5);
        *olen = 5;
    }

    if (resp[1] == 0x6a && resp[2] == 0x82) {
        Dbprintf("***** bad response from card (file not found)...");
        resp[0] = prepend;
        resp[1] = 0x6a;
        resp[2] =0x82;
        AddCrc14A(resp, 3);

        //Dbhexdump(5, &resp[0], false); // special print
        //EmSendCmd14443aRaw(&resp[0], 5);
        //EmSendCmd(&resp[0], 5);
        memcpy(output, resp, 5);
        *olen = 5;
        FpgaDisableTracing();
    }

    if (len > 2) {
        Dbprintf("***** sending it over the wire... len: %d =>\n", len);
        resp[1] = prepend;

        // if we have a generate AC request, lets extract the data and populate the template
        if (resp[1] != 0xff && resp[2] == 0x77) {
            Dbprintf("we have detected a generate ac response, lets repackage it!");
            Dbhexdump(len, &resp[1], false); // special print
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
            Dbhexdump(len, &template[0], false); // special print

            AddCrc14A(&template[1], len-3);
            Dbprintf("\nafter crc rearranged is: ");
            Dbhexdump(len, &template[0], false); // special print
            Dbprintf("\n");

            //EmSendCmd(&template[1], len-1);
            memcpy(output, &template[1], len-1);
            *olen = len-1;

            BigBuf_free();
            return;
        }

        //Dbhexdump(len, &resp[1], false); // special print
        AddCrc14A(&resp[1], len);
        Dbhexdump(len+2, &resp[1], false); // special print

        // Check we don't want to modify the response (application profile response)
        //uint8_t modifyme[] = {0x03, 0x77, 0x0e, 0x82, 0x02};

        BigBuf_free();

        if (prepend == 0xff) {
            Dbprintf("pdol request, we can can the response...");
            return;
        }

        if (memcmp(&resp[2], &pay1_response[0], sizeof(pay1_response)) == 0 && true) {
            Dbprintf("Switching out the pay1 response for a pay2 response...");
            //EmSendCmd(&pay2_response[0], sizeof(pay2_response));
            memcpy(output, &pay2_response[0], sizeof(pay2_response));
            *olen = sizeof(pay2_response);
        }
        else if (memcmp(&resp[1], &fci_template[0], 2) == 0 && true) {
            Dbprintf("***** modifying response to have full fci template...!");
            //EmSendCmd(&fci_template[0], sizeof(fci_template));
            memcpy(output, &fci_template[0], sizeof(fci_template));
            *olen = sizeof(fci_template);
        } else {
            //Dbprintf("***** not modifying response...");
            //EmSendCmd(&resp[1], len + 2);
            memcpy(output, &resp[1], len + 2);
            *olen = len + 2;
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

int CmdSmartRaw(const uint8_t prepend, const uint8_t *data, int dlen, uint8_t *output, uint16_t *olen) {

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

    SmartCardDirectSend(prepend, payload, output, olen);

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

