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

static void SmartCardDirectSend(uint8_t prepend, const smart_card_raw_t *p, uint8_t *output, uint16_t *olen) {
    LED_D_ON();

    uint16_t len = 0;
    uint8_t *resp = BigBuf_malloc(ISO7816_MAX_FRAME);
    resp[0] = prepend;
    // check if alloacted...
    smartcard_command_t flags = p->flags;

    if ((flags & SC_LOG) == SC_LOG)
        set_tracing(true);
    else
        set_tracing(false);

    if ((flags & SC_CONNECT) == SC_CONNECT) {

        I2C_Reset_EnterMainProgram();

        if ((flags & SC_SELECT) == SC_SELECT) {
            smart_card_atr_t card;
            bool gotATR = GetATR(&card, true);

            if (gotATR == false) {
                Dbprintf("No ATR received...\n");
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
        uint8_t cmd_getresp[] = {0x00, ISO7816_GET_RESPONSE, 0x00, 0x00, resp[2]};

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
        resp[2] = 0x82;
        AddCrc14A(resp, 3);

        memcpy(output, resp, 5);
        *olen = 5;
    }

    if (resp[1] == 0x6a && resp[2] == 0x82) {
        Dbprintf("***** bad response from card (file not found)...");
        resp[0] = prepend;
        resp[1] = 0x6a;
        resp[2] = 0x82;
        AddCrc14A(resp, 3);

        memcpy(output, resp, 5);
        *olen = 5;
        FpgaDisableTracing();
    }

    if (len > 2) {
        Dbprintf("***** sending it over the wire... len: %d =>\n", len);
        resp[1] = prepend;

        AddCrc14A(&resp[1], len);
        Dbhexdump(len + 2, &resp[1], false);

        BigBuf_free();

        if (prepend == 0xff) {
            Dbprintf("pdol request, we can ignore the response...");
            return;
        }

        memcpy(output, &resp[1], len + 2);
        *olen = len + 2;

        BigBuf_free();
    }

OUT:
    LEDsoff();
}

int CmdSmartRaw(const uint8_t prepend, const uint8_t *data, int dlen, uint8_t *output, uint16_t *olen) {

    Dbprintf("sending command to smart card... %02x %02x %02x... =>", prepend, data[0], data[1]);
    Dbhexdump(dlen, data, false);

    if (data[4] + 5 != dlen) {
        Dbprintf("invalid length of data. Received: %d, command specifies %d", dlen, data[4] + 5);
        dlen = data[4] + 5;
    }

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

    if (dlen > 0) {
        if (use_t0)
            payload->flags |= SC_RAW_T0;
        else
            payload->flags |= SC_RAW;
    }

    SmartCardDirectSend(prepend, payload, output, olen);

    return PM3_SUCCESS;
}
