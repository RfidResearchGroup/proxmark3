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
// Card side on a PM5 built with USB_HOST_CCID: the card sits in a USB CCID
// reader on the CEP port. The reader owns voltage, clock, PPS and the T=0
// procedure bytes, the class driver builds the T=1 blocks. The reader frames
// every byte, so a raw frame goes as an APDU like a T=0 one.
//-----------------------------------------------------------------------------
#include "smartcard_apis.h"

#include "ccid_reader.h"
#include "pm5_cep_usb_host.h"
#include "dbprint.h"
#include "pm3_cmd.h"
#include "string.h"
#include "ticks_apis.h"

// Keep in step with ISO7816_MAX_FRAME in the command layer.
#define SC_CCID_MAX_FRAME       270
// The reader enumerates after it is plugged in.
#define SC_CCID_READY_MS        3000
#define SC_CCID_FIDI_DEFAULT    0x11

// An exchange runs whole in SmartCard_HwSend(), its answer waits here for
// SmartCard_HwRecv().
static uint8_t s_resp[SC_CCID_MAX_FRAME];
static uint16_t s_resp_len = 0;
static bool s_resp_ready = false;

static bool reader_wait(void) {
    uint32_t start = GetTickCount();
    while (cep_usb_host_ready() == false) {
        cep_usb_host_task();
        if (cep_usb_host_failed() || GetTickCountDelta(start) > SC_CCID_READY_MS) {
            return false;
        }
    }
    return true;
}

static uint8_t bcd(uint8_t v) {
    return (uint8_t)((v >> 4) * 10 + (v & 0x0F));
}

void SmartCard_HwOpen(void) {
    s_resp_ready = false;
    // a host stopped by a transfer error starts again
    cep_usb_host_restart();
}

void SmartCard_HwClose(void) {
    s_resp_ready = false;
    if (cep_usb_host_ready()) {
        ccid_reader_power_off();
    }
}

smartcard_present_t SmartCard_HwGetPresent(void) {
    // GetSlotStatus would tell, nothing asks for it yet
    return SC_CHK_UNSUPPORTED;
}

bool SmartCard_HwATR(uint8_t *atr, uint16_t *len, uint32_t wait) {
    (void)wait;

    if ((atr == NULL) || (len == NULL)) {
        return false;
    }

    s_resp_ready = false;

    if (cep_usb_host_restart() == false) {
        if (g_dbglevel >= DBG_ERROR) {
            DbpString("SC: no USB reader on the CEP port");
        }
        return false;
    }
    if (reader_wait() == false) {
        if (g_dbglevel >= DBG_ERROR) {
            Dbprintf("SC: the USB device on the CEP port is not usable ( %s )",
                     cep_usb_host_failed() ? cep_usb_host_failure() : "still enumerating");
        }
        return false;
    }

    uint16_t n = 0;
    if (ccid_reader_power_on(atr, &n, *len) != PM3_SUCCESS) {
        return false;
    }
    *len = n;
    return n > 0;
}

bool SmartCard_HwSend(smartcard_mode_t mode, const uint8_t *data, uint16_t len) {

    s_resp_ready = false;

    // T=0 and raw go in the protocol the card runs, a PPS may have put it in T=1
    if ((mode == SC_MODE_T1) && (ccid_reader_protocol() != 1)) {
        return false;
    }

    uint16_t n = 0;
    if (ccid_reader_xfr_apdu(data, len, s_resp, &n, sizeof(s_resp)) != PM3_SUCCESS) {
        return false;
    }
    s_resp_len = n;
    s_resp_ready = true;
    return true;
}

bool SmartCard_HwRecv(uint8_t *dest, uint16_t *len, uint32_t wait) {
    (void)wait;

    if (s_resp_ready == false) {
        *len = 0;
        return false;
    }

    uint16_t n = s_resp_len;
    if (n > *len) {
        n = *len;
    }
    memcpy(dest, s_resp, n);
    *len = n;
    s_resp_ready = false;
    return n > 0;
}

bool SmartCard_HwPPS(const uint8_t *req, uint8_t req_len, uint8_t out[3], uint32_t wait) {
    (void)wait;

    if ((req_len < 1) || (req_len > 2)) {
        return false;
    }

    s_resp_ready = false;

    uint8_t proto = (uint8_t)(req[0] & 0x0F);
    if (proto > 1) {
        return false;
    }

    // SetParameters, the reader runs the PPS itself. T=1 with no TA1 asked goes
    // as fast as card and reader allow: at 0x11 an ACR40T gets no answer to the
    // first block.
    uint8_t ta1 = (req_len == 2) ? req[1] : SC_CCID_FIDI_DEFAULT;
    int res;
    if ((req_len == 1) && (proto == 1)) {
        res = ccid_reader_select_fastest(proto, &ta1);
    } else {
        res = ccid_reader_select(proto, ta1);
    }
    if (res != PM3_SUCCESS) {
        return false;
    }

    out[0] = 1;
    out[1] = proto;
    out[2] = ta1;
    return true;
}

bool SmartCard_HwSetReload(uint16_t reload) {
    // The reader holds the rate it negotiated, there is nothing to put back.
    return reload != 0;
}

void SmartCard_HwSetClock(uint64_t f) {
    (void)f;
    if (g_dbglevel >= DBG_ERROR) {
        DbpString("SC: the USB reader picks the card clock");
    }
}

bool SmartCard_HwSetVoltage(smartcard_vcc_t v) {
    // The reader picks the voltage.
    (void)v;
    return false;
}

// The adapter is the reader: its release number, once the class driver took it.
// No waiting for one that still enumerates, the client gives the capabilities 1 s.
int SmartCard_HwAdapterInfo(uint8_t *major, uint8_t *minor, void *info) {
    (void)info;

    if (cep_usb_host_ready() == false) {
        return PM3_EDEVNOTSUPP;
    }

    uint16_t release = cep_usb_host_release();
    *major = bcd((uint8_t)(release >> 8));
    *minor = bcd((uint8_t)(release & 0xFF));
    return PM3_SUCCESS;
}
