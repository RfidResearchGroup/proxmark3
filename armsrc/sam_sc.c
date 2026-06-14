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
// HID Artemis SAM secure-channel transport (see sam_sc.h for design notes).
//-----------------------------------------------------------------------------
#include "sam_sc.h"

#include <string.h>
#include "BigBuf.h"
#include "appmain.h"
#include "cmd.h"
#include "dbprint.h"
#include "i2c.h"          // ISO7816_MAX_FRAME, I2C_Reset_EnterMainProgram
#include "proxmark3_arm.h"
#include "sam_common.h"
#include "ticks.h"
#include "util.h"         // LED_D_ON, LEDsoff

// Tracks whether the SIM module has been initialised since the last reset.
// Set true after the first successful sam_sc_handler() invocation; cleared by
// sam_sc_session_invalidate() (called from any other firmware path that takes
// over the SIM module - currently a manual hook left for future wiring) and
// by SAM_SC_FLAG_FORCE_RESET / SAM_SC_FLAG_RELEASE.
static bool s_sam_sc_session_active = false;

void sam_sc_session_invalidate(void) {
    s_sam_sc_session_active = false;
}

void sam_sc_handler(const PacketCommandNG *c) {

    if (c == NULL || c->length < SAM_SC_HEADER_LEN) {
        reply_ng(CMD_HF_SAM_SC, PM3_EINVARG, NULL, 0);
        return;
    }

    const uint8_t *body = c->data.asBytes;
    const uint8_t flags        = body[SAM_SC_OFF_FLAGS];
    const uint8_t addr_src     = body[SAM_SC_OFF_ADDR_SRC];
    const uint8_t addr_dest    = body[SAM_SC_OFF_ADDR_DEST];
    const uint8_t addr_reply   = body[SAM_SC_OFF_ADDR_REPLY];
    const uint8_t scFlag       = body[SAM_SC_OFF_SCFLAG];

    const bool force_reset = !!(flags & SAM_SC_FLAG_FORCE_RESET);
    const bool release     = !!(flags & SAM_SC_FLAG_RELEASE);
    const bool no_payload  = !!(flags & SAM_SC_FLAG_NO_PAYLOAD);

    const uint8_t *payload     = body + SAM_SC_HEADER_LEN;
    uint16_t payload_len       = (uint16_t)(c->length - SAM_SC_HEADER_LEN);

    if (no_payload) {
        // Caller is just managing session state (open/close); no SAM traffic.
        payload_len = 0;
    } else if (payload_len == 0) {
        reply_ng(CMD_HF_SAM_SC, PM3_EINVARG, NULL, 0);
        return;
    }

    LED_D_ON();
    set_tracing(true);

    // Reset the SAM only if the caller asked for it OR this is the first SC
    // op since boot / since the previous session was released. Crucially
    // this dispatcher does NOT reset on every call the way sam_picopass_get_pacs
    // does, so the SAM-side session-flag binding established by ContinueAuth
    // survives across multiple CMD_HF_SAM_SC invocations.
    //
    // After every reset we issue a sam_get_version() warmup ping. This
    // mirrors what sam_picopass_get_pacs does (which is what `hf iclass sam
    // --info` runs through). Without this warmup, the FIRST sam_send_payload_ex
    // after I2C_Reset can time out - the 8051<->SAM UART link needs a
    // sacrificial round-trip to settle. The version response is discarded.
    if (force_reset || s_sam_sc_session_active == false) {
        I2C_Reset_EnterMainProgram();
        StartTicks();
        sam_get_version(false);
        s_sam_sc_session_active = true;
    }

    int res = PM3_SUCCESS;

    if (no_payload == false) {

        uint8_t *response = BigBuf_calloc(ISO7816_MAX_FRAME);
        if (response == NULL) {
            res = PM3_EMALLOC;
            goto out;
        }
        uint16_t response_len = ISO7816_MAX_FRAME;

        res = sam_send_payload_ex(
                  addr_src, addr_dest, addr_reply, scFlag,
                  payload, &payload_len,
                  response, &response_len
              );

        if (res != PM3_SUCCESS) {
            // Whatever happened on the wire, the session may be in an
            // inconsistent state. Mark dirty so the next call re-opens.
            s_sam_sc_session_active = false;
        }

        if (release) {
            // Caller requested an explicit teardown after this op (typically
            // after a samCommandSecureChannelTerminate). Do a full reset to
            // bring the SAM back to a clean idle state.
            I2C_Reset_EnterMainProgram();
            s_sam_sc_session_active = false;
        }

        // Reformat the buffer for the host: prepend the SAM-assigned scFlag
        // (firmware-side index 4 of the routing tail), then the SAM payload
        // (firmware-side index 5 onward). See sam_sc.h for the wire layout.
        // memmove is safe across the overlapping ranges (dst < src by 4).
        if (res == PM3_SUCCESS && response_len >= 6) {
            uint8_t sc_flag = response[4];
            uint16_t sam_payload_len = (uint16_t)(response_len - 5);
            memmove(response + 1, response + 5, sam_payload_len);
            response[0] = sc_flag;
            response_len = (uint16_t)(1 + sam_payload_len);
            reply_ng(CMD_HF_SAM_SC, PM3_SUCCESS, response, response_len);
        } else if (res == PM3_SUCCESS) {
            // sam_send_payload_ex succeeded but the response is too short
            // to contain a routing tail + SAM payload. Treat as exchange
            // error so the host knows the result is unusable.
            reply_ng(CMD_HF_SAM_SC, PM3_ECARDEXCHANGE, NULL, 0);
        } else {
            // sam_send_payload_ex failed. Propagate the error; no payload.
            reply_ng(CMD_HF_SAM_SC, res, NULL, 0);
        }

        BigBuf_free();
        goto done;
    }

    // SAM_SC_FLAG_NO_PAYLOAD path: caller wants to manage session state only.
    if (release) {
        I2C_Reset_EnterMainProgram();
        s_sam_sc_session_active = false;
    }

out:
    reply_ng(CMD_HF_SAM_SC, res, NULL, 0);

done:
    set_tracing(false);
    LEDsoff();
}
