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
// HID Artemis SAM secure-channel transport.
//
// CMD_HF_SAM_PICOPASS is structurally unsuitable for sustaining an SCP02 /
// Grace secure channel because it (a) hard-resets the SAM at the start of
// every CLI invocation, wiping the SAM's internal session-flag binding, and
// (b) routes raw payloads through sam_send_request_iso15 whose loop is
// designed to relay 0x61-tagged SAM responses to an iCLASS card via NFC.
//
// This handler is a separate dispatcher that:
//   - Resets the SAM only on the very first call after device boot, OR when
//     the host explicitly asks for a reset.
//   - Skips the sam_get_version sanity ping.
//   - Sends a single SAM payload with a host-supplied scFlag and returns the
//     SAM's raw response - no NFC card-edge involvement at all.
//
// The host owns the SCP02 / Grace KDF + wrap/unwrap state machine; this
// firmware module is a thin transport pipe so that state can survive across
// CLI invocations on the SAM side.
//-----------------------------------------------------------------------------
#ifndef __SAM_SC_H
#define __SAM_SC_H

#include "common.h"
#include "pm3_cmd.h"

// CMD_HF_SAM_SC payload layout:
//
//   [0]    flags byte
//             BITMASK(0)  SAM_SC_FLAG_FORCE_RESET   - I2C_Reset before this op,
//                                                     marks session uninitialised
//             BITMASK(1)  SAM_SC_FLAG_RELEASE       - I2C_Reset after this op,
//                                                     marks session uninitialised
//             BITMASK(2)  SAM_SC_FLAG_NO_PAYLOAD    - send no payload, just
//                                                     manage session state
//                                                     (open / close)
//   [1]    addr_src        Grace routing FROM byte (typically 0x44)
//   [2]    addr_dest       Grace routing TO byte   (typically 0x0A = SAM)
//   [3]    addr_reply      Grace routing REPLY-TO  (typically 0x44)
//   [4]    scFlag          Grace routing scFlag    (0x00 for InitAuth;
//                                                   server-assigned thereafter)
//   [5...] SAM payload bytes starting with 0xA0 (or whatever SAM TLV the
//          host wants delivered raw; the firmware does not interpret).
//
// Reply: reply_ng(CMD_HF_SAM_SC, status, payload, payload_len)
//   payload[0]      = SAM-assigned scFlag (the byte the host MUST echo in the
//                     routing header of the next request - 0x00 during
//                     InitAuth, server-assigned thereafter)
//   payload[1..]    = raw SAM response starting at the first byte after the
//                     routing tail (typically 0xBD for Path A/B, 0xBE for
//                     Path C errorResponse)
//   payload_len     = 1 + len(SAM response)
//
// The scFlag is the load-bearing piece of state for sustaining a Grace
// secure channel: the SAM assigns it during InitAuth and binds the
// authenticated session to it. Subsequent ContinueAuth and wrapped APDUs
// MUST carry the same scFlag in their outgoing routing header or the SAM
// will reject them. Surfacing it as the first byte of the reply lets the
// host save and replay it on the next CMD_HF_SAM_SC call without any
// additional probing.

#define SAM_SC_FLAG_FORCE_RESET (1 << 0)
#define SAM_SC_FLAG_RELEASE     (1 << 1)
#define SAM_SC_FLAG_NO_PAYLOAD  (1 << 2)

// Wire-layout offsets within the CMD_HF_SAM_SC packet body.
#define SAM_SC_OFF_FLAGS        0
#define SAM_SC_OFF_ADDR_SRC     1
#define SAM_SC_OFF_ADDR_DEST    2
#define SAM_SC_OFF_ADDR_REPLY   3
#define SAM_SC_OFF_SCFLAG       4
#define SAM_SC_HEADER_LEN       5

void sam_sc_handler(const PacketCommandNG *c);

// Forces the next sam_sc_handler() call to perform an I2C reset before sending
// its payload. Intended to be called by other firmware paths that may have
// taken over the SIM module (e.g. CMD_HF_SAM_PICOPASS, CMD_SMART_*) and would
// otherwise leave a stale "session active" flag visible to sam_sc_handler.
void sam_sc_session_invalidate(void);

#endif
