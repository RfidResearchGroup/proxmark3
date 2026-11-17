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
#ifndef SMARTCARD_H
#define SMARTCARD_H

#include "common.h"
#include "i2c_apis.h"
#include "smartcard_apis.h"
#include "pm3_cmd.h"

// SAM secure-channel transport policy for the performance build.  Artemis
// offers T=0 first in its ATR; request its advertised T=1 service explicitly
// and use Fi=512/Di=32 with SIM firmware v4.66.  This is protocol selection only:
// it does not enable APDU dumps or other bring-up diagnostics.
#define SAM_SC_FORCE_T1_PROFILE     1
#define SAM_SC_T1_TA1               0x96

// The SIM module v4 supports up to 384 bytes for the length.
#define  ISO7816_MAX_FRAME 270

#define I2C_WAIT_MAX_MS         60000   // clamp on a host supplied SC_WAIT

// Must cover the card's block waiting time: 1.4 s at BWI=4, 2.9 s at BWI=5.
#define SIM_WAIT_MS             3000
#define SIM_WAIT_DELAY          I2C_ITERS_FOR_MS(SIM_WAIT_MS)

I2C_BUILD_ASSERT(SIM_WAIT_MS >= 3000, sim_wait_covers_bwt);
I2C_BUILD_ASSERT((uint64_t)I2C_WAIT_MAX_MS * I2C_ITERS_PER_MS <= 0xFFFFFFFFULL, wait_fits_u32);

// Reset the adapter, forgetting what the last ATR said. The card itself is
// left powered.
void SmartCard_ResetAdapter(void);

// Which SIM module opcode a set of SC_RAW* flags asks for.
smartcard_mode_t SmartCard_ModeForFlags(smartcard_command_t flags);

// Which SIM module opcode matches the protocol the card is currently running,
// for callers that carry no SC_RAW* flags of their own. T=0 until a PPS says
// otherwise.
smartcard_mode_t SmartCard_ActiveMode(void);

// Request the configured T=1 profile for the next SAM-only GetATR().  The
// request is consumed once, so unrelated SmartCardRaw traffic still follows
// its own ATR/PPS policy.
void sc_request_sam_t1_profile(void);

// Log one smartcard frame, timestamped from the tick counter. Start is where
// the previous frame ended, so a Tag frame's span is how long the card took to
// answer and a Rdr frame's is how long the host took to ask.
void sc_log_trace(const uint8_t *d, uint16_t len, bool reader2tag);
void sc_log_trace_span(const uint8_t *d, uint16_t len, bool reader2tag, uint32_t start);
void sc_log_trace_reset(void);

//
bool GetATR(smart_card_atr_t *card_ptr, bool verbose);

// generice functions
void SmartCardATR(void);
void SmartCardRaw(const smart_card_raw_t *p);
void SmartCardSetClock(uint64_t arg0);
void SmartCardPPS(const smart_card_pps_t *p);
void SmartCard_PrintStatus(void);
int SmartCard_GetModuleInfo(uint8_t *major, uint8_t *minor, void *info);

// Send one APDU to the card and hand its answer back with the caller's
// prepend byte and a CRC, for the EMV simulator.
int CmdSmartRaw(const uint8_t prepend, const uint8_t *data, int dlen, uint8_t *output, uint16_t *olen);

#endif // SMARTCARD_H
