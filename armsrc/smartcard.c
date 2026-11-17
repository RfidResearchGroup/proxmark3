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
// Smart card commands and the direct APDU transport used by the EMV
// simulator. The board side lives under common_arm/smartcard.
//-----------------------------------------------------------------------------
#include <inttypes.h>

#include "smartcard.h"
#include "smartcard_atr.h"
#include "smartcard_rate.h"

#include "BigBuf.h"
#include "iso14443a.h"
#include "string.h"
#include "mifareutil.h"
#include "fpga_loader.h"
#include "fpga_apis.h"
#include "proxmark3_arm.h"
#include "cmd.h"
#include "protocols.h"
#include "appmain.h"
#include "util.h"
#include "commonutil.h"
#include "crc16.h"
#include "dbprint.h"
#include "ticks_apis.h"

#define SC_PROTO_T0     (1 << 0)
#define SC_PROTO_T1     (1 << 1)

// protocols the last ATR offered, (1 << T). 0 = no ATR read since reset
static uint8_t s_card_protocols = 0;
// SmartCard_ModeForFlags() runs per APDU, so report the choice once per card
static bool s_proto_announced = false;

// The module opcode matching the protocol the card is actually running, taken
// from the active-protocol byte of a PPS response. 0 = nothing negotiated, so
// SmartCard_ActiveMode() falls back to T=0.
//
// Only a successful PPS sets this, which is what makes it safe to hand back
// SEND_T1 without probing the module version: I2C_DEVICE_CMD_PPS and
// I2C_DEVICE_CMD_SEND_T1 landed in the same module firmware
// (SIM_MODULE_VERS_T1_*), so a module that answered a PPS at all is known to
// understand T=1 too. An older module never answers, this stays 0, and callers
// keep the T=0 they had before.
static smartcard_mode_t s_active_mode = 0;

#if SAM_SC_FORCE_T1_PROFILE
// One-shot request used by the SAM secure-channel path.  Keep it separate
// from generic SmartCardRaw PPS selection so the performance policy does not
// alter unrelated contact-card commands.
static bool s_sam_t1_profile_requested = false;
#endif

// A negotiated rate lives in two places that reset independently: the module's
// UART divisor, which any I2C_Reset_EnterMainProgram() wipes, and the card,
// which only an RST pulse clears. Left alone the two drift apart and every
// exchange fails until something resets the card.
//
// So remember what was negotiated, keyed by the ATR it was negotiated against,
// and put it back after each ATR - the one window where PPS is legal
// (ISO/IEC 7816-3 clause 9). A different card brings a different ATR and drops
// the entry.
static struct {
    uint8_t atr[sizeof(((smart_card_atr_t *)0)->atr)];  // what it was negotiated against
    uint8_t atr_len;
    uint8_t ta1;                                        // 0 = nothing negotiated
    uint8_t proto;
    bool    reapply;                                    // off while SmartCardPPS negotiates
    bool    tried;                                      // already negotiated against this ATR
} s_pps = { {0}, 0, 0, 0, true, false };

// Defined further down, next to the Fi/Di tables it needs. Declared here
// because the callers that reset the module without asking for an ATR come
// first in this file.
static void sc_rate_restore(void);

// Reset the SIM_Adapter, then  enter the main program
// Note: the SIM_Adapter will not enter the main program after power up. Please run this function before use SIM_Adapter.
void I2C_Reset_EnterMainProgram(void) {
    // whatever we knew about the card is no longer trustworthy
    s_card_protocols = 0;
    s_proto_announced = false;
    s_active_mode = 0;
    StartTicks();
    sc_log_trace_reset();
    SmartCard_HwOpen();
}

void SmartCard_PrintStatus(void) {
    DbpString(_CYAN_("Smart card module (ISO 7816)"));

    uint8_t major = 0, minor = 0;
    bool present;

#ifndef PM5
    smartcard_rdv4_info_t info = {0};
    present = (SmartCard_GetModuleInfo(&major, &minor, &info) == PM3_SUCCESS);
#else
    present = (SmartCard_GetModuleInfo(&major, &minor, NULL) == PM3_SUCCESS);
#endif

    if (present == false) {
        DbpString("  version................. ( " _RED_("fail") " )");
        return;
    }

#ifndef PM5
    Dbprintf("  version................. v%d.%02d ( %s )"
             , major
             , minor
             , info.ok ? _GREEN_("ok") : _RED_("Outdated")
            );

    Dbprintf("  T=1, PPS................ ( %s )"
             , info.t1 ? _GREEN_("supported") : _YELLOW_("not in this firmware")
            );
#else
    Dbprintf("  version................. v%d.%02d", major, minor);
#endif
}

int SmartCard_GetModuleInfo(uint8_t *major, uint8_t *minor, void *info) {
    I2C_Reset_EnterMainProgram();
    // The capability probe runs this on every client connect. Without the
    // restore, reconnecting a client leaves the module on the default rate and
    // an already negotiated card unreachable.
    sc_rate_restore();
    return SmartCard_HwAdapterInfo(major, minor, info);
}

static uint32_t s_trace_tick = 0;
static bool s_trace_tick_valid = false;

void sc_log_trace_reset(void) {
    s_trace_tick_valid = false;
}

void sc_log_trace_span(const uint8_t *d, uint16_t len, bool reader2tag, uint32_t start) {
    uint32_t now = GetTicks();
    LogTrace(d, len, start, now, NULL, reader2tag);
    s_trace_tick = now;
    s_trace_tick_valid = true;
}

// A frame that can only be timed from the end of the one before - the card's
// answer, which is not known to have arrived until it has been read.
void sc_log_trace(const uint8_t *d, uint16_t len, bool reader2tag) {
    uint32_t now = GetTicks();
    if (s_trace_tick_valid == false) {
        s_trace_tick = now;
        s_trace_tick_valid = true;
    }
    LogTrace(d, len, s_trace_tick, now, NULL, reader2tag);
    s_trace_tick = now;
}

smartcard_mode_t SmartCard_ModeForFlags(smartcard_command_t flags) {

    // an explicit T=1 request is an override, honoured even if the ATR disagrees
    if ((flags & SC_RAW_T1) == SC_RAW_T1) {

        if ((s_card_protocols != 0) && ((s_card_protocols & SC_PROTO_T1) == 0)) {
            if ((g_dbglevel >= DBG_ERROR) && (s_proto_announced == false)) {
                s_proto_announced = true;
                DbpString("SC: " _YELLOW_("card offers no T=1") ", sending it anyway");
            }
        }
        return SC_MODE_T1;
    }

    if ((flags & SC_RAW_T0) == SC_RAW_T0) {

        // A T=0 request to a card offering no T=0 cannot work - it simply will
        // not hear it. Most modern EMV/JCOP cards are T=1 only and callers like
        // ExchangeAPDUSC() ask for T=0 unconditionally. Redirect only that case;
        // a card offering both keeps the caller's choice.
        if ((s_card_protocols != 0) &&
                ((s_card_protocols & SC_PROTO_T0) == 0) &&
                ((s_card_protocols & SC_PROTO_T1) == SC_PROTO_T1)) {

            if ((g_dbglevel >= DBG_INFO) && (s_proto_announced == false)) {
                s_proto_announced = true;
                DbpString("SC: card offers no T=0, sending as T=1");
            }
            return SC_MODE_T1;
        }

        return SC_MODE_T0;
    }

    // Raw pass through: the host owns the framing, so never second guess it.
    return SC_MODE_RAW;
}

// Put the module back on the negotiated rate without touching the card.
//
// A module reset returns its UART to the default divisor, but the card keeps
// the rate a PPS put it at - only an RST pulse clears that, and the callers
// below deliberately do not pulse one. Left alone the two sit at different
// rates and every exchange after the reset is garbage; the only other cure is
// an ATR, which resets the card and destroys a SAM's open secure channel.
//
// Only the rate is restored. TC1 and TC2 - guard time and WI - come from the
// ATR and are gone with the reset, so a card naming non-default ones still
// needs a fresh ATR. What the module comes up with is what those cards ran at
// before their ATR was read anyway.
static void sc_rate_restore(void) {

    if ((s_pps.ta1 == 0) || (s_pps.ta1 == 0x11)) {
        return;                         // nothing negotiated, the default is right
    }

    uint16_t r = SmartCard_RateReload(s_pps.ta1);
    if (r == 0) {
        return;
    }

    if (SmartCard_HwSetReload(r) == false) {
        if (g_dbglevel >= DBG_ERROR) {
            DbpString("SC: could not put the module back on the negotiated rate");
        }
        return;
    }

    if (g_dbglevel >= DBG_INFO) {
        Dbprintf("SC: module rate restored without a card reset, TA1 %02X (R=%u)", s_pps.ta1, r);
    }
}

static bool sc_pps(uint8_t proto, uint8_t ta1) {
    uint8_t req[2] = { (uint8_t)(proto & 0x0F), ta1 };
    uint8_t resp[3] = {0};
    if (SmartCard_HwPPS(req, sizeof(req), resp, SIM_WAIT_DELAY) == false) {
        return false;
    }
    // resp is [ok][active protocol][ta1 in force]
    if ((resp[0] != 1) || (resp[1] != (proto & 0x0F)) || (resp[2] != ta1)) {
        return false;
    }

    // Take the protocol from the module rather than from the request: the
    // caller asked for one, this is the one that ended up in force.
    s_active_mode = ((resp[1] & 0x0f) == 1) ? SC_MODE_T1
                      : SC_MODE_T0;
    return true;
}

// The opcode to send an APDU with, for callers that have no protocol
// preference of their own and just want to talk to the card the way it is
// currently configured - the SAM path, which has no CLI flags to carry one.
//
// SmartCard_ModeForFlags() is the other half of this: it starts from a caller's
// explicit SC_RAW_T0 / SC_RAW_T1 and only overrides it when the ATR says that
// choice cannot work. Here there is nothing to override, so follow what PPS
// actually negotiated and default to T=0 when nothing has been.
smartcard_mode_t SmartCard_ActiveMode(void) {
    return (s_active_mode != 0) ? s_active_mode : SC_MODE_T0;
}

void sc_request_sam_t1_profile(void) {
#if SAM_SC_FORCE_T1_PROFILE
    s_sam_t1_profile_requested = true;
#endif
}

static void sc_pps_remember(const uint8_t *atr, uint8_t atr_len, uint8_t proto, uint8_t ta1) {
    if ((atr_len == 0) || (atr_len > sizeof(s_pps.atr))) {
        return;
    }
    memcpy(s_pps.atr, atr, atr_len);
    s_pps.atr_len = atr_len;
    s_pps.ta1 = ta1;
    s_pps.proto = proto;
}

static void sc_pps_forget(void) {
    s_pps.atr_len = 0;
    s_pps.ta1 = 0;
    s_pps.tried = false;
    s_active_mode = 0;
}

bool GetATR(smart_card_atr_t *card_ptr, bool verbose) {

    if (card_ptr == NULL) {
        return false;
    }

    card_ptr->atr_len = 0;
    memset(card_ptr->atr, 0, sizeof(card_ptr->atr));

    uint16_t len = sizeof(card_ptr->atr);
    if (SmartCard_HwATR(card_ptr->atr, &len, SIM_WAIT_DELAY) == false) {
        return false;
    }

    if (len > sizeof(card_ptr->atr)) {
        len = sizeof(card_ptr->atr);
    }

    if (SmartCard_ATRCheckTCK(card_ptr->atr, (uint8_t)len) == false) {
        if (g_dbglevel > DBG_INFO) DbpString("Wrong ATR checksum");
    }

    card_ptr->atr_len = (uint8_t)(len & 0xff);

    s_card_protocols = SmartCard_ATRProtocols(card_ptr->atr, card_ptr->atr_len);
    s_proto_announced = false;
#if SAM_SC_FORCE_T1_PROFILE
    const bool request_sam_t1 = s_sam_t1_profile_requested;
    s_sam_t1_profile_requested = false;
    if (request_sam_t1) {
        // This reset starts a fresh SAM session.  Do not restore an older
        // cached T=0 PPS entry before the one PPS below selects T=1.
        sc_pps_forget();
    }
#endif
    if (g_dbglevel >= DBG_INFO) {
        // What the ATR advertises, and which of them the card actually runs
        // until something negotiates otherwise. Saying only "offers T=0 T=1"
        // reads like a state report when it is a capability list.
        Dbprintf("SC: ATR offers%s%s, card runs T=%u"
                 , (s_card_protocols & SC_PROTO_T0) ? " T=0" : ""
                 , (s_card_protocols & SC_PROTO_T1) ? " T=1" : ""
                 , SmartCard_ATRFirstProto(card_ptr->atr, card_ptr->atr_len)
                );
    }

    if (verbose) {
        sc_log_trace(card_ptr->atr, card_ptr->atr_len, false);
    }

    // Same card as the one a rate was negotiated for? Put it back. This is the
    // only moment a PPS is legal, and the module has just come up at the
    // default, so card and module move together.
    if (s_pps.reapply && s_pps.ta1 && (s_pps.atr_len == card_ptr->atr_len) &&
            (memcmp(s_pps.atr, card_ptr->atr, s_pps.atr_len) == 0)) {

        if (sc_pps(s_pps.proto, s_pps.ta1)) {
            if (g_dbglevel >= DBG_INFO) {
                Dbprintf("SC: rate restored, TA1 %02X", s_pps.ta1);
            }
        } else {
            // Refused or lost: the card stays at the default per 9.1, so drop
            // the entry rather than keep failing on every ATR from now on.
            if (g_dbglevel >= DBG_ERROR) {
                Dbprintf("SC: could not restore TA1 %02X, back to the default", s_pps.ta1);
            }
            sc_pps_forget();
        }

    } else {

        bool same_card = (s_pps.atr_len == card_ptr->atr_len) &&
                         (memcmp(s_pps.atr, card_ptr->atr, s_pps.atr_len) == 0);

        if (same_card == false) {
            sc_pps_forget();            // different card, start over
        }

        // First sight of this card: ask for the best rate its ATR allows. Only
        // once - a refusal is remembered so every later ATR does not retry it.
        if (s_pps.reapply && (s_pps.tried == false)) {

            uint8_t want_proto = SmartCard_ATRFirstProto(card_ptr->atr, card_ptr->atr_len);
            uint8_t want = SmartCard_RateBestTa1(card_ptr->atr, card_ptr->atr_len);

#if SAM_SC_FORCE_T1_PROFILE
            if (request_sam_t1 && (s_card_protocols & SC_PROTO_T1)) {
                want_proto = 1;
                want = SAM_SC_T1_TA1;
            }
#endif

            memcpy(s_pps.atr, card_ptr->atr, card_ptr->atr_len);
            s_pps.atr_len = card_ptr->atr_len;
            s_pps.tried = true;

            if (want && sc_pps(want_proto, want)) {
                s_pps.ta1 = want;
                s_pps.proto = want_proto;
                if (g_dbglevel >= DBG_INFO) {
                    Dbprintf("SC: negotiated T=%u TA1 %02X", want_proto, want);
                }
            }
        }
    }

    return true;
}

void SmartCardATR(void) {
    LED_D_ON();
    set_tracing(true);
    I2C_Reset_EnterMainProgram();
    smart_card_atr_t card;
    if (GetATR(&card, true)) {
        reply_ng(CMD_SMART_ATR, PM3_SUCCESS, (uint8_t *)&card, sizeof(smart_card_atr_t));
    } else {
        reply_ng(CMD_SMART_ATR, PM3_ETIMEOUT, NULL, 0);
    }
    set_tracing(false);
    LEDsoff();
//    StopTicks();
}

void SmartCardRaw(const smart_card_raw_t *p) {
    LED_D_ON();

    uint16_t len = 0;
    uint8_t *resp = BigBuf_calloc(ISO7816_MAX_FRAME);
    if (resp == NULL) {
        reply_ng(CMD_SMART_RAW, PM3_EMALLOC, NULL, 0);
        LEDsoff();
        return;
    }
    smartcard_command_t flags = p->flags;

    if ((flags & SC_CLEARLOG) == SC_CLEARLOG)
        clear_trace();

    if ((flags & SC_LOG) == SC_LOG)
        set_tracing(true);
    else
        set_tracing(false);

    if ((flags & SC_CONNECT) == SC_CONNECT) {

        I2C_Reset_EnterMainProgram();

        // Without SC_SELECT there is no ATR to negotiate against, so put the
        // rate back by hand. With it, GetATR() resets the card and runs the PPS
        // itself - and the module has to be on the default to hear that ATR.
        if ((flags & SC_SELECT) != SC_SELECT) {
            sc_rate_restore();
        }

        if ((flags & SC_SELECT) == SC_SELECT) {
            smart_card_atr_t card;
            bool gotATR = GetATR(&card, true);
            if (gotATR == false) {
                reply_ng(CMD_SMART_RAW, PM3_ESOFT, NULL, 0);
                goto OUT;
            }
        }
    }

    // A card runs the protocol its TD1 names until a PPS changes it, so an APDU
    // framed as T=1 against a card that came up in T=0 gets no answer at all.
    // Do the switch here rather than making every caller run `smart pps --t1`
    // first. PPS is only legal straight after an ATR, so take one; the exchange
    // could not have worked without the switch anyway, so nothing is lost.
    if (((flags & SC_RAW_T1) == SC_RAW_T1) && (SmartCard_ActiveMode() != SC_MODE_T1)) {

        smart_card_atr_t card;
        s_pps.reapply = false;              // this is the negotiation
        bool got_atr = GetATR(&card, false);
        s_pps.reapply = true;

        if (got_atr && ((s_card_protocols & SC_PROTO_T1) == SC_PROTO_T1)) {
            if ((sc_pps(1, 0x11) == false) && (g_dbglevel >= DBG_ERROR)) {
                DbpString("SC: " _YELLOW_("PPS to T=1 refused") ", sending it anyway");
            }
        }
    }

    if (((flags & SC_RAW) == SC_RAW) ||
            ((flags & SC_RAW_T0) == SC_RAW_T0) ||
            ((flags & SC_RAW_T1) == SC_RAW_T1)) {

        uint32_t wait = SIM_WAIT_DELAY;
        if ((flags & SC_WAIT) == SC_WAIT) {
            // Asking for N ms now actually waits N ms.  The old conversion
            // assumed 3.07 us per iteration while the delay had been changed to
            // 20 us, so `--timeout 1000` sat there for six and a half seconds.
            uint32_t ms = p->wait_delay;
            if (ms > I2C_WAIT_MAX_MS) {
                ms = I2C_WAIT_MAX_MS;
            }
            wait = I2C_ITERS_FOR_MS(ms);
        }

        sc_log_trace(p->data, p->len, true);

        bool res = SmartCard_HwSend(SmartCard_ModeForFlags(flags), p->data, p->len);

        if (res == false) {
            if (g_dbglevel > 3) {
                DbpString(I2C_ERROR);
            }
            reply_ng(CMD_SMART_RAW, PM3_ESOFT, NULL, 0);
            goto OUT;
        }

        // read bytes from module
        len = ISO7816_MAX_FRAME;
        res = SmartCard_HwRecv(resp, &len, wait);
        if (res) {
            sc_log_trace(resp, len, false);
        } else {
            len = 0;
        }
    }

    reply_ng(CMD_SMART_RAW, PM3_SUCCESS, resp, len);

OUT:
    BigBuf_free();
    set_tracing(false);
    LEDsoff();
}

/*
 * ISO/IEC 7816-3 clause 9 protocol and parameter selection.
 *
 * PPS is only legal in the window straight after the ATR, so the card is reset
 * and its ATR collected first - that also gives the SIM module the interface
 * bytes it needs to time the exchange.  The module answers with
 *
 *      [0] 1 when the card confirmed the request
 *      [1] the protocol now in force
 *      [2] the TA1 (FI/DI) now in force
 *
 * Note that SEND_T1 already runs a PPS on its own when the ATR offers T=1 but
 * names T=0 first, so this is only needed to negotiate Fi/Di explicitly.
 */
void SmartCardPPS(const smart_card_pps_t *p) {

    LED_D_ON();
    set_tracing(true);
    I2C_Reset_EnterMainProgram();

    smart_card_atr_t card;
    s_pps.reapply = false;                // this call is the negotiation
    bool got_atr = GetATR(&card, true);
    s_pps.reapply = true;
    if (got_atr == false) {
        reply_ng(CMD_SMART_PPS, PM3_ETIMEOUT, NULL, 0);
        goto out;
    }

    uint8_t req[2];
    uint16_t reqlen = 1;
    uint8_t want_proto = p->protocol;
    if (want_proto == SC_PPS_PROTO_CARD_DEFAULT) {
        want_proto = SmartCard_ATRFirstProto(card.atr, card.atr_len);
    }

    req[0] = (uint8_t)(want_proto & 0x0F);
    if (p->use_ta1) {
        req[1] = p->ta1;
        reqlen = 2;
    }

    uint8_t resp[3] = {0};
    if (SmartCard_HwPPS(req, reqlen, resp, SIM_WAIT_DELAY) == false) {
        if (g_dbglevel > DBG_DEBUG) {
            DbpString(I2C_ERROR);
        }
        reply_ng(CMD_SMART_PPS, PM3_ESOFT, NULL, 0);
        goto out;
    }

    // resp is [ok][active protocol][ta1 in force].
    //
    // Only a rate is worth remembering. A protocol override is a deliberate
    // one-off - `smart pps` defaults to T=1, so asking for a rate alone
    // switches the card's framing - and making that stick across every later
    // ATR breaks anything that builds T=0 APDUs, the SAM commands included.
    // Leave it to this session and do not cache it.
    if (resp[0] == 1) {

        uint8_t card_proto = SmartCard_ATRFirstProto(card.atr, card.atr_len);

        if (resp[2] == 0x11) {
            sc_pps_forget();                    // back to the default rate

        } else if (resp[1] == card_proto) {
            sc_pps_remember(card.atr, card.atr_len, resp[1], resp[2]);

        } else {
            // rate negotiated alongside a protocol change: honour it now, but
            // do not restore it later behind the user's back
            sc_pps_forget();
            if (g_dbglevel >= DBG_ERROR) {
                Dbprintf("SC: T=%u selected, rate not remembered (card offers T=%u first)",
                         resp[1], card_proto);
            }
        }
    }

    reply_ng(CMD_SMART_PPS, PM3_SUCCESS, resp, 3);

out:
    set_tracing(false);
    LEDsoff();
}

void SmartCardSetClock(uint64_t arg0) {
    LED_D_ON();
    set_tracing(true);
    I2C_Reset_EnterMainProgram();
    // Fsys and the card clock move together, so a negotiated etu stays valid in
    // card clocks - but the reset still wiped the divisor that produces it.
    sc_rate_restore();
    SmartCard_HwSetClock(arg0);
    reply_ng(CMD_SMART_SETCLOCK, PM3_SUCCESS, NULL, 0);
    set_tracing(false);
    LEDsoff();
}

// --- direct transport ------------------------------------------------------
//
// emvsim.c talks to the card itself. Its answer goes back to the reader with
// the caller's prepend byte and a CRC, not through a CMD_SMART_* reply.

// Maximum chained ISO 7816-4 GET RESPONSE (61xx) follow-ups before bailing.
// A misbehaving card that always returns 61xx would otherwise recurse without
// bound, allocating fresh smart_card_raw_t payloads from BigBuf each time
// until the device wedges. Eight rounds is more than any legitimate APDU
// chain would need.
#define SC_DIRECT_MAX_DEPTH 8

static void SmartCardDirectSend(uint8_t prepend, const smart_card_raw_t *p, uint8_t *output, uint16_t *olen, uint8_t depth) {
    LED_D_ON();

    uint16_t len = 0;
    uint8_t *resp = BigBuf_calloc(ISO7816_MAX_FRAME);
    if (resp == NULL) {
        Dbprintf("SmartCardDirectSend: BigBuf_calloc failed");
        if (olen) *olen = 0;
        LEDsoff();
        return;
    }
    resp[0] = prepend;
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

    if (((flags & SC_RAW) == SC_RAW) ||
            ((flags & SC_RAW_T0) == SC_RAW_T0) ||
            ((flags & SC_RAW_T1) == SC_RAW_T1)) {

        if ((flags & SC_WAIT) == SC_WAIT) {
            // see the same conversion in SmartCardRaw()
            uint32_t ms = p->wait_delay;
            if (ms > I2C_WAIT_MAX_MS) {
                ms = I2C_WAIT_MAX_MS;
            }
            wait = I2C_ITERS_FOR_MS(ms);
        }

        LogTrace(p->data, p->len, 0, 0, NULL, true);

        bool res = SmartCard_HwSend(SmartCard_ModeForFlags(flags), p->data, p->len);

        if (res == false) {
            if (g_dbglevel > 3) {
                Dbprintf("SmartCardDirectSend: I2C_BufferWrite failed");
            }
            goto OUT;
        }

        // read bytes from module
        len = ISO7816_MAX_FRAME;
        res = SmartCard_HwRecv(&resp[1], &len, wait);
        if (res) {
            LogTrace(&resp[1], len, 0, 0, NULL, false);
        } else {
            len = 0;
        }
    }

    if (len == 2 && resp[1] == 0x61) {

        if (depth >= SC_DIRECT_MAX_DEPTH) {
            Dbprintf("SmartCardDirectSend: GET RESPONSE chain depth (%u) exceeded; aborting", depth);
            goto OUT;
        }

        uint8_t cmd_getresp[] = {0x00, ISO7816_GET_RESPONSE, 0x00, 0x00, resp[2]};

        smart_card_raw_t *payload = (smart_card_raw_t *)BigBuf_calloc(sizeof(smart_card_raw_t) + sizeof(cmd_getresp));
        if (payload == NULL) {
            Dbprintf("SmartCardDirectSend: GET RESPONSE alloc failed");
            goto OUT;
        }
        payload->flags = SC_RAW | SC_LOG;
        payload->len = sizeof(cmd_getresp);
        payload->wait_delay = 0;
        memcpy(payload->data, cmd_getresp, sizeof(cmd_getresp));

        SmartCardDirectSend(prepend, payload, output, olen, depth + 1);
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
        Dbprintf("Failed to allocate memory");
        return PM3_EMALLOC;
    }

    payload->len = dlen;
    memcpy(payload->data, data, dlen);

    int timeout = 600;

    payload->flags = (SC_LOG | SC_CONNECT | SC_CLEARLOG);
    payload->wait_delay = 0;

    if (timeout > -1) {
        payload->flags |= SC_WAIT;
        payload->wait_delay = timeout;
    }

    if (dlen > 0) {
        payload->flags |= SC_RAW_T0;
    }
    SmartCardDirectSend(prepend, payload, output, olen, 0);

    return PM3_SUCCESS;
}
