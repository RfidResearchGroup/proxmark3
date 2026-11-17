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
#include "i2c.h"

#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "ticks_apis.h"
#include "dbprint.h"
#include "util.h"
#include "string.h"

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

// Reset the SIM_Adapter, then enter the bootloader program
// Reserve for firmware update.
void I2C_Reset_EnterBootloader(void) {
    StartTicks();
    SmartCard_HwOpenBootloader();
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
    return SmartCard_HwModuleInfo(major, minor, info);
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

// ISO 7816-3 clause 8: offered protocols are the low nibbles of the TDi bytes.
// No TD1 means T=0 only. T=15 is global interface bytes, not a protocol.
static uint8_t atr_protocols(const uint8_t *atr, uint8_t len) {

    if (len < 2) {
        return 0;
    }

    uint8_t y = (uint8_t)(atr[1] >> 4);      // T0
    uint8_t i = 2;
    uint8_t mask = 0;

    while (y) {

        if (y & 0x01) i++;                   // TA(i)
        if (y & 0x02) i++;                   // TB(i)
        if (y & 0x04) i++;                   // TC(i)

        if ((y & 0x08) == 0) {
            break;                           // no TD(i), nothing further named
        }
        if (i >= len) {
            break;                           // truncated ATR
        }

        uint8_t td = atr[i++];
        uint8_t t = (uint8_t)(td & 0x0F);
        if (t < 8) {
            mask |= (uint8_t)(1u << t);
        }
        y = (uint8_t)(td >> 4);
    }

    if (mask == 0) {
        mask = SC_PROTO_T0;                  // clause 8.2.3
    }
    return mask;
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

// The protocol of TD1, which is what the card runs if nothing is negotiated.
static uint8_t atr_first_proto(const uint8_t *atr, uint8_t len) {
    if ((len < 2) || ((atr[1] & 0x80) == 0)) {
        return 0;
    }
    uint8_t i = 2;
    if (atr[1] & 0x10) i++;
    if (atr[1] & 0x20) i++;
    if (atr[1] & 0x40) i++;
    return (i < len) ? (uint8_t)(atr[i] & 0x0F) : 0;
}

// The fastest rate worth proposing to a card, or 0 for none.
//
// Two rules keep this safe, both learned on the bench rather than assumed:
//
//   - Keep the Fi the card advertised and only lower Di. Proposing a different
//     Fi is refused: a SAM advertising Fi=512 took the whole Fi=512 family and
//     rejected every Fi=768/1024/1536/2048 offer.
//   - R = Fi / (16 * Di) is the module's UART reload. It has to be a whole
//     number or the sampling point drifts - that is the +3.2% which makes
//     Fi=372 unusable beyond Di=1 - and it must not fall below the floor.
//
// The floor is measured, not guessed. It was 8 while the module still waited
// out a turnaround guard before listening, which cost it the second byte of
// every answer above 31250 bit/s. With that guard applied only before
// transmitting (module v4.62), R=2 (125000 bit/s) is clean over repeated runs
// and R=1 still is not: at 16 clocks per etu a character is 192 instruction
// cycles, and the receive loop does not fit in that.
//
// A card with no TA1 offers nothing but the default, so nothing is proposed.
#define SC_PPS_MIN_RELOAD  2

// ISO/IEC 7816-3 tables 7 and 8. 0 marks an RFU entry, which nothing may use.
static const uint16_t s_fi_tab[16] = {372, 372, 558, 744, 1116, 1488, 1860, 0,
                                      0, 512, 768, 1024, 1536, 2048, 0, 0
                                     };
static const uint8_t s_di_tab[16] = {0, 1, 2, 4, 8, 16, 32, 64, 12, 20, 0, 0, 0, 0, 0, 0};

// The module's UART reload for a TA1, or 0 when the pair is unusable. Same
// arithmetic as UART_Set_FiDi() in the module firmware: R = Fi / (16 * Di),
// which has to come out whole or the sampling point drifts across a character.
static uint16_t sc_ta1_reload(uint8_t ta1) {

    uint16_t f = s_fi_tab[(ta1 >> 4) & 0x0F];
    uint8_t  d = s_di_tab[ta1 & 0x0F];

    if ((f == 0) || (d == 0)) {
        return 0;
    }
    if ((f % (uint16_t)(16u * d)) != 0) {
        return 0;
    }
    return (uint16_t)(f / (uint16_t)(16u * d));
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

    uint16_t r = sc_ta1_reload(s_pps.ta1);
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

static uint8_t sc_pps_best_ta1(const uint8_t *atr, uint8_t len) {

    if ((len < 3) || ((atr[1] & 0x10) == 0)) {
        return 0;                       // no TA1 - default only
    }

    uint8_t fi_idx = (uint8_t)((atr[2] >> 4) & 0x0F);
    uint16_t f = s_fi_tab[fi_idx];
    if (f == 0) {
        return 0;                       // RFU
    }

    uint8_t best = 0;
    uint16_t best_clocks = 372;         // has to beat the default to be worth it

    for (uint8_t di_idx = 1; di_idx < 16; di_idx++) {

        uint8_t d = s_di_tab[di_idx];
        if (d == 0) {
            continue;
        }
        if ((f % (uint16_t)(16u * d)) != 0) {
            continue;                   // divisor is not exact, the etu would drift
        }
        if ((f / (uint16_t)(16u * d)) < SC_PPS_MIN_RELOAD) {
            continue;                   // faster than the module can receive
        }

        uint16_t clocks = (uint16_t)(f / d);
        if (clocks >= best_clocks) {
            continue;
        }
        best_clocks = clocks;
        best = (uint8_t)((fi_idx << 4) | di_idx);
    }

    return best;
}

static bool sc_pps(uint8_t proto, uint8_t ta1) {
    uint8_t req[2] = { (uint8_t)(proto & 0x0F), ta1 };
    uint8_t resp[3] = {0};
    if (SmartCard_HwPps(req, sizeof(req), resp, SIM_WAIT_DELAY) == false) {
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
    if (SmartCard_HwAtr(card_ptr->atr, &len, SIM_WAIT_DELAY) == false) {
        return false;
    }

    if (len > sizeof(card_ptr->atr)) {
        len = sizeof(card_ptr->atr);
    }

    uint8_t pos_td = 1;
    if ((card_ptr->atr[1] & 0x10) == 0x10) pos_td++;
    if ((card_ptr->atr[1] & 0x20) == 0x20) pos_td++;
    if ((card_ptr->atr[1] & 0x40) == 0x40) pos_td++;

    // T0 indicate presence T=0 vs T=1.  T=1 has checksum TCK
    if ((card_ptr->atr[1] & 0x80) == 0x80) {

        pos_td++;

        // 1 == T1 ,  presence of checksum TCK
        if ((card_ptr->atr[pos_td] & 0x01) == 0x01) {

            uint8_t chksum = 0;
            // xor property.  will be zero when xored with chksum.
            for (uint16_t i = 1; i < len; ++i)
                chksum ^= card_ptr->atr[i];

            if (chksum) {
                if (g_dbglevel > DBG_INFO) DbpString("Wrong ATR checksum");
            }
        }
    }

    card_ptr->atr_len = (uint8_t)(len & 0xff);

    s_card_protocols = atr_protocols(card_ptr->atr, card_ptr->atr_len);
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
                 , atr_first_proto(card_ptr->atr, card_ptr->atr_len)
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

            uint8_t want_proto = atr_first_proto(card_ptr->atr, card_ptr->atr_len);
            uint8_t want = sc_pps_best_ta1(card_ptr->atr, card_ptr->atr_len);

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

void SmartCardAtr(void) {
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

void SmartCardUpgrade(uint64_t arg0) {

    LED_C_ON();

#define I2C_BLOCK_SIZE 128
    // write.   Sector0,  with 11,22,33,44
    // erase is 128bytes, and takes 50ms to execute

    I2C_Reset_EnterBootloader();

    bool isOK = true;
    uint16_t length = arg0, pos = 0;
    const uint8_t *fwdata = BigBuf_get_addr();
    uint8_t *verifydata = BigBuf_calloc(I2C_BLOCK_SIZE);
    if (verifydata == NULL) {
        reply_ng(CMD_SMART_UPGRADE, PM3_EMALLOC, NULL, 0);
        LED_C_OFF();
        return;
    }

    while (length) {

        uint8_t msb = (pos >> 8) & 0xFF;
        uint8_t lsb = pos & 0xFF;

        Dbprintf("FW %02X%02X", msb, lsb);

        size_t size = MIN(I2C_BLOCK_SIZE, length);

        // write
        int16_t res = SmartCard_HwModuleWrite(fwdata + pos, size, msb, lsb, I2C_DEVICE_ADDRESS_BOOT);
        if (!res) {
            Dbprintf("Writing failed at offset 0x%04X", pos);
            isOK = false;
            break;
        }

        // writing takes time.
        WaitMS(50);

        // read
        res = SmartCard_HwModuleRead(verifydata, size, msb, lsb, I2C_DEVICE_ADDRESS_BOOT);
        if (res <= 0) {
            Dbprintf("Reading back failed at offset 0x%04X", pos);
            isOK = false;
            break;
        }

        // cmp
        if (0 != memcmp(fwdata + pos, verifydata, size)) {
            Dbprintf("Verify mismatch at offset 0x%04X", pos);
            isOK = false;
            break;
        }

        length -= size;
        pos += size;
    }

    reply_ng(CMD_SMART_UPGRADE, (isOK) ? PM3_SUCCESS : PM3_ESOFT, NULL, 0);
    LED_C_OFF();
    BigBuf_free();
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
        want_proto = atr_first_proto(card.atr, card.atr_len);
    }

    req[0] = (uint8_t)(want_proto & 0x0F);
    if (p->use_ta1) {
        req[1] = p->ta1;
        reqlen = 2;
    }

    uint8_t resp[3] = {0};
    if (SmartCard_HwPps(req, reqlen, resp, SIM_WAIT_DELAY) == false) {
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

        uint8_t card_proto = atr_first_proto(card.atr, card.atr_len);

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
