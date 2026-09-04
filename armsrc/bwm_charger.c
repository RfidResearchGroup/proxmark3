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
// Proxmark5 BWM charger (AW32001E) + fuel gauge (BQ27427) - see bwm_charger.h.
//-----------------------------------------------------------------------------

#include "bwm_charger.h"

#if defined(WITH_PM5_LOWBATT_SHUTDOWN) && !defined(WITH_BWM_LOWBATT_BEEP)
#error "WITH_PM5_LOWBATT_SHUTDOWN requires WITH_BWM_LOWBATT_BEEP (shares its poll + buzzer)"
#endif

#if defined(WITH_BWM_CHARGERKICK) || defined(WITH_BWM_STATUS)

#include "i2c.h"
#include "dbprint.h"
#include "ticks_apis.h"   // WaitMS / GetTickCount / GetTickCountDelta
#include "ansi.h"

#ifdef WITH_BWM_LOWBATT_BEEP
#include "buzzer.h"        // generic mainboard buzzer API (not BWM-specific)
#endif

#ifdef WITH_PM5_LOWBATT_SHUTDOWN
#include "gpio_apis.h"     // Gpio_ARM_Power_ON_Low (power-latch release)
#include "util.h"          // LEDsoff
#endif

// --- AW32001E charger register map (I2C 8-bit address 0x93) --------------------
#define BWM_CHG_ADDR         0x93
#define BWM_CHG_REG_MAINCTL  0x06   // bit5 = FET_DIS: shipping mode -> VMIX/charge path off
#define BWM_CHG_REG_SYSSTAT  0x08   // system status (CHG_STAT / PG_STAT / THERM_STAT)
#define BWM_CHG_REG_FAULT    0x09   // fault register (latched, read-on-clear)
#define BWM_CHG_FET_DIS      (1u << 5)
#define BWM_CHG_REG_VCHG     0x04   // Charge Voltage: VBAT_REG[7:2], VBAT_PRE[1], VRECH[0]
// AW32001E datasheet V1.2 REG04: VBAT_REG = 3600mV + 15mV*code, [7:2] (POR 0x28=4.200V)
#define BWM_CHG_VCHG_BASE_MV 3600
#define BWM_CHG_VCHG_STEP_MV 15
#define BWM_CHG_VCHG_MASK    0xFC   // REG04[7:2]
#define BWM_CHG_VCHG_SHIFT   2
#define BWM_CHG_VCHG_MIN_MV  3600
#define BWM_CHG_VCHG_MAX_MV  4200   // firmware safety ceiling (chip allows 4545)

// --- BQ27427 fuel gauge (I2C 8-bit address 0xAA = 7-bit 0x55 << 1) -------------
#define BWM_GAUGE_ADDR       0xAA
// Standard commands (16-bit, little-endian)
#define BWM_GAUGE_TEMP       0x02   // 0.1 K
#define BWM_GAUGE_VOLTAGE    0x04   // mV
#define BWM_GAUGE_REMCAP     0x0C   // mAh
#define BWM_GAUGE_FCC        0x0E   // mAh, FullChargeCapacity (health: FCC/design cap)
#define BWM_GAUGE_CURRENT    0x10   // signed mA
#define BWM_GAUGE_SOC        0x1C   // %

#endif // WITH_BWM_CHARGERKICK || WITH_BWM_STATUS

#ifdef WITH_BWM_CHARGERKICK
// Emergency charge-enable. Normal PM5 firmware never touches the charger, so a BWM
// left in shipping/FET-disabled mode won't take charge even with USB present. This
// wakes the power path at boot so the AW32001 can charge autonomously.
//
// SCOPE: runs from AppMain(), i.e. only once the PM5 has actually booted. It cannot
// help a cell too flat to boot (that needs USB reaching VUSBIN in hardware), and it
// cannot reroute VBUS to the charger input. It only ensures that when the charger
// HAS input, its path is enabled.
void bwm_charger_kick(void) {
    StartTicks();
    I2C_init(true);
    WaitMS(2);   // let the bus settle

    uint8_t v = 0;
    // No ACK -> BWM absent or charger dead. Nothing to do; leave the bus and return.
    if (I2C_BufferReadRaw(&v, 1, BWM_CHG_REG_MAINCTL, BWM_CHG_ADDR) <= 0) {
        return;
    }

    // Shipping / FET-disabled -> clear it so the power/charge path comes alive.
    if (v & BWM_CHG_FET_DIS) {
        uint8_t nv = v & ~BWM_CHG_FET_DIS;
        if (I2C_BufferWrite(&nv, 1, BWM_CHG_REG_MAINCTL, BWM_CHG_ADDR)) {
            Dbprintf("[BWM] charger was FET-disabled (0x%02x) - path re-enabled", v);
        } else {
            Dbprintf(_RED_("[BWM] charger FET-disabled; re-enable write failed"));
        }
    }
}
#endif // WITH_BWM_CHARGERKICK

#ifdef WITH_BWM_STATUS
// BWM battery telemetry for `hw status`.
// The BQ27427 address/commands and the current-sign convention are the TI standard
// set - confirm against a known-charging module before trusting absolute values. If
// the gauge or charger doesn't ACK, the corresponding lines print "not responding"
// rather than reporting garbage, so this is safe to ship even if an address is wrong
// on a given board.
static bool g_bwm_present = false;

static bool bwm_gauge_read16(uint8_t cmd, uint16_t *out) {
    uint8_t d[2] = {0};
    if (I2C_BufferReadRaw(d, 2, cmd, BWM_GAUGE_ADDR) <= 0) {
        return false;
    }
    *out = (uint16_t)(d[0] | (d[1] << 8)); // little-endian
    return true;
}

static bool bq_read_design_cap(uint16_t *cap);   // fwd decl (defined with the provisioning code below)

// Reads the BWM charger + fuel gauge and prints a battery section. Called from
// SendStatus() under #ifdef PM5, so it only runs on a booted PM5 with I2C available.
void bwm_print_battery_status(void) {
    if (g_bwm_present == false) {
        return;   // no BWM detected at boot; nothing to report
    }
    DbpString(_CYAN_("Battery / BWM"));

    StartTicks();
    I2C_init(true);
    WaitMS(2);   // let the bus settle

    // --- charger (AW32001) ---
    // REG09 (Fault) latches faults and is read-on-clear: read it TWICE - the 1st read
    // returns the latched history, the 2nd returns the live state (datasheet: "read
    // REG09 two times consecutively"). Bits [7:6] are the EN_SHIPPING_DGL config field,
    // not faults, so mask to 0x3F. Fault bit map (AW32001E REG09H):
    //   b5 VIN_FAULT  b4 THERM_SD  b3 BAT_OVP  b2 SAFETY_TMR  b1 NTC_HOT  b0 NTC_COLD
    uint8_t mainctl = 0, f1 = 0, fault = 0, sysstat = 0;
    if (I2C_BufferReadRaw(&mainctl, 1, BWM_CHG_REG_MAINCTL, BWM_CHG_ADDR) <= 0) {
        Dbprintf("  Charger............. " _YELLOW_("not responding") " (BWM absent or I2C down)");
    } else {
        Dbprintf("  Charger MainCtl..... 0x%02x  %s", mainctl,
                 (mainctl & BWM_CHG_FET_DIS) ? _RED_("FET_DIS (VMIX off / shipping)")
                 : _GREEN_("power path enabled"));

        I2C_BufferReadRaw(&f1,    1, BWM_CHG_REG_FAULT, BWM_CHG_ADDR); // 1st = latched history
        I2C_BufferReadRaw(&fault, 1, BWM_CHG_REG_FAULT, BWM_CHG_ADDR); // 2nd = current state
        fault &= 0x3F;

        if (fault == 0) {
            Dbprintf("  Charger fault....... 0x00 (none)");
        } else {
            Dbprintf("  Charger fault....... " _RED_("0x%02x") "%s%s%s%s%s%s", fault,
                     (fault & 0x20) ? " VIN_FAULT"  : "",
                     (fault & 0x10) ? " THERM_SD"   : "",
                     (fault & 0x08) ? " BAT_OVP"    : "",
                     (fault & 0x04) ? " SAFETY_TMR" : "",
                     (fault & 0x02) ? " NTC_HOT"    : "",
                     (fault & 0x01) ? " NTC_COLD"   : "");
        }

        // Live charge state from REG08 (System Status): CHG_STAT[4:3], PG_STAT[1], THERM_STAT[0]
        if (I2C_BufferReadRaw(&sysstat, 1, BWM_CHG_REG_SYSSTAT, BWM_CHG_ADDR) > 0) {
            static const char *cs[] = { "not charging", "pre-charge", "charging", "charge done" };
            Dbprintf("  Charge status....... %s%s%s", cs[(sysstat >> 3) & 0x03],
                     (sysstat & 0x02) ? ", power good" : ", power fail",
                     (sysstat & 0x01) ? ", thermal-reg" : "");
        }

        // Configured charge profile (read-only). Decode tables from AW32001E datasheet V1.4:
        //   IIN_LIM (REG00[3:0]): 0000=50mA, else 80mA + 30mA*(code-1)  [1111=500mA]
        //   VIN_DPM (REG00[7:4]): 3880mV + 80mV*code                    [1000=4.52V default]
        //   ICHG    (REG02[5:0]): 8mA * (code+1)                        [63=512mA]
        uint8_t reg00 = 0, reg01 = 0, reg02 = 0;
        if (I2C_BufferReadRaw(&reg00, 1, 0x00, BWM_CHG_ADDR) > 0) {
            uint8_t iin = reg00 & 0x0F;
            uint8_t vdpm = (reg00 >> 4) & 0x0F;
            uint16_t iin_ma = (iin == 0) ? 50 : (80 + 30 * (iin - 1));
            uint16_t vdpm_mv = 3880 + 80 * vdpm;
            Dbprintf("  Input limit......... %u mA, VIN_DPM %u mV", iin_ma, vdpm_mv);
        }
        if (I2C_BufferReadRaw(&reg01, 1, 0x01, BWM_CHG_ADDR) > 0) {
            Dbprintf("  Charge enable....... %s", (reg01 & (1u << 3)) ? _YELLOW_("disabled") : _GREEN_("enabled"));
        }
        if (I2C_BufferReadRaw(&reg02, 1, 0x02, BWM_CHG_ADDR) > 0) {
            uint16_t ichg_ma = 8 * ((reg02 & 0x3F) + 1);
            Dbprintf("  Charge current...... %u mA", ichg_ma);
        }
        uint8_t reg04 = 0;
        if (I2C_BufferReadRaw(&reg04, 1, BWM_CHG_REG_VCHG, BWM_CHG_ADDR) > 0) {
            // VBAT_REG (REG04[7:2]): 3600mV + 15mV*code  [101000=4.200V default]
            uint16_t vchg_mv = BWM_CHG_VCHG_BASE_MV + ((reg04 >> BWM_CHG_VCHG_SHIFT) & 0x3F) * BWM_CHG_VCHG_STEP_MV;
            Dbprintf("  Charge voltage...... %u mV", vchg_mv);
        }
    }

    // --- fuel gauge (BQ27427) ---
    uint16_t soc = 0, mv = 0, rem = 0, temp = 0, raw_i = 0;
    if (bwm_gauge_read16(BWM_GAUGE_SOC, &soc) && bwm_gauge_read16(BWM_GAUGE_VOLTAGE, &mv)) {
        bwm_gauge_read16(BWM_GAUGE_REMCAP, &rem);
        bwm_gauge_read16(BWM_GAUGE_TEMP, &temp);
        bwm_gauge_read16(BWM_GAUGE_CURRENT, &raw_i);

        int16_t cur = (int16_t)raw_i;      // +charge / -discharge (verify polarity on hw)
        int tempC10 = (int)temp - 2732;    // 0.1 K -> 0.1 C
        int tabs = (tempC10 < 0) ? -tempC10 : tempC10;

        Dbprintf("  Battery SoC......... %u %%", soc);
        Dbprintf("  Battery voltage..... %u mV", mv);
        Dbprintf("  Battery current..... %d mA %s", cur,
                 (cur > 5)  ? _GREEN_("(charging)") :
                 (cur < -5) ? _YELLOW_("(discharging)") : "(idle)");
        Dbprintf("  Remaining capacity.. %u mAh", rem);
        // Measured drain / projected runtime: when running on battery the gauge
        // Current is negative (discharging); |cur| is the real system draw, so
        // remaining runtime ~= RemainingCapacity / draw. Only meaningful while
        // discharging - on charge or idle there is no drain figure to report.
        // (Projection is only as good as RemCap - provision Design Capacity first.)
        if (cur < -5) {
            uint16_t draw = (uint16_t)(-cur);            // mA drawn from the battery
            uint32_t mins = ((uint32_t)rem * 60) / draw; // RemCap/draw -> hours, *60 -> mins
            Dbprintf("  Battery drain....... %u mA (approx %u h %u min left)",
                     draw, (unsigned)(mins / 60), (unsigned)(mins % 60));
        }
        Dbprintf("  Temp (gauge)........ %d.%d C", tempC10 / 10, tabs % 10);

        // Battery health: FullChargeCapacity (0x0E) vs the gauge's programmed Design
        // Capacity. FCC is the gauge's learned present full capacity; health = FCC/design.
        // NOTE: only meaningful once the gauge has run an Impedance Track learning cycle
        // (a full charge/discharge). Before that it is an unconverged estimate. If Design
        // Capacity was never provisioned (hw bwmsetcap), the ratio is against the gauge
        // default, not the fitted cell - so it can read wildly wrong.
        uint16_t fcc = 0, design = 0;
        if (bwm_gauge_read16(BWM_GAUGE_FCC, &fcc) && fcc > 0) {
            if (bq_read_design_cap(&design) == false || design == 0) {
                design = BWM_DEFAULT_DESIGN_CAP_MAH;   // fall back to the fitted-cell rating
            }
            unsigned health = (unsigned)(((uint32_t)fcc * 100) / design);
            Dbprintf("  Full charge cap..... %u mAh (design %u)", fcc, design);
            Dbprintf("  Battery health...... %u", health);
        }
    } else {
        Dbprintf("  Fuel gauge.......... " _YELLOW_("not responding") " (BQ27427 absent or I2C down)");
    }
}

// --- BQ27427 provisioning: set Design Capacity for the fitted cell -------------
// One-time. The gauge ships with a ~1000+ mAh default profile, so RemainingCapacity
// reads wrong for the fitted pack until Design Capacity is programmed. Invoked by the
// `hw bwmsetcap` client command (CMD_PM5_BWM_SET_CAP) - deliberately NOT run at boot,
// because a config-update cycle disrupts the Impedance Track learning cycle.
// Per BQ27427 TRM (SLUUCD5): State subclass 82 (0x52), Design Capacity at offset 6
// -> block addr 0x46 (MSB)/0x47 (LSB), big-endian. Assumes gauge UNSEALED (factory default).

static bool bq_control(uint16_t sub) {
    uint8_t d[2] = { (uint8_t)(sub & 0xFF), (uint8_t)(sub >> 8) };
    return I2C_BufferWrite(d, 2, 0x00, BWM_GAUGE_ADDR);       // Control() 0x00
}
static bool bq_flags(uint16_t *f) {
    uint8_t d[2] = {0};
    if (I2C_BufferReadRaw(d, 2, 0x06, BWM_GAUGE_ADDR) <= 0) return false;
    *f = (uint16_t)(d[0] | (d[1] << 8));                      // Flags() 0x06
    return true;
}
static bool bq_select_state_block(void) {
    uint8_t v;
    v = 0x00;
    if (!I2C_BufferWrite(&v, 1, 0x61, BWM_GAUGE_ADDR)) return false; // BlockDataControl
    v = 0x52;
    if (!I2C_BufferWrite(&v, 1, 0x3E, BWM_GAUGE_ADDR)) return false; // DataClass = 82 (State)
    v = 0x00;
    if (!I2C_BufferWrite(&v, 1, 0x3F, BWM_GAUGE_ADDR)) return false; // DataBlock = 0
    WaitMS(5);
    return true;
}
static bool bq_read_design_cap(uint16_t *cap) {
    if (!bq_select_state_block()) return false;
    uint8_t d[2] = {0};
    if (I2C_BufferReadRaw(d, 2, 0x46, BWM_GAUGE_ADDR) <= 0) return false;
    *cap = (uint16_t)((d[0] << 8) | d[1]);                    // big-endian
    return true;
}

// Enable or disable battery charging by clearing/setting CEB (REG01[3]:
// 0 = charge enabled, 1 = charge disabled). Read-modify-write to preserve the
// other REG01 fields. NOTE: REG01 is watchdog-affected on the AW32001E - this
// reverts to its default on watchdog expiry (~160 s) unless the watchdog is
// serviced (REG02[6]=1) or disabled (REG05[6:5]=00), so treat it as a one-shot.
bool bwm_charger_set_charge(bool enable) {
    uint8_t reg01 = 0;
    if (I2C_BufferReadRaw(&reg01, 1, 0x01, BWM_CHG_ADDR) <= 0) {
        return false;
    }
    if (enable) {
        reg01 &= ~(1u << 3);   // CEB = 0 -> charge enabled
    } else {
        reg01 |= (1u << 3);    // CEB = 1 -> charge disabled
    }
    return I2C_BufferWrite(&reg01, 1, 0x01, BWM_CHG_ADDR);
}

// Set the charge-voltage regulation target (AW32001E REG04 VBAT_REG, bits [7:2]).
// Clamps to 3600..4200 mV (the chip allows up to 4545, but we cap the ceiling in
// firmware so a stray value can't over-stress the cell), rounds to the nearest
// 15 mV step, and preserves REG04[1:0] (VBAT_PRE / VRECH). Read-modify-write.
// Returns the mV actually applied, or 0 on I2C failure.
uint16_t bwm_charger_set_vchg(uint16_t mv) {
    if (mv < BWM_CHG_VCHG_MIN_MV) {
        mv = BWM_CHG_VCHG_MIN_MV;
    }
    if (mv > BWM_CHG_VCHG_MAX_MV) {
        mv = BWM_CHG_VCHG_MAX_MV;
    }
    uint16_t code = (uint16_t)(((mv - BWM_CHG_VCHG_BASE_MV) + (BWM_CHG_VCHG_STEP_MV / 2)) / BWM_CHG_VCHG_STEP_MV);
    if (code > 0x3F) {
        code = 0x3F;   // 6-bit field
    }
    uint8_t reg04 = 0;
    if (I2C_BufferReadRaw(&reg04, 1, BWM_CHG_REG_VCHG, BWM_CHG_ADDR) <= 0) {
        return 0;
    }
    reg04 = (uint8_t)((reg04 & ~BWM_CHG_VCHG_MASK) | ((code << BWM_CHG_VCHG_SHIFT) & BWM_CHG_VCHG_MASK));
    if (I2C_BufferWrite(&reg04, 1, BWM_CHG_REG_VCHG, BWM_CHG_ADDR) == false) {
        return 0;
    }
    return (uint16_t)(BWM_CHG_VCHG_BASE_MV + code * BWM_CHG_VCHG_STEP_MV);
}

// Program Design Capacity (and matching Design Energy). Idempotent: returns true
// without a config-update cycle if the value is already correct.
bool bwm_gauge_provision_capacity(uint16_t cap_mah) {

    uint16_t cur = 0;
    if (bq_read_design_cap(&cur) && cur == cap_mah) {
        return true;    // already correct - do NOT run another CFGUPDATE cycle
    }
    uint16_t energy_mwh = (uint16_t)(((uint32_t)cap_mah * 37) / 10);   // ~3.7 V nominal

    // Enter CONFIG_UPDATE and wait for the gauge to acknowledge it.
    if (bq_control(0x0013) == false) {   // SET_CFGUPDATE
        return false;
    }

    uint16_t flags = 0;
    int tries = 0;
    do {
        WaitMS(50);
        if (bq_flags(&flags) == false) {
            return false;
        }
    } while (((flags & 0x0010) == 0) && (++tries < 40));   // wait for CFGUPDATE (Flags bit 4), ~2 s

    if ((flags & 0x0010) == 0) {
        return false;
    }

    if (!bq_select_state_block()) return false;

    uint8_t blk[32] = {0};
    if (I2C_BufferReadRaw(blk, 32, 0x40, BWM_GAUGE_ADDR) <= 0) return false;

    blk[6] = (uint8_t)(cap_mah >> 8);
    blk[7] = (uint8_t)(cap_mah & 0xFF);      // DesignCapacity
    blk[8] = (uint8_t)(energy_mwh >> 8);
    blk[9] = (uint8_t)(energy_mwh & 0xFF);   // DesignEnergy
    I2C_BufferWrite(&blk[6], 2, 0x46, BWM_GAUGE_ADDR);
    I2C_BufferWrite(&blk[8], 2, 0x48, BWM_GAUGE_ADDR);

    uint16_t sum = 0;                                         // block checksum = 255 - (sum mod 256)
    for (int i = 0; i < 32; i++) sum += blk[i];
    uint8_t csum = (uint8_t)(0xFF - (uint8_t)(sum & 0xFF));
    I2C_BufferWrite(&csum, 1, 0x60, BWM_GAUGE_ADDR);          // commit block
    WaitMS(10);

    if (!bq_control(0x0042)) return false;                    // SOFT_RESET (exit CFGUPDATE)
    tries = 0;
    do { WaitMS(50); if (!bq_flags(&flags)) return false; }
    while (((flags & 0x0010) != 0) && (++tries < 40));
    return ((flags & 0x0010) == 0);
}

// Enable battery charging on the BWM by replicating the charger register writes
// from at32_unit_test.c:test_bat_charger_only_settings() (upstream RRG values),
// WITHOUT pulling in that file's unrelated UART-debug / RGB test routines.
// AW32001E @ 0x93:
//   REG01[3] CEB  -> 0    : charge enabled
//   REG02    ICHG =  0x1F : 256 mA charge current
//   REG05         =  0x1A : safety timer disabled (upstream)
//   REG03         =  0xE1 : 3 A discharge current
//   REG0B         =  0x6B : 11 mA pre-charge current
//
// Probe for the BWM charger over I2C and, if found, apply the charge configuration.
void bwm_detect_and_init(void) {
    StartTicks();
    I2C_init(true);

    // Single bounded probe. Any non-ACK => no BWM fitted; skip everything.
    uint8_t v = 0;
    if (I2C_BufferReadRaw(&v, 1, 0x01, BWM_CHG_ADDR) <= 0) {
        g_bwm_present = false;
        return;
    }
    g_bwm_present = true;

    // Enable charging (clear CEB, REG01[3]) + upstream charge profile
    // (matches at32_unit_test.c:test_bat_charger_only_settings(), AW32001ECSR).
    if (v & (1u << 3)) {
        v &= ~(1u << 3);
        I2C_BufferWrite(&v, 1, 0x01, BWM_CHG_ADDR);
    }
    uint8_t w;
    w = 0x1F;
    I2C_BufferWrite(&w, 1, 0x02, BWM_CHG_ADDR); // charge current 256 mA
    w = 0xE1;
    I2C_BufferWrite(&w, 1, 0x03, BWM_CHG_ADDR); // discharge current 3 A
    w = 0x1A;
    I2C_BufferWrite(&w, 1, 0x05, BWM_CHG_ADDR); // safety timer disabled (upstream)
    w = 0x6B;
    I2C_BufferWrite(&w, 1, 0x0B, BWM_CHG_ADDR); // pre-charge 11 mA

    // Pin the charge-voltage target (chip POR is 4.2V); default 4100 -> 4.095V.
    bwm_charger_set_vchg(BWM_DEFAULT_VCHG_MV);
}
#endif // WITH_BWM_STATUS

#ifdef WITH_BWM_LOWBATT_BEEP
#ifndef WITH_BWM_STATUS
#error "WITH_BWM_LOWBATT_BEEP requires WITH_BWM_STATUS (for the fuel-gauge reads)"
#endif

// Low-battery audible warning (on by default; opt out with PLATFORM_EXTRAS=NO_LOWBATT_BEEP).
// Reuses the WITH_BWM_STATUS fuel-gauge/charger reads and the generic mainboard buzzer.

// Thresholds - all overridable from the build if needed.
#ifndef BWM_LOWBATT_SOC_PCT
#define BWM_LOWBATT_SOC_PCT    10      // warn at or below this state-of-charge (%)
#endif
#ifndef BWM_LOWBATT_MV
#define BWM_LOWBATT_MV         3500    // ...and only if pack voltage is under this (mV)
#endif
#ifndef BWM_LOWBATT_PERIOD_MS
#define BWM_LOWBATT_PERIOD_MS  30000   // re-check at most this often
#endif

#ifdef WITH_PM5_LOWBATT_SHUTDOWN
// Critical shutdown floors (opt-in via WITH_PM5_LOWBATT_SHUTDOWN). Sits BELOW the
// warn thresholds above so the beep fires first. Voltage is the hard gate: the
// BQ27427 learns a FullChargeCapacity (~415 mAh on the fitted VXE 502540) below the
// 500 mAh design rating, so SoC over-reports and is only a secondary trigger here.
#ifndef BWM_SHUTDOWN_MV
#define BWM_SHUTDOWN_MV        3300    // power off at/under this pack voltage (mV, under load)
#endif
#ifndef BWM_SHUTDOWN_SOC_PCT
#define BWM_SHUTDOWN_SOC_PCT   3       // ...or at/under this SoC (%) - secondary, gauge may drift
#endif
#ifndef BWM_SHUTDOWN_CONFIRMATIONS
#define BWM_SHUTDOWN_CONFIRMATIONS 3   // consecutive critical polls before power-off (debounce HF-field sag)
#endif
#endif // WITH_PM5_LOWBATT_SHUTDOWN

// Two short chirps - the low-battery signature.
static void bwm_beep_low_batt(void) {
    BuzzerBeep(80);
    SpinDelay(80);
    BuzzerBeep(80);
}

// Throttled low-battery poll. Only warns on battery (USB absent) when BOTH the
// state-of-charge and the pack voltage are below their floors. Silent while
// charging or if the BWM/gauge is not present. With WITH_PM5_LOWBATT_SHUTDOWN it
// also powers the board off once the pack drops to the critical floor, confirmed
// across several consecutive polls so a transient HF-field sag can't trip it.
void bwm_lowbatt_check(void) {
    static uint32_t last_tick = 0;
#ifdef WITH_PM5_LOWBATT_SHUTDOWN
    static uint8_t crit = 0;
    static bool s_vusb_setup = false;
#endif

    if ((last_tick != 0) && (GetTickCountDelta(last_tick) < BWM_LOWBATT_PERIOD_MS)) {
        return;
    }
    last_tick = GetTickCount();

    StartTicks();
    I2C_init(true);

    uint8_t sysstat = 0;
    if (I2C_BufferReadRaw(&sysstat, 1, BWM_CHG_REG_SYSSTAT, BWM_CHG_ADDR) <= 0) {
        return;   // no BWM / I2C error - stay quiet
    }
    if (sysstat & 0x02) {
#ifdef WITH_PM5_LOWBATT_SHUTDOWN
        crit = 0;   // power good (USB present): charging -> reset the shutdown streak
#endif
        return;   // power good (USB present) -> charging/idle, don't warn
    }

    uint16_t soc = 0, mv = 0;
    if ((bwm_gauge_read16(BWM_GAUGE_SOC, &soc) == false) ||
            (bwm_gauge_read16(BWM_GAUGE_VOLTAGE, &mv) == false)) {
        return;
    }

#ifdef WITH_PM5_LOWBATT_SHUTDOWN
    // Critical: voltage-primary, SoC secondary. Require BWM_SHUTDOWN_CONFIRMATIONS
    // consecutive sub-floor polls, then latch power off (same release as the
    // long-press shutdown; a button press powers back on, in hardware).
    // voltage-primary; SoC can only *corroborate* (it over-reads on an
    // uncalibrated gauge - e.g. <3% reported at 3.6 V). Never let SoC alone
    // trigger power-off: require the pack to also be in the low-batt zone.
    if ((mv <= BWM_SHUTDOWN_MV) ||
            ((soc <= BWM_SHUTDOWN_SOC_PCT) && (mv <= BWM_LOWBATT_MV))) {
        if (++crit >= BWM_SHUTDOWN_CONFIRMATIONS) {
            // Confirm on the VUSB pin, not the charger PG bit: PG can read
            // "power fail" on USB under load, so only power off if USB is really out.
            if (s_vusb_setup == false) {
                gpio_vusb_setup();
                s_vusb_setup = true;
            }
            if (Gpio_VUSB_Read()) {
                crit = 0;          // USB present, not a real drain
            } else {
                Dbprintf(_RED_("[BWM] critical battery %u mV / %u%% - powering off"), mv, soc);
                bwm_beep_low_batt();   // last warning before cut-off
                LEDsoff();
                Gpio_ARM_Power_ON_Low();
                while (1);             // wait for power-off
            }
        }
    } else {
        crit = 0;                  // recovered above the floor -> reset the streak
    }
#endif

    if ((soc > BWM_LOWBATT_SOC_PCT) || (mv >= BWM_LOWBATT_MV)) {
        return;   // still healthy
    }

    bwm_beep_low_batt();   // BuzzerBeep() lazily sets the buzzer up on first use
}
#endif // WITH_BWM_LOWBATT_BEEP
