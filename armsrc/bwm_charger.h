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
// Proxmark5 BWM (Battery Wireless Module) power subsystem.
//
// Charger : AW32001E  @ I2C 0x93 (8-bit form the I2C_* API uses)
// Fuel gauge: BQ27427 @ I2C 7-bit 0x55 (0xAA 8-bit)
//
// Everything here is opt-in via the WITH_BWM_* build flags and only meaningful
// on PLATFORM=PM5 (AT32F435) with a BWM fitted. If the BWM/charger/gauge does
// not ACK on I2C, each entry point degrades gracefully rather than reporting
// garbage.
//-----------------------------------------------------------------------------

#ifndef __BWM_CHARGER_H
#define __BWM_CHARGER_H

#include "common.h"

// Reference design capacity for the fitted cell (VXE 502540, 500 mAh / 3.7 V).
// Used as the default target for `hw bwm setcap` and as the fall-back divisor for
// the battery-health estimate.
#define BWM_DEFAULT_DESIGN_CAP_MAH   500
#define BWM_DEFAULT_VCHG_MV          4100   // default charge-voltage target (mV); snaps to 4095 (15mV step)

#ifdef WITH_BWM_CHARGERKICK
// Emergency charge-path enable. Clears the AW32001 shipping/FET-disabled state so
// the charger can run autonomously when it has input. Safe no-op if no BWM ACKs.
// Runs from AppMain() (post-boot), so it cannot revive a cell too flat to boot.
void bwm_charger_kick(void);
#endif // WITH_BWM_CHARGERKICK

#ifdef WITH_BWM_STATUS
// Probe for the BWM charger over I2C and, if present, apply the charge profile.
// Records presence for bwm_print_battery_status(). Call once early in AppMain().
void bwm_detect_and_init(void);

// Print the "Battery / BWM" section for `hw status`. Silent if no BWM was
// detected by bwm_detect_and_init().
void bwm_print_battery_status(void);

// Compact battery telemetry for CMD_PM5_BWM_GET_BATTERY - a machine-readable
// subset of what bwm_print_battery_status() prints (same underlying reads,
// so the two can't drift on the numbers they share). All fields zeroed if
// bwm_present is false or gauge_ok is false.
typedef struct {
    bool bwm_present;
    bool gauge_ok;
    uint16_t soc_pct;
    uint16_t voltage_mv;
    int16_t  current_ma;      // +charge / -discharge
    uint16_t remaining_mah;
    uint16_t full_charge_mah;
    uint16_t design_cap_mah;
    int16_t  temp_c10;        // tenths of a degree C
    uint8_t  charger_fault;   // 0 = none, else AW32001E REG09 bits masked 0x3F
    uint8_t  charge_status;   // 0=not charging,1=pre-charge,2=charging,3=done
    uint8_t  health_pct;
} PACKED bwm_battery_info_t;

// Returns false (all fields zeroed) if no BWM was detected. A false gauge_ok
// with bwm_present true means the charger ACKed but the fuel gauge didn't.
bool bwm_read_battery_info(bwm_battery_info_t *out);

// One-time BQ27427 Design Capacity provisioning (CMD_PM5_BWM_SET_CAP /
// `hw bwm setcap`). Idempotent - returns true without a CFGUPDATE cycle if the
// value is already correct. Assumes the gauge is UNSEALED (factory default).
bool bwm_gauge_provision_capacity(uint16_t cap_mah);

// Enable/disable battery charging (clear/set AW32001E CEB, REG01[3]).
// One-shot: reverts on the charger watchdog timeout (~160 s).
bool bwm_charger_set_charge(bool enable);

// Set the AW32001E charge-voltage regulation target (REG04 VBAT_REG). Clamps to a
// safe window, rounds to the nearest hardware step, preserves REG04[1:0]. Returns
// the actual mV applied, or 0 on I2C failure.
uint16_t bwm_charger_set_vchg(uint16_t mv);
#endif // WITH_BWM_STATUS

#ifdef WITH_BWM_LOWBATT_BEEP
// Throttled low-battery poll. On battery (USB absent) with both SoC and pack
// voltage below their floors, chirps the mainboard buzzer. Call from the idle
// loop. Requires WITH_BWM_STATUS (for the fuel-gauge reads).
void bwm_lowbatt_check(void);
#endif // WITH_BWM_LOWBATT_BEEP

#endif // __BWM_CHARGER_H
