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
// PM5 antenna-RGB "alive on battery" indicator - see rgb_indicator.h.
//-----------------------------------------------------------------------------

#include "rgb_indicator.h"

#ifdef WITH_PM5_PWR_LED

#include "rgb_apis.h"     // RgbLedSet
#include "gpio_apis.h"    // gpio_vusb_setup / Gpio_VUSB_Read (USB-present detection)
#include "ticks_apis.h"   // GetTickCount / GetTickCountDelta

#ifndef PM5_PWR_LED_PERIOD_MS
#define PM5_PWR_LED_PERIOD_MS  1000   // re-evaluate at most once a second
#endif

// Set via rgb_indicator_set_external() so the indicator backs off while tune
// (or any external RGB user) controls the LED.
static volatile bool s_rgb_external = false;
static bool s_pwr_led_setup = false;

void rgb_indicator_set_external(bool owned) {
    s_rgb_external = owned;
}

// "Alive on battery" indicator. When the PM5 runs on battery (USB unplugged) it
// otherwise gives no sign it is on, so users leave it draining. This lights the
// antenna RGB a dim green while on battery, and turns it off when on USB (where the
// cable already signals power). Throttled + edge-triggered to avoid I2C spam and to
// yield the RGB to hf/lf tune (which claims it via rgb_indicator_set_external()).
void rgb_indicator_update(void) {
    static uint32_t last_tick = 0;
    static int last_state = -1;   // -1 unknown, 0 = off/USB, 1 = green/battery

    if ((last_tick != 0) && (GetTickCountDelta(last_tick) < PM5_PWR_LED_PERIOD_MS)) {
        return;
    }
    last_tick = GetTickCount();

    // While tune (or any external RGB user) owns the LED, do nothing and force a
    // refresh next time it is released.
    if (s_rgb_external) {
        last_state = -1;
        return;
    }

    if (s_pwr_led_setup == false) {
        gpio_vusb_setup();
        s_pwr_led_setup = true;
    }

    int on_battery = (Gpio_VUSB_Read() == false) ? 1 : 0;
    if (on_battery == last_state) {
        return;   // edge-triggered: only write RGB when the state changes
    }
    last_state = on_battery;

    if (on_battery) {
        RgbLedSet(0, 8, 0);   // dim green: alive, on battery
    } else {
        RgbLedSet(0, 0, 0);   // on USB: off (cable already signals power)
    }
}

#endif // WITH_PM5_PWR_LED
