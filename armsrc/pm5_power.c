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
// Proxmark5 (AT32F435) power-save idle - see pm5_power.h.
//
// Idle: SCLK PLL-288 -> HICK-48, PLL off, LDO 1.3 -> 1.1 V (good to 144 MHz),
// FPGA CLKOUT1 parked low, core in WFI until an IRQ or a 1 ms SysTick wake.
// USB is crystal-less off HICK-48 (ACC-trimmed on the SOF, usb_cdc_at32.c) and
// the 1 kHz tick counter is on the ERTC (HEXT/20), so neither notices the PLL
// going away. Everything else keeps its 288 MHz assumption via the boost.
//
// Ported from the Fantasi firmware.
//-----------------------------------------------------------------------------
#include "pm5_power.h"

#include "proxmark3_arm.h"
#include "dbprint.h"
#include "ticks_apis.h"
#include "fpga_apis.h"
#include "config_gpio_proxmark5.h"
#ifdef WITH_BWM_FORWARD
#include "bwm_uart_at32.h"
#endif

#include "at32f435_437.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_pwc.h"
#include "at32f435_437_gpio.h"

// Full speed through USB enumeration and the rest of the boot.
#define PM5_POWER_BOOT_GRACE_MS   3000
// Quiet time after the last boost before downclocking: back-to-back commands
// (autopwn, scripts, BWM forwarded traffic) don't pay the switch each time.
#define PM5_POWER_IDLE_MS         200
#define PM5_POWER_CLK_WAIT        500000u

static volatile uint32_t s_boost;            // >0 = something holds 288 MHz
static volatile bool s_clk_high = true;      // boot runs at 288 MHz
static bool s_powersave = true;
static uint32_t s_last_busy_tick;

// Stats for `hw status`.
static uint32_t s_downclocks;
static uint32_t s_low_ms;
static uint32_t s_low_since_tick;
static uint32_t s_sleeps;
static uint32_t s_asleep_ms;
static uint32_t s_asleep_us_resid;

static void pm5_fpga_clk_park(void) {
    // Static low, not floating, while the PLL behind CLKOUT1 is off.
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_mode = GPIO_MODE_OUTPUT;
    gpio_init_struct.gpio_pins = AT32_GPIO_FPGA_24M_CLK_PIN;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_bits_reset(AT32_GPIO_FPGA_24M_CLK, AT32_GPIO_FPGA_24M_CLK_PIN);
    gpio_init(AT32_GPIO_FPGA_24M_CLK, &gpio_init_struct);
}

// Voltage-safe ordering: up = LDO before frequency, down = frequency before LDO.
// The LDO is only writable while SCLK is on HICK/HEXT, which holds on both paths.
// Runs with IRQs masked.
static void pm5_clk_apply(bool high) {
    uint32_t i;
    if (high) {
        pwc_ldo_output_voltage_set(PWC_LDO_OUTPUT_1V3);
        for (volatile uint32_t d = 0; d < 2000; d++) {}   // LDO settle

        crm_clock_source_enable(CRM_CLOCK_SOURCE_PLL, TRUE);
        for (i = 0; i < PM5_POWER_CLK_WAIT; i++) {
            if (crm_flag_get(CRM_PLL_STABLE_FLAG) == SET) break;
        }
        crm_auto_step_mode_enable(TRUE);
        crm_sysclk_switch(CRM_SCLK_PLL);
        for (i = 0; i < PM5_POWER_CLK_WAIT; i++) {
            if (crm_sysclk_switch_status_get() == CRM_SCLK_PLL) break;
        }
        crm_auto_step_mode_enable(FALSE);
        system_core_clock_update();

        FpgaSetup24MHzClk();   // CLKOUT1 back on PA8
    } else {
        pm5_fpga_clk_park();

        crm_clock_source_enable(CRM_CLOCK_SOURCE_HICK, TRUE);
        for (i = 0; i < PM5_POWER_CLK_WAIT; i++) {
            if (crm_flag_get(CRM_HICK_STABLE_FLAG) == SET) break;
        }
        crm_auto_step_mode_enable(TRUE);
        crm_sysclk_switch(CRM_SCLK_HICK);
        for (i = 0; i < PM5_POWER_CLK_WAIT; i++) {
            if (crm_sysclk_switch_status_get() == CRM_SCLK_HICK) break;
        }
        crm_auto_step_mode_enable(FALSE);
        crm_clock_source_enable(CRM_CLOCK_SOURCE_PLL, FALSE);
        pwc_ldo_output_voltage_set(PWC_LDO_OUTPUT_1V1);
        system_core_clock_update();
    }
#ifdef WITH_BWM_FORWARD
    bwm_uart_clock_update();   // UART4 baud follows APB1
#endif
    s_clk_high = high;
}

void pm5_power_init(void) {
    // SCLK-from-HICK must be 48 MHz, not the 8 MHz reset default. usb_enable()
    // already selects this for the crystal-less USB clock; make it explicit.
    crm_hick_sclk_frequency_select(CRM_HICK_SCLK_48MHZ);

    // Free-running cycle counter: measures the time actually spent in WFI.
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    s_last_busy_tick = GetTickCount();
}

void pm5_power_boost(void) {
    __disable_irq();
    if (s_boost++ == 0 && s_clk_high == false) {
        pm5_clk_apply(true);
        s_low_ms += GetTickCountDelta(s_low_since_tick);
    }
    __enable_irq();
}

void pm5_power_unboost(void) {
    __disable_irq();
    if (s_boost > 0) {
        s_boost--;
    }
    __enable_irq();
    // The downclock itself is left to pm5_power_idle() after PM5_POWER_IDLE_MS.
    if (s_boost == 0) {
        s_last_busy_tick = GetTickCount();
    }
}

static bool pm5_power_may_downclock(void) {
    if (s_boost != 0 || s_clk_high == false) {
        return false;
    }
    if (GetTickCount() < PM5_POWER_BOOT_GRACE_MS) {
        return false;
    }
    if (GetTickCountDelta(s_last_busy_tick) < PM5_POWER_IDLE_MS) {
        return false;
    }
    // A reader field or emulation left running needs the FPGA clock.
    return FpgaIsOff();
}

// Halt until the next IRQ, at most ~1 ms (one-shot SysTick, AHB/8 source like
// SpinDelayUs which reprograms SysTick anyway). IRQs stay masked across the
// WFI so the cycle delta measures only the sleep; the waking ISR runs after.
static void pm5_power_wfi(void) {
    SysTick->CTRL = 0;
    SysTick->LOAD = (system_core_clock / 8 / 1000) - 1;
    SysTick->VAL = 0;
    SysTick->CTRL = SysTick_CTRL_TICKINT_Msk | SysTick_CTRL_ENABLE_Msk;

    __disable_irq();
    uint32_t t0 = DWT->CYCCNT;
    __WFI();
    uint32_t cycles = DWT->CYCCNT - t0;
    __enable_irq();

    SysTick->CTRL = 0;

    s_sleeps++;
    s_asleep_us_resid += cycles / (system_core_clock / 1000000);
    if (s_asleep_us_resid >= 1000) {
        s_asleep_ms += s_asleep_us_resid / 1000;
        s_asleep_us_resid %= 1000;
    }
}

void pm5_power_idle(void) {
    if (s_powersave == false) {
        return;
    }
    if (pm5_power_may_downclock()) {
        SpinDelayUs(10);   // let a just-sent FPGA conf word land before its clock stops
        __disable_irq();
        pm5_clk_apply(false);
        __enable_irq();
        s_downclocks++;
        s_low_since_tick = GetTickCount();
    }
    pm5_power_wfi();
}

void pm5_power_set_enabled(bool on) {
    s_powersave = on;
    if (on == false && s_clk_high == false) {
        __disable_irq();
        pm5_clk_apply(true);
        __enable_irq();
        s_low_ms += GetTickCountDelta(s_low_since_tick);
    }
}

bool pm5_power_get_enabled(void) {
    return s_powersave;
}

// Per-mille of uptime, printed as a percentage with one decimal.
static uint32_t pm5_power_permille(uint32_t ms, uint32_t uptime_ms) {
    if (uptime_ms == 0) {
        return 0;
    }
    return (uint32_t)(((uint64_t)ms * 1000) / uptime_ms);
}

void pm5_power_print_status(void) {
    uint32_t uptime = GetTickCount();
    uint32_t low = pm5_power_permille(s_low_ms, uptime);
    uint32_t asleep = pm5_power_permille(s_asleep_ms, uptime);

    DbpString(_CYAN_("Power"));
    Dbprintf("  Power-save idle..... %s", s_powersave ? _GREEN_("enabled") : _YELLOW_("disabled"));
    DbpString("  Core clock.......... 288 MHz active, 48 MHz idle ( PLL off, LDO 1.1 V )");
    Dbprintf("  Uptime.............. %u ms", uptime);
    Dbprintf("  Idle at 48 MHz...... %u.%u %% ( %u downclocks )", low / 10, low % 10, s_downclocks);
    Dbprintf("  Halted in WFI....... %u.%u %% ( %u sleeps )", asleep / 10, asleep % 10, s_sleeps);
}
