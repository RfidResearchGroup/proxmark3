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
// PM5 (AT32F435) mainboard buzzer - see buzzer.h.
//
// Wiring: PB13 = enable (push-pull), PC9 = TMR8_CH4 PWM modulation. The bring-up
// sequence is the one proven by the factory QC self-test.
//-----------------------------------------------------------------------------

#include "buzzer.h"

#include "at32f435_437.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_tmr.h"
#include "ticks_apis.h"   // SpinDelay
#include "wdt_apis.h"
#include "pm5_power.h"

// Buzzer wiring on the PM5 mainboard.
#define BUZZER_EN_GPIO      GPIOB
#define BUZZER_EN_PIN       GPIO_PINS_13
#define BUZZER_MOD_GPIO     GPIOC
#define BUZZER_MOD_PIN      GPIO_PINS_9
#define BUZZER_MOD_SRC      GPIO_PINS_SOURCE9
#define BUZZER_MOD_MUX      GPIO_MUX_3
#define BUZZER_MOD_TMR      TMR8
#define BUZZER_MOD_TMR_CH   TMR_SELECT_CHANNEL_4
#define BUZZER_TIMER_PRESCALER 95U

static bool s_buzzer_ready = false;

void BuzzerSetup(void) {
    crm_periph_clock_enable(CRM_GPIOB_PERIPH_CLOCK, TRUE);
    crm_periph_clock_enable(CRM_GPIOC_PERIPH_CLOCK, TRUE);
    crm_periph_clock_enable(CRM_TMR8_PERIPH_CLOCK, TRUE);

    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);

    // Enable pin (PB13): push-pull output, driven low = silent.
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_mode = GPIO_MODE_OUTPUT;
    gpio_init_struct.gpio_pins = BUZZER_EN_PIN;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init(BUZZER_EN_GPIO, &gpio_init_struct);
    gpio_bits_write(BUZZER_EN_GPIO, BUZZER_EN_PIN, FALSE);

    // Modulation pin (PC9): alternate function = TMR8_CH4.
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_pins = BUZZER_MOD_PIN;
    gpio_init(BUZZER_MOD_GPIO, &gpio_init_struct);
    gpio_pin_mux_config(BUZZER_MOD_GPIO, BUZZER_MOD_SRC, BUZZER_MOD_MUX);

    tmr_internal_clock_set(BUZZER_MOD_TMR);
    tmr_reset(BUZZER_MOD_TMR);
    tmr_base_init(BUZZER_MOD_TMR, BUZZER_DEFAULT_PERIOD, BUZZER_TIMER_PRESCALER);   // ~2 kHz from 192 MHz
    tmr_output_config_type tmr_output_struct;
    tmr_output_default_para_init(&tmr_output_struct);
    tmr_output_struct.oc_mode = TMR_OUTPUT_CONTROL_PWM_MODE_A;
    tmr_output_struct.oc_polarity = TMR_OUTPUT_ACTIVE_HIGH;
    tmr_output_struct.oc_output_state = TRUE;
    tmr_output_channel_config(BUZZER_MOD_TMR, BUZZER_MOD_TMR_CH, &tmr_output_struct);
    tmr_channel_value_set(BUZZER_MOD_TMR, BUZZER_MOD_TMR_CH, BUZZER_DEFAULT_DUTY);
    tmr_counter_enable(BUZZER_MOD_TMR, TRUE);
    tmr_output_enable(BUZZER_MOD_TMR, TRUE);

    s_buzzer_ready = true;
}

static void buzzer_tone_start(uint16_t period, uint16_t duty) {
    if (s_buzzer_ready == false) {
        BuzzerSetup();
    }
    BUZZER_MOD_TMR->pr = period;
    tmr_channel_value_set(BUZZER_MOD_TMR, BUZZER_MOD_TMR_CH, duty);
    gpio_bits_write(BUZZER_EN_GPIO, BUZZER_EN_PIN, TRUE);
}

void BuzzerTone(uint16_t period, uint16_t duty, uint16_t on_ms) {
    buzzer_tone_start(period, duty);
    SpinDelay(on_ms);
    BuzzerOff();
}

void BuzzerBeep(uint16_t on_ms) {
    BuzzerTone(BUZZER_DEFAULT_PERIOD, BUZZER_DEFAULT_DUTY, on_ms);
}

void BuzzerOff(void) {
    if (s_buzzer_ready) {
        gpio_bits_write(BUZZER_EN_GPIO, BUZZER_EN_PIN, FALSE);
    }
}

// Keep the PWM running during long notes while feeding the watchdog regularly.
static void buzzer_wait(uint32_t duration_ms) {
    while (duration_ms > 0U) {
        uint32_t step_ms = duration_ms;
        if (step_ms > 20U) {
            step_ms = 20U;
        }
        WDT_HIT();
        SpinDelay((int)step_ms);
        duration_ms -= step_ms;
    }
    WDT_HIT();
}

rtttl_status_t BuzzerPlayRtttl(const char *text, size_t length) {
    BuzzerOff();
    rtttl_parser_t parser;
    rtttl_status_t status = rtttl_init(&parser, text, length);
    if (status != RTTTL_OK) {
        return status;
    }

    // Standalone/event callers also need the full-speed clock, not just USB.
    pm5_power_boost();
    crm_clocks_freq_type clocks;
    crm_clocks_freq_get(&clocks);
    uint32_t timer_clock_hz = clocks.apb2_freq;
    if (clocks.apb2_freq != clocks.ahb_freq) {
        // APB timers run at twice PCLK when the APB prescaler is not 1.
        timer_clock_hz *= 2U;
    }
    uint32_t timer_tick_hz = timer_clock_hz / (BUZZER_TIMER_PRESCALER + 1U);
    rtttl_event_t event;
    while ((status = rtttl_next(&parser, &event)) == RTTTL_OK) {
        if (event.frequency_hz != 0U) {
            uint32_t counts = (timer_tick_hz + event.frequency_hz / 2U) / event.frequency_hz;
            if (counts < 2U || counts > 65536U) {
                status = RTTTL_ERROR_RANGE;
                break;
            }
            buzzer_tone_start((uint16_t)(counts - 1U), (uint16_t)(counts / 2U));
        }
        buzzer_wait(event.duration_ms);
        BuzzerOff();
    }
    BuzzerOff();
    pm5_power_unboost();
    if (status == RTTTL_DONE) {
        return RTTTL_OK;
    }
    return status;
}
