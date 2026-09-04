//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Sept 2005
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
// Timers, Clocks functions used in LF or Legic where you would need detailed time.
//-----------------------------------------------------------------------------
#include "ticks_apis.h"
#include "proxmark3_arm.h"
#include "ticks_hw_at32.h"

#include "at32f435_437.h"
#include "at32f435_437_misc.h"
#include "at32f435_437_pwc.h"
#include "at32f435_437_ertc.h"

/**
 * SysTick 频率计算，以下计算条件需要严格遵守 AHBCLK = 288mhz 且 systick的时钟输入是 AHBCLK 的8分频的条件
 *
 * - AHBCLK = 288,000, 000 = 288mhz
 * - systick-clk = 288mhz / 8 = 36,000,000 = 36mhz = 27.7ns
 * - systick-val = 24bit = 0xFFFFFF = 16777215
 * - max time = 27.7ns * 16777215 = 464,728.8555us = 464.7288555ms
 */
#define MAX_US_STEP (464728U)

// timer counts in 27.7ns increments (16777215/36MHz), rounding applies
// WARNING: timer can't measure more than 1.39s (27.7ns * 0xFFFFFF * 3), more loop delay may to decreased accuracy.
void SpinDelayUs(int us) {
    uint32_t fac_us = system_core_clock / 8 / 1000000;
    uint32_t temp = 0;
    SysTick->CTRL &= ~(uint32_t)SYSTICK_CLOCK_SOURCE_AHBCLK_NODIV; // ahbclk div8 = 36mhz
    while (us) {
        SysTick->CTRL &= ~SysTick_CTRL_ENABLE_Msk;
        if (us > MAX_US_STEP) {
            SysTick->LOAD = MAX_US_STEP * fac_us;
            us -= MAX_US_STEP;
        } else {
            SysTick->LOAD = us * fac_us;
            us = 0;
        }
        SysTick->VAL = 0x00;
        SysTick->CTRL |= SysTick_CTRL_ENABLE_Msk;
        do {
            temp = SysTick->CTRL;
        } while ((temp & 0x01) && !(temp & (1 << 16)));
        SysTick->CTRL &= ~SysTick_CTRL_ENABLE_Msk;
        SysTick->VAL = 0x00;
    }
}

// configCounter() is defined below (outside AS_BOOTROM); forward-declare it so the
// precision/timestamp counters inside the AS_BOOTROM block can reuse it.
static void configCounter(const uint32_t frequency);

#ifndef AS_BOOTROM

// timer counts in 27.7ns increments (16777215/36MHz), rounding applies
// WARNING: timer can't measure more than 464.7288555ms (27.7ns * 0xFFFFFF)
void SpinDelayUsPrecision(int us) {
    uint32_t fac_us = system_core_clock / 8 / 1000000;
    uint32_t temp = 0;
    SysTick->CTRL &= ~SysTick_CTRL_ENABLE_Msk;
    SysTick->CTRL &= ~(uint32_t)SYSTICK_CLOCK_SOURCE_AHBCLK_NODIV; // ahbclk div8 = 36mhz
    SysTick->VAL = 0x00;
    SysTick->LOAD = us * fac_us;
    SysTick->CTRL |= SysTick_CTRL_ENABLE_Msk;
    do {
        temp = SysTick->CTRL;
    } while ((temp & 0x01) && !(temp & (1 << 16)));
    SysTick->CTRL &= ~SysTick_CTRL_ENABLE_Msk;
    SysTick->VAL = 0x00;
}

//  -------------------------------------------------------------------------
//  Timer lib: 1 kHz: TickCount functions
//
//  Precision Test Procedure:
//    ti = GetTickCount();
//    SpinDelay(1000);
//    ti = GetTickCount() - ti;
//    Dbprintf("timer(1s): %d t=%d", ti, GetTickCount());
//  -------------------------------------------------------------------------

// Cached tick start value when 'StartTickCount' call.
static volatile uint64_t tick_start_val;

// from date to timestamp(unix format, UTC zone only)
// we can use 'mktime()' from 'time.h', but more rom space required, so custom first.
// tips: year is full length, such as: 2025, not 25
static uint64_t mktime_utc_fast(int year, int month, int day, int hour, int minute, int second, uint32_t ms) {
    static const uint16_t cum_days[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

    int years = year - 1970;
    int leap_count = (years + 2) / 4;
    if (year > 2100) leap_count--;
    if (year > 2200) leap_count--;
    if (year > 2300) leap_count--;

    uint64_t days = years * 365ULL + leap_count;
    days += cum_days[month - 1];
    if (month > 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))) {
        days++;
    }
    days += (day - 1);

    return (days * 86400ULL + hour * 3600ULL + minute * 60ULL + second) * 1000ULL + ms;
}

// Start tick count
void StartTickCount(void) {
    UpdateTickCountLabel();
    crm_periph_clock_enable(CRM_PWC_PERIPH_CLOCK, TRUE); // enable the pwc clock
    pwc_battery_powered_domain_access(TRUE); // allow access to ertc
    crm_battery_powered_domain_reset(TRUE); // reset ertc bpr domain
    crm_battery_powered_domain_reset(FALSE);
    // Select clock source: HEXT = 8mhz, ertc clk = 400khz
    // When using an external high-speed crystal oscillator, the clock can be very accurate,
    // so calibration does not need to be considered temporarily.
    crm_ertc_clock_select(CRM_ERTC_CLOCK_HEXT_DIV_20);
    crm_ertc_clock_enable(TRUE); // enable the ertc clock
    ertc_reset(); // deinitializes the ertc registers
    ertc_wait_update(); // wait for ertc apb registers update
    // configure the ertc divider, ertc second(1hz) = ertc_clk / (div_a + 1) * (div_b + 1)
    // the subsecond frequency is 3125(from div_b clk), so 1 clk = 0.32ms = 320us, the subsecond will -1 every 0.32ms
    ertc_divider_set(127, 3124); // 400000 / (127 + 1) * (3124 + 1) = 1hz
    ertc_hour_mode_set(ERTC_HOUR_MODE_24); // configure the ertc hour mode
    // set datetime: 2025-08-15 13:00:00, format: YEAR-MONTH-DAY HOUR:MINUTE:SECOND
    ertc_date_set(25, 8, 15, 5); // set date
    ertc_time_set(13, 0, 0, ERTC_AM); // set time
    // update tick start value when 'poweron'
    // no need calc, we can hard code cause by 'ertc_date_set' and 'ertc_time_set' is hard code
    // calc online: https://www.timestamp-converter.com/
    tick_start_val = 1755262800000ULL; // tick_start_val = mktime_utc_fast(2025, 8, 15, 13, 0, 0, 0);
}

// Get the current count.
uint32_t RAMFUNC GetTickCount(void) {
    ertc_time_type time;
    ertc_calendar_get(&time);
    return mktime_utc_fast(
               // time.year is short length, not full, so 2025 is 25.
               time.year + 2000,
               // month & day & hour & min & sec is full length
               time.month, time.day, time.hour, time.min, time.sec,
               // this ms is from 0 -> 1000 of second, not timestamp value
               // ms = ((divb + 1) - subsecond * 1000) / (divb + 1)
               (3125 - ertc_sub_second_get()) * 1000 / 3125) - tick_start_val; // current - start = tick
}

//  -------------------------------------------------------------------------
//  Timer for iso14443 commands. Uses ssp_clk from FPGA
//  -------------------------------------------------------------------------

void StartCountSspClk(void) {
    crm_periph_clock_enable(CRM_GPIO_PERIPH_COUNT_SSP_CLK, TRUE);
    crm_periph_clock_enable(AT32_CRM_TMR_PERIPH_COUNT_SSP_CLK, TRUE);

    // gpio init
    gpio_init_type gpio_init_struct = {0};
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_pins = CRM_GPIO_COUNT_SSP_CLK_PIN;
    gpio_init(CRM_GPIO_COUNT_SSP_CLK, &gpio_init_struct); // gpio setup
    gpio_pin_mux_config(CRM_GPIO_COUNT_SSP_CLK, CRM_GPIO_COUNT_SSP_CLK_SOURCE, CRM_GPIO_COUNT_SSP_CLK_MUX); // important !!! remap gpio to be timer EXT(CHx) function.

    // timer init
    tmr_input_config_type tmr_input_config_struct;
    tmr_input_config_struct.input_channel_select = AT32_TMR_COUNT_SSP_CLK_IN_CH;
    tmr_input_config_struct.input_mapped_select = TMR_CC_CHANNEL_MAPPED_DIRECT;
    tmr_input_config_struct.input_polarity_select = TMR_INPUT_RISING_EDGE;
    tmr_input_channel_init(AT32_TMR_COUNT_SSP_CLK, &tmr_input_config_struct, TMR_CHANNEL_INPUT_DIV_1);
    tmr_trigger_input_select(AT32_TMR_COUNT_SSP_CLK, TMR_SUB_INPUT_SEL_C2DF2); // select the timer input trigger: C2IF2
    tmr_sub_mode_select(AT32_TMR_COUNT_SSP_CLK, TMR_SUB_EXTERNAL_CLOCK_MODE_A); // select the slave mode: external mode a
    tmr_32_bit_function_enable(AT32_TMR_COUNT_SSP_CLK, TRUE); // 32bit enable, reduce the complexity of cascading.
    tmr_base_init(AT32_TMR_COUNT_SSP_CLK, UINT32_MAX - 1, 0); // 288mhz, not count increment frequency.
    tmr_cnt_dir_set(AT32_TMR_COUNT_SSP_CLK, TMR_COUNT_UP);
    // tmr_external_clock_mode2_config(CRM_TMR_COUNT_SSP_CLK, TMR_ES_FREQUENCY_DIV_1, TMR_ES_POLARITY_NON_INVERTED, 0x00); ext引脚而非ch2引脚时，使用此初始化函数
    tmr_counter_enable(AT32_TMR_COUNT_SSP_CLK, TRUE);

    // TODO DXL 可能还得像原先的逻辑那样，跳过8个clock，去同步ssp的frame和时钟，因为我们没有用级联定时器这种操作，理论上
    //  可能只需要同步一次frame的上升和下降，因为在ssp-timode的实现下，frame的上升刚好是在lsb的上升沿去执行的，
    //  同步完成之后，理论上下一次clk的上升刚好就是下一帧的msb，这个时候重置一下clk值就刚好是新的一次帧计数？不过，这还不好说，具体得看后续的实现。
}

void ResetSspClk(void) {
    // tmr_counter_value_set(CRM_TMR_COUNT_SSP_CLK, 0);
    AT32_TMR_COUNT_SSP_CLK->cval = 0;
}

uint32_t RAMFUNC GetCountSspClk(void) {
    // return tmr_counter_value_get(CRM_TMR_COUNT_SSP_CLK);
    return AT32_TMR_COUNT_SSP_CLK->cval;
}

//  -------------------------------------------------------------------------
//  Precision counter, input capture and timestamp counter.
//  See ticks_apis.h for the generic contract. Both the precision counter and
//  the timestamp counter run at 1.5 MHz (12 counts = 1 T0 = 8 us).
//  -------------------------------------------------------------------------

// Timestamp counter overflow count, combined for ~47 min timing.
static uint16_t timestamp_high = 0;

void StartPrecisionCounter(void) {
    // Reuses the 32-bit timer @ 1.5 MHz (same source as StartTicks).
    configCounter(1500000);
}

void StopPrecisionCounter(void) {
    tmr_counter_enable(AT32_TMR_PRECISE_COUNTER, FALSE);
}

void ResetPrecisionCounter(void) {
    tmr_counter_value_set(AT32_TMR_PRECISE_COUNTER, 0);
}

uint16_t RAMFUNC GetPrecisionCounter(void) {
    return (uint16_t)tmr_counter_value_get(AT32_TMR_PRECISE_COUNTER);
}

// The free running counter itself, and the distance from a captured value.
//
// Declared in ticks_apis.h and used by the Hitag paths, which need a reference
// they can subtract from rather than a value relative to the last reset.  These
// were added for AT91 without an AT32 counterpart, which left the PM5 build
// failing to link with undefined references to both.
uint16_t RAMFUNC GetPrecisionCounterRaw(void) {
    return (uint16_t)tmr_counter_value_get(AT32_TMR_PRECISE_COUNTER);
}

uint16_t RAMFUNC GetPrecisionCounterDelta(uint16_t start) {
    return (uint16_t)((uint16_t)tmr_counter_value_get(AT32_TMR_PRECISE_COUNTER) - start);
}

void StartLoEdgeCapture(void) {
    crm_periph_clock_enable(CRM_GPIO_PERIPH_INPUT_CAPTURE, TRUE);
    crm_periph_clock_enable(AT32_CRM_TMR_PERIPH_INPUT_CAPTURE, TRUE);

    // GPIO: PB4 -> TMR3_CH1 (input capture on the LF SSC frame signal).
    gpio_init_type gpio_init_struct = {0};
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_pins = CRM_GPIO_INPUT_CAPTURE_PIN;
    gpio_init(CRM_GPIO_INPUT_CAPTURE, &gpio_init_struct); // gpio setup
    gpio_pin_mux_config(CRM_GPIO_INPUT_CAPTURE, CRM_GPIO_INPUT_CAPTURE_SOURCE, CRM_GPIO_INPUT_CAPTURE_MUX); // remap gpio to TMR3_CH1

    // Time base: 16-bit counter @ 1.5 MHz (TIMER_CLK / (191 + 1) = 288MHz / 192),
    // matching the AT91 TC1 (MCK/32) so that 12 counts = 1 T0 = 8 us.
    tmr_reset(AT32_TMR_INPUT_CAPTURE);
    tmr_base_init(AT32_TMR_INPUT_CAPTURE, UINT16_MAX, 191);
    tmr_cnt_dir_set(AT32_TMR_INPUT_CAPTURE, TMR_COUNT_UP);

    // PWM input mode (dual-edge capture) on CH1 (TI1 = PB4):
    // CH1 = direct + falling edge, CH2 = indirect (chained from TI1) + rising edge.
    tmr_input_config_type ic = {0};
    ic.input_channel_select = TMR_SELECT_CHANNEL_1;
    ic.input_mapped_select = TMR_CC_CHANNEL_MAPPED_DIRECT;
    ic.input_polarity_select = TMR_INPUT_FALLING_EDGE;
    tmr_pwm_input_config(AT32_TMR_INPUT_CAPTURE, &ic, TMR_CHANNEL_INPUT_DIV_1);

    // Slave reset mode: reset the counter on the CH1 (falling) edge, so C1DT holds
    // the period since the previous falling edge (matches AT91 ABETRG + ETRGEDG_FALLING).
    tmr_trigger_input_select(AT32_TMR_INPUT_CAPTURE, TMR_SUB_INPUT_SEL_C1DF1);
    tmr_sub_mode_select(AT32_TMR_INPUT_CAPTURE, TMR_SUB_RESET_MODE);
    tmr_sub_sync_mode_set(AT32_TMR_INPUT_CAPTURE, TRUE);

    tmr_counter_value_set(AT32_TMR_INPUT_CAPTURE, 0);
    tmr_counter_enable(AT32_TMR_INPUT_CAPTURE, TRUE);
}

void StopLoEdgeCapture(void) {
    tmr_counter_enable(AT32_TMR_INPUT_CAPTURE, FALSE);
}

void EnableLoEdgeCapture(void) {
    tmr_counter_value_set(AT32_TMR_INPUT_CAPTURE, 0);
    tmr_counter_enable(AT32_TMR_INPUT_CAPTURE, TRUE);
}

void ResetLoEdgeCapture(void) {
    tmr_counter_value_set(AT32_TMR_INPUT_CAPTURE, 0);
}

uint16_t RAMFUNC GetLoEdgeCaptureCount(void) {
    return (uint16_t)tmr_counter_value_get(AT32_TMR_INPUT_CAPTURE);
}

uint16_t RAMFUNC GetLoEdgeCaptureFalling(void) {
    // The falling-edge value is captured on CH1 (C1DT).
    return (uint16_t)tmr_channel_value_get(AT32_TMR_INPUT_CAPTURE, TMR_SELECT_CHANNEL_1);
}

uint16_t RAMFUNC GetLoEdgeCaptureRising(void) {
    // The rising-edge value is captured on CH2 (C2DT).
    return (uint16_t)tmr_channel_value_get(AT32_TMR_INPUT_CAPTURE, TMR_SELECT_CHANNEL_2);
}

lo_edge_t RAMFUNC GetLoEdgeCaptureStatus(void) {
    // Reading the status clears the edge-event flags (matches AT91 TC_SR semantics).
    uint32_t ists = AT32_TMR_INPUT_CAPTURE->ists;
    // Only clear the overflow flag if it is set, to avoid clearing the edge-event flags.
    if (ists & TMR_OVF_FLAG) {
        // Clear the overflow flag to avoid repeated interrupts.
        AT32_TMR_INPUT_CAPTURE->ists = ~TMR_OVF_FLAG;
    }
    if (ists & INPUT_CAPTURE_EVT_RISING_EDGE) {
        AT32_TMR_INPUT_CAPTURE->ists = ~INPUT_CAPTURE_EVT_RISING_EDGE;
        return LO_EDGE_RISING;
    }
    if (ists & INPUT_CAPTURE_EVT_FALLING_EDGE) {
        AT32_TMR_INPUT_CAPTURE->ists = ~INPUT_CAPTURE_EVT_FALLING_EDGE;
        return LO_EDGE_FALLING;
    }
    return LO_EDGE_NO;
}

void StartTimestamp(void) {
    // TMR6: basic 16-bit timer, free-running @ 1.5 MHz.
    crm_periph_clock_enable(AT32_CRM_TMR_PERIPH_TIMESTAMP, TRUE);
    // APB1 = 144 MHz, divX = (144 MHz / 1.5 MHz) * 2 - 1 = 191 (see configCounter()).
    tmr_base_init(AT32_TMR_TIMESTAMP, UINT16_MAX, 191);
    tmr_cnt_dir_set(AT32_TMR_TIMESTAMP, TMR_COUNT_UP);
    tmr_counter_value_set(AT32_TMR_TIMESTAMP, 0);
    tmr_counter_enable(AT32_TMR_TIMESTAMP, TRUE);
    timestamp_high = 0;
}

void StopTimestamp(void) {
    tmr_counter_enable(AT32_TMR_TIMESTAMP, FALSE);
}

uint32_t RAMFUNC GetTimestamp(void) {
    // Sample the counter on both sides of the overflow check, so a wrap that
    // lands between the two cannot make the timestamp go backwards.  See the
    // AT91 version for why that matters.
    uint16_t cv_before = (uint16_t)tmr_counter_value_get(AT32_TMR_TIMESTAMP);
    bool overflowed = tmr_flag_get(AT32_TMR_TIMESTAMP, TMR_OVF_FLAG);
    uint16_t cv_after = (uint16_t)tmr_counter_value_get(AT32_TMR_TIMESTAMP);

    if (overflowed) {
        tmr_flag_clear(AT32_TMR_TIMESTAMP, TMR_OVF_FLAG);
        timestamp_high++;
        cv_before = cv_after;
    }
    return (((uint32_t)timestamp_high << 16) + cv_before) / TICKS_PER_CARRIER_PERIOD;
}

#endif // #ifndef AS_BOOTROM

/**
 * Configure the timer to count up at the specified frequency.
 * @param frequency the frequency of timer running.
 */
static void configCounter(const uint32_t frequency) {
    crm_periph_clock_enable(AT32_CRM_TMR_PERIPH_32B_TIMER_CLK, TRUE);

    // AT32 has a 32-bit timer, perhaps we can achieve higher counting time without connecting the timer?
    tmr_32_bit_function_enable(AT32_TMR_32B_TIMER, TRUE);

    // TODO DXL 注意，如果apb1的预分频系数不是1，那么TIMER5的时钟速度会是apb1的两倍，这里记录下来，后期开发可能会遇到，如果完成移植，可将此段注释删除
    // See at32f435 manual reference 4.1.3
    // The timer uses APB1/2 as the clock. In particular, when the APB pre division coefficient is 1,
    // the clock frequency of the timer is equal to the clock frequency of APB1/2;
    // When the APB prescaler coefficient is not 1, the clock frequency of the timer is equal to twice the APB1/2 clock frequency.
    // So, if we are using not apb from ahb/1, must to div2.
#define FREQUENCY_APB1          144000000UL // apb1 = ahb/2 = 144mhz, apb1*2 = TIMER_CLK, TIMER_CLK/192(divX) = 1.5mhz
    const uint32_t divX = (FREQUENCY_APB1 / frequency) * 2 - 1;
    tmr_base_init(AT32_TMR_32B_TIMER, UINT32_MAX - 1, divX);

    tmr_cnt_dir_set(AT32_TMR_32B_TIMER, TMR_COUNT_UP);
    tmr_counter_enable(AT32_TMR_32B_TIMER, TRUE);
}

//  -------------------------------------------------------------------------
//  microseconds timer
//  1us = 1tick
//  -------------------------------------------------------------------------

void StartCountUS(void) {
    // see: https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/clocks.md#occasional-tc0tc1--countus-functions
    configCounter(1000000); // 1 MHZ
}

uint32_t RAMFUNC GetCountUS(void) {
    // TODO DXL maybe no function call is a good idea?
    //  If it affects accuracy, you can consider directly reading the register.
    // return AT32_TMR_32B_TIMER->cval;
    return tmr_counter_value_get(AT32_TMR_32B_TIMER);
}

//  -------------------------------------------------------------------------
//  Timer for bitbanging, or LF stuff when you need a very precise timer
//  1us = 1.5ticks
//  -------------------------------------------------------------------------

void StartTicks(void) {
    // see: https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/clocks.md#occasional-tc0tc1--ticks-functions
    configCounter(1500000); // 1.5 MHz
}

// Reset the count value to 0
void ResetTicks(void) {
    tmr_counter_value_set(AT32_TMR_32B_TIMER, 0);
}

void StopTicks(void) {
    tmr_counter_enable(AT32_TMR_32B_TIMER, FALSE);
    crm_periph_clock_enable(AT32_CRM_TMR_PERIPH_32B_TIMER_CLK, FALSE);
    // TODO DXL 也许需要在这里停止 其他定时器，因为PM3原本的代码有这个设计，但是我们需要查一下用处，看看是否能这么做
}

uint32_t GetTicks(void) {
    // TODO DXL maybe no function call is a good idea?
    //  If it affects accuracy, you can consider directly reading the register.
    // return AT32_TMR_32B_TIMER->cval;
    return tmr_counter_value_get(AT32_TMR_32B_TIMER);
}
