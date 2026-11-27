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
// See pm5_cep_logic.h.
//-----------------------------------------------------------------------------

#include "pm5_cep_logic.h"

#include "proxmark3_arm.h" // __disable_irq/__enable_irq, same as pm5_power.c
#include "at32f435_437.h"  // DWT->CYCCNT, system_core_clock - same as pm5_power.c

static cep_logic_entry_t s_logic_ring[CEP_LOGIC_RING_SIZE];
static volatile uint32_t s_logic_count;  // monotonic, entries recorded since last START/CLEAR
static volatile bool s_logic_running;
static volatile bool s_logic_skip_idle; // don't record MOSI 0xFF/0x00 filler - set at START
static uint32_t s_logic_last_cyccnt;
static uint64_t s_logic_virtual_ticks; // accumulated, in GetTicks()'s 1.5 MHz unit
static uint32_t s_logic_tick_remainder; // leftover numerator from the last division, carried forward

// GetTicks() shares a 32-bit timer that StartTicks() resets on every call
// (I2C init, BWM charger polling, smartcard code, ...), so it goes backwards
// mid-capture. DWT->CYCCNT is free-running (enabled once in pm5_power_init(),
// never reset after) and gives us a real monotonic source; converting each
// delta through the current system_core_clock into the same 1.5 MHz unit
// also keeps timestamps sane across a pm5_power clock boost/downclock.
// Relies on cep_logic_record() being called at least once per CYCCNT period
// (~15s at full clock) - a silence longer than that would alias the unsigned
// delta below. CEP's idle polls (every ~1s) make that a non-issue in practice.
static uint32_t cep_logic_now_ticks(void) {
    uint32_t now = DWT->CYCCNT;
    uint32_t delta = now - s_logic_last_cyccnt; // unsigned, wraps correctly
    s_logic_last_cyccnt = now;
    uint64_t num = (uint64_t)delta * 1500000ULL + s_logic_tick_remainder;
    s_logic_virtual_ticks += num / system_core_clock;
    s_logic_tick_remainder = num % system_core_clock; // carry the truncated fraction forward
    return (uint32_t)s_logic_virtual_ticks; // wraps after ~47 min, same as GetTicks()
}

void cep_logic_record(uint8_t chan, uint8_t data) {
    if (!s_logic_running) {
        return;
    }
    // USART1_IRQHandler can preempt a main-loop caller mid-update, and also
    // calls us directly - save/restore PRIMASK instead of blindly
    // re-enabling, so we don't unmask interrupts an ISR caller had off.
    //
    // Advance the timebase for every byte, even one skip-idle is about to
    // discard below. Otherwise a long run of filler leaves the gap
    // unaccounted for and the next recorded byte's delta can exceed
    // cep_logic_now_ticks()'s ~15s alias window.
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    uint32_t t = cep_logic_now_ticks();
    __set_PRIMASK(primask);

    if (s_logic_skip_idle && chan == CEP_LOGIC_CHAN_MOSI && (data == 0xffu || data == 0x00u)) {
        return;
    }

    primask = __get_PRIMASK();
    __disable_irq();
    uint32_t idx = s_logic_count++;
    __set_PRIMASK(primask);
    cep_logic_entry_t *e = &s_logic_ring[idx & (CEP_LOGIC_RING_SIZE - 1)];
    e->t_ticks = t;
    e->chan = chan;
    e->data = data;
}

void cep_logic_ctrl(uint8_t action, bool skip_idle, cep_logic_status_t *status) {
    switch (action) {
        case CEP_LOGIC_ACTION_START:
            s_logic_skip_idle = skip_idle;
            // Fresh timebase baseline: last_cyccnt must be "now", not 0, or
            // the first delta after START would span time since boot.
            s_logic_last_cyccnt = DWT->CYCCNT;
            s_logic_virtual_ticks = 0;
            s_logic_tick_remainder = 0;
            s_logic_running = true;
            break;
        case CEP_LOGIC_ACTION_STOP:
            s_logic_running = false;
            break;
        case CEP_LOGIC_ACTION_CLEAR:
            s_logic_running = false;
            s_logic_count = 0;
            break;
        case CEP_LOGIC_ACTION_STATUS:
        default:
            break;
    }
    status->running = s_logic_running;
    status->overflowed = (s_logic_count > CEP_LOGIC_RING_SIZE);
    status->count = s_logic_count;
}

uint16_t cep_logic_fetch(uint32_t offset, cep_logic_entry_t *out, uint16_t max_count,
                         uint32_t *count, uint32_t *oldest_valid) {
    uint32_t total = s_logic_count;
    uint32_t oldest = (total > CEP_LOGIC_RING_SIZE) ? (total - CEP_LOGIC_RING_SIZE) : 0;
    *count = total;
    *oldest_valid = oldest;
    if (offset < oldest || offset >= total) {
        return 0;
    }
    uint32_t avail = total - offset;
    uint16_t n = (avail < max_count) ? (uint16_t)avail : max_count;
    for (uint16_t i = 0; i < n; i++) {
        out[i] = s_logic_ring[(offset + i) & (CEP_LOGIC_RING_SIZE - 1)];
    }
    return n;
}
