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
// PM5 CEP bus logic logger. Taps the bytes pm5_cep.c already moves over
// SPI1/USART1 and timestamps them into a ring buffer instead of sniffing the
// lines electrically - see pm3_cmd.h for the wire format
// (CMD_CEP_LOGIC_CTRL/CMD_CEP_LOGIC_FETCH). Byte-level timestamps, not
// electrical edge capture.
//
// Opt-in: PLATFORM_EXTRAS=CEPLOGIC (see Makefile.platform.sample), on top of
// PLATFORM=PM5's default WITH_CEP. Without it, the functions below are
// no-op stubs (pm5_cep_logic.c isn't even compiled in - see
// armsrc/Makefile/CMakeLists.txt's SRC_CEP) so pm5_cep.c and appmain.c call
// them unconditionally either way.
//-----------------------------------------------------------------------------

#ifndef __PM5_CEP_LOGIC_H
#define __PM5_CEP_LOGIC_H

#include "common.h"
#include "pm3_cmd.h"

#ifdef WITH_CEP_LOGIC

// Called from pm5_cep.c at each byte boundary (SPI1 RX/TX, USART1 RX). No-op
// unless recording is on. Safe to call from USART1_IRQHandler and from
// main-loop code - the shared index update is a short critical section.
void cep_logic_record(uint8_t chan, uint8_t data);

// Apply a CEP_LOGIC_ACTION_* and always fill *status with the result.
// skip_idle only matters for CEP_LOGIC_ACTION_START - see cep_logic_record().
void cep_logic_ctrl(uint8_t action, bool skip_idle, cep_logic_status_t *status);

// Copy up to max_count entries starting at offset into out. Returns how many
// were copied; 0 if offset is outside [oldest_valid, count). Always fills
// *count and *oldest_valid so the caller can resync after an overflow.
// Call cep_logic_ctrl(CEP_LOGIC_ACTION_STOP, ...) first for a consistent read
// - fetching while still running can race the recorder.
uint16_t cep_logic_fetch(uint32_t offset, cep_logic_entry_t *out, uint16_t max_count,
                         uint32_t *count, uint32_t *oldest_valid);

#else // !WITH_CEP_LOGIC - not built in, always report "nothing recorded"

static inline void cep_logic_record(uint8_t chan, uint8_t data) {
    (void)chan;
    (void)data;
}

static inline void cep_logic_ctrl(uint8_t action, bool skip_idle, cep_logic_status_t *status) {
    (void)action;
    (void)skip_idle;
    status->running = false;
    status->overflowed = false;
    status->count = 0;
}

static inline uint16_t cep_logic_fetch(uint32_t offset, cep_logic_entry_t *out, uint16_t max_count,
                                       uint32_t *count, uint32_t *oldest_valid) {
    (void)offset;
    (void)out;
    (void)max_count;
    *count = 0;
    *oldest_valid = 0;
    return 0;
}

#endif // WITH_CEP_LOGIC

#endif // __PM5_CEP_LOGIC_H
