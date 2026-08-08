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
// LF ADC read/write implementation
//-----------------------------------------------------------------------------

#ifndef __LFADC_H__
#define __LFADC_H__

#include "proxmark3_arm.h"
#include "common.h"
#include "cmd.h"
#include "util.h"
#include "string.h"

extern bool g_logging;

/*
 * Trigger on a modulation swap by observing an edge change
 * PEAK_THROUGH_LEFT:
 *  1. When the peak of the falling edge appears to rise, it is considered to be the rising edge.
 *  2. When the peak of the rising edge drops, it is considered a falling edge.
 *  Note: The edge status is from waveform of the analog signal is reversed.
 * PEAK_THROUGH_CENTER:
 *  1. The timing for edge judgment is based on the level range without modulation.
 *  2. The edge switching will not be determined within the range of the peak of the falling edge and the peak of the rising edge.
 *  Note: not reversed.
 */
typedef enum {
    LF_ADC_WAV_REVERSED = 0U,
    LF_ADC_NOT_REVERSED = 1U,
} lf_adc_edge_mode_t;

// What working mode should the module be initialized to?
typedef enum {
    LF_ADC_READER = 0U,
    LF_ADC_TAG_SIM = 1U,
    LF_ADC_SNIFF = 2U,
} lf_adc_init_mode_t;

uint8_t lf_get_adc_avg(void);
void lf_sample_mean(void);
bool lf_test_periods(size_t expected, size_t count);
size_t lf_count_edge_periods(size_t max);
size_t lf_detect_gap(size_t max);
void lf_reset_counter(void);

bool lf_get_tag_modulation(void);
bool lf_get_reader_modulation(void);

void lf_wait_periods(size_t periods);
void lf_init(lf_adc_init_mode_t init_mode, lf_adc_edge_mode_t edge_mode, bool ledcontrol);
void lf_finalize(bool ledcontrol);
size_t lf_detect_field_drop(size_t max);
void lf_reset_field(size_t periods);

bool lf_manchester_send_bytes(const uint8_t *frame, size_t frame_len, bool ledcontrol);
void lf_modulation(bool modulation);

#endif // __LFADC_H__
