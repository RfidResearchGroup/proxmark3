//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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

extern bool logging;

bool lf_test_periods(size_t expected, size_t count);
size_t lf_count_edge_periods(size_t max);
size_t lf_detect_gap(size_t max);
void lf_reset_counter();
bool lf_get_tag_modulation();
void lf_wait_periods(size_t periods);
void lf_init(bool reader);
void lf_finalize();
size_t lf_detect_field_drop(size_t max);
bool lf_manchester_send_bytes(const uint8_t *frame, size_t frame_len);
void lf_modulation(bool mod);

#endif // __LFADC_H__
