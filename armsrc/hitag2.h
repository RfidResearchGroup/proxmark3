//-----------------------------------------------------------------------------
// (c) 2012 Roel Verdult
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hitag2 type prototyping
//-----------------------------------------------------------------------------

#ifndef _HITAG2_H_
#define _HITAG2_H_

#include <stdint.h>
#include <stdbool.h>
#include "hitag.h"

void SniffHitag(void);
void SimulateHitagTag(bool tag_mem_supplied, uint8_t *data);
void ReaderHitag(hitag_function htf, hitag_data *htd);
void WriterHitag(hitag_function htf, hitag_data *htd, int page);

#endif
