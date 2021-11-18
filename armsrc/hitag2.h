//-----------------------------------------------------------------------------
// (c) 2012 Roel Verdult
// modified 2021 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hitag2 type prototyping
//-----------------------------------------------------------------------------

#ifndef _HITAG2_H_
#define _HITAG2_H_

#include "common.h"
#include "hitag.h"

void SniffHitag2(bool ledcontrol);
void SimulateHitag2(bool ledcontrol);
void ReaderHitag(hitag_function htf, hitag_data *htd, bool ledcontrol);
void WriterHitag(hitag_function htf, hitag_data *htd, int page, bool ledcontrol);
void EloadHitag(uint8_t *data, uint16_t len);
#endif
