//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// HitagS emulation (preliminary test version)
//
// (c) 2016 Oguzhan Cicek, Hendrik Schwartke, Ralf Spenneberg
//     <info@os-s.de>
//-----------------------------------------------------------------------------

#ifndef _HITAGS_H_
#define _HITAGS_H_

#include "common.h"

#include "hitag.h"

void SimulateHitagSTag(bool tag_mem_supplied, uint8_t *data, bool ledcontrol);
void ReadHitagS(hitag_function htf, hitag_data *htd, bool ledcontrol);
void WritePageHitagS(hitag_function htf, hitag_data *htd, int page, bool ledcontrol);
void Hitag_check_challenges(uint8_t *data, uint32_t datalen, bool ledcontrol);
#endif
