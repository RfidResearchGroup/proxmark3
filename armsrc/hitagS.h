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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "hitag2_crypto.h"
#include "hitag.h"
#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"
#include "BigBuf.h"

void SimulateHitagSTag(bool tag_mem_supplied, uint8_t *data);
void ReadHitagS(hitag_function htf, hitag_data *htd);
void WritePageHitagS(hitag_function htf, hitag_data *htd, int page);
void check_challenges(bool file_given, uint8_t *data);

#endif
