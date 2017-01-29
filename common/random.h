//-----------------------------------------------------------------------------
// Micolous Jan 2017
// Iceman Jan 2017
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// pseudo rng generator.  To be used when PM3 simulates Mifare tag.
// i.e.  'hf mf sim'  
//       'hf 14a sim'
//-----------------------------------------------------------------------------

#ifndef __RANDOM_H
#define __RANDOM_H

#include "common.h"
#include "ticks.h"
void fast_prand();
void fast_prandEx(uint32_t seed);
uint32_t prand();
#endif