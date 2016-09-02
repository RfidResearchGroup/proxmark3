//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC RF emulation public interface
//-----------------------------------------------------------------------------

#ifndef __LEGICRF_H
#define __LEGICRF_H

#include "proxmark3.h"	//
#include "apps.h"
#include "util.h"		//
#include "string.h"		
#include "legic_prng.h"	// legic PRNG impl
#include "crc.h"		// legic crc-4


extern void LegicRfSimulate(int phase, int frame, int reqresp);
extern int  LegicRfReader(int offset, int bytes, int iv);
extern void LegicRfWriter(int offset, int bytes, int iv);
extern void LegicRfRawWriter(int address, int data, int iv);

int ice_legic_select_card();
void ice_legic_setup();

#endif /* __LEGICRF_H */
