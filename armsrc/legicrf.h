//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//     2018 AntiCat
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC RF emulation public interface
//-----------------------------------------------------------------------------

#ifndef __LEGICRF_H
#define __LEGICRF_H

#include "proxmark3.h"

extern void LegicRfInfo(void);
extern void LegicRfReader(uint16_t offset, uint16_t len, uint8_t iv);
extern void LegicRfWriter(uint16_t offset, uint16_t byte, uint8_t iv, uint8_t *data);

#endif /* __LEGICRF_H */
