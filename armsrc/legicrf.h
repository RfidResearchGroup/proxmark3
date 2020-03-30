//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//     2018 AntiCat
//     2020 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC RF emulation public interface
//-----------------------------------------------------------------------------

#ifndef __LEGICRF_H
#define __LEGICRF_H

#include "common.h"
#include "legic.h"              /* legic_card_select_t struct */

void LegicRfInfo(void);
int LegicRfReaderEx(uint16_t offset, uint16_t len, uint8_t iv);
void LegicRfReader(uint16_t offset, uint16_t len, uint8_t iv);
void LegicRfWriter(uint16_t offset, uint16_t len, uint8_t iv, uint8_t *data);

legic_card_select_t* getLegicCardInfo(void);
#endif /* __LEGICRF_H */
