//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//     2018 AntiCat
//     2019 Piwi
//     2020 Iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC RF emulation public interface
//-----------------------------------------------------------------------------

#ifndef __LEGICRFSIM_H
#define __LEGICRFSIM_H

#include "common.h"

void LegicRfSimulate(uint8_t tagtype, bool send_reply);

#endif /* __LEGICRFSIM_H */
