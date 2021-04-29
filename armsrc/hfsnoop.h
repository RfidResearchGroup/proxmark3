//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
// Piwi, Feb 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions internal to the app source.
//-----------------------------------------------------------------------------
#ifndef __HFSNOOP_H
#define __HFSNOOP_H

#include "proxmark3_arm.h"

int HfSniff(uint32_t samplesToSkip, uint32_t triggersToSkip, uint16_t *len);
void HfPlotDownload(void);
#endif
