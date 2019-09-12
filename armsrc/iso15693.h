//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions internal to the app source.
//-----------------------------------------------------------------------------
#ifndef __ISO15693_H
#define __ISO15693_H

#include "common.h"

#include "pm3_cmd.h" // struct

void RecordRawAdcSamplesIso15693(void);
void AcquireRawAdcSamplesIso15693(void);
void ReaderIso15693(uint32_t parameter); // Simulate an ISO15693 reader - greg
void SimTagIso15693(uint32_t parameter, uint8_t *uid); // simulate an ISO15693 tag - greg
void BruteforceIso15693Afi(uint32_t speed); // find an AFI of a tag - atrox
void DirectTag15693Command(uint32_t datalen, uint32_t speed, uint32_t recv, uint8_t *data); // send arbitrary commands from CLI - atrox
void Iso15693InitReader(void);

#endif
