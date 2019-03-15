//-----------------------------------------------------------------------------
// Samy Kamkar 2012
// Federico Dotta, 2015
// Maurizio Agazzini, 2015
// Christian Herrmann, 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// StandAlone Mod
//-----------------------------------------------------------------------------

#ifndef __LF_HIDBRUTE_H
#define __LF_HIDBRUTE_H

#include "standalone.h" // standalone definitions
#include "apps.h" // debugstatements, lfops?

#define OPTS 3

void hid_corporate_1000_calculate_checksum_and_set(uint32_t *high, uint32_t *low, uint32_t cardnum, uint32_t fc);

#endif /* __LF_HIDBRUTE_H */
