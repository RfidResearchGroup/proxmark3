//-----------------------------------------------------------------------------
// (c) 2016 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC type prototyping
//-----------------------------------------------------------------------------

#ifndef _LEGIC_H_
#define _LEGIC_H_

#include "common.h"

//-----------------------------------------------------------------------------
// LEGIC
//-----------------------------------------------------------------------------
typedef struct {
    uint8_t uid[4];
    uint32_t tagtype;
    uint8_t cmdsize;
    uint8_t addrsize;
    uint16_t cardsize;
} legic_card_select_t;

#endif // _LEGIC_H_
