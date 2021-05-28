//-----------------------------------------------------------------------------
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CIPURSE crypto primitives
//-----------------------------------------------------------------------------

#ifndef __CIPURSECRYPTO_H__
#define __CIPURSECRYPTO_H__

#include "common.h"

enum CipurseChannelSecurityLevel {
    CPSNone,
    CPSPlain,
    CPSMACed,
    CPSEncrypted
}

struct CipurseSession {
    uint8_t keyId,
    uint8_t[16] key,
    
    uint8_t[16] RP,
    uint8_t[6]  rP,
    uint8_t[16] RT,
    uint8_t[6]  rT,
    
    uint8_t[16] k0,
    uint8_t[16] cP,
    
    uint8_t[16] frameKey,
    uint8_t[16] frameKey1
}




#endif /* __CIPURSECRYPTO_H__ */
