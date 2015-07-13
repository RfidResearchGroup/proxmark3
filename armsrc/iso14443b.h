//-----------------------------------------------------------------------------
// Merlok - June 2011
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type A.
//-----------------------------------------------------------------------------

#ifndef __ISO14443B_H
#define __ISO14443B_H
#include "common.h"

int iso14443b_apdu(uint8_t const *message, size_t message_length, uint8_t *response);
void iso14443b_setup();
int iso14443b_select_card();

#endif /* __ISO14443B_H */
