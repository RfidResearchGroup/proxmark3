//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Generic TEA crypto code.
// ref: http://143.53.36.235:8080/source.htm#ansi
//-----------------------------------------------------------------------------

#ifndef __TEA_H
#define __TEA_H

#include "commonutil.h"
#include <stdint.h>
#include <stddef.h>
void tea_encrypt(uint8_t *v, uint8_t *key);
void tea_decrypt(uint8_t *v, uint8_t *key);
#endif /* __TEA_H */
