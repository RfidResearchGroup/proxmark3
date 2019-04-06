//-----------------------------------------------------------------------------
// Merlok - June 2011, 2012
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Mifare Classic Card Simulation
//-----------------------------------------------------------------------------

#ifndef __MIFARESIM_H
#define __MIFARESIM_H

#include <stdint.h>

extern void Mifare1ksim(uint16_t flags, uint8_t exitAfterNReads, uint8_t arg2, uint8_t *datain);

#define AC_DATA_READ             0
#define AC_DATA_WRITE            1
#define AC_DATA_INC              2
#define AC_DATA_DEC_TRANS_REST	 3
#define AC_KEYA_READ             0
#define AC_KEYA_WRITE            1
#define AC_KEYB_READ             2
#define AC_KEYB_WRITE            3
#define AC_AC_READ               4
#define AC_AC_WRITE              5

#define AUTHKEYA                 0
#define AUTHKEYB                 1
#define AUTHKEYNONE              0xff

#define TAG_RESPONSE_COUNT 9								// number of precompiled responses

// Prepare ("precompile") the responses of the anticollision phase.
// There will be not enough time to do this at the moment the reader sends its REQA or SELECT
// There are 7 predefined responses with a total of 18 bytes data to transmit.
// Coded responses need one byte per bit to transfer (data, parity, start, stop, correction)
// 18 * 8 data bits, 18 * 1 parity bits, 5 start bits, 5 stop bits, 5 correction bits  ->   need 177 bytes buffer
#define ALLOCATED_TAG_MODULATION_BUFFER_SIZE 512	// number of bytes required for precompiled response

#endif