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

#ifndef CheckCrc14A
# define CheckCrc14A(data, len)	check_crc(CRC_14443_A, (data), (len))
#endif

void Mifare1ksim(uint16_t flags, uint8_t exitAfterNReads, uint8_t *datain);

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

#endif
