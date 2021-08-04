//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// AID DESFire functions
//-----------------------------------------------------------------------------

#ifndef _AIDDESFIRE_H_
#define _AIDDESFIRE_H_

#include "common.h"

const char *nxp_cluster_to_text(uint8_t cluster);
int AIDDFDecodeAndPrint(uint8_t aid[3]);

#endif // _AIDDESFIRE_H_
