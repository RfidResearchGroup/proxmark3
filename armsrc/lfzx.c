//-----------------------------------------------------------------------------
// Copyright (C) 2021 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency ZX8211 funtions
//-----------------------------------------------------------------------------
#ifndef __LFOPS_H
#define __LFOPS_H

#include "lfzx.h"
#include "pm3_cmd.h" // struct

int zx8211_read(zx8211_data_t *zxd, bool ledcontrol) {
    return PM3_SUCCESS;
}

int zx8211_write(zx8211_data_t *zxd, bool ledcontrol) {
    return PM3_SUCCESS;
}

#endif