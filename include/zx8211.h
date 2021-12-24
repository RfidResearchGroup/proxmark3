//-----------------------------------------------------------------------------
// Copyright (C) 2021 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency ZX8211 structs
//-----------------------------------------------------------------------------

#ifndef ZX8211_H__
#define ZX8211_H__

#define ZX8211_NUM_BLOCKS 32

// Common word/block addresses


typedef struct {
    bool parity;
} zx8211_data_t;

#endif // ZX8211_H__ 
