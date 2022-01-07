//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
#ifndef EMOJIS_ALT_H__
#define EMOJIS_ALT_H__

typedef struct emoji_alt_s {
    const char *alias;
    const char *alttext;
} emoji_alt_t;
// emoji_alt_t array are expected to be NULL terminated

static emoji_alt_t EmojiAltTable[] = {
    {":wink:", ";)"},
    {NULL, NULL}
};

#endif
