//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/lumag/emv-tools/
// Copyright (C) 2012, 2015 Dmitry Eremin-Solenikov
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
// libopenemv - a library to work with EMV family of smart cards
//-----------------------------------------------------------------------------

#ifndef TAGS_H
#define TAGS_H

#include "tlv.h"

// AC
# define EMVAC_AC_MASK   0xC0
# define EMVAC_AAC       0x00
# define EMVAC_TC        0x40
# define EMVAC_ARQC      0x80
# define EMVAC_CDAREQ    0x10
# define EMVAC_AC2_MASK  0x30
# define EMVAC_AAC2      0x00
# define EMVAC_TC2       0x10
# define EMVAC_ARQC2     0x20

// CID
# define EMVCID_ADVICE       0x08
# define EMVCID_REASON_MASK  0x07

bool emv_tag_dump(const struct tlv *tlv, int level);
const char *emv_get_tag_name(const struct tlv *tlv);

#endif
