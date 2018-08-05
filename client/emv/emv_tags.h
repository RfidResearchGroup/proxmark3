/*
 * libopenemv - a library to work with EMV family of smart cards
 * Copyright (C) 2015 Dmitry Eremin-Solenikov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef TAGS_H
#define TAGS_H

#include "tlv.h"
#include <stdio.h>

// AC
# define EMVAC_AC_MASK   0xC0
# define EMVAC_AAC       0x00
# define EMVAC_TC        0x40
# define EMVAC_ARQC      0x80
# define EMVAC_CDAREQ    0x10

// CID
# define EMVCID_ADVICE       0x08
# define EMVCID_REASON_MASK  0x07

bool emv_tag_dump(const struct tlv *tlv, FILE *f, int level);

#endif
