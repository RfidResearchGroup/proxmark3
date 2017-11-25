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

#ifndef DOL_H
#define DOL_H

#include "emv/tlv.h"
#include <stddef.h>

struct tlv *dol_process(const struct tlv *tlv, const struct tlvdb *tlvdb, tlv_tag_t tag);
struct tlvdb *dol_parse(const struct tlv *tlv, const unsigned char *buf, size_t len);

#endif
