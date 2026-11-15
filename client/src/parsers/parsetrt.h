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
// TRT, Tianjin Railway Transit single ticket parser for MIFARE Ultralight
//
// Layout from the Flipper Zero trt plugin by @zinongli (GPLv3).
//-----------------------------------------------------------------------------

#ifndef PARSETRT_H__
#define PARSETRT_H__

#include "common.h"

bool is_valid_trt_card(const uint8_t *data, size_t datalen);
int trt_parser_parse(const uint8_t *data, size_t datalen);
int trt_selftest(void);

#endif
