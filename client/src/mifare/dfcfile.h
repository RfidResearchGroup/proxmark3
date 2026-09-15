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
#ifndef __DFCFILE_H
#define __DFCFILE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

size_t dfc_file_length(const uint8_t *data, size_t capacity);
int dfc_file_load(const char *filename, uint8_t *dfcb, size_t capacity, size_t *length);
int dfc_file_save(
    const char *filename,
    const char *format,
    const uint8_t *dfcb,
    size_t length);
int dfc_file_print(const uint8_t *dfcb, size_t length, bool verbose);

#endif
