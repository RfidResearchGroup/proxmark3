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
#include "jsonutils.h"

#include <stdbool.h>
#include <string.h>
#include "commonutil.h"  // hexstr_to_byte_array

json_t *json_object_get_ci(const json_t *object, const char *key) {
    if (json_is_object(object) == false || key == NULL) {
        return NULL;
    }

    const char *object_key = NULL;
    json_t *value = NULL;
    json_object_foreach((json_t *)object, object_key, value) {
        if (object_key != NULL && strcasecmp(object_key, key) == 0) {
            return value;
        }
    }
    return NULL;
}

bool json_string_hex(const json_t *value, uint8_t *out, size_t len) {
    if (json_is_string(value) == false || out == NULL) {
        return false;
    }
    const char *hex = json_string_value(value);
    size_t parsed = 0;
    return hex != NULL && strlen(hex) == len * 2U &&
           hexstr_to_byte_array(hex, out, &parsed) && parsed == len;
}
