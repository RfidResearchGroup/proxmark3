//-----------------------------------------------------------------------------
// Borrowed initially from
// https://github.com/rogerz/jansson/blob/json_path/src/path.c
// Copyright (c) 2012 Rogerz Zhang <rogerz.zhang@gmail.com>
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

#ifndef JANSSON_PATH_H
#define JANSSON_PATH_H

//#include <stdio.h>
#include <stdlib.h>  /* for size_t */
//#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

json_t *json_path_get(const json_t *json, const char *path);
int json_path_set_new(json_t *json, const char *path, json_t *value, size_t flags, json_error_t *error);

static JSON_INLINE
int json_path_set(json_t *json, const char *path, json_t *value, size_t flags, json_error_t *error) {
    return json_path_set_new(json, path, json_incref(value), flags, error);
}

#ifdef __cplusplus
}
#endif
#endif
