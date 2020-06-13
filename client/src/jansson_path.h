/*
 * Copyright (c) 2009-2016 Petri Lehtinen <petri@digip.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

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
