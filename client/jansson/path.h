/*
 * Copyright (c) 2012 Rogerz Zhang <rogerz.zhang@gmail.com>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 * 
 * source here https://github.com/rogerz/jansson/blob/json_path/src/path.c
 */

json_t *json_path_get(const json_t *json, const char *path);
int json_path_set_new(json_t *json, const char *path, json_t *value, size_t flags, json_error_t *error);

static JSON_INLINE
int json_path_set(json_t *json, const char *path, json_t *value, size_t flags, json_error_t *error)
{
    return json_path_set_new(json, path, json_incref(value), flags, error);
}
