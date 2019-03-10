/*
 * Copyright (c) 2012 Rogerz Zhang <rogerz.zhang@gmail.com>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * source here https://github.com/rogerz/jansson/blob/json_path/src/path.c
 */

#include <string.h>
#include <assert.h>

#include <jansson.h>
#include "jansson_private.h"

json_t *json_path_get(const json_t *json, const char *path) {
    static const char root_chr = '$', array_open = '[';
    static const char *path_delims = ".[", *array_close = "]";
    const json_t *cursor;
    char *token, *buf, *peek, *endptr, delim = '\0';
    const char *expect;

    if (!json || !path || path[0] != root_chr)
        return NULL;
    else
        buf = jsonp_strdup(path);

    peek = buf + 1;
    cursor = json;
    token = NULL;
    expect = path_delims;

    while (peek && *peek && cursor) {
        char *last_peek = peek;
        peek = strpbrk(peek, expect);
        if (peek) {
            if (!token && peek != last_peek)
                goto fail;
            delim = *peek;
            *peek++ = '\0';
        } else if (expect != path_delims || !token) {
            goto fail;
        }

        if (expect == path_delims) {
            if (token) {
                cursor = json_object_get(cursor, token);
            }
            expect = (delim == array_open ? array_close : path_delims);
            token = peek;
        } else if (expect == array_close) {
            size_t index = strtol(token, &endptr, 0);
            if (*endptr)
                goto fail;
            cursor = json_array_get(cursor, index);
            token = NULL;
            expect = path_delims;
        } else {
            goto fail;
        }
    }

    jsonp_free(buf);
    return (json_t *)cursor;
fail:
    jsonp_free(buf);
    return NULL;
}

int json_path_set_new(json_t *json, const char *path, json_t *value, size_t flags, json_error_t *error) {
    static const char root_chr = '$', array_open = '[', object_delim = '.';
    static const char *const path_delims = ".[", *array_close = "]";

    json_t *cursor, *parent = NULL;
    char *token, *buf = NULL, *peek, delim = '\0';
    const char *expect;
    int index_saved = -1;

    jsonp_error_init(error, "<path>");

    if (!json || !path || flags || !value) {
        jsonp_error_set(error, -1, -1, 0, json_error_invalid_argument, "invalid argument");
        goto fail;
    } else {
        buf = jsonp_strdup(path);
    }

    if (buf[0] != root_chr) {
        jsonp_error_set(error, -1, -1, 0, json_error_invalid_format, "path should start with $");
        goto fail;
    }

    peek = buf + 1;
    cursor = json;
    token = NULL;
    expect = path_delims;

    while (peek && *peek && cursor) {
        char *last_peek = peek;
        peek = strpbrk(last_peek, expect);

        if (peek) {
            if (!token && peek != last_peek) {
                jsonp_error_set(error, -1, -1, last_peek - buf, json_error_invalid_format, "unexpected trailing chars");
                goto fail;
            }
            delim = *peek;
            *peek++ = '\0';
        } else { // end of path
            if (expect == path_delims) {
                break;
            } else {
                jsonp_error_set(error, -1, -1, peek - buf, json_error_invalid_format, "missing ']'?");
                goto fail;
            }
        }

        if (expect == path_delims) {
            if (token) {
                if (token[0] == '\0') {
                    jsonp_error_set(error, -1, -1, peek - buf, json_error_invalid_format, "empty token");
                    goto fail;
                }

                parent = cursor;
                cursor = json_object_get(parent, token);

                if (!cursor) {
                    if (!json_is_object(parent)) {
                        jsonp_error_set(error, -1, -1, peek - buf, json_error_item_not_found, "object expected");
                        goto fail;
                    }
                    if (delim == object_delim) {
                        cursor = json_object();
                        json_object_set_new(parent, token, cursor);
                    } else {
                        jsonp_error_set(error, -1, -1, peek - buf, json_error_item_not_found, "new array is not allowed");
                        goto fail;
                    }
                }
            }
            expect = (delim == array_open ? array_close : path_delims);
            token = peek;
        } else if (expect == array_close) {
            char *endptr;
            size_t index;

            parent = cursor;
            if (!json_is_array(parent)) {
                jsonp_error_set(error, -1, -1, peek - buf, json_error_item_not_found, "array expected");
                goto fail;
            }
            index = strtol(token, &endptr, 0);
            if (*endptr) {
                jsonp_error_set(error, -1, -1, peek - buf, json_error_item_not_found, "invalid array index");
                goto fail;
            }
            cursor = json_array_get(parent, index);
            if (!cursor) {
                jsonp_error_set(error, -1, -1, peek - buf, json_error_item_not_found, "array index out of bound");
                goto fail;
            }
            index_saved = index;
            token = NULL;
            expect = path_delims;
        } else {
            assert(1);
            jsonp_error_set(error, -1, -1, peek - buf, json_error_unknown, "unexpected error in path move");
            goto fail;
        }
    }

    if (token) {
        if (json_is_object(cursor)) {
            json_object_set(cursor, token, value);
        } else {
            jsonp_error_set(error, -1, -1, peek - buf, json_error_item_not_found, "object expected");
            goto fail;
        }
        cursor = json_object_get(cursor, token);
    } else if (index_saved != -1 && json_is_array(parent)) {
        json_array_set(parent, index_saved, value);
        cursor = json_array_get(parent, index_saved);
    } else {
        jsonp_error_set(error, -1, -1, peek - buf, json_error_item_not_found, "invalid path");
        goto fail;
    }

    json_decref(value);
    jsonp_free(buf);
    return 0;

fail:
    json_decref(value);
    jsonp_free(buf);
    return -1;
}
