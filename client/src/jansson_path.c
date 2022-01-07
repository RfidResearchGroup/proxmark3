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

#include <string.h>
#include <assert.h>

#include "jansson.h"
#include "jansson_path.h"

////// memory.c private functions

/* C89 allows these to be macros */
#undef malloc
#undef free

/* memory function pointers */
static json_malloc_t do_malloc = malloc;
static json_free_t do_free = free;

static void *jsonp_malloc(size_t size) {
    if (!size)
        return NULL;

    return (*do_malloc)(size);
}

static void jsonp_free(void *ptr) {
    if (!ptr)
        return;

    (*do_free)(ptr);
}

static char *jsonp_strndup(const char *str, size_t len) {
    char *new_str = jsonp_malloc(len + 1);
    if (!new_str)
        return NULL;

    memcpy(new_str, str, len);
    new_str[len] = '\0';
    return new_str;
}

static char *jsonp_strdup(const char *str) {
    return jsonp_strndup(str, strlen(str));
}

////// error.c private functions

static void jsonp_error_set_source(json_error_t *error, const char *source) {
    size_t length;

    if (!error || !source)
        return;

    length = strlen(source);
    if (length < JSON_ERROR_SOURCE_LENGTH) {
        strncpy(error->source, source, JSON_ERROR_SOURCE_LENGTH - 1);
    } else {
        size_t extra = length - JSON_ERROR_SOURCE_LENGTH + 4;
        memcpy(error->source, "...", 3);
        strncpy(error->source + 3, source + extra, length - extra + 1);
    }
}

static void jsonp_error_init(json_error_t *error, const char *source) {
    if (error) {
        error->text[0] = '\0';
        error->line = -1;
        error->column = -1;
        error->position = 0;
        if (source)
            jsonp_error_set_source(error, source);
        else
            error->source[0] = '\0';
    }
}

static void jsonp_error_vset(json_error_t *error, int line, int column,
                             size_t position, enum json_error_code code,
                             const char *msg, va_list ap) {
    if (!error)
        return;

    if (error->text[0] != '\0') {
        /* error already set */
        return;
    }

    error->line = line;
    error->column = column;
    error->position = (int)position;

    vsnprintf(error->text, JSON_ERROR_TEXT_LENGTH - 1, msg, ap);
    error->text[JSON_ERROR_TEXT_LENGTH - 2] = '\0';
    error->text[JSON_ERROR_TEXT_LENGTH - 1] = code;
}

static void jsonp_error_set(json_error_t *error, int line, int column,
                            size_t position, enum json_error_code code,
                            const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    jsonp_error_vset(error, line, column, position, code, msg, ap);
    va_end(ap);
}


// original path.c from jansson fork

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
                jsonp_error_set(error, -1, -1, last_peek - buf, json_error_invalid_format, "missing ']'?");
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
        jsonp_error_set(error, -1, -1, 0, json_error_item_not_found, "invalid path");
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
