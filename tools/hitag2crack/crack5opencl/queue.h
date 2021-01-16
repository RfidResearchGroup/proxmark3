/****************************************************************************

Author : Gabriele 'matrix' Gristina <gabriele.gristina@gmail.com>
Date   : Sun Jan 10 13:59:37 CET 2021
Version: 0.1beta
License: GNU General Public License v3 or any later version (see LICENSE.txt)

*****************************************************************************
    Copyright (C) 2020-2021  <Gabriele Gristina>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
****************************************************************************/

#ifndef QUEUE_H
#define QUEUE_H

// set 1 to enable the test unit
#ifndef TEST_UNIT
#define TEST_UNIT 0
#endif

#if TEST_UNIT == 1
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#endif

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>

// enum errors
typedef enum wu_queue_error {
    QUEUE_EMPTY = 1,
    NO_ERROR = 0,
    ERROR_GENERIC = -1,
    ERROR_QUEUE_TYPE_INVALID = -2,
    ERROR_CTX_NULL = -3,
    ERROR_CTX_IS_INIT = -4,
    ERROR_CTX_IS_NOT_INIT = -5,
    ERROR_MUTEXATTR_INIT = -6,
    ERROR_MUTEXATTR_SETTYPE = -7,
    ERROR_MUTEX_INIT = -8,
    ERROR_ALLOC = -9,
    ERROR_UNDEFINED = -10

} wu_queue_error_t;

// enum queue types
typedef enum wu_queue_type {
    QUEUE_TYPE_FORWARD = 0,
    QUEUE_TYPE_REVERSE,
    QUEUE_TYPE_RANDOM

} wu_queue_type_t;

// hold wu data
typedef struct wu_queue_data {
    size_t id;
    size_t off;
    size_t max;
    size_t rem;

} wu_queue_data_t;

// lists
typedef struct wu_queue_item wu_queue_item_t;
struct wu_queue_item {
    wu_queue_data_t data;
    wu_queue_item_t *next;
    wu_queue_item_t *prev;
};

// main ctx
typedef struct wu_queue_ctx {
    unsigned int init;

    wu_queue_type_t queue_type;
    wu_queue_item_t *queue_head;
    wu_queue_item_t *queue_tail;

    size_t queue_size;

    // mutex
    pthread_mutexattr_t queue_mutex_attr;
    unsigned char pad1[4];
    pthread_mutex_t queue_mutex;

} wu_queue_ctx_t;

// exports
int wu_queue_init(wu_queue_ctx_t *ctx, wu_queue_type_t queue_type);
int wu_queue_done(wu_queue_ctx_t *ctx);
int wu_queue_push(wu_queue_ctx_t *ctx, size_t id, size_t off, size_t max);
int wu_queue_pop(wu_queue_ctx_t *ctx, wu_queue_data_t *wu, short remove);
int wu_queue_destroy(wu_queue_ctx_t *ctx);

const char *wu_queue_strdesc(wu_queue_type_t type);
const char *wu_queue_strerror(int error);

#if TEST_UNIT == 1
int wu_queue_print(wu_queue_ctx_t *ctx);
#endif

#endif // QUEUE_H
