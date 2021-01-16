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

#ifndef THREADS_H
#define THREADS_H

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <pthread.h>

#include "ht2crack5opencl.h"
#include "opencl.h"
#include "hitag2.h"

typedef enum thread_status {
    TH_START = 0,
    TH_WAIT,
    TH_PROCESSING,
    TH_ERROR,
    TH_FOUND_KEY,
    TH_END

} thread_status_t;

typedef enum thread_type {
    THREAD_TYPE_SEQ = 0,
    THREAD_TYPE_ASYNC

} thread_type_t;

typedef enum thread_error {
    THREAD_NOERROR = 0,
    THREAD_ERROR_CTX_IS_NULL = -1,
    THREAD_ERROR_CTX_IS_INIT = -2,
    THREAD_ERROR_TYPE_INVALID = -3,
    THREAD_ERROR_COUNT_INVALID = -4,
    THREAD_ERROR_ATTR_SETDETACH = -5,
    THREAD_ERROR_ATTR = -6,
    THREAD_ERROR_MUTEXATTR = -7,
    THREAD_ERROR_CREATE = -8,
    THREAD_ERROR_MUTEX = -9,
    THREAD_ERROR_COND = -10,
    THREAD_ERROR_MUTEX_USLEEP = -11,
    THREAD_ERROR_COND_USLEEP = -12,
    THREAD_ERROR_GENERIC = -13,
    THREAD_ERROR_ALLOC = -14,
    THREAD_ERROR_INTERNAL = -15

} thread_error_t;

typedef struct threads_ctx {
    short init;
    short type;

    unsigned char pad1[4];
    size_t thread_count;

    pthread_t *thread_handles;

    pthread_mutex_t *thread_mutexs;
    pthread_cond_t *thread_conds;

    short enable_condusleep;

    // get rid of sleep/usleep call to synchronize threads
    unsigned char pad2[6];
    pthread_mutex_t thread_mutex_usleep;
    pthread_cond_t thread_cond_usleep;

    pthread_attr_t attr;
    pthread_mutexattr_t mutex_attr;

    unsigned char pad3[4];
} thread_ctx_t;

// used by threads engine
typedef struct thread_arg {
    thread_status_t status;
    unsigned char pad1[4];
    size_t max_threads;

    uint64_t s;
    uint32_t uid, nR1, aR1, nR2, aR2;
    bool r;
    bool err;
    bool quit;

    unsigned char pad2[1];
    uint64_t off;
    uint64_t *matches;
    uint32_t *matches_found;
    size_t slice;
    size_t max_slices;
    size_t device_id;

    uint64_t key;

    opencl_ctx_t *ocl_ctx;
    thread_ctx_t *thread_ctx;

} thread_args_t;

int thread_init(thread_ctx_t *ctx, short type, size_t thread_count);
int thread_start(thread_ctx_t *ctx, thread_args_t *args);
int thread_stop(thread_ctx_t *ctx);
int thread_start_scheduler(thread_ctx_t *ctx, thread_args_t *t_arg, wu_queue_ctx_t *queue_ctx);
bool thread_setEnd(thread_ctx_t *ctx, thread_args_t *t_arg);

void tprintf(const char *restrict format, ...);
const char *thread_strerror(int error);
const char *thread_status_strdesc(thread_status_t s);

void *computing_process(void *arg);
void *computing_process_async(void *arg);

int thread_destroy(thread_ctx_t *ctx);

#endif // THREADS_H
