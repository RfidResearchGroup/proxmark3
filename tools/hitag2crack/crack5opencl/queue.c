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

#include "queue.h"

#if TEST_UNIT == 1
int wu_queue_print(wu_queue_ctx_t *ctx) {
    wu_queue_item_t *ptr = 0; //NULL;
    size_t sum = 0;
    int ret = -1;

    if (!ctx) return -1;
    if (!ctx->init) return ERROR_CTX_IS_NOT_INIT;

    pthread_mutex_lock(&ctx->queue_mutex);

    if ((ret = wu_queue_done(ctx)) != 0) {
        pthread_mutex_unlock(&ctx->queue_mutex);
        return ret;
    }

    switch (ctx->queue_type) {
        case QUEUE_TYPE_FORWARD:
            ptr = ctx->queue_head;
            printf("> show queue contents in FORWARD mode, from head\n");
            break;
        case QUEUE_TYPE_REVERSE:
            ptr = ctx->queue_tail;
            printf("> show queue contents in REVERSE mode, from tail\n");
            break;
        case QUEUE_TYPE_RANDOM:
            ptr = ctx->queue_head;
            printf("> show queue contents in RANDOM mode, from head\n");
        default:
            pthread_mutex_unlock(&ctx->queue_mutex);
            return ERROR_QUEUE_TYPE_INVALID;
    }

    int cnt = 0;

    printf("# Queue size: %zu\n", ctx->queue_size);

    do {
        sum += ptr->data.id;

        if (cnt++ < 4) printf("# ID %zu, OFF %zu, MAX %zu\n", ptr->data.id, ptr->data.off, ptr->data.max);

        if (ctx->queue_type == QUEUE_TYPE_FORWARD || ctx->queue_type == QUEUE_TYPE_RANDOM) {
            if (!ptr->next) break;
            ptr = ptr->next;
        } else if (ctx->queue_type == QUEUE_TYPE_REVERSE) {
            if (!ptr->prev) break;
            ptr = ptr->prev;
        }

    } while (ptr);

    if (!ptr) {
        printf("! Fail: ptr must be not null here\n");
        pthread_mutex_unlock(&ctx->queue_mutex);
        return -1;
    }

    switch (ctx->queue_type) {
        case QUEUE_TYPE_RANDOM:
            printf("> show queue contents in RANDOM mode, from end to head\n");
            break;
        case QUEUE_TYPE_FORWARD:
            printf("> show queue contents in FORWARD mode, from end to head\n");
            break;
        case QUEUE_TYPE_REVERSE:
            printf("> show queue contents in REVERSE mode, from start to tail\n");
            break;
    }

    cnt = 0;

    do {
        sum -= ptr->data.id;
        if (cnt++ < 4) printf("# ID %zu, OFF %zu, MAX %zu\n", ptr->data.id, ptr->data.off, ptr->data.max);

        if (ctx->queue_type == QUEUE_TYPE_FORWARD || ctx->queue_type == QUEUE_TYPE_RANDOM) {
            if (!ptr->prev) break;
            ptr = ptr->prev;
        } else if (ctx->queue_type == QUEUE_TYPE_REVERSE) {
            if (!ptr->next) break;
            ptr = ptr->next;
        }

    } while (ptr);

    if (sum != 0) {
        printf("! Fail: sum is not zero\n");
        pthread_mutex_unlock(&ctx->queue_mutex);
        return -1;
    }

    pthread_mutex_unlock(&ctx->queue_mutex);
    return 0;
}

#endif

const char *wu_queue_strerror(int error) {
    switch (error) {
        case QUEUE_EMPTY:
            return (const char *) "QUERY_EMPTY";
        case NO_ERROR:
            return (const char *) "NO_ERROR";
        case ERROR_GENERIC:
            return (const char *) "ERROR_GENERIC";
        case ERROR_QUEUE_TYPE_INVALID:
            return (const char *) "ERROR_QUEUE_TYPE_INVALID";
        case ERROR_CTX_NULL:
            return (const char *) "ERROR_CTX_NULL";
        case ERROR_CTX_IS_INIT:
            return (const char *) "ERROR_CTX_IS_INIT";
        case ERROR_CTX_IS_NOT_INIT:
            return (const char *) "ERROR_CTX_IS_NOT_INIT";
        case ERROR_MUTEXATTR_INIT:
            return (const char *) "ERROR_MUTEXATTR_INIT";
        case ERROR_MUTEXATTR_SETTYPE:
            return (const char *) "ERROR_MUTEXATTR_SETTYPE";
        case ERROR_MUTEX_INIT:
            return (const char *) "ERROR_MUTEX_INIT";
        case ERROR_ALLOC:
            return (const char *) "ERROR_ALLOC";
        case ERROR_UNDEFINED:
        default:
            return (const char *) "ERROR_UNDEFINED";
    }
}

const char *wu_queue_strdesc(wu_queue_type_t type) {
    switch (type) {
        case QUEUE_TYPE_FORWARD:
            return (const char *) "FORWARD";
        case QUEUE_TYPE_REVERSE:
            return (const char *) "REVERSE";
        case QUEUE_TYPE_RANDOM:
            return (const char *) "RANDOM";
    }

    return (const char *) "UNKNOWN";
}

int wu_queue_init(wu_queue_ctx_t *ctx, wu_queue_type_t queue_type) {
#if TEST_UNIT == 1
    fprintf(stdout, "[%s] enter\n", __func__);
    fflush(stdout);
#endif

    if (!ctx) return ERROR_CTX_NULL;

    // Conditional jump or move depends on uninitialised value(s). It's good as it
    if (ctx->init) return ERROR_CTX_IS_INIT;

    if (queue_type == QUEUE_TYPE_RANDOM) srand((unsigned int) time(0));
    else if (queue_type != QUEUE_TYPE_FORWARD && queue_type != QUEUE_TYPE_REVERSE) {
#if TEST_UNIT == 1
        fprintf(stderr, "! Error, invalid 'queue_type'.\n");
#endif
        return ERROR_QUEUE_TYPE_INVALID;
    }

    memset(ctx, 0, sizeof(wu_queue_ctx_t));
    ctx->queue_type = queue_type;
    ctx->queue_head = 0; //NULL;
    ctx->queue_tail = 0; //NULL;

    int ret;

    if ((ret = pthread_mutexattr_init(&ctx->queue_mutex_attr)) != 0) {
#if TEST_UNIT == 1
        fprintf(stderr, "! Error, pthread_mutexattr_init() failed (%d): %s\n", ret, strerror(ret));
#endif
        memset(ctx, 0, sizeof(wu_queue_ctx_t));
        return ERROR_MUTEXATTR_INIT;
    }

    if ((ret = pthread_mutexattr_settype(&ctx->queue_mutex_attr, PTHREAD_MUTEX_ERRORCHECK)) != 0) {
#if TEST_UNIT == 1
        fprintf(stderr, "! Error, pthread_mutexattr_settype(PTHREAD_MUTEX_ERRORCHECK) failed (%d): %s\n", ret, strerror(ret));
#endif
        pthread_mutexattr_destroy(&ctx->queue_mutex_attr);
        memset(ctx, 0, sizeof(wu_queue_ctx_t));
        return ERROR_MUTEXATTR_SETTYPE;
    }

    if ((ret = pthread_mutex_init(&ctx->queue_mutex, &ctx->queue_mutex_attr)) != 0) {
#if TEST_UNIT == 1
        fprintf(stderr, "! Error, pthread_mutex_init() failed (%d): %s\n", ret, strerror(ret));
#endif
        pthread_mutexattr_destroy(&ctx->queue_mutex_attr);
        memset(ctx, 0, sizeof(wu_queue_ctx_t));
        return ERROR_MUTEX_INIT;
    }

    ctx->init = 1;
    return NO_ERROR;
}

int wu_queue_done(wu_queue_ctx_t *ctx) {
    if (!ctx) return ERROR_CTX_NULL;
    if (!ctx->init) return ERROR_CTX_IS_NOT_INIT;

    switch (ctx->queue_type) {
        case QUEUE_TYPE_RANDOM:
            return (ctx->queue_head == NULL);
        case QUEUE_TYPE_FORWARD:
            return (ctx->queue_head == NULL);
        case QUEUE_TYPE_REVERSE:
            return (ctx->queue_tail == NULL);
    }

    return ERROR_QUEUE_TYPE_INVALID;
}

int wu_queue_push(wu_queue_ctx_t *ctx, size_t id, size_t off, size_t max) {
    if (!ctx) return ERROR_CTX_NULL;
    if (!ctx->init) return ERROR_CTX_IS_NOT_INIT;

    pthread_mutex_lock(&ctx->queue_mutex);

    wu_queue_item_t *ptr = 0; //NULL;

    short first = 0;

    if (ctx->queue_head == 0) first = 1;

    if (!(ptr = (wu_queue_item_t *) calloc(1, sizeof(wu_queue_item_t)))) {
#if TEST_UNIT == 1
        fprintf(stderr, "! Error: calloc() failed (%d): %s\n", errno, strerror(errno));
#endif
        pthread_mutex_unlock(&ctx->queue_mutex);
        return ERROR_ALLOC;
    }

    ptr->data.id = id;
    ptr->data.off = off;
    ptr->data.max = max;
    ptr->next = 0; //NULL;
    ptr->prev = 0; //NULL;

    if (first) {
        ctx->queue_head = ptr;
        ctx->queue_tail = ptr;
        ctx->queue_size++;
        pthread_mutex_unlock(&ctx->queue_mutex);
        return NO_ERROR;
    }

    // set tail
    ptr->prev = ctx->queue_tail;
    ctx->queue_tail = ptr;

    // set head
    wu_queue_item_t *last = ctx->queue_head;
    while (last->next != 0) last = last->next;
    last->next = ptr;

    ctx->queue_size++;
    pthread_mutex_unlock(&ctx->queue_mutex);
    return NO_ERROR;
}

int wu_queue_pop(wu_queue_ctx_t *ctx, wu_queue_data_t *wu, short remove) {
    if (!ctx) return ERROR_CTX_NULL;
    if (!ctx->init) return ERROR_CTX_IS_NOT_INIT;

    int ret = -1;
    int rnd = 0;
    wu_queue_item_t *ptr = 0, *ptrPrev = 0;

    pthread_mutex_lock(&ctx->queue_mutex);

    if ((ret = wu_queue_done(ctx)) != 0) {
#if TEST_UNIT == 1
        fprintf(stderr, "ret from wu_queue_done() (%d): %s\n", ret, wu_queue_strerror(ret));
#endif
        pthread_mutex_unlock(&ctx->queue_mutex);
        return ret;
    }

    switch (ctx->queue_type) {
        case QUEUE_TYPE_FORWARD:
            ptr = ctx->queue_head;
            break;
        case QUEUE_TYPE_REVERSE:
            ptr = ctx->queue_tail;
            break;
        case QUEUE_TYPE_RANDOM:
            ptr = ctx->queue_head;
            rnd = rand() % (int) ctx->queue_size;
            for (int r = 0; r < rnd; r++) {
                ptrPrev = ptr;
                ptr = ptr->next;
            }
            break;
    }

    if (!ptr) {
        pthread_mutex_unlock(&ctx->queue_mutex);
        return ERROR_GENERIC;
    }

    if (!remove) {
        wu->id = ptr->data.id;
        wu->off = ptr->data.off;
        wu->max = ptr->data.max;
    }

    switch (ctx->queue_type) {
        case QUEUE_TYPE_FORWARD:
            ctx->queue_head = (ctx->queue_head)->next;
            break;
        case QUEUE_TYPE_REVERSE:
            ctx->queue_tail = (ctx->queue_tail)->prev;
            break;
        case QUEUE_TYPE_RANDOM: // from the head
#if TEST_UNIT == 1
            fprintf(stdout, "pop id %zu\n", wu->id);
            fflush(stdout);
#endif
            if (ptrPrev == NULL) {
                ctx->queue_head = (ctx->queue_head)->next;
            } else {
                ptrPrev->next = ptr->next;
            }
            break;
    }

    memset(ptr, 0, sizeof(wu_queue_item_t));
    free(ptr);

    ctx->queue_size--;

    if (!remove) wu->rem = ctx->queue_size;

    pthread_mutex_unlock(&ctx->queue_mutex);
    return NO_ERROR;
}

int wu_queue_destroy(wu_queue_ctx_t *ctx) {
#if TEST_UNIT == 1
    fprintf(stdout, "[%s] enter\n", __func__);
    fflush(stdout);
#endif

    if (!ctx) return ERROR_CTX_NULL;
    if (!ctx->init) return ERROR_CTX_IS_NOT_INIT;

    int ret = -1;

    // unload the queue
    while ((ret = wu_queue_pop(ctx, 0, 1)) == 0) {};

    if (ret != QUEUE_EMPTY) {
#if TEST_UNIT
        fprintf(stderr, "! Error, wu_queue_pop() failed (%d): %s\n", ret, wu_queue_strerror(ret));
#endif
        return ret;
    }

#if TEST_UNIT == 1
    printf("ret from wu_queue_pop() (%d): %s\n", ret, wu_queue_strerror(ret));
#endif

#if TEST_UNIT == 1
    if (ctx->queue_head != 0) fprintf(stderr, "queue_head not null\n");
    if (ctx->queue_tail != 0) fprintf(stderr, "queue_tail not null\n");
#endif

    ctx->queue_head = 0; //NULL;
    ctx->queue_tail = 0; //NULL;
    ctx->init = 0;

    pthread_mutex_destroy(&ctx->queue_mutex);
    pthread_mutexattr_destroy(&ctx->queue_mutex_attr);

    memset(ctx, 0, sizeof(wu_queue_ctx_t));
    //ctx = 0; //NULL;

    return NO_ERROR;
}

#if TEST_UNIT == 1
int main(void) {
    unsigned int profiles[11][2] = {
        { 16384, 5 }, // 0, best for Intel GPU's with Neo
        { 8192,  6 }, // 1, only for Intel NEO
        { 4096,  7 }, // 2 (old 0) seems the best for all others (also NVIDIA) :D Apple/Intel GPU's stable here
        { 2048,  8 }, // 3 (old 1) usefulfor any kind of CPU's
        { 1024,  9 },
        { 512,  10 },
        { 256,  11 },
        { 128,  12 }, // 7, (old 5) the last good value with NVIDIA GPU's
        { 64,   13 },
        { 32,   14 },
        { 16,   15 },
    };

    size_t err = 0, err_max = 1;
    size_t id = 0;
    size_t max = profiles[0][0];
    size_t chunk = profiles[0][1];
    size_t sum = 0;
    int i = 0;

    wu_queue_ctx_t ctx;
    memset(&ctx, 0, sizeof(wu_queue_ctx_t));

    printf("Selected the following config: max %zu, chunk %zu\n", max, chunk);
    fflush(stdout);

    wu_queue_type_t types[4] = { QUEUE_TYPE_FORWARD, QUEUE_TYPE_REVERSE, QUEUE_TYPE_RANDOM, 1234 };
    int types_max = (int)(sizeof(types) / sizeof(wu_queue_type_t));

    for (i = 0; i < types_max; i++) {
        int ret = 0;
        printf("[%d] trying wu_queue_init() in %s mode\n", i, wu_queue_strdesc(types[i]));

        if ((ret = wu_queue_init(&ctx, types[i])) != 0) {
            fprintf(stderr, "[%d] Error: wu_queue_init(%s) failed (%d): %s\n", i, wu_queue_strdesc(types[i]), ret, wu_queue_strerror(ret));
            err++;
            continue;
        }

        printf("[%d] trying wu_queue_push()\n", i);

        for (id = 0; id < max; id++) {
            sum += id;
            ret = wu_queue_push(&ctx, id, id << chunk, max);
            if (ret != 0) {
                fprintf(stderr, "[%d] Error: wu_queue_push(%zu) failed (%d): %s\n", i, id, ret, wu_queue_strerror(ret));
                err++;
                continue;
            }
        }

        printf("[%d] push sum: %zu\n", i, sum);

        if (wu_queue_print(&ctx) == -1) {
            fprintf(stderr, "[%d] wu_queue_print() error\n", i);
            err++;
            continue;
        }

        wu_queue_data_t wu;

        while ((ret = wu_queue_pop(&ctx, &wu, 0)) == 0) sum -= wu.id;

        if (ret != QUEUE_EMPTY) {
            fprintf(stderr, "[%d] Error: wu_queue_pop() failed (%d): %s\n", i, ret, wu_queue_strerror(ret));
            err++;
            continue;
        }

        printf("[%d] pop sum: %zu\n", i, sum);

        if (sum != 0) {
            fprintf(stderr, "[%d] Fail: sum is not zero (%zu)\n", i, sum);
            err++;
            continue;
        }

        if (wu_queue_print(&ctx) == -1) {
            fprintf(stderr, "[%d] wu_queue_print() error\n", i);
            err++;
            continue;
        }

        printf("[%d] trying wu_queue_destroy()\n", i);
        if ((ret = wu_queue_destroy(&ctx)) != 0) {
            fprintf(stderr, "! Error: wu_queue_destroy() failed (%d): %s\n", ret, wu_queue_strerror(ret));
            err++;
            continue;
        }
    }

    printf("Catched %zu/%zu error(s).\n", err, err_max);

    if (err == err_max) {
        printf("Self-Test pass\n");
        return 0;
    }

    printf("Self-Test fail\n");
    return -1;
}
#endif // TEST_UNIT
