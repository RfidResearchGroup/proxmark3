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

#include "threads.h"

const char *thread_strerror(int error) {
    switch (error) {
        case THREAD_NOERROR:
            return (const char *) "No error";
        case THREAD_ERROR_CTX_IS_NULL:
            return (const char *) "CTX IS NULL";
        case THREAD_ERROR_CTX_IS_INIT:
            return (const char *) "CTX IS INIT";
        case THREAD_ERROR_TYPE_INVALID:
            return (const char *) "INVALID TYPE";
        case THREAD_ERROR_COUNT_INVALID:
            return (const char *) "INVALID THREAD COUNT";
        case THREAD_ERROR_ATTR_SETDETACH:
            return (const char *) "SETDETACHSTATE FAILED";
        case THREAD_ERROR_ATTR:
            return (const char *) "INIT ATTR FAILED";
        case THREAD_ERROR_MUTEXATTR:
            return (const char *) "INIT MUTEXATTR FAILED";
        case THREAD_ERROR_CREATE:
            return (const char *) "PTHREAD CREATE FAILED";
        case THREAD_ERROR_MUTEX:
            return (const char *) "INIT MUTEXFAILED";
        case THREAD_ERROR_COND:
            return (const char *) "INIT COND FAILED";
        case THREAD_ERROR_MUTEX_USLEEP:
            return (const char *) "INIT MUTEX USLEEP FAILED";
        case THREAD_ERROR_COND_USLEEP:
            return (const char *) "INIT COND USLEEP FAILED";
        case THREAD_ERROR_GENERIC:
            return (const char *) "GENERIC ERROR";
        case THREAD_ERROR_ALLOC:
            return (const char *) "ALLOC FAILED";
        case THREAD_ERROR_INTERNAL:
            return (const char *) "INTERNAL ERROR";
    }

    return (const char *) "GENERIC";
}

int thread_init(thread_ctx_t *ctx, short type, size_t thread_count) {
    if (!ctx) return THREAD_ERROR_CTX_IS_NULL;
    if (ctx->init) return THREAD_ERROR_CTX_IS_INIT;
    if (type != THREAD_TYPE_ASYNC && type != THREAD_TYPE_SEQ) return THREAD_ERROR_TYPE_INVALID;
    if (thread_count == 0) return THREAD_ERROR_COUNT_INVALID;

    memset(ctx, 0, sizeof(thread_ctx_t));

    ctx->thread_count = thread_count;
    ctx->type = type;
    ctx->enable_condusleep = (type == THREAD_TYPE_ASYNC && thread_count == 1);

    ctx->thread_handles = (pthread_t *) calloc(thread_count, sizeof(pthread_t));
    if (!ctx->thread_handles) {
        return THREAD_ERROR_ALLOC;
    }

    ctx->thread_mutexs = (pthread_mutex_t *) calloc(thread_count, sizeof(pthread_mutex_t));
    if (!ctx->thread_mutexs) {
        free(ctx->thread_handles);
        return THREAD_ERROR_ALLOC;
    }

    ctx->thread_conds = (pthread_cond_t *) calloc(thread_count, sizeof(pthread_cond_t));
    if (!ctx->thread_conds) {
        free(ctx->thread_handles);
        free(ctx->thread_mutexs);
        return THREAD_ERROR_ALLOC;
    }

    if (pthread_attr_init(&ctx->attr) != 0) {
        free(ctx->thread_handles);
        free(ctx->thread_mutexs);
        free(ctx->thread_conds);
        return THREAD_ERROR_ATTR;
    }

    pthread_attr_setdetachstate(&ctx->attr, PTHREAD_CREATE_JOINABLE);

    if (pthread_mutexattr_init(&ctx->mutex_attr) != 0) {
        free(ctx->thread_handles);
        free(ctx->thread_mutexs);
        free(ctx->thread_conds);
        pthread_attr_destroy(&ctx->attr);
        return THREAD_ERROR_MUTEXATTR;
    }

    pthread_mutexattr_settype(&ctx->mutex_attr, PTHREAD_MUTEX_ERRORCHECK);

    if (ctx->enable_condusleep) {
        if (pthread_mutex_init(&ctx->thread_mutex_usleep, NULL) != 0) {
            free(ctx->thread_handles);
            free(ctx->thread_mutexs);
            free(ctx->thread_conds);
            pthread_attr_destroy(&ctx->attr);
            pthread_mutexattr_destroy(&ctx->mutex_attr);
            return THREAD_ERROR_MUTEX_USLEEP;
        }

        if (pthread_cond_init(&ctx->thread_cond_usleep, NULL) != 0) {
            free(ctx->thread_handles);
            free(ctx->thread_mutexs);
            free(ctx->thread_conds);
            pthread_mutex_destroy(&ctx->thread_mutex_usleep);
            pthread_attr_destroy(&ctx->attr);
            pthread_mutexattr_destroy(&ctx->mutex_attr);
            return THREAD_ERROR_COND_USLEEP;
        }
    }

    int err = 0;
    int z = 0;

    for (z = 0; z < (int) ctx->thread_count; z++) {
        if (ctx->type == THREAD_TYPE_ASYNC) {
            if (pthread_mutex_init(&ctx->thread_mutexs[z], NULL) != 0) {
                err = THREAD_ERROR_MUTEX;
                break;
            }

            if (pthread_cond_init(&ctx->thread_conds[z], NULL) != 0) {
                pthread_mutex_destroy(&ctx->thread_mutexs[z]);
                err = THREAD_ERROR_COND;
                break;
            }
        }
    }

    if (err != 0) {
        z--; // step back

        for (; z >= 0; z--) {
            pthread_cond_destroy(&ctx->thread_conds[z]);
            pthread_mutex_destroy(&ctx->thread_mutexs[z]);
        }

        if (ctx->enable_condusleep) {
            pthread_mutex_destroy(&ctx->thread_mutex_usleep);
            pthread_cond_destroy(&ctx->thread_cond_usleep);
        }

        free(ctx->thread_handles);
        free(ctx->thread_mutexs);
        free(ctx->thread_conds);
        pthread_attr_destroy(&ctx->attr);
        pthread_mutexattr_destroy(&ctx->mutex_attr);
        return err;
    }

    ctx->init = 1;
    return 0;
}

int thread_start_scheduler(thread_ctx_t *ctx, thread_args_t *t_arg, wu_queue_ctx_t *queue_ctx) {
    size_t z;
    bool found = false;
    bool done = false;
    unsigned int th_cnt;

    if (ctx->type == THREAD_TYPE_SEQ) {
        bool error = false;
        uint32_t slice = 0;
        for (slice = 0; slice < t_arg[0].max_slices; slice += ctx->thread_count) {
            int err = 0;

            if ((err = thread_start(ctx, t_arg)) != 0) {
                printf("Error: thread_start() failed (%d): %s\n", err, thread_strerror(err));
            }

            // waiting threads return
            if (err == 0) thread_stop(ctx);

            for (z = 0; z < ctx->thread_count; z++) {
                if (t_arg[z].r) {
                    found = true;
                    break;
                }

                if (t_arg[z].err) {
                    error = true;
                }
            }

            // internal err
            if (error && err == 0) {
                thread_destroy(ctx);
                err = THREAD_ERROR_INTERNAL;
            }

            if (err != 0) return err;

            if (found) break;
        }
    } else if (ctx->type == THREAD_TYPE_ASYNC) {

        // crack hitag key or die tryin'
        do { // master
            th_cnt = 0;

            for (z = 0; z < ctx->thread_count; z++) {
#if TDEBUG >= 1 && DEBUGME == 1
                if (ctx->thread_count == 1) { printf("[%zu] get status from thread ...\n", z); fflush(stdout); }
#endif

                pthread_mutex_lock(&ctx->thread_mutexs[z]);
                thread_status_t cur_status = t_arg[z].status;
                pthread_mutex_unlock(&ctx->thread_mutexs[z]);

#if TDEBUG >= 1 && DEBUGME == 1
                if (ctx->thread_count == 1) { printf("[%zu] thread status: %s\n", z, thread_status_strdesc(cur_status)); fflush(stdout); }
#endif
                if (found) {
#if TDEBUG >= 3
                    printf("[%zu] Processing exit logic\n", z);
                    fflush(stdout);
#endif

                    if (cur_status < TH_FOUND_KEY) {
#if TDEBUG >= 1
                        printf("[%zu] key found from another thread, set quit\n", z);
                        fflush(stdout);
#endif
                        pthread_mutex_lock(&ctx->thread_mutexs[z]);
                        t_arg[z].status = TH_END;
                        t_arg[z].quit = true;
                        if (cur_status == TH_WAIT) {
                            pthread_cond_signal(&ctx->thread_conds[z]);
                        }
                        pthread_mutex_unlock(&ctx->thread_mutexs[z]);
                    } else {
                        if (ctx->thread_count == 1) {
                            th_cnt++;
#if TDEBUG >= 1
                            printf("[%zu] Increment th_cnt: %u/%zu\n", z, th_cnt, ctx->thread_count);
                            fflush(stdout);
#endif
                        }
                    }
                    continue;
                }

                if (cur_status == TH_WAIT) {
                    pthread_mutex_lock(&ctx->thread_mutexs[z]);

                    if (wu_queue_done(queue_ctx) != QUEUE_EMPTY) {
                        t_arg[z].status = TH_PROCESSING;

#if TDEBUG >= 1
                        printf("[master] thread [%zu], I give you another try (%s)\n", z, thread_status_strdesc(t_arg[z].status));
                        fflush(stdout);
#endif

                        pthread_cond_signal(&ctx->thread_conds[z]);
                        pthread_mutex_unlock(&ctx->thread_mutexs[z]);
                        continue;
                    } else {
#if TDEBUG >= 1
                        printf("[master] thread [%zu], max step reached. Quit.\n", z);
                        fflush(stdout);
#endif

                        cur_status = t_arg[z].status = TH_END;
                        t_arg[z].quit = true;

                        pthread_cond_signal(&ctx->thread_conds[z]);
                        pthread_mutex_unlock(&ctx->thread_mutexs[z]);
                    }
                }

                if (cur_status == TH_PROCESSING) {
                    if (ctx->enable_condusleep) {
#if TDEBUG >= 1
                        printf("[master] before pthread_cond_wait, TH_PROCESSING\n");
                        fflush(stdout);
#endif
                        pthread_mutex_lock(&ctx->thread_mutex_usleep);
#if TDEBUG >= 1
                        printf("[master] thread [%zu], I'm waiting you end of task, I'm in %s give me a signal.\n", z, thread_status_strdesc(t_arg[z].status));
                        fflush(stdout);
#endif
                        pthread_cond_wait(&ctx->thread_cond_usleep, &ctx->thread_mutex_usleep);
#if TDEBUG >= 1
                        printf("[master] thread [%zu], got the signal with new state: %s.\n", z, thread_status_strdesc(t_arg[z].status));
                        fflush(stdout);
#endif
                        if (t_arg[z].status == TH_FOUND_KEY) {
                            found = true;
                        }

                        pthread_mutex_unlock(&ctx->thread_mutex_usleep);
#if TDEBUG >= 1
                        printf("[master] after pthread_cond_wait, TH_PROCESSING\n");
                        fflush(stdout);
#endif
                        continue;
                    }

                    // since found is handled before this part (line 237), removing the if-statement
                    // doesn't change anything according to cppcheck.
#if TDEBUG >= 1
                    printf("[master] thread [%zu], the key is found. set TH_END from TH_PROCESSING\n", z);
                    fflush(stdout);
#endif
                    pthread_mutex_lock(&ctx->thread_mutexs[z]);
                    t_arg[z].status = TH_END;
                    t_arg[z].quit = true;
                    pthread_mutex_unlock(&ctx->thread_mutexs[z]);
                    continue;

                }
                if (cur_status == TH_ERROR) {
                    // something went wrong
                    pthread_mutex_lock(&ctx->thread_mutexs[z]);
                    t_arg[z].status = TH_END;
                    t_arg[z].quit = true;
                    pthread_mutex_unlock(&ctx->thread_mutexs[z]);
                    continue;
                }

                if (cur_status >= TH_FOUND_KEY) {
                    th_cnt++;

                    if (cur_status == TH_FOUND_KEY) {
                        thread_setEnd(ctx, t_arg);
                        found = true;
                        done = true;
                    }
                }
            }

            if (th_cnt == ctx->thread_count) done = true;

        } while (!done);
    }

    return (found) ? 0 : 1;
}

int thread_destroy(thread_ctx_t *ctx) {
    if (!ctx) return -1;
    if (!ctx->init) return -2;

    if (ctx->enable_condusleep) {
        pthread_cond_destroy(&ctx->thread_cond_usleep);
        pthread_mutex_destroy(&ctx->thread_mutex_usleep);
    }

    for (size_t z = 0; z < ctx->thread_count; z++) {
        pthread_cond_destroy(&ctx->thread_conds[z]);
        pthread_mutex_destroy(&ctx->thread_mutexs[z]);
    }

    pthread_mutexattr_destroy(&ctx->mutex_attr);
    pthread_attr_init(&ctx->attr);

    free(ctx->thread_conds);
    free(ctx->thread_mutexs);
    free(ctx->thread_handles);

    memset(ctx, 0, sizeof(thread_ctx_t));
    ctx->init = 0;
    return 0;
}

int thread_start(thread_ctx_t *ctx, thread_args_t *t_arg) {
    int err = 0;
    int z = 0;

    for (z = 0; z < (int) ctx->thread_count; z++) {
        if (pthread_create(&ctx->thread_handles[z], &ctx->attr, (ctx->type == THREAD_TYPE_ASYNC) ? computing_process_async : computing_process, (void *) &t_arg[z]) != 0) {
            err = THREAD_ERROR_CREATE;
            break;
        }
    }

    if (err != 0) {
        z--; // step back

        for (; z >= 0; z++) {
            pthread_cancel(ctx->thread_handles[z]);
            pthread_join(ctx->thread_handles[z], NULL);
        }

        return err;
    }

    return 0;
}

int thread_stop(thread_ctx_t *ctx) {
    for (size_t z = 0; z < ctx->thread_count; z++) {
        if (ctx->type == THREAD_TYPE_ASYNC) pthread_cancel(ctx->thread_handles[z]);
        pthread_join(ctx->thread_handles[z], NULL);
    }

    return 0;
}

const char *thread_status_strdesc(thread_status_t s) {
    switch (s) {
        case TH_START:
            return (const char *) "START";
        case TH_WAIT:
            return (const char *) "WAIT";
        case TH_PROCESSING:
            return (const char *) "PROCESSING";
        case TH_ERROR:
            return (const char *) "ERROR";
        case TH_FOUND_KEY:
            return (const char *) "FOUND_KEY";
        case TH_END:
            return (const char *) "END";
    }

    return (const char *) "... or die tryin'";
}

bool thread_setEnd(thread_ctx_t *ctx, thread_args_t *t_arg) {
    bool found = false;

    size_t z;

    int c_ret = 0;

    for (z = 0; z < ctx->thread_count; z++) {
        int m_ret = pthread_mutex_lock(&ctx->thread_mutexs[z]);
        if (m_ret != 0) {
            printf("[%zu] [%s] Error: pthread_mutex_lock() failed (%d): %s\n", z, __func__, m_ret, strerror(m_ret));
        }

        thread_status_t tmp = t_arg[z].status;

#if DEBUGME > 0
        printf("[%zu] [%s] Thread status: %s\n", z, __func__, thread_status_strdesc(t_arg[z].status));
#endif

        if (tmp == TH_FOUND_KEY || tmp == TH_END || tmp == TH_ERROR) {
            if (tmp == TH_FOUND_KEY) found = true;
            pthread_mutex_unlock(&ctx->thread_mutexs[z]);
            continue;
        }

#if DEBUGME > 0
        printf("[%zu] [%s] Set thread status to TH_END\n", z, __func__);
#endif

        t_arg[z].status = TH_END;

        if (tmp == TH_WAIT) {
#if DEBUGME > 0
            printf("[%zu] [%s] Send cond_signal to thread\n", z, __func__);
#endif

            c_ret = pthread_cond_signal(&ctx->thread_conds[z]);
            if (c_ret != 0) {
                printf("[%zu] [%s] Error: pthread_cond_signal() failed (%d): %s\n", z, __func__, c_ret, strerror(c_ret));
            }
        }

        pthread_mutex_unlock(&ctx->thread_mutexs[z]);
    }

    return found;
}

void *computing_process(void *arg) {
    thread_args_t *a = (thread_args_t *) arg;

    uint64_t off = 0;

    size_t z = a->device_id;
    uint64_t *matches = a->matches;
    uint32_t *matches_found = a->matches_found;

    uint32_t uid = a->uid;
    uint32_t aR2 = a->aR2;
    uint32_t nR1 = a->nR1;
    uint32_t nR2 = a->nR2;

    opencl_ctx_t *ctx = a->ocl_ctx;

    wu_queue_data_t wu;
    wu_queue_pop(&ctx->queue_ctx, &wu, false);
    off = wu.off;
    a->slice = wu.id + 1;

    if (ctx->queue_ctx.queue_type == QUEUE_TYPE_RANDOM) {
        float progress = 100.0 - (((wu.rem + 1) * 100.0) / wu.max);
#if DEBUGME > 0
        printf("[%zu] Slice %zu (off %zu), max %zu, remain %zu slice(s)\n", z, wu.id + 1, wu.off, wu.max, wu.rem);
#else
        printf("\r[%zu] Slice %zu/%zu (%zu remain) ( %2.1f%% )", z, wu.id + 1, wu.max, wu.rem, progress);
#endif // DEBUGME
    } else {
        float progress = (((wu.id + 1) * 100.0) / wu.max);
#if DEBUGME > 0
        printf("[%zu] Slice %zu/%zu, off %zu\n", z, wu.id + 1, wu.max, wu.off);
#else
        printf("\r[%zu] Slice %zu/%zu ( %2.1f%% )", z, wu.id + 1, wu.max, progress);
#endif // DEBUGME
    }
    fflush(stdout);

    int ret = runKernel(ctx, (uint32_t) off, matches, matches_found, z);

    a->r = false;
    a->err = false;

    if (ret < 1) { // error or nada
        if (ret == -1) a->err = true;
        pthread_exit(NULL);
    }

    if (!ctx->force_hitag2_opencl) {
#if DEBUGME >= 2
        printf("[%s][%zu] master, I found %5u candidates @ slice %zu\n", __func__, z, matches_found[0], a->slice + 1);
        fflush(stdout);
#endif

        for (uint32_t match = 0; match < matches_found[0]; match++) {
            a->r = try_state(matches[match], uid, aR2, nR1, nR2, &a->key);
            if (a->r) break;
        }
    } else {
        // the OpenCL kernel return only one key if found, else nothing

#if TDEBUG >= 1
        printf("[%s][%zu] master, I found the key @ slice %zu\n", __func__, z, a->slice + 1);
        fflush(stdout);
#endif

        a->r = true;
        a->key = matches[0];
    }

    pthread_exit(NULL);
    return NULL;
}

void *computing_process_async(void *arg) {
    thread_args_t *a = (thread_args_t *) arg;

    size_t z = a->device_id;

    // TH_START, not really needed lock with mutex here
    pthread_mutex_lock(&a->thread_ctx->thread_mutexs[z]);

    // fetching data from thread struct, I hope they are good
    thread_status_t status = a->status;

    uint64_t *matches = a->matches;
    uint32_t *matches_found = a->matches_found;
    uint32_t uid = a->uid;
    uint32_t aR2 = a->aR2;
    uint32_t nR1 = a->nR1;
    uint32_t nR2 = a->nR2;

    size_t max_slices = a->max_slices;

    opencl_ctx_t *ctx = a->ocl_ctx;

    pthread_mutex_unlock(&a->thread_ctx->thread_mutexs[z]);

    if (status == TH_START) {
#if TDEBUG >= 1
        printf("[%s][%zu] plat id %d, uid %u, aR2 %u, nR1 %u, nR2 %u, Initial status: %s\n", __func__, z, ctx->id_platform, uid, aR2, nR1, nR2, thread_status_strdesc(status));
#endif
        status = TH_WAIT;
        // proceed to next
    }

    do {
        if (status == TH_WAIT) {
            pthread_mutex_lock(&a->thread_ctx->thread_mutexs[z]);

            // update thread status to WAIT, todo: check with multiple devices

            if (a->status == TH_END) { // other threads found the key
                fflush(stdout);
                //status = TH_END;
                a->quit = true;
                pthread_mutex_unlock(&a->thread_ctx->thread_mutexs[z]);
                pthread_exit(NULL);
            } else {
                a->status = TH_WAIT;

                if (a->thread_ctx->enable_condusleep) {
                    pthread_mutex_lock(&a->thread_ctx->thread_mutex_usleep);
                    pthread_cond_signal(&a->thread_ctx->thread_cond_usleep);  // unlock master/TH_PROCESSING cond
#if TDEBUG >= 1
                    printf("[%s][%zu] after pthread_cond_signal TH_WAIT\n", __func__, z);
                    fflush(stdout);
#endif
                    pthread_mutex_unlock(&a->thread_ctx->thread_mutex_usleep);
                }
            }

#if TDEBUG >= 1
            printf("[%s][%zu] master, i'm here to serve you. I'm in %s give me a signal.\n", __func__, z, thread_status_strdesc(status));
            fflush(stdout);
#endif

            pthread_cond_wait(&a->thread_ctx->thread_conds[z], &a->thread_ctx->thread_mutexs[z]);

            status = a->status; // read new status from master

#if TDEBUG >= 2
            printf("[%s][%zu] master, got the signal with new state: %s.\n", __func__, z, thread_status_strdesc(status));
            fflush(stdout);
#endif

            pthread_mutex_unlock(&a->thread_ctx->thread_mutexs[z]);

            if (status == TH_WAIT) {
#if TDEBUG >=1
                printf("[%s] ! Error: need to be TH_PROCESSING or TH_END, not TH_WAIT ... exit\n", __func__);
                fflush(stdout);
#endif
                break;
            }
        }

        if (status == TH_ERROR) {
#if TDEBUG >= 1
            printf("[%s][%zu] master, got error signal, proceed with exit\n", __func__, z);
            fflush(stdout);
#endif
            pthread_exit(NULL);
        }

        if (status == TH_PROCESSING) {
#if TDEBUG >= 2
            printf("[%s][%zu] master, got a work-unit, processing ...\n", __func__, z);
            fflush(stdout);
#endif

            wu_queue_data_t wu;
            wu_queue_pop(&ctx->queue_ctx, &wu, false);
            uint32_t off = wu.off;
            a->slice = wu.id + 1;

            if (ctx->queue_ctx.queue_type == QUEUE_TYPE_RANDOM) {
                float progress = 100.0 - (((wu.rem + 1) * 100.0) / wu.max);
#if DEBUGME > 0
                printf("[%zu] Slice %zu (off %zu), max %zu, remain %zu slice(s)\n", z, wu.id + 1, wu.off, wu.max, wu.rem);
#else
                printf("\r[%zu] Slice %zu/%zu (%zu remain) ( %2.1f%% )", z, wu.id + 1, wu.max, wu.rem, progress);
#endif // DEBUGME
            } else {
                float progress = (((wu.id + 1) * 100.0) / wu.max);
#if DEBUGME > 0
                printf("[%zu] Slice %zu/%zu, off %zu\n", z, wu.id + 1, wu.max, wu.off);
#else
                printf("\r[%zu] Slice %zu/%zu ( %2.1f%% )", z, wu.id + 1, wu.max, progress);
#endif // DEBUGME
            }

            fflush(stdout);

            int ret = runKernel(ctx, off, matches, matches_found, z);

            if (ret < 1) { // error or nada
                if (ret == -1) {
                    // untested code
                    pthread_mutex_lock(&a->thread_ctx->thread_mutexs[z]);
                    a->err = true;
                    a->status = TH_ERROR;
                    pthread_mutex_unlock(&a->thread_ctx->thread_mutexs[z]);
#if TDEBUG >= 1
                    printf("[%s][%zu] master, something is broken, exit\n", __func__, z);
                    fflush(stdout);
#endif

                    if (a->thread_ctx->enable_condusleep) {
                        pthread_mutex_lock(&a->thread_ctx->thread_mutex_usleep);
                        pthread_cond_signal(&a->thread_ctx->thread_cond_usleep);  // unlock master/TH_PROCESSING cond
#if TDEBUG >= 1
                        printf("[%s][%zu] after pthread_cond_signal TH_ERROR\n", __func__, z);
#endif
                        pthread_mutex_unlock(&a->thread_ctx->thread_mutex_usleep);
                    }

                    pthread_exit(NULL);
                    // end of unstested code
                }

#if TDEBUG >= 1
                printf("[%s][%zu] master, process is done but no candidates found\n", __func__, z);
                fflush(stdout);
#endif
                pthread_mutex_lock(&a->thread_ctx->thread_mutexs[z]);

                if (a->slice >= max_slices) a->status = TH_END;
                else a->status = TH_WAIT;

                status = a->status;

                pthread_mutex_unlock(&a->thread_ctx->thread_mutexs[z]);

                if (a->thread_ctx->enable_condusleep) {
                    pthread_mutex_lock(&a->thread_ctx->thread_mutex_usleep);
                    pthread_cond_signal(&a->thread_ctx->thread_cond_usleep);  // unlock master/TH_PROCESSING cond
#if TDEBUG >= 1
                    printf("[%s][%zu] after pthread_cond_signal TH_WAIT\n", __func__, z);
                    fflush(stdout);
#endif
                    pthread_mutex_unlock(&a->thread_ctx->thread_mutex_usleep);
                }

                continue;
            }

            if (!ctx->force_hitag2_opencl) {
#if TDEBUG >= 1
                printf("[%s][%zu] master, we got %5u candidates. Proceed to validation\n", __func__, z, matches_found[0]);
                fflush(stdout);
#endif

                for (uint32_t match = 0; match < matches_found[0]; match++) {
                    if (a->quit) {
                        pthread_mutex_lock(&a->thread_ctx->thread_mutexs[z]);
                        a->status = TH_END;
                        pthread_mutex_unlock(&a->thread_ctx->thread_mutexs[z]);
#if TDEBUG >= 1
                        printf("[%s][%zu] master, Another thread found the key, quit 2 \n", __func__, z);
                        fflush(stdout);
#endif

                        if (a->thread_ctx->enable_condusleep) {
                            pthread_mutex_lock(&a->thread_ctx->thread_mutex_usleep);
                            pthread_cond_signal(&a->thread_ctx->thread_cond_usleep);  // unlock master/TH_PROCESSING cond
#if TDEBUG >= 1
                            printf("[%s][%zu] after pthread_cond_signal TH_END\n", __func__, z);
                            fflush(stdout);
#endif
                            pthread_mutex_unlock(&a->thread_ctx->thread_mutex_usleep);
                        }

                        pthread_exit(NULL);
                    }

                    a->r = try_state(matches[match], uid, aR2, nR1, nR2, &a->key);
                    if (a->r) {
                        pthread_mutex_lock(&a->thread_ctx->thread_mutexs[z]);
                        a->s = matches[match];
                        a->status = TH_FOUND_KEY;
                        a->quit = true;
                        pthread_mutex_unlock(&a->thread_ctx->thread_mutexs[z]);
#if TDEBUG >= 1
                        printf("[%s][%zu] master, I found the key ! state %" STR(OFF_FORMAT_U) ", slice %zu\n", __func__, z, a->s, a->slice + 1);
                        fflush(stdout);
#endif

                        if (a->thread_ctx->enable_condusleep) {
                            pthread_mutex_lock(&a->thread_ctx->thread_mutex_usleep);
                            pthread_cond_signal(&a->thread_ctx->thread_cond_usleep);  // unlock master/TH_PROCESSING cond
#if TDEBUG >= 1
                            printf("[%s][%zu] after pthread_cond_signal TH_FOUND_KEY\n", __func__, z);
#endif
                            pthread_mutex_unlock(&a->thread_ctx->thread_mutex_usleep);
                        }

                        pthread_exit(NULL);
                    }
                }

                if (a->quit) {
                    pthread_mutex_lock(&a->thread_ctx->thread_mutexs[z]);
                    a->status = TH_END;
                    pthread_mutex_unlock(&a->thread_ctx->thread_mutexs[z]);
#if TDEBUG >= 1
                    printf("[%s][%zu] master, Another thread found the key, quit 1 \n", __func__, z);
                    fflush(stdout);
#endif

                    if (a->thread_ctx->enable_condusleep) {
                        pthread_mutex_lock(&a->thread_ctx->thread_mutex_usleep);
                        pthread_cond_signal(&a->thread_ctx->thread_cond_usleep);  // unlock master/TH_PROCESSING cond
#if TDEBUG >= 1
                        printf("[%s][%zu] after pthread_cond_signal TH_END\n", __func__, z);
#endif
                        pthread_mutex_unlock(&a->thread_ctx->thread_mutex_usleep);
                    }

                    pthread_exit(NULL);
                }

                // setting internal status to wait
                status = TH_WAIT;
                continue;
            } else {
                // the OpenCL kernel return only one key if found, else nothing

                pthread_mutex_lock(&a->thread_ctx->thread_mutexs[z]);
                a->r = true;
                a->key = matches[0];
                status = a->status = TH_FOUND_KEY;
                a->quit = true;
                pthread_mutex_unlock(&a->thread_ctx->thread_mutexs[z]);
#if TDEBUG >= 1
                printf("[%s][%zu] master, I found the key at slice %zu\n", __func__, z, a->slice + 1);
                fflush(stdout);
#endif

                if (a->thread_ctx->enable_condusleep) {
                    pthread_mutex_lock(&a->thread_ctx->thread_mutex_usleep);
                    pthread_cond_signal(&a->thread_ctx->thread_cond_usleep);  // unlock master/TH_PROCESSING cond
#if TDEBUG >= 1
                    printf("[%s][%zu] after pthread_cond_signal TH_FOUND_KEY\n", __func__, z);
#endif
                    pthread_mutex_unlock(&a->thread_ctx->thread_mutex_usleep);
                }

                pthread_exit(NULL);
            }
        }

        if (status >= TH_FOUND_KEY) {
#if TDEBUG >= 1
            if (status == TH_FOUND_KEY) {
                printf("[%s][%zu] master, TH_FOUND_KEY, if you see this message, something is wrong\n", __func__, z);
                fflush(stdout);
            } else if (status == TH_END) {
                printf("[%s][%zu] master, TH_END reached\n", __func__, z);
                fflush(stdout);
            }
#endif
            pthread_exit(NULL);
        }

    } while (status < TH_FOUND_KEY);

    pthread_exit(NULL);
    return NULL;
}
