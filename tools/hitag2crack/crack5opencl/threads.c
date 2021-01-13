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

const char *thread_strerror (int error)
{
	switch (error)
	{
		case THREAD_NOERROR: return (const char *) "No error";
	}

	return (const char *) "GENERIC";
}

int thread_init (thread_ctx_t *ctx, short type, size_t thread_count)
{
	if (!ctx) return THREAD_ERROR_CTX_IS_NULL;
	if (ctx->init) return THREAD_ERROR_CTX_IS_INIT;
	if (type != THREAD_TYPE_ASYNC && type != THREAD_TYPE_SEQ) return THREAD_ERROR_TYPE_INVALID;
	if (thread_count == 0) return THREAD_ERROR_COUNT_INVALID;

	memset (ctx, 0, sizeof (thread_ctx_t));

	ctx->thread_count = thread_count;
	ctx->type = type;
	ctx->enable_condusleep = (type == THREAD_TYPE_ASYNC && thread_count == 1);

	ctx->thread_handles = (pthread_t *) calloc (thread_count, sizeof (pthread_t));
	if (!ctx->thread_handles)
	{
		return THREAD_ERROR_ALLOC;
	}

	ctx->thread_mutexs = (pthread_mutex_t *) calloc (thread_count, sizeof (pthread_mutex_t));
	if (!ctx->thread_mutexs)
	{
		free (ctx->thread_handles);
		return THREAD_ERROR_ALLOC;
	}

	ctx->thread_conds = (pthread_cond_t *) calloc (thread_count, sizeof (pthread_cond_t));
	if (!ctx->thread_conds)
	{
		free (ctx->thread_handles);
		free (ctx->thread_mutexs);
		return THREAD_ERROR_ALLOC;
	}

	if (pthread_attr_init (&ctx->attr) != 0)
	{
		free (ctx->thread_handles);
		free (ctx->thread_mutexs);
		free (ctx->thread_conds);
		return THREAD_ERROR_ATTR;
	}

	pthread_attr_setdetachstate (&ctx->attr, PTHREAD_CREATE_JOINABLE);

	if (pthread_mutexattr_init (&ctx->mutex_attr) != 0)
	{
		free (ctx->thread_handles);
		free (ctx->thread_mutexs);
		free (ctx->thread_conds);
		pthread_attr_destroy (&ctx->attr);
		return THREAD_ERROR_MUTEXATTR;
	}

	pthread_mutexattr_settype (&ctx->mutex_attr, PTHREAD_MUTEX_ERRORCHECK);

	if (ctx->enable_condusleep)
	{
		if (pthread_mutex_init (&ctx->thread_mutex_usleep, NULL) != 0)
		{
			free (ctx->thread_handles);
			free (ctx->thread_mutexs);
			free (ctx->thread_conds);
			pthread_attr_destroy (&ctx->attr);
			pthread_mutexattr_destroy (&ctx->mutex_attr);
			return THREAD_ERROR_MUTEX_USLEEP;
		}

		if (pthread_cond_init (&ctx->thread_cond_usleep, NULL) != 0)
		{
			free (ctx->thread_handles);
			free (ctx->thread_mutexs);
			free (ctx->thread_conds);
			pthread_mutex_destroy (&ctx->thread_mutex_usleep);
			pthread_attr_destroy (&ctx->attr);
			pthread_mutexattr_destroy (&ctx->mutex_attr);
			return THREAD_ERROR_COND_USLEEP;
		}
	}

	int err = 0;
	int z = 0;

	for (z = 0; z < (int) ctx->thread_count; z++)
	{
		if (ctx->type == THREAD_TYPE_ASYNC)
		{
			if (pthread_mutex_init (&ctx->thread_mutexs[z], NULL) != 0)
			{
				err = THREAD_ERROR_MUTEX;
				break;
			}

			if (pthread_cond_init (&ctx->thread_conds[z], NULL) != 0)
			{
				pthread_mutex_destroy (&ctx->thread_mutexs[z]);
				err = THREAD_ERROR_COND;
				break;
			}
		}
	}

	if (err != 0)
	{
		z--; // step back

		for (; z >= 0; z--)
		{
			pthread_cond_destroy (&ctx->thread_conds[z]);
			pthread_mutex_destroy (&ctx->thread_mutexs[z]);
		}

		if (ctx->enable_condusleep)
		{
			pthread_mutex_destroy (&ctx->thread_mutex_usleep);
			pthread_cond_destroy (&ctx->thread_cond_usleep);
		}

		free (ctx->thread_handles);
		free (ctx->thread_mutexs);
		free (ctx->thread_conds);
		pthread_attr_destroy (&ctx->attr);
		pthread_mutexattr_destroy (&ctx->mutex_attr);
		return err;
	}

	ctx->init = 1;
	return 0;
}

int thread_destroy (thread_ctx_t *ctx)
{
	if (!ctx) return -1;
	if (!ctx->init) return -2;

	if (ctx->enable_condusleep)
	{
		pthread_cond_destroy (&ctx->thread_cond_usleep);
		pthread_mutex_destroy (&ctx->thread_mutex_usleep);
	}

	for (size_t z = 0; z < ctx->thread_count; z++)
	{
		pthread_cond_destroy (&ctx->thread_conds[z]);
		pthread_mutex_destroy (&ctx->thread_mutexs[z]);
	}

	pthread_mutexattr_destroy (&ctx->mutex_attr);
	pthread_attr_init (&ctx->attr);

	free (ctx->thread_conds);
	free (ctx->thread_mutexs);
	free (ctx->thread_handles);

	memset (ctx, 0, sizeof (thread_ctx_t));
	ctx->init = 0;
	return 0;
}

int thread_start (thread_ctx_t *ctx, thread_args_t *t_arg)
{
	int err = 0;
	int z = 0;

	for (z = 0; z < (int) ctx->thread_count; z++)
	{
		if (pthread_create (&ctx->thread_handles[z], &ctx->attr, (ctx->type == THREAD_TYPE_ASYNC) ? computing_process_async : computing_process, (void *) &t_arg[z]) != 0)
		{
			err = THREAD_ERROR_CREATE;
			break;
		}
	}

	if (err != 0)
	{
		z--; // step back

		for (; z >= 0; z++)
		{
			pthread_cancel (ctx->thread_handles[z]);
			pthread_join (ctx->thread_handles[z], NULL);
		}

		return err;
	}

	return 0;
}

int thread_stop (thread_ctx_t *ctx)
{
	for (size_t z = 0; z < ctx->thread_count; z++)
	{
		if (ctx->type == THREAD_TYPE_ASYNC) pthread_cancel (ctx->thread_handles[z]);
		pthread_join (ctx->thread_handles[z], NULL);
	}

	return 0;
}

__attribute__ ((format (printf, 1, 2)))
void tprintf (const char * restrict format, ...)
{
	flockfile (stdout);

	va_list va_args;
	va_start (va_args, format);
	vprintf (format, va_args);
	va_end (va_args);

	funlockfile (stdout);

	fflush (stdout);
}

const char *thread_status_strdesc (thread_status_t s)
{
	switch (s)
	{
		case TH_START: return (const char *) "START";
		case TH_WAIT: return (const char *) "WAIT";
		case TH_PROCESSING: return (const char *) "PROCESSING";
		case TH_ERROR: return (const char *) "ERROR";
		case TH_STOP: return (const char *) "STOP";
		case TH_FOUND_KEY: return (const char *) "FOUND_KEY";
		case TH_END: return (const char *) "END";
	}

	return (const char *) "... or die tryin'";
}

bool thread_setEnd (thread_ctx_t *ctx, thread_args_t *t_arg)
{
	bool found = false;

	size_t z;

	int m_ret = 0;
	int c_ret = 0;

	for (z = 0; z < ctx->thread_count; z++)
	{
		m_ret = pthread_mutex_lock (&ctx->thread_mutexs[z]);
		if (m_ret != 0)
		{
			tprintf ("[%zu] [%s] Error: pthread_mutex_lock() failed (%d): %s\n", z, __func__, m_ret, strerror (m_ret));
		}

		thread_status_t tmp = t_arg[z].status;

		#if DEBUGME > 0
		tprintf ("[%zu] [%s] Thread status: %s\n", z, __func__, thread_status_strdesc(t_arg[z].status));
		#endif

		if (tmp == TH_FOUND_KEY || tmp == TH_END || tmp == TH_ERROR)
		{
			if (tmp == TH_FOUND_KEY) found = true;
			pthread_mutex_unlock (&ctx->thread_mutexs[z]);
			continue;
		}

		#if DEBUGME > 0
		tprintf ("[%zu] [%s] Set thread status to TH_STOP\n", z, __func__);
		#endif

		t_arg[z].status = TH_STOP;

		if (tmp == TH_WAIT)
		{
			#if DEBUGME > 0
			tprintf ("[%zu] [%s] Send cond_signal to thread\n", z, __func__);
			#endif

			c_ret = pthread_cond_signal (&ctx->thread_conds[z]);
			if (c_ret != 0)
			{
				tprintf ("[%zu] [%s] Error: pthread_cond_signal() failed (%d): %s\n", z, __func__, c_ret, strerror (c_ret));
			}
		}

		pthread_mutex_unlock (&ctx->thread_mutexs[z]);
	}

	return found;
}

void *computing_process (void *arg)
{
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
	wu_queue_pop (&ctx->queue_ctx, &wu, false);
	off = wu.off;
	a->slice = wu.id+1;

	if (ctx->queue_ctx.queue_type == QUEUE_TYPE_RANDOM)
	{
		#if DEBUGME > 0
		printf ("[%zu] Slice %zu (off %zu), max %zu, remain %zu slice(s)\n", z, wu.id+1, wu.off, wu.max, wu.rem);
		#else
		printf ("[%zu] Slice %zu/%zu (%zu remain)\n", z, wu.id+1, wu.max, wu.rem);
		#endif // DEBUGME
	}
	else
	{
		#if DEBUGME > 0
		printf ("[%zu] Slice %zu/%zu, off %zu\n", z, wu.id+1, wu.max, wu.off);
		#else
		printf ("[%zu] Slice %zu/%zu\n", z, wu.id+1, wu.max);
		#endif // DEBUGME
	}
	fflush (stdout);

	int ret = runKernel (ctx, (uint32_t) off, matches, matches_found, z);

	a->r = false;
	a->err = false;

	if (ret < 1) // error or nada
	{
		if (ret == -1) a->err = true;
		pthread_exit (NULL);
	}

	if (!ctx->force_hitag2_opencl)
	{
		#if DEBUGME >= 2
		printf ("[slave][%zu] master, I found %5u candidates @ slice %zu\n", z, matches_found[0], a->slice+1);
		fflush (stdout);
		#endif

		for (uint32_t match = 0; match < matches_found[0]; match++)
		{
			a->r = try_state (matches[match], uid, aR2, nR1, nR2, &a->key);
			if (a->r) break;
		}
	}
	else
	{
		// the OpenCL kernel return only one key if found, else nothing

		#if TDEBUG >= 1
		printf ("[slave][%zu] master, I found the key @ slice %zu\n", z, a->slice+1);
		fflush (stdout);
		#endif

		a->r = true;
		a->key = matches[0];
	}

	pthread_exit (NULL);
}

void *computing_process_async (void *arg)
{
	thread_args_t *a = (thread_args_t *) arg;

	size_t z = a->device_id;

	// TH_START, not really needed lock with mutex here
	pthread_mutex_lock (&a->thread_ctx->thread_mutexs[z]);

	// fetching data from thread struct, I hope they are good
	thread_status_t status = a->status;

	uint32_t uid = a->uid;
	uint32_t aR2 = a->aR2;
	uint32_t nR1 = a->nR1;
	uint32_t nR2 = a->nR2;

	uint64_t *matches = a->matches;
	uint32_t *matches_found = a->matches_found;
	size_t max_step = a->max_step;

	opencl_ctx_t *ctx = a->ocl_ctx;

	pthread_mutex_unlock (&a->thread_ctx->thread_mutexs[z]);

	uint64_t off = 0;
//	size_t slice = 0;
	int ret = 0;

	if (status == TH_START)
	{
		#if TDEBUG >= 1
		printf ("[slave][%zu] plat id %d, uid %u, aR2 %u, nR1 %u, nR2 %u, Initial status: %s\n", z, ctx->id_platform, uid, aR2, nR1, nR2, thread_status_strdesc (status));
		#endif
		status = TH_WAIT;
		// proceed to next
	}

	do // slave
	{
		if (status == TH_WAIT)
		{
			pthread_mutex_lock (&a->thread_ctx->thread_mutexs[z]);

			// update thread status to WAIT, todo: check with multiple devices

			if (a->status == TH_END) // other threads found the key
			{
				fflush(stdout);
				status = TH_END;
				a->quit = true;
				pthread_mutex_unlock (&a->thread_ctx->thread_mutexs[z]);
				pthread_exit (NULL);
			}
			else
			{
				a->status = TH_WAIT;

				if (a->thread_ctx->enable_condusleep)
				{
					pthread_mutex_lock (&a->thread_ctx->thread_mutex_usleep);
					pthread_cond_signal (&a->thread_ctx->thread_cond_usleep); // unlock master/TH_PROCESSING cond
					#if TDEBUG >= 1
					printf ("[slate][%zu] after pthread_cond_signal TH_WAIT\n", z);
					fflush (stdout);
					#endif
					pthread_mutex_unlock (&a->thread_ctx->thread_mutex_usleep);
				}
			}

			#if TDEBUG >= 1
			printf ("[slave][%zu] master, i'm here to serve you. I'm in %s give me a signal.\n", z, thread_status_strdesc (status));
			fflush (stdout);
			#endif

			pthread_cond_wait (&a->thread_ctx->thread_conds[z], &a->thread_ctx->thread_mutexs[z]);

			status = a->status; // read new status from master

			#if TDEBUG >= 2
			printf ("[slave][%zu] master, got the signal with new state: %s.\n", z, thread_status_strdesc (status));
			fflush (stdout);
			#endif

			pthread_mutex_unlock (&a->thread_ctx->thread_mutexs[z]);

			if (status == TH_WAIT)
			{
				#if TDEBUG >=1
				printf ("[slave] ! Error: need to be TH_PROCESSING or TH_END, not TH_WAIT ... exit\n");
				fflush (stdout);
				#endif
				break;
			}
		}

		if (status == TH_ERROR)
		{
			#if TDEBUG >= 1
			printf ("[slave][%zu] master, got error signal, proceed with exit\n", z);
			fflush (stdout);
			#endif
			pthread_exit (NULL);
		}

		if (status == TH_PROCESSING)
		{
			#if TDEBUG >= 2
			printf ("[slave][%zu] master, got a work-unit, processing ...\n", z);
			fflush (stdout);
			#endif

			wu_queue_data_t wu;
			wu_queue_pop (&ctx->queue_ctx, &wu, false);
			off = wu.off;
			a->slice = wu.id+1;

			if (ctx->queue_ctx.queue_type == QUEUE_TYPE_RANDOM)
			{
				#if DEBUGME > 0
				printf ("[%zu] Slice %zu (off %zu), max %zu, remain %zu slice(s)\n", z, wu.id+1, wu.off, wu.max, wu.rem);
				#else
				printf ("[%zu] Slice %zu/%zu (%zu remain)\n", z, wu.id+1, wu.max, wu.rem);
				#endif // DEBUGME
			}
			else
			{
				#if DEBUGME > 0
				printf ("[%zu] Slice %zu/%zu, off %zu\n", z, wu.id+1, wu.max, wu.off);
				#else
				printf ("[%zu] Slice %zu/%zu\n", z, wu.id+1, wu.max);
				#endif // DEBUGME
			}

			fflush (stdout);

			ret = runKernel (ctx, (uint32_t) off, matches, matches_found, z);

			if (ret < 1) // error or nada
			{
				if (ret == -1)
				{
					// untested code
					pthread_mutex_lock (&a->thread_ctx->thread_mutexs[z]);
					a->err = true;
					a->status = TH_ERROR;
					pthread_mutex_unlock (&a->thread_ctx->thread_mutexs[z]);
					#if TDEBUG >= 1
					printf ("[slave][%zu] master, something is broken, exit\n", z);
					fflush (stdout);
					#endif

					if (a->thread_ctx->enable_condusleep)
					{
						pthread_mutex_lock (&a->thread_ctx->thread_mutex_usleep);
						pthread_cond_signal (&a->thread_ctx->thread_cond_usleep); // unlock master/TH_PROCESSING cond
						#if TDEBUG >= 1
						printf ("[slave][%zu] after pthread_cond_signal TH_ERROR\n", z);
						#endif
						pthread_mutex_unlock (&a->thread_ctx->thread_mutex_usleep);
					}

					pthread_exit (NULL);
					// end of unstested code
				}

				#if TDEBUG >= 1
				printf ("[slave][%zu] master, process is done but no candidates found\n", z);
				fflush (stdout);
				#endif
				pthread_mutex_lock (&a->thread_ctx->thread_mutexs[z]);

				if (a->slice >= max_step) a->status = TH_END;
				else a->status = TH_WAIT;

				status = a->status;

				pthread_mutex_unlock (&a->thread_ctx->thread_mutexs[z]);

				if (a->thread_ctx->enable_condusleep)
				{
					pthread_mutex_lock (&a->thread_ctx->thread_mutex_usleep);
					pthread_cond_signal (&a->thread_ctx->thread_cond_usleep); // unlock master/TH_PROCESSING cond
					#if TDEBUG >= 1
					printf ("[slave][%zu] after pthread_cond_signal TH_WAIT\n", z);
					fflush (stdout);
					#endif
					pthread_mutex_unlock (&a->thread_ctx->thread_mutex_usleep);
				}

				continue;
			}

			if (!ctx->force_hitag2_opencl)
			{
				#if TDEBUG >= 1
				printf ("[slave][%zu] master, we got %5u candidates. Proceed to validation\n", z, matches_found[0]);
				fflush (stdout);
				#endif

				for (uint32_t match = 0; match < matches_found[0]; match++)
				{
					if (a->quit)
					{
						pthread_mutex_lock (&a->thread_ctx->thread_mutexs[z]);
						a->status = TH_END;
						pthread_mutex_unlock (&a->thread_ctx->thread_mutexs[z]);
						#if TDEBUG >= 1
						printf ("[slave][%zu] master, Another thread found the key, quit 2 \n", z);
						fflush (stdout);
						#endif

						if (a->thread_ctx->enable_condusleep)
						{
							pthread_mutex_lock (&a->thread_ctx->thread_mutex_usleep);
							pthread_cond_signal (&a->thread_ctx->thread_cond_usleep); // unlock master/TH_PROCESSING cond
							#if TDEBUG >= 1
							printf ("[slave][%zu] after pthread_cond_signal TH_END\n", z);
							#endif
							pthread_mutex_unlock (&a->thread_ctx->thread_mutex_usleep);
						}

						pthread_exit (NULL);
					}

					a->r = try_state (matches[match], uid, aR2, nR1, nR2, &a->key);
					if (a->r)
					{
						pthread_mutex_lock (&a->thread_ctx->thread_mutexs[z]);
						a->s = matches[match];
						status = a->status = TH_FOUND_KEY;
						a->quit = true;
						pthread_mutex_unlock (&a->thread_ctx->thread_mutexs[z]);
						#if TDEBUG >= 1
						printf ("[slave][%zu] master, I found the key ! state %" STR(OFF_FORMAT_U) ", slice %zu\n", z, a->s, a->slice+1);
						fflush (stdout);
						#endif

						if (a->thread_ctx->enable_condusleep)
						{
							pthread_mutex_lock (&a->thread_ctx->thread_mutex_usleep);
							pthread_cond_signal (&a->thread_ctx->thread_cond_usleep); // unlock master/TH_PROCESSING cond
							#if TDEBUG >= 1
							printf ("[slave][%zu] after pthread_cond_signal TH_FOUND_KEY\n", z);
							#endif
							pthread_mutex_unlock (&a->thread_ctx->thread_mutex_usleep);
						}

						pthread_exit (NULL);
					}
				}

				if (a->quit)
				{
					pthread_mutex_lock (&a->thread_ctx->thread_mutexs[z]);
					a->status = TH_END;
					pthread_mutex_unlock (&a->thread_ctx->thread_mutexs[z]);
					#if TDEBUG >= 1
					printf ("[slave][%zu] master, Another thread found the key, quit 1 \n", z);
					fflush (stdout);
					#endif

					if (a->thread_ctx->enable_condusleep)
					{
						pthread_mutex_lock (&a->thread_ctx->thread_mutex_usleep);
						pthread_cond_signal (&a->thread_ctx->thread_cond_usleep); // unlock master/TH_PROCESSING cond
						#if TDEBUG >= 1
						printf ("[slave][%zu] after pthread_cond_signal TH_END\n", z);
						#endif
						pthread_mutex_unlock (&a->thread_ctx->thread_mutex_usleep);
					}

					pthread_exit (NULL);
				}

				// setting internal status to wait
				status = TH_WAIT;
				continue;
			}
			else
			{
				// the OpenCL kernel return only one key if found, else nothing

				pthread_mutex_lock (&a->thread_ctx->thread_mutexs[z]);
				a->r = true;
				a->key = matches[0];
				status = a->status = TH_FOUND_KEY;
				a->quit = true;
				pthread_mutex_unlock (&a->thread_ctx->thread_mutexs[z]);
				#if TDEBUG >= 1
				printf ("[slave][%zu] master, I found the key at slice %zu\n", z, a->slice+1);
				fflush (stdout);
				#endif

				if (a->thread_ctx->enable_condusleep)
				{
					pthread_mutex_lock (&a->thread_ctx->thread_mutex_usleep);
					pthread_cond_signal (&a->thread_ctx->thread_cond_usleep); // unlock master/TH_PROCESSING cond
					#if TDEBUG >= 1
					printf ("[slave][%zu] after pthread_cond_signal TH_FOUND_KEY\n", z);
					#endif
					pthread_mutex_unlock (&a->thread_ctx->thread_mutex_usleep);
				}

				pthread_exit (NULL);
			}
		}

		if (status >= TH_FOUND_KEY)
		{
			#if TDEBUG >= 1
			if (status == TH_FOUND_KEY)
			{
				printf ("[slave][%zu] master, TH_FOUND_KEY, if you see this message, something is wrong\n", z);
				fflush (stdout);
			}
			else if (status == TH_END)
			{
				printf ("[slave][%zu] master, TH_END reached\n", z);
				fflush (stdout);
			}
			#endif
			pthread_exit (NULL);
		}

	} while (status < TH_FOUND_KEY);

	pthread_exit (NULL);
}
