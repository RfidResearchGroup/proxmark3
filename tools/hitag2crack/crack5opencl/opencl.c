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

#include "opencl.h"

bool plat_dev_enabled(unsigned int id, unsigned int *sel, unsigned int cnt, unsigned int cur_type, unsigned int allow_type) {
    // usefull only with devices
    if (allow_type != CL_DEVICE_TYPE_ALL) {
        if (cur_type != allow_type) return false;
    }

    if (sel[0] == 0xff) return true; // all
    else {
        for (unsigned int i = 0; i < cnt; i++) {
            if (sel[i] == (id + 1)) return true;
        }
    }

    return false;
}

int runKernel(opencl_ctx_t *ctx, uint32_t cand_base, uint64_t *matches, uint32_t *matches_found, size_t id) {
    int err = 0;

    size_t global_ws[3] = { ctx->global_ws[id], GLOBAL_WS_1, GLOBAL_WS_2 };
    size_t local_ws[3]  = { ctx->local_ws[id], 1, 1 };

    if (ctx->profiling) {
        printf("[%zu] global_ws %zu, ctx->local_ws: %zu\n", id, global_ws[0], local_ws[0]);
        fflush(stdout);
    }

    *matches_found = 0;

    // Write our data set into the input array in device memory
    err = clEnqueueWriteBuffer(ctx->commands[id], ctx->matches_found[id], CL_TRUE, 0, sizeof(uint32_t), matches_found, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        printf("[%zu] Error: clEnqueueWriteBuffer (matches_found) failed (%d)\n", id, err);
        return -1;
    }

    // Set the arguments to our compute kernel
    err  = clSetKernelArg(ctx->kernels[id], 0, sizeof(uint32_t), &cand_base);
    err |= clSetKernelArg(ctx->kernels[id], 4, sizeof(cl_mem), &ctx->matches_found[id]);

    if (err != CL_SUCCESS) {
        printf("[%zu] Error: clSetKernelArg (cand_base|ctx->matches_found) failed (%d)\n", id, err);
        return -1;
    }

    cl_event event;

    err = clEnqueueNDRangeKernel(ctx->commands[id], ctx->kernels[id], 2, NULL, global_ws, local_ws, 0, NULL, &event);
    if (err != CL_SUCCESS) {
        printf("[%zu] Error: clEnqueueNDRangeKernel() failed (%d)\n", id, err);
        return -1;
    }

    // todo, check if is possible remove
    err = clFlush(ctx->commands[id]);
    if (err != CL_SUCCESS) {
        printf("[%zu] Error: clFlush() failed (%d)\n", id, err);
        return -1;
    }

    if (ctx->profiling) {
        err = clWaitForEvents(1, &event);
        if (err != CL_SUCCESS) {
            printf("[%zu] Error: clWaitForEvents() failed (%d)\n", id, err);
            return -1;
        }

        cl_ulong gpu_t_start = 0, gpu_t_end = 0;

        err  = clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &gpu_t_start, NULL);
        err |= clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &gpu_t_end, NULL);
        if (err != CL_SUCCESS) {
            printf("[%zu] Error: clGetEventOPENCL_PROFILINGInfo() failed (%d)\n", id, err);
            return -1;
        }

        const double time_ms = (double)(gpu_t_end - gpu_t_start) / 1000000;

        printf("[%zu] kernel exec time (ms): %.2f]\n", id, time_ms);
        fflush(stdout);
    }

    err  = clReleaseEvent(event);
    if (err != CL_SUCCESS) {
        printf("[%zu] Error: clReleaseEvent() failed (%d)\n", id, err);
        return -1;
    }

    // Wait for the command commands to get serviced before reading back results
    // todo, check if is possible remove, because of blocking clEnqueueReadBuffer (CL_TRUE)
    err = clFinish(ctx->commands[id]);
    if (err != CL_SUCCESS) {
        printf("[%zu] Error: clFinish() failed (%d)\n", id, err);
        return -1;
    }

    // read back the matches counter first
    err = clEnqueueReadBuffer(ctx->commands[id], ctx->matches_found[id], CL_TRUE, 0, sizeof(uint32_t), matches_found, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        printf("[%zu] Error: clEnqueueReadBuffer(matches_found) failed (%d)\n", id, err);
        return -1;
    }

    if (matches_found[0] > 0) {
        if (ctx->force_hitag2_opencl) {
            if (matches_found[0] != 1) printf("[%zu] BUG: if match the counter must be 1. Here %u are founds\n", id, matches_found[0]);
        } else {
            if (matches_found[0] > (uint32_t)(ctx->global_ws[id]*WGS_MATCHES_FACTOR)) {
                printf("[%zu] BUG: the next clEnqueueReadBuffer will crash. 'matches' buffer (%u) is lower than requested (%u)\n", id, (uint32_t)(ctx->global_ws[id]*WGS_MATCHES_FACTOR), matches_found[0]);
            }
        }

        err = clEnqueueReadBuffer(ctx->commands[id], ctx->matches[id], CL_TRUE, 0, sizeof(uint64_t) * matches_found[0], matches, 0, NULL, NULL);
        if (err != CL_SUCCESS) {
            printf("[%zu] Error: clEnqueueReadBuffer(matches) failed (%d)\n", id, err);
            return -1;
        }

        // key found
        return 1;
    }

    // nada
    return 0;
}
