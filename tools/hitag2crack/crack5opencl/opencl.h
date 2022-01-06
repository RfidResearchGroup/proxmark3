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

#ifndef OPENCL_H
#define OPENCL_H

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#define CL_TARGET_OPENCL_VERSION 220
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#include <CL/cl.h>
#endif

#include "ht2crack5opencl.h"
#include "queue.h"
#include <stdbool.h>

#include <stdio.h>
#include <errno.h>

// max number of concurrent devices (tested up to 4x RTX 3090)
#define MAX_OPENCL_DEVICES 16

// defines structures
typedef struct compute_device_ctx {
    char name[0xff];
    char vendor[0x40];
    char version[0x40];
    char driver_version[0x40];

    bool is_gpu, is_apple_gpu, is_nv;
    bool have_lop3, have_local_memory;
    bool warning, unsupported;

    bool selected;

    unsigned char pad1[1];
    unsigned int profile;

    unsigned int sm_maj;
    unsigned int sm_min;
    unsigned int compute_units;

    cl_device_id device_id;
    cl_platform_id platform_id;

} compute_device_ctx_t;

typedef struct compute_platform_ctx {
    unsigned int device_cnt;
    unsigned int compute_units_max;

    bool is_nv, is_apple, is_intel, is_pocl;
    bool warning;
    bool selected;

    unsigned char pad1[2];
    compute_device_ctx_t device[0x10];

    char name[0xff];
    char vendor[0x40];
    char version[0x40];

    unsigned char pad2[1];
    cl_platform_id platform_id;
    cl_context context;
    cl_program program;

} compute_platform_ctx_t;

typedef struct opencl_ctx {
    char *kernelSource[1];
    size_t kernelSource_len;

    size_t *global_ws;
    size_t *local_ws;
    unsigned int *profiles;

    cl_device_id *device_ids;       // compute device id's array
    cl_context *contexts;           // compute contexts
    cl_command_queue *commands;     // compute command queue (for each device)
    cl_program *programs;           // compute program's
    cl_kernel *kernels;             // compute kernel's

//  cl_mem cand_base;               // device memory used for the candidate base
    cl_mem *keystreams;             // device memory used for the keystream array
    cl_mem *candidates;             // device memory used for the candidates array
    cl_mem *matches;                // device memory used for the matches array
    cl_mem *matches_found;          // device memory used for the matches_found array
    cl_mem *checks;                 // device memory used for uid, aR2, nR1, nR2

    wu_queue_ctx_t queue_ctx;
    bool profiling;
    unsigned char pad2[1];
    short thread_sched_type;
    bool force_hitag2_opencl;

    unsigned char pad3[3];

} opencl_ctx_t;

bool plat_dev_enabled(unsigned int id, const unsigned int *sel,
                      unsigned int cnt, unsigned int cur_type, unsigned int allow_type);
unsigned int get_smallest_profile(compute_platform_ctx_t *cd_ctx, size_t ocl_platform_cnt);
int discoverDevices(unsigned int profile_selected, uint32_t device_types_selected,
                    cl_uint *platform_detected_cnt, size_t *selected_platforms_cnt,
                    size_t *selected_devices_cnt, compute_platform_ctx_t **cd_ctx,
                    unsigned int *plat_sel, unsigned int plat_cnt, unsigned int *dev_sel,
                    unsigned int dev_cnt, bool verbose, bool show);
int runKernel(opencl_ctx_t *ctx, uint32_t cand_base, uint64_t *matches, uint32_t *matches_found, size_t id);

#endif // OPENCL_H
