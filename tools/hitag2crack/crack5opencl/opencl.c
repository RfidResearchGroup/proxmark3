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

bool plat_dev_enabled(unsigned int id, const unsigned int *sel,
                      unsigned int cnt, unsigned int cur_type, unsigned int allow_type) {
    // usefulonly with devices
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

unsigned int get_smallest_profile(compute_platform_ctx_t *cd_ctx, size_t ocl_platform_cnt) {
    unsigned int profile = 0xff;

    size_t x = 0, y = 0;

    for (x = 0; x < ocl_platform_cnt; x++) {
        if (!cd_ctx[x].selected) continue;

        for (y = 0; y < cd_ctx[x].device_cnt; y++) {
            if (!cd_ctx[x].device[y].selected) continue;

#if DEBUGME > 1
            printf("[debug] Initial profile for device %zu: %d\n", z, cd_ctx[x].device[y].profile);
#endif

            // with same devices will be selected the best
            // but for different devices in the same platform we need the worst for now (todo)
            if (cd_ctx[x].device[y].profile < profile) profile = cd_ctx[x].device[y].profile;
        }
    }

    // at worst, set profile to 0
    if (profile > 10) profile = 0;

    return profile;
}

int discoverDevices(unsigned int profile_selected, uint32_t device_types_selected,
                    cl_uint *platform_detected_cnt, size_t *selected_platforms_cnt,
                    size_t *selected_devices_cnt, compute_platform_ctx_t **cd_ctx,
                    unsigned int *plat_sel, unsigned int plat_cnt, unsigned int *dev_sel,
                    unsigned int dev_cnt, bool verbose, bool show) {
    int err = 0;
    unsigned int ocl_platform_max = MAX_OPENCL_DEVICES; // 16
    cl_uint ocl_platform_cnt;

    cl_platform_id *ocl_platforms = (cl_platform_id *) calloc(ocl_platform_max, sizeof(cl_platform_id));
    if (!ocl_platforms) {
        printf("Error: calloc (ocl_platforms) failed (%d): %s\n", errno, strerror(errno));
        return -2;
    }

    // enum platforms
    err = clGetPlatformIDs(ocl_platform_max, ocl_platforms, &ocl_platform_cnt);
    if (err != CL_SUCCESS) {
        printf("Error: clGetPlatformIDs() failed (%d)\n", err);
        free(ocl_platforms);
        return -3;
    }

    if (ocl_platform_cnt == 0) {
        printf("No platforms found, exit\n");
        free(ocl_platforms);
        return -4;
    }

    // allocate memory to hold info about platforms/devices
    *cd_ctx = (compute_platform_ctx_t *) calloc(ocl_platform_cnt, sizeof(compute_platform_ctx_t));
    if (*cd_ctx == NULL) {
        printf("Error: calloc (compute_platform_ctx_t) failed (%d): %s\n", errno, strerror(errno));
        free(ocl_platforms);
        return -5;
    }

    cl_platform_info ocl_platforms_info[3] = { CL_PLATFORM_NAME, CL_PLATFORM_VENDOR, CL_PLATFORM_VERSION };
    unsigned int ocl_platforms_info_cnt = sizeof(ocl_platforms_info) / sizeof(cl_platform_info);

    cl_device_info ocl_devices_info[8] = { CL_DEVICE_TYPE, CL_DEVICE_NAME, CL_DEVICE_VERSION, CL_DRIVER_VERSION, CL_DEVICE_VENDOR, CL_DEVICE_LOCAL_MEM_TYPE, CL_DEVICE_MAX_WORK_ITEM_SIZES, CL_DEVICE_MAX_COMPUTE_UNITS };
    unsigned int ocl_devices_info_cnt = sizeof(ocl_devices_info) / sizeof(cl_device_info);

    unsigned int info_idx;
    size_t tmp_len = 0;
    char *tmp_buf = NULL;

    unsigned int global_device_id = 0;

    if (verbose) printf("- Found %u OpenCL Platform(s)\n", ocl_platform_cnt);

    for (cl_uint platform_idx = 0; platform_idx < ocl_platform_cnt; platform_idx++) {
        (*cd_ctx)[platform_idx].platform_id = ocl_platforms[platform_idx];
        (*cd_ctx)[platform_idx].selected = plat_dev_enabled(platform_idx, plat_sel, plat_cnt, 0, 0);

        if ((*cd_ctx)[platform_idx].selected)(*selected_platforms_cnt)++;

        if (verbose) printf("\n-- Platform ID: %u\n", platform_idx + 1);

        for (info_idx = 0; info_idx < ocl_platforms_info_cnt; info_idx++) {
            cl_platform_info ocl_info = ocl_platforms_info[info_idx];

            err = clGetPlatformInfo((*cd_ctx)[platform_idx].platform_id, ocl_info, 0, NULL, &tmp_len);
            if (err != CL_SUCCESS) {
                printf("Error: clGetPlatformInfo(param size) failed (%d)\n", err);
                free(*cd_ctx);
                free(ocl_platforms);
                return -6;
            }

            if (tmp_len > 0) {
                if (!(tmp_buf = (char *) calloc(tmp_len, sizeof(char)))) {
                    printf("Error: calloc (ocl_info %u) failed (%d): %s\n", info_idx, errno, strerror(errno));
                    free(*cd_ctx);
                    free(ocl_platforms);
                    return -7;
                }

                err = clGetPlatformInfo((*cd_ctx)[platform_idx].platform_id, ocl_info, tmp_len, tmp_buf, 0);
                if (err != CL_SUCCESS) {
                    printf("Error: clGetPlatformInfo(param) failed (%d)\n", err);
                    free(tmp_buf);
                    free(*cd_ctx);
                    free(ocl_platforms);
                    return -8;
                }
            } else {
                tmp_len = 4;
                if (!(tmp_buf = (char *) calloc(tmp_len, sizeof(char)))) {
                    printf("Error: calloc (ocl_info %u) failed (%d): %s\n", info_idx, errno, strerror(errno));
                    free(*cd_ctx);
                    free(ocl_platforms);
                    return -7;
                }

                strncpy(tmp_buf, "N/A\0", tmp_len);
            }

            if (verbose) {
                const char *tmp_info_desc = (info_idx == 0) ? "Name" : (info_idx == 1) ? "Vendor" : "Version";

                printf("%14s: %s\n", tmp_info_desc, tmp_buf);
            }

            switch (info_idx) {
                case 0:
                    strncpy((*cd_ctx)[platform_idx].name, tmp_buf, tmp_len < 0xff ? tmp_len : 0xff - 1);
                    break;
                case 1:
                    strncpy((*cd_ctx)[platform_idx].vendor, tmp_buf, tmp_len < 0x40 ? tmp_len : 0x40 - 1);
                    break;
                case 2:
                    strncpy((*cd_ctx)[platform_idx].version, tmp_buf, tmp_len < 0x40 ? tmp_len : 0x40 - 1);
                    break;
            }

            if (info_idx == 1) {
                if (!strncmp(tmp_buf, "NVIDIA", 6))(*cd_ctx)[platform_idx].is_nv = true;
                else if (!strncmp(tmp_buf, "Apple", 5)) { (*cd_ctx)[platform_idx].is_apple = true; (*cd_ctx)[platform_idx].warning = true; }
                else if (!strncmp(tmp_buf, "Intel", 5))(*cd_ctx)[platform_idx].is_intel = true;
                else if (!strncmp(tmp_buf, "The pocl project", 16))(*cd_ctx)[platform_idx].is_pocl = true;
            }

            free(tmp_buf);
        }

        if (!show && verbose) {
            printf("%14s: %s\n", "Selected", ((*cd_ctx)[platform_idx].selected) ? "yes" : "no");
            if ((*cd_ctx)[platform_idx].warning) printf("\n%14s: performance will not be optimal using this platform\n\n", "=====> Warning");
        }

        // enum devices with this platform
        unsigned int ocl_device_cnt = 0;
        unsigned int ocl_device_max = MAX_OPENCL_DEVICES;

        cl_device_id *ocl_devices = (cl_device_id *) calloc(ocl_device_max, sizeof(cl_device_id));
        if (!ocl_devices) {
            printf("Error: calloc (ocl_devices) failed (%d): %s\n", errno, strerror(errno));
            free(*cd_ctx);
            free(ocl_platforms);
            return -7;
        }

        err = clGetDeviceIDs((*cd_ctx)[platform_idx].platform_id, CL_DEVICE_TYPE_ALL, ocl_device_max, ocl_devices, &ocl_device_cnt);
        if (ocl_device_cnt == 0) {
            if (device_types_selected == CL_DEVICE_TYPE_ALL) printf("No device(s) available with platform id %u\n", platform_idx);
            (*cd_ctx)[platform_idx].device_cnt = 0;
            continue;
        }

        if (err != CL_SUCCESS) {
            printf("Error: clGetDeviceIDs(cnt) failed (%d)\n", err);
            free(ocl_devices);
            free(*cd_ctx);
            free(ocl_platforms);
            return -9;
        }

        if (verbose) printf("%14s: %u\n", "Device(s)", ocl_device_cnt);

        (*cd_ctx)[platform_idx].device_cnt = ocl_device_cnt;

        for (unsigned int device_idx = 0; device_idx < ocl_device_cnt; device_idx++) {
            memset(&(*cd_ctx)[platform_idx].device[device_idx], 0, sizeof(compute_device_ctx_t));
            cl_device_id ocl_device = ocl_devices[device_idx];
            (*cd_ctx)[platform_idx].device[device_idx].platform_id = (*cd_ctx)[platform_idx].platform_id;

            if (verbose) printf("---- * ID: %u\n", global_device_id + 1);

            for (info_idx = 0; info_idx < ocl_devices_info_cnt; info_idx++) {
                cl_device_info ocl_dev_info = ocl_devices_info[info_idx];

                if (info_idx == 0) {
                    cl_device_type device_type;

                    err = clGetDeviceInfo(ocl_device, ocl_dev_info, sizeof(cl_device_type), &device_type, 0);
                    if (err != CL_SUCCESS) {
                        printf("Error: clGetDeviceInfo(device_type) failed (%d)\n", err);
                        free(ocl_devices);
                        free(*cd_ctx);
                        free(ocl_platforms);
                        return -10;
                    }

                    if (device_type & CL_DEVICE_TYPE_GPU)(*cd_ctx)[platform_idx].device[device_idx].is_gpu = 1;
                    else if ((device_type & CL_DEVICE_TYPE_CPU) && (*cd_ctx)[platform_idx].is_pocl) {
                        (*cd_ctx)[platform_idx].device[device_idx].profile = (profile_selected > 1) ? 0 : profile_selected;
                    }

                    if (verbose) printf("%14s: %s\n", "Device Type", (device_type & CL_DEVICE_TYPE_GPU) ? "GPU" : (device_type & CL_DEVICE_TYPE_CPU) ? "CPU" : "Other");

                    if ((*cd_ctx)[platform_idx].selected == false)(*cd_ctx)[platform_idx].device[device_idx].selected = false;
                    else (*cd_ctx)[platform_idx].device[device_idx].selected = plat_dev_enabled(global_device_id, dev_sel, dev_cnt, (unsigned int) device_type, device_types_selected);
                    global_device_id++;
                    if ((*cd_ctx)[platform_idx].device[device_idx].selected)(*selected_devices_cnt)++;
                    continue;
                } else if (info_idx == 5) {
                    cl_device_local_mem_type local_mem_type;

                    err = clGetDeviceInfo(ocl_device, ocl_dev_info, sizeof(cl_device_local_mem_type), &local_mem_type, 0);
                    if (err != CL_SUCCESS) {
                        printf("Error: clGetDeviceInfo(local_mem_type) failed (%d)\n", err);
                        free(ocl_devices);
                        free(*cd_ctx);
                        free(ocl_platforms);
                        return -10;
                    }

                    if (local_mem_type == CL_LOCAL || local_mem_type == CL_GLOBAL) {
                        if (verbose) printf("%14s: %s\n", "Local Mem Type", (local_mem_type == CL_LOCAL) ? "Local" : "Global");
                        if ((*cd_ctx)[platform_idx].is_apple) {
                            if (strncmp((*cd_ctx)[platform_idx].device[device_idx].vendor, "Intel", 5) != 0) {
                                (*cd_ctx)[platform_idx].device[device_idx].have_local_memory = true;

                                if ((*cd_ctx)[platform_idx].device[device_idx].is_gpu) {
                                    if (profile_selected > 2)(*cd_ctx)[platform_idx].device[device_idx].profile = PROFILE_DEFAULT;  // Apple-Intel GPU's
                                } else {
                                    if (profile_selected > 3)(*cd_ctx)[platform_idx].device[device_idx].profile = PROFILE_DEFAULT;  // Apple-Intel CPU's
                                }
                            }
                        } else if ((*cd_ctx)[platform_idx].is_nv) {
                            (*cd_ctx)[platform_idx].device[device_idx].have_local_memory = true;
                        }
                    } else {
                        if (verbose) printf("%14s: None\n", "Local Mem Type");
                    }

                    if (verbose) printf("%14s: %s\n", "Local Mem Opt", ((*cd_ctx)[platform_idx].device[device_idx].have_local_memory) ? "yes" : "no");

                    continue;
                } else if (info_idx == 6) {
                    size_t wis[3] = { 0 };
                    err = clGetDeviceInfo(ocl_device, ocl_dev_info, sizeof(size_t) * 3, wis, 0);
                    if (err != CL_SUCCESS) {
                        printf("Error: clGetDeviceInfo(work_items_size) failed (%d)\n", err);
                        free(ocl_devices);
                        free(*cd_ctx);
                        free(ocl_platforms);
                        return -10;
                    }

                    if (verbose) printf("%14s: (%zu,%zu,%zu)\n", "Max Work-Items", wis[0], wis[1], wis[2]);

#if APPLE_GPU_BROKEN == 1
                    if (wis[1] < GLOBAL_WS_1 && (*cd_ctx)[platform_idx].device[device_idx].is_apple_gpu) {
                        (*cd_ctx)[platform_idx].device[device_idx].unsupported = true;
                    }
#endif
                    continue;
                } else if (info_idx == 7) {
                    cl_uint cores = 0;
                    err = clGetDeviceInfo(ocl_device, ocl_dev_info, sizeof(cl_uint), &cores, 0);
                    if (err != CL_SUCCESS) {
                        printf("Error: clGetDeviceInfo(compute_units) failed (%d)\n", err);
                        free(ocl_devices);
                        free(*cd_ctx);
                        free(ocl_platforms);
                        return -10;
                    }

                    if (verbose) printf("%14s: %u\n", "Compute Units", cores);

                    (*cd_ctx)[platform_idx].device[device_idx].compute_units = cores;
                    continue;
                }

                tmp_len = 0;
                tmp_buf = NULL;

                err = clGetDeviceInfo(ocl_device, ocl_dev_info, 0, NULL, &tmp_len);
                if (err != CL_SUCCESS) {
                    printf("Error: clGetDeviceInfo(param size) failed (%d)\n", err);
                    free(ocl_devices);
                    free(*cd_ctx);
                    free(ocl_platforms);
                    return -10;
                }

                if (tmp_len > 0) {
                    if (!(tmp_buf = (char *) calloc(tmp_len, sizeof(char)))) {
                        printf("Error: calloc (ocl_dev_info %u) failed (%d): %s\n", info_idx, errno, strerror(errno));
                        free(ocl_devices);
                        free(*cd_ctx);
                        free(ocl_platforms);
                        return -7;
                    }

                    err = clGetDeviceInfo(ocl_device, ocl_dev_info, tmp_len, tmp_buf, 0);
                    if (err != CL_SUCCESS) {
                        printf("Error: clGetDeviceInfo(param) failed (%d)\n", err);
                        free(tmp_buf);
                        free(ocl_devices);
                        free(*cd_ctx);
                        free(ocl_platforms);
                        return -10;
                    }
                } else {
                    tmp_len = 4;
                    if (!(tmp_buf = (char *) calloc(tmp_len, sizeof(char)))) {
                        printf("Error: calloc (ocl_dev_info %u) failed (%d): %s\n", info_idx, errno, strerror(errno));
                        free(ocl_devices);
                        free(*cd_ctx);
                        free(ocl_platforms);
                        return -7;
                    }

                    strncpy(tmp_buf, "N/A\0", tmp_len);
                }

                if (verbose) {
                    const char *tmp_dev_info_desc = (info_idx == 1) ? "Name" : (info_idx == 2) ? "Version" : (info_idx == 3) ? "Driver Version" : "Vendor";

                    printf("%14s: %s\n", tmp_dev_info_desc, tmp_buf);
                }

                switch (info_idx) {
                    case 1:
                        strncpy((*cd_ctx)[platform_idx].device[device_idx].name, tmp_buf, tmp_len < 0xff ? tmp_len : 0xff - 1);
                        break;
                    case 2:
                        strncpy((*cd_ctx)[platform_idx].device[device_idx].version, tmp_buf, tmp_len < 0x40 ? tmp_len : 0x40 - 1);
                        break;
                    case 3:
                        strncpy((*cd_ctx)[platform_idx].device[device_idx].driver_version, tmp_buf, tmp_len < 0x40 ? tmp_len : 0x40 - 1);
                        break;
                    case 4:
                        strncpy((*cd_ctx)[platform_idx].device[device_idx].vendor, tmp_buf, tmp_len < 0x40 ? tmp_len : 0x40 - 1);
                        break;
                }

                if (info_idx == 1) {
                    // force profile to 0-1 with Jetson Nano
                    if (strstr(tmp_buf, "Tegra") && (*cd_ctx)[platform_idx].is_pocl) {
                        (*cd_ctx)[platform_idx].device[device_idx].profile = (profile_selected > 1) ? 0 : profile_selected;
                    }
                } else if (info_idx == 4) {
                    if (!strncmp(tmp_buf, "Intel", 5)) {
                        if ((*cd_ctx)[platform_idx].is_apple) {
                            (*cd_ctx)[platform_idx].device[device_idx].is_apple_gpu = (*cd_ctx)[platform_idx].device[device_idx].is_gpu;
                        }

                        // force profile to 0 with Intel GPU and 2 with Intel CPU's
                        if ((*cd_ctx)[platform_idx].is_intel) {
                            if ((*cd_ctx)[platform_idx].device[device_idx].is_gpu) {
                                (*cd_ctx)[platform_idx].device[device_idx].profile = 0; // Intel GPU's, work better with a very slow profile
                            } else {
                                (*cd_ctx)[platform_idx].device[device_idx].profile = (profile_selected > 2) ? PROFILE_DEFAULT : profile_selected; // Intel CPU's
                            }
                        }
                    }

                    if (!strncmp(tmp_buf, "NVIDIA", 6) && (*cd_ctx)[platform_idx].is_nv) {
                        unsigned int sm_maj = 0, sm_min = 0;

                        err  = clGetDeviceInfo(ocl_device, 0x4000, sizeof(unsigned int), &sm_maj, 0);
                        err |= clGetDeviceInfo(ocl_device, 0x4001, sizeof(unsigned int), &sm_min, 0);

                        if (err != CL_SUCCESS) {
                            printf("Error: clGetDeviceInfo(sm_maj/sm_min) failed (%d)\n", err);
                            free(tmp_buf);
                            free(ocl_devices);
                            free(*cd_ctx);
                            free(ocl_platforms);
                            return -10;
                        }

                        (*cd_ctx)[platform_idx].device[device_idx].sm_maj = sm_maj;
                        (*cd_ctx)[platform_idx].device[device_idx].sm_min = sm_min;

                        if (verbose) printf("%14s: %u%u\n", "SM", sm_maj, sm_min);

                        if (sm_maj >= 5) { // >= Maxwell
                            // https://docs.nvidia.com/cuda/parallel-thread-execution/index.html#logic-and-shift-instructions-lop3
                            // Requires sm_50 or higher.
                            (*cd_ctx)[platform_idx].device[device_idx].have_lop3 = true;
                        } else {
                            (*cd_ctx)[platform_idx].device[device_idx].warning = true;
                        }

                        (*cd_ctx)[platform_idx].device[device_idx].is_nv = true;

                        if ((*cd_ctx)[platform_idx].device[device_idx].is_gpu) {
                            if (profile_selected > 10) {
                                // NVIDIA RTX 3090 perform better with 5
                                (*cd_ctx)[platform_idx].device[device_idx].profile = (sm_maj >= 8) ? 5 : PROFILE_DEFAULT;
                            }
                        }
                    } else {
                        (*cd_ctx)[platform_idx].device[device_idx].warning = true;
                    }
                }

                free(tmp_buf);
            }

            if (!show && verbose) printf("%14s: %s\n", "Selected", ((*cd_ctx)[platform_idx].device[device_idx].selected) ? "yes" : "no");

            if ((*cd_ctx)[platform_idx].device[device_idx].unsupported) {
                printf("\n%14s: this device was not supported, because of missing resources\n\n", "=====> Warning");
                continue;
            }

            if ((*cd_ctx)[platform_idx].device[device_idx].warning) {
                if (!show && verbose) printf("\n%14s: performance will not be optimal using this device\n\n", "=====> Warning");
            }

            (*cd_ctx)[platform_idx].device[device_idx].device_id = ocl_device;
        }
        free(ocl_devices);
        ocl_devices = NULL;
    }

    free(ocl_platforms);
    ocl_platforms = NULL;

    *platform_detected_cnt = ocl_platform_cnt;

    if (show) free(*cd_ctx);

    return 0;
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
