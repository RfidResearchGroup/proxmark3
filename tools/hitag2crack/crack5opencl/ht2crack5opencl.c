/* ht2crack5opencl.c
 * This code is heavily based on the crack5gpu.
 *
 * Additional changes done by Gabriele 'matrix' Gristina <gabriele.gristina@gmail.com>
 *  - Using optimized OpenCL kernel (ht2crack5opencl_kernel.cl)
 *  - Rewriting OpenCL host code
 *  - Add OpenCL Platforms/Devices enumeration, used to selectively enable kernel optimizations
 *  - Support Multi-Platform (GPU & CPU), using custom async or sequential thread engine, and queue
 *  - Reduce memory read from OpenCL device to host (for each iteration only the exact number of candidates are read, instead of a big buffer)
 *  - Support 'Computing Profiles', to fine-tune workloads based on available resources
 *  - Support HiTag2 Key check on device.
 *    In this case reduce a lot the memory in use but but it loses on performance ~1 sec
 *    (with GeForce GTX 1080 Ti, 70.449128 vs 71.062680 (Slice 4043/4096))
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/time.h>
#include <getopt.h>

#include "ht2crack5opencl.h"
#include "queue.h"
#include "threads.h"
#include "opencl.h"
#include "hitag2.h"
#include "dolphin_macro.h"

#define MAX_BITSLICES 32
#define VECTOR_SIZE (MAX_BITSLICES/8)

typedef unsigned int __attribute__((aligned(VECTOR_SIZE))) __attribute__((vector_size(VECTOR_SIZE))) bitslice_value_t;
typedef union {
    bitslice_value_t value;
    uint8_t bytes[MAX_BITSLICES / 8];
} bitslice_t;

static bitslice_t keystream[32];

//uint64_t candidates[(1 << 20)];
// Reduce type size of candidates array to fit OpenCL
static uint16_t candidates[(1 << 20) * 3];

// compute profile constants, from low to high workloads
static unsigned int profiles[11][2] = {
    { 16384, 5 }, // 0, best for Intel GPU's with Neo
    { 8192,  6 }, // 1, only for Intel NEO
    { 4096,  7 }, // 2 (old 0) seems the best for all others (also NVIDIA) :D Apple/Intel GPU's stable here
    { 2048,  8 }, // 3 (old 1) usefull for any kind of CPU's
    { 1024,  9 },
    { 512,  10 },
    { 256,  11 },
    { 128,  12 }, // 7, (old 5) the last good value with NVIDIA GPU's
    { 64,   13 },
    { 32,   14 },
    { 16,   15 },
};

static uint64_t expand(uint64_t mask, uint64_t value) {
    uint64_t fill = 0;

    for (uint64_t bit_index = 0; bit_index < 48; bit_index++) {
        if (mask & 1) {
            fill |= (value & 1) << bit_index;
            value >>= 1;
        }
        mask >>= 1;
    }

    return fill;
}

static void bitslice(const uint64_t value, bitslice_t *restrict bitsliced_value) {
    // set constants
    bitslice_t bs_zeroes, bs_ones;
    memset(bs_ones.bytes, 0xff, VECTOR_SIZE);
    memset(bs_zeroes.bytes, 0x00, VECTOR_SIZE);

    for (size_t bit_idx = 0; bit_idx < 32; bit_idx++) {
        const bool bit = get_bit(32 - 1 - bit_idx, value);
        bitsliced_value[bit_idx].value = (bit) ? bs_ones.value : bs_zeroes.value;
    }
}

// convert byte-reversed 8 digit hex to unsigned long
static unsigned long hexreversetoulong(char *hex) {
    unsigned long ret = 0L;
    unsigned int x;
    char i;

    if (strlen(hex) != 8)
        return 0L;

    for (i = 0 ; i < 4 ; ++i) {
        if (sscanf(hex, "%2X", &x) != 1)
            return 0L;
        ret += ((unsigned long) x) << i * 8;
        hex += 2;
    }
    return ret;
}

#if ENABLE_EMOJ == 1
static const char *emoj[3][2] = { {"∩", "つ"}, {"つ", "⊃"}, {"⊃", "੭ " } };
#endif

__attribute__((noreturn))
static void usage(char *name) {
    printf("%s [options] {UID} {nR1} {aR1} {nR2} {aR2}\n\n" \
           "Options:\n"
           "-p     : select OpenCL Platform(s). Multiple allowed (1,2,3,etc.). [Default: all]\n"
           "-d     : select OpenCL Device(s). Multiple allowed (1,2,3,etc.). [Default: all]\n"
           "-D     : select OpenCL Device Type. 0: GPU, 1: CPU, 2: all. [Default: GPU]\n"
           "-S     : select the thread scheduler type. 0: sequential, 1: asynchronous. [Default 1]\n"
           "-P     : select the Profile, from 0 to 10. [Default: auto-tuning]\n"
           "-F     : force verify key with OpenCL instead of CPU. [Default: disabled]\n"
           "-Q     : select queue engine. 0: forward, 1: reverse, 2: random. [Default: 0]\n"
           "-s     : show the list of OpenCL platforms/devices, then exit\n"
           "-V     : enable debug messages\n"
           "-v     : show the version\n"
           "-h     : show this help\n\n", name);

    printf("Example, select devices 1, 2 and 3 using platform 1 and 2, with random queue engine:\n\n"
           "%s -D 2 -Q 2 -p 1,2 -d 1,2,3 2ab12bf2 4B71E49D 6A606453 D79BD94B 16A2255B\n\n", name);

    exit(8);
}

static bool parse_arg(char *restrict in, unsigned int *out, unsigned int *out_cnt, const int opt_type) {
    unsigned int cnt = 0;

    if (in == NULL) {
        out[cnt++] = 0xff;
        *out_cnt = cnt;
    } else {
        if (strchr(in, ',')) {
            // multiple values
            char *saveptr = NULL;
            char *next = strtok_r(in, ",", &saveptr);

            do {
                unsigned int tmp_sel = (unsigned int) strtoul(next, NULL, 10);
                if (errno == EINVAL || errno == ERANGE ||
                        (tmp_sel < 1 || tmp_sel > 16)) {
                    printf("! Invalid %s argument\n", (opt_type == 0) ? "'platform'" : "'device'");
                    return false;
                }

                out[cnt++] = tmp_sel;

            } while ((next = strtok_r(NULL, ",", &saveptr)) != NULL);

            *out_cnt = cnt;

            // todo: sort, uniq
        } else {
            out[0] = (unsigned int) strtoul(in, NULL, 10);
            if (errno == EINVAL || errno == ERANGE) {
                printf("! Invalid %s argument\n", (opt_type == 0) ? "'platform'" : "'device'");
                return false;
            }
            *out_cnt = 1;
        }
    }

    return true;
}

int main(int argc, char **argv) {
    opencl_ctx_t ctx;

    uint32_t uid = 0, nR1 = 0, aR1 = 0, nR2 = 0, aR2 = 0;
    bool opencl_profiling = 0;
    bool force_hitag2_opencl = false;
    bool verbose = false;
    bool show = false;

    char *platforms_selected = NULL;
    char *devices_selected = NULL;
    unsigned int device_types_selected = 0;
    unsigned int thread_scheduler_type_selected = THREAD_TYPE_ASYNC;
    unsigned int profile_selected = 2;
    unsigned int queue_type = 0;

    uint32_t target = 0;
    uint32_t **matches_found = NULL;
    uint64_t **matches = NULL;

    int opt;

    while ((opt = getopt(argc, argv, "p:d:D:S:P:F:Q:svVh")) != -1) {
        switch (opt) {
            case 'p':
                // 1, 2, 3, etc ..
                platforms_selected = strdup(optarg);
                break;
            case 'd':
                // 1, 2, 3, etc ...
                devices_selected = strdup(optarg);
                break;
            case 'D':
                // 0: gpu, 1: cpu, 2: all
                device_types_selected = (unsigned int) strtoul(optarg, NULL, 10);
                if (device_types_selected > 2) {
                    printf("! Invalid DEVICE TYPE argument (accepted values: from 0 to 2)\n");
                    usage(argv[0]);
                }
                break;
            case 'S':
                // 0: sequential, 1: async
                thread_scheduler_type_selected = (unsigned int) strtoul(optarg, NULL, 10);
                break;
            case 'P':
                profile_selected = (unsigned int) strtoul(optarg, NULL, 10);
                if (profile_selected > 10) {
                    printf("! Invalid PROFILE argument (accepted valuee: from 0 to 10)\n");
                    usage(argv[0]);
                }
                break;
            case 'F':
                force_hitag2_opencl = true;
                break;
            case 'Q':
                // 0: forward, 1: reverse, 2: random
                queue_type = (unsigned int) strtoul(optarg, NULL, 10);
                if (queue_type != QUEUE_TYPE_FORWARD && queue_type != QUEUE_TYPE_REVERSE && queue_type != QUEUE_TYPE_RANDOM) {
                    printf("! Invalid QUEUE TYPE argument (accepted values: 0, 1 or 2)\n");
                    usage(argv[0]);
                }
                break;
            case 's':
                show = true;
                break;
            case 'V':
                verbose = true;
                break;
            case 'v':
                printf("Version: %s\n", VERSION);
                exit(0);
            case 'h':
            default:
                usage(argv[0]);
        }
    }

    unsigned int plat_sel[16] = { 0 };
    unsigned int plat_cnt = 0;
    unsigned int dev_sel[16] = { 0 };
    unsigned int dev_cnt = 0;

    if (!parse_arg(platforms_selected, plat_sel, &plat_cnt, 0)) {
        free(platforms_selected);
        usage(argv[0]);
    }

    if (!parse_arg(devices_selected, dev_sel, &dev_cnt, 1)) {
        free(platforms_selected);
        free(devices_selected);
        usage(argv[0]);
    }

    free(platforms_selected);
    free(devices_selected);

    if (device_types_selected == 0) device_types_selected = CL_DEVICE_TYPE_GPU;
    else if (device_types_selected == 1) device_types_selected = CL_DEVICE_TYPE_CPU;
    else device_types_selected = CL_DEVICE_TYPE_ALL;

    if (show) {
        plat_sel[0] = 0xff;
        dev_sel[0] = 0xff;
        device_types_selected = CL_DEVICE_TYPE_ALL;
    }

    if (verbose) {
        if (plat_sel[0] == 0xff) printf("Platforms selected    : ALL\n");
        else {
            printf("Platforms selected    : %u", plat_sel[0]);
            for (unsigned int i = 1; i < plat_cnt; i++) printf(", %u", plat_sel[i]);
            printf("\n");
        }

        if (dev_sel[0] == 0xff)	printf("Devices selected      : ALL\n");
        else {
            printf("Devices selected      : %u", dev_sel[0]);
            for (unsigned int i = 1; i < dev_cnt; i++) printf(", %u", dev_sel[i]);
            printf("\n");
        }

        printf("Device types selected : %s\n", (device_types_selected == CL_DEVICE_TYPE_GPU) ? "GPU" : (device_types_selected == CL_DEVICE_TYPE_CPU) ? "CPU" : "ALL");
        printf("Scheduler selected    : %s\n", (thread_scheduler_type_selected == 0) ? "sequential" : "async");
        printf("Profile selected      : %d\n", profile_selected);
    }

    if (!show) {
        if ((argc - optind) < 5) {
#if DEBUGME > 0
            printf("! Invalid extra arguments\n");
#endif
            usage(argv[0]);
        }

        for (int e = 0; e < 5; optind++, e++) {
            switch (e) {
                case 0: // UID
                    if (!strncmp(argv[optind], "0x", 2) || !strncmp(argv[optind], "0X", 2)) {
                        if (strlen(argv[optind]) != 2 + 8) { printf("! Invalid UID length\n"); usage(argv[0]); }
                        uid = (uint32_t) rev32(hexreversetoulong(argv[optind] + 2));
                    } else {
                        if (strlen(argv[optind]) != 8) { printf("! Invalid UID length\n"); usage(argv[0]); }
                        uid = (uint32_t) rev32(hexreversetoulong(argv[optind]));
                    }
                    break;

                case 1: // nR1
                    if (!strncmp(argv[optind], "0x", 2) || !strncmp(argv[optind], "0X", 2)) {
                        if (strlen(argv[optind]) != 2 + 8) { printf("! Invalid nR1 length\n"); usage(argv[0]); }
                        nR1 = (uint32_t) rev32(hexreversetoulong(argv[optind] + 2));
                    } else {
                        if (strlen(argv[optind]) != 8) { printf("! Invalid nR1 length\n"); usage(argv[0]); }
                        nR1 = (uint32_t) rev32(hexreversetoulong(argv[optind]));
                    }
                    break;

                case 2: // aR1
                    if (strlen(argv[optind]) != 8) { printf("! Invalid aR1 length\n"); usage(argv[0]); }
                    aR1 = (uint32_t) strtoul(argv[optind], NULL, 16);
                    break;

                case 3: // nR2
                    if (!strncmp(argv[optind], "0x", 2) || !strncmp(argv[optind], "0X", 2)) {
                        if (strlen(argv[optind]) != 2 + 8) { printf("! Invalid nR2 length\n"); usage(argv[0]); }
                        nR2 = (uint32_t) rev32(hexreversetoulong(argv[optind] + 2));
                    } else {
                        if (strlen(argv[optind]) != 8) { printf("! Invalid nR2 length\n"); usage(argv[0]); }
                        nR2 = (uint32_t) rev32(hexreversetoulong(argv[optind]));
                    }
                    break;

                case 4: // aR2
                    if (strlen(argv[optind]) != 8) { printf("! Invalid aR2 length\n"); usage(argv[0]); }
                    aR2 = (uint32_t) strtoul(argv[optind], NULL, 16);
                    break;

                default: // skip invalid instead of show usage and exit
                    optind = argc;
                    break;
            }
        }
    }

    memset(&ctx, 0, sizeof(opencl_ctx_t));
    memset(keystream, 0, sizeof(keystream));
    memset(candidates, 0, sizeof(candidates));

    ctx.profiling = opencl_profiling;
    ctx.thread_sched_type = (short) thread_scheduler_type_selected;
    ctx.force_hitag2_opencl = force_hitag2_opencl;

    uint32_t checks[4] = { uid, aR2, nR1, nR2 };

    if (!show) {
        if (verbose) printf("uid: %u, aR2: %u, nR1: %u, nR2: %u\n", checks[0], checks[1], checks[2], checks[3]);

        target = ~aR1;
        // bitslice inverse target bits
        bitslice(~target, keystream);

        size_t layer_0_found = 0;

        // compute layer 0 output
        for (size_t i0 = 0; i0 < 1 << 20; i0++) {
            uint64_t state0 = expand(0x5806b4a2d16c, i0);

            if (f(state0) == target >> 31) {
                // using uint64_t
                // candidates[layer_0_found++] = state0;
                // or
                // cf kernel, state is now split in 3 shorts >> 2
                candidates[(layer_0_found * 3) + 0] = (uint16_t)((state0 >> (32 + 2)) & 0xffff);
                candidates[(layer_0_found * 3) + 1] = (uint16_t)((state0 >> (16 + 2)) & 0xffff);
                candidates[(layer_0_found * 3) + 2] = (uint16_t)((state0 >> (0 + 2)) & 0xffff);
                layer_0_found++;
            }
        }

#if DEBUGME >= 1
        printf("[debug] layer_0_found: %zu\n", layer_0_found);
#endif
    }

    // powered by dolphin's macros :)
    int freeListIdx = 0;

    // todo, calculate the max number of allocations to remove 0x40
    void **freeList = (void **) malloc(0x40 * sizeof(void *));
    if (!freeList) {
        printf("Error: malloc (freeList) failed (%d): %s\n", errno, strerror(errno));
        exit(3);
    }

    if (!show) {
        // load OpenCL kernel source
        struct stat st;
        const char *opencl_kernel = "ht2crack5opencl_kernel.cl";

        int fd = open(opencl_kernel, O_RDONLY);
        if (fd <= 0) {
            printf("Error: open (%s) failed (%d): %s\n", opencl_kernel, errno, strerror(errno));
            exit(3);
        }

        if (fstat(fd, &st)) {
            printf("Error: stat (%s) failed (%d): %s\n", opencl_kernel, errno, strerror(errno));
            close(fd);
            exit(3);
        }

        ctx.kernelSource_len = (size_t) st.st_size;
        ctx.kernelSource[0]  = (char *) calloc(ctx.kernelSource_len + 1, sizeof(char));   // size + \0
        if (!ctx.kernelSource[0]) {
            printf("Error: calloc (ctx.kernelSource[0]) failed (%d): %s\n", errno, strerror(errno));
            exit(3);
        }

        MEMORY_FREE_ADD(ctx.kernelSource[0])

        if (read(fd, ctx.kernelSource[0], ctx.kernelSource_len) < (ssize_t) ctx.kernelSource_len) {
            printf("Error: read (%s) failed (%d): %s\n", opencl_kernel, errno, strerror(errno));
            close(fd);
            MEMORY_FREE_ALL
            exit(3);
        }

        ctx.kernelSource[0][ctx.kernelSource_len] = '\0';

        close(fd);
    }

    // now discover and set up compute device(s)
    int err = 0;
    cl_uint ocl_platform_cnt = 0;
    unsigned int ocl_platform_max = MAX_OPENCL_DEVICES; // 16

    cl_platform_id *ocl_platforms = (cl_platform_id *) calloc(ocl_platform_max, sizeof(cl_platform_id));
    if (!ocl_platforms) {
        printf("Error: calloc (ocl_platforms) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ocl_platforms)

    // enum platforms
    err = clGetPlatformIDs(ocl_platform_max, ocl_platforms, &ocl_platform_cnt);
    if (err != CL_SUCCESS) {
        printf("Error: clGetPlatformIDs() failed (%d)\n", err);
        MEMORY_FREE_ALL
        exit(2);
    }

    if (ocl_platform_cnt == 0) {
        printf("No platforms found, exit\n");
        MEMORY_FREE_ALL
        exit(2);
    }

    // allocate memory to hold info about platforms/devices
    compute_platform_ctx_t *cd_ctx = (compute_platform_ctx_t *) calloc(ocl_platform_cnt, sizeof(compute_platform_ctx_t));
    if (!cd_ctx) {
        printf("Error: calloc (compute_platform_ctx_t) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(err);
    }

    MEMORY_FREE_ADD(cd_ctx)

    cl_platform_info ocl_platforms_info[3] = { CL_PLATFORM_NAME, CL_PLATFORM_VENDOR, CL_PLATFORM_VERSION };
    unsigned int ocl_platforms_info_cnt = sizeof(ocl_platforms_info) / sizeof(cl_platform_info);

    cl_device_info ocl_devices_info[8] = { CL_DEVICE_TYPE, CL_DEVICE_NAME, CL_DEVICE_VERSION, CL_DRIVER_VERSION, CL_DEVICE_VENDOR, CL_DEVICE_LOCAL_MEM_TYPE, CL_DEVICE_MAX_WORK_ITEM_SIZES, CL_DEVICE_MAX_COMPUTE_UNITS };
    unsigned int ocl_devices_info_cnt = sizeof(ocl_devices_info) / sizeof(cl_device_info);

    unsigned int info_idx = 0;
    size_t tmp_len = 0;
    char *tmp_buf = NULL;

    unsigned int global_device_id = 0;
    size_t selected_platforms_cnt = 0;
    size_t selected_devices_cnt = 0;

    if (show) verbose = true;

    if (verbose) printf("- Found %u OpenCL Platform(s)\n", ocl_platform_cnt);

    for (cl_uint platform_idx = 0; platform_idx < ocl_platform_cnt; platform_idx++) {
        cd_ctx[platform_idx].platform_id = ocl_platforms[platform_idx];
        cd_ctx[platform_idx].selected = plat_dev_enabled(platform_idx, plat_sel, plat_cnt, 0, 0);

        if (cd_ctx[platform_idx].selected) selected_platforms_cnt++;

        if (verbose) printf("\n-- Platform ID: %d\n", platform_idx + 1);

        for (info_idx = 0; info_idx < ocl_platforms_info_cnt; info_idx++) {
            cl_platform_info ocl_info = ocl_platforms_info[info_idx];

            err = clGetPlatformInfo(cd_ctx[platform_idx].platform_id, ocl_info, 0, NULL, &tmp_len);
            if (err != CL_SUCCESS) {
                printf("Error: clGetPlatformInfo(param size) failed (%d)\n", err);
                MEMORY_FREE_ALL
                exit(2);
            }

            if (tmp_len > 0) {
                if (!(tmp_buf = (char *) calloc(tmp_len, sizeof(char)))) {
                    printf("Error: calloc (ocl_info %u) failed (%d): %s\n", info_idx, errno, strerror(errno));
                    MEMORY_FREE_ALL
                    exit(2);
                }

                MEMORY_FREE_ADD(tmp_buf)

                err = clGetPlatformInfo(cd_ctx[platform_idx].platform_id, ocl_info, tmp_len, tmp_buf, 0);
                if (err != CL_SUCCESS) {
                    printf("Error: clGetPlatformInfo(param) failed (%d)\n", err);
                    MEMORY_FREE_ALL
                    exit(2);
                }
            } else {
                tmp_len = 4;
                if (!(tmp_buf = (char *) calloc(tmp_len, sizeof(char)))) {
                    printf("Error: calloc (ocl_info %u) failed (%d): %s\n", info_idx, errno, strerror(errno));
                    MEMORY_FREE_ALL
                    exit(2);
                }

                MEMORY_FREE_ADD(tmp_buf)

                strncpy(tmp_buf, "N/A\0", tmp_len);
            }

            if (verbose) {
                const char *tmp_info_desc = (info_idx == 0) ? "Name" : (info_idx == 1) ? "Vendor" : "Version";

                printf("%14s: %s\n", tmp_info_desc, tmp_buf);
            }

            switch (info_idx) {
                case 0:
                    strncpy(cd_ctx[platform_idx].name, tmp_buf, tmp_len < 0xff ? tmp_len : 0xff - 1);
                    break;
                case 1:
                    strncpy(cd_ctx[platform_idx].vendor, tmp_buf, tmp_len < 0x40 ? tmp_len : 0x40 - 1);
                    break;
                case 2:
                    strncpy(cd_ctx[platform_idx].version, tmp_buf, tmp_len < 0x40 ? tmp_len : 0x40 - 1);
                    break;
            }

            if (info_idx == 1) {
                // todo: do the same this devices
                if (!strncmp(tmp_buf, "NVIDIA", 6)) cd_ctx[platform_idx].is_nv = true;
                else if (!strncmp(tmp_buf, "Apple", 5)) { cd_ctx[platform_idx].is_apple = true; cd_ctx[platform_idx].warning = true; }
                else if (!strncmp(tmp_buf, "Intel", 5)) cd_ctx[platform_idx].is_intel = true;
            }

            MEMORY_FREE_DEL(tmp_buf)
        }

        if (!show && verbose) {
            printf("%14s: %s\n", "Selected", (cd_ctx[platform_idx].selected) ? "yes" : "no");
            if (cd_ctx[platform_idx].warning) printf("\n%14s: performance will not be optimal using this platform\n\n", "=====> Warning");
        }

        // enum devices with this platform
        unsigned int ocl_device_cnt = 0;
        unsigned int ocl_device_max = MAX_OPENCL_DEVICES;

        cl_device_id *ocl_devices = (cl_device_id *) calloc(ocl_device_max, sizeof(cl_device_id));
        if (!ocl_devices) {
            printf("Error: calloc (ocl_devices) failed (%d): %s\n", errno, strerror(errno));
            MEMORY_FREE_ALL
            exit(2);
        }

        MEMORY_FREE_ADD(ocl_devices)

        err = clGetDeviceIDs(cd_ctx[platform_idx].platform_id, CL_DEVICE_TYPE_ALL, ocl_device_max, ocl_devices, &ocl_device_cnt);
        if (ocl_device_cnt == 0) {
            if (device_types_selected == CL_DEVICE_TYPE_ALL) printf("No device(s) available with platform id %d\n", platform_idx);
            cd_ctx[platform_idx].device_cnt = 0;
            continue;
        }

        if (err != CL_SUCCESS) {
            printf("Error: clGetDeviceIDs(cnt) failed (%d)\n", err);
            MEMORY_FREE_ALL
            exit(2);
        }

        if (verbose) printf("%14s: %u\n", "Device(s)", ocl_device_cnt);

        cd_ctx[platform_idx].device_cnt = ocl_device_cnt;

        for (unsigned int device_idx = 0; device_idx < ocl_device_cnt; device_idx++) {
            memset(&cd_ctx[platform_idx].device[device_idx], 0, sizeof(compute_device_ctx_t));
            cl_device_id ocl_device = ocl_devices[device_idx];
            cd_ctx[platform_idx].device[device_idx].platform_id = cd_ctx[platform_idx].platform_id;

            if (verbose) printf("---- * ID: %u\n", global_device_id + 1);

            for (info_idx = 0; info_idx < ocl_devices_info_cnt; info_idx++) {
                cl_device_info ocl_dev_info = ocl_devices_info[info_idx];

                if (info_idx == 0) {
                    cl_device_type device_type;

                    err = clGetDeviceInfo(ocl_device, ocl_dev_info, sizeof(cl_device_type), &device_type, 0);
                    if (err != CL_SUCCESS) {
                        printf("Error: clGetDeviceInfo(device_type) failed (%d)\n", err);
                        MEMORY_FREE_ALL
                        exit(2);
                    }

                    if (device_type & CL_DEVICE_TYPE_GPU) cd_ctx[platform_idx].device[device_idx].is_gpu = 1;

                    if (verbose) printf("%14s: %s\n", "Device Type", (device_type & CL_DEVICE_TYPE_GPU) ? "GPU" : (device_type & CL_DEVICE_TYPE_CPU) ? "CPU" : "Other");

                    cd_ctx[platform_idx].device[device_idx].selected = plat_dev_enabled(global_device_id, dev_sel, dev_cnt, (unsigned int) device_type, device_types_selected);
                    global_device_id++;
                    if (cd_ctx[platform_idx].device[device_idx].selected) selected_devices_cnt++;
                    continue;
                } else if (info_idx == 5) {
                    cl_device_local_mem_type local_mem_type;

                    err = clGetDeviceInfo(ocl_device, ocl_dev_info, sizeof(cl_device_local_mem_type), &local_mem_type, 0);
                    if (err != CL_SUCCESS) {
                        printf("Error: clGetDeviceInfo(local_mem_type) failed (%d)\n", err);
                        MEMORY_FREE_ALL
                        exit(2);
                    }

                    if (local_mem_type == CL_LOCAL || local_mem_type == CL_GLOBAL) {
                        if (verbose) printf("%14s: %s\n", "Local Mem Type", (local_mem_type == CL_LOCAL) ? "Local" : "Global");

                        if (cd_ctx[platform_idx].is_apple) {
                            if (strncmp(cd_ctx[platform_idx].device[device_idx].vendor, "Intel", 5) != 0) cd_ctx[platform_idx].device[device_idx].have_local_memory = true;
                        } else if (cd_ctx[platform_idx].is_nv) cd_ctx[platform_idx].device[device_idx].have_local_memory = true;
                        /*
                        						// swap the 'if' comment for enable local memory with apple gpu's (my Iris crash, abort 6)
                        						// if (!(!strncmp (cd_ctx[platform_idx].device[device_idx].vendor, "Intel", 5) && cd_ctx[platform_idx].is_apple && !cd_ctx[platform_idx].device[device_idx].is_gpu))
                        						if (!(!strncmp (cd_ctx[platform_idx].device[device_idx].vendor, "Intel", 5) && cd_ctx[platform_idx].is_apple))
                        						{
                        							cd_ctx[platform_idx].device[device_idx].have_local_memory = true;
                        						}
                        */
                    } else {
                        if (verbose) printf("%14s: None\n", "Local Mem Type");
                    }

                    if (verbose) printf("%14s: %s\n", "Local Mem Opt", (cd_ctx[platform_idx].device[device_idx].have_local_memory) ? "yes" : "no");

                    continue;
                } else if (info_idx == 6) {
                    size_t wis[3] = { 0 };
                    err = clGetDeviceInfo(ocl_device, ocl_dev_info, sizeof(size_t) * 3, wis, 0);
                    if (err != CL_SUCCESS) {
                        printf("Error: clGetDeviceInfo(work_items_size) failed (%d)\n", err);
                        MEMORY_FREE_ALL
                        exit(2);
                    }

                    if (verbose) printf("%14s: (%zu,%zu,%zu)\n", "Max Work-Items", wis[0], wis[1], wis[2]);

#if APPLE_GPU_BROKEN == 1
                    if (wis[1] < GLOBAL_WS_1 && cd_ctx[platform_idx].device[device_idx].is_apple_gpu) {
                        cd_ctx[platform_idx].device[device_idx].unsupported = true;
                    }
#endif
                    continue;
                } else if (info_idx == 7) {
                    cl_uint cores = 0;
                    err = clGetDeviceInfo(ocl_device, ocl_dev_info, sizeof(cl_uint), &cores, 0);
                    if (err != CL_SUCCESS) {
                        printf("Error: clGetDeviceInfo(compute_units) failed (%d)\n", err);
                        MEMORY_FREE_ALL
                        exit(2);
                    }

                    if (verbose) printf("%14s: %u\n", "Compute Units", cores);

                    cd_ctx[platform_idx].device[device_idx].compute_units = cores;
                    continue;
                }

                tmp_len = 0;
                tmp_buf = NULL;

                err = clGetDeviceInfo(ocl_device, ocl_dev_info, 0, NULL, &tmp_len);
                if (err != CL_SUCCESS) {
                    printf("Error: clGetDeviceInfo(param size) failed (%d)\n", err);
                    MEMORY_FREE_ALL
                    exit(2);
                }

                if (tmp_len > 0) {
                    if (!(tmp_buf = (char *) calloc(tmp_len, sizeof(char)))) {
                        printf("Error: calloc (ocl_dev_info %u) failed (%d): %s\n", info_idx, errno, strerror(errno));
                        MEMORY_FREE_ALL
                        exit(2);
                    }

                    MEMORY_FREE_ADD(tmp_buf)

                    err = clGetDeviceInfo(ocl_device, ocl_dev_info, tmp_len, tmp_buf, 0);
                    if (err != CL_SUCCESS) {
                        printf("Error: clGetDeviceInfo(param) failed (%d)\n", err);
                        MEMORY_FREE_ALL
                        exit(2);
                    }
                } else {
                    tmp_len = 4;
                    if (!(tmp_buf = (char *) calloc(tmp_len, sizeof(char)))) {
                        printf("Error: calloc (ocl_dev_info %u) failed (%d): %s\n", info_idx, errno, strerror(errno));
                        MEMORY_FREE_ALL
                        exit(2);
                    }

                    MEMORY_FREE_ADD(tmp_buf)

                    strncpy(tmp_buf, "N/A\0", tmp_len);
                }

                if (verbose) {
                    const char *tmp_dev_info_desc = (info_idx == 1) ? "Name" : (info_idx == 2) ? "Version" : (info_idx == 3) ? "Driver Version" : "Vendor";

                    printf("%14s: %s\n", tmp_dev_info_desc, tmp_buf);
                }

                switch (info_idx) {
                    case 1:
                        strncpy(cd_ctx[platform_idx].device[device_idx].name, tmp_buf, tmp_len < 0xff ? tmp_len : 0xff - 1);
                        break;
                    case 2:
                        strncpy(cd_ctx[platform_idx].device[device_idx].version, tmp_buf, tmp_len < 0x40 ? tmp_len : 0x40 - 1);
                        break;
                    case 3:
                        strncpy(cd_ctx[platform_idx].device[device_idx].driver_version, tmp_buf, tmp_len < 0x40 ? tmp_len : 0x40 - 1);
                        break;
                    case 4:
                        strncpy(cd_ctx[platform_idx].device[device_idx].vendor, tmp_buf, tmp_len < 0x40 ? tmp_len : 0x40 - 1);
                        break;
                }

                if (info_idx == 4) {
                    if (!strncmp(tmp_buf, "Intel", 5) && cd_ctx[platform_idx].is_apple) {
                        // disable hitag2 with apple platform and not apple device vendor (< Apple M1)
                        ctx.force_hitag2_opencl = false;

                        cd_ctx[platform_idx].device[device_idx].is_apple_gpu = cd_ctx[platform_idx].device[device_idx].is_gpu;
                    }

                    if (!strncmp(tmp_buf, "NVIDIA", 6) && cd_ctx[platform_idx].is_nv) {
                        unsigned int sm_maj = 0, sm_min = 0;

                        err  = clGetDeviceInfo(ocl_device, 0x4000, sizeof(unsigned int), &sm_maj, 0);
                        err |= clGetDeviceInfo(ocl_device, 0x4001, sizeof(unsigned int), &sm_min, 0);

                        if (err != CL_SUCCESS) {
                            printf("Error: clGetDeviceInfo(sm_maj/sm_min) failed (%d)\n", err);
                            MEMORY_FREE_ALL
                            exit(2);
                        }

                        cd_ctx[platform_idx].device[device_idx].sm_maj = sm_maj;
                        cd_ctx[platform_idx].device[device_idx].sm_min = sm_min;

                        if (verbose) printf("%14s: %u%u\n", "SM", sm_maj, sm_min);

                        if (sm_maj >= 5) { // >= Maxwell
                            // https://docs.nvidia.com/cuda/parallel-thread-execution/index.html#logic-and-shift-instructions-lop3
                            // Requires sm_50 or higher.
                            cd_ctx[platform_idx].device[device_idx].have_lop3 = true;
                        } else {
                            cd_ctx[platform_idx].device[device_idx].warning = true;
                        }

                        cd_ctx[platform_idx].device[device_idx].is_nv = true;
                    } else {
                        cd_ctx[platform_idx].device[device_idx].warning = true;
                    }
                }

                MEMORY_FREE_DEL(tmp_buf)
            }

            if (!show && verbose) printf("%14s: %s\n", "Selected", (cd_ctx[platform_idx].device[device_idx].selected) ? "yes" : "no");

            if (cd_ctx[platform_idx].device[device_idx].unsupported) {
                printf("\n%14s: this device was not supported, beacuse of missing resources\n\n", "=====> Warning");
                continue;
            }

            if (cd_ctx[platform_idx].device[device_idx].warning) {
                if (!show && verbose) printf("\n%14s: performance will not be optimal using this device\n\n", "=====> Warning");
            }

            cd_ctx[platform_idx].device[device_idx].device_id = ocl_device;
        }
        MEMORY_FREE_DEL(ocl_devices)
    }
    MEMORY_FREE_DEL(ocl_platforms)

    // new selection engine, need to support multi-gpu system (with the same platform)

    if (verbose) printf("\n");

    if (show) {
        MEMORY_FREE_ALL
        exit(2);
    }

    if (selected_platforms_cnt == 0) {
        printf("! No platform was selected ...\n");
        MEMORY_FREE_ALL
        exit(2);
    }

    if (selected_devices_cnt == 0) {
        printf("! No device(s) was selected ...\n");
        MEMORY_FREE_ALL
        exit(2);
    }

    size_t w = 0, q = 0, g = 0;

    size_t z = 0; // z is a dolphin's friend

    // show selected devices

    printf("Selected %zu OpenCL Device(s)\n\n", selected_devices_cnt);

    for (w = 0; w < ocl_platform_cnt; w++) {
        if (!cd_ctx[w].selected) continue;

        for (q = 0; q < cd_ctx[w].device_cnt; q++) {
            if (!cd_ctx[w].device[q].selected) continue;

            printf("%2zu - %s", z, cd_ctx[w].device[q].name);
            if (verbose) {
                printf(" (Lop3 %s, ", (cd_ctx[w].device[q].have_lop3) ? "yes" : "no");
                printf("Local Memory %s)", (cd_ctx[w].device[q].have_local_memory) ? "yes" : "no");
            }
            printf("\n");

            z++;
        }
    }
    printf("\n");

    if (selected_devices_cnt != z) {
        printf("BUG: z and selected_devices_cnt are not equal\n");
        MEMORY_FREE_ALL
        exit(2);
    }

    // time to eat some memory :P

    if (!(ctx.device_ids = (cl_device_id *) calloc(selected_devices_cnt, sizeof(cl_device_id)))) {
        printf("Error: calloc (ctx.device_ids) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.device_ids)

    if (!(ctx.contexts = (cl_context *) calloc(selected_devices_cnt, sizeof(cl_context)))) {
        printf("Error: calloc (ctx.contexts) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.contexts)

    if (!(ctx.commands = (cl_command_queue *) calloc(selected_devices_cnt, sizeof(cl_command_queue)))) {
        printf("Error: calloc (ctx.commands) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.commands)

    if (!(ctx.programs = (cl_program *) calloc(selected_devices_cnt, sizeof(cl_program)))) {
        printf("Error: calloc (ctx.programs) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.programs)

    if (!(ctx.kernels = (cl_kernel *) calloc(selected_devices_cnt, sizeof(cl_kernel)))) {
        printf("Error: calloc (ctx.kernels) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.kernels)

    if (!(matches = (uint64_t **) calloc(selected_devices_cnt, sizeof(uint64_t *)))) {
        printf("Error: calloc (**matches) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(matches)

    if (!(matches_found = (uint32_t **) calloc(selected_devices_cnt, sizeof(uint32_t *)))) {
        printf("Error: calloc (**matches_found) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(matches_found)

    if (!(ctx.keystreams = (cl_mem *) calloc(selected_devices_cnt, sizeof(cl_mem)))) {
        printf("Error: calloc (ctx.keystreams) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.keystreams)

    if (!(ctx.candidates = (cl_mem *) calloc(selected_devices_cnt, sizeof(cl_mem)))) {
        printf("Error: calloc (ctx.candidates) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.candidates)

    if (!(ctx.matches = (cl_mem *) calloc(selected_devices_cnt, sizeof(cl_mem)))) {
        printf("Error: calloc (ctx.matches) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.matches)

    if (!(ctx.matches_found = (cl_mem *) calloc(selected_devices_cnt, sizeof(cl_mem)))) {
        printf("Error: calloc (ctx.matches_found) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.matches_found)

    if (ctx.force_hitag2_opencl) {
        if (!(ctx.checks = (cl_mem *) calloc(selected_devices_cnt, sizeof(cl_mem)))) {
            printf("Error: calloc (ctx.checks) failed (%d): %s\n", errno, strerror(errno));
            MEMORY_FREE_ALL
            exit(2);
        }

        MEMORY_FREE_ADD(ctx.checks)
    }

    if (!(ctx.global_ws = (size_t *) calloc(selected_devices_cnt, sizeof(size_t)))) {
        printf("Error: calloc (ctx.global_ws) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.global_ws)

    if (!(ctx.local_ws = (size_t *) calloc(selected_devices_cnt, sizeof(size_t)))) {
        printf("Error: calloc (ctx.local_ws) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.local_ws)

    if (!(ctx.profiles = (int *) calloc(selected_devices_cnt, sizeof(int)))) {
        printf("Error: calloc (ctx.profiles) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_ALL
        exit(2);
    }

    MEMORY_FREE_ADD(ctx.profiles)

    // show buidlog in case of error
    // todo: only for device models
    unsigned int build_errors = 0;
    unsigned int build_logs = 0;

    cl_command_queue_properties queue_properties = 0;

    if (opencl_profiling) queue_properties = CL_QUEUE_PROFILING_ENABLE;

    // setup, phase 1

    z = 0; // dolphin

    for (w = 0; w < ocl_platform_cnt; w++) {
        if (!cd_ctx[w].selected) continue;

        for (q = 0; q < cd_ctx[w].device_cnt; q++) {
            if (!cd_ctx[w].device[q].selected) continue;

            ctx.device_ids[z] = cd_ctx[w].device[q].device_id;

            // create the opencl context with the array
            ctx.contexts[z] = clCreateContext(NULL, 1, &ctx.device_ids[z], NULL, NULL, &err);
            if (!ctx.contexts[z] || err != CL_SUCCESS) {
                printf("[%zu] Error: clCreateContext() failed (%d)\n", z, err);
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST(matches, z)
                MEMORY_FREE_LIST(matches_found, z)
                MEMORY_FREE_ALL
                exit(2);
            }

            // create comman queues for each selected devices
            ctx.commands[z] = clCreateCommandQueue(ctx.contexts[z], ctx.device_ids[z], queue_properties, &err);
            if (!ctx.commands[z] || err != CL_SUCCESS) {
                printf("[%zu] Error: clCreateCommandQueue() failed (%d)\n", z, err);
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST(matches, z)
                MEMORY_FREE_LIST(matches_found, z)
                MEMORY_FREE_ALL
                exit(2);
            }

            // from clang:
            // warning: cast from 'char *(*)[1]' to 'const char **' increases required alignment from 1 to 8
            const char *a = (const char *)ctx.kernelSource[0];
            const char **ks = &a;

            // create the compute program from the source buffer
            //ctx.programs[z] = clCreateProgramWithSource(ctx.contexts[z], 1, (const char **) &ctx.kernelSource, &ctx.kernelSource_len, &err);
            ctx.programs[z] = clCreateProgramWithSource(ctx.contexts[z], 1, ks, &ctx.kernelSource_len, &err);
            if (!ctx.programs[z] || err != CL_SUCCESS) {
                printf("[%zu] Error: clCreateProgramWithSource() failed (%d)\n", z, err);
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST(matches, z)
                MEMORY_FREE_LIST(matches_found, z)
                MEMORY_FREE_ALL
                exit(2);
            }

            // build the program executable
            bool have_local_memory = false;
            size_t blen = 0;
            char build_options[0x100];

            memset(build_options, 0, sizeof(build_options));

            strncpy(build_options, "-Werror", 8);
            blen += 7;

            if (cd_ctx[w].device[q].have_lop3) { // enable lop3
                strncpy(build_options + blen, " -D HAVE_LOP3", 14);
                blen += 13;
            }

            if (ctx.force_hitag2_opencl) {
                // force using hitag2 key validation with OpenCL
                strncpy(build_options + blen, " -D WITH_HITAG2_FULL", 21);
                blen += 20;
            }

            // Intel's gpu are worst than Apple
#if APPLE_GPU_BROKEN == 0
            if (cd_ctx[w].device[q].is_gpu && !strncmp(cd_ctx[w].device[q].vendor, "Intel", 5)) {
                if (cd_ctx[w].is_apple || cd_ctx[w].is_intel) {
                    strncpy(build_options + blen, " -D LOWPERF", 13);
                    blen += 12;
                }
            }
#endif

#if DEBUGME >= 1
            printf("[debug] Device %zu have local mem ? %d\n", z, cd_ctx[w].device[q].have_local_memory);
#endif

            if (cd_ctx[w].device[q].have_local_memory) { // kernel keystream memory optimization
                have_local_memory = true;
                strncpy(build_options + blen, " -D HAVE_LOCAL_MEMORY", 22);
                blen += 21;
            }

            if (verbose) printf("[%zu] Building OpenCL program with options (len %zu): %s\n", z, blen, build_options);

            err = clBuildProgram(ctx.programs[z], 1, &ctx.device_ids[z], build_options, NULL, NULL);

#if DEBUGME == 0
            if (err != CL_SUCCESS)
#endif
            {
#if DEBUGME > 0
                if (err != CL_SUCCESS)
#endif
                {
                    printf("[%zu] Error: clBuildProgram() failed (%d)\n", z, err);
                    build_errors++;
                }

                // todo: if same device model of other and build_logs > 0, continue

                size_t len = 0;
                err = clGetProgramBuildInfo(ctx.programs[z], cd_ctx[w].device[q].device_id, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
                if (err != CL_SUCCESS) {
                    printf("[%zu] Error: clGetProgramBuildInfo failed (%d)\n", z, err);
                    continue;
//					exit (2);
                }

                if (len == 0) continue;

                if (len > 0xdeadbe) len = 0xdeadbe; // limit build_log size

                char *buffer = (char *) calloc(len, sizeof(char));
                if (!buffer) {
                    printf("[%zu] Error: calloc (CL_PROGRAM_BUILD_LOG) failed (%d): %s\n", z, errno, strerror(errno));
                    continue;
//					exit (2);
                }

                MEMORY_FREE_ADD(buffer)

                err = clGetProgramBuildInfo(ctx.programs[z], cd_ctx[w].device[q].device_id, CL_PROGRAM_BUILD_LOG, len, buffer, 0);
                if (err != CL_SUCCESS) {
                    printf("[%zu] clGetProgramBuildInfo() failed (%d)\n", z, err);
                    MEMORY_FREE_DEL(buffer)
                    continue;
//					exit (2);
                }

#if DEBUGME > 0
                if (len > 2)
#endif
                {
                    printf("[%zu] Build log (len %zu):\n--------\n%s\n--------\n", z, len, buffer);
                }

                MEMORY_FREE_DEL(buffer)

                build_logs++;
#if DEBUGME == 0
                continue; // todo: evaluate this, one or more can be broken, so continue
#endif
            }

            // todo, continue if build_errors

            // Create the compute kernel in the program we wish to run
            ctx.kernels[z] = clCreateKernel(ctx.programs[z], "find_state", &err);
            if (!ctx.kernels[z] || err != CL_SUCCESS) {
                printf("[%zu] Error: clCreateKernel() failed (%d)\n", z, err);
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST(matches, z)
                MEMORY_FREE_LIST(matches_found, z)
                MEMORY_FREE_ALL
                exit(3);
            }

            size_t wgs = 0;
            err = clGetKernelWorkGroupInfo(ctx.kernels[z], cd_ctx[w].device[q].device_id, CL_KERNEL_WORK_GROUP_SIZE, sizeof(size_t), &wgs, NULL);
            if (err != CL_SUCCESS) {
                printf("[%zu] Error: clGetKernelWorkGroupInfo(CL_KERNEL_WORK_GROUP_SIZE) failed (%d)\n", z, err);
                MEMORY_FREE_OPENCL(ctx, z)
                // if macros work, next 2 macro are not needed
                MEMORY_FREE_LIST(matches, z)
                MEMORY_FREE_LIST(matches_found, z)
                MEMORY_FREE_ALL
                exit(3);
            }

            ctx.local_ws[z] = wgs;

            // never got it
            if (ctx.local_ws[z] < 32 && have_local_memory) {
                printf("Warning: local work-item size is less than the length of the keystream, and local memory optimization is enabled. An unexpected result could arise.\n");
            }

            z++;
        }
    }

    // z is device counter, dolphin counter as well

    // setup, phase 2 (select lower profile)

    int profile = 0xff;

    g = 0;

    for (w = 0; w < ocl_platform_cnt; w++) {
        if (!cd_ctx[w].selected) continue;

        for (q = 0; q < cd_ctx[w].device_cnt; q++) {
            if (!cd_ctx[w].device[q].selected) continue;

            ctx.profiles[g] = (int) profile_selected; // start with default

#if DEBUGME > 1
            printf("[debug] Initial profile for device %zu: %d\n", z, ctx.profiles[g]);
#endif

            // force profile to 0 with Apple GPU's to get it stable, and 1 for CPU
            if (cd_ctx[w].is_apple && !strncmp(cd_ctx[w].device[q].vendor, "Intel", 5)) {
                if (cd_ctx[w].device[q].is_gpu) {
                    if (profile_selected > 2) ctx.profiles[g] = PROFILE_DEFAULT; // Apple-Intel GPU's, 2 is the old 0
                } else {
                    if (profile_selected > 3) ctx.profiles[g] = PROFILE_DEFAULT; // Apple-Intel CPU's, 3 is the old 1
                }
            }

            // force profile to 0 with Intel GPU and 2 wih Intel CPU's
            if (cd_ctx[w].is_intel && !strncmp(cd_ctx[w].device[q].vendor, "Intel", 5)) {
                if (cd_ctx[w].device[q].is_gpu) {
                    ctx.profiles[g] = 0; // Intel GPU, work better with a very slow profile
                } else {
                    if (profile_selected > 2) ctx.profiles[g] = PROFILE_DEFAULT; // Intel CPU (2 is the old 0)
                }
            }

            // force profile to 2 with NVIDIA GPU's with NVIDIA platform
            if (cd_ctx[w].is_nv && cd_ctx[w].device[q].is_gpu && !strncmp(cd_ctx[w].device[q].vendor, "NVIDIA", 6)) {
                if (profile_selected > 10) {
                    // NVIDIA RTX 3090 perform better with 5
                    ctx.profiles[g] = (cd_ctx[w].device[q].sm_maj >= 8) ? 5 : PROFILE_DEFAULT;
                }
            }

            // probably unstested hw, set profile to 0
            if (profile_selected == 0xff) {
                profile_selected = 0;
                ctx.profiles[g] = 0;
            }

            // with same devices will be selected the best
            // but for different devices in the same platform we need the worst for now (todo)
            if (ctx.profiles[q] < profile) profile = ctx.profiles[q];
        }
    }

    // profile consistency check
    if (profile < 0 || profile > 10) {
        printf("! Error: the selected profile is not allowed (%d)\n", profile);
        MEMORY_FREE_OPENCL(ctx, z)
        MEMORY_FREE_LIST_Z(matches, z)
        MEMORY_FREE_LIST_Z(matches_found, z)
        MEMORY_FREE_ALL
        exit(2);
    }

    // setup, phase 3 (finis him)

    z = 0;

    for (w = 0; w < ocl_platform_cnt; w++) {
        if (!cd_ctx[w].selected) continue;

        for (q = 0; q < cd_ctx[w].device_cnt; q++) {
            if (!cd_ctx[w].device[q].selected) continue;

            ctx.global_ws[z] = (1 << profiles[profile][1]);

            // the following happens with cpu devices or Apple GPU
            if (ctx.local_ws[z] > 256) {
                if (cd_ctx[w].is_apple) ctx.local_ws[z] = 256;
                else if (!cd_ctx[w].device[q].is_gpu) ctx.local_ws[z] = 256;
            }

            // dow't allow gws < lws
            if (ctx.global_ws[z] < ctx.local_ws[z]) ctx.local_ws[z] = ctx.global_ws[z];

            if (opencl_profiling) printf("[%zu] global_ws %zu, local_ws %zu\n", g, ctx.global_ws[z], ctx.local_ws[z]);

            if (!ctx.force_hitag2_opencl) {
                if (!(matches[z] = (uint64_t *) calloc((uint32_t)(ctx.global_ws[z] * WGS_MATCHES_FACTOR), sizeof(uint64_t)))) {
                    printf("[%zu] Error: calloc (matches) failed (%d): %s\n", g, errno, strerror(errno));
                    MEMORY_FREE_OPENCL(ctx, z)
                    MEMORY_FREE_LIST(matches, z)
                    MEMORY_FREE_LIST(matches_found, z)
                    MEMORY_FREE_ALL
                    exit(2);
                }
            } else {
                // one
                if (!(matches[z] = (uint64_t *) calloc(1, sizeof(uint64_t)))) {
                    printf("[%zu] Error: calloc (matches) failed (%d): %s\n", z, errno, strerror(errno));
                    MEMORY_FREE_OPENCL(ctx, z)
                    MEMORY_FREE_LIST(matches, z)
                    MEMORY_FREE_LIST(matches_found, z)
                    MEMORY_FREE_ALL
                    exit(2);
                }
            }

            if (!(matches_found[z] = (uint32_t *) calloc(1, sizeof(uint32_t)))) {
                printf("[%zu] Error: calloc (matches_found) failed (%d): %s\n", z, errno, strerror(errno));
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST_Z(matches, z)
                MEMORY_FREE_LIST(matches_found, z)
                MEMORY_FREE_ALL
                exit(2);
            }

            ctx.candidates[z] = clCreateBuffer(ctx.contexts[z],  CL_MEM_READ_ONLY,  sizeof(uint16_t) * ((1 << 20) * 3), NULL, NULL);
            //ctx.candidates = clCreateBuffer(ctx.contexts[z],  CL_MEM_READ_ONLY,  sizeof(uint64_t) * ((1 << 20)), NULL, NULL);
            ctx.keystreams[z]  = clCreateBuffer(ctx.contexts[z],  CL_MEM_READ_ONLY,  VECTOR_SIZE * 32, NULL, NULL);

            if (!ctx.force_hitag2_opencl) {
                ctx.matches[z] = clCreateBuffer(ctx.contexts[z], CL_MEM_WRITE_ONLY, sizeof(uint64_t) * (uint32_t)(ctx.global_ws[z] * WGS_MATCHES_FACTOR), NULL, NULL);
            } else { // one
                ctx.matches[z] = clCreateBuffer(ctx.contexts[z], CL_MEM_WRITE_ONLY, sizeof(uint64_t), NULL, NULL);
            }

            ctx.matches_found[z] = clCreateBuffer(ctx.contexts[z], CL_MEM_READ_WRITE, sizeof(uint32_t), NULL, NULL);

            if (ctx.force_hitag2_opencl) {
                ctx.checks[z] = clCreateBuffer(ctx.contexts[z], CL_MEM_READ_ONLY, sizeof(uint32_t) * 4, NULL, NULL);
                if (!ctx.checks[z]) {
                    printf("[%zu] Error: invalid shared cl_mem (ctx.candidates|ctx.keystream|ctx.checks)\n", z);
                    MEMORY_FREE_OPENCL(ctx, z)
                    MEMORY_FREE_LIST_Z(matches, z)
                    MEMORY_FREE_LIST_Z(matches_found, z)
                    MEMORY_FREE_ALL
                    exit(3);
                }
            }

            if (!ctx.candidates[z] || !ctx.keystreams[z]) {
                printf("[%zu] Error: invalid shared cl_mem (ctx.candidates|ctx.keystream)\n", z);
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST_Z(matches, z)
                MEMORY_FREE_LIST_Z(matches_found, z)
                MEMORY_FREE_ALL
                exit(3);
            }

            if (!ctx.matches[z] || !ctx.matches_found[z]) {
                printf("[%zu] Error: invalid per-device cl_mem (ctx.matches or ctx.matches_found)\n", z);
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST_Z(matches, z)
                MEMORY_FREE_LIST_Z(matches_found, z)
                MEMORY_FREE_ALL
                exit(3);
            }

            // Write our data set into the input array in device memory
            // todo
            // if z is last set CL_TRUE (blocking) else CL_FALSE (non-blocking)
            // using this way, setup time can be reduced
            err = clEnqueueWriteBuffer(ctx.commands[z], ctx.keystreams[z], CL_TRUE, 0, VECTOR_SIZE * 32, keystream, 0, NULL, NULL);
            if (err != CL_SUCCESS) {
                printf("[%zu] Error: clEnqueueWriteBuffer(ctx.keystream) failed (%d)\n", z, err);
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST_Z(matches, z)
                MEMORY_FREE_LIST_Z(matches_found, z)
                MEMORY_FREE_ALL
                exit(3);
            }

            err = clEnqueueWriteBuffer(ctx.commands[z], ctx.candidates[z], CL_TRUE, 0, sizeof(uint16_t) * ((1 << 20) * 3), candidates, 0, NULL, NULL);
//			err = clEnqueueWriteBuffer(ctx.commands[z], ctx.candidates, CL_TRUE, 0, sizeof(uint64_t) * ((1 << 20)), candidates, 0, NULL, NULL);
            if (err != CL_SUCCESS) {
                printf("[%zu] Error: clEnqueueWriteBuffer(ctx.candidates) failed (%d)\n", z, err);
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST_Z(matches, z)
                MEMORY_FREE_LIST_Z(matches_found, z)
                MEMORY_FREE_ALL
                exit(3);
            }

            if (ctx.force_hitag2_opencl) {
                err = clEnqueueWriteBuffer(ctx.commands[z], ctx.checks[z], CL_TRUE, 0, sizeof(uint32_t) * 4, checks, 0, NULL, NULL);
                if (err != CL_SUCCESS) {
                    printf("[%zu] Error: clEnqueueWriteBuffer(ctx.checks) failed (%d)\n", z, err);
                    MEMORY_FREE_OPENCL(ctx, z)
                    MEMORY_FREE_LIST_Z(matches, z)
                    MEMORY_FREE_LIST_Z(matches_found, z)
                    MEMORY_FREE_ALL
                    exit(3);
                }
            }

            // Set the arguments to our compute kernel
            err  = clSetKernelArg(ctx.kernels[z], 1, sizeof(cl_mem), &ctx.candidates[z]);
            err |= clSetKernelArg(ctx.kernels[z], 2, sizeof(cl_mem), &ctx.keystreams[z]);
            err |= clSetKernelArg(ctx.kernels[z], 3, sizeof(cl_mem), &ctx.matches[z]);
            if (ctx.force_hitag2_opencl) err |= clSetKernelArg(ctx.kernels[z], 5, sizeof(cl_mem), &ctx.checks[z]);

            if (err != CL_SUCCESS) {
                printf("[%zu] Error: clSetKernelArg(ctx.candidates|ctx.keystream|ctx.matches|ctx.checks) failed (%d)\n", z, err);
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST_Z(matches, z)
                MEMORY_FREE_LIST_Z(matches_found, z)
                MEMORY_FREE_ALL
                exit(3);
            }

            z++;
        }
    }

    if (build_errors > 0) {
#if DEBUGME >= 2
        printf("[debug] Detected build errors with %u device(s).\n", build_errors);
#endif
        MEMORY_FREE_OPENCL(ctx, z)
        MEMORY_FREE_LIST_Z(matches, z)
        MEMORY_FREE_LIST_Z(matches_found, z)
        MEMORY_FREE_ALL
        exit(3);
    }

    // at this point z is the max value, still usefull for free's

#if DEBUGME > 0
    printf("[debug] Lower profile between %u device(s) is: %d\n", selected_devices_cnt, profile);
#endif

    uint32_t max_step = profiles[profile][0];
    uint32_t chunk = profiles[profile][1];

#if DEBUGME > 0
    printf("[debug] Init queue\n");
#endif

    int ret = 0;
    if ((ret = wu_queue_init(&ctx.queue_ctx, queue_type)) != 0) {
        printf("! Error: wu_queue_init(%s) failed (%d): %s\n", wu_queue_strdesc(queue_type), ret, wu_queue_strerror(ret));
        MEMORY_FREE_OPENCL(ctx, z)
        MEMORY_FREE_LIST_Z(matches, z)
        MEMORY_FREE_LIST_Z(matches_found, z)
        MEMORY_FREE_ALL
        exit(2);
    }

#if DEBUGME > 0
    printf("[queue] Fill queue with pre-calculated offset using profile (%d): ", profile);
#endif

    for (size_t step = 0; step < max_step; step++) wu_queue_push(&ctx.queue_ctx, step, step << chunk, max_step);

#if DEBUGME > 0
    printf("done\n");
#endif

    // save selected_devices_cnt
    size_t thread_count = selected_devices_cnt;

    thread_ctx_t th_ctx;
    memset(&th_ctx, 0, sizeof(thread_ctx_t));

    thread_args_t *t_arg = (thread_args_t *) calloc(thread_count, sizeof(thread_args_t));
    if (!t_arg) {
        printf("Error: calloc (thread_args_t) failed (%d): %s\n", errno, strerror(errno));
        MEMORY_FREE_OPENCL(ctx, z)
        MEMORY_FREE_LIST_Z(matches, z)
        MEMORY_FREE_LIST_Z(matches_found, z)
        MEMORY_FREE_ALL
        exit(3);
    }

    MEMORY_FREE_ADD(t_arg)

    if ((ret = thread_init(&th_ctx, ctx.thread_sched_type, thread_count)) != 0) {
        printf("Error: thread_init(%zu) failed (%d)\n", thread_count, ret);
        MEMORY_FREE_OPENCL(ctx, z)
        MEMORY_FREE_LIST_Z(matches, z)
        MEMORY_FREE_LIST_Z(matches_found, z)
        MEMORY_FREE_ALL
        exit(3);
    }

    // preload constant values in threads memory, and start threads
    for (z = 0; z < thread_count; z++) {
        t_arg[z].uid = uid;
        t_arg[z].aR2 = aR2;
        t_arg[z].nR1 = nR1;
        t_arg[z].nR2 = nR2;
        t_arg[z].max_step = max_step;
        t_arg[z].ocl_ctx = &ctx;
        t_arg[z].device_id = z;
        t_arg[z].async = (ctx.thread_sched_type == THREAD_TYPE_ASYNC);
        t_arg[z].thread_ctx = &th_ctx;

        if (ctx.thread_sched_type == THREAD_TYPE_ASYNC) {
            t_arg[z].matches = matches[z];
            t_arg[z].matches_found = matches_found[z];
            t_arg[z].status = TH_START;
        }
    }

    if (ctx.thread_sched_type == THREAD_TYPE_ASYNC) {
        if ((ret = thread_start(&th_ctx, t_arg)) != 0) {
            printf("Error: thread_start() failed (%d): %s\n", ret, thread_strerror(ret));
            thread_destroy(&th_ctx);
            MEMORY_FREE_OPENCL(ctx, z)
            MEMORY_FREE_LIST_Z(matches, z)
            MEMORY_FREE_LIST_Z(matches_found, z)
            MEMORY_FREE_ALL
            exit(3);
        }
    }

#if DEBUGME >= 1
    // they now are all in TH_WAIT locked by a cond_wait
    // try the normal routine
    if (ctx.thread_sched_type == THREAD_TYPE_ASYNC) {
        size_t th_status_err = 0;
        for (z = 0; z < thread_count; z++) {
            pthread_mutex_lock(&thread_mutexs[z]);
            thread_status_t tmp = t_arg[z].status;
            pthread_mutex_unlock(&thread_mutexs[z]);

            if (tmp != TH_START) {
                printf("! Warning: Thread %zu is not in TH_START, found in %s\n", z, thread_status_strdesc(tmp));
                th_status_err++;
            }
        }

        if (th_status_err != 0) {
            printf("! Warning: %zu thread(s) found in wrong initial state ...\n", th_status_err);
        } else {
            printf("# %zu thread(s) ready\n", thread_count);
        }
    }
#endif // DEBUGME >= 1

    bool found = false;
    bool error = false;
    bool show_overall_time = true;

    struct timeval cpu_t_start, cpu_t_end, cpu_t_result;

    fprintf(stderr, "Attack 5 - opencl - start (Max Slices %u, %s order", max_step, wu_queue_strdesc(ctx.queue_ctx.queue_type));

    if (!verbose) fprintf(stderr, ")\n\n");
    else fprintf(stderr, ", Profile %d, Async Threads %s, HiTag2 key verify on device %s)\n\n", profile, (ctx.thread_sched_type == THREAD_TYPE_ASYNC) ? "yes" : "no", (force_hitag2_opencl) ? "yes" : "no");

    if (gettimeofday(&cpu_t_start, NULL) == -1) {
        printf("! gettimeofday(start) failed (%d): %s\n", errno, strerror(errno));
        show_overall_time = false;
    }

    if (ctx.thread_sched_type == THREAD_TYPE_ASYNC) {
        // crack hitag key or die tryin'
        unsigned int th_cnt;

        bool done = false;

        do { // master
            th_cnt = 0;

            for (z = 0; z < thread_count; z++) {
#if TDEBUG >= 1 && DEBUGME == 1
                if (thread_count == 1) { printf("[%zu] get status from slave ...\n", z); fflush(stdout); }
#endif

                pthread_mutex_lock(&th_ctx.thread_mutexs[z]);
                thread_status_t cur_status = t_arg[z].status;
                pthread_mutex_unlock(&th_ctx.thread_mutexs[z]);

#if TDEBUG >= 1 && DEBUGME == 1
                if (thread_count == 1) { printf("[%zu] slave status: %s\n", z, thread_status_strdesc(cur_status)); fflush(stdout); }
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
                        pthread_mutex_lock(&th_ctx.thread_mutexs[z]);
                        t_arg[z].status = TH_END;
                        t_arg[z].quit = true;
                        if (cur_status == TH_WAIT) pthread_cond_signal(&th_ctx.thread_conds[z]);
                        pthread_mutex_unlock(&th_ctx.thread_mutexs[z]);
                    } else {
                        if (thread_count == 1) {
                            th_cnt++;
#if TDEBUG >= 1
                            printf("[%zu] Increment th_cnt: %u/%zu\n", z, th_cnt, thread_count);
                            fflush(stdout);
#endif
                        }
                    }
                    continue;
                }

                if (cur_status == TH_WAIT) {
                    pthread_mutex_lock(&th_ctx.thread_mutexs[z]);

                    if (found) {
#if TDEBUG >= 1
                        printf("[%zu] key is found in another thread 1\n", z);
                        fflush(stdout);
#endif
                        t_arg[z].status = TH_END;
                        t_arg[z].quit = true;
                        pthread_mutex_unlock(&th_ctx.thread_mutexs[z]);
                        continue;
                    }

                    if (wu_queue_done(&ctx.queue_ctx) != QUEUE_EMPTY) {
                        t_arg[z].status = TH_PROCESSING;

#if TDEBUG >= 1
                        printf("[master] slave [%zu], I give you another try (%s)\n", z, thread_status_strdesc(t_arg[z].status));
                        fflush(stdout);
#endif

                        pthread_cond_signal(&th_ctx.thread_conds[z]);
                        pthread_mutex_unlock(&th_ctx.thread_mutexs[z]);
                        continue;
                    } else {
#if TDEBUG >= 1
                        printf("[master] slave [%zu], max step reached. Quit.\n", z);
                        fflush(stdout);
#endif

                        cur_status = t_arg[z].status = TH_END;
                        t_arg[z].quit = true;

                        pthread_cond_signal(&th_ctx.thread_conds[z]);
                        pthread_mutex_unlock(&th_ctx.thread_mutexs[z]);
                    }
                }

                if (cur_status == TH_PROCESSING) {
                    if (th_ctx.enable_condusleep) {
#if TDEBUG >= 1
                        printf("[master] before pthread_cond_wait, TH_PROCESSING\n");
#endif
                        pthread_mutex_lock(&th_ctx.thread_mutex_usleep);
#if TDEBUG >= 1
                        printf("[master] slave [%zu], I'm waiting you end of task, I'm in %s give me a signal.\n", z, thread_status_strdesc(t_arg[z].status));
                        fflush(stdout);
#endif
                        pthread_cond_wait(&th_ctx.thread_cond_usleep, &th_ctx.thread_mutex_usleep);
#if TDEBUG >= 1
                        printf("[master] slave [%zu], got the signal with new state: %s.\n", z, thread_status_strdesc(t_arg[z].status));
                        fflush(stdout);
#endif

                        if (t_arg[z].status == TH_FOUND_KEY) found = true;

                        pthread_mutex_unlock(&th_ctx.thread_mutex_usleep);
#if TDEBUG >= 1
                        printf("[master] after pthread_cond_wait, TH_PROCESSING\n");
#endif
                        continue;
                    }

                    if (found) {
#if TDEBUG >= 1
                        printf("[master] slave [%zu], the key is found. set TH_END from TH_PROCESSING\n", z);
                        fflush(stdout);
#endif

                        pthread_mutex_lock(&th_ctx.thread_mutexs[z]);
                        t_arg[z].status = TH_END;
                        t_arg[z].quit = true;
                        pthread_mutex_unlock(&th_ctx.thread_mutexs[z]);
                        continue;
                    }
                }

                if (cur_status == TH_ERROR) {
                    // something went wrong
                    pthread_mutex_lock(&th_ctx.thread_mutexs[z]);
                    t_arg[z].status = TH_END;
                    t_arg[z].quit = true;
                    pthread_mutex_unlock(&th_ctx.thread_mutexs[z]);
                    continue;
                }

                // todo, do more clean exit logic
                if (cur_status >= TH_FOUND_KEY) {
                    th_cnt++;

                    if (cur_status == TH_FOUND_KEY) {
                        thread_setEnd(&th_ctx, t_arg);
                        found = true;
                        done = true;
                    }
                }
            }

            if (th_cnt == thread_count) done = true;

        } while (!done);

        // end of async engine
    } else if (ctx.thread_sched_type == THREAD_TYPE_SEQ) {
        uint32_t step = 0;
        bool quit = false;

        for (step = 0; step < max_step; step += thread_count) {
            for (z = 0; z < thread_count; z++) {
                t_arg[z].r = found;
                t_arg[z].matches = matches[z];
                t_arg[z].matches_found = matches_found[z];
            }

            if ((ret = thread_start(&th_ctx, t_arg)) != 0) {
                printf("Error: thread_start() failed (%d): %s\n", ret, thread_strerror(ret));
                thread_destroy(&th_ctx);
                MEMORY_FREE_OPENCL(ctx, z)
                MEMORY_FREE_LIST_Z(matches, z)
                MEMORY_FREE_LIST_Z(matches_found, z)
                MEMORY_FREE_ALL
                exit(3);
            }

            // waiting threads return
            thread_stop(&th_ctx);

            for (z = 0; z < th_ctx.thread_count; z++) {
                if (t_arg[z].r) found = true;

                if (t_arg[z].err) {
                    error = true;
                    quit = true;
                }
            }

            if (found || quit) break;
        }
    }

    // if found, show the key here
    for (size_t y = 0; y < thread_count; y++) {
        if (t_arg[y].r) {
            if (verbose) printf("\n");

            if (thread_count > 1) printf("[%zu] ", y);

            printf("Key found @ slice %lu/%lu: ", t_arg[y].slice, t_arg[y].max_step);
            for (int i = 0; i < 6; i++) {
                printf("%02X", (uint8_t)(t_arg[y].key & 0xff));
                t_arg[y].key = t_arg[y].key >> 8;
            }
            printf("\n");
            fflush(stdout);
            break;
        }
    }

    if (show_overall_time) {
        if (gettimeofday(&cpu_t_end, NULL) == 0) {
            timersub(&cpu_t_end, &cpu_t_start, &cpu_t_result);
        } else {
            printf("! gettimeofday(end) failed (%d): %s\n", errno, strerror(errno));
            show_overall_time = false;
        }
    }

    if (!found) {
        printf("\nError. %s\n", (error) ? "something went wrong :(" : "Key not found :|");
        if (error) exit(-1);
    }

    printf("\nAttack 5 - opencl - end");

    if (show_overall_time) printf(" in %ld.%06ld second(s).\n\n", (long int)cpu_t_result.tv_sec, (long int)cpu_t_result.tv_usec);
    else printf("\n");

    fflush(stdout);

#if DEBUGME > 1
    printf("stop threads\n");
    fflush(stdout);
#endif

    thread_stop(&th_ctx);

#if DEBUGME > 1
    printf("destroy threads\n");
    fflush(stdout);
#endif

    if ((ret = thread_destroy(&th_ctx)) != 0) {
#if DEBUGME > 0
        printf("Warning: thread_destroy() failed (%d): %s\n", ret, thread_strerror(ret));
#endif
    }

#if DEBUGME > 1
    printf("wu_queue_destroy\n");
    fflush(stdout);
#endif

    if ((ret = wu_queue_destroy(&ctx.queue_ctx)) != 0) {
#if DEBUGME > 0
        printf("Warning: wu_queue_destroy() failed (%d): %s\n", ret, wu_queue_strerror(ret));
#endif
    }

    z = selected_devices_cnt - 1;
    MEMORY_FREE_OPENCL(ctx, z)
    MEMORY_FREE_LIST_Z(matches, z)
    MEMORY_FREE_LIST_Z(matches_found, z)
    MEMORY_FREE_ALL

    return (found) ? 0 : 1;
}
