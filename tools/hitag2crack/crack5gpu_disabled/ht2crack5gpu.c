/* ht2crack5.c
 *
 * This code is heavily based on the HiTag2 Hell CPU implementation
 *  from https://github.com/factoritbv/hitag2hell by FactorIT B.V.,
 *  with the following changes:
 *  * Main takes a UID and 2 {nR},{aR} pairs as arguments
 *    and searches for states producing the first aR sample,
 *    reconstructs the corresponding key candidates
 *    and tests them against the second nR,aR pair;
 *  * Reduce max_bitslices and some type sizes to fit OpenCL
 *  * Reuses the Hitag helping functions of the other attacks.
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
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#define CL_TARGET_OPENCL_VERSION 220
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#include <CL/cl.h>
#endif
#include "ht2crackutils.h"

const uint8_t bits[9] = {20, 14, 4, 3, 1, 1, 1, 1, 1};
#define lfsr_inv(state) (((state)<<1) | (__builtin_parityll((state) & ((0xce0044c101cd>>1)|(1ull<<(47))))))
#define i4(x,a,b,c,d) ((uint32_t)((((x)>>(a))&1)<<3)|(((x)>>(b))&1)<<2|(((x)>>(c))&1)<<1|(((x)>>(d))&1))
#define f(state) ((0xdd3929b >> ( (((0x3c65 >> i4(state, 2, 3, 5, 6) ) & 1) <<4) \
                                | ((( 0xee5 >> i4(state, 8,12,14,15) ) & 1) <<3) \
                                | ((( 0xee5 >> i4(state,17,21,23,26) ) & 1) <<2) \
                                | ((( 0xee5 >> i4(state,28,29,31,33) ) & 1) <<1) \
                                | (((0x3c65 >> i4(state,34,43,44,46) ) & 1) ))) & 1)

#define MAX_BITSLICES 32
#define VECTOR_SIZE (MAX_BITSLICES/8)
#define KERNELFILENAME "ht2crack5kernel.cl"

typedef unsigned int __attribute__((aligned(VECTOR_SIZE))) __attribute__((vector_size(VECTOR_SIZE))) bitslice_value_t;
typedef union {
    bitslice_value_t value;
    uint8_t bytes[MAX_BITSLICES / 8];
} bitslice_t;

// we never actually set or use the lowest 2 bits the initial state, so we can save 2 bitslices everywhere
__thread bitslice_t state[-2 + 32 + 48];

bitslice_t keystream[32];
bitslice_t bs_zeroes, bs_ones;

#define f_a_bs(a,b,c,d)       (~(((a|b)&c)^(a|d)^b)) // 6 ops
#define f_b_bs(a,b,c,d)       (~(((d|c)&(a^b))^(d|a|b))) // 7 ops
#define f_c_bs(a,b,c,d,e)     (~((((((c^e)|d)&a)^b)&(c^b))^(((d^e)|a)&((d^b)|c)))) // 13 ops
#define lfsr_bs(i) (state[-2+i+ 0].value ^ state[-2+i+ 2].value ^ state[-2+i+ 3].value ^ state[-2+i+ 6].value ^ \
                    state[-2+i+ 7].value ^ state[-2+i+ 8].value ^ state[-2+i+16].value ^ state[-2+i+22].value ^ \
                    state[-2+i+23].value ^ state[-2+i+26].value ^ state[-2+i+30].value ^ state[-2+i+41].value ^ \
                    state[-2+i+42].value ^ state[-2+i+43].value ^ state[-2+i+46].value ^ state[-2+i+47].value);
#define get_bit(n, word) ((word >> (n)) & 1)

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

static void bitslice(const uint64_t value, bitslice_t *restrict bitsliced_value, const size_t bit_len, bool reverse) {
    size_t bit_idx;
    for (bit_idx = 0; bit_idx < bit_len; bit_idx++) {
        bool bit;
        if (reverse) {
            bit = get_bit(bit_len - 1 - bit_idx, value);
        } else {
            bit = get_bit(bit_idx, value);
        }
        if (bit) {
            bitsliced_value[bit_idx].value = bs_ones.value;
        } else {
            bitsliced_value[bit_idx].value = bs_zeroes.value;
        }
    }
}

uint32_t uid, nR1, aR1, nR2, aR2;

// Reduce type size of candidates array to fit OpenCL
uint16_t candidates[(1 << 20) * 3];
bitslice_t initial_bitslices[48];
size_t filter_pos[20] = {4, 7, 9, 13, 16, 18, 22, 24, 27, 30, 32, 35, 45, 47  };
size_t thread_count = 8;
size_t layer_0_found;

static void try_state(uint64_t s);

struct context {
    char *kernelSource;                 // source for kernel

    cl_platform_id platform_id;         // compute platform id
    cl_device_id device_id;             // compute device id
    cl_context context;                 // compute context
    cl_command_queue commands;          // compute command queue
    cl_program program;                 // compute program
    cl_kernel kernel;                   // compute kernel

//    cl_mem cand_base;                   // device memory used for the candidate base
    cl_mem keystream;                   // device memory used for the keystream array
    cl_mem candidates;                  // device memory used for the candidates array
    cl_mem matches;                     // device memory used for the matches array
    cl_mem matches_found;               // device memory used for the matches_found array
};


static void runKernel(struct context *ctx, uint32_t cand_base, uint64_t *matches, uint32_t *matches_found) {
    int err;
    size_t global[2];

    // Write our data set into the input array in device memory
    err = clEnqueueWriteBuffer(ctx->commands, ctx->matches_found, CL_TRUE, 0, sizeof(uint32_t), matches_found, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        printf("Error: Failed to enque kernel writebuffer in runKernel! %d\n", err);
        exit(1);
    }

    // Set the arguments to our compute kernel
    err  = clSetKernelArg(ctx->kernel, 0, sizeof(uint32_t), &cand_base);
    err |= clSetKernelArg(ctx->kernel, 4, sizeof(cl_mem), &ctx->matches_found);
    if (err != CL_SUCCESS) {
        printf("Error: Failed to set kernel arguments in runKernel! %d\n", err);
        exit(1);
    }

    // Execute the kernel over the entire range of our 2d input data set using 8K * 1K threads
    global[0] = 8192;
    global[1] = 1024;
    err = clEnqueueNDRangeKernel(ctx->commands, ctx->kernel, 2, NULL, global, NULL, 0, NULL, NULL);
    if (err) {
        printf("Error: Failed to execute kernel!\n");
        exit(1);
    }

    // Wait for the command commands to get serviced before reading back results
    err = clFinish(ctx->commands);
    if (err) {
        printf("Error: Failed to execute kernel! clFinish = %d\n", err);
        exit(1);
    }

    // Read back the results from the device to verify the output
    err = clEnqueueReadBuffer(ctx->commands, ctx->matches, CL_TRUE, 0, sizeof(uint64_t) * 8192, matches, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        printf("Error: Failed to read matches array! %d\n", err);
        exit(1);
    }

    err = clEnqueueReadBuffer(ctx->commands, ctx->matches_found, CL_TRUE, 0, sizeof(uint32_t), matches_found, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        printf("Error: Failed to read matches_found! %d\n", err);
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    memset(candidates, 0, sizeof(candidates));
    struct context ctx;
    uint64_t matches[8192];
    uint32_t matches_found[1];

    // set constants
    memset(bs_ones.bytes, 0xff, VECTOR_SIZE);
    memset(bs_zeroes.bytes, 0x00, VECTOR_SIZE);

    uint32_t target = 0;

    if (argc < 6) {
        printf("%s UID {nR1} {aR1} {nR2} {aR2}\n", argv[0]);
        exit(1);
    }

    if (!strncmp(argv[1], "0x", 2) || !strncmp(argv[1], "0X", 2)) {
        uid = rev32(hexreversetoulong(argv[1] + 2));
    } else {
        uid = rev32(hexreversetoulong(argv[1]));
    }

    if (!strncmp(argv[2], "0x", 2) || !strncmp(argv[2], "0X", 2)) {
        nR1 = rev32(hexreversetoulong(argv[2] + 2));
    } else {
        nR1 = rev32(hexreversetoulong(argv[2]));
    }

    aR1 = strtol(argv[3], NULL, 16);

    if (!strncmp(argv[4], "0x", 2) || !strncmp(argv[4], "0X", 2)) {
        nR2 = rev32(hexreversetoulong(argv[4] + 2));
    } else {
        nR2 = rev32(hexreversetoulong(argv[4]));
    }

    aR2 = strtol(argv[5], NULL, 16);

    target = ~aR1;
    // bitslice inverse target bits
    bitslice(~target, keystream, 32, true);

    // bitslice all possible 256 values in the lowest 8 bits
    memset(initial_bitslices[0].bytes, 0xaa, VECTOR_SIZE);
    memset(initial_bitslices[1].bytes, 0xcc, VECTOR_SIZE);
    memset(initial_bitslices[2].bytes, 0xf0, VECTOR_SIZE);
    size_t interval = 1;
    for (size_t bit = 3; bit < 8; bit++) {
        for (size_t byte = 0; byte < VECTOR_SIZE;) {
            for (size_t length = 0; length < interval; length++) {
                initial_bitslices[bit].bytes[byte++] = 0x00;
            }
            for (size_t length = 0; length < interval; length++) {
                initial_bitslices[bit].bytes[byte++] = 0xff;
            }
        }
        interval <<= 1;
    }

    // compute layer 0 output
    for (size_t i0 = 0; i0 < 1 << 20; i0++) {
        uint64_t state0 = expand(0x5806b4a2d16c, i0);

        if (f(state0) == target >> 31) {
            // cf kernel, state is now split in 3 shorts >> 2
            candidates[(layer_0_found * 3) + 0] = (uint16_t)((state0 >> (32 + 2)) & 0xffff);
            candidates[(layer_0_found * 3) + 1] = (uint16_t)((state0 >> (16 + 2)) & 0xffff);
            candidates[(layer_0_found * 3) + 2] = (uint16_t)((state0 >> (0 + 2)) & 0xffff);
            layer_0_found++;
        }
    }

    // load OpenCL kernel source
    ////////////////////////////
    struct stat filestat;
    int fd;

    fd = open(KERNELFILENAME, O_RDONLY);
    if (fd <= 0) {
        printf("Cannot open %s\n", KERNELFILENAME);
        exit(1);
    }

    if (fstat(fd, &filestat)) {
        printf("Cannot stat %s\n", KERNELFILENAME);
        exit(1);
    }

    ctx.kernelSource = (char *)calloc(1, filestat.st_size);
    if (!ctx.kernelSource) {
        printf("Cannot calloc kernelSource\n");
        exit(1);
    }

    if (read(fd, ctx.kernelSource, filestat.st_size) < filestat.st_size) {
        printf("Cannot read %s\n", KERNELFILENAME);
        exit(1);
    }

    close(fd);

    // discover and set up compute device
    /////////////////////////////////////
    int err;

    // Connect to a compute device
    err = clGetPlatformIDs(1, &(ctx.platform_id), NULL);
    if (err != CL_SUCCESS) {
        printf("Error: Failed to get platform id: %d\n", err);
        exit(1);
    }

    err = clGetDeviceIDs(ctx.platform_id, CL_DEVICE_TYPE_GPU, 1, &(ctx.device_id), NULL);
    if (err != CL_SUCCESS) {
        printf("Error: Failed to create a device group!: %d\n", err);
        exit(1);
    }

    // Create a compute context
    ctx.context = clCreateContext(0, 1, &(ctx.device_id), NULL, NULL, &err);
    if (!ctx.context) {
        printf("Error: Failed to create a compute context!\n");
        exit(1);
    }

    // Create a command commands
    ctx.commands = clCreateCommandQueue(ctx.context, ctx.device_id, 0, &err);
    if (!ctx.commands) {
        printf("Error: Failed to create a command commands!\n");
        exit(1);
    }

    // Create the compute program from the source buffer
    ctx.program = clCreateProgramWithSource(ctx.context, 1, (const char **) & (ctx.kernelSource), NULL, &err);
    if (!ctx.program) {
        printf("Error: Failed to create compute program!\n");
        exit(1);
    }

    // Build the program executable
    err = clBuildProgram(ctx.program, 0, NULL, "-Werror", NULL, NULL);

    if (err != CL_SUCCESS) {
        size_t len;
        char buffer[1024 * 1024];

        printf("Error: Failed to build program executable!\n");
        err = clGetProgramBuildInfo(ctx.program, ctx.device_id, CL_PROGRAM_BUILD_LOG, sizeof(buffer), buffer, &len);
        if (err != CL_SUCCESS) {
            printf("clGetProgramBuildInfo failed: %d\n", err);
            exit(1);
        } else {
            printf("%s\n", buffer);
            exit(1);
        }
    }

    // Create the compute kernel in the program we wish to run
    ctx.kernel = clCreateKernel(ctx.program, "find_state", &err);
    if (!ctx.kernel || err != CL_SUCCESS) {
        printf("Error: Failed to create compute kernel!\n");
        exit(1);
    }

    ctx.candidates = clCreateBuffer(ctx.context,  CL_MEM_READ_ONLY,  sizeof(uint16_t) * ((1 << 20) * 3), NULL, NULL);
    ctx.keystream = clCreateBuffer(ctx.context,  CL_MEM_READ_ONLY,  VECTOR_SIZE * 32, NULL, NULL);

    ctx.matches = clCreateBuffer(ctx.context, CL_MEM_WRITE_ONLY, sizeof(uint64_t) * 8192, NULL, NULL);
    ctx.matches_found = clCreateBuffer(ctx.context, CL_MEM_READ_WRITE, sizeof(uint32_t), NULL, NULL);

    if (!ctx.candidates || !ctx.keystream || !ctx.matches || !ctx.matches_found) {
        printf("Error: Failed to allocate device memory!\n");
        exit(1);
    }

    // set up constant vars
    ///////////////////////

    // Write our data set into the input array in device memory
    err = clEnqueueWriteBuffer(ctx.commands, ctx.keystream, CL_TRUE, 0, VECTOR_SIZE * 32, keystream, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        printf("Error: Failed to write to keystream array!\n");
        exit(1);
    }

    err = clEnqueueWriteBuffer(ctx.commands, ctx.candidates, CL_TRUE, 0, sizeof(uint16_t) * ((1 << 20) * 3), candidates, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        printf("Error: Failed to write to candidates array!\n");
        exit(1);
    }

    // Set the arguments to our compute kernel
    err  = clSetKernelArg(ctx.kernel, 1, sizeof(cl_mem), &ctx.candidates);
    err |= clSetKernelArg(ctx.kernel, 2, sizeof(cl_mem), &ctx.keystream);
    err |= clSetKernelArg(ctx.kernel, 3, sizeof(cl_mem), &ctx.matches);
    if (err != CL_SUCCESS) {
        printf("Error: Failed to set kernel arguments! %d\n", err);
        exit(1);
    }

    // run kernel
    /////////////
    for (uint32_t step = 0; step < 64; step++) {
        printf("slice %3u/64: ", step + 1);
        fflush(stdout);
        matches_found[0] = 0;
        runKernel(&ctx, step << 13, matches, matches_found);

        printf("%5u candidates\n", matches_found[0]);
        for (uint32_t match = 0; match < matches_found[0]; match++) {
            try_state(matches[match]);
        }
    }

    printf("Key not found\n");
    exit(1);
}

static void try_state(uint64_t s) {
    Hitag_State hstate;
    uint64_t keyrev, nR1xk;
    uint32_t b = 0;

    hstate.shiftreg = s;
    rollback(&hstate, 2);

    // recover key
    keyrev = hstate.shiftreg & 0xffff;
    nR1xk = (hstate.shiftreg >> 16) & 0xffffffff;
    for (int i = 0; i < 32; i++) {
        hstate.shiftreg = ((hstate.shiftreg) << 1) | ((uid >> (31 - i)) & 0x1);
        b = (b << 1) | fnf(hstate.shiftreg);
    }
    keyrev |= (nR1xk ^ nR1 ^ b) << 16;

    // test key
    hitag2_init(&hstate, keyrev, uid, nR2);
    if ((aR2 ^ hitag2_nstep(&hstate, 32)) == 0xffffffff) {

        uint64_t key = rev64(keyrev);

        printf("Key: ");
        for (int i = 0; i < 6; i++) {
            printf("%02X", (uint8_t)(key & 0xff));
            key = key >> 8;
        }
        printf("\n");
        exit(0);
    }
}
