/*
 * main.cu - CUDA-accelerated 2TDEA key recovery.
 * Written by C2Pwn
 *
 * Usage
 * -----
 *   Counterfeit mode (-c):
 *     desbrute -c <ERndB_null_16hex> <ERndB_target_16hex> <key_32hex> <seg 1-4> [device]
 *
 *   Reader nonce mode (-r):
 *     desbrute -r <ERndB_16hex> <ERndARndBprime_32hex> <key_32hex> <seg 1-4> [device]
 *
 *   [device] is optional. When omitted the best available GPU is chosen
 *   automatically (highest SM count). Pass an integer to force a specific
 *   CUDA device index.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <cuda_runtime.h>

#include "des_host.h"
#include "desbrute.h"

/* ========================================================================== */
/* Helpers                                                                     */
/* ========================================================================== */

static int hex_to_bytes(const char *hex, uint8_t *buf, size_t len)
{
    size_t i;
    if (strlen(hex) != len * 2) return 0;
    for (i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) return 0;
        buf[i] = (uint8_t)byte;
    }
    return 1;
}

static void print_hex(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) printf("%02X", buf[i]);
}

static void print_separator(void)
{
    printf("---------------------------------------------------------------\n");
}

static void print_usage(const char *name)
{
    fprintf(stderr,
        "\nUsage:\n"
        "  Counterfeit:  %s -c <ERndB_null_16hex> <ERndB_target_16hex>"
        " <key_32hex> <seg 1-4> [device]\n"
        "  Reader nonce: %s -r <ERndB_16hex> <ERndARndBprime_32hex>"
        " <key_32hex> <seg 1-4> [device]\n"
        "\n"
        "  seg    : 1-4  (which 4-byte block of the 16-byte key to brute-force)\n"
        "  device : optional CUDA device index (default: auto-select best GPU)\n"
        "\n",
        name, name);
    exit(1);
}

/* ========================================================================== */
/* Auto device selection                                                       */
/* ========================================================================== */

/*
 * Pick the CUDA device with the most streaming multiprocessors.
 * On a single-GPU system this always returns 0.
 * On multi-GPU systems it chooses the most powerful card.
 * Prints a one-line summary of all available devices.
 */
static int pick_best_device(void)
{
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess || count == 0) {
        fprintf(stderr, "[cuda] No CUDA devices found.\n");
        exit(1);
    }

    int best_dev = 0, best_mp = 0;
    int d;
    for (d = 0; d < count; d++) {
        struct cudaDeviceProp p;
        if (cudaGetDeviceProperties(&p, d) != cudaSuccess) continue;
        printf("  [dev %d] %s  SM %d.%d  %d MPs\n",
               d, p.name, p.major, p.minor, p.multiProcessorCount);
        if (p.multiProcessorCount > best_mp) {
            best_mp  = p.multiProcessorCount;
            best_dev = d;
        }
    }
    return best_dev;
}

/* ========================================================================== */
/* GPU info banner                                                             */
/* ========================================================================== */

static void print_gpu_info(int dev)
{
    struct cudaDeviceProp p;
    if (cudaGetDeviceProperties(&p, dev) != cudaSuccess) return;

    double bw_gbps = 2.0 * p.memoryClockRate * 1e3
                     * p.memoryBusWidth / 8.0 / 1e9;

    /* Approximate CUDA core count — varies by architecture */
    int cores_per_mp =
        (p.major == 9)                         ? 128 :
        (p.major == 8 && p.minor == 9)         ? 128 :
        (p.major == 8 && p.minor == 6)         ? 128 :
        (p.major == 8 && p.minor == 0)         ? 64  :
        (p.major == 7 && p.minor == 5)         ? 64  :
        (p.major == 7)                         ? 64  :
        (p.major == 6 && p.minor == 1)         ? 128 :
        (p.major == 6 && p.minor == 0)         ? 64  :
        (p.major == 5)                         ? 128 : 64;

    print_separator();
    printf("  GPU  : %s  [device %d]\n", p.name, dev);
    printf("  SM   : %d.%d  |  MPs: %d  |  CUDA cores: ~%d\n",
           p.major, p.minor, p.multiProcessorCount,
           p.multiProcessorCount * cores_per_mp);
    printf("  Clock: %d MHz (mem: %d MHz, bus: %d-bit)\n",
           p.clockRate / 1000, p.memoryClockRate / 1000, p.memoryBusWidth);
    printf("  VRAM : %.0f MB  |  Peak BW: %.0f GB/s\n",
           (double)p.totalGlobalMem / (1024.0 * 1024.0), bw_gbps);
    printf("  L2   : %d KB  |  Warp size: %d\n",
           p.l2CacheSize / 1024, p.warpSize);
    print_separator();
}

/* ========================================================================== */
/* main                                                                        */
/* ========================================================================== */

int main(int argc, char **argv)
{
    int is_reader_mode, seg, key_mode, cuda_dev, lfsr_type;
    uint8_t init_ciphertext[BLOCK_SIZE];
    uint8_t tmp_blocks[2 * BLOCK_SIZE];
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t prev_ciphertext[BLOCK_SIZE];
    uint8_t base_key[KEY_SIZE];
    desbrute_result_t result;

    /* --- Argument parsing ------------------------------------------------- */
    if (argc < 2) print_usage(argv[0]);

    if (strcmp(argv[1], "-c") == 0) {
        is_reader_mode = 0;
        if (argc < 6 || argc > 7) {
            fprintf(stderr, "Error: -c requires exactly 4 arguments"
                            " plus an optional device index.\n");
            print_usage(argv[0]);
        }
    } else if (strcmp(argv[1], "-r") == 0) {
        is_reader_mode = 1;
        if (argc < 6 || argc > 7) {
            fprintf(stderr, "Error: -r requires exactly 4 arguments"
                            " plus an optional device index.\n");
            print_usage(argv[0]);
        }
    } else {
        fprintf(stderr, "Error: first argument must be -c or -r\n");
        print_usage(argv[0]);
    }

    /* --- Parse fixed positional args ------------------------------------- */
    if (is_reader_mode) {
        if (!hex_to_bytes(argv[2], init_ciphertext, BLOCK_SIZE)) {
            fprintf(stderr, "Error: ERndB must be exactly 16 hex chars (8 bytes)\n");
            return 1;
        }
        if (!hex_to_bytes(argv[3], tmp_blocks, 2 * BLOCK_SIZE)) {
            fprintf(stderr, "Error: ERndA||RndB' must be exactly 32 hex chars (16 bytes)\n");
            return 1;
        }
        memcpy(prev_ciphertext, tmp_blocks,              BLOCK_SIZE);
        memcpy(ciphertext,      tmp_blocks + BLOCK_SIZE, BLOCK_SIZE);
    } else {
        if (!hex_to_bytes(argv[2], init_ciphertext, BLOCK_SIZE)) {
            fprintf(stderr, "Error: null-key ERndB must be exactly 16 hex chars (8 bytes)\n");
            return 1;
        }
        if (!hex_to_bytes(argv[3], ciphertext, BLOCK_SIZE)) {
            fprintf(stderr, "Error: target ERndB must be exactly 16 hex chars (8 bytes)\n");
            return 1;
        }
        memset(prev_ciphertext, 0, BLOCK_SIZE);
    }

    if (!hex_to_bytes(argv[4], base_key, KEY_SIZE)) {
        fprintf(stderr, "Error: base key must be exactly 32 hex chars (16 bytes)\n");
        return 1;
    }

    seg = atoi(argv[5]);
    if (seg < 1 || seg > 4) {
        fprintf(stderr, "Error: segment must be 1, 2, 3, or 4\n");
        return 1;
    }
    key_mode = seg - 1;

    /* --- CUDA device selection -------------------------------------------- */
    print_separator();
    printf("  DESBRUTE - CUDA 2TDEA key recovery engine\n");
    print_separator();

    if (argc == 7) {
        /* Explicit device requested */
        cuda_dev = atoi(argv[6]);
        int count = 0;
        cudaGetDeviceCount(&count);
        if (cuda_dev < 0 || cuda_dev >= count) {
            fprintf(stderr,
                "[cuda] Device %d does not exist (%d device(s) available).\n"
                "       Re-run without the [device] argument to auto-select.\n",
                cuda_dev, count);
            return 1;
        }
        printf("  Device: %d (user-specified)\n", cuda_dev);
    } else {
        /* Auto-select best device */
        printf("  Auto-selecting best CUDA device...\n");
        cuda_dev = pick_best_device();
        printf("  Selected: device %d\n", cuda_dev);
    }

    if (cudaSetDevice(cuda_dev) != cudaSuccess) {
        fprintf(stderr, "[cuda] Failed to set device %d\n", cuda_dev);
        return 1;
    }

    /* --- LFSR detection (counterfeit mode only, CPU) ---------------------- */
    lfsr_type = LFSR_UNDEF;
    if (!is_reader_mode) {
        lfsr_type = h_detect_lfsr(init_ciphertext);
        switch (lfsr_type) {
        case LFSR_ULCG:
            printf("[lfsr] Detected: ULCG\n"); break;
        case LFSR_MFC:
            printf("[lfsr] Detected: MFC (USCUID-UL / FJ8010)\n"); break;
        default:
            fprintf(stderr, "[lfsr] ERROR: unrecognised LFSR - cannot proceed\n");
            return 1;
        }
    }

    /* --- Banner ----------------------------------------------------------- */
    print_gpu_info(cuda_dev);
    printf("  Mode        : %s\n", is_reader_mode ? "Reader nonce (-r)" : "Counterfeit (-c)");
    printf("  Segment     : %d  (key_mode %d, bytes %d-%d of full key)\n",
           seg, key_mode, key_mode * 4, key_mode * 4 + 3);
    printf("  Base key    : ");  print_hex(base_key, KEY_SIZE);          printf("\n");
    printf("  Ciphertext  : ");  print_hex(ciphertext, BLOCK_SIZE);      printf("\n");
    printf("  Init CT     : ");  print_hex(init_ciphertext, BLOCK_SIZE); printf("\n");
    if (is_reader_mode) {
        printf("  Prev CT     : ");  print_hex(prev_ciphertext, BLOCK_SIZE); printf("\n");
    }
    print_separator();
    fflush(stdout);

    /* --- Launch GPU search ------------------------------------------------ */
    uint64_t ct_be   = bytes_to_u64(ciphertext);
    uint64_t init_be = bytes_to_u64(init_ciphertext);
    uint64_t prev_be = bytes_to_u64(prev_ciphertext);

    desbrute_launch(ct_be, init_be, prev_be,
                    base_key, key_mode, lfsr_type, is_reader_mode,
                    &result);

    /* --- Metrics ---------------------------------------------------------- */
    print_separator();
    printf("  PERFORMANCE METRICS\n");
    print_separator();
    printf("  GPU kernel time : %.3f ms\n",   result.gpu_ms);
    printf("  Wall-clock time : %.3f ms\n",   result.wall_ms);
    printf("  Candidates      : %llu / %llu\n",
           (unsigned long long)result.candidates_tested,
           (unsigned long long)(1ULL << 28));
    printf("  Throughput      : %.2f M keys/s\n", result.keys_per_sec / 1e6);
    {
        double overhead_pct = (result.wall_ms > 0)
                              ? 100.0 * (result.wall_ms - result.gpu_ms) / result.wall_ms
                              : 0.0;
        printf("  Host overhead   : %.1f%%\n", overhead_pct);
    }
    print_separator();

    /* --- Result ----------------------------------------------------------- */
    if (!result.found) {
        printf("  RESULT: No matching key found.\n");
        print_separator();
        return 1;
    }

    /* Reconstruct full key from winning index */
    uint8_t b0 = (uint8_t)(( result.idx        & 0x7Fu) << 1);
    uint8_t b1 = (uint8_t)(((result.idx >>  7) & 0x7Fu) << 1);
    uint8_t b2 = (uint8_t)(((result.idx >> 14) & 0x7Fu) << 1);
    uint8_t b3 = (uint8_t)(((result.idx >> 21) & 0x7Fu) << 1);

    uint8_t full_key[KEY_SIZE];
    memcpy(full_key, base_key, KEY_SIZE);
    {
        int seg_offset = key_mode * 4;
        full_key[seg_offset]     = b0;
        full_key[seg_offset + 1] = b1;
        full_key[seg_offset + 2] = b2;
        full_key[seg_offset + 3] = b3;
    }

    printf("  RESULT: KEY FOUND\n");
    printf("  Index   : %u (0x%08X)\n", result.idx, result.idx);
    printf("  Full key: "); print_hex(full_key, KEY_SIZE); printf("\n");
    print_separator();

    cudaDeviceReset();
    return 0;
}
