/*
 * desbrute.h — Shared types and GPU launch interface.
 * No external dependencies beyond CUDA runtime.
 */
#pragma once
#include <stdint.h>

#define BLOCK_SIZE  8
#define KEY_SIZE   16

#define LFSR_UNDEF  0
#define LFSR_ULCG   1
#define LFSR_MFC    2

/* Metrics returned by desbrute_launch */
typedef struct {
    int      found;              /* 1 if a key was found                    */
    uint32_t idx;                /* winning candidate index (if found)      */
    double   wall_ms;            /* wall-clock time in milliseconds         */
    float    gpu_ms;             /* GPU kernel time (CUDA events)           */
    uint64_t candidates_tested;  /* total candidates processed before exit  */
    double   keys_per_sec;       /* throughput: candidates / gpu_sec        */
} desbrute_result_t;

/*
 * desbrute_launch — brute-force 2^28 candidate key indices on the GPU.
 *
 * All uint64_t block values are big-endian packed (byte 0 in bits 63-56).
 * The caller must have already called cudaSetDevice() if needed.
 */
void desbrute_launch(
    uint64_t  ciphertext_be,
    uint64_t  init_ciphertext_be,
    uint64_t  prev_ciphertext_be,
    const uint8_t base_key[KEY_SIZE],
    int       key_mode,
    int       lfsr_type,
    int       is_reader_mode,
    desbrute_result_t *result
);
