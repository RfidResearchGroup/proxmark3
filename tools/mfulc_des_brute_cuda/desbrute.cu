/*
 * desbrute.cu  --  CUDA brute-force engine for 2TDEA key recovery.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif
#include <cuda_runtime.h>
#include "desbrute.h"

#ifdef _WIN32
typedef LARGE_INTEGER wall_time_t;

static void wall_time_now(wall_time_t *t)
{
    QueryPerformanceCounter(t);
}

static double wall_time_seconds(const wall_time_t *start, const wall_time_t *now)
{
    LARGE_INTEGER qpf;
    QueryPerformanceFrequency(&qpf);
    return (double)(now->QuadPart - start->QuadPart) / (double)qpf.QuadPart;
}

static void sleep_ms(unsigned int ms)
{
    Sleep(ms);
}
#else
typedef struct timespec wall_time_t;

static void wall_time_now(wall_time_t *t)
{
    clock_gettime(CLOCK_MONOTONIC, t);
}

static double wall_time_seconds(const wall_time_t *start, const wall_time_t *now)
{
    time_t sec = now->tv_sec - start->tv_sec;
    long nsec = now->tv_nsec - start->tv_nsec;
    return (double)sec + (double)nsec / 1e9;
}

static void sleep_ms(unsigned int ms)
{
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&req, NULL);
}
#endif

/* ========================================================================== */
/* CUDA error-checking                                                         */
/* ========================================================================== */

/*
 * CUDA_CHECK  --  check a CUDA runtime call and jump to cleanup on failure.
 *
 * Requires the enclosing function to have:
 *   • A label  cleanup:  near the end.
 *   • All device handles/pointers initialised to NULL/nullptr before first use.
 */
#define CUDA_CHECK(call)  do {                                          \
    cudaError_t _ce = (call);                                           \
    if (_ce != cudaSuccess) {                                           \
        fprintf(stderr, "[cuda] %s:%d  %s\n",                          \
                __FILE__, __LINE__, cudaGetErrorString(_ce));           \
        goto cleanup;                                                   \
    }                                                                   \
} while (0)

/* ========================================================================== */
/* DES constant tables                                                         */
/* ========================================================================== */

__constant__ static uint8_t d_IP[64] = {
    58,50,42,34,26,18,10, 2, 60,52,44,36,28,20,12, 4,
    62,54,46,38,30,22,14, 6, 64,56,48,40,32,24,16, 8,
    57,49,41,33,25,17, 9, 1, 59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5, 63,55,47,39,31,23,15, 7
};
__constant__ static uint8_t d_FP[64] = {
    40, 8,48,16,56,24,64,32, 39, 7,47,15,55,23,63,31,
    38, 6,46,14,54,22,62,30, 37, 5,45,13,53,21,61,29,
    36, 4,44,12,52,20,60,28, 35, 3,43,11,51,19,59,27,
    34, 2,42,10,50,18,58,26, 33, 1,41, 9,49,17,57,25
};

/*
 * Combined S+P table: SP[s*64 + b6] is the contribution of S-box s with 6-bit
 * input b6 to the 32-bit P-permutation output.  Size: 8x64x4 = 2 KB.
 * Precomputed on CPU in desbrute_launch() and uploaded via cudaMemcpyToSymbol.
 */
__constant__ static uint32_t d_SP[512];

/* Precomputed DES encryption subkeys for the fixed key half */
__constant__ static uint64_t d_fixed_sk[16];

/*
 * Key-schedule XOR tables for the variable (candidate) key half.
 *
 * The 4 variable bytes contribute 28 effective bits (7 bits each, parity
 * discarded) to the 16x48-bit subkeys.  Because the DES key schedule is a
 * sequence of linear bit operations (PC1 permutation, half-rotations, PC2
 * permutation), the contribution of each input bit to every subkey bit is
 * fixed and can be precomputed.
 *
 * d_cand_sk_base[r]          = subkeys when all variable bytes are 0
 * d_cand_sk_contrib[b*16+r]  = XOR contribution of effective bit b (0..27)
 *                               to subkey round r (0..15)
 *
 * In the kernel, per candidate:
 *   cand_sk[r] = d_cand_sk_base[r]
 *   for b in 0..27 (unrolled, branchless):
 *     mask = -(uint64_t)((idx >> b) & 1)   // 0 or 0xFFFFFFFFFFFFFFFF
 *     cand_sk[r] ^= d_cand_sk_contrib[b*16+r] & mask
 *
 * This replaces DPERM(PC1,56) + 16xDPERM(PC2,48) with 28x16 ALU ops.
 * Size: (16 + 28*16) * 8 = 3712 bytes.
 */
__constant__ static uint64_t d_cand_sk_base[16];
__constant__ static uint64_t d_cand_sk_contrib[28 * 16];

/* ========================================================================== */
/* Bit permutation macro (used only for IP/FP in device code)                 */
/* ========================================================================== */

#define DPERM(src, src_bits, tbl, N, dst)  do {                  \
    int _i;  (dst) = 0;                                           \
    _Pragma("unroll")                                             \
    for (_i = 0; _i < (N); _i++) {                               \
        int _sb = (tbl)[_i] - 1;                                  \
        (dst) |= (((src) >> ((src_bits)-1-_sb)) & 1ULL)           \
                 << ((N)-1-_i);                                   \
    }                                                             \
} while(0)

/* ========================================================================== */
/* Device DES primitives                                                       */
/* ========================================================================== */

/*
 * Feistel f function using the shared-memory SP table.
 *
 * E expansion is inlined as direct bit extractions from R — eliminates the
 * 48-iteration DPERM(E) loop entirely.  Called 3x16 = 48 times per candidate.
 *
 * E table maps R bits (DES 1-indexed) to 6-bit S-box inputs (0-indexed from
 * MSB of 48-bit eR):
 *   S1: E[0..5]  = DES bits 32,1,2,3,4,5   → R bits 0,31,30,29,28,27
 *   S2: E[6..11] = DES bits 4,5,6,7,8,9    → R bits 28,27,26,25,24,23
 *   S3:          = DES bits 8..13           → R bits 24..19
 *   S4:          = DES bits 12..17          → R bits 20..15
 *   S5:          = DES bits 16..21          → R bits 16..11
 *   S6:          = DES bits 20..25          → R bits 12..7
 *   S7:          = DES bits 24..29          → R bits 8..3
 *   S8:          = DES bits 28,29,30,31,32,1→ R bits 4,3,2,1,0,31
 *
 * In our uint32_t R: DES bit i (1-based) = bit (32-i) from LSB.
 */
__device__ static __forceinline__
uint32_t d_des_f(uint32_t R, uint64_t K, const uint32_t * __restrict__ sp)
{
    /* Extract 6-bit S-box inputs directly from R */
    uint32_t r0 = ((R & 1u) << 5) | ((R >> 27) & 0x1Fu);  /* S1 */
    uint32_t r1 = (R >> 23) & 0x3Fu;                        /* S2 */
    uint32_t r2 = (R >> 19) & 0x3Fu;                        /* S3 */
    uint32_t r3 = (R >> 15) & 0x3Fu;                        /* S4 */
    uint32_t r4 = (R >> 11) & 0x3Fu;                        /* S5 */
    uint32_t r5 = (R >>  7) & 0x3Fu;                        /* S6 */
    uint32_t r6 = (R >>  3) & 0x3Fu;                        /* S7 */
    uint32_t r7 = ((R & 0x1Fu) << 1) | ((R >> 31) & 1u);   /* S8 */

    /* XOR with subkey 6-bit chunks (K is 48 bits in bits 47..0) */
    r0 ^= (uint32_t)((K >> 42) & 0x3Fu);
    r1 ^= (uint32_t)((K >> 36) & 0x3Fu);
    r2 ^= (uint32_t)((K >> 30) & 0x3Fu);
    r3 ^= (uint32_t)((K >> 24) & 0x3Fu);
    r4 ^= (uint32_t)((K >> 18) & 0x3Fu);
    r5 ^= (uint32_t)((K >> 12) & 0x3Fu);
    r6 ^= (uint32_t)((K >>  6) & 0x3Fu);
    r7 ^= (uint32_t)(K & 0x3Fu);

    return sp[r0] ^ sp[64+r1] ^ sp[128+r2] ^ sp[192+r3]
         ^ sp[256+r4] ^ sp[320+r5] ^ sp[384+r6] ^ sp[448+r7];
}

/*
 * 16 Feistel rounds with NO Initial or Final Permutation.
 *
 *   rev=0  encrypt (subkeys sk[0]..sk[15])
 *   rev=1  decrypt (subkeys sk[15]..sk[0])
 *
 * Input  `block` must already have IP applied.
 * Output is the pre-FP word (R16 || L16).
 */
__device__ static __forceinline__
uint64_t d_des_rounds(uint64_t block, const uint64_t sk[16], int rev,
                      const uint32_t * __restrict__ sp)
{
    uint32_t L = (uint32_t)(block >> 32);
    uint32_t R = (uint32_t)(block);
    #pragma unroll 16
    for (int i = 0; i < 16; i++) {
        uint64_t K = rev ? sk[15 - i] : sk[i];
        uint32_t nR = L ^ d_des_f(R, K, sp);
        L = R;
        R = nR;
    }
    return ((uint64_t)R << 32) | L;   /* R16 || L16  (pre-FP) */
}

/*
 * Optimised 2TDEA decrypt.
 *
 * One IP at entry + three rounds-only stages + one FP at exit.
 * Saves 4 permutations vs. the naive DES_full x 3 approach.
 *
 *   mode=0  K1=candidate, K2=fixed:  D_cand -> E_fixed -> D_cand
 *   mode=1  K2=candidate, K1=fixed:  D_fixed -> E_cand -> D_fixed
 */
__device__ static __forceinline__
uint64_t d_tdea2_dec(uint64_t cipher, const uint64_t cand_sk[16], int mode,
                     const uint32_t * __restrict__ sp)
{
    uint64_t ip, t1, t2, t3, out;
    DPERM(cipher, 64, d_IP, 64, ip);
    if (mode == 0) {
        t1 = d_des_rounds(ip, cand_sk,    1, sp);
        t2 = d_des_rounds(t1, d_fixed_sk, 0, sp);
        t3 = d_des_rounds(t2, cand_sk,    1, sp);
    } else {
        t1 = d_des_rounds(ip, d_fixed_sk, 1, sp);
        t2 = d_des_rounds(t1, cand_sk,    0, sp);
        t3 = d_des_rounds(t2, d_fixed_sk, 1, sp);
    }
    DPERM(t3, 64, d_FP, 64, out);
    return out;
}

/* ========================================================================== */
/* LFSR validators (counterfeit mode only)                                     */
/* ========================================================================== */

__device__ static __forceinline__ int d_valid_lfsr_ulcg(uint64_t x64)
{
    uint16_t x = (uint16_t)(x64 >> 48);
    x = (uint16_t)(x << 15 | ((x >> 1) ^ ((x >> 3 ^ x >> 4 ^ x >> 6) & 1)));
    if (x != (uint16_t)((x64 >> 32) & 0xFFFF)) return 0;
    x = (uint16_t)(x << 15 | ((x >> 1) ^ ((x >> 3 ^ x >> 4 ^ x >> 6) & 1)));
    if (x != (uint16_t)((x64 >> 16) & 0xFFFF)) return 0;
    x = (uint16_t)(x << 15 | ((x >> 1) ^ ((x >> 3 ^ x >> 4 ^ x >> 6) & 1)));
    return (x == (uint16_t)(x64 & 0xFFFF));
}

__device__ static __forceinline__ int d_valid_lfsr_mfc(uint64_t x64)
{
    int i;
    uint16_t x = (uint16_t)(x64 & 0xFFFF);
    #pragma unroll 16
    for (i = 0; i < 16; i++)
        x = (uint16_t)(x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15);
    if (x != (uint16_t)((x64 >> 16) & 0xFFFF)) return 0;
    #pragma unroll 16
    for (i = 0; i < 16; i++)
        x = (uint16_t)(x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15);
    if (x != (uint16_t)((x64 >> 32) & 0xFFFF)) return 0;
    #pragma unroll 16
    for (i = 0; i < 16; i++)
        x = (uint16_t)(x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15);
    return (x == (uint16_t)((x64 >> 48) & 0xFFFF));
}

/* ========================================================================== */
/* Brute-force kernel                                                          */
/* ========================================================================== */

/*
 * PROGRESS_STRIDE: candidates each thread processes between progress flushes.
 * Lower = finer granularity, slightly more atomic overhead.
 */
#define PROGRESS_STRIDE 4096u

__global__ void desbrute_kernel(
    uint64_t              ciphertext,
    uint64_t              init_ciphertext,
    uint64_t              prev_ciphertext,
    int                   cand_mode,
    int                   lfsr_type,
    int                   is_reader_mode,
    int                  *d_found,
    uint32_t             *d_result_idx,
    unsigned long long   *d_progress
)
{
    /*
     * Step 1: load SP table from __constant__ into shared memory.
     *
     * Using shared memory avoids constant-cache serialisation: in a 32-thread
     * warp each thread accesses a different S-box entry (divergent), so constant
     * memory would serialize those 32 reads.  Shared memory handles them in
     * parallel with ~4-cycle latency.
     */
    __shared__ uint32_t s_SP[512];
    for (int i = (int)threadIdx.x; i < 512; i += (int)blockDim.x)
        s_SP[i] = d_SP[i];
    __syncthreads();   /* Barrier 1: SP table visible to all threads in block */

    /*
     * Step 2: initialise per-block early-exit flag.
     * Separate barrier so the intent of each sync is clear.
     */
    __shared__ int s_found;
    if (threadIdx.x == 0)
        s_found = *d_found;
    __syncthreads();   /* Barrier 2: s_found visible before loop starts */

    const uint32_t total  = 1u << 28;
    const uint32_t stride = (uint32_t)(gridDim.x * blockDim.x);
    uint32_t idx = (uint32_t)(blockIdx.x * blockDim.x + threadIdx.x);

    /*
     * candidates_tested semantics
     * ----------------------------
     *  no-match : sum of per-thread counters == total (2^28)
     *  match    : approximate work done before early-exit; not necessarily
     *             idx+1 because threads run in parallel and some overshoot.
     */
    unsigned long long local_count = 0;

    for (; idx < total; idx += stride) {

        /*
         * Periodic progress flush and early-exit check.
         *
         * __syncthreads() is intentionally absent here.  If it were present,
         * threads that finish fewer iterations than PROGRESS_STRIDE could exit
         * the loop while others hit the barrier -> deadlock.
         *
         * Only thread 0 flushes local_count and re-reads d_found.
         * A __threadfence_block() after the write makes the updated s_found
         * visible to other threads in the same block within a few cycles.
         */
        if ((local_count & (PROGRESS_STRIDE - 1)) == 0) {
            if (s_found) goto done;
            if (threadIdx.x == 0) {
                atomicAdd(d_progress, local_count);
                local_count = 0;
                s_found = *d_found;
                __threadfence_block();   /* push s_found write to shared mem */
            }
        }
        local_count++;

        uint64_t cand_sk[16];
        #pragma unroll 16
        for (int r = 0; r < 16; r++)
            cand_sk[r] = d_cand_sk_base[r];

        #pragma unroll 28
        for (int b = 0; b < 28; b++) {
            uint64_t mask = (uint64_t)(-(int64_t)((idx >> b) & 1u));
            #pragma unroll 16
            for (int r = 0; r < 16; r++)
                cand_sk[r] ^= d_cand_sk_contrib[b * 16 + r] & mask;
        }

        /* Optimised 2TDEA decrypt (single IP/FP for the whole chain) */
        uint64_t out = d_tdea2_dec(ciphertext, cand_sk, cand_mode, s_SP);

        /* Match check */
        int match = 0;
        if (is_reader_mode) {
            uint64_t init_out = d_tdea2_dec(init_ciphertext, cand_sk,
                                            cand_mode, s_SP);
            out ^= prev_ciphertext;
            uint64_t rotated = (init_out << 8) | (init_out >> 56);
            match = (out == rotated);
        } else {
            if      (lfsr_type == LFSR_ULCG) match = d_valid_lfsr_ulcg(out);
            else if (lfsr_type == LFSR_MFC)  match = d_valid_lfsr_mfc(out);
        }

        if (match) {
            if (atomicCAS(d_found, 0, 1) == 0)
                *d_result_idx = idx;
            s_found = 1;
            /* Do NOT increment local_count again here -- it was already
             * counted above.  An extra ++ would make candidates_tested
             * off by one. */
            goto done;
        }
    }

done:
    /* Flush remaining local count to the global progress counter */
    if (local_count > 0)
        atomicAdd(d_progress, local_count);
}

/* ========================================================================== */
/* CPU helpers                                                                  */
/* ========================================================================== */

static void cpu_des_keyschedule(uint64_t key64, uint64_t sk[16])
{
    static const uint8_t PC1[56] = {
        57,49,41,33,25,17, 9, 1, 58,50,42,34,26,18,
        10, 2,59,51,43,35,27,19, 11, 3,60,52,44,36,
        63,55,47,39,31,23,15, 7, 62,54,46,38,30,22,
        14, 6,61,53,45,37,29,21, 13, 5,28,20,12, 4
    };
    static const uint8_t PC2[48] = {
        14,17,11,24, 1, 5,  3,28,15, 6,21,10,
        23,19,12, 4,26, 8, 16, 7,27,20,13, 2,
        41,52,31,37,47,55, 30,40,51,45,33,48,
        44,49,39,56,34,53, 46,42,50,36,29,32
    };
    static const uint8_t SHF[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
    int i, j;
    uint64_t key56 = 0;
    for (i = 0; i < 56; i++) {
        int sb = PC1[i] - 1;
        key56 |= ((key64 >> (63 - sb)) & 1ULL) << (55 - i);
    }
    uint32_t C = (uint32_t)(key56 >> 28) & 0x0FFFFFFFu;
    uint32_t D = (uint32_t)(key56)       & 0x0FFFFFFFu;
    for (i = 0; i < 16; i++) {
        int s = SHF[i];
        C = ((C << s) | (C >> (28 - s))) & 0x0FFFFFFFu;
        D = ((D << s) | (D >> (28 - s))) & 0x0FFFFFFFu;
        uint64_t CD = ((uint64_t)C << 28) | D;
        uint64_t sub = 0;
        for (j = 0; j < 48; j++) {
            int sb2 = PC2[j] - 1;
            sub |= ((CD >> (55 - sb2)) & 1ULL) << (47 - j);
        }
        sk[i] = sub;
    }
}

static inline uint64_t cpu_bytes_to_u64(const uint8_t *b)
{
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] <<  8) | (uint64_t)b[7];
}

/*
 * Precompute the combined S+P table on the CPU.
 *
 * For S-box s (0..7) and 6-bit input b6 (0..63):
 *   sval = SBOX[s][row][col]                   (4-bit output, 0..15)
 *   sval occupies sout bits [28-s*4 .. 31-s*4] (bit 0 = integer LSB)
 *   P permutation: pf[31-i] = sout[32 - P[i]]
 *   SP[s*64+b6] accumulates only pf bits from S-box s.
 */
static void cpu_compute_sp(uint32_t sp_out[512])
{
    static const uint8_t SBOX[512] = {
        /* S1 */
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
        /* S2 */
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
        /* S3 */
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
        /* S4 */
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
        /* S5 */
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
        /* S6 */
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
        /* S7 */
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
        /* S8 */
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    };
    static const uint8_t P[32] = {
        16, 7,20,21,29,12,28,17,
         1,15,23,26, 5,18,31,10,
         2, 8,24,14,32,27, 3, 9,
        19,13,30, 6,22,11, 4,25
    };

    int s, b6, i;
    for (s = 0; s < 8; s++) {
        for (b6 = 0; b6 < 64; b6++) {
            int row  = ((b6 >> 5) & 1) * 2 + (b6 & 1);
            int col  = (b6 >> 1) & 0xF;
            int sval = SBOX[s * 64 + row * 16 + col];   /* 4-bit, 0..15 */

            /* Accumulate pf contribution from this S-box only */
            uint32_t sp = 0;
            for (i = 0; i < 32; i++) {
                int sout_bit = 32 - P[i];        /* integer bit index (0=LSB) */
                int sbox_lo  = 28 - s * 4;
                int sbox_hi  = 31 - s * 4;
                if (sout_bit >= sbox_lo && sout_bit <= sbox_hi) {
                    int sval_bit = sout_bit - sbox_lo;   /* 0..3 */
                    if ((sval >> sval_bit) & 1)
                        sp |= (1u << (31 - i));
                }
            }
            sp_out[s * 64 + b6] = sp;
        }
    }
}

/*
 * Precompute the per-bit XOR contribution tables for the candidate key half.
 *
 * The 4 variable bytes (at byte positions var_offset..var_offset+3 within
 * the 8-byte half-key) contribute 28 effective bits (7 each) to the 16
 * DES subkeys.  Because PC1 and PC2 are linear bit selections, each input
 * bit's contribution to every subkey bit is fixed and can be tabulated.
 *
 * For each of the 28 effective bit positions b (0..27):
 *   byte_in_half = b / 7        which variable byte (0..3)
 *   bit_in_byte  = b % 7        which bit within that byte (0..6)
 *   actual bit in key byte = bit (bit_in_byte + 1) (parity at bit 0 is 0)
 *
 * We compute the key schedule for a half-key with only that one bit set,
 * giving the XOR contribution of that bit to each subkey round.
 *
 * Outputs:
 *   sk_base[16]            -- subkeys for candidate half with variable bytes=0
 *   sk_contrib[28 * 16]    -- contrib[b*16+r] = subkey[r] XOR contrib of bit b
 */
static void cpu_compute_sk_tables(
    uint64_t base_half,
    int      var_offset,
    uint64_t sk_base[16],
    uint64_t sk_contrib[28 * 16])
{
    /* Base: key schedule with variable bytes already zeroed (base_half has them 0) */
    cpu_des_keyschedule(base_half, sk_base);

    /* Per-bit contributions */
    int b, r;
    for (b = 0; b < 28; b++) {
        int byte_in_half = b / 7;
        int bit_in_byte  = b % 7;

        /* Build half-key with only this one effective bit set */
        uint8_t tmp[8];
        memset(tmp, 0, sizeof(tmp));
        tmp[var_offset + byte_in_half] = (uint8_t)(1u << (bit_in_byte + 1));

        uint64_t bit_key = cpu_bytes_to_u64(tmp);
        uint64_t sk_for_bit[16];
        cpu_des_keyschedule(bit_key, sk_for_bit);

        /* XOR contribution: because key schedule is linear over GF(2), the
         * contribution of this bit equals the key schedule result for the
         * half-key with only this bit set (base has variable bytes = 0,
         * which means their contribution is 0 already).                    */
        for (r = 0; r < 16; r++)
            sk_contrib[b * 16 + r] = sk_for_bit[r];
    }
}

/* ========================================================================== */
/* Public launch function                                                      */
/* ========================================================================== */

void desbrute_launch(
    uint64_t  ciphertext_be,
    uint64_t  init_ciphertext_be,
    uint64_t  prev_ciphertext_be,
    const uint8_t base_key[KEY_SIZE],
    int       key_mode,
    int       lfsr_type,
    int       is_reader_mode,
    desbrute_result_t *result
)
{
    /* -- API-level validation ----------------------------------------------- */
    if (!result)
        return;

    memset(result, 0, sizeof(*result));
    result->idx = UINT32_MAX;   /* sentinel: no match yet */

    if (!base_key)                                        { return; }
    if (key_mode < 0 || key_mode > 3)                    { return; }
    if (is_reader_mode != 0 && is_reader_mode != 1)      { return; }
    if (!is_reader_mode && lfsr_type == LFSR_UNDEF)      { return; }

    /* -- Declare all locals up-front so no goto bypasses an initialisation -- */
    cudaStream_t stream          = NULL;
    cudaStream_t progress_stream = NULL;
    cudaEvent_t  ev_start        = NULL;
    cudaEvent_t  ev_stop         = NULL;
    int                *d_found      = NULL;
    uint32_t           *d_result_idx = NULL;
    unsigned long long *d_progress   = NULL;
    int candidate_in_k1;
    int cand_mode;
    int var_offset;
    uint64_t fixed_u64;
    uint64_t base_half;
    int block_size;
    int min_grid;
    int dev;
    int dev_mp;
    int grid_size;
    uint64_t total_candidates;
    wall_time_t qpc_start, qpc_now;
    uint64_t h_fixed_sk[16];
    uint32_t h_SP[512];
    uint8_t  cand_bytes[8];
    uint64_t h_cand_sk_base[16];
    uint64_t h_cand_sk_contrib[28 * 16];

    /* -- Candidate / fixed half selection ----------------------------------- */
    candidate_in_k1 = (key_mode < 2) ? 1 : 0;
    cand_mode        = candidate_in_k1 ? 0 : 1;
    if (candidate_in_k1)
        var_offset = (key_mode % 2) * 4;
    else
        var_offset = ((key_mode - 2) % 2) * 4;

    /* -- Fixed-half subkeys ------------------------------------------------- */
    fixed_u64 = candidate_in_k1
                ? cpu_bytes_to_u64(base_key + 8)
                : cpu_bytes_to_u64(base_key);
    cpu_des_keyschedule(fixed_u64, h_fixed_sk);

    CUDA_CHECK(cudaMemcpyToSymbol(d_fixed_sk, h_fixed_sk, 16 * sizeof(uint64_t)));

    /* -- Precompute and upload SP table ------------------------------------- */
    cpu_compute_sp(h_SP);
    CUDA_CHECK(cudaMemcpyToSymbol(d_SP, h_SP, 512 * sizeof(uint32_t)));

    /* -- Candidate half: zero out variable bytes ---------------------------- */
    if (candidate_in_k1) memcpy(cand_bytes, base_key,     8);
    else                  memcpy(cand_bytes, base_key + 8, 8);
    cand_bytes[var_offset]     = 0;
    cand_bytes[var_offset + 1] = 0;
    cand_bytes[var_offset + 2] = 0;
    cand_bytes[var_offset + 3] = 0;
    base_half = cpu_bytes_to_u64(cand_bytes);

    /* -- Key-schedule tables (main throughput optimisation) ----------------- */
    cpu_compute_sk_tables(base_half, var_offset, h_cand_sk_base, h_cand_sk_contrib);

    CUDA_CHECK(cudaMemcpyToSymbol(d_cand_sk_base,   h_cand_sk_base,
                                  16 * sizeof(uint64_t)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_cand_sk_contrib, h_cand_sk_contrib,
                                  28 * 16 * sizeof(uint64_t)));

    /* -- Device buffers ----------------------------------------------------- */
    CUDA_CHECK(cudaMalloc((void **)&d_found,      sizeof(int)));
    CUDA_CHECK(cudaMalloc((void **)&d_result_idx, sizeof(uint32_t)));
    CUDA_CHECK(cudaMalloc((void **)&d_progress,   sizeof(unsigned long long)));

    CUDA_CHECK(cudaMemset(d_found,      0,    sizeof(int)));
    CUDA_CHECK(cudaMemset(d_result_idx, 0xFF, sizeof(uint32_t)));  /* UINT32_MAX */
    CUDA_CHECK(cudaMemset(d_progress,   0,    sizeof(unsigned long long)));

    /* -- Launch configuration ----------------------------------------------- */
    block_size = 256;
    min_grid   = 0;
    CUDA_CHECK(cudaOccupancyMaxPotentialBlockSize(&min_grid, &block_size,
                                                  desbrute_kernel, 0, 0));
    if (block_size > 256) block_size = 256;

    /*
     * Use the CURRENT device (not hardcoded 0) so the grid is correctly sized
     * when the user passes a non-zero [cuda_dev] argument.
     */
    dev    = 0;
    dev_mp = 1;
    CUDA_CHECK(cudaGetDevice(&dev));
    CUDA_CHECK(cudaDeviceGetAttribute(&dev_mp, cudaDevAttrMultiProcessorCount, dev));

    grid_size        = dev_mp * 64;
    if (grid_size > 65535) grid_size = 65535;
    total_candidates = 1ULL << 28;

    printf("\n[kernel] Grid: %d blocks x %d threads  (64 waves/SM on dev %d)\n",
           grid_size, block_size, dev);
    printf("[kernel] Keyspace: 2^28 = %llu candidates\n",
           (unsigned long long)total_candidates);
    fflush(stdout);

    /* -- Streams and events -------------------------------------------------
     * Two streams:
     *   stream          -- the kernel runs here
     *   progress_stream -- independent stream for live progress copies
     *
     * Because progress_stream has no dependency on the kernel stream,
     * cudaMemcpyAsync on it reads d_progress while the kernel is still running.
     * Atomic updates in the kernel commit to L2/DRAM so they are visible.
     */
    CUDA_CHECK(cudaStreamCreate(&stream));
    CUDA_CHECK(cudaStreamCreate(&progress_stream));
    CUDA_CHECK(cudaEventCreate(&ev_start));
    CUDA_CHECK(cudaEventCreate(&ev_stop));

    /* -- Wall-clock start --------------------------------------------------- */
    wall_time_now(&qpc_start);

    /* -- Launch ------------------------------------------------------------- */
    CUDA_CHECK(cudaEventRecord(ev_start, stream));

    desbrute_kernel<<<grid_size, block_size, 0, stream>>>(
        ciphertext_be, init_ciphertext_be, prev_ciphertext_be,
        cand_mode, lfsr_type, is_reader_mode,
        d_found, d_result_idx, d_progress
    );

    /* Check for launch errors immediately */
    CUDA_CHECK(cudaGetLastError());

#if defined(DEBUG) || defined(_DEBUG)
    /* In debug builds, synchronise now to surface async execution errors close
     * to the launch site rather than at a later sync point. */
    CUDA_CHECK(cudaStreamSynchronize(stream));
#endif

    CUDA_CHECK(cudaEventRecord(ev_stop, stream));

    /* -- Progress polling loop ---------------------------------------------- */
    printf("[search] Running\n");
    fflush(stdout);

    {
        cudaError_t q;
        while ((q = cudaStreamQuery(stream)) == cudaErrorNotReady) {
            sleep_ms(150);

            /* Read progress via the independent progress_stream */
            unsigned long long prog = 0;
            cudaMemcpyAsync(&prog, d_progress, sizeof(unsigned long long),
                            cudaMemcpyDeviceToHost, progress_stream);
            cudaStreamSynchronize(progress_stream);

            wall_time_now(&qpc_now);
            double wall_s = wall_time_seconds(&qpc_start, &qpc_now);

            double pct = (prog >= total_candidates)
                         ? 100.0
                         : 100.0 * (double)prog / (double)total_candidates;
            double kps = (wall_s > 0.001) ? (double)prog / wall_s : 0.0;

            int hf = 0;
            cudaMemcpyAsync(&hf, d_found, sizeof(int),
                            cudaMemcpyDeviceToHost, progress_stream);
            cudaStreamSynchronize(progress_stream);

            printf("\r[search] %6.2f%%  |  %8.2f M keys/s  |  %.2f s elapsed%s",
                   pct, kps / 1e6, wall_s, hf ? "  [FOUND!]" : "       ");
            fflush(stdout);
        }

        /* Any status other than cudaSuccess means an async error occurred */
        if (q != cudaSuccess) {
            fprintf(stderr, "\n[cuda] stream error: %s\n", cudaGetErrorString(q));
            goto cleanup;
        }
    }

    CUDA_CHECK(cudaStreamSynchronize(stream));
    printf("\n");

    /* -- Gather results ----------------------------------------------------- */
    wall_time_now(&qpc_now);
    result->wall_ms = 1000.0 * wall_time_seconds(&qpc_start, &qpc_now);

    {
        float gpu_ms = 0.0f;
        CUDA_CHECK(cudaEventElapsedTime(&gpu_ms, ev_start, ev_stop));
        result->gpu_ms = gpu_ms;

        unsigned long long final_prog = 0;
        CUDA_CHECK(cudaMemcpy(&final_prog, d_progress,
                              sizeof(unsigned long long), cudaMemcpyDeviceToHost));
        result->candidates_tested = (uint64_t)final_prog;

        if (gpu_ms > 0.0f)
            result->keys_per_sec = (double)final_prog / (gpu_ms / 1000.0);

        int h_found = 0;
        uint32_t h_result_idx = UINT32_MAX;
        CUDA_CHECK(cudaMemcpy(&h_found,      d_found,
                              sizeof(int),      cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(&h_result_idx, d_result_idx,
                              sizeof(uint32_t), cudaMemcpyDeviceToHost));
        result->found = h_found;
        result->idx   = h_result_idx;
    }

    /* -- Cleanup (also reached via CUDA_CHECK goto on error) ---------------- */
cleanup:
    if (ev_stop)         cudaEventDestroy(ev_stop);
    if (ev_start)        cudaEventDestroy(ev_start);
    if (progress_stream) cudaStreamDestroy(progress_stream);
    if (stream)          cudaStreamDestroy(stream);
    if (d_progress)      cudaFree(d_progress);
    if (d_result_idx)    cudaFree(d_result_idx);
    if (d_found)         cudaFree(d_found);
}
