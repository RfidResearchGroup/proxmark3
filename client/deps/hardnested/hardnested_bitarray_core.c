//-----------------------------------------------------------------------------
// Copyright (C) 2016, 2017 by piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.ch b
//-----------------------------------------------------------------------------
// Implements a card only attack based on crypto text (encrypted nonces
// received during a nested authentication) only. Unlike other card only
// attacks this doesn't rely on implementation errors but only on the
// inherent weaknesses of the crypto1 cypher. Described in
//   Carlo Meijer, Roel Verdult, "Ciphertext-only Cryptanalysis on Hardened
//   Mifare Classic Cards" in Proceedings of the 22nd ACM SIGSAC Conference on
//   Computer and Communications Security, 2015
//-----------------------------------------------------------------------------
// some helper functions which can benefit from SIMD instructions or other special instructions
//

#include "hardnested_bitarray_core.h"
#include "hardnested_bf_core.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef __APPLE__
#include <malloc.h>
#endif

// this needs to be compiled several times for each instruction set.
// For each instruction set, define a dedicated function name:
#if defined (__AVX512F__)
#define MALLOC_BITARRAY malloc_bitarray_AVX512
#define FREE_BITARRAY free_bitarray_AVX512
#define BITCOUNT bitcount_AVX512
#define COUNT_STATES count_states_AVX512
#define BITARRAY_AND bitarray_AND_AVX512
#define BITARRAY_LOW20_AND bitarray_low20_AND_AVX512
#define COUNT_BITARRAY_AND count_bitarray_AND_AVX512
#define COUNT_BITARRAY_LOW20_AND count_bitarray_low20_AND_AVX512
#define BITARRAY_AND4 bitarray_AND4_AVX512
#define BITARRAY_OR bitarray_OR_AVX512
#define COUNT_BITARRAY_AND2 count_bitarray_AND2_AVX512
#define COUNT_BITARRAY_AND3 count_bitarray_AND3_AVX512
#define COUNT_BITARRAY_AND4 count_bitarray_AND4_AVX512
#elif defined (__AVX2__)
#define MALLOC_BITARRAY malloc_bitarray_AVX2
#define FREE_BITARRAY free_bitarray_AVX2
#define BITCOUNT bitcount_AVX2
#define COUNT_STATES count_states_AVX2
#define BITARRAY_AND bitarray_AND_AVX2
#define BITARRAY_LOW20_AND bitarray_low20_AND_AVX2
#define COUNT_BITARRAY_AND count_bitarray_AND_AVX2
#define COUNT_BITARRAY_LOW20_AND count_bitarray_low20_AND_AVX2
#define BITARRAY_AND4 bitarray_AND4_AVX2
#define BITARRAY_OR bitarray_OR_AVX2
#define COUNT_BITARRAY_AND2 count_bitarray_AND2_AVX2
#define COUNT_BITARRAY_AND3 count_bitarray_AND3_AVX2
#define COUNT_BITARRAY_AND4 count_bitarray_AND4_AVX2
#elif defined (__AVX__)
#define MALLOC_BITARRAY malloc_bitarray_AVX
#define FREE_BITARRAY free_bitarray_AVX
#define BITCOUNT bitcount_AVX
#define COUNT_STATES count_states_AVX
#define BITARRAY_AND bitarray_AND_AVX
#define BITARRAY_LOW20_AND bitarray_low20_AND_AVX
#define COUNT_BITARRAY_AND count_bitarray_AND_AVX
#define COUNT_BITARRAY_LOW20_AND count_bitarray_low20_AND_AVX
#define BITARRAY_AND4 bitarray_AND4_AVX
#define BITARRAY_OR bitarray_OR_AVX
#define COUNT_BITARRAY_AND2 count_bitarray_AND2_AVX
#define COUNT_BITARRAY_AND3 count_bitarray_AND3_AVX
#define COUNT_BITARRAY_AND4 count_bitarray_AND4_AVX
#elif defined (__SSE2__)
#define MALLOC_BITARRAY malloc_bitarray_SSE2
#define FREE_BITARRAY free_bitarray_SSE2
#define BITCOUNT bitcount_SSE2
#define COUNT_STATES count_states_SSE2
#define BITARRAY_AND bitarray_AND_SSE2
#define BITARRAY_LOW20_AND bitarray_low20_AND_SSE2
#define COUNT_BITARRAY_AND count_bitarray_AND_SSE2
#define COUNT_BITARRAY_LOW20_AND count_bitarray_low20_AND_SSE2
#define BITARRAY_AND4 bitarray_AND4_SSE2
#define BITARRAY_OR bitarray_OR_SSE2
#define COUNT_BITARRAY_AND2 count_bitarray_AND2_SSE2
#define COUNT_BITARRAY_AND3 count_bitarray_AND3_SSE2
#define COUNT_BITARRAY_AND4 count_bitarray_AND4_SSE2
#elif defined (__MMX__)
#define MALLOC_BITARRAY malloc_bitarray_MMX
#define FREE_BITARRAY free_bitarray_MMX
#define BITCOUNT bitcount_MMX
#define COUNT_STATES count_states_MMX
#define BITARRAY_AND bitarray_AND_MMX
#define BITARRAY_LOW20_AND bitarray_low20_AND_MMX
#define COUNT_BITARRAY_AND count_bitarray_AND_MMX
#define COUNT_BITARRAY_LOW20_AND count_bitarray_low20_AND_MMX
#define BITARRAY_AND4 bitarray_AND4_MMX
#define BITARRAY_OR bitarray_OR_MMX
#define COUNT_BITARRAY_AND2 count_bitarray_AND2_MMX
#define COUNT_BITARRAY_AND3 count_bitarray_AND3_MMX
#define COUNT_BITARRAY_AND4 count_bitarray_AND4_MMX
#elif defined (__ARM_NEON) && !defined (NOSIMD_BUILD)
#define MALLOC_BITARRAY malloc_bitarray_NEON
#define FREE_BITARRAY free_bitarray_NEON
#define BITCOUNT bitcount_NEON
#define COUNT_STATES count_states_NEON
#define BITARRAY_AND bitarray_AND_NEON
#define BITARRAY_LOW20_AND bitarray_low20_AND_NEON
#define COUNT_BITARRAY_AND count_bitarray_AND_NEON
#define COUNT_BITARRAY_LOW20_AND count_bitarray_low20_AND_NEON
#define BITARRAY_AND4 bitarray_AND4_NEON
#define BITARRAY_OR bitarray_OR_NEON
#define COUNT_BITARRAY_AND2 count_bitarray_AND2_NEON
#define COUNT_BITARRAY_AND3 count_bitarray_AND3_NEON
#define COUNT_BITARRAY_AND4 count_bitarray_AND4_NEON
#else
#define MALLOC_BITARRAY malloc_bitarray_NOSIMD
#define FREE_BITARRAY free_bitarray_NOSIMD
#define BITCOUNT bitcount_NOSIMD
#define COUNT_STATES count_states_NOSIMD
#define BITARRAY_AND bitarray_AND_NOSIMD
#define BITARRAY_LOW20_AND bitarray_low20_AND_NOSIMD
#define COUNT_BITARRAY_AND count_bitarray_AND_NOSIMD
#define COUNT_BITARRAY_LOW20_AND count_bitarray_low20_AND_NOSIMD
#define BITARRAY_AND4 bitarray_AND4_NOSIMD
#define BITARRAY_OR bitarray_OR_NOSIMD
#define COUNT_BITARRAY_AND2 count_bitarray_AND2_NOSIMD
#define COUNT_BITARRAY_AND3 count_bitarray_AND3_NOSIMD
#define COUNT_BITARRAY_AND4 count_bitarray_AND4_NOSIMD
#endif


// typedefs and declaration of functions:
typedef uint32_t *malloc_bitarray_t(uint32_t);
malloc_bitarray_t malloc_bitarray_AVX512, malloc_bitarray_AVX2, malloc_bitarray_AVX, malloc_bitarray_SSE2, malloc_bitarray_MMX, malloc_bitarray_NOSIMD, malloc_bitarray_NEON, malloc_bitarray_dispatch;
typedef void free_bitarray_t(uint32_t *);
free_bitarray_t free_bitarray_AVX512, free_bitarray_AVX2, free_bitarray_AVX, free_bitarray_SSE2, free_bitarray_MMX, free_bitarray_NOSIMD, free_bitarray_NEON, free_bitarray_dispatch;
typedef uint32_t bitcount_t(uint32_t);
bitcount_t bitcount_AVX512, bitcount_AVX2, bitcount_AVX, bitcount_SSE2, bitcount_MMX, bitcount_NOSIMD, bitcount_NEON, bitcount_dispatch;
typedef uint32_t count_states_t(uint32_t *);
count_states_t count_states_AVX512, count_states_AVX2, count_states_AVX, count_states_SSE2, count_states_MMX, count_states_NOSIMD, count_states_NEON, count_states_dispatch;
typedef void bitarray_AND_t(uint32_t[], uint32_t[]);
bitarray_AND_t bitarray_AND_AVX512, bitarray_AND_AVX2, bitarray_AND_AVX, bitarray_AND_SSE2, bitarray_AND_MMX, bitarray_AND_NOSIMD, bitarray_AND_NEON, bitarray_AND_dispatch;
typedef void bitarray_low20_AND_t(uint32_t *, uint32_t *);
bitarray_low20_AND_t bitarray_low20_AND_AVX512, bitarray_low20_AND_AVX2, bitarray_low20_AND_AVX, bitarray_low20_AND_SSE2, bitarray_low20_AND_MMX, bitarray_low20_AND_NOSIMD, bitarray_low20_AND_NEON, bitarray_low20_AND_dispatch;
typedef uint32_t count_bitarray_AND_t(uint32_t *, uint32_t *);
count_bitarray_AND_t count_bitarray_AND_AVX512, count_bitarray_AND_AVX2, count_bitarray_AND_AVX, count_bitarray_AND_SSE2, count_bitarray_AND_MMX, count_bitarray_AND_NOSIMD, count_bitarray_AND_NEON, count_bitarray_AND_dispatch;
typedef uint32_t count_bitarray_low20_AND_t(uint32_t *, uint32_t *);
count_bitarray_low20_AND_t count_bitarray_low20_AND_AVX512, count_bitarray_low20_AND_AVX2, count_bitarray_low20_AND_AVX, count_bitarray_low20_AND_SSE2, count_bitarray_low20_AND_MMX, count_bitarray_low20_AND_NOSIMD, count_bitarray_low20_AND_NEON, count_bitarray_low20_AND_dispatch;
typedef void bitarray_AND4_t(uint32_t *, uint32_t *, uint32_t *, uint32_t *);
bitarray_AND4_t bitarray_AND4_AVX512, bitarray_AND4_AVX2, bitarray_AND4_AVX, bitarray_AND4_SSE2, bitarray_AND4_MMX, bitarray_AND4_NOSIMD, bitarray_AND4_NEON, bitarray_AND4_dispatch;
typedef void bitarray_OR_t(uint32_t[], uint32_t[]);
bitarray_OR_t bitarray_OR_AVX512, bitarray_OR_AVX2, bitarray_OR_AVX, bitarray_OR_SSE2, bitarray_OR_MMX, bitarray_OR_NOSIMD, bitarray_OR_NEON, bitarray_OR_dispatch;
typedef uint32_t count_bitarray_AND2_t(uint32_t *, uint32_t *);
count_bitarray_AND2_t count_bitarray_AND2_AVX512, count_bitarray_AND2_AVX2, count_bitarray_AND2_AVX, count_bitarray_AND2_SSE2, count_bitarray_AND2_MMX, count_bitarray_AND2_NOSIMD, count_bitarray_AND2_NEON, count_bitarray_AND2_dispatch;
typedef uint32_t count_bitarray_AND3_t(uint32_t *, uint32_t *, uint32_t *);
count_bitarray_AND3_t count_bitarray_AND3_AVX512, count_bitarray_AND3_AVX2, count_bitarray_AND3_AVX, count_bitarray_AND3_SSE2, count_bitarray_AND3_MMX, count_bitarray_AND3_NOSIMD, count_bitarray_AND3_NEON, count_bitarray_AND3_dispatch;
typedef uint32_t count_bitarray_AND4_t(uint32_t *, uint32_t *, uint32_t *, uint32_t *);
count_bitarray_AND4_t count_bitarray_AND4_AVX512, count_bitarray_AND4_AVX2, count_bitarray_AND4_AVX, count_bitarray_AND4_SSE2, count_bitarray_AND4_MMX, count_bitarray_AND4_NOSIMD, count_bitarray_AND4_NEON, count_bitarray_AND4_dispatch;


inline uint32_t *MALLOC_BITARRAY(uint32_t x) {
#if defined (_WIN32)
    return __builtin_assume_aligned(_aligned_malloc((x), __BIGGEST_ALIGNMENT__), __BIGGEST_ALIGNMENT__);
#elif defined (__APPLE__)
    uint32_t *allocated_memory;
    if (posix_memalign((void **)&allocated_memory, __BIGGEST_ALIGNMENT__, x)) {
        return NULL;
    } else {
        return __builtin_assume_aligned(allocated_memory, __BIGGEST_ALIGNMENT__);
    }
#else
    return __builtin_assume_aligned(memalign(__BIGGEST_ALIGNMENT__, (x)), __BIGGEST_ALIGNMENT__);
#endif
}


inline void FREE_BITARRAY(uint32_t *x) {
#ifdef _WIN32
    _aligned_free(x);
#else
    free(x);
#endif
}


inline uint32_t BITCOUNT(uint32_t a) {
    return __builtin_popcountl(a);
}


inline uint32_t COUNT_STATES(uint32_t *A) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < (1 << 19); i++) {
        count += BITCOUNT(A[i]);
    }
    return count;
}


inline void BITARRAY_AND(uint32_t *restrict A, uint32_t *restrict B) {
    A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
    B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
    for (uint32_t i = 0; i < (1 << 19); i++) {
        A[i] &= B[i];
    }
}


inline void BITARRAY_LOW20_AND(uint32_t *restrict A, uint32_t *restrict B) {
    uint16_t *a = (uint16_t *)__builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
    uint16_t *b = (uint16_t *)__builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);

    for (uint32_t i = 0; i < (1 << 20); i++) {
        if (!b[i]) {
            a[i] = 0;
        }
    }
}


inline uint32_t COUNT_BITARRAY_AND(uint32_t *restrict A, uint32_t *restrict B) {
    A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
    B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
    uint32_t count = 0;
    for (uint32_t i = 0; i < (1 << 19); i++) {
        A[i] &= B[i];
        count += BITCOUNT(A[i]);
    }
    return count;
}


inline uint32_t COUNT_BITARRAY_LOW20_AND(uint32_t *restrict A, uint32_t *restrict B) {
    uint16_t *a = (uint16_t *)__builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
    uint16_t *b = (uint16_t *)__builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
    uint32_t count = 0;

    for (uint32_t i = 0; i < (1 << 20); i++) {
        if (!b[i]) {
            a[i] = 0;
        }
        count += BITCOUNT(a[i]);
    }
    return count;
}


inline void BITARRAY_AND4(uint32_t *restrict A, uint32_t *restrict B, uint32_t *restrict C, uint32_t *restrict D) {
    A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
    B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
    C = __builtin_assume_aligned(C, __BIGGEST_ALIGNMENT__);
    D = __builtin_assume_aligned(D, __BIGGEST_ALIGNMENT__);
    for (uint32_t i = 0; i < (1 << 19); i++) {
        A[i] = B[i] & C[i] & D[i];
    }
}


inline void BITARRAY_OR(uint32_t *restrict A, uint32_t *restrict B) {
    A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
    B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
    for (uint32_t i = 0; i < (1 << 19); i++) {
        A[i] |= B[i];
    }
}


inline uint32_t COUNT_BITARRAY_AND2(uint32_t *restrict A, uint32_t *restrict B) {
    A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
    B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
    uint32_t count = 0;
    for (uint32_t i = 0; i < (1 << 19); i++) {
        count += BITCOUNT(A[i] & B[i]);
    }
    return count;
}


inline uint32_t COUNT_BITARRAY_AND3(uint32_t *restrict A, uint32_t *restrict B, uint32_t *restrict C) {
    A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
    B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
    C = __builtin_assume_aligned(C, __BIGGEST_ALIGNMENT__);
    uint32_t count = 0;
    for (uint32_t i = 0; i < (1 << 19); i++) {
        count += BITCOUNT(A[i] & B[i] & C[i]);
    }
    return count;
}


inline uint32_t COUNT_BITARRAY_AND4(uint32_t *restrict A, uint32_t *restrict B, uint32_t *restrict C, uint32_t *restrict D) {
    A = __builtin_assume_aligned(A, __BIGGEST_ALIGNMENT__);
    B = __builtin_assume_aligned(B, __BIGGEST_ALIGNMENT__);
    C = __builtin_assume_aligned(C, __BIGGEST_ALIGNMENT__);
    D = __builtin_assume_aligned(D, __BIGGEST_ALIGNMENT__);
    uint32_t count = 0;
    for (uint32_t i = 0; i < (1 << 19); i++) {
        count += BITCOUNT(A[i] & B[i] & C[i] & D[i]);
    }
    return count;
}


#ifdef NOSIMD_BUILD

// pointers to functions:
malloc_bitarray_t *malloc_bitarray_function_p = &malloc_bitarray_dispatch;
free_bitarray_t *free_bitarray_function_p = &free_bitarray_dispatch;
bitcount_t *bitcount_function_p = &bitcount_dispatch;
count_states_t *count_states_function_p = &count_states_dispatch;
bitarray_AND_t *bitarray_AND_function_p = &bitarray_AND_dispatch;
bitarray_low20_AND_t *bitarray_low20_AND_function_p = &bitarray_low20_AND_dispatch;
count_bitarray_AND_t *count_bitarray_AND_function_p = &count_bitarray_AND_dispatch;
count_bitarray_low20_AND_t *count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_dispatch;
bitarray_AND4_t *bitarray_AND4_function_p = &bitarray_AND4_dispatch;
bitarray_OR_t *bitarray_OR_function_p = &bitarray_OR_dispatch;
count_bitarray_AND2_t *count_bitarray_AND2_function_p = &count_bitarray_AND2_dispatch;
count_bitarray_AND3_t *count_bitarray_AND3_function_p = &count_bitarray_AND3_dispatch;
count_bitarray_AND4_t *count_bitarray_AND4_function_p = &count_bitarray_AND4_dispatch;

// determine the available instruction set at runtime and call the correct function
uint32_t *malloc_bitarray_dispatch(uint32_t x) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) malloc_bitarray_function_p = &malloc_bitarray_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) malloc_bitarray_function_p = &malloc_bitarray_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) malloc_bitarray_function_p = &malloc_bitarray_AVX2;
            else if (__builtin_cpu_supports("avx")) malloc_bitarray_function_p = &malloc_bitarray_AVX;
            else if (__builtin_cpu_supports("sse2")) malloc_bitarray_function_p = &malloc_bitarray_SSE2;
            else if (__builtin_cpu_supports("mmx")) malloc_bitarray_function_p = &malloc_bitarray_MMX;
            else
#endif
                malloc_bitarray_function_p = &malloc_bitarray_NOSIMD;

    // call the most optimized function for this CPU
    return (*malloc_bitarray_function_p)(x);
}

void free_bitarray_dispatch(uint32_t *x) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) free_bitarray_function_p = &free_bitarray_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) free_bitarray_function_p = &free_bitarray_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) free_bitarray_function_p = &free_bitarray_AVX2;
            else if (__builtin_cpu_supports("avx")) free_bitarray_function_p = &free_bitarray_AVX;
            else if (__builtin_cpu_supports("sse2")) free_bitarray_function_p = &free_bitarray_SSE2;
            else if (__builtin_cpu_supports("mmx")) free_bitarray_function_p = &free_bitarray_MMX;
            else
#endif
                free_bitarray_function_p = &free_bitarray_NOSIMD;

    // call the most optimized function for this CPU
    (*free_bitarray_function_p)(x);
}

uint32_t bitcount_dispatch(uint32_t a) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) bitcount_function_p = &bitcount_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) bitcount_function_p = &bitcount_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) bitcount_function_p = &bitcount_AVX2;
            else if (__builtin_cpu_supports("avx")) bitcount_function_p = &bitcount_AVX;
            else if (__builtin_cpu_supports("sse2")) bitcount_function_p = &bitcount_SSE2;
            else if (__builtin_cpu_supports("mmx")) bitcount_function_p = &bitcount_MMX;
            else
#endif
                bitcount_function_p = &bitcount_NOSIMD;

    // call the most optimized function for this CPU
    return (*bitcount_function_p)(a);
}

uint32_t count_states_dispatch(uint32_t *bitarray) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) count_states_function_p = &count_states_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) count_states_function_p = &count_states_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) count_states_function_p = &count_states_AVX2;
            else if (__builtin_cpu_supports("avx")) count_states_function_p = &count_states_AVX;
            else if (__builtin_cpu_supports("sse2")) count_states_function_p = &count_states_SSE2;
            else if (__builtin_cpu_supports("mmx")) count_states_function_p = &count_states_MMX;
            else
#endif
                count_states_function_p = &count_states_NOSIMD;

    // call the most optimized function for this CPU
    return (*count_states_function_p)(bitarray);
}

void bitarray_AND_dispatch(uint32_t *A, uint32_t *B) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) bitarray_AND_function_p = &bitarray_AND_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) bitarray_AND_function_p = &bitarray_AND_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) bitarray_AND_function_p = &bitarray_AND_AVX2;
            else if (__builtin_cpu_supports("avx")) bitarray_AND_function_p = &bitarray_AND_AVX;
            else if (__builtin_cpu_supports("sse2")) bitarray_AND_function_p = &bitarray_AND_SSE2;
            else if (__builtin_cpu_supports("mmx")) bitarray_AND_function_p = &bitarray_AND_MMX;
            else
#endif
                bitarray_AND_function_p = &bitarray_AND_NOSIMD;

    // call the most optimized function for this CPU
    (*bitarray_AND_function_p)(A, B);
}

void bitarray_low20_AND_dispatch(uint32_t *A, uint32_t *B) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) bitarray_low20_AND_function_p = &bitarray_low20_AND_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) bitarray_low20_AND_function_p = &bitarray_low20_AND_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) bitarray_low20_AND_function_p = &bitarray_low20_AND_AVX2;
            else if (__builtin_cpu_supports("avx")) bitarray_low20_AND_function_p = &bitarray_low20_AND_AVX;
            else if (__builtin_cpu_supports("sse2")) bitarray_low20_AND_function_p = &bitarray_low20_AND_SSE2;
            else if (__builtin_cpu_supports("mmx")) bitarray_low20_AND_function_p = &bitarray_low20_AND_MMX;
            else
#endif
                bitarray_low20_AND_function_p = &bitarray_low20_AND_NOSIMD;

    // call the most optimized function for this CPU
    (*bitarray_low20_AND_function_p)(A, B);
}

uint32_t count_bitarray_AND_dispatch(uint32_t *A, uint32_t *B) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) count_bitarray_AND_function_p = &count_bitarray_AND_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) count_bitarray_AND_function_p = &count_bitarray_AND_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) count_bitarray_AND_function_p = &count_bitarray_AND_AVX2;
            else if (__builtin_cpu_supports("avx")) count_bitarray_AND_function_p = &count_bitarray_AND_AVX;
            else if (__builtin_cpu_supports("sse2")) count_bitarray_AND_function_p = &count_bitarray_AND_SSE2;
            else if (__builtin_cpu_supports("mmx")) count_bitarray_AND_function_p = &count_bitarray_AND_MMX;
            else
#endif
                count_bitarray_AND_function_p = &count_bitarray_AND_NOSIMD;

    // call the most optimized function for this CPU
    return (*count_bitarray_AND_function_p)(A, B);
}

uint32_t count_bitarray_low20_AND_dispatch(uint32_t *A, uint32_t *B) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_AVX2;
            else if (__builtin_cpu_supports("avx")) count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_AVX;
            else if (__builtin_cpu_supports("sse2")) count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_SSE2;
            else if (__builtin_cpu_supports("mmx")) count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_MMX;
            else
#endif
                count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_NOSIMD;

    // call the most optimized function for this CPU
    return (*count_bitarray_low20_AND_function_p)(A, B);
}

void bitarray_AND4_dispatch(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) bitarray_AND4_function_p = &bitarray_AND4_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) bitarray_AND4_function_p = &bitarray_AND4_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) bitarray_AND4_function_p = &bitarray_AND4_AVX2;
            else if (__builtin_cpu_supports("avx")) bitarray_AND4_function_p = &bitarray_AND4_AVX;
            else if (__builtin_cpu_supports("sse2")) bitarray_AND4_function_p = &bitarray_AND4_SSE2;
            else if (__builtin_cpu_supports("mmx")) bitarray_AND4_function_p = &bitarray_AND4_MMX;
            else
#endif
                bitarray_AND4_function_p = &bitarray_AND4_NOSIMD;

    // call the most optimized function for this CPU
    (*bitarray_AND4_function_p)(A, B, C, D);
}

void bitarray_OR_dispatch(uint32_t *A, uint32_t *B) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) bitarray_OR_function_p = &bitarray_OR_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) bitarray_OR_function_p = &bitarray_OR_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) bitarray_OR_function_p = &bitarray_OR_AVX2;
            else if (__builtin_cpu_supports("avx")) bitarray_OR_function_p = &bitarray_OR_AVX;
            else if (__builtin_cpu_supports("sse2")) bitarray_OR_function_p = &bitarray_OR_SSE2;
            else if (__builtin_cpu_supports("mmx")) bitarray_OR_function_p = &bitarray_OR_MMX;
            else
#endif
                bitarray_OR_function_p = &bitarray_OR_NOSIMD;

    // call the most optimized function for this CPU
    (*bitarray_OR_function_p)(A, B);
}

uint32_t count_bitarray_AND2_dispatch(uint32_t *A, uint32_t *B) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) count_bitarray_AND2_function_p = &count_bitarray_AND2_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) count_bitarray_AND2_function_p = &count_bitarray_AND2_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) count_bitarray_AND2_function_p = &count_bitarray_AND2_AVX2;
            else if (__builtin_cpu_supports("avx")) count_bitarray_AND2_function_p = &count_bitarray_AND2_AVX;
            else if (__builtin_cpu_supports("sse2")) count_bitarray_AND2_function_p = &count_bitarray_AND2_SSE2;
            else if (__builtin_cpu_supports("mmx")) count_bitarray_AND2_function_p = &count_bitarray_AND2_MMX;
            else
#endif
                count_bitarray_AND2_function_p = &count_bitarray_AND2_NOSIMD;

    // call the most optimized function for this CPU
    return (*count_bitarray_AND2_function_p)(A, B);
}

uint32_t count_bitarray_AND3_dispatch(uint32_t *A, uint32_t *B, uint32_t *C) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) count_bitarray_AND3_function_p = &count_bitarray_AND3_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) count_bitarray_AND3_function_p = &count_bitarray_AND3_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) count_bitarray_AND3_function_p = &count_bitarray_AND3_AVX2;
            else if (__builtin_cpu_supports("avx")) count_bitarray_AND3_function_p = &count_bitarray_AND3_AVX;
            else if (__builtin_cpu_supports("sse2")) count_bitarray_AND3_function_p = &count_bitarray_AND3_SSE2;
            else if (__builtin_cpu_supports("mmx")) count_bitarray_AND3_function_p = &count_bitarray_AND3_MMX;
            else
#endif
                count_bitarray_AND3_function_p = &count_bitarray_AND3_NOSIMD;

    // call the most optimized function for this CPU
    return (*count_bitarray_AND3_function_p)(A, B, C);
}

uint32_t count_bitarray_AND4_dispatch(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D) {
#if defined(COMPILER_HAS_SIMD_NEON)
    if (arm_has_neon()) count_bitarray_AND4_function_p = &count_bitarray_AND4_NEON;
    else
#endif

#if defined(COMPILER_HAS_SIMD_AVX512)
        if (__builtin_cpu_supports("avx512f")) count_bitarray_AND4_function_p = &count_bitarray_AND4_AVX512;
        else
#endif
#if defined(COMPILER_HAS_SIMD_X86)
            if (__builtin_cpu_supports("avx2")) count_bitarray_AND4_function_p = &count_bitarray_AND4_AVX2;
            else if (__builtin_cpu_supports("avx")) count_bitarray_AND4_function_p = &count_bitarray_AND4_AVX;
            else if (__builtin_cpu_supports("sse2")) count_bitarray_AND4_function_p = &count_bitarray_AND4_SSE2;
            else if (__builtin_cpu_supports("mmx")) count_bitarray_AND4_function_p = &count_bitarray_AND4_MMX;
            else
#endif
                count_bitarray_AND4_function_p = &count_bitarray_AND4_NOSIMD;

    // call the most optimized function for this CPU
    return (*count_bitarray_AND4_function_p)(A, B, C, D);
}


///////////////////////////////////////////////77
// Entries to dispatched function calls

uint32_t *malloc_bitarray(uint32_t x) {
    return (*malloc_bitarray_function_p)(x);
}

void free_bitarray(uint32_t *x) {
    (*free_bitarray_function_p)(x);
}

uint32_t bitcount(uint32_t a) {
    return (*bitcount_function_p)(a);
}

uint32_t count_states(uint32_t *A) {
    return (*count_states_function_p)(A);
}

void bitarray_AND(uint32_t *A, uint32_t *B) {
    (*bitarray_AND_function_p)(A, B);
}

void bitarray_low20_AND(uint32_t *A, uint32_t *B) {
    (*bitarray_low20_AND_function_p)(A, B);
}

uint32_t count_bitarray_AND(uint32_t *A, uint32_t *B) {
    return (*count_bitarray_AND_function_p)(A, B);
}

uint32_t count_bitarray_low20_AND(uint32_t *A, uint32_t *B) {
    return (*count_bitarray_low20_AND_function_p)(A, B);
}

void bitarray_AND4(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D) {
    (*bitarray_AND4_function_p)(A, B, C, D);
}

void bitarray_OR(uint32_t *A, uint32_t *B) {
    (*bitarray_OR_function_p)(A, B);
}

uint32_t count_bitarray_AND2(uint32_t *A, uint32_t *B) {
    return (*count_bitarray_AND2_function_p)(A, B);
}

uint32_t count_bitarray_AND3(uint32_t *A, uint32_t *B, uint32_t *C) {
    return (*count_bitarray_AND3_function_p)(A, B, C);
}

uint32_t count_bitarray_AND4(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D) {
    return (*count_bitarray_AND4_function_p)(A, B, C, D);
}

#endif

