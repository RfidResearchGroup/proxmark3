#pragma once

#include <stdint.h>

// GCC-style vector extensions work with Clang >= 3 or GCC >= 4.0:
#if !defined(VEC_SUPPRESS_GCC)
  #if __GNUC__ >= 4 || __clang_major__ >= 3
    #define VEC_GCC
  #endif
#endif

// For testing purposes, allow the user to bypass any platform-specific support
// and to use only the generic functions:
#if !defined(VEC_SUPPRESS_HW)

  // Check for SSE support:
  #if defined(__SSE2__)
    #define VEC_SSE2
    #include <emmintrin.h>
  #endif

  // Check for SSE4 support:
  #if defined(__SSE4_1__)
    #define VEC_SSE41
    #include <nmmintrin.h>
  #endif

  // Check for ARM NEON support:
  #if defined(__ARM_NEON__) || defined(__ARM_NEON)
    #define VEC_NEON
    #include <arm_neon.h>

    // GCC and Clang support inline assembly:
    #if defined(__GNUC__) || defined(__clang_major__)
      #define VEC_NEON_ASM
    #endif
  #endif
#endif

// Define architecture-independent vector types.
// This syntax is valid for GCC and LLVM/Clang:
#if defined(VEC_GCC)
typedef float    vec4f __attribute__ ((vector_size (16), aligned (16)));
typedef int32_t  vec4i __attribute__ ((vector_size (16), aligned (16)));
typedef uint32_t vec4u __attribute__ ((vector_size (16), aligned (16)));
#endif

// Union to represent a 4x32-bit (128-bit) vector in various ways:
union vec {

	// Named member representation in float form, assuming a 3D vector:
	struct {
		float x;
		float y;
		float z;
		float w;
	};

	// Named member representation in signed integer form:
	struct {
		int32_t xi;
		int32_t yi;
		int32_t zi;
		int32_t wi;
	};

	// Named member representation in unsigned integer form:
	struct {
		uint32_t xu;
		uint32_t yu;
		uint32_t zu;
		uint32_t wu;
	};

	// Representation as array of separate elements:
	union {
		float    f[4];
		int32_t  i[4];
		uint32_t u[4];
	} elem;

	// Representation as GCC-style vector extensions:
#if defined(VEC_GCC)
	union {
		vec4f f;
		vec4i i;
		vec4u u;
	} gcc;
#endif

	// SSE representation:
#if defined(VEC_SSE2)
	union {
		__m128  f;
		__m128i i;
		__m128i u;
	} sse;
#endif

	// NEON representation:
#if defined(VEC_NEON)
	union {
		float32x4_t f;
		int32x4_t   i;
		uint32x4_t  u;
	} neon;
#endif
};

// Compile-time constant instantiation macros:
#define VEC(a, b, c, d) \
	((union vec) { .elem.f = { (a), (b), (c), (d) } })

#define VEC_I(a, b, c, d) \
	((union vec) { .elem.i = { (a), (b), (c), (d) } })

#define VEC_U(a, b, c, d) \
	((union vec) { .elem.u = { (a), (b), (c), (d) } })

// Include platform-specific function definitions. The most "powerful"
// definitions come first and get a chance to declare functions. What they
// cannot define will eventually be defined by a "less powerful" file. The
// generic file acts as a catch-all in case none of the more powerful methods
// are available.

#if defined(VEC_SSE41)
  #include "private/sse41.h"
#endif

#if defined(VEC_SSE2)
  #include "private/sse2.h"
#endif

#if defined(VEC_NEON_ASM)
  #include "private/neon_asm.h"
#endif

#if defined(VEC_NEON)
  #include "private/neon_intrin.h"
#endif

#if defined(VEC_GCC)
  #include "private/gcc.h"
#endif

#include "private/generic.h"
