# vec

Source: https://github.com/aklomp/vec

[![Build](https://github.com/aklomp/vec/actions/workflows/test.yml/badge.svg)](https://github.com/aklomp/vec/actions/workflows/test.yml)

A small, header-only, cross-platform SIMD vector library for C11. Provides an
abstraction of 128-bit vectors divided into four 32-bit elements, which can be
floating or integer. Does this using a clever `union` type. Oriented mainly
towards 3D graphics, but can be used for any type of 32×4 bit vector.

## Usage

This library is header-only, meaning that there is no code to compile, just a
single header file to include. This header file is `include/vec/vec.h`. Include
that file into your source code and you can use the library.

(That file will conditionally pull in a number of platform-specific files from
a subdirectory, but that all happens invisibly in the background.)

In general, this library will be included in other projects as a Git
subrepository. The project's build environment should be configured to add the
following search path to `CFLAGS`:

```make
CFLAGS += -I path/to/vec/include
```

Now you can include the library as:

```c
#include <vec/vec.h>
```

The library's backend has support for the following vector formats, in order of
preference from highest to lowest:

- On x86: SSE4 SIMD operations.
- On x86: SSE2 SIMD operations.
- On ARM: NEON SIMD operations (NEON32) using inline assembly.
- On ARM: NEON SIMD operations (NEON32) using intrinsics.
- On GCC or Clang, if new enough: GCC-style vector extensions. These are
  "generic" cross-platform vector types that are not tied to any one hardware
  implementation. The compiler turns these into appropriate SIMD instructions
  for the platform.
- The old-fashioned way: all operations are done separately on each of the four
  elements of the union. This uses only plain C and should work on all
  platforms.

Support for these vector formats is detected at compile time by testing
predefined compiler macros. The backends with higher preference are "allowed"
to define a given function first. Those with lower preference fill in the
functions that haven't yet been defined. The generic backend acts as a backstop
and defines all functions that have not been defined.

## Data structure

The basic data structure is the `union vec`. As the name implies, this is a C
union that wraps a 128-bit data structure which is internally divided into four
32-bit elements. Depending on context, these elements can be interpreted as
32-bit floats, 32-bit signed ints, 32-bit unsigned ints, or as a single 128-bit
SIMD vector with four independent lanes.

The charm of the `union vec` is that it allows us to access the same underlying
bits *as if* it's any of these data types, in a relatively typesafe way. In the
same line of code, the `union vec` can be treated as an array of floating point
elements, or as a single SIMD register.

The abstraction is invisible and seamless to the programmer, because the
compiler will transparently handle the different views of memory. Aliasing
memory through a union is quite cheap because no type conversion is performed.
We merely look at the same bits in memory through different glasses. Compilers
and processors have good support for that kind of access.

`union vec` provides the following ways of interpreting 16 bytes of memory:

```c
// Declare a variable for demo purposes:
union vec vec;

// As a series of four named 32-bit floating-point variables,
// named to match 3D graphics vectors (the common use case):
float vec.x, vec.y, vec.z, vec.w;

// As a series of four named 32-bit signed integer variables:
int32_t vec.xi, vec.yi, vec.zi, vec.wi;

// As a series of four named 32-bit unsigned integer variables:
uint32_t vec.xu, vec.yu, vec.zu, vec.wu;

// As arrays of four 32-bit floating-point, signed integer
// and unsigned integer variables:
float    vec.elem.f[4];
int32_t  vec.elem.i[4];
uint32_t vec.elem.u[4];

// If GCC-style portable vector extensions are available, we
// define vector extension typedefs called 'vec4f', 'vec4i'
// and 'vec4u', and define the following extra aliases:
vec4f vec.gcc.f;
vec4i vec.gcc.i;
vec4u vec.gcc.u;

// If x86_64 SSE2 is available, the following extra aliases
// are available (i and u are functionally identical):
__m128  vec.sse.f;
__m128i vec.sse.i;
__m128i vec.sse.u;

// If ARM NEON is available, the following extra aliases are
// available:
float32x4_t vec.neon.f;
int32x4_t   vec.neon.i;
uint32x4_t  vec.neon.u;
```

## Instantiation

Macros are available for compile-time static initialization of vectors. Use
these for hard-coded, static values.

```c
// Create a floating-point vector:
union vec a = VEC(1.0f, 2.0f, 3.0f, 4.0f);

// Alternatively, for floating-point, it is possible to use union
// initialization syntax directly:
union vec b = { { 1.0f, 2.0f, 3.0f, 4.0f } };

// Create a signed integer vector:
union vec c = VEC_I(-2, -1, 0, 1);

// Create an unsigned integer vector:
union vec d = VEC_U(1, 2, 3, 4);
```

To instantiate an `union vec` at runtime from constant literals or other
variables, use the provided inline functions.

```c
// Create a floating-point vector:
static inline union vec
vec (const float x, const float y, const float z, const float w);

// Create a signed integer vector:
static inline union vec
vec_i (const int32_t x, const int32_t y, const int32_t z, const int32_t w);

// Create an unsigned integer vector:
static inline union vec
vec_u (const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t w);
```

```c
// Create a vector set to all zeros, valid for all numeric types:
static inline union vec
vec_zero (void);
```

```c
// Create a floating-point vector with four identical elements:
static inline union vec
vec_1 (const float val);

// Create a signed integer vector with four identical elements:
static inline union vec
vec_i1 (const int32_t val);

// Create an unsigned integer vector with four identical elements:
static inline union vec
vec_u1 (const uint32_t val);
```

## Conversion

Functions are available to convert floats to signed integers and vice versa.

```c
// Convert a float vector to signed integer:
static inline union vec
vec_to_int (const union vec v);

// Convert a signed integer vector to float:
static inline union vec
vec_to_float (const union vec v);
```

## Arithmetic

Addition, subtraction, multiplication and division are available.
Multiplication and division are only supported for floats because SIMD
instruction sets have spotty support for these operations on integers. If you
need integer multiplications or divisions, convert to float, do the float
operation, and convert back.

```c
// Floating-point addition (a + b):
static inline union vec
vec_add (const union vec a, const union vec b);

// Signed integer addition (a + b):
static inline union vec
vec_iadd (const union vec a, const union vec b);

// Unsigned integer addition (a + b):
static inline union vec
vec_uadd (const union vec a, const union vec b);
```

```c
// Floating-point subtraction (a - b):
static inline union vec
vec_sub (const union vec a, const union vec b);

// Signed integer subtraction (a - b):
static inline union vec
vec_isub (const union vec a, const union vec b);

// Unsigned integer subtraction (a - b):
static inline union vec
vec_usub (const union vec a, const union vec b);
```

```c
// Floating-point multiplication (a * b):
static inline union vec
vec_mul (const union vec a, const union vec b);
```

```c
// Floating-point division (a / b):
static inline union vec
vec_div (const union vec a, const union vec b);
```

## Bitwise logic

The bitwise logical functions `AND`, `NOT`, `OR` and `XOR` are available. These
operate on the unsigned integer representation.

```c
// Bitwise a AND b:
static inline union vec
vec_and (const union vec a, const union vec b);

// Bitwise a OR b:
static inline union vec
vec_or (const union vec a, const union vec b);

// Bitwise a XOR b:
static inline union vec
vec_xor (const union vec a, const union vec b);

// Bitwise NOT a:
static inline union vec
vec_not (const union vec a);
```

## Comparisons

Comparison functions are available for all operand types. These functions
return a `union vec` where each 32-bit lane is all-ones (`0xFFFFFFFF`) if the
comparison is true for those lanes in the source vectors, or all-zeros if the
comparison is false. This "masking" vector can be used in combination with the
bitwise logical functions to construct new vectors.

```c
// Floating-point test of a < b:
static inline union vec
vec_lt (const union vec a, const union vec b);

// Signed integer test of a < b:
static inline union vec
vec_ilt (const union vec a, const union vec b);

// Unsigned integer test of a < b:
static inline union vec
vec_ult (const union vec a, const union vec b);
```

```c
// Floating-point test of a <= b:
static inline union vec
vec_le (const union vec a, const union vec b);

// Signed integer test of a <= b:
static inline union vec
vec_ile (const union vec a, const union vec b);

// Unsigned integer test of a <= b:
static inline union vec
vec_ule (const union vec a, const union vec b);
```

```c
// Floating-point test of a == b:
static inline union vec
vec_eq (const union vec a, const union vec b);

// Signed integer test of a == b:
static inline union vec
vec_ieq (const union vec a, const union vec b);

// Unsigned integer test of a == b:
static inline union vec
vec_ueq (const union vec a, const union vec b);
```

```c
// Floating-point test of a >= b:
static inline union vec
vec_ge (const union vec a, const union vec b);

// Signed integer test of a >= b:
static inline union vec
vec_ige (const union vec a, const union vec b);

// Unsigned integer test of a >= b:
static inline union vec
vec_uge (const union vec a, const union vec b);
```

```c
// Floating-point test of a > b:
static inline union vec
vec_gt (const union vec a, const union vec b);

// Signed integer test of a > b:
static inline union vec
vec_igt (const union vec a, const union vec b);

// Unsigned integer test of a > b:
static inline union vec
vec_ugt (const union vec a, const union vec b);
```

## 3D vector operations

Dot and cross product functions are available for 3D vectors in (x, y, z, w)
format. These functions are only available for floating point operands.

```c
// Dot product of a and b:
//   ret = ax * bx + ay * by + az * bz
static inline float
vec_dot (const union vec a, const union vec b);
```

```c
// Cross product of a and b:
//   x = ay * bz - az * by
//   y = az * bx - ax * bz
//   z = ax * by - ay * bx
//   w = 0
static inline union vec
vec_cross (const union vec a, const union vec b);
```

## Testing

An extensive test suite can be found in `test/`. Typing `make test` in that
directory will compile and run three binaries: one with only the generic
per-element routines, one with GCC vector extension routines enabled but not
SIMD, and one with SIMD routines enabled. If all tests pass, a binary will run
cleanly without any output and return zero. On error, it will print diagnostics
and return nonzero. This library has been tested on all supported platforms.

Automated tests are run on every commit by [Travis CI](https://travis-ci.org/aklomp/vec).

[![Build Status](https://travis-ci.org/aklomp/vec.svg)](https://travis-ci.org/aklomp/vec)

## License

MIT license. See `LICENSE` file for details.
