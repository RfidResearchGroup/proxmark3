// Return float version of a + b:
#ifndef VEC_FN_ADD
#define VEC_FN_ADD
static inline union vec
vec_add (const union vec a, const union vec b)
{
	return (union vec) { .gcc.f = a.gcc.f + b.gcc.f };
}
#endif

// Return signed integer version of a + b:
#ifndef VEC_FN_IADD
#define VEC_FN_IADD
static inline union vec
vec_iadd (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.i + b.gcc.i };
}
#endif

// Return unsigned integer version of a + b:
#ifndef VEC_FN_UADD
#define VEC_FN_UADD
static inline union vec
vec_uadd (const union vec a, const union vec b)
{
	return (union vec) { .gcc.u = a.gcc.u + b.gcc.u };
}
#endif

// Return float version of a - b:
#ifndef VEC_FN_SUB
#define VEC_FN_SUB
static inline union vec
vec_sub (const union vec a, const union vec b)
{
	return (union vec) { .gcc.f = a.gcc.f - b.gcc.f };
}
#endif

// Return signed integer version of a - b:
#ifndef VEC_FN_ISUB
#define VEC_FN_ISUB
static inline union vec
vec_isub (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.i - b.gcc.i };
}
#endif

// Return unsigned integer version of a - b:
#ifndef VEC_FN_USUB
#define VEC_FN_USUB
static inline union vec
vec_usub (const union vec a, const union vec b)
{
	return (union vec) { .gcc.u = a.gcc.u - b.gcc.u };
}
#endif

// Return float version of a * b:
#ifndef VEC_FN_MUL
#define VEC_FN_MUL
static inline union vec
vec_mul (const union vec a, const union vec b)
{
	return (union vec) { .gcc.f = a.gcc.f * b.gcc.f };
}
#endif

// Return float version of a / b:
#ifndef VEC_FN_DIV
#define VEC_FN_DIV
static inline union vec
vec_div (const union vec a, const union vec b)
{
	return (union vec) { .gcc.f = a.gcc.f / b.gcc.f };
}
#endif

// Return bitwise a AND b:
#ifndef VEC_FN_AND
#define VEC_FN_AND
static inline union vec
vec_and (const union vec a, const union vec b)
{
	return (union vec) { .gcc.u = a.gcc.u & b.gcc.u };
}
#endif

// Return bitwise a OR b:
#ifndef VEC_FN_OR
#define VEC_FN_OR
static inline union vec
vec_or (const union vec a, const union vec b)
{
	return (union vec) { .gcc.u = a.gcc.u | b.gcc.u };
}
#endif

// Return bitwise a XOR b:
#ifndef VEC_FN_XOR
#define VEC_FN_XOR
static inline union vec
vec_xor (const union vec a, const union vec b)
{
	return (union vec) { .gcc.u = a.gcc.u ^ b.gcc.u };
}
#endif

// Return bitwise NOT v:
#ifndef VEC_FN_NOT
#define VEC_FN_NOT
static inline union vec
vec_not (const union vec v)
{
	return (union vec) { .gcc.u = ~v.gcc.u };
}
#endif

// GCC added support for vector comparisons in version 4.8:
#ifdef __GNUC__
  #if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)
    #define VEC_GCC_COMPARE
  #endif
#else

  // Assume we're using clang - it's supported vector comparisons since at
  // least version 3.0, possibly earlier:
  #define VEC_GCC_COMPARE
#endif

// Return float version of a == b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_EQ 
#define VEC_FN_EQ
static inline union vec
vec_eq (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.f == b.gcc.f };
}
#endif
#endif

// Return signed integer version of a == b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_IEQ
#define VEC_FN_IEQ
static inline union vec
vec_ieq (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.i == b.gcc.i };
}
#endif
#endif

// Return float version of a == b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_UEQ
#define VEC_FN_UEQ
static inline union vec
vec_ueq (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.u == b.gcc.u };
}
#endif
#endif

// Return float version of a < b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_LT
#define VEC_FN_LT
static inline union vec
vec_lt (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.f < b.gcc.f };
}
#endif
#endif

// Return signed integer version of a < b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_ILT
#define VEC_FN_ILT
static inline union vec
vec_ilt (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.i < b.gcc.i };
}
#endif
#endif

// Return unsigned integer version of a < b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_ULT
#define VEC_FN_ULT
static inline union vec
vec_ult (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.u < b.gcc.u };
}
#endif
#endif

// Return float version of a <= b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_LE
#define VEC_FN_LE
static inline union vec
vec_le (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.f <= b.gcc.f };
}
#endif
#endif

// Return signed integer version of a <= b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_ILE
#define VEC_FN_ILE
static inline union vec
vec_ile (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.i <= b.gcc.i };
}
#endif
#endif

// Return unsigned integer version of a <= b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_ULE
#define VEC_FN_ULE
static inline union vec
vec_ule (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.u <= b.gcc.u };
}
#endif
#endif

// Return float version of a > b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_GT
#define VEC_FN_GT
static inline union vec
vec_gt (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.f > b.gcc.f };
}
#endif
#endif

// Return signed integer version of a > b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_IGT
#define VEC_FN_IGT
static inline union vec
vec_igt (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.i > b.gcc.i };
}
#endif
#endif

// Return unsigned integer version of a > b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_UGT
#define VEC_FN_UGT
static inline union vec
vec_ugt (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.u > b.gcc.u };
}
#endif
#endif

// Return float version of a >= b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_GE
#define VEC_FN_GE
static inline union vec
vec_ge (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.f >= b.gcc.f };
}
#endif
#endif

// Return signed integer version of a >= b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_IGE
#define VEC_FN_IGE
static inline union vec
vec_ige (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.i >= b.gcc.i };
}
#endif
#endif

// Return unsigned integer version of a >= b:
#ifdef VEC_GCC_COMPARE
#ifndef VEC_FN_UGE
#define VEC_FN_UGE
static inline union vec
vec_uge (const union vec a, const union vec b)
{
	return (union vec) { .gcc.i = a.gcc.u >= b.gcc.u };
}
#endif
#endif
