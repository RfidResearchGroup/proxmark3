// Instantiate a float vector:
#ifndef VEC_FN_
#define VEC_FN_
static inline union vec
vec (const float x, const float y, const float z, const float w)
{
	return (union vec) { .sse.f = _mm_setr_ps(x, y, z, w) };
}
#endif

// Instantiate a signed integer vector:
#ifndef VEC_FN_I
#define VEC_FN_I
static inline union vec
vec_i (const int32_t x, const int32_t y, const int32_t z, const int32_t w)
{
	return (union vec) { .sse.i = _mm_setr_epi32(x, y, z, w) };
}
#endif

// Instantiate an unsigned integer vector:
#ifndef VEC_FN_U
#define VEC_FN_U
static inline union vec
vec_u (const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t w)
{
	return vec_i((int32_t) x, (int32_t) y, (int32_t) z, (int32_t) w);
}
#endif

// Instantiate a float vector with four identical elements:
#ifndef VEC_FN_1
#define VEC_FN_1
static inline union vec
vec_1 (const float val)
{
	return (union vec) { .sse.f = _mm_set1_ps(val) };
}
#endif

// Instantiate a signed integer vector with four identical elements:
#ifndef VEC_FN_I1
#define VEC_FN_I1
static inline union vec
vec_i1 (const int32_t val)
{
	return (union vec) { .sse.i = _mm_set1_epi32(val) };
}
#endif

// Instantiate an unsigned integer vector with four identical elements:
#ifndef VEC_FN_U1
#define VEC_FN_U1
static inline union vec
vec_u1 (const uint32_t val)
{
	return vec_i1((int32_t) val);
}
#endif

// Instantiate a float vector set to all zeros:
#ifndef VEC_FN_ZERO
#define VEC_FN_ZERO
static inline union vec
vec_zero (void)
{
	return (union vec) { .sse.f = _mm_setzero_ps() };
}
#endif

// Instantiate a signed integer vector set to all zeros:
#ifndef VEC_FN_IZERO
#define VEC_FN_IZERO
static inline union vec
vec_izero (void)
{
	return (union vec) { .sse.i = _mm_setzero_si128() };
}
#endif

// Instantiate an unsigned integer vector set to all zeros:
#ifndef VEC_FN_UZERO
#define VEC_FN_UZERO
static inline union vec
vec_uzero (void)
{
	return vec_izero();
}
#endif

// Convert a float vector to signed integer:
#ifndef VEC_FN_TO_INT
#define VEC_FN_TO_INT
static inline union vec
vec_to_int (const union vec v)
{
	return (union vec) { .sse.i = _mm_cvttps_epi32(v.sse.f) };
}
#endif

// Convert a signed integer vector to float:
#ifndef VEC_FN_TO_FLOAT
#define VEC_FN_TO_FLOAT
static inline union vec
vec_to_float (const union vec v)
{
	return (union vec) { .sse.f = _mm_cvtepi32_ps(v.sse.i) };
}
#endif

// Return float version of a + b:
#ifndef VEC_FN_ADD
#define VEC_FN_ADD
static inline union vec
vec_add (const union vec a, const union vec b)
{
	return (union vec) { .sse.f = _mm_add_ps(a.sse.f, b.sse.f) };
}
#endif

// Return signed integer version of a + b:
#ifndef VEC_FN_IADD
#define VEC_FN_IADD
static inline union vec
vec_iadd (const union vec a, const union vec b)
{
	return (union vec) { .sse.i = _mm_add_epi32(a.sse.i, b.sse.i) };
}
#endif

// Return unsigned integer version of a + b:
#ifndef VEC_FN_UADD
#define VEC_FN_UADD
static inline union vec
vec_uadd (const union vec a, const union vec b)
{
	return vec_iadd(a, b);
}
#endif

// Return float version of a - b:
#ifndef VEC_FN_SUB
#define VEC_FN_SUB
static inline union vec
vec_sub (const union vec a, const union vec b)
{
	return (union vec) { .sse.f = _mm_sub_ps(a.sse.f, b.sse.f) };
}
#endif

// Return signed integer version of a - b:
#ifndef VEC_FN_ISUB
#define VEC_FN_ISUB
static inline union vec
vec_isub (const union vec a, const union vec b)
{
	return (union vec) { .sse.i = _mm_sub_epi32(a.sse.i, b.sse.i) };
}
#endif

// Return unsigned integer version of a - b:
#ifndef VEC_FN_USUB
#define VEC_FN_USUB
static inline union vec
vec_usub (const union vec a, const union vec b)
{
	return vec_isub(a, b);
}
#endif

// Return float version of a * b:
#ifndef VEC_FN_MUL
#define VEC_FN_MUL
static inline union vec
vec_mul (const union vec a, const union vec b)
{
	return (union vec) { .sse.f = _mm_mul_ps(a.sse.f, b.sse.f) };
}
#endif

// Return float version of a / b:
#ifndef VEC_FN_DIV
#define VEC_FN_DIV
static inline union vec
vec_div (const union vec a, const union vec b)
{
	return (union vec) { .sse.f = _mm_div_ps(a.sse.f, b.sse.f) };
}
#endif

// Return bitwise a AND b:
#ifndef VEC_FN_AND
#define VEC_FN_AND
static inline union vec
vec_and (const union vec a, const union vec b)
{
	return (union vec) { .sse.u = _mm_and_si128(a.sse.u, b.sse.u) };
}
#endif

// Return bitwise a OR b:
#ifndef VEC_FN_OR
#define VEC_FN_OR
static inline union vec
vec_or (const union vec a, const union vec b)
{
	return (union vec) { .sse.u = _mm_or_si128(a.sse.u, b.sse.u) };
}
#endif

// Return bitwise a XOR b:
#ifndef VEC_FN_XOR
#define VEC_FN_XOR
static inline union vec
vec_xor (const union vec a, const union vec b)
{
	return (union vec) { .sse.u = _mm_xor_si128(a.sse.u, b.sse.u) };
}
#endif

// Return bitwise NOT v:
#ifndef VEC_FN_NOT
#define VEC_FN_NOT
static inline union vec
vec_not (const union vec v)
{
	const __m128i allset = _mm_set1_epi32(INT32_C(0xFFFFFFFF));

	return (union vec) { .sse.u = _mm_xor_si128(v.sse.u, allset) };
}
#endif

// Return float version of a == b:
#ifndef VEC_FN_EQ
#define VEC_FN_EQ
static inline union vec
vec_eq (const union vec a, const union vec b)
{
	return (union vec) { .sse.f = _mm_cmpeq_ps(a.sse.f, b.sse.f) };
}
#endif

// Return signed integer version of a == b:
#ifndef VEC_FN_IEQ
#define VEC_FN_IEQ
static inline union vec
vec_ieq (const union vec a, const union vec b)
{
	return (union vec) { .sse.i = _mm_cmpeq_epi32(a.sse.i, b.sse.i) };
}
#endif

// Return float version of a == b:
#ifndef VEC_FN_UEQ
#define VEC_FN_UEQ
static inline union vec
vec_ueq (const union vec a, const union vec b)
{
	return (union vec) { .sse.u = _mm_cmpeq_epi32(a.sse.u, b.sse.u) };
}
#endif

// Return float version of a < b:
#ifndef VEC_FN_LT
#define VEC_FN_LT
static inline union vec
vec_lt (const union vec a, const union vec b)
{
	return (union vec) { .sse.f = _mm_cmplt_ps(a.sse.f, b.sse.f) };
}
#endif

// Return signed integer version of a < b:
#ifndef VEC_FN_ILT
#define VEC_FN_ILT
static inline union vec
vec_ilt (const union vec a, const union vec b)
{
	return (union vec) { .sse.i = _mm_cmplt_epi32(a.sse.i, b.sse.i) };
}
#endif

// Return unsigned integer version of a < b:
#ifndef VEC_FN_ULT
#define VEC_FN_ULT
static inline union vec
vec_ult (const union vec a, const union vec b)
{
	const __m128i bias = _mm_set1_epi32(INT32_C(0x80000000));

	return (union vec) { .sse.i = _mm_cmplt_epi32(
		_mm_sub_epi32(a.sse.i, bias),
		_mm_sub_epi32(b.sse.i, bias)) };
}
#endif

// Return float version of a <= b:
#ifndef VEC_FN_LE
#define VEC_FN_LE
static inline union vec
vec_le (const union vec a, const union vec b)
{
	return (union vec) { .sse.f = _mm_cmple_ps(a.sse.f, b.sse.f) };
}
#endif

// Return signed integer version of a <= b:
#ifndef VEC_FN_ILE
#define VEC_FN_ILE
static inline union vec
vec_ile (const union vec a, const union vec b)
{
	return (union vec) { .sse.i = _mm_or_si128(
		_mm_cmplt_epi32(a.sse.i, b.sse.i),
		_mm_cmpeq_epi32(a.sse.i, b.sse.i)) };
}
#endif

// Return unsigned integer version of a <= b:
#ifndef VEC_FN_ULE
#define VEC_FN_ULE
static inline union vec
vec_ule (const union vec a, const union vec b)
{
	return vec_or(vec_ult(a, b), vec_ueq(a, b));
}
#endif

// Return float version of a > b:
#ifndef VEC_FN_GT
#define VEC_FN_GT
static inline union vec
vec_gt (const union vec a, const union vec b)
{
	return (union vec) { .sse.f = _mm_cmpgt_ps(a.sse.f, b.sse.f) };
}
#endif

// Return signed integer version of a > b:
#ifndef VEC_FN_IGT
#define VEC_FN_IGT
static inline union vec
vec_igt (const union vec a, const union vec b)
{
	return (union vec) { .sse.i = _mm_cmpgt_epi32(a.sse.i, b.sse.i) };
}
#endif

// Return unsigned integer version of a > b:
#ifndef VEC_FN_UGT
#define VEC_FN_UGT
static inline union vec
vec_ugt (const union vec a, const union vec b)
{
	const __m128i bias = _mm_set1_epi32(INT32_C(0x80000000));

	return (union vec) { .sse.i = _mm_cmpgt_epi32(
		_mm_sub_epi32(a.sse.i, bias),
		_mm_sub_epi32(b.sse.i, bias)) };
}
#endif

// Return float version of a >= b:
#ifndef VEC_FN_GE
#define VEC_FN_GE
static inline union vec
vec_ge (const union vec a, const union vec b)
{
	return (union vec) { .sse.f = _mm_cmpge_ps(a.sse.f, b.sse.f) };
}
#endif

// Return signed integer version of a >= b:
#ifndef VEC_FN_IGE
#define VEC_FN_IGE
static inline union vec
vec_ige (const union vec a, const union vec b)
{
	return (union vec) { .sse.i = _mm_or_si128(
		_mm_cmpgt_epi32(a.sse.i, b.sse.i),
		_mm_cmpeq_epi32(a.sse.i, b.sse.i)) };
}
#endif

// Return unsigned integer version of a >= b:
#ifndef VEC_FN_UGE
#define VEC_FN_UGE
static inline union vec
vec_uge (const union vec a, const union vec b)
{
	return vec_or(vec_ugt(a, b), vec_ueq(a, b));
}
#endif

// Return dot product of two 3D vectors:
#ifndef VEC_FN_DOT
#define VEC_FN_DOT
static inline float
vec_dot (const union vec a, const union vec b)
{
	const __m128 mulx = _mm_mul_ps(a.sse.f, b.sse.f);
	const __m128 muly = _mm_shuffle_ps(mulx, mulx, _MM_SHUFFLE(0, 0, 0, 1));
	const __m128 mulz = _mm_shuffle_ps(mulx, mulx, _MM_SHUFFLE(0, 0, 0, 2));
	const __m128 sum  = _mm_add_ps(mulx, _mm_add_ps(muly, mulz));

	// Extract first element:
	return ((union vec) { .xi = _mm_cvtsi128_si32(_mm_castps_si128(sum)) }).x;
}
#endif

// Return cross product of two 3D vectors:
#ifndef VEC_FN_CROSS
#define VEC_FN_CROSS
static inline union vec
vec_cross (const union vec a, const union vec b)
{
	// Shuffle a:
	const __m128 ayzx = _mm_shuffle_ps(a.sse.f, a.sse.f, _MM_SHUFFLE(0, 0, 2, 1));
	const __m128 azxy = _mm_shuffle_ps(a.sse.f, a.sse.f, _MM_SHUFFLE(0, 1, 0, 2));

	// Shuffle b:
	const __m128 byzx = _mm_shuffle_ps(b.sse.f, b.sse.f, _MM_SHUFFLE(0, 0, 2, 1));
	const __m128 bzxy = _mm_shuffle_ps(b.sse.f, b.sse.f, _MM_SHUFFLE(0, 1, 0, 2));

	// (ay * bz), (az * bx), (ax * by), (ax * bx):
	const __m128 mul1 = _mm_mul_ps(ayzx, bzxy);

	// (az * by), (ax * bz), (ay * bx), (ax * bx):
	const __m128 mul2 = _mm_mul_ps(azxy, byzx);

	return (union vec) { .sse.f = _mm_sub_ps(mul1, mul2) };
}
#endif
