// Instantiate a float vector:
#ifndef VEC_FN_
#define VEC_FN_
static inline union vec
vec (const float x, const float y, const float z, const float w)
{
	union {
		float    i[2];
		uint64_t u;
	} lo = { { x, y } }
	, hi = { { z, w } };

	return (union vec) { .neon.f = vcombine_f32(vcreate_f32(lo.u), vcreate_f32(hi.u)) };
}
#endif

// Instantiate a signed integer vector:
#ifndef VEC_FN_I
#define VEC_FN_I
static inline union vec
vec_i (const int32_t x, const int32_t y, const int32_t z, const int32_t w)
{
	union {
		int32_t  i[2];
		uint64_t u;
	} lo = { { x, y } }
	, hi = { { z, w } };

	return (union vec) { .neon.i = vcombine_s32(vcreate_s32(lo.u), vcreate_s32(hi.u)) };
}
#endif

// Instantiate an unsigned integer vector:
#ifndef VEC_FN_U
#define VEC_FN_U
static inline union vec
vec_u (const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t w)
{
	union {
		uint32_t i[2];
		uint64_t u;
	} lo = { { x, y } }
	, hi = { { z, w } };

	return (union vec) { .neon.u = vcombine_u32(vcreate_u32(lo.u), vcreate_u32(hi.u)) };
}
#endif

// Instantiate a float vector with four identical elements:
#ifndef VEC_FN_1
#define VEC_FN_1
static inline union vec
vec_1 (const float val)
{
	return (union vec) { .neon.f = vdupq_n_f32(val) };
}
#endif

// Instantiate a signed integer vector with four identical elements:
#ifndef VEC_FN_I1
#define VEC_FN_I1
static inline union vec
vec_i1 (const int32_t val)
{
	return (union vec) { .neon.i = vdupq_n_s32(val) };
}
#endif

// Instantiate an unsigned integer vector with four identical elements:
#ifndef VEC_FN_U1
#define VEC_FN_U1
static inline union vec
vec_u1 (const uint32_t val)
{
	return (union vec) { .neon.u = vdupq_n_u32(val) };
}
#endif

// Instantiate a float vector set to all zeros:
#ifndef VEC_FN_ZERO
#define VEC_FN_ZERO
static inline union vec
vec_zero (void)
{
	return vec_1(0.0f);
}
#endif

// Instantiate a signed integer vector set to all zeros:
#ifndef VEC_FN_IZERO
#define VEC_FN_IZERO
static inline union vec
vec_izero (void)
{
	return vec_i1(0);
}
#endif

// Instantiate an unsigned integer vector set to all zeros:
#ifndef VEC_FN_UZERO
#define VEC_FN_UZERO
static inline union vec
vec_uzero (void)
{
	return vec_u1(0U);
}
#endif

// Convert a float vector to signed integer:
#ifndef VEC_FN_TO_INT
#define VEC_FN_TO_INT
static inline union vec
vec_to_int (const union vec v)
{
	return (union vec) { .neon.i = vcvtq_s32_f32(v.neon.f) };
}
#endif

// Convert a signed integer vector to float:
#ifndef VEC_FN_TO_FLOAT
#define VEC_FN_TO_FLOAT
static inline union vec
vec_to_float (const union vec v)
{
	return (union vec) { .neon.f = vcvtq_f32_s32(v.neon.i) };
}
#endif

// Return float version of a + b:
#ifndef VEC_FN_ADD
#define VEC_FN_ADD
static inline union vec
vec_add (const union vec a, const union vec b)
{
	return (union vec) { .neon.f = vaddq_f32(a.neon.f, b.neon.f) };
}
#endif

// Return signed integer version of a + b:
#ifndef VEC_FN_IADD
#define VEC_FN_IADD
static inline union vec
vec_iadd (const union vec a, const union vec b)
{
	return (union vec) { .neon.i = vaddq_s32(a.neon.i, b.neon.i) };
}
#endif

// Return unsigned integer version of a + b:
#ifndef VEC_FN_UADD
#define VEC_FN_UADD
static inline union vec
vec_uadd (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vaddq_u32(a.neon.u, b.neon.u) };
}
#endif

// Return float version of a - b:
#ifndef VEC_FN_SUB
#define VEC_FN_SUB
static inline union vec
vec_sub (const union vec a, const union vec b)
{
	return (union vec) { .neon.f = vsubq_f32(a.neon.f, b.neon.f) };
}
#endif

// Return signed integer version of a - b:
#ifndef VEC_FN_ISUB
#define VEC_FN_ISUB
static inline union vec
vec_isub (const union vec a, const union vec b)
{
	return (union vec) { .neon.i = vsubq_s32(a.neon.i, b.neon.i) };
}
#endif

// Return unsigned integer version of a - b:
#ifndef VEC_FN_USUB
#define VEC_FN_USUB
static inline union vec
vec_usub (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vsubq_u32(a.neon.u, b.neon.u) };
}
#endif

// Return float version of a * b:
#ifndef VEC_FN_MUL
#define VEC_FN_MUL
static inline union vec
vec_mul (const union vec a, const union vec b)
{
	return (union vec) { .neon.f = vmulq_f32(a.neon.f, b.neon.f) };
}
#endif

// Return float version of a / b (intrinsics version):
#ifndef VEC_FN_DIV
#define VEC_FN_DIV
static inline union vec
vec_div (const union vec a, const union vec b)
{
	// Estimate reciprocal of b:
	float32x4_t recp = vrecpeq_f32(b.neon.f);

	// Refine the estimate using Newton-Raphson:
	recp = vmulq_f32(vrecpsq_f32(b.neon.f, recp), recp);
	recp = vmulq_f32(vrecpsq_f32(b.neon.f, recp), recp);

	// Multiply by the reciprocal to approximate a / b:
	return (union vec) { .neon.f = vmulq_f32(a.neon.f, recp) };
}
#endif

// Return bitwise a AND b:
#ifndef VEC_FN_AND
#define VEC_FN_AND
static inline union vec
vec_and (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vandq_u32(a.neon.u, b.neon.u) };
}
#endif

// Return bitwise a OR b:
#ifndef VEC_FN_OR
#define VEC_FN_OR
static inline union vec
vec_or (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vorrq_u32(a.neon.u, b.neon.u) };
}
#endif

// Return bitwise a XOR b:
#ifndef VEC_FN_XOR
#define VEC_FN_XOR
static inline union vec
vec_xor (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = veorq_u32(a.neon.u, b.neon.u) };
}
#endif

// Return bitwise NOT v:
#ifndef VEC_FN_NOT
#define VEC_FN_NOT
static inline union vec
vec_not (const union vec v)
{
	return (union vec) { .neon.u = vmvnq_u32(v.neon.u) };
}
#endif

// Return float version of a == b:
#ifndef VEC_FN_EQ
#define VEC_FN_EQ
static inline union vec
vec_eq (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vceqq_f32(a.neon.f, b.neon.f) };
}
#endif

// Return signed integer version of a == b:
#ifndef VEC_FN_IEQ
#define VEC_FN_IEQ
static inline union vec
vec_ieq (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vceqq_s32(a.neon.i, b.neon.i) };
}
#endif

// Return float version of a == b:
#ifndef VEC_FN_UEQ
#define VEC_FN_UEQ
static inline union vec
vec_ueq (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vceqq_u32(a.neon.u, b.neon.u) };
}
#endif

// Return float version of a < b:
#ifndef VEC_FN_LT
#define VEC_FN_LT
static inline union vec
vec_lt (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcltq_f32(a.neon.f, b.neon.f) };
}
#endif

// Return signed integer version of a < b:
#ifndef VEC_FN_ILT
#define VEC_FN_ILT
static inline union vec
vec_ilt (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcltq_s32(a.neon.i, b.neon.i) };
}
#endif

// Return unsigned integer version of a < b:
#ifndef VEC_FN_ULT
#define VEC_FN_ULT
static inline union vec
vec_ult (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcltq_u32(a.neon.u, b.neon.u) };
}
#endif

// Return float version of a <= b:
#ifndef VEC_FN_LE
#define VEC_FN_LE
static inline union vec
vec_le (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcleq_f32(a.neon.f, b.neon.f) };
}
#endif

// Return signed integer version of a <= b:
#ifndef VEC_FN_ILE
#define VEC_FN_ILE
static inline union vec
vec_ile (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcleq_s32(a.neon.i, b.neon.i) };
}
#endif

// Return unsigned integer version of a <= b:
#ifndef VEC_FN_ULE
#define VEC_FN_ULE
static inline union vec
vec_ule (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcleq_u32(a.neon.u, b.neon.u) };
}
#endif

// Return float version of a > b:
#ifndef VEC_FN_GT
#define VEC_FN_GT
static inline union vec
vec_gt (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcgtq_f32(a.neon.f, b.neon.f) };
}
#endif

// Return signed integer version of a > b:
#ifndef VEC_FN_IGT
#define VEC_FN_IGT
static inline union vec
vec_igt (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcgtq_s32(a.neon.i, b.neon.i) };
}
#endif

// Return unsigned integer version of a > b:
#ifndef VEC_FN_UGT
#define VEC_FN_UGT
static inline union vec
vec_ugt (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcgtq_u32(a.neon.u, b.neon.u) };
}
#endif

// Return float version of a >= b:
#ifndef VEC_FN_GE
#define VEC_FN_GE
static inline union vec
vec_ge (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcgeq_f32(a.neon.f, b.neon.f) };
}
#endif

// Return signed integer version of a >= b:
#ifndef VEC_FN_IGE
#define VEC_FN_IGE
static inline union vec
vec_ige (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcgeq_s32(a.neon.i, b.neon.i) };
}
#endif

// Return unsigned integer version of a >= b:
#ifndef VEC_FN_UGE
#define VEC_FN_UGE
static inline union vec
vec_uge (const union vec a, const union vec b)
{
	return (union vec) { .neon.u = vcgeq_u32(a.neon.u, b.neon.u) };
}
#endif

// Return dot product of two 3D vectors:
#ifndef VEC_FN_DOT
#define VEC_FN_DOT
static inline float
vec_dot (const union vec a, const union vec b)
{
	const float32x4_t mul = vmulq_f32(a.neon.f, b.neon.f);
	return vgetq_lane_f32(mul, 0)
	     + vgetq_lane_f32(mul, 1)
	     + vgetq_lane_f32(mul, 2);
}
#endif

// Return cross product of two 3D vectors (intrinsics version):
#ifndef VEC_FN_CROSS
#define VEC_FN_CROSS
static inline union vec
vec_cross (const union vec a, const union vec b)
{
	const float32x4_t ayzwx = (float32x4_t) vextq_u32((uint32x4_t) a.neon.f, (uint32x4_t) a.neon.f, 1);
	const float32x4_t byzwx = (float32x4_t) vextq_u32((uint32x4_t) b.neon.f, (uint32x4_t) b.neon.f, 1);

	const float32x4_t ayzxw = vcombine_f32(vget_low_f32(ayzwx), vrev64_f32(vget_high_f32(ayzwx)));
	const float32x4_t byzxw = vcombine_f32(vget_low_f32(byzwx), vrev64_f32(vget_high_f32(byzwx)));

	const float32x2x2_t azxwy_pair = vtrn_f32(vget_high_f32(a.neon.f), vget_low_f32(a.neon.f));
	const float32x2x2_t bzxwy_pair = vtrn_f32(vget_high_f32(b.neon.f), vget_low_f32(b.neon.f));

	const float32x4_t azxyw = vcombine_f32(azxwy_pair.val[0], vrev64_f32(azxwy_pair.val[1]));
	const float32x4_t bzxyw = vcombine_f32(bzxwy_pair.val[0], vrev64_f32(bzxwy_pair.val[1]));

	return (union vec) { .neon.f = vmlsq_f32(vmulq_f32(ayzxw, bzxyw), byzxw, azxyw) };
}
#endif
