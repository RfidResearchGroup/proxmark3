// Instantiate a float vector:
#ifndef VEC_FN_
#define VEC_FN_
static inline union vec
vec (const float x, const float y, const float z, const float w)
{
	return (union vec) { .x = x, .y = y, .z = z, .w = w };
}
#endif

// Instantiate a signed integer vector:
#ifndef VEC_FN_I
#define VEC_FN_I
static inline union vec
vec_i (const int32_t x, const int32_t y, const int32_t z, const int32_t w)
{
	return (union vec) { .xi = x, .yi = y, .zi = z, .wi = w };
}
#endif

// Instantiate an unsigned integer vector:
#ifndef VEC_FN_U
#define VEC_FN_U
static inline union vec
vec_u (const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t w)
{
	return (union vec) { .xu = x, .yu = y, .zu = z, .wu = w };
}
#endif

// Instantiate a float vector with four identical elements:
#ifndef VEC_FN_1
#define VEC_FN_1
static inline union vec
vec_1 (const float val)
{
	return vec(val, val, val, val);
}
#endif

// Instantiate a signed integer vector with four identical elements:
#ifndef VEC_FN_I1
#define VEC_FN_I1
static inline union vec
vec_i1 (const int32_t val)
{
	return vec_i(val, val, val, val);
}
#endif

// Instantiate an unsigned integer vector with four identical elements:
#ifndef VEC_FN_U1
#define VEC_FN_U1
static inline union vec
vec_u1 (const uint32_t val)
{
	return vec_u(val, val, val, val);
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
	return (union vec) { .xi = v.x, .yi = v.y, .zi = v.z, .wi = v.w };
}
#endif

// Convert a signed integer vector to float:
#ifndef VEC_FN_TO_FLOAT
#define VEC_FN_TO_FLOAT
static inline union vec
vec_to_float (const union vec v)
{
	return (union vec) { .x = v.xi, .y = v.yi, .z = v.zi, .w = v.wi };
}
#endif

// Return float version of a + b:
#ifndef VEC_FN_ADD
#define VEC_FN_ADD
static inline union vec
vec_add (const union vec a, const union vec b)
{
	return (union vec) {
		.x = a.x + b.x,
		.y = a.y + b.y,
		.z = a.z + b.z,
		.w = a.w + b.w,
	};
}
#endif

// Return signed integer version of a + b:
#ifndef VEC_FN_IADD
#define VEC_FN_IADD
static inline union vec
vec_iadd (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xi + b.xi,
		.yi = a.yi + b.yi,
		.zi = a.zi + b.zi,
		.wi = a.wi + b.wi,
	};
}
#endif

// Return unsigned integer version of a + b:
#ifndef VEC_FN_UADD
#define VEC_FN_UADD
static inline union vec
vec_uadd (const union vec a, const union vec b)
{
	return (union vec) {
		.xu = a.xu + b.xu,
		.yu = a.yu + b.yu,
		.zu = a.zu + b.zu,
		.wu = a.wu + b.wu,
	};
}
#endif

// Return float version of a - b:
#ifndef VEC_FN_SUB
#define VEC_FN_SUB
static inline union vec
vec_sub (const union vec a, const union vec b)
{
	return (union vec) {
		.x = a.x - b.x,
		.y = a.y - b.y,
		.z = a.z - b.z,
		.w = a.w - b.w,
	};
}
#endif

// Return signed integer version of a - b:
#ifndef VEC_FN_ISUB
#define VEC_FN_ISUB
static inline union vec
vec_isub (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xi - b.xi,
		.yi = a.yi - b.yi,
		.zi = a.zi - b.zi,
		.wi = a.wi - b.wi,
	};
}
#endif

// Return unsigned integer version of a - b:
#ifndef VEC_FN_USUB
#define VEC_FN_USUB
static inline union vec
vec_usub (const union vec a, const union vec b)
{
	return (union vec) {
		.xu = a.xu - b.xu,
		.yu = a.yu - b.yu,
		.zu = a.zu - b.zu,
		.wu = a.wu - b.wu,
	};
}
#endif

// Return float version of a * b:
#ifndef VEC_FN_MUL
#define VEC_FN_MUL
static inline union vec
vec_mul (const union vec a, const union vec b)
{
	return (union vec) {
		.x = a.x * b.x,
		.y = a.y * b.y,
		.z = a.z * b.z,
		.w = a.w * b.w,
	};
}
#endif

// Return float version of a / b:
#ifndef VEC_FN_DIV
#define VEC_FN_DIV
static inline union vec
vec_div (const union vec a, const union vec b)
{
	return (union vec) {
		.x = a.x / b.x,
		.y = a.y / b.y,
		.z = a.z / b.z,
		.w = a.w / b.w,
	};
}
#endif

// Return bitwise a AND b:
#ifndef VEC_FN_AND
#define VEC_FN_AND
static inline union vec
vec_and (const union vec a, const union vec b)
{
	return (union vec) {
		.xu = a.xu & b.xu,
		.yu = a.yu & b.yu,
		.zu = a.zu & b.zu,
		.wu = a.wu & b.wu,
	};
}
#endif

// Return bitwise a OR b:
#ifndef VEC_FN_OR
#define VEC_FN_OR
static inline union vec
vec_or (const union vec a, const union vec b)
{
	return (union vec) {
		.xu = a.xu | b.xu,
		.yu = a.yu | b.yu,
		.zu = a.zu | b.zu,
		.wu = a.wu | b.wu,
	};
}
#endif

// Return bitwise a XOR b:
#ifndef VEC_FN_XOR
#define VEC_FN_XOR
static inline union vec
vec_xor (const union vec a, const union vec b)
{
	return (union vec) {
		.xu = a.xu ^ b.xu,
		.yu = a.yu ^ b.yu,
		.zu = a.zu ^ b.zu,
		.wu = a.wu ^ b.wu,
	};
}
#endif

// Return bitwise NOT v:
#ifndef VEC_FN_NOT
#define VEC_FN_NOT
static inline union vec
vec_not (const union vec v)
{
	return (union vec) {
		.xu = ~v.xu,
		.yu = ~v.yu,
		.zu = ~v.zu,
		.wu = ~v.wu,
	};
}
#endif

// Return float version of a == b:
#ifndef VEC_FN_EQ
#define VEC_FN_EQ
static inline union vec
vec_eq (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.x == b.x ? -1 : 0,
		.yi = a.y == b.y ? -1 : 0,
		.zi = a.z == b.z ? -1 : 0,
		.wi = a.w == b.w ? -1 : 0,
	};
}
#endif

// Return signed integer version of a == b:
#ifndef VEC_FN_IEQ
#define VEC_FN_IEQ
static inline union vec
vec_ieq (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xi == b.xi ? -1 : 0,
		.yi = a.yi == b.yi ? -1 : 0,
		.zi = a.zi == b.zi ? -1 : 0,
		.wi = a.wi == b.wi ? -1 : 0,
	};
}
#endif

// Return float version of a == b:
#ifndef VEC_FN_UEQ
#define VEC_FN_UEQ
static inline union vec
vec_ueq (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xu == b.xu ? -1 : 0,
		.yi = a.yu == b.yu ? -1 : 0,
		.zi = a.zu == b.zu ? -1 : 0,
		.wi = a.wu == b.wu ? -1 : 0,
	};
}
#endif

// Return float version of a < b:
#ifndef VEC_FN_LT
#define VEC_FN_LT
static inline union vec
vec_lt (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.x < b.x ? -1 : 0,
		.yi = a.y < b.y ? -1 : 0,
		.zi = a.z < b.z ? -1 : 0,
		.wi = a.w < b.w ? -1 : 0,
	};
}
#endif

// Return signed integer version of a < b:
#ifndef VEC_FN_ILT
#define VEC_FN_ILT
static inline union vec
vec_ilt (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xi < b.xi ? -1 : 0,
		.yi = a.yi < b.yi ? -1 : 0,
		.zi = a.zi < b.zi ? -1 : 0,
		.wi = a.wi < b.wi ? -1 : 0,
	};
}
#endif

// Return unsigned integer version of a < b:
#ifndef VEC_FN_ULT
#define VEC_FN_ULT
static inline union vec
vec_ult (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xu < b.xu ? -1 : 0,
		.yi = a.yu < b.yu ? -1 : 0,
		.zi = a.zu < b.zu ? -1 : 0,
		.wi = a.wu < b.wu ? -1 : 0,
	};
}
#endif

// Return float version of a <= b:
#ifndef VEC_FN_LE
#define VEC_FN_LE
static inline union vec
vec_le (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.x <= b.x ? -1 : 0,
		.yi = a.y <= b.y ? -1 : 0,
		.zi = a.z <= b.z ? -1 : 0,
		.wi = a.w <= b.w ? -1 : 0,
	};
}
#endif

// Return signed integer version of a <= b:
#ifndef VEC_FN_ILE
#define VEC_FN_ILE
static inline union vec
vec_ile (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xi <= b.xi ? -1 : 0,
		.yi = a.yi <= b.yi ? -1 : 0,
		.zi = a.zi <= b.zi ? -1 : 0,
		.wi = a.wi <= b.wi ? -1 : 0,
	};
}
#endif

// Return unsigned integer version of a <= b:
#ifndef VEC_FN_ULE
#define VEC_FN_ULE
static inline union vec
vec_ule (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xu <= b.xu ? -1 : 0,
		.yi = a.yu <= b.yu ? -1 : 0,
		.zi = a.zu <= b.zu ? -1 : 0,
		.wi = a.wu <= b.wu ? -1 : 0,
	};
}
#endif

// Return float version of a > b:
#ifndef VEC_FN_GT
#define VEC_FN_GT
static inline union vec
vec_gt (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.x > b.x ? -1 : 0,
		.yi = a.y > b.y ? -1 : 0,
		.zi = a.z > b.z ? -1 : 0,
		.wi = a.w > b.w ? -1 : 0,
	};
}
#endif

// Return signed integer version of a > b:
#ifndef VEC_FN_IGT
#define VEC_FN_IGT
static inline union vec
vec_igt (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xi > b.xi ? -1 : 0,
		.yi = a.yi > b.yi ? -1 : 0,
		.zi = a.zi > b.zi ? -1 : 0,
		.wi = a.wi > b.wi ? -1 : 0,
	};
}
#endif

// Return unsigned integer version of a > b:
#ifndef VEC_FN_UGT
#define VEC_FN_UGT
static inline union vec
vec_ugt (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xu > b.xu ? -1 : 0,
		.yi = a.yu > b.yu ? -1 : 0,
		.zi = a.zu > b.zu ? -1 : 0,
		.wi = a.wu > b.wu ? -1 : 0,
	};
}
#endif

// Return float version of a >= b:
#ifndef VEC_FN_GE
#define VEC_FN_GE
static inline union vec
vec_ge (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.x >= b.x ? -1 : 0,
		.yi = a.y >= b.y ? -1 : 0,
		.zi = a.z >= b.z ? -1 : 0,
		.wi = a.w >= b.w ? -1 : 0,
	};
}
#endif

// Return signed integer version of a >= b:
#ifndef VEC_FN_IGE
#define VEC_FN_IGE
static inline union vec
vec_ige (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xi >= b.xi ? -1 : 0,
		.yi = a.yi >= b.yi ? -1 : 0,
		.zi = a.zi >= b.zi ? -1 : 0,
		.wi = a.wi >= b.wi ? -1 : 0,
	};
}
#endif

// Return unsigned integer version of a >= b:
#ifndef VEC_FN_UGE
#define VEC_FN_UGE
static inline union vec
vec_uge (const union vec a, const union vec b)
{
	return (union vec) {
		.xi = a.xu >= b.xu ? -1 : 0,
		.yi = a.yu >= b.yu ? -1 : 0,
		.zi = a.zu >= b.zu ? -1 : 0,
		.wi = a.wu >= b.wu ? -1 : 0,
	};
}
#endif

// Return dot product of two 3D vectors:
#ifndef VEC_FN_DOT
#define VEC_FN_DOT
static inline float
vec_dot (const union vec a, const union vec b)
{
	return a.x * b.x + a.y * b.y + a.z * b.z;
}
#endif

// Return cross product of two 3D vectors:
#ifndef VEC_FN_CROSS
#define VEC_FN_CROSS
static inline union vec
vec_cross (const union vec a, const union vec b)
{
	return (union vec) {
		.x = a.y * b.z - a.z * b.y,
		.y = a.z * b.x - a.x * b.z,
		.z = a.x * b.y - a.y * b.x,
		.w = 0.0f,
	};
}
#endif
