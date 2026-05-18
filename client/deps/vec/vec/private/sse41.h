// Return dot product of two 3D vectors:
#ifndef VEC_FN_DOT
#define VEC_FN_DOT
static inline float
vec_dot (const union vec a, const union vec b)
{
	const __m128 dot = _mm_dp_ps(a.sse.f, b.sse.f, 0x7F);

	// Extract first element:
	return ((union vec) { .xi = _mm_cvtsi128_si32(_mm_castps_si128(dot)) }).x;
}
#endif
