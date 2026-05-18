// Return float version of a / b:
#ifndef VEC_FN_DIV
#define VEC_FN_DIV
static inline union vec
vec_div (const union vec a, const union vec b)
{
#ifdef __aarch64__
	float32x4_t ret;

	__asm__ (
		"fdiv %0.4s,%1.4s,%2.4s   \n\t"

		: "=&w" (ret)				// Outputs: ret=v0
		: "w" (a.neon.f), "w" (b.neon.f)	// Inputs: a=v1, b=v2
	);
#else
	float32x4_t ret, tmp;

	__asm__ (
		"vrecpeq.f32 %q0,%q3      \n\t"
		"vrecpsq.f32 %q1,%q3,%q0  \n\t"
		"vmulq.f32   %q0,%q1,%q0  \n\t"
		"vrecpsq.f32 %q1,%q3,%q0  \n\t"
		"vmulq.f32   %q0,%q1,%q0  \n\t"
		"vmulq.f32   %q0,%q2,%q0  \n\t"

		: "=&w" (ret), "=&w" (tmp)		// Outputs: ret=q0, tmp=q1
		: "w" (a.neon.f), "w" (b.neon.f)	// Inputs: a=q2, b=q3
	);
#endif

	return (union vec) { .neon.f = ret };
}
#endif

// Return cross product of two 3D vectors:
#ifndef VEC_FN_CROSS
#define VEC_FN_CROSS
static inline union vec
vec_cross (const union vec a, const union vec b)
{
	// Make read/write copies of the inputs:
	float32x4_t atmp = a.neon.f, btmp = b.neon.f;

#ifdef __aarch64__
	float32x4_t ret, t1, t2;

	__asm__ (
		"zip1 %0.4s,%3.4s,%4.4s       \n\t"	// v0 := a0 b0 a1 b1
		"zip2 %1.4s,%3.4s,%4.4s       \n\t"	// v1 := a2 b2 a3 b3
		"trn1 %2.4s,%3.4s,%4.4s       \n\t"	// v2 := a0 b0 a2 b2
		"trn2 %3.4s,%3.4s,%4.4s       \n\t"	// v3 := a1 b1 a3 b3
		"ext  %0.16b,%0.16b,%0.16b,#8 \n\t"	// v0 := a1 b1 a0 b0
		"ext  %2.16b,%2.16b,%2.16b,#8 \n\t"	// v2 := a2 b2 a0 b0
		"trn2 %4.4s,%0.4s,%1.4s       \n\t"	// v4 := b1 b2 b0 b3 = byzxw
		"trn1 %0.4s,%0.4s,%1.4s       \n\t"	// v0 := a1 a2 a0 a3 = ayzxw
		"uzp1 %1.4s,%2.4s,%3.4s       \n\t"	// v1 := a2 a0 a1 a3 = azxyw
		"uzp2 %2.4s,%2.4s,%3.4s       \n\t"	// v2 := b2 b0 b1 b3 = bzxyw

		"fmul %0.4s,%0.4s,%2.4s       \n\t"	// v0 := ayzxw * bzxyw
		"fmls %0.4s,%1.4s,%4.4s       \n\t"	// v0 := ayzxw * bzxyw - azxyw * byzxw

		: "=&w" (ret), "=&w" (t1), "=&w" (t2),	// Outputs: ret=v0, t1=v1, t2=v2
		  "+w" (atmp), "+w" (btmp)		// Outputs (reused inputs): a=v3, b=v4
	);
#else
	float32x4_t ret, tmp;

	__asm__ (
		"vext.8    %q0,%q2,%q2,#4  \n\t"	// q0 := ayzwx
		"vext.8    %q1,%q3,%q3,#4  \n\t"	// q1 := byzwx
		"vrev64.32 %f0,%f0         \n\t"	// q0 := ayzxw
		"vrev64.32 %f1,%f1         \n\t"	// q1 := byzxw

		"vtrn.32   %e2,%f2         \n\t"	// q2 := axzyw
		"vtrn.32   %e3,%f3         \n\t"	// q3 := bxzyw
		"vrev64.32 %e2,%e2         \n\t"	// q2 := azxyw
		"vrev64.32 %e3,%e3         \n\t"	// q3 := bzxyw

		"vmulq.f32 %q0,%q0,%q3     \n\t"	// q0 := ayzxw * bzxyw
		"vmlsq.f32 %q0,%q2,%q1     \n\t"	// q0 := ayzxw * bzxyw - azxyw * byzxw

		: "=&w" (ret), "=&w" (tmp),		// Outputs: ret=q0, tmp=q1
		  "+w" (atmp), "+w" (btmp)		// Outputs (reused inputs): a=q2, b=q3
	);
#endif

	return (union vec) { .neon.f = ret };
}
#endif
