/* ht2crack5opencl_kernel.cl
 * -------------------------
 * This code is heavily based on crack5gpu implementation.
 *
 * Additional changes done by Gabriele 'matrix' Gristina <gabriele.gristina@gmail.com>
 *  - generic code optimizations
 *  - using local memory for keystream, if enabled by OpenCL host engine
 *  - added the two macros bs_res () and bs_res_lut_1, used during the generation of intermediate results
 *  - split lut3 function to some variants (tentative to reduce registers usage)
 *  - add support for devices without lop3.b32 instruction (for ! NVIDIA platforms/devices, like Intel and Apple CPU/GPU, not tested on ADM)
 *  - add HITAG2 routine to perform key verification, if enabled
 *  - using local memory for uid, aR2, nR1, nR2 (if HITAG2 routine is enabled)
 */

#define MAX_BITSLICES 32
#define KEYSTREAM_LENGTH 32

typedef uint bitslice_t __attribute__((aligned(MAX_BITSLICES / 8)));

#ifndef HAVE_LOP3
// (0xf0&(0xcc^0xaa))
inline static uint lut3_0x60(uint a, uint b, uint c) {
	const uint r = b ^ c;
	return a & r;
}

// (~((0xf0|0xcc)^0xaa))
inline static uint lut3_0xa9(uint a, uint b, uint c) {
	const uint r = a | b;
	return ~(r ^ c);
}

// (~((0xf0|0xcc|0xaa)))
inline static uint lut3_0x01(uint a, uint b, uint c) {
	const uint r = a | b;
	return ~(r | c);
}

// (((0xf0|0xcc)&0xaa))
inline static uint lut3_0xa8(uint a, uint b, uint c) {
	const uint r = a | b;
	return r & c;
}

// (((0xf0|0xcc)&0xaa)^0xcc)
inline static uint lut3_0x64(uint a, uint b, uint c) {
	const uint r = (a | b) & c;
	return r ^ b;
}

// (0xf0^0xaa^0xcc)
inline static uint lut3_0x96(uint a, uint b, uint c) {
	const uint r = a ^ b;
	return r ^ c;
}

// (((0xf0^0xcc)|0xaa))
inline static uint lut3_0xbe(uint a, uint b, uint c) {
	const uint r = a ^ b;
	return r | c;
}

// (~((0xf0^0xcc)&(0xaa^0xcc)))
inline static uint lut3_0xdb(uint a, uint b, uint c) {
	const uint r = a ^ b;
	const uint r2 = c ^ b;
	return ~(r & r2);
}
/*
// (0xf0|(0xcc&0xaa))
inline static uint lut3_0xf8(uint a, uint b, uint c) {
	const uint r = b & c;
	return a | r;
}
*/
/*
// (0xf0|(0xcc&(0x01)))
inline static uint lut3_0xf8_0x1(uint a, uint b) {
	const uint r = b & 0x1;
	return a | r;
}
*/

#ifdef WITH_HITAG2_FULL
// (0xf0|(0xcc&(0xC)))
inline static uint lut3_0xf8_0xC(uint a, uint b) {
	const uint r = b & 0xC;
	return a | r;
}

// (0xf0|0xcc|0xaa)
inline static uint lut3_0xfe(uint a, uint b, uint c) {
	const uint r = a | b;
	return r | c;
}
#endif // WITH_HITAG2_FULL

#else // HAVE_LOP3

inline static uint lut3_0x01(uint a, uint b, uint c) {
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, 0x01;" : "=r"(r): "r"(a), "r"(b), "r"(c));
	return r;
}

inline static uint lut3_0x60(uint a, uint b, uint c) {
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, 0x60;" : "=r"(r): "r"(a), "r"(b), "r"(c));
	return r;
}

inline static uint lut3_0x64(uint a, uint b, uint c) {
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, 0x64;" : "=r"(r): "r"(a), "r"(b), "r"(c));
	return r;
}

inline static uint lut3_0x96(uint a, uint b, uint c) {
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r"(r): "r"(a), "r"(b), "r"(c));
	return r;
}

inline static uint lut3_0xa8(uint a, uint b, uint c) {
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, 0xa8;" : "=r"(r): "r"(a), "r"(b), "r"(c));
	return r;
}

inline static uint lut3_0xa9(uint a, uint b, uint c) {
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, 0xa9;" : "=r"(r): "r"(a), "r"(b), "r"(c));
	return r;
}

inline static uint lut3_0xbe(uint a, uint b, uint c) {
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, 0xbe;" : "=r"(r): "r"(a), "r"(b), "r"(c));
	return r;
}

inline static uint lut3_0xdb(uint a, uint b, uint c) {
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, 0xdb;" : "=r"(r): "r"(a), "r"(b), "r"(c));
	return r;
}

/*
inline static uint lut3_0xf8(uint a, uint b, uint c) {
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, 0xf8;" : "=r"(r): "r"(a), "r"(b), "r"(c));
	return r;
}
*/
/*
inline static uint lut3_0xf8_0x1(uint a, uint b) {
	uint r;
	asm("lop3.b32 %0, %1, %2, 0x1, 0xf8;" : "=r"(r): "r"(a), "r"(b));
	return r;
}
*/

#ifdef WITH_HITAG2_FULL
inline static uint lut3_0xf8_0xC(uint a, uint b) {
	uint r;
	asm("lop3.b32 %0, %1, %2, 0xC, 0xf8;" : "=r"(r): "r"(a), "r"(b));
	return r;
}

inline static uint lut3_0xfe(uint a, uint b, uint c) {
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, 0xfe;" : "=r"(r): "r"(a), "r"(b), "r"(c));
	return r;
}
#endif // WITH_HITAG2_FULL

#endif // HAVE_LOP3

#define f_a_bs(a,b,c,d)       (lut3_0xa9(a,d,lut3_0x64(a,b,c))) // 2 luts
#define f_b_bs(a,b,c,d)       (lut3_0xa8(d,c,a^b) ^ lut3_0x01(d,a,b)) // 2 luts, 2 xors
#define f_c_bs(a,b,c,d,e)     (((lut3_0xdb((lut3_0xbe(c,e,d) & a), b, c)) ^ (lut3_0xbe(d,e,a) & lut3_0xbe(d,b,c))))
#define bs_res(a,b,c)         (lut3_0x60(a,b,c))

#define lfsr_bs(i)            (lut3_0x96(lut3_0x96(lut3_0x96(state[-2+i+ 0], state[-2+i+ 2], state[-2+i+ 3]),  \
                                                   lut3_0x96(state[-2+i+ 6], state[-2+i+ 7], state[-2+i+ 8]),  \
                                                   lut3_0x96(state[-2+i+16], state[-2+i+22], state[-2+i+23])), \
                                         lut3_0x96(state[-2+i+26], state[-2+i+30], state[-2+i+41]), \
                                         lut3_0x96(state[-2+i+42], state[-2+i+43], state[-2+i+46])) ^ state[-2+i+47])

// 46 iterations * 4 ops
static inline void bitslice (bitslice_t *restrict b, ulong x) {
	for (uint i = 0; i < 46; ++i) {
		b[i] = -(x & 1);
		x >>= 1;
	}
}

// don't care about the complexity of this function
static inline ulong unbitslice (const bitslice_t *restrict b, const uint s) {
	const bitslice_t mask = ((bitslice_t) 1) << s;
	ulong result = 0;

	for (int i = 47; i >= 0; --i) {
		result <<= 1;
		result |= (bool)(b[i] & mask);
	}
	return result;
}

///////////////////////////////

#ifdef WITH_HITAG2_FULL

/*
 * Hitag Crypto support macros
 * These macros reverse the bit order in a byte, or *within* each byte of a
 * 16 , 32 or 64 bit unsigned integer. (Not across the whole 16 etc bits.)
 */
#define rev8(X)   ((((X) >> 7) &1) + (((X) >> 5) &2) + (((X) >> 3) &4) \
                  + (((X) >> 1) &8) + (((X) << 1) &16) + (((X) << 3) &32) \
                  + (((X) << 5) &64) + (((X) << 7) &128) )
#define rev16(X)  (rev8 (X) + (rev8 (X >> 8) << 8))
#define rev32(X)  (rev16(X) + (rev16(X >> 16) << 16))
#define rev64(X)  (rev32(X) + (rev32(X >> 32) << 32))

// (0xf0|(0xcc&0xaa))
#define pickbits2_2_lut(a,b)     (lut3_0xf8_0xC(a,b))
#define pickbits2_2(S)           pickbits2_2_lut( ((S >> 1) & 3) , (S >> 2) )

// (0xf0|0xcc|0xaa)
#define pickbits1_1_2_lut(a,b,c) (lut3_0xfe(a,b,c))
#define pickbits1_1_2(S)         pickbits1_1_2_lut( ((S >> 7) & 1) , ((S >> 10) & 2) , ((S >> 11) & 0xC) )

#define pickbits1x4_lut(a,b,c,d) (lut3_0xfe(a,b,c) | d)
#define pickbits1x4(S)           pickbits1x4_lut( ((S >> 16) & 1) , ((S >> 19) & 2) , ((S >> 20) & 4) , ((S >> 22) & 8) )

#define pickbits2_1_1_lut(a,b,c) (lut3_0xfe(a,b,c))
#define pickbits2_1_1(S)         pickbits2_1_1_lut( ((S >> 27) & 3) , ((S >> 28) & 4) , ((S >> 29) & 8) )

#define pickbits1_2_1_lut(a,b,c) (lut3_0xfe(a,b,c))
#define pickbits1_2_1(S)         pickbits1_2_1_lut( ((S >> 33) & 1) , ((S >> 41) & 6) , ((S >> 42) & 8) )

static uint hitag2_crypt (ulong x)
{
	const uint ht2_function4a = 0x2C79; // 0010 1100 0111 1001
	const uint ht2_function4b = 0x6671; // 0110 0110 0111 0001
	const uint ht2_function5c = 0x7907287B; // 0111 1001 0000 0111 0010 1000 0111 1011

	uint bitindex;
	bitindex = (ht2_function4a >> pickbits2_2(x)) & 1;
	bitindex |= ((ht2_function4b << 1) >> pickbits1_1_2(x)) & 0x02;
	bitindex |= ((ht2_function4b << 2) >> pickbits1x4(x)) & 0x04;
	bitindex |= ((ht2_function4b << 3) >> pickbits2_1_1(x)) & 0x08;
	bitindex |= ((ht2_function4a << 4) >> pickbits1_2_1(x)) & 0x10;

	return (ht2_function5c >> bitindex) & 1;
}

static void hitag2_init2 (ulong *shiftreg, ulong *lfsr, const ulong sharedkey, const uint serialnum, uint initvector)
{
	ulong state = ((sharedkey & 0xFFFF) << 32) | serialnum;

	initvector ^= (uint)(sharedkey >> 16);
	state |= (ulong) initvector << 48;

	initvector >>= 16;
	state >>= 1;

	for (uint x = 0; x < 16; x++) state = (state >> 1) ^ (ulong) hitag2_crypt (state) << 46;

	state |= (ulong) initvector << 47;

	for (uint x = 0; x < 15; x++) state = (state >> 1) ^ (ulong) hitag2_crypt (state) << 46;

	state ^= (ulong) hitag2_crypt(state) << 47;

	*shiftreg = state;

//	ulong temp = state ^ (state >> 1);
//	*lfsr = state ^ (state >>  6) ^ (state >> 16) ^ (state >> 26) ^ (state >> 30) ^ (state >> 41) ^
//		(temp  >>  2) ^ (temp  >>  7) ^ (temp  >> 22) ^ (temp  >> 42) ^ (temp  >> 46);

	*lfsr = (ulong) state ^
		lut3_0x96 ((state >>  2), (state >>  3), (state >>  6)) ^
		lut3_0x96 ((state >>  7), (state >>  8), (state >> 16)) ^
		lut3_0x96 ((state >> 22), (state >> 23), (state >> 26)) ^
		lut3_0x96 ((state >> 30), (state >> 41), (state >> 42)) ^
		lut3_0x96 ((state >> 43), (state >> 46), (state >> 47));
}

static uint hitag2_nstep2 (ulong state, ulong lfsr)
{
	uint result = 0;
	for (uint nsteps = 32; nsteps > 0; nsteps--)
	{
		if (lfsr & 1)
		{
			state  = (state >> 1) | 0x800000000000;
			lfsr   = (lfsr >> 1) ^ 0xB38083220073;
			result = (result << 1) | hitag2_crypt (state);
		}
		else
		{
			state >>= 1;
			lfsr >>= 1;
			result = (result << 1) | hitag2_crypt (state);
		}
	}
	return result;
}

inline static int bitn(ulong x, int bit)
{
	const ulong bitmask = 1UL << bit;
	return (x & bitmask) ? 1 : 0;
}

static int fnR (ulong x)
{
	return (bitn(x, 1) ^ bitn(x, 2) ^ bitn(x, 5) ^ bitn(x, 6) ^ bitn(x, 7) ^
		bitn(x, 15) ^ bitn(x, 21) ^ bitn(x, 22) ^ bitn(x, 25) ^ bitn(x, 29) ^ bitn(x, 40) ^
		bitn(x, 41) ^ bitn(x, 42) ^ bitn(x, 45) ^ bitn(x, 46) ^ bitn(x, 47));
}

inline static int fa(unsigned int i) {
    return bitn(0x2C79, i);
}

inline static int fb(unsigned int i) {
    return bitn(0x6671, i);
}

static int fnf (ulong s)
{
	const uint x1 = (bitn(s,  2) << 0) | lut3_0x96( (bitn(s,  3) << 1), (bitn(s,  5) << 2), (bitn(s,  6) << 3));
	const uint x2 = (bitn(s,  8) << 0) | lut3_0x96( (bitn(s, 12) << 1), (bitn(s, 14) << 2), (bitn(s, 15) << 3));
	const uint x3 = (bitn(s, 17) << 0) | lut3_0x96( (bitn(s, 21) << 1), (bitn(s, 23) << 2), (bitn(s, 26) << 3));
	const uint x4 = (bitn(s, 28) << 0) | lut3_0x96( (bitn(s, 29) << 1), (bitn(s, 31) << 2), (bitn(s, 33) << 3));
	const uint x5 = (bitn(s, 34) << 0) | lut3_0x96( (bitn(s, 43) << 1), (bitn(s, 44) << 2), (bitn(s, 46) << 3));
	const uint x6 = lut3_0x96( (fa(x1) << 0), (fb(x2) << 1), lut3_0x96( (fb(x3) << 2), (fb(x4) << 3), (fa(x5) << 4)));

	return bitn(0x7907287B, x6);
}

#endif // WITH_HITAG2_FULL

// format this array with 32 bitsliced vectors of ones and zeroes representing the inverted keystream

__kernel
__attribute__((vec_type_hint(bitslice_t)))
void find_state(const uint candidate_index_base,
                __global const ushort *restrict candidates,
//                __global const ulong *restrict candidates,
                __global const bitslice_t *restrict _keystream,
                __global ulong *restrict matches,
#ifndef WITH_HITAG2_FULL
                __global uint *restrict matches_found)
#else
		__global uint *restrict matches_found,
		__global const uint *restrict _checks)
#endif
{
	const size_t gid[2] = { get_global_id(0), get_global_id(1) };

	// if (gid[0] == 0) printf("work-item 1,%u\n", gid[1]);

	#ifdef HAVE_LOCAL_MEMORY
	const size_t lid = get_local_id(0);
	const size_t lsize = get_local_size(0);
	#endif // HAVE_LOCAL_MEMORY

	const uint index = 3 * (candidate_index_base + gid[0]); // dimension 0 should at least keep the execution units saturated - 8k is fine

	const ulong3 c = { candidates[index], candidates[index + 1], candidates[index + 2] };

	const ulong candidate = ( c.x << 32 | c.y << 16 | c.z );

	#ifdef HAVE_LOCAL_MEMORY
	// store keystream in local memory
	__local bitslice_t keystream[32];

	for (size_t i = lid; i < 32; i+= lsize) keystream[i] = _keystream[i];

	#ifdef WITH_HITAG2_FULL
	// store uid, aR2, nR1, nR2 in local memory
	__local uint checks[4];

	for (uint i = lid; i < 4; i+= lsize) checks[i] = _checks[i];
	#endif

	// threads synchronization
	barrier (CLK_LOCAL_MEM_FENCE);
	#else
	#define keystream _keystream
	#define checks _checks
	#endif // HAVE_LOCAL_MEMORY

	// we never actually set or use the lowest 2 bits the initial state, so we can save 2 bitslices everywhere
	bitslice_t state[-2 + 48 + KEYSTREAM_LENGTH] = { 0 };

	// set bits 0+2, 0+3, 0+5, 0+6, 0+8, 0+12, 0+14, 0+15, 0+17, 0+21, 0+23, 0+26, 0+28, 0+29, 0+31, 0+33, 0+34, 0+43, 0+44, 0+46
	// get the 48-bit cipher states as 3 16-bit words from the host memory queue (to save 25% throughput)

	// using 64bit candidate
	//  const uint index = (candidate_index_base + gid[0]); // dimension 0 should at least keep the execution units saturated - 8k is fine
	//  const ulong candidate = candidates[index];
	//  bitslice (&state[-2 + 2], candidate >> 2);

	// set all 48 state bits except the lowest 2
	bitslice (&state[-2 + 2], candidate);

	// set bits 3, 6, 8, 12, 15
	state[-2 + 1 + 3] = 0xaaaaaaaa;
	state[-2 + 1 + 6] = 0xcccccccc;
	state[-2 + 1 + 8] = 0xf0f0f0f0;
	state[-2 + 1 + 12] = 0xff00ff00;
	state[-2 + 1 + 15] = 0xffff0000;

	const uint i1 = gid[1]; // dimension 1 should be 1024
	state[-2 + 18] = -((bool)(i1 & 0x1));
	state[-2 + 22] = -((bool)(i1 & 0x2));
	state[-2 + 24] = -((bool)(i1 & 0x4));
	state[-2 + 27] = -((bool)(i1 & 0x8));
	state[-2 + 30] = -((bool)(i1 & 0x10));
	state[-2 + 32] = -((bool)(i1 & 0x20));
	state[-2 + 35] = -((bool)(i1 & 0x40));
	state[-2 + 45] = -((bool)(i1 & 0x80));
	state[-2 + 47] = -((bool)(i1 & 0x100));
	state[-2 + 48] = -((bool)(i1 & 0x200)); // guess lfsr output 0

	// 0xfc07fef3f9fe
	const bitslice_t filter1_0 = f_a_bs(state[-2 + 3], state[-2 + 4], state[-2 + 6], state[-2 + 7]);
	const bitslice_t filter1_1 = f_b_bs(state[-2 + 9], state[-2 + 13], state[-2 + 15], state[-2 + 16]);
	const bitslice_t filter1_2 = f_b_bs(state[-2 + 18], state[-2 + 22], state[-2 + 24], state[-2 + 27]);
	const bitslice_t filter1_3 = f_b_bs(state[-2 + 29], state[-2 + 30], state[-2 + 32], state[-2 + 34]);
	const bitslice_t filter1_4 = f_a_bs(state[-2 + 35], state[-2 + 44], state[-2 + 45], state[-2 + 47]);
	const bitslice_t filter1 = f_c_bs(filter1_0, filter1_1, filter1_2, filter1_3, filter1_4);

	const bitslice_t results1 = filter1 ^ keystream[1];
	if (!results1) return;

	const bitslice_t filter2_0 = f_a_bs(state[-2 + 4], state[-2 + 5], state[-2 + 7], state[-2 + 8]);
	const bitslice_t filter2_3 = f_b_bs(state[-2 + 30], state[-2 + 31], state[-2 + 33], state[-2 + 35]);
	const bitslice_t filter3_0 = f_a_bs(state[-2 + 5], state[-2 + 6], state[-2 + 8], state[-2 + 9]);
	const bitslice_t filter5_2 = f_b_bs(state[-2 + 22], state[-2 + 26], state[-2 + 28], state[-2 + 31]);
	const bitslice_t filter6_2 = f_b_bs(state[-2 + 23], state[-2 + 27], state[-2 + 29], state[-2 + 32]);
	const bitslice_t filter7_2 = f_b_bs(state[-2 + 24], state[-2 + 28], state[-2 + 30], state[-2 + 33]);
	const bitslice_t filter9_1 = f_b_bs(state[-2 + 17], state[-2 + 21], state[-2 + 23], state[-2 + 24]);
	const bitslice_t filter9_2 = f_b_bs(state[-2 + 26], state[-2 + 30], state[-2 + 32], state[-2 + 35]);
	const bitslice_t filter10_0 = f_a_bs(state[-2 + 12], state[-2 + 13], state[-2 + 15], state[-2 + 16]);
	const bitslice_t filter11_0 = f_a_bs(state[-2 + 13], state[-2 + 14], state[-2 + 16], state[-2 + 17]);
	const bitslice_t filter12_0 = f_a_bs(state[-2 + 14], state[-2 + 15], state[-2 + 17], state[-2 + 18]);
	const bitslice_t filter14_1 = f_b_bs(state[-2 + 22], state[-2 + 26], state[-2 + 28], state[-2 + 29]);
	const bitslice_t filter15_1 = f_b_bs(state[-2 + 23], state[-2 + 27], state[-2 + 29], state[-2 + 30]);
	const bitslice_t filter15_3 = f_b_bs(state[-2 + 43], state[-2 + 44], state[-2 + 46], state[-2 + 48]);
	const bitslice_t filter16_1 = f_b_bs(state[-2 + 24], state[-2 + 28], state[-2 + 30], state[-2 + 31]);

	for (uint i2 = 0; i2 < 32; i2++) {
		state[-2 + 10] = -((bool)(i2 & 0x1));
		state[-2 + 19] = -((bool)(i2 & 0x2));
		state[-2 + 25] = -((bool)(i2 & 0x4));
		state[-2 + 36] = -((bool)(i2 & 0x8));
		state[-2 + 49] = -((bool)(i2 & 0x10)); // guess lfsr output 1

		// 0xfe07fffbfdff
		const bitslice_t filter2_1 = f_b_bs(state[-2 + 10], state[-2 + 14], state[-2 + 16], state[-2 + 17]);
		const bitslice_t filter2_2 = f_b_bs(state[-2 + 19], state[-2 + 23], state[-2 + 25], state[-2 + 28]);
		const bitslice_t filter2_4 = f_a_bs(state[-2 + 36], state[-2 + 45], state[-2 + 46], state[-2 + 48]);
		const bitslice_t filter2 = f_c_bs(filter2_0, filter2_1, filter2_2, filter2_3, filter2_4);

		const bitslice_t results2 = bs_res(results1,filter2,keystream[2]);
		if (!results2) continue;

		state[-2 + 50] = lfsr_bs(2);
		const bitslice_t filter3_3 = f_b_bs(state[-2 + 31], state[-2 + 32], state[-2 + 34], state[-2 + 36]);
		const bitslice_t filter4_0 = f_a_bs(state[-2 + 6], state[-2 + 7], state[-2 + 9], state[-2 + 10]);
		const bitslice_t filter4_1 = f_b_bs(state[-2 + 12], state[-2 + 16], state[-2 + 18], state[-2 + 19]);
		const bitslice_t filter4_2 = f_b_bs(state[-2 + 21], state[-2 + 25], state[-2 + 27], state[-2 + 30]);
		const bitslice_t filter7_0 = f_a_bs(state[-2 + 9], state[-2 + 10], state[-2 + 12], state[-2 + 13]);
		const bitslice_t filter7_1 = f_b_bs(state[-2 + 15], state[-2 + 19], state[-2 + 21], state[-2 + 22]);
		const bitslice_t filter8_2 = f_b_bs(state[-2 + 25], state[-2 + 29], state[-2 + 31], state[-2 + 34]);
		const bitslice_t filter10_1 = f_b_bs(state[-2 + 18], state[-2 + 22], state[-2 + 24], state[-2 + 25]);
		const bitslice_t filter10_2 = f_b_bs(state[-2 + 27], state[-2 + 31], state[-2 + 33], state[-2 + 36]);
		const bitslice_t filter11_1 = f_b_bs(state[-2 + 19], state[-2 + 23], state[-2 + 25], state[-2 + 26]);
		const bitslice_t filter13_0 = f_a_bs(state[-2 + 15], state[-2 + 16], state[-2 + 18], state[-2 + 19]);
		const bitslice_t filter13_1 = f_b_bs(state[-2 + 21], state[-2 + 25], state[-2 + 27], state[-2 + 28]);
		const bitslice_t filter16_0 = f_a_bs(state[-2 + 18], state[-2 + 19], state[-2 + 21], state[-2 + 22]);
		const bitslice_t filter16_3 = f_b_bs(state[-2 + 44], state[-2 + 45], state[-2 + 47], state[-2 + 49]);
		const bitslice_t filter17_1 = f_b_bs(state[-2 + 25], state[-2 + 29], state[-2 + 31], state[-2 + 32]);
		const bitslice_t filter17_3 = f_b_bs(state[-2 + 45], state[-2 + 46], state[-2 + 48], state[-2 + 50]);

		for (uint i3 = 0; i3 < 8; i3++) {
			state[-2 + 11] = -((bool)(i3 & 0x1));
			state[-2 + 20] = -((bool)(i3 & 0x2));
			state[-2 + 37] = -((bool)(i3 & 0x4));

			// 0xff07ffffffff
			const bitslice_t filter3_1 = f_b_bs(state[-2 + 11], state[-2 + 15], state[-2 + 17], state[-2 + 18]);
			const bitslice_t filter3_2 = f_b_bs(state[-2 + 20], state[-2 + 24], state[-2 + 26], state[-2 + 29]);
			const bitslice_t filter3_4 = f_a_bs(state[-2 + 37], state[-2 + 46], state[-2 + 47], state[-2 + 49]);
			const bitslice_t filter3 = f_c_bs(filter3_0, filter3_1, filter3_2, filter3_3, filter3_4);

			const bitslice_t results3 = bs_res(results2,filter3,keystream[3]);
			if (!results3) continue;

			state[-2 + 51] = lfsr_bs(3);
			state[-2 + 52] = lfsr_bs(4);
			state[-2 + 53] = lfsr_bs(5);
			state[-2 + 54] = lfsr_bs(6);
			state[-2 + 55] = lfsr_bs(7);

			const bitslice_t filter4_3 = f_b_bs(state[-2 + 32], state[-2 + 33], state[-2 + 35], state[-2 + 37]);
			const bitslice_t filter5_0 = f_a_bs(state[-2 + 7], state[-2 + 8], state[-2 + 10], state[-2 + 11]);
			const bitslice_t filter5_1 = f_b_bs(state[-2 + 13], state[-2 + 17], state[-2 + 19], state[-2 + 20]);
			const bitslice_t filter6_0 = f_a_bs(state[-2 + 8], state[-2 + 9], state[-2 + 11], state[-2 + 12]);
			const bitslice_t filter6_1 = f_b_bs(state[-2 + 14], state[-2 + 18], state[-2 + 20], state[-2 + 21]);
			const bitslice_t filter8_0 = f_a_bs(state[-2 + 10], state[-2 + 11], state[-2 + 13], state[-2 + 14]);
			const bitslice_t filter8_1 = f_b_bs(state[-2 + 16], state[-2 + 20], state[-2 + 22], state[-2 + 23]);
			const bitslice_t filter9_0 = f_a_bs(state[-2 + 11], state[-2 + 12], state[-2 + 14], state[-2 + 15]);
			const bitslice_t filter9_4 = f_a_bs(state[-2 + 43], state[-2 + 52], state[-2 + 53], state[-2 + 55]);
			const bitslice_t filter11_2 = f_b_bs(state[-2 + 28], state[-2 + 32], state[-2 + 34], state[-2 + 37]);
			const bitslice_t filter12_1 = f_b_bs(state[-2 + 20], state[-2 + 24], state[-2 + 26], state[-2 + 27]);
			const bitslice_t filter14_0 = f_a_bs(state[-2 + 16], state[-2 + 17], state[-2 + 19], state[-2 + 20]);
			const bitslice_t filter15_0 = f_a_bs(state[-2 + 17], state[-2 + 18], state[-2 + 20], state[-2 + 21]);
			const bitslice_t filter17_0 = f_a_bs(state[-2 + 19], state[-2 + 20], state[-2 + 22], state[-2 + 23]);

			for (uint i4 = 0; i4 < 2; i4++) {
				state[-2 + 38] = -i4;

				// 0xff87ffffffff
				const bitslice_t filter4_4 = f_a_bs(state[-2 + 38], state[-2 + 47], state[-2 + 48], state[-2 + 50]);
				const bitslice_t filter4 = f_c_bs(filter4_0, filter4_1, filter4_2, filter4_3, filter4_4);

				const bitslice_t results4 = bs_res(results3,filter4,keystream[4]);
				if (!results4) continue;

				state[-2 + 56] = lfsr_bs(8);
				const bitslice_t filter5_3 = f_b_bs(state[-2 + 33], state[-2 + 34], state[-2 + 36], state[-2 + 38]);
				const bitslice_t filter10_4 = f_a_bs(state[-2 + 44], state[-2 + 53], state[-2 + 54], state[-2 + 56]);
				const bitslice_t filter12_2 = f_b_bs(state[-2 + 29], state[-2 + 33], state[-2 + 35], state[-2 + 38]);

				for (uint i5 = 0; i5 < 2; i5++) {
					state[-2 + 39] = -i5;

					// 0xffc7ffffffff
					const bitslice_t filter5_4 = f_a_bs(state[-2 + 39], state[-2 + 48], state[-2 + 49], state[-2 + 51]);
					const bitslice_t filter5 = f_c_bs(filter5_0, filter5_1, filter5_2, filter5_3, filter5_4);

					const bitslice_t results5 = bs_res(results4,filter5,keystream[5]);
					if (!results5) continue;

					state[-2 + 57] = lfsr_bs(9);
					const bitslice_t filter6_3 = f_b_bs(state[-2 + 34], state[-2 + 35], state[-2 + 37], state[-2 + 39]);
					const bitslice_t filter11_4 = f_a_bs(state[-2 + 45], state[-2 + 54], state[-2 + 55], state[-2 + 57]);
					const bitslice_t filter13_2 = f_b_bs(state[-2 + 30], state[-2 + 34], state[-2 + 36], state[-2 + 39]);

					for (uint i6 = 0; i6 < 2; i6++) {
						state[-2 + 40] = -i6;

						// 0xffe7ffffffff
						const bitslice_t filter6_4 = f_a_bs(state[-2 + 40], state[-2 + 49], state[-2 + 50], state[-2 + 52]);
						const bitslice_t filter6 = f_c_bs(filter6_0, filter6_1, filter6_2, filter6_3, filter6_4);

						const bitslice_t results6 = bs_res(results5,filter6,keystream[6]);
						if (!results6) continue;

						state[-2 + 58] = lfsr_bs(10);
						const bitslice_t filter7_3 = f_b_bs(state[-2 + 35], state[-2 + 36], state[-2 + 38], state[-2 + 40]);
						const bitslice_t filter12_4 = f_a_bs(state[-2 + 46], state[-2 + 55], state[-2 + 56], state[-2 + 58]);
						const bitslice_t filter14_2 = f_b_bs(state[-2 + 31], state[-2 + 35], state[-2 + 37], state[-2 + 40]);
						const bitslice_t filter17_2 = f_b_bs(state[-2 + 34], state[-2 + 38], state[-2 + 40], state[-2 + 43]);

						#pragma unroll
						for (uint i7 = 0; i7 < 2; i7++) {
							state[-2 + 41] = -i7;

							// 0xfff7ffffffff
							const bitslice_t filter7_4 = f_a_bs(state[-2 + 41], state[-2 + 50], state[-2 + 51], state[-2 + 53]);
							const bitslice_t filter7 = f_c_bs(filter7_0, filter7_1, filter7_2, filter7_3, filter7_4);

							const bitslice_t results7 = bs_res(results6,filter7,keystream[7]);
							if (!results7) continue;

							state[-2 + 59] = lfsr_bs(11);
							const bitslice_t filter8_3 = f_b_bs(state[-2 + 36], state[-2 + 37], state[-2 + 39], state[-2 + 41]);
							const bitslice_t filter10_3 = f_b_bs(state[-2 + 38], state[-2 + 39], state[-2 + 41], state[-2 + 43]);
							const bitslice_t filter10 = f_c_bs(filter10_0, filter10_1, filter10_2, filter10_3, filter10_4);
							const bitslice_t filter12_3 = f_b_bs(state[-2 + 40], state[-2 + 41], state[-2 + 43], state[-2 + 45]);
							const bitslice_t filter12 = f_c_bs(filter12_0, filter12_1, filter12_2, filter12_3, filter12_4);
							const bitslice_t filter13_4 = f_a_bs(state[-2 + 47], state[-2 + 56], state[-2 + 57], state[-2 + 59]);
							const bitslice_t filter15_2 = f_b_bs(state[-2 + 32], state[-2 + 36], state[-2 + 38], state[-2 + 41]);

							#pragma unroll
							for (uint i8 = 0; i8 < 2; i8++) {
								state[-2 + 42] = -i8;

								// 0xffffffffffff
								const bitslice_t filter8_4 = f_a_bs(state[-2 + 42], state[-2 + 51], state[-2 + 52], state[-2 + 54]);
								const bitslice_t filter8 = f_c_bs(filter8_0, filter8_1, filter8_2, filter8_3, filter8_4);

								bitslice_t results8 = bs_res(results7,filter8,keystream[8]);
								if (!results8) continue;

								const bitslice_t filter9_3 = f_b_bs(state[-2 + 37], state[-2 + 38], state[-2 + 40], state[-2 + 42]);
								const bitslice_t filter9 = f_c_bs(filter9_0, filter9_1, filter9_2, filter9_3, filter9_4);

								results8 &= (filter9 ^ keystream[9]);
								if (!results8) continue;

								results8 &= (filter10 ^ keystream[10]);
								if (!results8) continue;

								const bitslice_t filter11_3 = f_b_bs(state[-2 + 39], state[-2 + 40], state[-2 + 42], state[-2 + 44]);
								const bitslice_t filter11 = f_c_bs(filter11_0, filter11_1, filter11_2, filter11_3, filter11_4);

								results8 &= (filter11 ^ keystream[11]);
								if (!results8) continue;

								results8 &= (filter12 ^ keystream[12]);
								if (!results8) continue;

								const bitslice_t filter13_3 = f_b_bs(state[-2 + 41], state[-2 + 42], state[-2 + 44], state[-2 + 46]);
								const bitslice_t filter13 = f_c_bs(filter13_0, filter13_1, filter13_2, filter13_3, filter13_4);

								results8 &= (filter13 ^ keystream[13]);
								if (!results8) continue;

								state[-2 + 60] = lfsr_bs(12);
								const bitslice_t filter14_3 = f_b_bs(state[-2 + 42], state[-2 + 43], state[-2 + 45], state[-2 + 47]);
								const bitslice_t filter14_4 = f_a_bs(state[-2 + 48], state[-2 + 57], state[-2 + 58], state[-2 + 60]);
								const bitslice_t filter14 = f_c_bs(filter14_0, filter14_1, filter14_2, filter14_3, filter14_4);

								results8 &= (filter14 ^ keystream[14]);
								if (!results8) continue;

								state[-2 + 61] = lfsr_bs(13);
								const bitslice_t filter15_4 = f_a_bs(state[-2 + 49], state[-2 + 58], state[-2 + 59], state[-2 + 61]);
								const bitslice_t filter15 = f_c_bs(filter15_0, filter15_1, filter15_2, filter15_3, filter15_4);

								results8 &= (filter15 ^ keystream[15]);
								if (!results8) continue;

								state[-2 + 62] = lfsr_bs(14);
								const bitslice_t filter16_2 = f_b_bs(state[-2 + 33], state[-2 + 37], state[-2 + 39], state[-2 + 42]);
								const bitslice_t filter16_4 = f_a_bs(state[-2 + 50], state[-2 + 59], state[-2 + 60], state[-2 + 62]);
								const bitslice_t filter16 = f_c_bs(filter16_0, filter16_1, filter16_2, filter16_3, filter16_4);

								results8 &= (filter16 ^ keystream[16]);
								if (!results8) continue;

								state[-2 + 63] = lfsr_bs(15);
								const bitslice_t filter17_4 = f_a_bs(state[-2 + 51], state[-2 + 60], state[-2 + 61], state[-2 + 63]);
								const bitslice_t filter17 = f_c_bs(filter17_0, filter17_1, filter17_2, filter17_3, filter17_4);

								results8 &= (filter17 ^ keystream[17]);
								if (!results8) continue;

								state[-2 + 64] = lfsr_bs(16);
								const bitslice_t filter18_0 = f_a_bs(state[-2 + 20], state[-2 + 21], state[-2 + 23], state[-2 + 24]);
								const bitslice_t filter18_1 = f_b_bs(state[-2 + 26], state[-2 + 30], state[-2 + 32], state[-2 + 33]);
								const bitslice_t filter18_2 = f_b_bs(state[-2 + 35], state[-2 + 39], state[-2 + 41], state[-2 + 44]);
								const bitslice_t filter18_3 = f_b_bs(state[-2 + 46], state[-2 + 47], state[-2 + 49], state[-2 + 51]);
								const bitslice_t filter18_4 = f_a_bs(state[-2 + 52], state[-2 + 61], state[-2 + 62], state[-2 + 64]);
								const bitslice_t filter18 = f_c_bs(filter18_0, filter18_1, filter18_2, filter18_3, filter18_4);

								results8 &= (filter18 ^ keystream[18]);
								if (!results8) continue;

								state[-2 + 65] = lfsr_bs(17);
								const bitslice_t filter19_0 = f_a_bs(state[-2 + 21], state[-2 + 22], state[-2 + 24], state[-2 + 25]);
								const bitslice_t filter19_1 = f_b_bs(state[-2 + 27], state[-2 + 31], state[-2 + 33], state[-2 + 34]);
								const bitslice_t filter19_2 = f_b_bs(state[-2 + 36], state[-2 + 40], state[-2 + 42], state[-2 + 45]);
								const bitslice_t filter19_3 = f_b_bs(state[-2 + 47], state[-2 + 48], state[-2 + 50], state[-2 + 52]);
								const bitslice_t filter19_4 = f_a_bs(state[-2 + 53], state[-2 + 62], state[-2 + 63], state[-2 + 65]);
								const bitslice_t filter19 = f_c_bs(filter19_0, filter19_1, filter19_2, filter19_3, filter19_4);

								results8 &= (filter19 ^ keystream[19]);
								if (!results8) continue;

								state[-2 + 66] = lfsr_bs(18);
								const bitslice_t filter20_0 = f_a_bs(state[-2 + 22], state[-2 + 23], state[-2 + 25], state[-2 + 26]);
								const bitslice_t filter20_1 = f_b_bs(state[-2 + 28], state[-2 + 32], state[-2 + 34], state[-2 + 35]);
								const bitslice_t filter20_2 = f_b_bs(state[-2 + 37], state[-2 + 41], state[-2 + 43], state[-2 + 46]);
								const bitslice_t filter20_3 = f_b_bs(state[-2 + 48], state[-2 + 49], state[-2 + 51], state[-2 + 53]);
								const bitslice_t filter20_4 = f_a_bs(state[-2 + 54], state[-2 + 63], state[-2 + 64], state[-2 + 66]);
								const bitslice_t filter20 = f_c_bs(filter20_0, filter20_1, filter20_2, filter20_3, filter20_4);

								results8 &= (filter20 ^ keystream[20]);
								if (!results8) continue;

								state[-2 + 67] = lfsr_bs(19);
								const bitslice_t filter21_0 = f_a_bs(state[-2 + 23], state[-2 + 24], state[-2 + 26], state[-2 + 27]);
								const bitslice_t filter21_1 = f_b_bs(state[-2 + 29], state[-2 + 33], state[-2 + 35], state[-2 + 36]);
								const bitslice_t filter21_2 = f_b_bs(state[-2 + 38], state[-2 + 42], state[-2 + 44], state[-2 + 47]);
								const bitslice_t filter21_3 = f_b_bs(state[-2 + 49], state[-2 + 50], state[-2 + 52], state[-2 + 54]);
								const bitslice_t filter21_4 = f_a_bs(state[-2 + 55], state[-2 + 64], state[-2 + 65], state[-2 + 67]);
								const bitslice_t filter21 = f_c_bs(filter21_0, filter21_1, filter21_2, filter21_3, filter21_4);

								results8 &= (filter21 ^ keystream[21]);
								if (!results8) continue;

								state[-2 + 68] = lfsr_bs(20);
								const bitslice_t filter22_0 = f_a_bs(state[-2 + 24], state[-2 + 25], state[-2 + 27], state[-2 + 28]);
								const bitslice_t filter22_1 = f_b_bs(state[-2 + 30], state[-2 + 34], state[-2 + 36], state[-2 + 37]);
								const bitslice_t filter22_2 = f_b_bs(state[-2 + 39], state[-2 + 43], state[-2 + 45], state[-2 + 48]);
								const bitslice_t filter22_3 = f_b_bs(state[-2 + 50], state[-2 + 51], state[-2 + 53], state[-2 + 55]);
								const bitslice_t filter22_4 = f_a_bs(state[-2 + 56], state[-2 + 65], state[-2 + 66], state[-2 + 68]);
								const bitslice_t filter22 = f_c_bs(filter22_0, filter22_1, filter22_2, filter22_3, filter22_4);

								results8 &= (filter22 ^ keystream[22]);
								if (!results8) continue;

								state[-2 + 69] = lfsr_bs(21);
								const bitslice_t filter23_0 = f_a_bs(state[-2 + 25], state[-2 + 26], state[-2 + 28], state[-2 + 29]);
								const bitslice_t filter23_1 = f_b_bs(state[-2 + 31], state[-2 + 35], state[-2 + 37], state[-2 + 38]);
								const bitslice_t filter23_2 = f_b_bs(state[-2 + 40], state[-2 + 44], state[-2 + 46], state[-2 + 49]);
								const bitslice_t filter23_3 = f_b_bs(state[-2 + 51], state[-2 + 52], state[-2 + 54], state[-2 + 56]);
								const bitslice_t filter23_4 = f_a_bs(state[-2 + 57], state[-2 + 66], state[-2 + 67], state[-2 + 69]);
								const bitslice_t filter23 = f_c_bs(filter23_0, filter23_1, filter23_2, filter23_3, filter23_4);

								results8 &= (filter23 ^ keystream[23]);
								if (!results8) continue;

								state[-2 + 70] = lfsr_bs(22);
								const bitslice_t filter24_0 = f_a_bs(state[-2 + 26], state[-2 + 27], state[-2 + 29], state[-2 + 30]);
								const bitslice_t filter24_1 = f_b_bs(state[-2 + 32], state[-2 + 36], state[-2 + 38], state[-2 + 39]);
								const bitslice_t filter24_2 = f_b_bs(state[-2 + 41], state[-2 + 45], state[-2 + 47], state[-2 + 50]);
								const bitslice_t filter24_3 = f_b_bs(state[-2 + 52], state[-2 + 53], state[-2 + 55], state[-2 + 57]);
								const bitslice_t filter24_4 = f_a_bs(state[-2 + 58], state[-2 + 67], state[-2 + 68], state[-2 + 70]);
								const bitslice_t filter24 = f_c_bs(filter24_0, filter24_1, filter24_2, filter24_3, filter24_4);

								results8 &= (filter24 ^ keystream[24]);
								if (!results8) continue;

								state[-2 + 71] = lfsr_bs(23);
								const bitslice_t filter25_0 = f_a_bs(state[-2 + 27], state[-2 + 28], state[-2 + 30], state[-2 + 31]);
								const bitslice_t filter25_1 = f_b_bs(state[-2 + 33], state[-2 + 37], state[-2 + 39], state[-2 + 40]);
								const bitslice_t filter25_2 = f_b_bs(state[-2 + 42], state[-2 + 46], state[-2 + 48], state[-2 + 51]);
								const bitslice_t filter25_3 = f_b_bs(state[-2 + 53], state[-2 + 54], state[-2 + 56], state[-2 + 58]);
								const bitslice_t filter25_4 = f_a_bs(state[-2 + 59], state[-2 + 68], state[-2 + 69], state[-2 + 71]);
								const bitslice_t filter25 = f_c_bs(filter25_0, filter25_1, filter25_2, filter25_3, filter25_4);

								results8 &= (filter25 ^ keystream[25]);
								if (!results8) continue;

								state[-2 + 72] = lfsr_bs(24);
								const bitslice_t filter26_0 = f_a_bs(state[-2 + 28], state[-2 + 29], state[-2 + 31], state[-2 + 32]);
								const bitslice_t filter26_1 = f_b_bs(state[-2 + 34], state[-2 + 38], state[-2 + 40], state[-2 + 41]);
								const bitslice_t filter26_2 = f_b_bs(state[-2 + 43], state[-2 + 47], state[-2 + 49], state[-2 + 52]);
								const bitslice_t filter26_3 = f_b_bs(state[-2 + 54], state[-2 + 55], state[-2 + 57], state[-2 + 59]);
								const bitslice_t filter26_4 = f_a_bs(state[-2 + 60], state[-2 + 69], state[-2 + 70], state[-2 + 72]);
								const bitslice_t filter26 = f_c_bs(filter26_0, filter26_1, filter26_2, filter26_3, filter26_4);

								results8 &= (filter26 ^ keystream[26]);
								if (!results8) continue;

								state[-2 + 73] = lfsr_bs(25);
								const bitslice_t filter27_0 = f_a_bs(state[-2 + 29], state[-2 + 30], state[-2 + 32], state[-2 + 33]);
								const bitslice_t filter27_1 = f_b_bs(state[-2 + 35], state[-2 + 39], state[-2 + 41], state[-2 + 42]);
								const bitslice_t filter27_2 = f_b_bs(state[-2 + 44], state[-2 + 48], state[-2 + 50], state[-2 + 53]);
								const bitslice_t filter27_3 = f_b_bs(state[-2 + 55], state[-2 + 56], state[-2 + 58], state[-2 + 60]);
								const bitslice_t filter27_4 = f_a_bs(state[-2 + 61], state[-2 + 70], state[-2 + 71], state[-2 + 73]);
								const bitslice_t filter27 = f_c_bs(filter27_0, filter27_1, filter27_2, filter27_3, filter27_4);

								results8 &= (filter27 ^ keystream[27]);
								if (!results8) continue;

								state[-2 + 74] = lfsr_bs(26);
								const bitslice_t filter28_0 = f_a_bs(state[-2 + 30], state[-2 + 31], state[-2 + 33], state[-2 + 34]);
								const bitslice_t filter28_1 = f_b_bs(state[-2 + 36], state[-2 + 40], state[-2 + 42], state[-2 + 43]);
								const bitslice_t filter28_2 = f_b_bs(state[-2 + 45], state[-2 + 49], state[-2 + 51], state[-2 + 54]);
								const bitslice_t filter28_3 = f_b_bs(state[-2 + 56], state[-2 + 57], state[-2 + 59], state[-2 + 61]);
								const bitslice_t filter28_4 = f_a_bs(state[-2 + 62], state[-2 + 71], state[-2 + 72], state[-2 + 74]);
								const bitslice_t filter28 = f_c_bs(filter28_0, filter28_1, filter28_2, filter28_3, filter28_4);

								results8 &= (filter28 ^ keystream[28]);
								if (!results8) continue;

								state[-2 + 75] = lfsr_bs(27);
								const bitslice_t filter29_0 = f_a_bs(state[-2 + 31], state[-2 + 32], state[-2 + 34], state[-2 + 35]);
								const bitslice_t filter29_1 = f_b_bs(state[-2 + 37], state[-2 + 41], state[-2 + 43], state[-2 + 44]);
								const bitslice_t filter29_2 = f_b_bs(state[-2 + 46], state[-2 + 50], state[-2 + 52], state[-2 + 55]);
								const bitslice_t filter29_3 = f_b_bs(state[-2 + 57], state[-2 + 58], state[-2 + 60], state[-2 + 62]);
								const bitslice_t filter29_4 = f_a_bs(state[-2 + 63], state[-2 + 72], state[-2 + 73], state[-2 + 75]);
								const bitslice_t filter29 = f_c_bs(filter29_0, filter29_1, filter29_2, filter29_3, filter29_4);

								results8 &= (filter29 ^ keystream[29]);
								if (!results8) continue;

								state[-2 + 76] = lfsr_bs(28);
								const bitslice_t filter30_0 = f_a_bs(state[-2 + 32], state[-2 + 33], state[-2 + 35], state[-2 + 36]);
								const bitslice_t filter30_1 = f_b_bs(state[-2 + 38], state[-2 + 42], state[-2 + 44], state[-2 + 45]);
								const bitslice_t filter30_2 = f_b_bs(state[-2 + 47], state[-2 + 51], state[-2 + 53], state[-2 + 56]);
								const bitslice_t filter30_3 = f_b_bs(state[-2 + 58], state[-2 + 59], state[-2 + 61], state[-2 + 63]);
								const bitslice_t filter30_4 = f_a_bs(state[-2 + 64], state[-2 + 73], state[-2 + 74], state[-2 + 76]);
								const bitslice_t filter30 = f_c_bs(filter30_0, filter30_1, filter30_2, filter30_3, filter30_4);

								results8 &= (filter30 ^ keystream[30]);
								if (!results8) continue;

								state[-2 + 77] = lfsr_bs(29);
								const bitslice_t filter31_0 = f_a_bs(state[-2 + 33], state[-2 + 34], state[-2 + 36], state[-2 + 37]);
								const bitslice_t filter31_1 = f_b_bs(state[-2 + 39], state[-2 + 43], state[-2 + 45], state[-2 + 46]);
								const bitslice_t filter31_2 = f_b_bs(state[-2 + 48], state[-2 + 52], state[-2 + 54], state[-2 + 57]);
								const bitslice_t filter31_3 = f_b_bs(state[-2 + 59], state[-2 + 60], state[-2 + 62], state[-2 + 64]);
								const bitslice_t filter31_4 = f_a_bs(state[-2 + 65], state[-2 + 74], state[-2 + 75], state[-2 + 77]);
								const bitslice_t filter31 = f_c_bs(filter31_0, filter31_1, filter31_2, filter31_3, filter31_4);

								results8 &= (filter31 ^ keystream[31]);
								if (!results8) continue;

								for (uint match_index = 0; match_index < MAX_BITSLICES && results8;) {
									const uint shift = clz(results8) + 1;
									match_index += shift;

									#ifdef WITH_HITAG2_FULL

									ulong state_check = unbitslice (&state[-2 + 2], MAX_BITSLICES - match_index);

									// 2 rollback
									state_check = (ulong)(((state_check << 1) & 0xffffffffffff) | (ulong)fnR(state_check));
									state_check = (ulong)(((state_check << 1) & 0xffffffffffff) | (ulong)fnR(state_check));

									// recover key
									ulong keyrev = state_check & 0xffff;
									ulong nR1xk = (state_check >> 16) & 0xffffffff;

									uint b = 0;

									for (uint i = 0; i < 32; i++) {
										state_check = ((state_check) << 1) | ((checks[0] >> (31 - i)) & 0x1);
										b = (b << 1) | fnf (state_check);
									}

									keyrev |= (nR1xk ^ checks[2] ^ b) << 16;

									ulong lfsr = 0;

									// test key
									hitag2_init2 (&state_check, &lfsr, keyrev, checks[0], checks[3]);

									if ((checks[1] ^ hitag2_nstep2 (state_check, lfsr)) == 0xffffffff)
									{
										// there can be only one (Highlander) :P
										matches[atomic_inc(matches_found)] = rev64 (keyrev);
										return;
									}

									#else

									// take the state from layer 2 so we can recover the lowest 2 bits on the host by inverting the LFSR
									matches[atomic_inc(matches_found)] = unbitslice (&state[-2 + 2], MAX_BITSLICES - match_index);


									#endif // WITH_HITAG2_FULL

									results8 <<= shift;
								} // key check
							} // 8
						} // 7
					} // 6
				} // 5
			} // 4
		} // 3
	} // 2
} // 1
