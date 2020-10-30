/* ht2crack5kernel.cl
 *
 * This code is heavily based on the HiTag2 Hell CPU implementation
 *  from https://github.com/factoritbv/hitag2hell by FactorIT B.V.
 * This file is the file openocl.cl with the following change:
 *  * promote keystream from constant to argument.
 */

#define MAX_BITSLICES 32
#define KEYSTREAM_LENGTH 32
typedef uint bitslice_t __attribute__((aligned(MAX_BITSLICES / 8)));

inline uint lut3(uint a, uint b, uint c, uint imm) {
    uint r;
    asm("lop3.b32 %0, %1, %2, %3, %4;"
        : "=r"(r)
        : "r"(a), "r"(b), "r"(c), "i"(imm));
    return r;
}
#define f_a_bs_lut_1          (((0xf0|0xcc)&0xaa)^0xcc)
#define f_a_bs_lut_2          (~((0xf0|0xcc)^0xaa))
#define f_a_bs(a,b,c,d)       ((lut3(a,d,lut3(a,b,c,f_a_bs_lut_1),f_a_bs_lut_2))) // 2 luts

#define f_b_bs_lut_1          (((0xf0|0xcc)&0xaa))
#define f_b_bs_lut_2          (~((0xf0|0xcc|0xaa)))
#define f_b_bs(a,b,c,d)       ((lut3(d,c,a^b,f_b_bs_lut_1)^lut3(d,a,b, f_b_bs_lut_2))) // 2 luts, 2 xors

#define f_c_bs_lut_1          (((0xf0^0xcc)|0xaa))
#define f_c_bs_lut_2          (~((0xf0^0xcc)&(0xaa^0xcc)))

// 4 luts, 2 ands, 1 xor
#define f_c_bs(a,b,c,d,e)     (((lut3((lut3(c,e,d, f_c_bs_lut_1) & a), b, c, f_c_bs_lut_2)) ^ (lut3(d,e,a, f_c_bs_lut_1) & lut3(d,b,c,f_c_bs_lut_1))))

// non-lut version of F: 20 lookups + 6*2 + 7*3 + 13 + = 66 ops
// lut version:          20 lookups + 2*2 + 4*3 + 7 + = 43 ops

#define lfsr_lut (0xf0^0xaa^0xcc)
// 7 luts, 1 xor
#define lfsr_bs(i) ( lut3(lut3(lut3(state[-2+i+ 0], state[-2+i+ 2], state[-2+i+ 3], lfsr_lut), \
                               lut3(state[-2+i+ 6], state[-2+i+ 7], state[-2+i+ 8], lfsr_lut), \
                               lut3(state[-2+i+16], state[-2+i+22], state[-2+i+23], lfsr_lut), \
                               lfsr_lut), \
                          lut3(state[-2+i+26], state[-2+i+30], state[-2+i+41], lfsr_lut), \
                          lut3(state[-2+i+42], state[-2+i+43], state[-2+i+46], lfsr_lut), lfsr_lut) ^ state[-2+i+47])

// 46 iterations * 4 ops
inline void bitslice(bitslice_t *restrict b, ulong x, const uchar n) {
    for (uchar i = 0; i < n; ++i) {
        b[i] = -(x & 1);
        x >>= 1;
    }
}

// don't care about the complexity of this function
inline ulong unbitslice(const bitslice_t *restrict b, const uchar s, const uchar n) {
    const bitslice_t mask = ((bitslice_t) 1) << s;
    ulong result = 0;
    for (char i = n - 1; i >= 0; --i) {
        result <<= 1;
        result |= (bool)(b[i] & mask);
    }
    return result;
}

// format this array with 32 bitsliced vectors of ones and zeroes representing the inverted keystream

__kernel
__attribute__((vec_type_hint(bitslice_t)))
void find_state(const uint candidate_index_base,
                __global const ushort *restrict candidates,
                __global const bitslice_t *restrict keystream,
                __global ulong *restrict matches,
                __global uint *restrict matches_found) {
    // we never actually set or use the lowest 2 bits the initial state, so we can save 2 bitslices everywhere
    bitslice_t state[-2 + 48 + KEYSTREAM_LENGTH];
    // set bits 0+2, 0+3, 0+5, 0+6, 0+8, 0+12, 0+14, 0+15, 0+17, 0+21, 0+23, 0+26, 0+28, 0+29, 0+31, 0+33, 0+34, 0+43, 0+44, 0+46
    // get the 48-bit cipher states as 3 16-bit words from the host memory queue (to save 25% throughput)
    const uint index = 3 * (candidate_index_base + get_global_id(0)); // dimension 0 should at least keep the execution units saturated - 8k is fine
    const ulong candidate = ((ulong) candidates[index] << 32) | ((ulong) candidates[index + 1] << 16) | candidates[index + 2];
    // set all 48 state bits except the lowest 2
    bitslice(&state[-2 + 2], candidate, 46);
    // set bits 3, 6, 8, 12, 15
    state[-2 + 1 + 3] = 0xaaaaaaaa;
    state[-2 + 1 + 6] = 0xcccccccc;
    state[-2 + 1 + 8] = 0xf0f0f0f0;
    state[-2 + 1 + 12] = 0xff00ff00;
    state[-2 + 1 + 15] = 0xffff0000;
    ushort i1 = get_global_id(1); // dimension 1 should be 1024
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
    for (uchar i2 = 0; i2 < (1 << 5);) {
        state[-2 + 10] = -((bool)(i2 & 0x1));
        state[-2 + 19] = -((bool)(i2 & 0x2));
        state[-2 + 25] = -((bool)(i2 & 0x4));
        state[-2 + 36] = -((bool)(i2 & 0x8));
        state[-2 + 49] = -((bool)(i2 & 0x10)); // guess lfsr output 1
        i2++;
        // 0xfe07fffbfdff
        const bitslice_t filter2_1 = f_b_bs(state[-2 + 10], state[-2 + 14], state[-2 + 16], state[-2 + 17]);
        const bitslice_t filter2_2 = f_b_bs(state[-2 + 19], state[-2 + 23], state[-2 + 25], state[-2 + 28]);
        const bitslice_t filter2_4 = f_a_bs(state[-2 + 36], state[-2 + 45], state[-2 + 46], state[-2 + 48]);
        const bitslice_t filter2 = f_c_bs(filter2_0, filter2_1, filter2_2, filter2_3, filter2_4);
        const bitslice_t results2 = results1 & (filter2 ^ keystream[2]);
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
        for (uchar i3 = 0; i3 < (1 << 3);) {
            state[-2 + 11] = -((bool)(i3 & 0x1));
            state[-2 + 20] = -((bool)(i3 & 0x2));
            state[-2 + 37] = -((bool)(i3 & 0x4));
            i3++;
            // 0xff07ffffffff
            const bitslice_t filter3_1 = f_b_bs(state[-2 + 11], state[-2 + 15], state[-2 + 17], state[-2 + 18]);
            const bitslice_t filter3_2 = f_b_bs(state[-2 + 20], state[-2 + 24], state[-2 + 26], state[-2 + 29]);
            const bitslice_t filter3_4 = f_a_bs(state[-2 + 37], state[-2 + 46], state[-2 + 47], state[-2 + 49]);
            const bitslice_t filter3 = f_c_bs(filter3_0, filter3_1, filter3_2, filter3_3, filter3_4);
            const bitslice_t results3 = results2 & (filter3 ^ keystream[3]);
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
            for (uchar i4 = 0; i4 < (1 << 1);) {
                state[-2 + 38] = -i4;
                i4++;
                // 0xff87ffffffff
                const bitslice_t filter4_4 = f_a_bs(state[-2 + 38], state[-2 + 47], state[-2 + 48], state[-2 + 50]);
                const bitslice_t filter4 = f_c_bs(filter4_0, filter4_1, filter4_2, filter4_3, filter4_4);
                const bitslice_t results4 = results3 & (filter4 ^ keystream[4]);
                if (!results4) continue;
                state[-2 + 56] = lfsr_bs(8);
                const bitslice_t filter5_3 = f_b_bs(state[-2 + 33], state[-2 + 34], state[-2 + 36], state[-2 + 38]);
                const bitslice_t filter10_4 = f_a_bs(state[-2 + 44], state[-2 + 53], state[-2 + 54], state[-2 + 56]);
                const bitslice_t filter12_2 = f_b_bs(state[-2 + 29], state[-2 + 33], state[-2 + 35], state[-2 + 38]);
                for (uchar i5 = 0; i5 < (1 << 1);) {
                    state[-2 + 39] = -i5;
                    i5++;
                    // 0xffc7ffffffff
                    const bitslice_t filter5_4 = f_a_bs(state[-2 + 39], state[-2 + 48], state[-2 + 49], state[-2 + 51]);
                    const bitslice_t filter5 = f_c_bs(filter5_0, filter5_1, filter5_2, filter5_3, filter5_4);
                    const bitslice_t results5 = results4 & (filter5 ^ keystream[5]);
                    if (!results5) continue;
                    state[-2 + 57] = lfsr_bs(9);
                    const bitslice_t filter6_3 = f_b_bs(state[-2 + 34], state[-2 + 35], state[-2 + 37], state[-2 + 39]);
                    const bitslice_t filter11_4 = f_a_bs(state[-2 + 45], state[-2 + 54], state[-2 + 55], state[-2 + 57]);
                    const bitslice_t filter13_2 = f_b_bs(state[-2 + 30], state[-2 + 34], state[-2 + 36], state[-2 + 39]);
                    for (uchar i6 = 0; i6 < (1 << 1);) {
                        state[-2 + 40] = -i6;
                        i6++;
                        // 0xffe7ffffffff
                        const bitslice_t filter6_4 = f_a_bs(state[-2 + 40], state[-2 + 49], state[-2 + 50], state[-2 + 52]);
                        const bitslice_t filter6 = f_c_bs(filter6_0, filter6_1, filter6_2, filter6_3, filter6_4);
                        const bitslice_t results6 = results5 & (filter6 ^ keystream[6]);
                        if (!results6) continue;
                        state[-2 + 58] = lfsr_bs(10);
                        const bitslice_t filter7_3 = f_b_bs(state[-2 + 35], state[-2 + 36], state[-2 + 38], state[-2 + 40]);
                        const bitslice_t filter12_4 = f_a_bs(state[-2 + 46], state[-2 + 55], state[-2 + 56], state[-2 + 58]);
                        const bitslice_t filter14_2 = f_b_bs(state[-2 + 31], state[-2 + 35], state[-2 + 37], state[-2 + 40]);
                        const bitslice_t filter17_2 = f_b_bs(state[-2 + 34], state[-2 + 38], state[-2 + 40], state[-2 + 43]);
#pragma unroll
                        for (uchar i7 = 0; i7 < (1 << 1);) {
                            state[-2 + 41] = -i7;
                            i7++;
                            // 0xfff7ffffffff
                            const bitslice_t filter7_4 = f_a_bs(state[-2 + 41], state[-2 + 50], state[-2 + 51], state[-2 + 53]);
                            const bitslice_t filter7 = f_c_bs(filter7_0, filter7_1, filter7_2, filter7_3, filter7_4);
                            const bitslice_t results7 = results6 & (filter7 ^ keystream[7]);
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
                            for (uchar i8 = 0; i8 < (1 << 1);) {
                                state[-2 + 42] = -i8;
                                i8++;
                                // 0xffffffffffff
                                const bitslice_t filter8_4 = f_a_bs(state[-2 + 42], state[-2 + 51], state[-2 + 52], state[-2 + 54]);
                                const bitslice_t filter8 = f_c_bs(filter8_0, filter8_1, filter8_2, filter8_3, filter8_4);
                                bitslice_t results8 = results7 & (filter8 ^ keystream[8]);
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
                                uchar match_index = 0;
                                // Save results
                                while (results8 && (match_index < MAX_BITSLICES)) {
                                    uchar shift = clz(results8) + 1;
                                    match_index += shift;
                                    // take the state from layer 2 so we can recover the lowest 2 bits on the host by inverting the LFSR
                                    matches[atomic_inc(matches_found)] = unbitslice(&state[-2 + 2], MAX_BITSLICES - match_index, 48);
                                    results8 <<= shift;
                                }
                            } // 8
                        } // 7
                    } // 6
                } // 5
            } // 4
        } // 3
    } // 2
} // 1

