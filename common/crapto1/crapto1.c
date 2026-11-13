//-----------------------------------------------------------------------------
// Copyright (C) 2008-2014 bla <blapost@gmail.com>
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
#include "crapto1.h"

#include "bucketsort.h"

#include <stdlib.h>
#include <string.h>
#if !defined(__arm__) || defined(__linux__) || defined(_WIN32) || defined(__APPLE__) // bare metal ARM Proxmark lacks pthreads
#include <pthread.h>
#endif
#include "parity.h"


#if !defined LOWMEM
#define CONSTRUCTOR
static uint8_t filterlut[0x100000];
static uint64_t filterbits[0x100000 / 64];
static uint8_t uc_evenparity32_lut[0x10E100A];

// GUNC
#if defined __GNUC__
#undef CONSTRUCTOR
#define CONSTRUCTOR __attribute__((constructor))
#endif

static void CONSTRUCTOR init_lut(void) {

    for (uint32_t i = 0; i < 1 << 20; ++i) {
        filterlut[i] = filter(i);
        filterbits[i >> 6] |= (uint64_t)filter(i) << (i & 63);
    }

    for (uint32_t i = 0; i < 0x10E100A; i++) {
        uc_evenparity32_lut[i] = evenparity32(i);
    }
}

// MSVC
#if defined _MSC_VER

typedef void(__cdecl *PF)(void);
#pragma section(".CRT$XCG", read)
__declspec(allocate(".CRT$XCG")) PF f[] = { init_lut };

#endif

#define filter(x) (filterlut[(x) & 0xfffff])
#define even32(x) (uc_evenparity32_lut[(x)])
#endif

#if !defined LOWMEM
// filter of the 64 states x << 6 | 0..63, as bits
#define filter_word(x) (filterbits[(x)])
// filter of states x, x | 1 (x even), as 2 bits
#define filter_pair(x) ((filterbits[((x) & 0xfffff) >> 6] >> ((x) & 62)) & 3)
#else
static uint64_t filter_word(uint32_t x) {
    uint64_t w = 0;
    for (uint32_t i = 0; i < 64; i++)
        w |= (uint64_t)filter(x << 6 | i) << i;
    return w;
}
#define filter_pair(x) (filter((x) & ~1) | filter((x) | 1) << 1)
#endif

#if defined __GNUC__
#define ctz64(x) __builtin_ctzll(x)
#else
static inline int ctz64(uint64_t x) {
    int n = 0;
    while (!(x & 1)) {
        x >>= 1;
        n++;
    }
    return n;
}
#endif

#define DUAL_THREADS 4
#define DUAL_CHUNK   4096

/** spread2
 * every bit of x doubled
 */
static inline uint64_t spread2(uint32_t x) {
    uint64_t v = x;
    v = (v | v << 16) & 0x0000FFFF0000FFFFULL;
    v = (v | v << 8) & 0x00FF00FF00FF00FFULL;
    v = (v | v << 4) & 0x0F0F0F0F0F0F0F0FULL;
    v = (v | v << 2) & 0x3333333333333333ULL;
    v = (v | v << 1) & 0x5555555555555555ULL;
    return v | v << 1;
}


/** update_contribution helper,
 *  calculates the partial linear feedback contributions and puts in MSB
 */
static inline void update_contribution(uint32_t *item, const uint32_t mask1, const uint32_t mask2) {
    uint32_t p = *item >> 25;
    p = p << 1 | (even32(*item & mask1));
    p = p << 1 | (even32(*item & mask2));
    *item = p << 24 | (*item & 0xffffff);
}

/** extend_table
 * using a bit of the keystream extend the table of possible lfsr states
 */
static inline void extend_table(uint32_t *tbl, uint32_t **end, int bit, int m1, int m2, uint32_t in) {
    register uint8_t tbl_filter;
    in <<= 24;
    for (*tbl <<= 1; tbl <= *end; *++tbl <<= 1) {
        tbl_filter = filter(*tbl);
        if (tbl_filter ^ filter(*tbl | 1)) {
            *tbl |= tbl_filter ^ bit;
            update_contribution(tbl, m1, m2);
            *tbl ^= in;
        } else if (tbl_filter == bit) {
            *++*end = tbl[1];
            tbl[1] = tbl[0] | 1;
            update_contribution(tbl, m1, m2);
            *tbl++ ^= in;
            update_contribution(tbl, m1, m2);
            *tbl ^= in;
        } else
            *tbl-- = *(*end)--;
    }
}

/** extend_table_simple
 * using a bit of the keystream extend the table of possible lfsr states
 */
static inline void extend_table_simple(uint32_t *tbl, uint32_t **end, int bit) {
    register uint8_t tbl_filter;
    for (*tbl <<= 1; tbl <= *end; *++tbl <<= 1) {
        tbl_filter = filter(*tbl);
        if (tbl_filter ^ filter(*tbl | 1)) { // replace
            *tbl |= tbl_filter ^ bit;
        } else if (tbl_filter == bit) {   // insert
            *++*end = *++tbl;
            *tbl = tbl[-1] | 1;
        } else {                            // drop
            *tbl-- = *(*end)--;
        }
    }
}
/** extend_table_dual
 * as extend_table, each new state must also give bit2 when xored with z
 */
static inline void extend_table_dual(uint32_t *tbl, uint32_t **end, int bit, int bit2, uint32_t z, int m1, int m2, uint32_t in) {
    in <<= 24;
    for (*tbl <<= 1; tbl <= *end; *++tbl <<= 1) {
        uint8_t ok0 = (filter(*tbl) == bit) && (filter(*tbl ^ z) == bit2);
        uint8_t ok1 = (filter(*tbl | 1) == bit) && (filter((*tbl | 1) ^ z) == bit2);
        if (ok0 && ok1) {                   // insert
            *++*end = tbl[1];
            tbl[1] = tbl[0] | 1;
            update_contribution(tbl, m1, m2);
            *tbl++ ^= in;
            update_contribution(tbl, m1, m2);
            *tbl ^= in;
        } else if (ok0 || ok1) {            // replace
            *tbl |= ok1;
            update_contribution(tbl, m1, m2);
            *tbl ^= in;
        } else {                            // drop
            *tbl-- = *(*end)--;
        }
    }
}

/** counting_sort_intersect
 * as bucket_sort_intersect, stable counting sort through one contiguous tmp area
 */
static void counting_sort_intersect(uint32_t *estart, uint32_t *estop, uint32_t *ostart, uint32_t *ostop,
                                    bucket_info_t *bucket_info, uint32_t *tmp) {
    uint32_t cnt[2][0x100] = {{0}};
    uint32_t *start[2] = {estart, ostart}, *stop[2] = {estop, ostop};

    for (int i = 0; i < 2; i++)
        for (uint32_t *p = start[i]; p <= stop[i]; p++)
            cnt[i][*p >> 24]++;

    for (int i = 0; i < 2; i++) {
        uint32_t off[0x100], n = 0, nb = 0;
        for (uint32_t j = 0; j <= 0xff; j++) {
            if (cnt[0][j] && cnt[1][j]) {
                bucket_info->bucket_info[i][nb].head = start[i] + n;
                off[j] = n;
                n += cnt[i][j];
                bucket_info->bucket_info[i][nb].tail = start[i] + n - 1;
                nb++;
            } else {
                off[j] = UINT32_MAX;
            }
        }
        for (uint32_t *p = start[i]; p <= stop[i]; p++) {
            uint32_t o = off[*p >> 24];
            if (o != UINT32_MAX) {
                tmp[o] = *p;
                off[*p >> 24]++;
            }
        }
        memcpy(start[i], tmp, n * sizeof(uint32_t));
        bucket_info->numbuckets = nb;
    }
}

#define DUAL_SCRATCH (1 << 21)

// short segments skip the 256 bucket sweep
#define SMALL_INTERSECT 64

/** extend_table_fast
 * as extend_table, branch free into dst. Returns the new count.
 * The two children differ only in bit 0, so one parity pair derives the other.
 */
static uint32_t extend_table_fast(const uint32_t *src, uint32_t n, uint32_t *dst, uint32_t bit,
                                  uint32_t m1, uint32_t m2, uint32_t in) {
    in <<= 24;
    uint32_t d1 = m1 & 1, d2 = m2 & 1;
    uint32_t cnt = 0;
    for (uint32_t k = 0; k < n; k++) {
        uint32_t v = src[k] << 1;
        uint32_t m = filter_pair(v) ^ ((bit - 1) & 3);
        uint32_t top = (v >> 25) << 2;
        uint32_t low = v & 0xffffff;
        uint32_t p = even32(v & m1), q = even32(v & m2);
        dst[cnt] = (((top | p << 1 | q) << 24) | low) ^ in;
        cnt += m & 1;
        dst[cnt] = (((top | (p ^ d1) << 1 | (q ^ d2)) << 24) | (low | 1)) ^ in;
        cnt += m >> 1;
    }
    return cnt;
}

/** sort_small_msb
 * insertion sort by the contribution byte, for short lists
 */
static void sort_small_msb(uint32_t *a, uint32_t n) {
    for (uint32_t i = 1; i < n; i++) {
        uint32_t v = a[i], k = v >> 24, j = i;
        while (j && (a[j - 1] >> 24) > k) {
            a[j] = a[j - 1];
            j--;
        }
        a[j] = v;
    }
}

/** small_intersect
 * as counting_sort_intersect for short lists, without the 256 bucket sweep.
 * Groups each list by contribution byte in place and keeps the common bytes.
 */
static void small_intersect(uint32_t *e, uint32_t ne, uint32_t *o, uint32_t no, bucket_info_t *bucket_info) {
    sort_small_msb(e, ne);
    sort_small_msb(o, no);

    uint32_t i = 0, j = 0, nb = 0;
    while (i < ne && j < no) {
        uint32_t be = e[i] >> 24, bo = o[j] >> 24;
        if (be < bo) {
            while (i < ne && (e[i] >> 24) == be) i++;
            continue;
        }
        if (bo < be) {
            while (j < no && (o[j] >> 24) == bo) j++;
            continue;
        }
        uint32_t i0 = i, j0 = j;
        while (i < ne && (e[i] >> 24) == be) i++;
        while (j < no && (o[j] >> 24) == bo) j++;
        bucket_info->bucket_info[0][nb].head = e + i0;
        bucket_info->bucket_info[0][nb].tail = e + i - 1;
        bucket_info->bucket_info[1][nb].head = o + j0;
        bucket_info->bucket_info[1][nb].tail = o + j - 1;
        nb++;
    }
    bucket_info->numbuckets = nb;
}

// extra recover state, NULL for the plain single keystream path
typedef struct {
    const uint32_t *z;              // difference trajectory, NULL when there is no second keystream
    uint32_t *tmp;                  // counting sort scratch
    struct Crypto1State *sl_end;    // statelist limit
} dual_rec_t;

/** recover
 * recursively narrow down the search space, 4 bits of keystream at a time
 */
static struct Crypto1State *
recover(uint32_t *o_head, uint32_t *o_tail, uint32_t oks, uint32_t aoks,
        uint32_t *e_head, uint32_t *e_tail, uint32_t eks, uint32_t aeks, int rem,
        struct Crypto1State *sl, uint32_t in, bucket_array_t bucket, const dual_rec_t *d) {
    bucket_info_t bucket_info;

    if (d && sl >= d->sl_end)
        return sl;

    if (rem == -1) {
        for (uint32_t *e = e_head; e <= e_tail; ++e) {
            if (d && sl + (o_tail - o_head + 1) >= d->sl_end)
                return d->sl_end;
            *e = *e << 1 ^ (even32(*e & LF_POLY_EVEN)) ^ (!!(in & 4));
            for (uint32_t *o = o_head; o <= o_tail; ++o, ++sl) {
                sl->even = *o;
                sl->odd = *e ^ (even32(*o & LF_POLY_ODD));
                sl[1].odd = sl[1].even = 0;
            }
        }
        return sl;
    }

    uint32_t n_o = o_tail - o_head + 1, n_e = e_tail - e_head + 1;
    if (d && d->z == NULL && n_o <= DUAL_SCRATCH / 2 && n_e <= DUAL_SCRATCH / 2) {
        // single keystream: branch free levels, ping ponging with the scratch area
        uint32_t *osrc = o_head, *odst = d->tmp;
        uint32_t *esrc = e_head, *edst = d->tmp + DUAL_SCRATCH;
        for (uint32_t i = 0; i < 4 && rem--; i++) {
            oks >>= 1;
            eks >>= 1;
            in >>= 2;
            n_o = extend_table_fast(osrc, n_o, odst, oks & 1, LF_POLY_EVEN << 1 | 1, LF_POLY_ODD << 1, 0);
            uint32_t *t = osrc;
            osrc = odst;
            odst = t;
            if (n_o == 0)
                return sl;

            n_e = extend_table_fast(esrc, n_e, edst, eks & 1, LF_POLY_ODD, LF_POLY_EVEN << 1 | 1, in & 3);
            t = esrc;
            esrc = edst;
            edst = t;
            if (n_e == 0)
                return sl;

            if (n_o > DUAL_SCRATCH / 2 || n_e > DUAL_SCRATCH / 2)
                return sl;
        }
        if (osrc != o_head)
            memcpy(o_head, osrc, n_o * sizeof(uint32_t));
        if (esrc != e_head)
            memcpy(e_head, esrc, n_e * sizeof(uint32_t));
        o_tail = o_head + n_o - 1;
        e_tail = e_head + n_e - 1;
    } else {
        for (uint32_t i = 0; i < 4 && rem--; i++) {
            oks >>= 1;
            eks >>= 1;
            in >>= 2;
            if (d && d->z) {
                // keystream bit times 31 - 2 * rem (odd) and 30 - 2 * rem (even)
                aoks >>= 1;
                aeks >>= 1;
                extend_table_dual(o_head, &o_tail, oks & 1, aoks & 1, d->z[31 - 2 * rem], LF_POLY_EVEN << 1 | 1, LF_POLY_ODD << 1, 0);
                if (o_head > o_tail)
                    return sl;

                extend_table_dual(e_head, &e_tail, eks & 1, aeks & 1, d->z[30 - 2 * rem], LF_POLY_ODD, LF_POLY_EVEN << 1 | 1, in & 3);
                if (e_head > e_tail)
                    return sl;
                continue;
            }
            extend_table(o_head, &o_tail, oks & 1, LF_POLY_EVEN << 1 | 1, LF_POLY_ODD << 1, 0);
            if (o_head > o_tail)
                return sl;

            extend_table(e_head, &e_tail, eks & 1, LF_POLY_ODD, LF_POLY_EVEN << 1 | 1, in & 3);
            if (e_head > e_tail)
                return sl;
        }
    }

    if (d && (uint32_t)(e_tail - e_head) < SMALL_INTERSECT && (uint32_t)(o_tail - o_head) < SMALL_INTERSECT)
        small_intersect(e_head, e_tail - e_head + 1, o_head, o_tail - o_head + 1, &bucket_info);
    else if (d)
        counting_sort_intersect(e_head, e_tail, o_head, o_tail, &bucket_info, d->tmp);
    else
        bucket_sort_intersect(e_head, e_tail, o_head, o_tail, &bucket_info, bucket);

    for (int i = bucket_info.numbuckets - 1; i >= 0; i--) {
        sl = recover(bucket_info.bucket_info[1][i].head, bucket_info.bucket_info[1][i].tail, oks, aoks,
                     bucket_info.bucket_info[0][i].head, bucket_info.bucket_info[0][i].tail, eks, aeks,
                     rem, sl, in, bucket, d);
    }

    return sl;
}



/** single_children
 * 2 bit mask of the states v, v | 1 (v even) giving keystream bit k
 */
static inline uint32_t single_children(uint32_t v, uint32_t k) {
    return filter_pair(v) ^ ((k - 1) & 3);
}

typedef struct {
    const uint8_t *kb;
    uint32_t in;    // byte swapped in << 1
} single_ctx_t;

typedef struct {
    const single_ctx_t *c;
    uint32_t *buf;
    uint32_t *out;
    uint32_t n;
} single_sink_t;

/** single_expand
 * as dual_expand against one keystream
 */
static void single_expand(single_sink_t *sk, const uint32_t *src, uint32_t n, int t, int d) {
    const single_ctx_t *c = sk->c;
    if (t > 17) {
        memcpy(sk->out + sk->n, src, n * sizeof(uint32_t));
        sk->n += n;
        return;
    }
    if (2 * n > DUAL_CHUNK) {
        single_expand(sk, src, n / 2, t, d);
        single_expand(sk, src + n / 2, n - n / 2, t, d);
        return;
    }
    uint32_t *dst = sk->buf + (d + 1) * DUAL_CHUNK;
    uint32_t cnt = 0;
    uint32_t k = c->kb[t];
    int contrib = t >= 10;
    uint32_t m1 = (t & 1) ? (LF_POLY_EVEN << 1 | 1) : LF_POLY_ODD;
    uint32_t m2 = (t & 1) ? (LF_POLY_ODD << 1) : (LF_POLY_EVEN << 1 | 1);
    uint32_t in = (!contrib || (t & 1)) ? 0 : ((c->in >> (t - 8)) & 3) << 24;
    for (uint32_t j = 0; j < n; j++) {
        uint32_t v = src[j] << 1;
        uint32_t m = single_children(v, k);
        uint32_t w0 = v, w1 = v | 1;
        if (contrib) {
            update_contribution(&w0, m1, m2);
            update_contribution(&w1, m1, m2);
            w0 ^= in;
            w1 ^= in;
        }
        dst[cnt] = w0;
        cnt += m & 1;
        dst[cnt] = w1;
        cnt += m >> 1;
    }
    if (cnt)
        single_expand(sk, dst, cnt, t + 2, d + 1);
}

/** single_build
 * all states for keystream bit times t..17, appended to out.
 * Times t and t + 2 as bitmasks, 64 states per word, the rest per state.
 */
static uint32_t single_build(uint32_t *out, uint32_t *buf, int t, const single_ctx_t *c) {
    single_sink_t sk = {c, buf, out, 0};
    uint64_t inv0 = c->kb[t] ? 0 : ~0ULL, inv1 = c->kb[t + 2] ? 0 : ~0ULL;
    uint32_t n = 0;
    for (uint32_t x = 0; x < 1 << 14; x++) {
        uint64_t v = filter_word(x) ^ inv0;
        if (!v)
            continue;
        uint32_t base = (x << 1) & 0x3fff;
        uint64_t m[2];
        m[0] = (uint32_t)v ? spread2((uint32_t)v) & (filter_word(base) ^ inv1) : 0;
        m[1] = (v >> 32) ? spread2((uint32_t)(v >> 32)) & (filter_word(base + 1) ^ inv1) : 0;
        for (uint32_t u = 0; u < 2; u++) {
            while (m[u]) {
                buf[n++] = x << 7 | u << 6 | ctz64(m[u]);
                m[u] &= m[u] - 1;
            }
        }
        if (n > DUAL_CHUNK - 128) {
            single_expand(&sk, buf, n, t + 4, 0);
            n = 0;
        }
    }
    if (n)
        single_expand(&sk, buf, n, t + 4, 0);
    return sk.n;
}

#if !defined(__arm__) || defined(__linux__) || defined(_WIN32) || defined(__APPLE__) // bare metal ARM Proxmark lacks malloc()/free()
/** lfsr_recovery
 * recover the state of the lfsr given 32 bits of the keystream
 * additionally you can use the in parameter to specify the value
 * that was fed into the lfsr at the time the keystream was generated
 */
struct Crypto1State *lfsr_recovery32(uint32_t ks2, uint32_t in) {
    struct Crypto1State *statelist, *sl;
    uint32_t *odd_head, *even_head, *bucket_mem;
    uint32_t oks = 0, eks = 0;
    uint8_t kb[18];
    int i;

    // split the keystream into an odd and even part
    for (i = 31; i >= 0; i -= 2)
        oks = oks << 1 | BEBIT(ks2, i);
    for (i = 30; i >= 0; i -= 2)
        eks = eks << 1 | BEBIT(ks2, i);

    for (i = 0; i < 18; i++)
        kb[i] = BEBIT(ks2, i);

    statelist = calloc(1 << 18, sizeof(struct Crypto1State));
    // one block above the mmap threshold, so calloc gets fresh zero pages without a memset
    odd_head = calloc((1 << 21) * 2 + (1 << 23), sizeof(uint32_t));
    if (!statelist || !odd_head) {
        free(statelist);
        free(odd_head);
        return NULL;
    }
    even_head = odd_head + (1 << 21);
    bucket_mem = even_head + (1 << 21);

    in = (in >> 16 & 0xff) | (in << 16) | (in & 0xff00); // Byte swapping
    single_ctx_t ctx = {kb, in << 1};

    // states which could have generated the first 18 bits of the keystream
    uint32_t no = single_build(odd_head, bucket_mem, 1, &ctx);
    uint32_t ne = single_build(even_head, bucket_mem, 0, &ctx);

    if (no && ne) {
        // 14 bits to go to recover 32 bits in total
        dual_rec_t rec = {NULL, bucket_mem, statelist + (1 << 18) - 1};
        bucket_array_t bucket = {{{0}}};
        bucket_info_t bucket_info;
        counting_sort_intersect(even_head, even_head + ne - 1, odd_head, odd_head + no - 1, &bucket_info, bucket_mem);

        sl = statelist;
        for (i = bucket_info.numbuckets - 1; i >= 0; i--) {
            sl = recover(bucket_info.bucket_info[1][i].head, bucket_info.bucket_info[1][i].tail, oks >> 8, 0,
                         bucket_info.bucket_info[0][i].head, bucket_info.bucket_info[0][i].tail, eks >> 8, 0,
                         7, sl, (in << 1) >> 8, bucket, &rec);
        }
        sl->odd = sl->even = 0;
    }

    free(odd_head);
    return statelist;
}

typedef struct {
    const uint8_t *kb1, *kb2;
    const uint32_t *z;
    uint32_t in;    // byte swapped in1 << 1
    int s;          // first keystream bit time used
} dual_ctx_t;

/** dual_children
 * 2 bit mask of states v, v | 1 (v even) giving k1, and k2 when xored with z
 */
static inline uint32_t dual_children(uint32_t v, uint32_t z, uint32_t k1, uint32_t k2) {
    uint32_t m1 = filter_pair(v);
    uint32_t m2 = filter_pair(v ^ z);
    if (z & 1)
        m2 = (m2 >> 1) | ((m2 & 1) << 1);
    m1 ^= (k1 - 1) & 3;
    m2 ^= (k2 - 1) & 3;
    return m1 & m2;
}

typedef struct {
    const dual_ctx_t *c;
    uint32_t *buf;      // one DUAL_CHUNK buffer per level
    uint32_t *out;
    uint32_t n;
} dual_sink_t;

/** dual_expand
 * extend n states through bit times t, t + 2, .. s + 17 and append the survivors to the sink.
 * Branch free, one level at a time, halved when a level could overflow its buffer.
 */
static void dual_expand(dual_sink_t *sk, const uint32_t *src, uint32_t n, int t, int d) {
    const dual_ctx_t *c = sk->c;
    if (t > c->s + 17) {
        memcpy(sk->out + sk->n, src, n * sizeof(uint32_t));
        sk->n += n;
        return;
    }
    if (2 * n > DUAL_CHUNK) {
        dual_expand(sk, src, n / 2, t, d);
        dual_expand(sk, src + n / 2, n - n / 2, t, d);
        return;
    }
    uint32_t *dst = sk->buf + (d + 1) * DUAL_CHUNK;
    uint32_t cnt = 0;
    uint32_t z = c->z[t], k1 = c->kb1[t], k2 = c->kb2[t];
    int contrib = t >= c->s + 10;
    uint32_t m1 = (t & 1) ? (LF_POLY_EVEN << 1 | 1) : LF_POLY_ODD;
    uint32_t m2 = (t & 1) ? (LF_POLY_ODD << 1) : (LF_POLY_EVEN << 1 | 1);
    uint32_t in = (!contrib || (t & 1)) ? 0 : ((c->in >> (t - 8)) & 3) << 24;
    for (uint32_t k = 0; k < n; k++) {
        uint32_t v = src[k] << 1;
        uint32_t m = dual_children(v, z, k1, k2);
        uint32_t w0 = v, w1 = v | 1;
        if (contrib) {
            update_contribution(&w0, m1, m2);
            update_contribution(&w1, m1, m2);
            w0 ^= in;
            w1 ^= in;
        }
        dst[cnt] = w0;
        cnt += m & 1;
        dst[cnt] = w1;
        cnt += m >> 1;
    }
    if (cnt)
        dual_expand(sk, dst, cnt, t + 2, d + 1);
}

/** xor_permute64
 * bit k of the result is bit k ^ x of w
 */
static inline uint64_t xor_permute64(uint64_t w, uint32_t x) {
    static const uint64_t m[6] = {
        0x5555555555555555ULL, 0x3333333333333333ULL, 0x0F0F0F0F0F0F0F0FULL,
        0x00FF00FF00FF00FFULL, 0x0000FFFF0000FFFFULL, 0x00000000FFFFFFFFULL
    };
    for (int k = 0; k < 6; k++) {
        if (x >> k & 1) {
            w = ((w & m[k]) << (1 << k)) | ((w >> (1 << k)) & m[k]);
        }
    }
    return w;
}

/** dual_word
 * bit i set when state w << 6 | i gives keystream bit time t for both inputs
 */
static inline uint64_t dual_word(uint32_t w, int t, const dual_ctx_t *c) {
    uint32_t z = c->z[t];
    uint64_t inv1 = c->kb1[t] ? 0 : ~0ULL, inv2 = c->kb2[t] ? 0 : ~0ULL;
    return (filter_word(w) ^ inv1) & (xor_permute64(filter_word(w ^ (z >> 6)), z & 63) ^ inv2);
}

/** dual_build
 * all states for bit times t..s+17 from 20 bit states in [lo << 6, hi << 6), appended to out.
 * Times t and t + 2 as bitmasks, 64 states per word, the rest per state.
 */
static uint32_t dual_build(uint32_t *out, uint32_t *buf, int t, uint32_t lo, uint32_t hi, const dual_ctx_t *c) {
    dual_sink_t sk = {c, buf, out, 0};
    uint32_t n = 0;
    for (uint32_t x = lo; x < hi; x++) {
        uint64_t v = dual_word(x, t, c);
        if (!v)
            continue;
        uint32_t base = (x << 1) & 0x3fff;
        uint64_t m[2];
        m[0] = (uint32_t)v ? spread2((uint32_t)v) & dual_word(base, t + 2, c) : 0;
        m[1] = (v >> 32) ? spread2((uint32_t)(v >> 32)) & dual_word(base + 1, t + 2, c) : 0;
        for (uint32_t u = 0; u < 2; u++) {
            while (m[u]) {
                buf[n++] = x << 7 | u << 6 | ctz64(m[u]);
                m[u] &= m[u] - 1;
            }
        }
        if (n > DUAL_CHUNK - 128) {
            dual_expand(&sk, buf, n, t + 4, 0);
            n = 0;
        }
    }
    if (n)
        dual_expand(&sk, buf, n, t + 4, 0);
    return sk.n;
}

typedef struct {
    uint32_t lo, hi;
    uint32_t *odd, *even, *buf;
    uint32_t no, ne;
    const dual_ctx_t *c;
} dual_job_t;

static void *dual_worker(void *arg) {
    dual_job_t *j = arg;
    j->no = dual_build(j->odd, j->buf, j->c->s + 1, j->lo, j->hi, j->c);
    j->ne = dual_build(j->even, j->buf, j->c->s, j->lo, j->hi, j->c);
    return NULL;
}

/** dual_match
 * P(filter(x ^ z) == k2 | filter(x) == k1), exact over the filter's nibble functions
 */
static double dual_match(uint32_t z, uint32_t k1, uint32_t k2) {
    static const uint32_t fn[5] = {0xf22c0, 0x6c9c0, 0x3c8b0, 0x1e458, 0x0d938};
    uint32_t cnt[5][2][2] = {{{0}}};
    for (int i = 0; i < 5; i++) {
        uint32_t zi = (z >> (4 * i)) & 0xf;
        for (uint32_t n = 0; n < 16; n++)
            cnt[i][!!(fn[i] >> n & (16 >> i))][!!(fn[i] >> (n ^ zi) & (16 >> i))]++;
    }
    double hit = 0, all = 0;
    for (uint32_t a = 0; a < 32; a++) {
        for (uint32_t b = 0; b < 32; b++) {
            if (BIT(0xEC57E80A, a) != k1)
                continue;
            double w = 1;
            for (int i = 0; i < 5; i++)
                w *= cnt[i][a >> (4 - i) & 1][b >> (4 - i) & 1];
            all += w;
            if (BIT(0xEC57E80A, b) == k2)
                hit += w;
        }
    }
    return all ? hit / all : 0;
}

/** lfsr_recovery32_dual
 * as lfsr_recovery32(ks1, in1), keeping only states that also produce ks2
 * when in2 is fed from the same key instead. States are after feeding in1.
 * Same key set as intersecting two lfsr_recovery32 runs, far fewer candidates.
 */
struct Crypto1State *lfsr_recovery32_dual(uint32_t ks1, uint32_t in1, uint32_t ks2, uint32_t in2) {
    struct Crypto1State *statelist, *sl;
    uint32_t *odd_head, *even_head, *bucket_mem;
    uint32_t oks = 0, aoks = 0, eks = 0, aeks = 0;
    uint32_t z[32];
    uint8_t kb1[32], kb2[32];
    double pm[32];
    int i;

    // fb=0 is linear: the in2 trajectory is the in1 one xor the one of in1 ^ in2 from zero state
    struct Crypto1State d = {0, 0};
    for (i = 0; i < 32; i++) {
        z[i] = d.odd & 0xfffff;
        crypto1_bit(&d, BEBIT(in1 ^ in2, i), 0);
        kb1[i] = BEBIT(ks1, i);
        kb2[i] = BEBIT(ks2, i);
    }

    statelist = calloc(1 << 18, sizeof(struct Crypto1State));
    if (!statelist)
        return NULL;

    // pruning per bit time, a zero means no key can give both keystreams
    for (i = 0; i < 32; i++) {
        pm[i] = dual_match(z[i], kb1[i], kb2[i]);
        if (pm[i] == 0)
            return statelist;
    }

    // latest start with ~2^(16 + s) * prod(p) <= 2^12 candidates left to verify
    int st = 12;
    for (; st > 0; st -= 2) {
        double e = (double)(1u << (16 + st));
        for (i = st; i < 32; i++)
            e *= pm[i];
        if (e <= 4096)
            break;
    }

    // split the keystreams into an odd and even part
    for (i = 31; i >= 0; i -= 2) {
        oks = oks << 1 | BEBIT(ks1, i);
        aoks = aoks << 1 | BEBIT(ks2, i);
    }
    for (i = 30; i >= 0; i -= 2) {
        eks = eks << 1 | BEBIT(ks1, i);
        aeks = aeks << 1 | BEBIT(ks2, i);
    }

    // one block above the mmap threshold, so calloc gets fresh zero pages without a memset
    odd_head = calloc((1 << 21) * 2 + (1 << 23), sizeof(uint32_t));
    if (!odd_head) {
        free(statelist);
        return NULL;
    }
    even_head = odd_head + (1 << 21);
    bucket_mem = even_head + (1 << 21);

    uint32_t in = (in1 >> 16 & 0xff) | (in1 << 16) | (in1 & 0xff00); // Byte swapping

retry:
    sl = statelist;
    dual_ctx_t ctx = {kb1, kb2, z, in << 1, st};

    // states giving keystream bit times s..s+17, per x range and table segment
    pthread_t tid[DUAL_THREADS];
    dual_job_t job[DUAL_THREADS];
    bool started[DUAL_THREADS] = {false};
    for (i = 0; i < DUAL_THREADS; i++) {
        job[i] = (dual_job_t) {
            (1 << 14) * i / DUAL_THREADS, (1 << 14) * (i + 1) / DUAL_THREADS,
            odd_head + i * ((1 << 21) / DUAL_THREADS), even_head + i * ((1 << 21) / DUAL_THREADS),
            bucket_mem + i * ((1 << 23) / DUAL_THREADS), 0, 0, &ctx
        };
        if (i)
            started[i] = (pthread_create(&tid[i], NULL, dual_worker, &job[i]) == 0);
    }
    dual_worker(&job[0]);
    uint32_t no = job[0].no, ne = job[0].ne;
    for (i = 1; i < DUAL_THREADS; i++) {
        if (started[i])
            pthread_join(tid[i], NULL);
        else
            dual_worker(&job[i]);
        memmove(odd_head + no, job[i].odd, job[i].no * sizeof(uint32_t));
        memmove(even_head + ne, job[i].even, job[i].ne * sizeof(uint32_t));
        no += job[i].no;
        ne += job[i].ne;
    }

    if (no && ne) {
        dual_rec_t rec = {z, bucket_mem, statelist + (1 << 18) - 1};
        bucket_array_t bucket = {{{0}}};
        bucket_info_t bucket_info;
        counting_sort_intersect(even_head, even_head + ne - 1, odd_head, odd_head + no - 1, &bucket_info, bucket_mem);

        int sh = st / 2 + 8;
        for (i = bucket_info.numbuckets - 1; i >= 0; i--) {
            sl = recover(bucket_info.bucket_info[1][i].head, bucket_info.bucket_info[1][i].tail, oks >> sh, aoks >> sh,
                         bucket_info.bucket_info[0][i].head, bucket_info.bucket_info[0][i].tail, eks >> sh, aeks >> sh,
                         7 - st / 2, sl, (in << 1) >> (st + 8), bucket, &rec);
        }

        // statelist full, start from bit time 0 where the tables are subsets of lfsr_recovery32's
        if (sl >= rec.sl_end && st) {
            st = 0;
            goto retry;
        }
    }

    // check the skipped bit times, first on ks1 while rolling back
    struct Crypto1State *w = st ? statelist : sl;
    for (struct Crypto1State *p = statelist; st && p < sl; p++) {
        struct Crypto1State k1 = *p;
        int b = 31;
        for (; b >= st; b--)
            lfsr_rollback_bit(&k1, BEBIT(in1, b), 0);
        for (; b >= 0; b--)
            if (lfsr_rollback_bit(&k1, BEBIT(in1, b), 0) != kb1[b])
                break;
        if (b >= 0)
            continue;
        k1 = *p;
        lfsr_rollback_word(&k1, in1, 0);
        struct Crypto1State k2 = k1;
        if (crypto1_word(&k1, in1, 0) == ks1 && crypto1_word(&k2, in2, 0) == ks2)
            *w++ = *p;
    }
    w->odd = w->even = 0;

    free(odd_head);
    return statelist;
}

static const uint32_t S1[] = {     0x62141, 0x310A0, 0x18850, 0x0C428, 0x06214,
                                   0x0310A, 0x85E30, 0xC69AD, 0x634D6, 0xB5CDE, 0xDE8DA, 0x6F46D, 0xB3C83,
                                   0x59E41, 0xA8995, 0xD027F, 0x6813F, 0x3409F, 0x9E6FA
                             };
static const uint32_t S2[] = {  0x3A557B00, 0x5D2ABD80, 0x2E955EC0, 0x174AAF60,
                                0x0BA557B0, 0x05D2ABD8, 0x0449DE68, 0x048464B0, 0x42423258, 0x278192A8,
                                0x156042D0, 0x0AB02168, 0x43F89B30, 0x61FC4D98, 0x765EAD48, 0x7D8FDD20,
                                0x7EC7EE90, 0x7F63F748, 0x79117020
                             };
static const uint32_t T1[] = {
    0x4F37D, 0x279BE, 0x97A6A, 0x4BD35, 0x25E9A, 0x12F4D, 0x097A6, 0x80D66,
    0xC4006, 0x62003, 0xB56B4, 0x5AB5A, 0xA9318, 0xD0F39, 0x6879C, 0xB057B,
    0x582BD, 0x2C15E, 0x160AF, 0x8F6E2, 0xC3DC4, 0xE5857, 0x72C2B, 0x39615,
    0x98DBF, 0xC806A, 0xE0680, 0x70340, 0x381A0, 0x98665, 0x4C332, 0xA272C
};
static const uint32_t T2[] = {  0x3C88B810, 0x5E445C08, 0x2982A580, 0x14C152C0,
                                0x4A60A960, 0x253054B0, 0x52982A58, 0x2FEC9EA8, 0x1156C4D0, 0x08AB6268,
                                0x42F53AB0, 0x217A9D58, 0x161DC528, 0x0DAE6910, 0x46D73488, 0x25CB11C0,
                                0x52E588E0, 0x6972C470, 0x34B96238, 0x5CFC3A98, 0x28DE96C8, 0x12CFC0E0,
                                0x4967E070, 0x64B3F038, 0x74F97398, 0x7CDC3248, 0x38CE92A0, 0x1C674950,
                                0x0E33A4A8, 0x01B959D0, 0x40DCACE8, 0x26CEDDF0
                             };
static const uint32_t C1[] = { 0x846B5, 0x4235A, 0x211AD};
static const uint32_t C2[] = { 0x1A822E0, 0x21A822E0, 0x21A822E0};
/** Reverse 64 bits of keystream into possible cipher states
 * Variation mentioned in the paper. Somewhat optimized version
 */
struct Crypto1State *lfsr_recovery64(uint32_t ks2, uint32_t ks3) {
    struct Crypto1State *statelist, *sl;
    uint8_t oks[32], eks[32], hi[32];
    uint32_t low = 0,  win = 0;
    uint32_t *tail, table[1 << 16];
    int i, j;

    sl = statelist = calloc(1, sizeof(struct Crypto1State) << 4);
    if (!sl)
        return 0;
    sl->odd = sl->even = 0;

    for (i = 30; i >= 0; i -= 2) {
        oks[i >> 1] = BEBIT(ks2, i);
        oks[16 + (i >> 1)] = BEBIT(ks3, i);
    }
    for (i = 31; i >= 0; i -= 2) {
        eks[i >> 1] = BEBIT(ks2, i);
        eks[16 + (i >> 1)] = BEBIT(ks3, i);
    }

    for (i = 0xfffff; i >= 0; --i) {
        if (filter(i) != oks[0])
            continue;

        *(tail = table) = i;
        for (j = 1; tail >= table && j < 29; ++j)
            extend_table_simple(table, &tail, oks[j]);

        if (tail < table)
            continue;

        for (j = 0; j < 19; ++j)
            low = low << 1 | (evenparity32(i & S1[j]));
        for (j = 0; j < 32; ++j)
            hi[j] = evenparity32(i & T1[j]);

        for (; tail >= table; --tail) {
            for (j = 0; j < 3; ++j) {
                *tail = *tail << 1;
                *tail |= evenparity32((i & C1[j]) ^ (*tail & C2[j]));
                if (filter(*tail) != oks[29 + j])
                    goto continue2;
            }

            for (j = 0; j < 19; ++j)
                win = win << 1 | (evenparity32(*tail & S2[j]));

            win ^= low;
            for (j = 0; j < 32; ++j) {
                win = win << 1 ^ hi[j] ^ (evenparity32(*tail & T2[j]));
                if (filter(win) != eks[j])
                    goto continue2;
            }

            *tail = *tail << 1 | (evenparity32(LF_POLY_EVEN & *tail));
            sl->odd = *tail ^ (evenparity32(LF_POLY_ODD & win));
            sl->even = win;
            ++sl;
            sl->odd = sl->even = 0;
continue2:
            ;
        }
    }
    return statelist;
}
#endif

/** lfsr_rollback_bit
 * Rollback the shift register in order to get previous states
 */
uint8_t lfsr_rollback_bit(struct Crypto1State *s, uint32_t in, int fb) {
    int out;
    uint8_t ret;
    uint32_t t;

    s->odd &= 0xffffff;
    t = s->odd, s->odd = s->even, s->even = t;

    out = s->even & 1;
    out ^= LF_POLY_EVEN & (s->even >>= 1);
    out ^= LF_POLY_ODD & s->odd;
    out ^= !!in;
    out ^= (ret = filter(s->odd)) & (!!fb);

    s->even |= (evenparity32(out)) << 23;
    return ret;
}
/** lfsr_rollback_byte
 * Rollback the shift register in order to get previous states
 */
uint8_t lfsr_rollback_byte(struct Crypto1State *s, uint32_t in, int fb) {
    uint8_t ret = 0;
    ret |= lfsr_rollback_bit(s, BIT(in, 7), fb) << 7;
    ret |= lfsr_rollback_bit(s, BIT(in, 6), fb) << 6;
    ret |= lfsr_rollback_bit(s, BIT(in, 5), fb) << 5;
    ret |= lfsr_rollback_bit(s, BIT(in, 4), fb) << 4;
    ret |= lfsr_rollback_bit(s, BIT(in, 3), fb) << 3;
    ret |= lfsr_rollback_bit(s, BIT(in, 2), fb) << 2;
    ret |= lfsr_rollback_bit(s, BIT(in, 1), fb) << 1;
    ret |= lfsr_rollback_bit(s, BIT(in, 0), fb) << 0;
    return ret;
}
/** lfsr_rollback_word
 * Rollback the shift register in order to get previous states
 */
uint32_t lfsr_rollback_word(struct Crypto1State *s, uint32_t in, int fb) {

    uint32_t ret = 0;
    // note: xor args have been swapped because some compilers emit a warning
    // for 10^x and 2^x as possible misuses for exponentiation. No comment.
    ret |= lfsr_rollback_bit(s, BEBIT(in, 31), fb) << (24 ^ 31);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 30), fb) << (24 ^ 30);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 29), fb) << (24 ^ 29);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 28), fb) << (24 ^ 28);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 27), fb) << (24 ^ 27);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 26), fb) << (24 ^ 26);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 25), fb) << (24 ^ 25);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 24), fb) << (24 ^ 24);

    ret |= lfsr_rollback_bit(s, BEBIT(in, 23), fb) << (24 ^ 23);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 22), fb) << (24 ^ 22);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 21), fb) << (24 ^ 21);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 20), fb) << (24 ^ 20);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 19), fb) << (24 ^ 19);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 18), fb) << (24 ^ 18);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 17), fb) << (24 ^ 17);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 16), fb) << (24 ^ 16);

    ret |= lfsr_rollback_bit(s, BEBIT(in, 15), fb) << (24 ^ 15);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 14), fb) << (24 ^ 14);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 13), fb) << (24 ^ 13);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 12), fb) << (24 ^ 12);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 11), fb) << (24 ^ 11);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 10), fb) << (24 ^ 10);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 9), fb) << (24 ^ 9);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 8), fb) << (24 ^ 8);

    ret |= lfsr_rollback_bit(s, BEBIT(in, 7), fb) << (24 ^ 7);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 6), fb) << (24 ^ 6);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 5), fb) << (24 ^ 5);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 4), fb) << (24 ^ 4);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 3), fb) << (24 ^ 3);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 2), fb) << (24 ^ 2);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 1), fb) << (24 ^ 1);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 0), fb) << (24 ^ 0);
    return ret;
}

/** nonce_distance
 * x,y valid tag nonces, then prng_successor(x, nonce_distance(x, y)) = y
 */
static uint16_t *dist = 0;
int nonce_distance(uint32_t from, uint32_t to) {
    if (!dist) {
        // allocation 2bytes * 0xFFFF times.
        dist = calloc(2 << 16,  sizeof(uint8_t));
        if (!dist)
            return -1;
        uint16_t x = 1;
        for (uint16_t i = 1; i; ++i) {
            dist[(x & 0xff) << 8 | x >> 8] = i;
            x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
        }
    }
    return (65535 + dist[to >> 16] - dist[from >> 16]) % 65535;
}

/** validate_prng_nonce
 * Determine if nonce is deterministic. ie: Suspectable to Darkside attack.
 * returns
 *   true = weak prng
 *   false = hardend prng
 */
bool validate_prng_nonce(uint32_t nonce) {
    uint16_t x = nonce >> 16;
    x = (x & 0xff) << 8 | x >> 8;
    for (uint8_t i = 0; i < 16; i++) {
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
    }
    x = (x & 0xff) << 8 | x >> 8;
    return x == (nonce & 0xFFFF);
}

static uint32_t fastfwd[2][8] = {
    { 0, 0x4BC53, 0xECB1, 0x450E2, 0x25E29, 0x6E27A, 0x2B298, 0x60ECB},
    { 0, 0x1D962, 0x4BC53, 0x56531, 0xECB1, 0x135D3, 0x450E2, 0x58980}
};

/** lfsr_prefix_ks
 *
 * Is an exported helper function from the common prefix attack
 * Described in the "dark side" paper. It returns an -1 terminated array
 * of possible partial(21 bit) secret state.
 * The required keystream(ks) needs to contain the keystream that was used to
 * encrypt the NACK which is observed when varying only the 3 last bits of Nr
 * only correct iff [NR_3] ^ NR_3 does not depend on Nr_3
 */
uint32_t *lfsr_prefix_ks(const uint8_t ks[8], int isodd) {
    uint32_t *candidates = calloc(4 << 10, sizeof(uint8_t));
    if (!candidates) return 0;

    int size = 0;

    for (int i = 0; i < 1 << 21; ++i) {
        int good = 1;
        for (uint32_t c = 0; good && c < 8; ++c) {
            uint32_t entry = i ^ fastfwd[isodd][c];
            good &= (BIT(ks[c], isodd) == filter(entry >> 1));
            good &= (BIT(ks[c], isodd + 2) == filter(entry));
        }
        if (good)
            candidates[size++] = i;
    }

    candidates[size] = -1;

    return candidates;
}

/** check_pfx_parity
 * helper function which eliminates possible secret states using parity bits
 */
static struct Crypto1State *check_pfx_parity(uint32_t prefix, uint32_t rresp, uint8_t parities[8][8], uint32_t odd, uint32_t even, struct Crypto1State *sl, uint32_t no_par) {
    uint32_t good = 1;

    for (uint32_t c = 0; good && c < 8; ++c) {
        sl->odd = odd ^ fastfwd[1][c];
        sl->even = even ^ fastfwd[0][c];

        lfsr_rollback_bit(sl, 0, 0);
        lfsr_rollback_bit(sl, 0, 0);

        uint32_t ks3 = lfsr_rollback_bit(sl, 0, 0);
        uint32_t ks2 = lfsr_rollback_word(sl, 0, 0);
        uint32_t ks1 = lfsr_rollback_word(sl, prefix | c << 5, 1);

        if (no_par)
            break;

        uint32_t nr = ks1 ^ (prefix | c << 5);
        uint32_t rr = ks2 ^ rresp;

        good &= evenparity32(nr & 0x000000ff) ^ parities[c][3] ^ BIT(ks2, 24);
        good &= evenparity32(rr & 0xff000000) ^ parities[c][4] ^ BIT(ks2, 16);
        good &= evenparity32(rr & 0x00ff0000) ^ parities[c][5] ^ BIT(ks2,  8);
        good &= evenparity32(rr & 0x0000ff00) ^ parities[c][6] ^ BIT(ks2,  0);
        good &= evenparity32(rr & 0x000000ff) ^ parities[c][7] ^ ks3;
    }

    return sl + good;
}

#if !defined(__arm__) || defined(__linux__) || defined(_WIN32) || defined(__APPLE__) // bare metal ARM Proxmark lacks malloc()/free()
/** lfsr_common_prefix
 * Implementation of the common prefix attack.
 * Requires the 28 bit constant prefix used as reader nonce (pfx)
 * The reader response used (rr)
 * The keystream used to encrypt the observed NACK's (ks)
 * The parity bits (par)
 * It returns a zero terminated list of possible cipher states after the
 * tag nonce was fed in
 */

struct Crypto1State *lfsr_common_prefix(uint32_t pfx, uint32_t rr, uint8_t ks[8], uint8_t par[8][8], uint32_t no_par) {
    struct Crypto1State *statelist, *s;
    uint32_t *odd, *even, *o, *e, top;

    odd = lfsr_prefix_ks(ks, 1);
    even = lfsr_prefix_ks(ks, 0);

    s = statelist = calloc(1, (sizeof * statelist) << 24); // was << 20. Need more for no_par special attack. Enough???
    if (!s || !odd || !even) {
        free(statelist);
        statelist = 0;
        goto out;
    }

    for (o = odd; *o + 1; ++o)
        for (e = even; *e + 1; ++e)
            for (top = 0; top < 64; ++top) {
                *o += 1 << 21;
                *e += (!(top & 7) + 1) << 21;
                s = check_pfx_parity(pfx, rr, par, *o, *e, s, no_par);
            }

    s->odd = s->even = 0;
out:
    free(odd);
    free(even);
    return statelist;
}
#endif
