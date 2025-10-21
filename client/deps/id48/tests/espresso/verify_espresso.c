


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "array_size2.h"
#include "id48.h"
#include "verify_espresso.h"

#if !defined true
    #define true ((bool)1u)
#endif
#if !defined false
    #define false ((bool)0u)
#endif

#if 1 // constant names for use in LUT_PLA_NAMES_xx
    static const char * const NAME_A  =  "a";
    static const char * const NAME_B  =  "b";
    static const char * const NAME_C  =  "c";
    static const char * const NAME_L0 = "l0";
    static const char * const NAME_L2 = "l2";
    static const char * const NAME_L3 = "l3";
    static const char * const NAME_L4 = "l4";
    static const char * const NAME_L5 = "l5";
    static const char * const NAME_L6 = "l6";
    static const char * const NAME_M0 = "m0";
    static const char * const NAME_M1 = "m1";
    static const char * const NAME_M3 = "m3";
    static const char * const NAME_M5 = "m5";
    static const char * const NAME_R0 = "r0";
    static const char * const NAME_R1 = "r1";
    static const char * const NAME_R2 = "r2";
    static const char * const NAME_R3 = "r3";
    static const char * const NAME_R4 = "r4";
    static const char * const NAME_R5 = "r5";
    static const char * const NAME_R6 = "r6";
#endif // constant names for use in LUT_PLA_NAMES_xx
#if 1 // LUT_PLA_NAMES_xx -- name arrays for generating espresso input files
    // NOTE: these arrays are in order of the most significant to least significant bit.
    //       did i get confused by that?
    const char  * const LUT_PLA_NAMES_g1[5] = { NAME_A , NAME_L2, NAME_L3, NAME_L0, NAME_L6, };
    const char  * const LUT_PLA_NAMES_g2[5] = { NAME_L5, NAME_B , NAME_M0, NAME_L4, NAME_M1, };
    const char  * const LUT_PLA_NAMES_g3[5] = { NAME_M5, NAME_C , NAME_R1, NAME_M3, NAME_R3, };
    const char  * const LUT_PLA_NAMES_g4[5] = { NAME_R2, NAME_R4, NAME_R6, NAME_R0, NAME_R5, };
    const char  * const LUT_PLA_NAMES_XX[8] = {
        NAME_L0, NAME_L4, NAME_L6, NAME_M1,
        NAME_M3, NAME_R0, NAME_R3, NAME_R5,
    };
#endif // LUT_PLA_NAMES_xx -- name arrays for generating espresso input files

#if 1 // actual lookup tables
    // LUTs were internal-only, and not even exposed to library internals.
    // so just copy/paste here for now for initial testing
    /// initial_idx = (l0 << 7) | (l4 << 6) | (l6 << 5) | (m1 << 4) | (m3 << 3) | (r0 << 2) | (r3 << 1) | (r5 << 0)
    static const uint8_t small_lut_XX[32] = {  // aka 256 bits
        0x44, 0xff, 0x4f, 0x4f, 0x55, 0xff, 0x55, 0x55,
        0xcc, 0xff, 0xcf, 0x4f, 0xcc, 0xff, 0xcc, 0x44,
        0x00, 0x00, 0x0f, 0x0f, 0x55, 0x55, 0x55, 0x55,
        0xcc, 0x00, 0xcf, 0x0f, 0xcc, 0x00, 0xcc, 0x00,
    };
    /// g1_idx = (a << 4) | (l2 << 3) | (l3 << 2) | (l0 << 1) | (l6 << 0)
    static const uint8_t small_lut_group1[4] = { // aka 32 bits
        0x4f, 0x92, 0xa1, 0x7c,
    };
    /// g2_idx = (l5 << 4) | (b << 3) | (m0 << 2) | (l4 << 1) | (m1 << 0)
    static const uint8_t small_lut_group2[4] = { // aka 32 bits
        0x8f, 0x52, 0x61, 0xbc,
    };
    /// g3_idx = (m5 << 4) | (c << 3) | (r1 << 2) | (m3 << 1) | (r3 << 0)
    static const uint8_t small_lut_group3[4] = { // aka 32 bits
        0x8f, 0x34, 0x61, 0xda,
    };
    /// g4_idx = (r2 << 4) | (r4 << 3) | (r6 << 2) | (r0 << 1) | (r5 << 0)
    static const uint8_t small_lut_group4[4] = { // aka 32 bits
        0x8f, 0x34, 0x52, 0xe9,
    };
    static inline bool get_bit(const uint8_t *table_start, uint32_t bit_idx) {
        const uint32_t byte = bit_idx / 8u;
        const uint8_t  mask = 1u << (bit_idx % 8u);
        return (table_start[byte] & mask) != 0;
    }
#endif // actual lookup tables



// 1. validated by hand that LUT --> PLA generation was accurate for all five LUTs
// 2. Ran the generated PLA through WASM-based espresso:
//    https://nudelerde.github.io/Espresso-Wasm-Web/index.html
// 3. Copied the output to each validation function
// 4. Converted the output to C-style boolean logic, and column-aligned formatting for easier review
//
// Same process used for each, but only g1 validates against the lookup table.
// Maybe just use the LUTs in an FPGA instead of trying to minimize to two-level logic?
// However, performance will be best with two-level, glitch-free logic....
//
// WHAT IS GOING WRONG WITH ESPRESSO OUTPUT (OR MY VALIDATION)?
//
// After adding a whole set of secondary validation functions... the root cause was ....
// Accidentally initializing any_failures to true instead of false in the other functions.
//
//    :-P
//
// I'll check this comment into my dev branch, even if I squash-merge it out later.
//
typedef struct _OUTPUT_INDEX3 {
    // the index is calculated from unstable ID48LIBX_STATE_REGISTERS
    // by function calculate_output_index(), which creates a single
    // 20-bit result:
    //           Fₒ( abc l₀l₂l₃l₄l₅l₆ m₀m₁m₃m₅ r₀r₁r₂r₃r₄r₅r₆ )
    //     msb 19 ---^                           lsb 00 ---^^
    // This union allows debugger to view the individual bit values more easily.
    union {
        uint32_t Raw32;
        struct {
            // seven bits from r: r₀..r₆
            uint32_t r6 : 1; // bit 00
            uint32_t r5 : 1; // bit 01
            uint32_t r4 : 1; // bit 02
            uint32_t r3 : 1; // bit 03
            uint32_t r2 : 1; // bit 04
            uint32_t r1 : 1; // bit 05
            uint32_t r0 : 1; // bit 06
            // four bits from m: m₀m₁m₃m₅
            uint32_t m5 : 1; // bit 07
            uint32_t m3 : 1; // bit 08
            uint32_t m1 : 1; // bit 09
            uint32_t m0 : 1; // bit 10
            // six bits from l: l₀l₂l₃l₄l₅l₆
            uint32_t l6 : 1; // bit 11
            uint32_t l5 : 1; // bit 12
            uint32_t l4 : 1; // bit 13
            uint32_t l3 : 1; // bit 14
            uint32_t l2 : 1; // bit 15
            uint32_t l0 : 1; // bit 16
            // and finally, the three bits a, b, c
            uint32_t c  : 1; // bit 17
            uint32_t b  : 1; // bit 18
            uint32_t a  : 1; // bit 19
        };
    };
} OUTPUT_INDEX3;



#if 1 // structures for mapping LUT indices to named fields
/// g1_idx = (a << 4) | (l2 << 3) | (l3 << 2) | (l0 << 1) | (l6 << 0)
typedef struct _INDEX_G1 {
    union {
        uint8_t as_uint8_t;
        struct {
            uint8_t l6 : 1; // least significant bit
            uint8_t l0 : 1;
            uint8_t l3 : 1;
            uint8_t l2 : 1;
            uint8_t  a : 1;
        };
    };
} INDEX_G1;
/// g2_idx = (l5 << 4) | (b << 3) | (m0 << 2) | (l4 << 1) | (m1 << 0)
typedef struct _INDEX_G2 {
    union {
        uint8_t as_uint8_t;
        struct {
            uint8_t m1 : 1;
            uint8_t l4 : 1;
            uint8_t m0 : 1;
            uint8_t  b : 1;
            uint8_t l5 : 1;
        };
    };
} INDEX_G2;
/// g3_idx = (m5 << 4) | (c << 3) | (r1 << 2) | (m3 << 1) | (r3 << 0)
typedef struct _INDEX_G3 {
    union {
        uint8_t as_uint8_t;
        struct {
            uint8_t r3 : 1;
            uint8_t m3 : 1;
            uint8_t r1 : 1;
            uint8_t  c : 1;
            uint8_t m5 : 1;
        };
    };
} INDEX_G3;
/// g4_idx = (r2 << 4) | (r4 << 3) | (r6 << 2) | (r0 << 1) | (r5 << 0)
typedef struct _INDEX_G4 {
    union {
        uint8_t as_uint8_t;
        struct {
            uint8_t r5 : 1;
            uint8_t r0 : 1;
            uint8_t r6 : 1;
            uint8_t r4 : 1;
            uint8_t r2 : 1;
        };
    };
} INDEX_G4;
/// initial_idx = (l0 << 7) | (l4 << 6) | (l6 << 5) | (m1 << 4) | (m3 << 3) | (r0 << 2) | (r3 << 1) | (r5 << 0)
typedef struct _INDEX_XX {
    union {
        uint8_t as_uint8_t;
        struct {
            uint8_t r5 : 1;
            uint8_t r3 : 1;
            uint8_t r0 : 1;
            uint8_t m3 : 1;
            uint8_t m1 : 1;
            uint8_t l6 : 1;
            uint8_t l4 : 1;
            uint8_t l0 : 1;
        };
    };
} INDEX_XX;
#endif // structures for mapping LUT indices to named fields

typedef struct _ESPRESSO_GENERATOR_ARGUMENTS {
    uint8_t const           input_count;
    char    const * const * names;
    char    const * const   output_name;
    uint8_t const *         lut_start;
} ESPRESSO_GENERATOR_ARGUMENTS;

static bool verify_lut_g1(void);
static bool verify_lut_g2(void);
static bool verify_lut_g3(void);
static bool verify_lut_g4(void);
static bool verify_lut_XX(void);

// Later, define a struct with functions for each thing to be validated
typedef bool (*lookuptable_func_t)(uint8_t);


/// g1_idx = (a << 4) | (l2 << 3) | (l3 << 2) | (l0 << 1) | (l6 << 0)
static bool espresso_implementation_g1_alt0(uint8_t idx) {
    // output_g1 = (a&l2&l0&!l6) | (a&l3&!l0&l6) | (!a&!l2&!l3) | (!l2&!l3&!l0&!l6) | (l2&l3&!l0&!l6) | (!a&!l2&l0&!l6) | (!a&!l3&!l0&l6) | (a&l2&!l3&l0) | (a&!l2&l3&l6) | (!a&l2&l3&l0&l6);

    static const bool _ = true;
    bool  a = idx & (1u << 4);
    bool l2 = idx & (1u << 3);
    bool l3 = idx & (1u << 2);
    bool l0 = idx & (1u << 1);
    bool l6 = idx & (1u << 0);
    return
        (     a   &&     l2   &&      _   &&     l0   &&   !(l6)   ) ||
        (     a   &&      _   &&     l3   &&   !(l0)  &&     l6    ) ||
        (   !(a)  &&   !(l2)  &&   !(l3)  &&      _   &&      _    ) ||
        (     _   &&   !(l2)  &&   !(l3)  &&   !(l0)  &&   !(l6)   ) ||
        (     _   &&     l2   &&     l3   &&   !(l0)  &&   !(l6)   ) ||
        (   !(a)  &&   !(l2)  &&     _    &&     l0   &&   !(l6)   ) ||
        (   !(a)  &&      _   &&   !(l3)  &&   !(l0)  &&     l6    ) ||
        (     a   &&     l2   &&   !(l3)  &&     l0   &&      _    ) ||
        (     a   &&   !(l2)  &&     l3   &&      _   &&     l6    ) ||
        (   !(a)  &&     l2   &&     l3   &&     l0   &&     l6    ) ;
}
static bool espresso_implementation_g1_alt1(uint8_t idx) {
    // output_g1 = (a&l2&l0&!l6) | (a&l3&!l0&l6) | (!a&!l2&!l3) | (!l2&!l3&!l0&!l6) | (l2&l3&!l0&!l6) | (!a&!l2&l0&!l6) | (!a&!l3&!l0&l6) | (a&l2&!l3&l0) | (a&!l2&l3&l6) | (!a&l2&l3&l0&l6);
    static const bool _ = true;
    INDEX_G1 t = { .as_uint8_t = idx };
    bool  a = t.a;
    bool l2 = t.l2;
    bool l3 = t.l3;
    bool l0 = t.l0;
    bool l6 = t.l6;
    return
        (     a   &&     l0   &&     l2   &&      _   &&   !(l6)   ) ||
        (     a   &&   !(l0)  &&      _   &&     l3   &&     l6    ) ||
        (   !(a)  &&      _   &&   !(l2)  &&   !(l3)  &&      _    ) ||
        (     _   &&   !(l0)  &&   !(l2)  &&   !(l3)  &&   !(l6)   ) ||
        (     _   &&   !(l0)  &&     l2   &&     l3   &&   !(l6)   ) ||
        (   !(a)  &&     l0   &&   !(l2)  &&     _    &&   !(l6)   ) ||
        (   !(a)  &&   !(l0)  &&      _   &&   !(l3)  &&     l6    ) ||
        (     a   &&     l0   &&     l2   &&   !(l3)  &&      _    ) ||
        (     a   &&      _   &&   !(l2)  &&     l3   &&     l6    ) ||
        (   !(a)  &&     l0   &&     l2   &&     l3   &&     l6    ) ;
}
static const lookuptable_func_t alt_for_g1[] = {
    espresso_implementation_g1_alt0,
    espresso_implementation_g1_alt1,
};


static bool espresso_implementation_g2_alt0(uint8_t idx) {
    // output_g2 = (b&m0&!l4&!m1) | (l5&b&l4&m1) | (!l5&!b&!m0) | (!b&!m0&!l4&!m1) | (l5&b&!m0&l4) | (l5&!b&m0&l4&!m1) | (!l5&b&m0&!m1) | (!l5&!m0&!l4&m1) | (l5&m0&!l4&m1) | (!l5&!b&l4&m1);
    // g2_idx = (l5 << 4) | (b << 3) | (m0 << 2) | (l4 << 1) | (m1 << 0)
    bool l5 = idx & (1u << 4);
    bool b  = idx & (1u << 3);
    bool m0 = idx & (1u << 2);
    bool l4 = idx & (1u << 1);
    bool m1 = idx & (1u << 0);
    static const bool _ = true;
    return 
        (      _   &&     b   &&     m0   &&   !(l4)  &&   !(m1)  ) |
        (     l5   &&     b   &&      _   &&     l4   &&     m1   ) |
        (   !(l5)  &&   !(b)  &&   !(m0)  &&      _   &&      _   ) |
        (      _   &&   !(b)  &&   !(m0)  &&   !(l4)  &&   !(m1)  ) |
        (     l5   &&     b   &&   !(m0)  &&     l4   &&      _   ) |
        (     l5   &&   !(b)  &&     m0   &&     l4   &&   !(m1)  ) |
        (   !(l5)  &&     b   &&     m0   &&      _   &&   !(m1)  ) |
        (   !(l5)  &&     _   &&   !(m0)  &&   !(l4)  &&     m1   ) |
        (     l5   &&     _   &&     m0   &&   !(l4)  &&     m1   ) |
        (   !(l5)  &&   !(b)  &&      _   &&     l4   &&     m1   ) ;
}
static bool espresso_implementation_g2_alt1(uint8_t idx) {
    // output_g2 = (b&m0&!l4&!m1) | (l5&b&l4&m1) | (!l5&!b&!m0) | (!b&!m0&!l4&!m1) | (l5&b&!m0&l4) | (l5&!b&m0&l4&!m1) | (!l5&b&m0&!m1) | (!l5&!m0&!l4&m1) | (l5&m0&!l4&m1) | (!l5&!b&l4&m1);
    INDEX_G2 t = { .as_uint8_t = idx };
    bool l5 = t.l5;
    bool b  = t.b;
    bool m0 = t.m0;
    bool l4 = t.l4;
    bool m1 = t.m1;
    static const bool _ = true;
    return 
        (      _   &&     b   &&     m0   &&   !(l4)  &&   !(m1)  ) |
        (     l5   &&     b   &&      _   &&     l4   &&     m1   ) |
        (   !(l5)  &&   !(b)  &&   !(m0)  &&      _   &&      _   ) |
        (      _   &&   !(b)  &&   !(m0)  &&   !(l4)  &&   !(m1)  ) |
        (     l5   &&     b   &&   !(m0)  &&     l4   &&      _   ) |
        (     l5   &&   !(b)  &&     m0   &&     l4   &&   !(m1)  ) |
        (   !(l5)  &&     b   &&     m0   &&      _   &&   !(m1)  ) |
        (   !(l5)  &&     _   &&   !(m0)  &&   !(l4)  &&     m1   ) |
        (     l5   &&     _   &&     m0   &&   !(l4)  &&     m1   ) |
        (   !(l5)  &&   !(b)  &&      _   &&     l4   &&     m1   ) ;
}

static const lookuptable_func_t alt_for_g2[] = {
    espresso_implementation_g2_alt0,
    espresso_implementation_g2_alt1,
    // espresso_implementation_g1_alt2, // fails ... generated via https://github.com/omritriki/espresso-py ...
};


static bool espresso_implementation_g3_alt0(uint8_t idx) {
    // output_g3 = (c&r1&!m3&!r3) | (m5&c&m3&r3) | (!m5&!c&!r1) | (!c&!r1&!m3&!r3) | (!m5&!r1&m3&!r3) | (m5&r1&m3&!r3) | (m5&c&!r1&r3) | (m5&!c&r1&!m3&r3) | (!m5&c&r1&!m3) | (!m5&!c&m3&r3);
    // g3_idx = (m5 << 4) | (c << 3) | (r1 << 2) | (m3 << 1) | (r3 << 0)
    bool m5 = idx & (1u << 4);
    bool c  = idx & (1u << 3);
    bool r1 = idx & (1u << 2);
    bool m3 = idx & (1u << 1);
    bool r3 = idx & (1u << 0);
    static const bool _ = true;
    return
        (      _   &&     c   &&     r1   &&   !(m3)  &&   !(r3)  ) ||
        (     m5   &&     c   &&      _   &&     m3   &&     r3   ) ||
        (   !(m5)  &&   !(c)  &&   !(r1)  &&      _   &&      _   ) ||
        (      _   &&   !(c)  &&   !(r1)  &&   !(m3)  &&   !(r3)  ) ||
        (   !(m5)  &&     _   &&   !(r1)  &&     m3   &&   !(r3)  ) ||
        (     m5   &&     _   &&     r1   &&     m3   &&   !(r3)  ) ||
        (     m5   &&     c   &&   !(r1)  &&      _   &&     r3   ) ||
        (     m5   &&   !(c)  &&     r1   &&   !(m3)  &&     r3   ) ||
        (   !(m5)  &&     c   &&     r1   &&   !(m3)  &&      _   ) ||
        (   !(m5)  &&   !(c)  &&      _   &&     m3   &&     r3   ) ;
}
static bool espresso_implementation_g3_alt1(uint8_t idx) {
    // output_g3 = (c&r1&!m3&!r3) | (m5&c&m3&r3) | (!m5&!c&!r1) | (!c&!r1&!m3&!r3) | (!m5&!r1&m3&!r3) | (m5&r1&m3&!r3) | (m5&c&!r1&r3) | (m5&!c&r1&!m3&r3) | (!m5&c&r1&!m3) | (!m5&!c&m3&r3);
    INDEX_G3 t = { .as_uint8_t = idx };
    bool c  = t.c;
    bool r1 = t.r1;
    bool r3 = t.r3;
    bool m3 = t.m3;
    bool m5 = t.m5;
    static const bool _ = true;
    return
        (      _   &&     c   &&     r1   &&   !(m3)  &&   !(r3)  ) ||
        (     m5   &&     c   &&      _   &&     m3   &&     r3   ) ||
        (   !(m5)  &&   !(c)  &&   !(r1)  &&      _   &&      _   ) ||
        (      _   &&   !(c)  &&   !(r1)  &&   !(m3)  &&   !(r3)  ) ||
        (   !(m5)  &&     _   &&   !(r1)  &&     m3   &&   !(r3)  ) ||
        (     m5   &&     _   &&     r1   &&     m3   &&   !(r3)  ) ||
        (     m5   &&     c   &&   !(r1)  &&      _   &&     r3   ) ||
        (     m5   &&   !(c)  &&     r1   &&   !(m3)  &&     r3   ) ||
        (   !(m5)  &&     c   &&     r1   &&   !(m3)  &&      _   ) ||
        (   !(m5)  &&   !(c)  &&      _   &&     m3   &&     r3   ) ;
}

static const lookuptable_func_t alt_for_g3[] = {
    espresso_implementation_g3_alt0,
    espresso_implementation_g3_alt1,
};

static bool espresso_implementation_g4_alt0(uint8_t idx) {
    // output_g4 = (r2&r6&r0&!r5) | (r4&r6&!r0&r5) | (!r2&!r4&!r6) | (r2&r4&!r6&!r0&!r5) | (r2&!r4&r6&!r5) | (!r2&r4&r6&!r0) | (!r2&!r6&r0&!r5) | (!r4&!r6&!r0&r5) | (r2&r4&r0&r5) | (!r2&!r4&r0&r5);
    // g4_idx = (r2 << 4) | (r4 << 3) | (r6 << 2) | (r0 << 1) | (r5 << 0)
    bool r2 = idx & (1u << 4);
    bool r4 = idx & (1u << 3);
    bool r6 = idx & (1u << 2);
    bool r0 = idx & (1u << 1);
    bool r5 = idx & (1u << 0);
    static const bool _ = true;
    return
        (     r2   &&      _   &&     r6   &&     r0   &&   !(r5)  ) |
        (      _   &&     r4   &&     r6   &&   !(r0)  &&     r5   ) |
        (   !(r2)  &&   !(r4)  &&   !(r6)  &&      _   &&      _   ) |
        (     r2   &&     r4   &&   !(r6)  &&   !(r0)  &&   !(r5)  ) |
        (     r2   &&   !(r4)  &&     r6   &&      _   &&   !(r5)  ) |
        (   !(r2)  &&     r4   &&     r6   &&   !(r0)  &&      _   ) |
        (   !(r2)  &&      _   &&   !(r6)  &&     r0   &&   !(r5)  ) |
        (      _   &&   !(r4)  &&   !(r6)  &&   !(r0)  &&     r5   ) |
        (     r2   &&     r4   &&      _   &&     r0   &&     r5   ) |
        (   !(r2)  &&   !(r4)  &&      _   &&     r0   &&     r5   ) ;
}
static bool espresso_implementation_g4_alt1(uint8_t idx) {
    // output_g4 = (r2&r6&r0&!r5) | (r4&r6&!r0&r5) | (!r2&!r4&!r6) | (r2&r4&!r6&!r0&!r5) | (r2&!r4&r6&!r5) | (!r2&r4&r6&!r0) | (!r2&!r6&r0&!r5) | (!r4&!r6&!r0&r5) | (r2&r4&r0&r5) | (!r2&!r4&r0&r5);
    // g4_idx = (r2 << 4) | (r4 << 3) | (r6 << 2) | (r0 << 1) | (r5 << 0)
    INDEX_G4 t = { .as_uint8_t = idx };
    bool r2 = t.r2;
    bool r4 = t.r4;
    bool r6 = t.r6;
    bool r0 = t.r0;
    bool r5 = t.r5;
    static const bool _ = true;
    return
        (     r2   &&      _   &&     r6   &&     r0   &&   !(r5)  ) |
        (      _   &&     r4   &&     r6   &&   !(r0)  &&     r5   ) |
        (   !(r2)  &&   !(r4)  &&   !(r6)  &&      _   &&      _   ) |
        (     r2   &&     r4   &&   !(r6)  &&   !(r0)  &&   !(r5)  ) |
        (     r2   &&   !(r4)  &&     r6   &&      _   &&   !(r5)  ) |
        (   !(r2)  &&     r4   &&     r6   &&   !(r0)  &&      _   ) |
        (   !(r2)  &&      _   &&   !(r6)  &&     r0   &&   !(r5)  ) |
        (      _   &&   !(r4)  &&   !(r6)  &&   !(r0)  &&     r5   ) |
        (     r2   &&     r4   &&      _   &&     r0   &&     r5   ) |
        (   !(r2)  &&   !(r4)  &&      _   &&     r0   &&     r5   ) ;
}

static const lookuptable_func_t alt_for_g4[] = {
    espresso_implementation_g4_alt0,
    espresso_implementation_g4_alt1,
};

static bool espresso_implementation_xx_alt0(uint8_t idx) {
    // output_xx = (!l6&m1&!r0) | (l4&!m3&r3) | (!l4&l6&!r5) | (!l0&!m1&m3) | (!l0&r3&!r5);
    /// xx_idx = (l0 << 7) | (l4 << 6) | (l6 << 5) | (m1 << 4) | (m3 << 3) | (r0 << 2) | (r3 << 1) | (r5 << 0)
    static const bool _ = true;
    bool l0 = idx & (1u << 7);
    bool l4 = idx & (1u << 6);
    bool l6 = idx & (1u << 5);
    bool m1 = idx & (1u << 4);
    bool m3 = idx & (1u << 3);
    bool r0 = idx & (1u << 2);
    bool r3 = idx & (1u << 1);
    bool r5 = idx & (1u << 0);

    return
        (      _    &&      _    &&   !(l6)   &&     m1   &&      _   &&   !(r0)  &&      _   &&      _   ) ||
        (      _    &&     l4    &&      _    &&      _   &&   !(m3)  &&      _   &&     r3   &&      _   ) ||
        (      _    &&   !(l4)   &&     l6    &&      _   &&      _   &&      _   &&      _   &&   !(r5)  ) ||
        (   !(l0)   &&      _    &&      _    &&   !(m1)  &&     m3   &&      _   &&      _   &&      _   ) ||
        (   !(l0)   &&      _    &&      _    &&      _   &&      _   &&      _   &&     r3   &&   !(r5)  ) ;
}
static bool espresso_implementation_xx_alt1(uint8_t idx) {
    // output_XX = (!l6&m1&!r0) | (l4&!m3&r3) | (!l4&l6&!r5) | (!l0&!m1&m3) | (!l0&r3&!r5);
    static const bool _ = true;
    /// xx_idx = (l0 << 7) | (l4 << 6) | (l6 << 5) | (m1 << 4) | (m3 << 3) | (r0 << 2) | (r3 << 1) | (r5 << 0)
    INDEX_XX t = { .as_uint8_t = idx };
    bool l0 = t.l0;
    bool l4 = t.l4;
    bool l6 = t.l6;
    bool m1 = t.m1;
    bool m3 = t.m3;
    bool r0 = t.r0;
    bool r3 = t.r3;
    bool r5 = t.r5;
    return
        (      _    &&      _    &&   !(l6)   &&     m1   &&      _   &&   !(r0)  &&      _   &&      _   ) ||
        (      _    &&     l4    &&      _    &&      _   &&   !(m3)  &&      _   &&     r3   &&      _   ) ||
        (      _    &&   !(l4)   &&     l6    &&      _   &&      _   &&      _   &&      _   &&   !(r5)  ) ||
        (   !(l0)   &&      _    &&      _    &&   !(m1)  &&     m3   &&      _   &&      _   &&      _   ) ||
        (   !(l0)   &&      _    &&      _    &&      _   &&      _   &&      _   &&     r3   &&   !(r5)  ) ;
}

static const lookuptable_func_t alt_for_xx[] = {
    espresso_implementation_xx_alt0,
    espresso_implementation_xx_alt1,
};



typedef struct _VERIFICATION_T {
    uint8_t const             input_count;
    char    const * const *   names;
    char    const * const     output_name;
    uint8_t const *           lut_start;
    lookuptable_func_t const * const altFns;
    size_t  const                    altFnCount;
} VERIFICATION_T;


VERIFICATION_T const verification_table[] = {
    { .input_count = 5, .names = LUT_PLA_NAMES_g1, .output_name = "g1", .lut_start = small_lut_group1, .altFns = alt_for_g1, .altFnCount = ARRAY_SIZE2(alt_for_g1) },
    { .input_count = 5, .names = LUT_PLA_NAMES_g2, .output_name = "g2", .lut_start = small_lut_group2, .altFns = alt_for_g2, .altFnCount = ARRAY_SIZE2(alt_for_g2) },
    { .input_count = 5, .names = LUT_PLA_NAMES_g3, .output_name = "g3", .lut_start = small_lut_group3, .altFns = alt_for_g3, .altFnCount = ARRAY_SIZE2(alt_for_g3) },
    { .input_count = 5, .names = LUT_PLA_NAMES_g4, .output_name = "g4", .lut_start = small_lut_group4, .altFns = alt_for_g4, .altFnCount = ARRAY_SIZE2(alt_for_g4) },
    { .input_count = 8, .names = LUT_PLA_NAMES_XX, .output_name = "xx", .lut_start = small_lut_XX    , .altFns = alt_for_xx, .altFnCount = ARRAY_SIZE2(alt_for_xx) },
};


static bool espresso_implementation_g1(bool a,  bool l0, bool l2, bool l3, bool l6) {
    // output_g1 = (a&l2&l0&!l6) | (a&l3&!l0&l6) | (!a&!l2&!l3) | (!l2&!l3&!l0&!l6) | (l2&l3&!l0&!l6) | (!a&!l2&l0&!l6) | (!a&!l3&!l0&l6) | (a&l2&!l3&l0) | (a&!l2&l3&l6) | (!a&l2&l3&l0&l6);
    static const bool _ = true;
    return
        (     a   &&     l0   &&     l2   &&      _   &&   !(l6)   ) |
        (     a   &&   !(l0)  &&      _   &&     l3   &&     l6    ) |
        (   !(a)  &&      _   &&   !(l2)  &&   !(l3)  &&      _    ) |
        (     _   &&   !(l0)  &&   !(l2)  &&   !(l3)  &&   !(l6)   ) |
        (     _   &&   !(l0)  &&     l2   &&     l3   &&   !(l6)   ) |
        (   !(a)  &&     l0   &&   !(l2)  &&     _    &&   !(l6)   ) |
        (   !(a)  &&   !(l0)  &&      _   &&   !(l3)  &&     l6    ) |
        (     a   &&     l0   &&     l2   &&   !(l3)  &&      _    ) |
        (     a   &&      _   &&   !(l2)  &&     l3   &&     l6    ) |
        (   !(a)  &&     l0   &&     l2   &&     l3   &&     l6    ) ;
}
static bool espresso_implementation_g2(bool b,  bool l4, bool l5, bool m0, bool m1) {
    // output_g2 = (b&m0&!l4&!m1) | (l5&b&l4&m1) | (!l5&!b&!m0) | (!b&!m0&!l4&!m1) | (l5&b&!m0&l4) | (l5&!b&m0&l4&!m1) | (!l5&b&m0&!m1) | (!l5&!m0&!l4&m1) | (l5&m0&!l4&m1) | (!l5&!b&l4&m1);
    static const bool _ = true;
    return 
        (      _   &&     b   &&     m0   &&   !(l4)  &&   !(m1)  ) |
        (     l5   &&     b   &&      _   &&     l4   &&     m1   ) |
        (   !(l5)  &&   !(b)  &&   !(m0)  &&      _   &&      _   ) |
        (      _   &&   !(b)  &&   !(m0)  &&   !(l4)  &&   !(m1)  ) |
        (     l5   &&     b   &&   !(m0)  &&     l4   &&      _   ) |
        (     l5   &&   !(b)  &&     m0   &&     l4   &&   !(m1)  ) |
        (   !(l5)  &&     b   &&     m0   &&      _   &&   !(m1)  ) |
        (   !(l5)  &&     _   &&   !(m0)  &&   !(l4)  &&     m1   ) |
        (     l5   &&     _   &&     m0   &&   !(l4)  &&     m1   ) |
        (   !(l5)  &&   !(b)  &&      _   &&     l4   &&     m1   ) ;
}
static bool espresso_implementation_g3(bool c,  bool r1, bool r3, bool m3, bool m5) {
    // output_g3 = (c&r1&!m3&!r3) | (m5&c&m3&r3) | (!m5&!c&!r1) | (!c&!r1&!m3&!r3) | (!m5&!r1&m3&!r3) | (m5&r1&m3&!r3) | (m5&c&!r1&r3) | (m5&!c&r1&!m3&r3) | (!m5&c&r1&!m3) | (!m5&!c&m3&r3);
    static const bool _ = true;
    return
        (      _   &&     c   &&     r1   &&   !(m3)  &&   !(r3)  ) |
        (     m5   &&     c   &&      _   &&     m3   &&     r3   ) |
        (   !(m5)  &&   !(c)  &&   !(r1)  &&      _   &&      _   ) |
        (      _   &&   !(c)  &&   !(r1)  &&   !(m3)  &&   !(r3)  ) |
        (   !(m5)  &&     _   &&   !(r1)  &&     m3   &&   !(r3)  ) |
        (     m5   &&     _   &&     r1   &&     m3   &&   !(r3)  ) |
        (     m5   &&     c   &&   !(r1)  &&      _   &&     r3   ) |
        (     m5   &&   !(c)  &&     r1   &&   !(m3)  &&     r3   ) |
        (   !(m5)  &&     c   &&     r1   &&   !(m3)  &&      _   ) |
        (   !(m5)  &&   !(c)  &&      _   &&     m3   &&     r3   ) ;
}
static bool espresso_implementation_g4(bool r0, bool r2, bool r4, bool r5, bool r6) {
    // output_g4 = (r2&r6&r0&!r5) | (r4&r6&!r0&r5) | (!r2&!r4&!r6) | (r2&r4&!r6&!r0&!r5) | (r2&!r4&r6&!r5) | (!r2&r4&r6&!r0) | (!r2&!r6&r0&!r5) | (!r4&!r6&!r0&r5) | (r2&r4&r0&r5) | (!r2&!r4&r0&r5);
    static const bool _ = true;
    return
        (     r2   &&      _   &&     r6   &&     r0   &&   !(r5)  ) |
        (      _   &&     r4   &&     r6   &&   !(r0)  &&     r5   ) |
        (   !(r2)  &&   !(r4)  &&   !(r6)  &&      _   &&      _   ) |
        (     r2   &&     r4   &&   !(r6)  &&   !(r0)  &&   !(r5)  ) |
        (     r2   &&   !(r4)  &&     r6   &&      _   &&   !(r5)  ) |
        (   !(r2)  &&     r4   &&     r6   &&   !(r0)  &&      _   ) |
        (   !(r2)  &&      _   &&   !(r6)  &&     r0   &&   !(r5)  ) |
        (      _   &&   !(r4)  &&   !(r6)  &&   !(r0)  &&     r5   ) |
        (     r2   &&     r4   &&      _   &&     r0   &&     r5   ) |
        (   !(r2)  &&   !(r4)  &&      _   &&     r0   &&     r5   ) ;
}
static bool espresso_implementation_XX(bool l0, bool l4, bool l6, bool m1, bool m3, bool r0, bool r3, bool r5) {
    // output_XX = (!l6&m1&!r0) | (l4&!m3&r3) | (!l4&l6&!r5) | (!l0&!m1&m3) | (!l0&r3&!r5);
    static const bool _ = true;
    return
        (      _    &&      _    &&   !(l6)   &&     m1   &&      _   &&   !(r0)  &&      _   &&      _   ) |
        (      _    &&     l4    &&      _    &&      _   &&   !(m3)  &&      _   &&     r3   &&      _   ) |
        (      _    &&   !(l4)   &&     l6    &&      _   &&      _   &&      _   &&      _   &&   !(r5)  ) |
        (   !(l0)   &&      _    &&      _    &&   !(m1)  &&     m3   &&      _   &&      _   &&      _   ) |
        (   !(l0)   &&      _    &&      _    &&      _   &&      _   &&      _   &&     r3   &&   !(r5)  );
}

static bool verify_alternatives(void)
{
    bool any_failures_overall = false;

    for (uint16_t q = 0; q < ARRAY_SIZE2(verification_table); ++q) {
        bool any_failures_this_table = false;
        VERIFICATION_T const * vt = &verification_table[q];
        const char* fstr = vt->output_name;
        uint16_t limit = 1u << vt->input_count;

        for (uint16_t fn_idx = 0; fn_idx < vt->altFnCount; ++fn_idx ) {

            bool any_failures_this_table_alts = false;
            const lookuptable_func_t fn = vt->altFns[fn_idx];

            for (uint16_t ix = 0; ix < limit; ++ix) {
                uint8_t i = (uint8_t)ix;

                bool lut_result = get_bit(vt->lut_start, i);
                bool other_result = fn(i);
                if (lut_result != other_result) {
                    printf("%s: verification failed for fn[ %d ]( %3d )\n", fstr, fn_idx, i);
                    any_failures_this_table_alts = true;
                }
            }
            if (any_failures_this_table_alts) {
                printf("FAILURE - %s alt %d\n", fstr, fn_idx);
            } else {
                printf("SUCCESS - %s alt %d\n", fstr, fn_idx);
            }

            // percolate to outer variable....
            any_failures_this_table |= any_failures_this_table_alts;
        }

        if (vt->altFnCount == 0) {
            // nothing was tested ...
        } else if (any_failures_this_table) {
            printf("FAILURE ---------> At least one of the alt functions for %s \n", fstr);
        } else {
            printf("SUCCESS ---------> All alternate for %s \n", fstr);
        }
        
        any_failures_overall |= any_failures_this_table;
    }

    if (any_failures_overall) {
        printf("=====> FAILURE: Some of the alternate generators are still failing\n");
    } else {
        printf("=====> SUCCESS: All alternate generators are succeeding\n");
    }
    return !any_failures_overall;
}

static bool verify_lut_g1(void)
{
    static const char* fstr = "verify_lut_g1";
    bool any_failures = false;
    for (uint8_t i = 0; i < 32; ++i) {
        INDEX_G1 t = { .as_uint8_t = i };
        bool lut_result = get_bit(small_lut_group1, i);
        bool other_result = espresso_implementation_g1(t.a, t.l0, t.l2, t.l3, t.l6);
        if (lut_result != other_result) {
            printf("%s: verification failed for index %d\n", fstr, t.as_uint8_t);
            any_failures = true;
        }
    }
    if (any_failures) {
        printf("FAILURE - %s\n", fstr);
    } else {
        printf("SUCCESS - %s\n", fstr);
    }
    return !any_failures;
}
static bool verify_lut_g2(void)
{
    static const char* fstr = "verify_lut_g2";
    bool any_failures = false;
    for (uint8_t i = 0; i < 32; ++i) {
        INDEX_G2 t = { .as_uint8_t = i };
        bool lut_result = get_bit(small_lut_group2, i);        
        bool other_result = espresso_implementation_g2(t.b, t.l4, t.l5, t.m0, t.m1);
        if (lut_result != other_result) {
            printf("%s: verification failed for index %d\n", fstr, t.as_uint8_t);
            any_failures = true;
        }
    }
    if (any_failures) {
        printf("FAILURE - %s\n", fstr);
    } else {
        printf("SUCCESS - %s\n", fstr);
    }
    return !any_failures;
}
static bool verify_lut_g3(void)
{
    static const char* fstr = "verify_lut_g3";
    bool any_failures = false;
    for (uint8_t i = 0; i < 32; ++i) {
        INDEX_G3 t = { .as_uint8_t = i };
        bool lut_result = get_bit(small_lut_group3, i);
        bool other_result = espresso_implementation_g3(t.c, t.r1, t.r3, t.m3, t.m5);
        if (lut_result != other_result) {
            printf("%s: verification failed for index %d\n", fstr, t.as_uint8_t);
            any_failures = true;
        }
    }
    if (any_failures) {
        printf("FAILURE - %s\n", fstr);
    } else {
        printf("SUCCESS - %s\n", fstr);
    }
    return !any_failures;
}
static bool verify_lut_g4(void)
{
    static const char* fstr = "verify_lut_g4";
    bool any_failures = false;
    for (uint8_t i = 0; i < 32; ++i) {
        INDEX_G4 t = { .as_uint8_t = i };
        bool lut_result = get_bit(small_lut_group4, i);
        bool other_result = espresso_implementation_g4(t.r0, t.r2, t.r4, t.r5, t.r6);
        if (lut_result != other_result) {
            printf("%s: verification failed for index %d\n", fstr, t.as_uint8_t);
            any_failures = true;
        }
    }
    if (any_failures) {
        printf("FAILURE - %s\n", fstr);
    } else {
        printf("SUCCESS - %s\n", fstr);
    }
    return !any_failures;
}
static bool verify_lut_XX(void)
{
    static const char* fstr = "verify_lut_XX";
    bool any_failures = false;
    for (uint16_t ix = 0; ix < 256; ++ix) {
        uint8_t i = (uint8_t)ix;
        INDEX_XX t = { .as_uint8_t = i };
        bool lut_result = get_bit(small_lut_XX, i);
        bool other_result = espresso_implementation_XX(t.l0, t.l4, t.l6, t.m1, t.m3, t.r0, t.r3, t.r5);
        if (lut_result != other_result) {
            printf("%s: verification failed for index %d\n", fstr, t.as_uint8_t);
            any_failures = true;
        }
    }
    if (any_failures) {
        printf("FAILURE - %s\n", fstr);
    } else {
        printf("SUCCESS - %s\n", fstr);
    }
    return !any_failures;
}

// order of input_names is based on resulting .PLA output,
// so least significant bit is at input_names[input_count-1]
static bool generate_espresso_file(uint8_t input_count, const char * const * input_names, const char * output_name, const uint8_t * lut_table_start, FILE* f_output) {
    if (input_count > 8) {
        printf("FAILURE - Cannot generate espresso file for more than 8 inputs (code would need update)\n");
    }
    fprintf(f_output, "# ###################\n");
    fprintf(f_output, "# Generating .PLA\n");
    fprintf(f_output, "# ###################\n");
    fprintf(f_output, "\n\n");
    fprintf(f_output, ".i %d\n", input_count);
    fprintf(f_output, ".o 1\n");
    const uint16_t iterations = 1u << input_count;
    fprintf(f_output, ".ilb");
    for (uint16_t i = 0; i < input_count; ++i) {
        const char* name = input_names[i];
        fprintf(f_output, " %s", name);
    }
    fprintf(f_output, "\n");
    fprintf(f_output, ".ob %s\n", output_name);
    for (uint16_t ix = 0; ix < iterations; ++ix) {

        uint8_t i = (uint8_t)ix;
        // NOTE:  Seems we've handled it properly here, by shifting the bit to be tested appropriately
        //        based on the total number of inputs.  So input_names[0] is the most significant bit....
        for (uint8_t bitmask = (1u << (input_count - 1u)); bitmask != 0; bitmask >>= 1) {
            fputc(((i & bitmask) != 0) ? '1' : '0', f_output);
        }
        bool bit = get_bit(lut_table_start, i);
        fprintf(f_output, "  %c\n", bit ? '1' : '0');
    }
    fprintf(f_output, ".e\n\n");

    fprintf(f_output, "# ###################\n");
    fprintf(f_output, "# END OF .PLA\n");
    fprintf(f_output, "# ###################\n");
    return true;
}

bool generate_all_lut_espresso_files(void)
{

    bool any_failures = false;

    for (size_t i = 0; i < ARRAY_SIZE2(verification_table); ++i) {
        VERIFICATION_T const * args = &verification_table[i];

        bool current_result = false;
        FILE* file = NULL;
        char filename[20] = {0}; // needs: 14 for two-letter output name

        // First create the filename to be written
        // Yes, presumes "safe" output_name ...
        if (snprintf(NULL, 0, "output_%s.pla", args->output_name) < ARRAY_SIZE2(filename)) {
            snprintf(filename, ARRAY_SIZE2(filename), "output_%s.pla", args->output_name);
            file = fopen(filename, "w");
            if (file == NULL) {
                printf("failed to open output file '%s'", filename);
            }
        }
        if (file != NULL) {
            current_result = generate_espresso_file(
                args->input_count,
                args->names,
                args->output_name,
                args->lut_start,
                file
            );
            if (!current_result) {
                printf("Failed to generate espresso file for %s\n", args->output_name);
            }
        }
        if (file != NULL) {
            fclose(file);
            file = NULL;
        }
        any_failures |= !current_result;
    }

    return !any_failures;
}
bool verify_espresso_results(void)
{
    //generate_all_lut_espresso_files();

    bool unused = verify_alternatives();
    bool r_g1 = verify_lut_g1();
    bool r_g2 = verify_lut_g2();
    bool r_g3 = verify_lut_g3();
    bool r_g4 = verify_lut_g4();
    bool r_xx = verify_lut_XX();
    return r_g1 && r_g2 && r_g3 && r_g4 && r_xx;
}
