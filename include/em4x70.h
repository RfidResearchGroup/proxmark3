//-----------------------------------------------------------------------------
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
// Low frequency EM4x70 structs
//-----------------------------------------------------------------------------

#ifndef EM4X70_H__
#define EM4X70_H__

#define EM4X70_NUM_BLOCKS 16

// Common word/block addresses
#define EM4X70_PIN_WORD_LOWER 10
#define EM4X70_PIN_WORD_UPPER 11

typedef struct {
    bool parity;

    // Used for writing address
    uint8_t address;
    uint16_t word;

    // PIN to unlock
    uint32_t pin;

    // Used for authentication
    uint8_t rnd[7];
    uint8_t frnd[4];

    // Used to write new key
    //
    //     idx      contains
    //      0      K₉₅ .. K₈₈   (MSB is sent first)
    //      1      K₈₇ .. K₈₀
    //      2      K₇₉ .. K₇₂
    //      3      K₇₁ .. K₆₄
    //      4      K₆₃ .. K₅₆
    //      5      K₅₅ .. K₄₈
    //      6      K₄₇ .. K₄₀
    //      7      K₃₉ .. K₃₂
    //      8      K₃₁ .. K₂₄
    //      9      K₂₃ .. K₁₆
    //     10      K₁₅ .. K₈
    //     11      K₇  .. K₀
    //
    // See more exhaustive notes in armsrc/em4x70.c
    uint8_t crypt_key[12];

    // used for bruteforce the partial key
    uint16_t start_key;

} em4x70_data_t;


// Proxmark3 client/device command architecture requires
// that the device does not initiate a response unless/until
// a command from the client arrives.  The device may only
// provide a single response to each client command.  This
// appears to prevent the device from processing long-running
// command, while also sending periodic updates to the client.
// Instead, it appears that the client must pre-select a
// maximum amount of processing to occur, and then provide
// that as part of the parameters.  The PM3 device, meanwhile,
// must re-parse/re-validate those parameters each time,
// and then resume the long-running parsing.
// This adds a small (normally negligible) delay between
// the chunks of processing time.
//
// GOAL:
// * Enable client to branch effectively
//   * Indicate bit of the key that is being flipped / started at
// * Enable offline mode (`#if defined(WITH_FLASH)`)
//   * worker functions take structured data in, output structured data (no debug prints for outputs!)
// * Enable following sequence:
//   * Phase 1     - validate starting set
//   *   Phase 2   - given N, write branched key and report starting frn & max iteration count
//   *     Phase 3 - given frn start & iteration count, brute-force that group...
//   *     Phase 3 - given frn start & iteration count, brute-force that group...
//   *     ...
//   *     Phase 3 - given frn start & iteration count, brute-force that group...
//   *   Phase 2   - given new N, write branched key and report starting frn & max iteration count
//   *     Phase 3 - given frn start & iteration count, brute-force that group...
//   *     Phase 3 - given frn start & iteration count, brute-force that group...
//   *     ...
//   *     Phase 3 - given frn start & iteration count, brute-force that group...
//
typedef enum EM4X70_AUTHBRANCH_PHASE {
    // all other values are invalid
    EM4X70_AUTHBRANCH_PHASE0_UNINITIALIZED                    = 0,
    EM4X70_AUTHBRANCH_PHASE1_REQUESTED_VERIFY_STARTING_VALUES = 1,
    EM4X70_AUTHBRANCH_PHASE1_COMPLETED_VERIFY_STARTING_VALUES = 2,
    EM4X70_AUTHBRANCH_PHASE2_REQUESTED_WRITE_BRANCHED_KEY     = 3,
    EM4X70_AUTHBRANCH_PHASE2_COMPLETED_WRITE_BRANCHED_KEY     = 4,
    EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE            = 5,
    EM4X70_AUTHBRANCH_PHASE3_COMPLETED_BRUTE_FORCE            = 6,
    // largest value uses >16 bits to force 32-bit size
} em4x70_authbranch_phase_t;

enum { EM4X70_MINIMUM_KEY_DIVERGENCE_BITS =  5 };
enum { EM4X70_MAXIMUM_KEY_DIVERGENCE_BITS = 31 };

// ALL VALUES IN THIS STRUCTURE ARE STORED INTERNALLY AS BIG-ENDIAN VALUES (for consistency)
// This structures uses only `uint8_t`, to ensure size does not vary across client/compilation.
//     e.g., sizeof(enum) is implementation dependent, and actually causes problems today
//     e.g., sizeof(bool) is implementation dependent
//
// Users must convert any multi-byte values to/from native form.
// See, for example, the following functions:
//     MemBeToUint4byte()
//     Uint4byteToMemBe()
//
// TODO: align(4) or equivalent macro for this struct

typedef struct EM4X70_AUTHBRANCH_PHASE1_INPUT {
    uint8_t useParity;          // do not use bool directly, because sizeof(bool) is implementation-dependent
    uint8_t be_rnd[7];          // big-endian, rnd/frn are required for phase 2 -- verifying original auth
    uint8_t be_key[12];         // big-endian
    uint8_t be_frn[4];          // big-endian, 28-bit value shifted right by 4 (lowest four bits always zero)
    uint8_t be_start_frn[4];    // big-endian
    uint8_t be_xormask[4];      // which bits of the key to change
} em4x70_authbranch_phase1_input_t;
typedef struct EM4X70_AUTHBRANCH_PHASE2_INPUT {
    uint8_t be_xormask[4];      // which bits of the key to change
} em4x70_authbranch_phase2_input_t;
typedef struct EM4X70_AUTHBRANCH_PHASE2_OUTPUT {
    uint8_t be_key[12];           // big-endian -- written to transponder!
    uint8_t be_start_frn[4];      // big-endian
    uint8_t be_max_iterations[4]; // big-endian -- max loop iterations w/`frn` incremented by 0x10 each time
} em4x70_authbranch_phase2_output_t;
typedef struct EM4X70_AUTHBRANCH_PHASE3_INPUT {
    uint8_t be_starting_frn[4];    // big-endian
    uint8_t be_max_iterations[4]; // big-endian -- how many times to increment `frn` by 0x10
} em4x70_authbranch_phase3_input_t;
typedef struct EM4X70_AUTHBRANCH_PHASE3_OUTPUT {
    uint8_t be_next_start_frn[4]; // big-endian -- simplify continuation if working frn not found (inc. when abort detected!)
    uint8_t found_working_value;  // do not use boolean ... size is implementation-dependent
    uint8_t be_successful_ac[3];  // big-endian -- transponder response, 20 bits, least significant 4 bits are zero
    uint8_t be_successful_frn[4]; // big-endian -- found a value that worked! (invalid value: 0xFFFFFFFF)
} em4x70_authbranch_phase3_output_t;

typedef struct {
    uint8_t be_phase[4];  // big-endian ... do not use enum directly because size differs between clients/devices

    // phase 1  input: key, rnd,  frn, parity, start_frn, branching divergence -- These do not get overwritten in phase 2/3
    // phase 1 output: SUCCESS if could write key and authenticate with the transponder (else error code)
    em4x70_authbranch_phase1_input_t  phase1_input;

    // phase 2  input: xor mask to be applied to the phase1 key for branching
    // phase 2 output: SUCCESS if could write branched key (also indicates { key, start frn, end frn })
    em4x70_authbranch_phase2_input_t  phase2_input;
    em4x70_authbranch_phase2_output_t phase2_output;

    // phase 3  input: starting frn & max iterations (+rnd from phase1 input)
    em4x70_authbranch_phase3_input_t  phase3_input;
    em4x70_authbranch_phase3_output_t phase3_output;
} em4x70_authbranch_t;
// Examples of branched key, branched frn start, and branched iterations derivation:
//
// When N is in range 5..31:
//    N              :== bit of key to branch from
//    Kx             :==    1u << N
//    Kt             :==   (1u << N)-1
//    Km             :== ~((1u << N)-1)
//
//    Ft             :==
//    Fm             :==
//    frn_Start      :== frn & Fm
//    max iterations :== 1 << (N-4)
//    BranchKey      :== (K & Km) ^ Kx
//
//
//   N   Kx         Kt         Km         Ft         Fm         Iter(max)
//   0   0000_0001  0000_0000  FFFF_FFFF  0000_000F  FFFF_FFF0  0000_0001  ==    1      ____ these are a special
//   1   0000_0002  0000_0001  FFFF_FFFE  0000_000F  FFFF_FFF0  0000_0001  ==    1         / case ... because the
//   2   0000_0004  0000_0003  FFFF_FFFC  0000_000F  FFFF_FFF0  0000_0001  ==    1        /  lowest five bits of
//   3   0000_0008  0000_0007  FFFF_FFF8  0000_000F  FFFF_FFF0  0000_0001  ==    1       /   the original key are
//   4   0000_0010  0000_000F  FFFF_FFF0  0000_000F  FFFF_FFF0  0000_0001  ==    1      /    irrelevant to `frn`
//   ------------------------------------------------------------------------------------------------------------
//   5   0000_0020  0000_001F  FFFF_FFE0  0000_001F  FFFF_FFE0  0000_0002  ==    2     ----- least significant bit of frn may change
//   6   0000_0040  0000_003F  FFFF_FFC0  0000_003F  FFFF_FFC0  0000_0004  ==    4
//   7   0000_0080  0000_007F  FFFF_FF80  0000_007F  FFFF_FF80  0000_0008  ==    8
//   8   0000_0100  0000_00FF  FFFF_FF00  0000_00FF  FFFF_FF00  0000_0010  ==   16
//   9   0000_0200  0000_01FF  FFFF_FE00  0000_01FF  FFFF_FE00  0000_0020  ==   32
//  10   0000_0400  0000_03FF  FFFF_FC00  0000_03FF  FFFF_FC00  0000_0040  ==   64
//  11   0000_0800  0000_07FF  FFFF_F800  0000_07FF  FFFF_F800  0000_0080  ==  128
//  12   0000_1000  0000_0FFF  FFFF_F000  0000_0FFF  FFFF_F000  0000_0100  ==  256
//  13   0000_2000  0000_1FFF  FFFF_E000  0000_1FFF  FFFF_E000  0000_0200  ==  512
//  14   0000_4000  0000_3FFF  FFFF_C000  0000_3FFF  FFFF_C000  0000_0400  ==    1 Ki
//  15   0000_8000  0000_7FFF  FFFF_8000  0000_7FFF  FFFF_8000  0000_0800  ==    2 Ki
//  16   0001_0000  0000_FFFF  FFFF_0000  0000_FFFF  FFFF_0000  0000_1000  ==    4 Ki
//  17   0002_0000  0001_FFFF  FFFE_0000  0001_FFFF  FFFE_0000  0000_2000  ==    8 Ki
//  18   0004_0000  0003_FFFF  FFFC_0000  0003_FFFF  FFFC_0000  0000_4000  ==   16 Ki
//  19   0008_0000  0007_FFFF  FFF8_0000  0007_FFFF  FFF8_0000  0000_8000  ==   32 Ki
//  20   0010_0000  000F_FFFF  FFF0_0000  000F_FFFF  FFF0_0000  0001_0000  ==   64 Ki
//  21   0020_0000  001F_FFFF  FFE0_0000  001F_FFFF  FFE0_0000  0002_0000  ==  128 Ki
//  22   0040_0000  003F_FFFF  FFC0_0000  003F_FFFF  FFC0_0000  0004_0000  ==  256 Ki
//  23   0080_0000  007F_FFFF  FF80_0000  007F_FFFF  FF80_0000  0008_0000  ==  512 Ki
//  24   0100_0000  00FF_FFFF  FF00_0000  00FF_FFFF  FF00_0000  0010_0000  ==    1 Mi
//  25   0200_0000  01FF_FFFF  FE00_0000  01FF_FFFF  FE00_0000  0020_0000  ==    2 Mi
//  26   0400_0000  03FF_FFFF  FC00_0000  03FF_FFFF  FC00_0000  0040_0000  ==    4 Mi
//  27   0800_0000  07FF_FFFF  F800_0000  07FF_FFFF  F800_0000  0080_0000  ==    8 Mi
//  28   1000_0000  0FFF_FFFF  F000_0000  0FFF_FFFF  F000_0000  0100_0000  ==   16 Mi
//  29   2000_0000  1FFF_FFFF  E000_0000  1FFF_FFFF  E000_0000  0200_0000  ==   32 Mi
//  30   4000_0000  3FFF_FFFF  C000_0000  3FFF_FFFF  C000_0000  0400_0000  ==   64 Mi
//  31   8000_0000  7FFF_FFFF  8000_0000  7FFF_FFFF  8000_0000  0800_0000  ==  128 Mi
//
// Note that, at N=31, only a single bit of the original `frn` is kept.
// At N >= 32, it requires a full brute-forcing of the entire 28-bit frn.



#endif /* EM4X70_H__ */
