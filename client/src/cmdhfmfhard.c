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
// Implements a card only attack based on crypto text (encrypted nonces
// received during a nested authentication) only. Unlike other card only
// attacks this doesn't rely on implementation errors but only on the
// inherent weaknesses of the crypto1 cypher. Described in
//   Carlo Meijer, Roel Verdult, "Ciphertext-only Cryptanalysis on Hardened
//   Mifare Classic Cards" in Proceedings of the 22nd ACM SIGSAC Conference on
//   Computer and Communications Security, 2015
//-----------------------------------------------------------------------------

#include "cmdhfmfhard.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <locale.h>
#include <math.h>
#include <time.h> // MingW
#include <lz4frame.h>
#include <bzlib.h>

#include "commonutil.h"  // ARRAYLEN
#include "comms.h"
#include "proxmark3.h"
#include "ui.h"
#include "util_posix.h"
#include "crapto1/crapto1.h"
#include "parity.h"
#include "hardnested_bruteforce.h"
#include "hardnested_bf_core.h"
#include "hardnested_bitarray_core.h"
#include "fileutils.h"

#define NUM_CHECK_BITFLIPS_THREADS      (num_CPUs())
#define NUM_REDUCTION_WORKING_THREADS   (num_CPUs())

// ignore bitflip arrays which have nearly only valid states
#define IGNORE_BITFLIP_THRESHOLD        0.9901

#define STATE_FILES_DIRECTORY           "hardnested_tables/"
#define STATE_FILE_TEMPLATE_RAW         "bitflip_%d_%03" PRIx16 "_states.bin"
#define STATE_FILE_TEMPLATE_LZ4         "bitflip_%d_%03" PRIx16 "_states.bin.lz4"
#define STATE_FILE_TEMPLATE_BZ2         "bitflip_%d_%03" PRIx16 "_states.bin.bz2"

#define DEBUG_KEY_ELIMINATION
// #define DEBUG_REDUCTION

// possible sum property values
static uint16_t sums[NUM_SUMS] = {
    0,   32,  56,  64,  80,  96,  104, 112,
    120, 128, 136, 144, 152, 160, 176, 192,
    200, 224, 256
};

// number of possible partial sum property values
#define NUM_PART_SUMS                  9

typedef enum {
    EVEN_STATE = 0,
    ODD_STATE = 1
} odd_even_t;

static uint32_t num_acquired_nonces = 0;
static uint64_t start_time = 0;
static uint16_t effective_bitflip[2][0x400];
static uint16_t num_effective_bitflips[2] = {0, 0};
static uint16_t all_effective_bitflip[0x400];
static uint16_t num_all_effective_bitflips = 0;
static uint16_t num_1st_byte_effective_bitflips = 0;
#define CHECK_1ST_BYTES 0x01
#define CHECK_2ND_BYTES 0x02
static uint8_t hardnested_stage = CHECK_1ST_BYTES;
static uint64_t known_target_key;
static uint32_t test_state[2] = {0, 0};
static float brute_force_per_second;

static void get_SIMD_instruction_set(char *instruction_set) {
    switch (GetSIMDInstrAuto()) {
#if defined(COMPILER_HAS_SIMD_AVX512)
        case SIMD_AVX512:
            strcpy(instruction_set, "AVX512F");
            break;
#endif
#if defined(COMPILER_HAS_SIMD_X86)
        case SIMD_AVX2:
            strcpy(instruction_set, "AVX2");
            break;
        case SIMD_AVX:
            strcpy(instruction_set, "AVX");
            break;
        case SIMD_SSE2:
            strcpy(instruction_set, "SSE2");
            break;
        case SIMD_MMX:
            strcpy(instruction_set, "MMX");
            break;
#endif
#if defined(COMPILER_HAS_SIMD_NEON)
        case SIMD_NEON:
            strcpy(instruction_set, "NEON");
            break;
#endif
        case SIMD_AUTO:
        case SIMD_NONE:
            strcpy(instruction_set, "no");
            break;
    }
}

static void print_progress_header(void) {
    char progress_text[80];
    char instr_set[12] = "";
    get_SIMD_instruction_set(instr_set);
    snprintf(progress_text, sizeof(progress_text), "Start using " _YELLOW_("%d") " threads and " _YELLOW_("%s") " SIMD core", num_CPUs(), instr_set);

    PrintAndLogEx(INFO, "Hardnested attack starting...");
    PrintAndLogEx(INFO, "---------+---------+---------------------------------------------------------+-----------------+-------");
    PrintAndLogEx(INFO, "         |         |                                                         | Expected to brute force");
    PrintAndLogEx(INFO, " Time    | #nonces | Activity                                                | #states         | time ");
    PrintAndLogEx(INFO, "---------+---------+---------------------------------------------------------+-----------------+-------");
    PrintAndLogEx(INFO, "       0 |       0 | %-73s |                 |", progress_text);
}

void hardnested_print_progress(uint32_t nonces, const char *activity, float brute_force, uint64_t min_diff_print_time) {
    static uint64_t last_print_time = 0;
    if (msclock() - last_print_time >= min_diff_print_time) {
        last_print_time = msclock();
        uint64_t total_time = msclock() - start_time;
        float brute_force_time = brute_force / brute_force_per_second;
        char brute_force_time_string[20];
        if (brute_force_time < 90) {
            snprintf(brute_force_time_string, sizeof(brute_force_time_string), "%2.0fs", brute_force_time);
        } else if (brute_force_time < 60 * 90) {
            snprintf(brute_force_time_string, sizeof(brute_force_time_string), "%2.0fmin", brute_force_time / 60);
        } else if (brute_force_time < 60 * 60 * 36) {
            snprintf(brute_force_time_string, sizeof(brute_force_time_string), "%2.0fh", brute_force_time / (60 * 60));
        } else {
            snprintf(brute_force_time_string, sizeof(brute_force_time_string), "%2.0fd", brute_force_time / (60 * 60 * 24));
        }
        PrintAndLogEx(INFO, " %7.0f | %7u | %-55s | %15.0f | %5s", (float)total_time / 1000.0, nonces, activity, brute_force, brute_force_time_string);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// bitarray functions

static inline void clear_bitarray24(uint32_t *bitarray) {
    memset(bitarray, 0x00, sizeof(uint32_t) * (1 << 19));
}

static inline void set_bitarray24(uint32_t *bitarray) {
    memset(bitarray, 0xff, sizeof(uint32_t) * (1 << 19));
}

static inline void set_bit24(uint32_t *bitarray, uint32_t index) {
    bitarray[index >> 5] |= 0x80000000 >> (index & 0x0000001f);
}

static inline uint32_t test_bit24(const uint32_t *bitarray, uint32_t index) {
    return bitarray[index >> 5] & (0x80000000 >> (index & 0x0000001f));
}

static inline uint32_t next_state(uint32_t *bitarray, uint32_t state) {
    if (++state == (1 << 24)) {
        return (1 << 24);
    }

    uint32_t index = state >> 5;
    uint_fast8_t bit = state & 0x1F;
    uint32_t line = bitarray[index] << bit;

    while (bit <= 0x1F) {
        if (line & 0x80000000) {
            return state;
        }
        state++;
        bit++;
        line <<= 1;
    }
    index++;
    while (state < (1 << 24) && bitarray[index] == 0x00000000) {
        index++;
        state += 0x20;
    }

    if (state >= (1 << 24)) {
        return (1 << 24);
    }
#if defined __GNUC__
    return state + __builtin_clz(bitarray[index]);
#else
    bit = 0x00;
    line = bitarray[index];
    while (bit <= 0x1F) {
        if (line & 0x80000000) {
            return state;
        }
        state++;
        bit++;
        line <<= 1;
    }
    return (1 << 24);
#endif
}


#define BITFLIP_2ND_BYTE 0x0200


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// bitflip property bitarrays

static uint32_t *bitflip_bitarrays[2][0x400];
static uint32_t count_bitflip_bitarrays[2][0x400];

static int compare_count_bitflip_bitarrays(const void *b1, const void *b2) {
    uint64_t count1 = (uint64_t)count_bitflip_bitarrays[ODD_STATE][*(uint16_t *)b1] * count_bitflip_bitarrays[EVEN_STATE][*(uint16_t *)b1];
    uint64_t count2 = (uint64_t)count_bitflip_bitarrays[ODD_STATE][*(uint16_t *)b2] * count_bitflip_bitarrays[EVEN_STATE][*(uint16_t *)b2];
    return (count1 > count2) - (count2 > count1);
}


#define OUTPUT_BUFFER_LEN 80
#define INPUT_BUFFER_LEN 80

//----------------------------------------------------------------------------
// Initialize decompression of the respective bitflip_bitarray stream
//----------------------------------------------------------------------------
static void init_bunzip2(bz_stream *compressed_stream, char *input_buffer, uint32_t insize, char *output_buffer, uint32_t outsize) {

    // initialize bz_stream structure for bunzip2:
    compressed_stream->next_in = input_buffer;
    compressed_stream->avail_in = insize;
    compressed_stream->next_out = output_buffer;
    compressed_stream->avail_out = outsize;
    compressed_stream->bzalloc = NULL;
    compressed_stream->bzfree = NULL;

    BZ2_bzDecompressInit(compressed_stream, 0, 0);

}

static void init_bitflip_bitarrays(void) {
#if defined (DEBUG_REDUCTION)
    uint8_t line = 0;
#endif
    uint64_t init_bitflip_bitarrays_starttime = msclock();

    char state_file_name[MAX(strlen(STATE_FILE_TEMPLATE_RAW), MAX(strlen(STATE_FILE_TEMPLATE_LZ4), strlen(STATE_FILE_TEMPLATE_BZ2))) + 1];
    char state_files_path[strlen(get_my_executable_directory()) + strlen(STATE_FILES_DIRECTORY) + sizeof(state_file_name)];
    uint16_t nraw = 0, nlz4 = 0, nbz2 = 0;
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        num_effective_bitflips[odd_even] = 0;
        for (uint16_t bitflip = 0x001; bitflip < 0x400; bitflip++) {
            bool open_uncompressed = false;
            bool open_lz4compressed = false;
            bool open_bz2compressed = false;

            bitflip_bitarrays[odd_even][bitflip] = NULL;
            count_bitflip_bitarrays[odd_even][bitflip] = 1 << 24;

            char *path;
            snprintf(state_file_name, sizeof(state_file_name), STATE_FILE_TEMPLATE_RAW, odd_even, bitflip);
            strncpy(state_files_path, STATE_FILES_DIRECTORY, sizeof(state_files_path) - 1);
            strncat(state_files_path, state_file_name, sizeof(state_files_path) - (strlen(STATE_FILES_DIRECTORY) + 1));
            if (searchFile(&path, RESOURCES_SUBDIR, state_files_path, "", true) == PM3_SUCCESS) {
                open_uncompressed = true;
            } else {
                snprintf(state_file_name, sizeof(state_file_name), STATE_FILE_TEMPLATE_LZ4, odd_even, bitflip);
                strncpy(state_files_path, STATE_FILES_DIRECTORY, sizeof(state_files_path) - 1);
                strncat(state_files_path, state_file_name, sizeof(state_files_path) - (strlen(STATE_FILES_DIRECTORY) + 1));
                if (searchFile(&path, RESOURCES_SUBDIR, state_files_path, "", true) == PM3_SUCCESS) {
                    open_lz4compressed = true;
                } else {
                    snprintf(state_file_name, sizeof(state_file_name), STATE_FILE_TEMPLATE_BZ2, odd_even, bitflip);
                    strncpy(state_files_path, STATE_FILES_DIRECTORY, sizeof(state_files_path) - 1);
                    strncat(state_files_path, state_file_name, sizeof(state_files_path) - (strlen(STATE_FILES_DIRECTORY) + 1));
                    if (searchFile(&path, RESOURCES_SUBDIR, state_files_path, "", true) == PM3_SUCCESS) {
                        open_bz2compressed = true;
                    } else {
                        continue;
                    }
                }
            }

            FILE *statesfile = fopen(path, "rb");
            free(path);
            if (statesfile == NULL) {
                continue;
            }

            fseek(statesfile, 0, SEEK_END);
            int fsize = ftell(statesfile);
            if (fsize == -1) {
                PrintAndLogEx(ERR, "File read error with %s. Aborting...\n", state_file_name);
                fclose(statesfile);
                exit(5);
            }
            uint32_t filesize = (uint32_t)fsize;
            rewind(statesfile);

            if (open_uncompressed) {

                uint32_t count = 0;
                size_t bytesread = fread(&count, 1, sizeof(count), statesfile);
                if (bytesread != 4) {
                    PrintAndLogEx(ERR, "File read error with %s. Aborting...\n", state_file_name);
                    fclose(statesfile);
                    exit(5);
                }

                if ((float)count / (1 << 24) < IGNORE_BITFLIP_THRESHOLD) {
                    uint32_t *bitset = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
                    if (bitset == NULL) {
                        PrintAndLogEx(ERR, "Out of memory error in init_bitflip_statelists(). Aborting...\n");
                        fclose(statesfile);
                        exit(4);
                    }

                    bytesread = fread(bitset, 1, filesize - sizeof(count), statesfile);
                    if (bytesread != filesize - sizeof(count)) {
                        PrintAndLogEx(ERR, "File read error with %s. Aborting...\n", state_file_name);
                        fclose(statesfile);
                        exit(5);
                    }

                    effective_bitflip[odd_even][num_effective_bitflips[odd_even]++] = bitflip;
                    bitflip_bitarrays[odd_even][bitflip] = bitset;
                    count_bitflip_bitarrays[odd_even][bitflip] = count;
#if defined (DEBUG_REDUCTION)
                    PrintAndLogEx(INFO, "(%03" PRIx16 " %s:%5.1f%%) ", bitflip, odd_even ? "odd " : "even", (float)count / (1 << 24) * 100.0);
                    line++;
                    if (line == 8) {
                        PrintAndLogEx(NORMAL, "");
                        line = 0;
                    }
#endif
                }
                fclose(statesfile);
                nraw++;
                continue;

            } else if (open_lz4compressed) {

                char *compressed_data = calloc(filesize, sizeof(uint8_t));
                if (compressed_data == NULL) {
                    PrintAndLogEx(ERR, "Out of memory error in init_bitflip_statelists(). Aborting...\n");
                    fclose(statesfile);
                    exit(4);
                }
                size_t bytesread = fread(compressed_data, 1, filesize, statesfile);
                if (bytesread != filesize) {
                    PrintAndLogEx(ERR, "File read error with %s (2). Aborting...\n", state_file_name);
                    free(compressed_data);
                    fclose(statesfile);
                    exit(5);
                }
                fclose(statesfile);

                char *uncompressed_data = calloc((sizeof(uint32_t) * (1 << 19)) + sizeof(uint32_t), sizeof(uint8_t));
                if (uncompressed_data == NULL) {
                    PrintAndLogEx(ERR,   "Out of memory error in init_bitflip_statelists(). Aborting...\n");
                    free(compressed_data);
                    exit(4);
                }

                LZ4F_decompressionContext_t ctx;
                LZ4F_errorCode_t result = LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION);
                if (LZ4F_isError(result)) {
                    PrintAndLogEx(ERR, "File read error with %s (3) Failed to create decompression context: %s. Aborting...\n", state_file_name, LZ4F_getErrorName(result));
                    free(compressed_data);
                    free(uncompressed_data);
                    exit(5);
                }

                size_t expected_output_size = (sizeof(uint32_t) * (1 << 19)) + sizeof(uint32_t);
                size_t consumed_input_size = filesize;
                size_t generated_output_size = expected_output_size;
                result = LZ4F_decompress(ctx, uncompressed_data, &generated_output_size, compressed_data, &consumed_input_size, NULL);

                LZ4F_freeDecompressionContext(ctx);
                free(compressed_data);

                if (LZ4F_isError(result)) {
                    PrintAndLogEx(ERR, "File read error with %s (3) %s. Aborting...\n", state_file_name, LZ4F_getErrorName(result));
                    free(uncompressed_data);
                    exit(5);
                }
                if (generated_output_size != expected_output_size) {
                    PrintAndLogEx(ERR, "File read error with %s (3) got %lu instead of %lu bytes. Aborting...\n", state_file_name, generated_output_size, expected_output_size);
                    free(uncompressed_data);
                    exit(5);
                }

                uint32_t count = ((uint32_t *)uncompressed_data)[0];

                if ((float)count / (1 << 24) < IGNORE_BITFLIP_THRESHOLD) {
                    uint32_t *bitset = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
                    if (bitset == NULL) {
                        PrintAndLogEx(ERR, "Out of memory error in init_bitflip_statelists(). Aborting...\n");
                        free(uncompressed_data);
                        exit(4);
                    }
                    memcpy(bitset, uncompressed_data + sizeof(uint32_t), sizeof(uint32_t) * (1 << 19));
                    effective_bitflip[odd_even][num_effective_bitflips[odd_even]++] = bitflip;
                    bitflip_bitarrays[odd_even][bitflip] = bitset;
                    count_bitflip_bitarrays[odd_even][bitflip] = count;
#if defined (DEBUG_REDUCTION)
                    PrintAndLogEx(INFO, "(%03" PRIx16 " %s:%5.1f%%) ", bitflip, odd_even ? "odd " : "even", (float)count / (1 << 24) * 100.0);
                    line++;
                    if (line == 8) {
                        PrintAndLogEx(NORMAL, "");
                        line = 0;
                    }
#endif
                }
                free(uncompressed_data);
                nlz4++;
                continue;
            } else if (open_bz2compressed) {

                char input_buffer[filesize];
                size_t bytesread = fread(input_buffer, 1, filesize, statesfile);
                if (bytesread != filesize) {
                    PrintAndLogEx(ERR, "File read error with %s. Aborting...\n", state_file_name);
                    fclose(statesfile);
                    exit(5);
                }
                fclose(statesfile);

                uint32_t count = 0;
                bz_stream compressed_stream;
                init_bunzip2(&compressed_stream, input_buffer, filesize, (char *)&count, sizeof(count));
                int res = BZ2_bzDecompress(&compressed_stream);
                if (res != BZ_OK) {
                    PrintAndLogEx(ERR, "Bunzip2 error. Aborting...\n");
                    BZ2_bzDecompressEnd(&compressed_stream);
                    exit(4);
                }
                if ((float)count / (1 << 24) < IGNORE_BITFLIP_THRESHOLD) {
                    uint32_t *bitset = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
                    if (bitset == NULL) {
                        PrintAndLogEx(ERR, "Out of memory error in init_bitflip_statelists(). Aborting...\n");
                        BZ2_bzDecompressEnd(&compressed_stream);
                        exit(4);
                    }
                    compressed_stream.next_out = (char *)bitset;
                    compressed_stream.avail_out = sizeof(uint32_t) * (1 << 19);
                    res = BZ2_bzDecompress(&compressed_stream);
                    if (res != BZ_OK && res != BZ_STREAM_END) {
                        PrintAndLogEx(ERR, "Bunzip2 error. Aborting...\n");
                        BZ2_bzDecompressEnd(&compressed_stream);
                        exit(4);
                    }
                    effective_bitflip[odd_even][num_effective_bitflips[odd_even]++] = bitflip;
                    bitflip_bitarrays[odd_even][bitflip] = bitset;
                    count_bitflip_bitarrays[odd_even][bitflip] = count;
#if defined (DEBUG_REDUCTION)
                    PrintAndLogEx(INFO, "(%03" PRIx16 " %s:%5.1f%%) ", bitflip, odd_even ? "odd " : "even", (float)count / (1 << 24) * 100.0);
                    line++;
                    if (line == 8) {
                        PrintAndLogEx(NORMAL, "");
                        line = 0;
                    }
#endif
                }
                BZ2_bzDecompressEnd(&compressed_stream);
                nbz2++;
            }
        }
        effective_bitflip[odd_even][num_effective_bitflips[odd_even]] = 0x400; // EndOfList marker
    }
    {
        char progress_text[80];
        snprintf(progress_text, sizeof(progress_text), "Loaded %u RAW / %u LZ4 / %u BZ2 in %"PRIu64" ms", nraw, nlz4, nbz2, msclock() - init_bitflip_bitarrays_starttime);
        hardnested_print_progress(0, progress_text, (float)(1LL << 47), 0);
    }
    uint16_t i = 0;
    uint16_t j = 0;
    num_all_effective_bitflips = 0;
    num_1st_byte_effective_bitflips = 0;
    while (i < num_effective_bitflips[EVEN_STATE] || j < num_effective_bitflips[ODD_STATE]) {
        if (effective_bitflip[EVEN_STATE][i] < effective_bitflip[ODD_STATE][j]) {
            all_effective_bitflip[num_all_effective_bitflips++] = effective_bitflip[EVEN_STATE][i];
            i++;
        } else if (effective_bitflip[EVEN_STATE][i] > effective_bitflip[ODD_STATE][j]) {
            all_effective_bitflip[num_all_effective_bitflips++] = effective_bitflip[ODD_STATE][j];
            j++;
        } else {
            all_effective_bitflip[num_all_effective_bitflips++] = effective_bitflip[EVEN_STATE][i];
            i++;
            j++;
        }
        if (!(all_effective_bitflip[num_all_effective_bitflips - 1] & BITFLIP_2ND_BYTE)) {
            num_1st_byte_effective_bitflips = num_all_effective_bitflips;
        }
    }
    qsort(all_effective_bitflip, num_1st_byte_effective_bitflips, sizeof(uint16_t), compare_count_bitflip_bitarrays);
#if defined (DEBUG_REDUCTION)
    PrintAndLogEx(INFO, "1st byte effective bitflips (%d): ", num_1st_byte_effective_bitflips);
    for (uint16_t i = 0; i < num_1st_byte_effective_bitflips; i++) {
        PrintAndLogEx(INFO, "%03x ",  all_effective_bitflip[i]);
    }
#endif
    qsort(all_effective_bitflip + num_1st_byte_effective_bitflips, num_all_effective_bitflips - num_1st_byte_effective_bitflips, sizeof(uint16_t), compare_count_bitflip_bitarrays);
#if defined (DEBUG_REDUCTION)
    PrintAndLogEx(INFO, "2nd byte effective bitflips (%d): ", num_all_effective_bitflips - num_1st_byte_effective_bitflips);
    for (uint16_t i = num_1st_byte_effective_bitflips; i < num_all_effective_bitflips; i++) {
        PrintAndLogEx(INFO, "%03x ",  all_effective_bitflip[i]);
    }
#endif
    {
        char progress_text[80];
        snprintf(progress_text, sizeof(progress_text), "Using %d precalculated bitflip state tables", num_all_effective_bitflips);
        hardnested_print_progress(0, progress_text, (float)(1LL << 47), 0);
    }
}

static void free_bitflip_bitarrays(void) {
    for (int16_t bitflip = 0x3ff; bitflip > 0x000; bitflip--) {
        free_bitarray(bitflip_bitarrays[ODD_STATE][bitflip]);
    }
    for (int16_t bitflip = 0x3ff; bitflip > 0x000; bitflip--) {
        free_bitarray(bitflip_bitarrays[EVEN_STATE][bitflip]);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// sum property bitarrays

static uint32_t *part_sum_a0_bitarrays[2][NUM_PART_SUMS];
static uint32_t *part_sum_a8_bitarrays[2][NUM_PART_SUMS];
static uint32_t *sum_a0_bitarrays[2][NUM_SUMS];

static uint16_t PartialSumProperty(uint32_t state, odd_even_t odd_even) {
    uint16_t sum = 0;
    for (uint16_t j = 0; j < 16; j++) {
        uint32_t st = state;
        uint16_t part_sum = 0;
        if (odd_even == ODD_STATE) {
            part_sum ^= filter(st);
            for (uint16_t i = 0; i < 4; i++) {
                st = (st << 1) | ((j >> (3 - i)) & 0x01) ;
                part_sum ^= filter(st);
            }
            part_sum ^= 1; // XOR 1 cancelled out for the other 8 bits
        } else {
            for (uint16_t i = 0; i < 4; i++) {
                st = (st << 1) | ((j >> (3 - i)) & 0x01) ;
                part_sum ^= filter(st);
            }
        }
        sum += part_sum;
    }
    return sum;
}

static void init_part_sum_bitarrays(void) {
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        for (uint16_t part_sum_a0 = 0; part_sum_a0 < NUM_PART_SUMS; part_sum_a0++) {
            part_sum_a0_bitarrays[odd_even][part_sum_a0] = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
            if (part_sum_a0_bitarrays[odd_even][part_sum_a0] == NULL) {
                PrintAndLogEx(ERR, "Out of memory error in init_part_suma0_statelists(). Aborting...\n");
                exit(4);
            }
            clear_bitarray24(part_sum_a0_bitarrays[odd_even][part_sum_a0]);
        }
    }
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        //PrintAndLogEx(INFO, "(%d, %" PRIu16 ")...", odd_even, part_sum_a0);
        for (uint32_t state = 0; state < (1 << 20); state++) {
            uint16_t part_sum_a0 = PartialSumProperty(state, odd_even) / 2;
            for (uint16_t low_bits = 0; low_bits < 1 << 4; low_bits++) {
                set_bit24(part_sum_a0_bitarrays[odd_even][part_sum_a0], state << 4 | low_bits);
            }
        }
    }

    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        for (uint16_t part_sum_a8 = 0; part_sum_a8 < NUM_PART_SUMS; part_sum_a8++) {
            part_sum_a8_bitarrays[odd_even][part_sum_a8] = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
            if (part_sum_a8_bitarrays[odd_even][part_sum_a8] == NULL) {
                PrintAndLogEx(ERR, "Out of memory error in init_part_suma8_statelists(). Aborting...\n");
                exit(4);
            }
            clear_bitarray24(part_sum_a8_bitarrays[odd_even][part_sum_a8]);
        }
    }
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        //PrintAndLogEx(INFO, "(%d, %" PRIu16 ")...", odd_even, part_sum_a8);
        for (uint32_t state = 0; state < (1 << 20); state++) {
            uint16_t part_sum_a8 = PartialSumProperty(state, odd_even) / 2;
            for (uint16_t high_bits = 0; high_bits < 1 << 4; high_bits++) {
                set_bit24(part_sum_a8_bitarrays[odd_even][part_sum_a8], state | high_bits << 20);
            }
        }
    }
}

static void free_part_sum_bitarrays(void) {
    for (int16_t part_sum_a8 = (NUM_PART_SUMS - 1); part_sum_a8 >= 0; part_sum_a8--) {
        free_bitarray(part_sum_a8_bitarrays[ODD_STATE][part_sum_a8]);
    }
    for (int16_t part_sum_a8 = (NUM_PART_SUMS - 1); part_sum_a8 >= 0; part_sum_a8--) {
        free_bitarray(part_sum_a8_bitarrays[EVEN_STATE][part_sum_a8]);
    }
    for (int16_t part_sum_a0 = (NUM_PART_SUMS - 1); part_sum_a0 >= 0; part_sum_a0--) {
        free_bitarray(part_sum_a0_bitarrays[ODD_STATE][part_sum_a0]);
    }
    for (int16_t part_sum_a0 = (NUM_PART_SUMS - 1); part_sum_a0 >= 0; part_sum_a0--) {
        free_bitarray(part_sum_a0_bitarrays[EVEN_STATE][part_sum_a0]);
    }
}

static void init_sum_bitarrays(void) {
    for (uint16_t sum_a0 = 0; sum_a0 < NUM_SUMS; sum_a0++) {
        for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
            sum_a0_bitarrays[odd_even][sum_a0] = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
            if (sum_a0_bitarrays[odd_even][sum_a0] == NULL) {
                PrintAndLogEx(ERR, "Out of memory error in init_sum_bitarrays(). Aborting...\n");
                exit(4);
            }
            clear_bitarray24(sum_a0_bitarrays[odd_even][sum_a0]);
        }
    }
    for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
        for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
            uint16_t sum_a0 = 2 * p * (16 - 2 * q) + (16 - 2 * p) * 2 * q;
            uint16_t sum_a0_idx = 0;
            while (sums[sum_a0_idx] != sum_a0) sum_a0_idx++;
            bitarray_OR(sum_a0_bitarrays[EVEN_STATE][sum_a0_idx], part_sum_a0_bitarrays[EVEN_STATE][q]);
            bitarray_OR(sum_a0_bitarrays[ODD_STATE][sum_a0_idx], part_sum_a0_bitarrays[ODD_STATE][p]);
        }
    }

}

static void free_sum_bitarrays(void) {
    for (int8_t sum_a0 = NUM_SUMS - 1; sum_a0 >= 0; sum_a0--) {
        free_bitarray(sum_a0_bitarrays[ODD_STATE][sum_a0]);
        free_bitarray(sum_a0_bitarrays[EVEN_STATE][sum_a0]);
    }
}

#ifdef DEBUG_KEY_ELIMINATION
static char failstr[250] = "";
#endif

// the probability that a random nonce has a Sum Property K
static const float p_K0[NUM_SUMS] = {
    0.0290, 0.0083, 0.0006, 0.0339, 0.0048, 0.0934, 0.0119, 0.0489,
    0.0602, 0.4180, 0.0602, 0.0489, 0.0119, 0.0934, 0.0048, 0.0339,
    0.0006, 0.0083, 0.0290
};
static float my_p_K[NUM_SUMS];
static const float *p_K;

static uint32_t cuid;
static noncelist_t nonces[256];
static uint8_t best_first_bytes[256];
static uint64_t maximum_states = 0;
static uint8_t best_first_byte_smallest_bitarray = 0;
static uint16_t first_byte_Sum = 0;
static uint16_t first_byte_num = 0;
static bool write_stats = false;
static FILE *fstats = NULL;
static uint32_t *all_bitflips_bitarray[2];
static uint32_t num_all_bitflips_bitarray[2];
static bool all_bitflips_bitarray_dirty[2];
static uint64_t last_sample_clock = 0;
static uint64_t sample_period = 0;
static uint64_t num_keys_tested = 0;
static statelist_t *candidates = NULL;

static int add_nonce(uint32_t nonce_enc, uint8_t par_enc) {
    uint8_t first_byte = nonce_enc >> 24;
    noncelistentry_t *p1 = nonces[first_byte].first;
    noncelistentry_t *p2 = NULL;

    if (p1 == NULL) { // first nonce with this 1st byte
        first_byte_num++;
        first_byte_Sum += evenparity32((nonce_enc & 0xff000000) | (par_enc & 0x08));
    }

    while (p1 != NULL && (p1->nonce_enc & 0x00ff0000) < (nonce_enc & 0x00ff0000)) {
        p2 = p1;
        p1 = p1->next;
    }

    if (p1 == NULL) {                                                          // need to add at the end of the list
        if (p2 == NULL) {           // list is empty yet. Add first entry.
            p2 = nonces[first_byte].first = calloc(1, sizeof(noncelistentry_t));
        } else {                    // add new entry at end of existing list.
            p2 = p2->next = calloc(1, sizeof(noncelistentry_t));
        }
    } else if ((p1->nonce_enc & 0x00ff0000) != (nonce_enc & 0x00ff0000)) {     // found distinct 2nd byte. Need to insert.
        if (p2 == NULL) {           // need to insert at start of list
            p2 = nonces[first_byte].first = calloc(1, sizeof(noncelistentry_t));
        } else {
            p2 = p2->next = calloc(1, sizeof(noncelistentry_t));
        }
    } else {                                                                   // we have seen this 2nd byte before. Nothing to add or insert.
        return (0);
    }

    // add or insert new data
    p2->next = p1;
    p2->nonce_enc = nonce_enc;
    p2->par_enc = par_enc;

    nonces[first_byte].num++;
    nonces[first_byte].Sum += evenparity32((nonce_enc & 0x00ff0000) | (par_enc & 0x04));
    nonces[first_byte].sum_a8_guess_dirty = true;   // indicates that we need to recalculate the Sum(a8) probability for this first byte
    return (1); // new nonce added
}

static void init_nonce_memory(void) {
    for (uint16_t i = 0; i < 256; i++) {
        nonces[i].num = 0;
        nonces[i].Sum = 0;
        nonces[i].first = NULL;
        for (uint8_t j = 0; j < NUM_SUMS; j++) {
            nonces[i].sum_a8_guess[j].sum_a8_idx = j;
            nonces[i].sum_a8_guess[j].prob = 0.0;
        }
        nonces[i].sum_a8_guess_dirty = false;
        for (uint16_t bitflip = 0x000; bitflip < 0x400; bitflip++) {
            nonces[i].BitFlips[bitflip] = 0;
        }
        nonces[i].states_bitarray[EVEN_STATE] = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
        if (nonces[i].states_bitarray[EVEN_STATE] == NULL) {
            PrintAndLogEx(ERR, "Out of memory error in init_nonce_memory(). Aborting...\n");
            exit(4);
        }
        set_bitarray24(nonces[i].states_bitarray[EVEN_STATE]);
        nonces[i].num_states_bitarray[EVEN_STATE] = 1 << 24;
        nonces[i].states_bitarray[ODD_STATE] = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
        if (nonces[i].states_bitarray[ODD_STATE] == NULL) {
            PrintAndLogEx(ERR, "Out of memory error in init_nonce_memory(). Aborting...\n");
            exit(4);
        }
        set_bitarray24(nonces[i].states_bitarray[ODD_STATE]);
        nonces[i].num_states_bitarray[ODD_STATE] = 1 << 24;
        nonces[i].all_bitflips_dirty[EVEN_STATE] = false;
        nonces[i].all_bitflips_dirty[ODD_STATE] = false;
    }
    first_byte_num = 0;
    first_byte_Sum = 0;
}

static void free_nonce_list(noncelistentry_t *p) {
    if (p == NULL) {
        return;
    } else {
        free_nonce_list(p->next);
        free(p);
    }
}

static void free_nonces_memory(void) {
    for (uint16_t i = 0; i < 256; i++) {
        free_nonce_list(nonces[i].first);
    }
    for (int i = 255; i >= 0; i--) {
        free_bitarray(nonces[i].states_bitarray[ODD_STATE]);
        free_bitarray(nonces[i].states_bitarray[EVEN_STATE]);
    }
}

static double p_hypergeometric(uint16_t i_K, uint16_t n, uint16_t k) {
    // for efficient computation we are using the recursive definition
    //                      (K-k+1) * (n-k+1)
    // P(X=k) = P(X=k-1) * --------------------
    //                         k * (N-K-n+k)
    // and
    //           (N-K)*(N-K-1)*...*(N-K-n+1)
    // P(X=0) = -----------------------------
    //               N*(N-1)*...*(N-n+1)

    uint16_t const N = 256;
    uint16_t K = sums[i_K];

    // avoids log(x<=0) in calculation below
    if (n - k > N - K || k > K) {
        return 0.0;
    }

    if (k == 0) {
        // use logarithms to avoid overflow with huge factorials (double type can only hold 170!)
        double log_result = 0.0;
        for (int16_t i = N - K; i >= N - K - n + 1; i--) {
            log_result += log(i);
        }
        for (int16_t i = N; i >= N - n + 1; i--) {
            log_result -= log(i);
        }
        return exp(log_result);
    } else {
        if (n - k == N - K) { // special case. The published recursion below would fail with a divide by zero exception
            double log_result = 0.0;
            for (int16_t i = k + 1; i <= n; i++) {
                if (i) {
                    log_result += log(i);
                }
            }
            for (int16_t i = K + 1; i <= N; i++) {
                if (i) {
                    log_result -= log(i);
                }
            }
            return exp(log_result);
        } else {          // recursion
            return (p_hypergeometric(i_K, n, k - 1) * (K - k + 1) * (n - k + 1) / (k * (N - K - n + k)));
        }
    }
}

static float sum_probability(uint16_t i_K, uint16_t n, uint16_t k) {
    if (k > sums[i_K]) {
        return 0.0;
    }

    double p_T_is_k_when_S_is_K = p_hypergeometric(i_K, n, k);
    double p_S_is_K = p_K[i_K];
    double p_T_is_k = 0;
    for (uint8_t i = 0; i < NUM_SUMS; i++) {
        p_T_is_k += p_K[i] * p_hypergeometric(i, n, k);
    }
    return (p_T_is_k_when_S_is_K * p_S_is_K / p_T_is_k);
}

static uint32_t part_sum_count[2][NUM_PART_SUMS][NUM_PART_SUMS];

static void init_allbitflips_array(void) {
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t *bitset = all_bitflips_bitarray[odd_even] = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * (1 << 19));
        if (bitset == NULL) {
            PrintAndLogEx(WARNING, "Out of memory in init_allbitflips_array(). Aborting...");
            exit(4);
        }
        set_bitarray24(bitset);
        all_bitflips_bitarray_dirty[odd_even] = false;
        num_all_bitflips_bitarray[odd_even] = 1 << 24;
    }
}

static void update_allbitflips_array(void) {
    if (hardnested_stage & CHECK_2ND_BYTES) {
        for (uint16_t i = 0; i < 256; i++) {
            for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
                if (nonces[i].all_bitflips_dirty[odd_even]) {
                    uint32_t old_count = num_all_bitflips_bitarray[odd_even];
                    num_all_bitflips_bitarray[odd_even] = count_bitarray_low20_AND(all_bitflips_bitarray[odd_even], nonces[i].states_bitarray[odd_even]);
                    nonces[i].all_bitflips_dirty[odd_even] = false;
                    if (num_all_bitflips_bitarray[odd_even] != old_count) {
                        all_bitflips_bitarray_dirty[odd_even] = true;
                    }
                }
            }
        }
    }
}

static uint32_t estimated_num_states_part_sum_coarse(uint16_t part_sum_a0_idx, uint16_t part_sum_a8_idx, odd_even_t odd_even) {
    return part_sum_count[odd_even][part_sum_a0_idx][part_sum_a8_idx];
}

static uint32_t estimated_num_states_part_sum(uint8_t first_byte, uint16_t part_sum_a0_idx, uint16_t part_sum_a8_idx, odd_even_t odd_even) {
    if (odd_even == ODD_STATE) {
        return count_bitarray_AND3(part_sum_a0_bitarrays[odd_even][part_sum_a0_idx],
                                   part_sum_a8_bitarrays[odd_even][part_sum_a8_idx],
                                   nonces[first_byte].states_bitarray[odd_even]);
    } else {
        return count_bitarray_AND4(part_sum_a0_bitarrays[odd_even][part_sum_a0_idx],
                                   part_sum_a8_bitarrays[odd_even][part_sum_a8_idx],
                                   nonces[first_byte].states_bitarray[odd_even],
                                   nonces[first_byte ^ 0x80].states_bitarray[odd_even]);
    }

    // estimate reduction by all_bitflips_match()
    // if (odd_even) {
    // float p_bitflip = (float)nonces[first_byte ^ 0x80].num_states_bitarray[ODD_STATE] / num_all_bitflips_bitarray[ODD_STATE];
    // return (float)count * p_bitflip; //(p_bitflip - 0.25*p_bitflip*p_bitflip);
    // } else {
    // return count;
    // }
}

static uint64_t estimated_num_states(uint8_t first_byte, uint16_t sum_a0, uint16_t sum_a8) {
    uint64_t num_states = 0;
    for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
        for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
            if (2 * p * (16 - 2 * q) + (16 - 2 * p) * 2 * q == sum_a0) {
                for (uint8_t r = 0; r < NUM_PART_SUMS; r++) {
                    for (uint8_t s = 0; s < NUM_PART_SUMS; s++) {
                        if (2 * r * (16 - 2 * s) + (16 - 2 * r) * 2 * s == sum_a8) {
                            num_states += (uint64_t)estimated_num_states_part_sum(first_byte, p, r, ODD_STATE)
                                          * estimated_num_states_part_sum(first_byte, q, s, EVEN_STATE);
                        }
                    }
                }
            }
        }
    }
    return num_states;
}

static uint64_t estimated_num_states_coarse(uint16_t sum_a0, uint16_t sum_a8) {
    uint64_t num_states = 0;
    for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
        for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
            if (2 * p * (16 - 2 * q) + (16 - 2 * p) * 2 * q == sum_a0) {
                for (uint8_t r = 0; r < NUM_PART_SUMS; r++) {
                    for (uint8_t s = 0; s < NUM_PART_SUMS; s++) {
                        if (2 * r * (16 - 2 * s) + (16 - 2 * r) * 2 * s == sum_a8) {
                            num_states += (uint64_t)estimated_num_states_part_sum_coarse(p, r, ODD_STATE)
                                          * estimated_num_states_part_sum_coarse(q, s, EVEN_STATE);
                        }
                    }
                }
            }
        }
    }
    return num_states;
}

static void update_p_K(void) {
    if (hardnested_stage & CHECK_2ND_BYTES) {
        uint64_t total_count = 0;
        uint16_t sum_a0 = sums[first_byte_Sum];
        for (uint8_t sum_a8_idx = 0; sum_a8_idx < NUM_SUMS; sum_a8_idx++) {
            uint16_t sum_a8 = sums[sum_a8_idx];
            total_count += estimated_num_states_coarse(sum_a0, sum_a8);
        }
        for (uint8_t sum_a8_idx = 0; sum_a8_idx < NUM_SUMS; sum_a8_idx++) {
            uint16_t sum_a8 = sums[sum_a8_idx];
            float f = estimated_num_states_coarse(sum_a0, sum_a8);
            my_p_K[sum_a8_idx] = f / total_count;
        }
        // PrintAndLogEx(INFO,  "my_p_K = [");
        // for (uint8_t sum_a8_idx = 0; sum_a8_idx < NUM_SUMS; sum_a8_idx++) {
        // PrintAndLogEx(INFO, "%7.4f ", my_p_K[sum_a8_idx]);
        // }
        p_K = my_p_K;
    }
}

static void update_sum_bitarrays(odd_even_t odd_even) {
    if (all_bitflips_bitarray_dirty[odd_even]) {
        for (uint8_t part_sum = 0; part_sum < NUM_PART_SUMS; part_sum++) {
            bitarray_AND(part_sum_a0_bitarrays[odd_even][part_sum], all_bitflips_bitarray[odd_even]);
            bitarray_AND(part_sum_a8_bitarrays[odd_even][part_sum], all_bitflips_bitarray[odd_even]);
        }
        for (uint16_t i = 0; i < 256; i++) {
            nonces[i].num_states_bitarray[odd_even] = count_bitarray_AND(nonces[i].states_bitarray[odd_even], all_bitflips_bitarray[odd_even]);
        }
        for (uint8_t part_sum_a0 = 0; part_sum_a0 < NUM_PART_SUMS; part_sum_a0++) {
            for (uint8_t part_sum_a8 = 0; part_sum_a8 < NUM_PART_SUMS; part_sum_a8++) {
                part_sum_count[odd_even][part_sum_a0][part_sum_a8]
                += count_bitarray_AND2(part_sum_a0_bitarrays[odd_even][part_sum_a0], part_sum_a8_bitarrays[odd_even][part_sum_a8]);
            }
        }
        all_bitflips_bitarray_dirty[odd_even] = false;
    }
}

static int compare_expected_num_brute_force(const void *b1, const void *b2) {
    uint8_t index1 = *(uint8_t *)b1;
    uint8_t index2 = *(uint8_t *)b2;
    float score1 = nonces[index1].expected_num_brute_force;
    float score2 = nonces[index2].expected_num_brute_force;
    return (score1 > score2) - (score1 < score2);
}

static int compare_sum_a8_guess(const void *b1, const void *b2) {
    float prob1 = ((guess_sum_a8_t *)b1)->prob;
    float prob2 = ((guess_sum_a8_t *)b2)->prob;
    return (prob1 < prob2) - (prob1 > prob2);

}

static float check_smallest_bitflip_bitarrays(void) {
    uint64_t smallest = 1LL << 48;
    // initialize best_first_bytes, do a rough estimation on remaining states
    for (uint16_t i = 0; i < 256; i++) {
        uint32_t num_odd = nonces[i].num_states_bitarray[ODD_STATE];
        uint32_t num_even = nonces[i].num_states_bitarray[EVEN_STATE]; // * (float)nonces[i^0x80].num_states_bitarray[EVEN_STATE] / num_all_bitflips_bitarray[EVEN_STATE];
        if ((uint64_t)num_odd * num_even < smallest) {
            smallest = (uint64_t)num_odd * num_even;
            best_first_byte_smallest_bitarray = i;
        }
    }

#if defined (DEBUG_REDUCTION)
    uint32_t num_odd = nonces[best_first_byte_smallest_bitarray].num_states_bitarray[ODD_STATE];
    uint32_t num_even = nonces[best_first_byte_smallest_bitarray].num_states_bitarray[EVEN_STATE]; // * (float)nonces[best_first_byte_smallest_bitarray^0x80].num_states_bitarray[EVEN_STATE] / num_all_bitflips_bitarray[EVEN_STATE];
    PrintAndLogEx(INFO, "0x%02x: %8d * %8d = %12" PRIu64 " (2^%1.1f)\n", best_first_byte_smallest_bitarray, num_odd, num_even, (uint64_t)num_odd * num_even, log((uint64_t)num_odd * num_even) / log(2.0));
#endif
    return (float)smallest / 2.0;
}

static void update_expected_brute_force(uint8_t best_byte) {

    float total_prob = 0.0;
    for (uint8_t i = 0; i < NUM_SUMS; i++) {
        total_prob += nonces[best_byte].sum_a8_guess[i].prob;
    }
    // linear adjust probabilities to result in total_prob = 1.0;
    for (uint8_t i = 0; i < NUM_SUMS; i++) {
        nonces[best_byte].sum_a8_guess[i].prob /= total_prob;
    }
    float prob_all_failed = 1.0;
    nonces[best_byte].expected_num_brute_force = 0.0;
    for (uint8_t i = 0; i < NUM_SUMS; i++) {
        nonces[best_byte].expected_num_brute_force += nonces[best_byte].sum_a8_guess[i].prob * (float)nonces[best_byte].sum_a8_guess[i].num_states / 2.0;
        prob_all_failed -= nonces[best_byte].sum_a8_guess[i].prob;
        nonces[best_byte].expected_num_brute_force += prob_all_failed * (float)nonces[best_byte].sum_a8_guess[i].num_states / 2.0;
    }
    return;
}

static float sort_best_first_bytes(void) {

    // initialize best_first_bytes, do a rough estimation on remaining states for each Sum_a8 property
    // and the expected number of states to brute force
    for (uint16_t i = 0; i < 256; i++) {
        best_first_bytes[i] = i;
        float prob_all_failed = 1.0;
        nonces[i].expected_num_brute_force = 0.0;
        for (uint8_t j = 0; j < NUM_SUMS; j++) {
            nonces[i].sum_a8_guess[j].num_states = estimated_num_states_coarse(sums[first_byte_Sum], sums[nonces[i].sum_a8_guess[j].sum_a8_idx]);
            nonces[i].expected_num_brute_force += nonces[i].sum_a8_guess[j].prob * (float)nonces[i].sum_a8_guess[j].num_states / 2.0;
            prob_all_failed -= nonces[i].sum_a8_guess[j].prob;
            nonces[i].expected_num_brute_force += prob_all_failed * (float)nonces[i].sum_a8_guess[j].num_states / 2.0;
        }
    }

    // sort based on expected number of states to brute force
    qsort(best_first_bytes, 256, 1, compare_expected_num_brute_force);

    // PrintAndLogEx(INFO, "refine estimations: ");
#define NUM_REFINES 1
    // refine scores for the best:
    for (uint16_t i = 0; i < NUM_REFINES; i++) {
        // PrintAndLogEx(INFO, "%d...", i);
        uint16_t first_byte = best_first_bytes[i];
        for (uint8_t j = 0; j < NUM_SUMS && nonces[first_byte].sum_a8_guess[j].prob > 0.05; j++) {
            nonces[first_byte].sum_a8_guess[j].num_states = estimated_num_states(first_byte, sums[first_byte_Sum], sums[nonces[first_byte].sum_a8_guess[j].sum_a8_idx]);
        }
        // while (nonces[first_byte].sum_a8_guess[0].num_states == 0
        // || nonces[first_byte].sum_a8_guess[1].num_states == 0
        // || nonces[first_byte].sum_a8_guess[2].num_states == 0) {
        // if (nonces[first_byte].sum_a8_guess[0].num_states == 0) {
        // nonces[first_byte].sum_a8_guess[0].prob = 0.0;
        // PrintAndLogEx(INFO, "(0x%02x,%d)", first_byte, 0);
        // }
        // if (nonces[first_byte].sum_a8_guess[1].num_states == 0) {
        // nonces[first_byte].sum_a8_guess[1].prob = 0.0;
        // PrintAndLogEx(INFO, "(0x%02x,%d)", first_byte, 1);
        // }
        // if (nonces[first_byte].sum_a8_guess[2].num_states == 0) {
        // nonces[first_byte].sum_a8_guess[2].prob = 0.0;
        // PrintAndLogEx(INFO, "(0x%02x,%d)", first_byte, 2);
        // }
        // PrintAndLogEx(INFO, "|");
        // qsort(nonces[first_byte].sum_a8_guess, NUM_SUMS, sizeof(guess_sum_a8_t), compare_sum_a8_guess);
        // for (uint8_t j = 0; j < NUM_SUMS && nonces[first_byte].sum_a8_guess[j].prob > 0.05; j++) {
        // nonces[first_byte].sum_a8_guess[j].num_states = estimated_num_states(first_byte, sums[first_byte_Sum], sums[nonces[first_byte].sum_a8_guess[j].sum_a8_idx]);
        // }
        // }
        // float fix_probs = 0.0;
        // for (uint8_t j = 0; j < NUM_SUMS; j++) {
        // fix_probs += nonces[first_byte].sum_a8_guess[j].prob;
        // }
        // for (uint8_t j = 0; j < NUM_SUMS; j++) {
        // nonces[first_byte].sum_a8_guess[j].prob /= fix_probs;
        // }
        // for (uint8_t j = 0; j < NUM_SUMS && nonces[first_byte].sum_a8_guess[j].prob > 0.05; j++) {
        // nonces[first_byte].sum_a8_guess[j].num_states = estimated_num_states(first_byte, sums[first_byte_Sum], sums[nonces[first_byte].sum_a8_guess[j].sum_a8_idx]);
        // }
        float prob_all_failed = 1.0;
        nonces[first_byte].expected_num_brute_force = 0.0;
        for (uint8_t j = 0; j < NUM_SUMS; j++) {
            nonces[first_byte].expected_num_brute_force += nonces[first_byte].sum_a8_guess[j].prob * (float)nonces[first_byte].sum_a8_guess[j].num_states / 2.0;
            prob_all_failed -= nonces[first_byte].sum_a8_guess[j].prob;
            nonces[first_byte].expected_num_brute_force += prob_all_failed * (float)nonces[first_byte].sum_a8_guess[j].num_states / 2.0;
        }
    }

    // copy best byte to front:
    float least_expected_brute_force = (1LL << 48);
    uint8_t best_byte = 0;
    for (uint16_t i = 0; i < 10; i++) {
        uint16_t first_byte = best_first_bytes[i];
        if (nonces[first_byte].expected_num_brute_force < least_expected_brute_force) {
            least_expected_brute_force = nonces[first_byte].expected_num_brute_force;
            best_byte = i;
        }
    }
    if (best_byte != 0) {
        // PrintAndLogEx(INFO, "0x%02x <-> 0x%02x", best_first_bytes[0], best_first_bytes[best_byte]);
        uint8_t tmp = best_first_bytes[0];
        best_first_bytes[0] = best_first_bytes[best_byte];
        best_first_bytes[best_byte] = tmp;
    }

    return nonces[best_first_bytes[0]].expected_num_brute_force;
}

static float update_reduction_rate(float last, bool init) {
#define QUEUE_LEN 4
    static float queue[QUEUE_LEN];

    for (uint16_t i = 0; i < QUEUE_LEN - 1; i++) {
        if (init) {
            queue[i] = (float)(1LL << 48);
        } else {
            queue[i] = queue[i + 1];
        }
    }
    if (init) {
        queue[QUEUE_LEN - 1] = (float)(1LL << 48);
    } else {
        queue[QUEUE_LEN - 1] = last;
    }

    // linear regression
    float avg_y = 0.0;
    float avg_x = 0.0;
    for (uint16_t i = 0; i < QUEUE_LEN; i++) {
        avg_x += i;
        avg_y += queue[i];
    }
    avg_x /= QUEUE_LEN;
    avg_y /= QUEUE_LEN;

    float dev_xy = 0.0;
    float dev_x2 = 0.0;
    for (uint16_t i = 0; i < QUEUE_LEN; i++) {
        dev_xy += (i - avg_x) * (queue[i] - avg_y);
        dev_x2 += (i - avg_x) * (i - avg_x);
    }

    float reduction_rate = -1.0 * dev_xy / dev_x2;  // the negative slope of the linear regression

#if defined (DEBUG_REDUCTION)
    PrintAndLogEx(INFO, "update_reduction_rate(%1.0f) = %1.0f per sample, brute_force_per_sample = %1.0f\n", last, reduction_rate, brute_force_per_second * (float)sample_period / 1000.0);
#endif
    return reduction_rate;
}

static bool shrink_key_space(float *brute_forces) {
#if defined(DEBUG_REDUCTION)
    PrintAndLogEx(INFO, "shrink_key_space() with stage = 0x%02x\n", hardnested_stage);
#endif
    float brute_forces1 = check_smallest_bitflip_bitarrays();
    float brute_forces2 = (float)(1LL << 47);
    if (hardnested_stage & CHECK_2ND_BYTES) {
        brute_forces2 = sort_best_first_bytes();
    }
    *brute_forces = MIN(brute_forces1, brute_forces2);
    float reduction_rate = update_reduction_rate(*brute_forces, false);

//iceman 2018
    return ((hardnested_stage & CHECK_2ND_BYTES) &&
            reduction_rate >= 0.0 &&
            (reduction_rate < brute_force_per_second * (float)sample_period / 1000.0  || *brute_forces < 0xF00000));

}

static void estimate_sum_a8(void) {
    if (first_byte_num == 256) {
        for (uint16_t i = 0; i < 256; i++) {
            if (nonces[i].sum_a8_guess_dirty) {
                for (uint8_t j = 0; j < NUM_SUMS; j++) {
                    uint16_t sum_a8_idx = nonces[i].sum_a8_guess[j].sum_a8_idx;
                    nonces[i].sum_a8_guess[j].prob = sum_probability(sum_a8_idx, nonces[i].num, nonces[i].Sum);
                }
                qsort(nonces[i].sum_a8_guess, NUM_SUMS, sizeof(guess_sum_a8_t), compare_sum_a8_guess);
                nonces[i].sum_a8_guess_dirty = false;
            }
        }
    }
}

static int read_nonce_file(char *filename) {

    if (filename == NULL) {
        PrintAndLogEx(WARNING, "Filename is NULL");
        return PM3_EINVARG;
    }
    FILE *fnonces = NULL;
    char progress_text[80] = "";
    uint8_t read_buf[9];

    num_acquired_nonces = 0;
    if ((fnonces = fopen(filename, "rb")) == NULL) {
        PrintAndLogEx(WARNING, "Could not open file " _YELLOW_("%s"), filename);
        return PM3_EFILE;
    }

    snprintf(progress_text, 80, "Reading nonces from file " _YELLOW_("%s"), filename);
    hardnested_print_progress(0, progress_text, (float)(1LL << 47), 0);
    size_t bytes_read = fread(read_buf, 1, 6, fnonces);
    if (bytes_read != 6) {
        PrintAndLogEx(ERR, "File reading error.");
        fclose(fnonces);
        return PM3_EFILE;
    }
    cuid = bytes_to_num(read_buf, 4);
    uint8_t trgBlockNo = bytes_to_num(read_buf + 4, 1);
    uint8_t trgKeyType = bytes_to_num(read_buf + 5, 1);

    bytes_read = fread(read_buf, 1, 9, fnonces);
    while (bytes_read == 9) {
        uint32_t nt_enc1 = bytes_to_num(read_buf, 4);
        uint32_t nt_enc2 = bytes_to_num(read_buf + 4, 4);
        uint8_t par_enc = bytes_to_num(read_buf + 8, 1);
        add_nonce(nt_enc1, par_enc >> 4);
        add_nonce(nt_enc2, par_enc & 0x0f);
        num_acquired_nonces += 2;
        bytes_read = fread(read_buf, 1, 9, fnonces);
    }
    fclose(fnonces);

    char progress_string[80];
    snprintf(progress_string, sizeof(progress_string), "Read %u nonces from file. cuid = %08x", num_acquired_nonces, cuid);
    hardnested_print_progress(num_acquired_nonces, progress_string, (float)(1LL << 47), 0);
    snprintf(progress_string, sizeof(progress_string), "Target Block=%d, Keytype=%c", trgBlockNo, trgKeyType == 0 ? 'A' : 'B');
    hardnested_print_progress(num_acquired_nonces, progress_string, (float)(1LL << 47), 0);

    bool got_match = false;
    for (uint8_t i = 0; i < NUM_SUMS; i++) {
        if (first_byte_Sum == sums[i]) {
            first_byte_Sum = i;
            got_match = true;
            break;
        }
    }
    if (got_match == false) {
        PrintAndLogEx(FAILED, "No match for the First_Byte_Sum (%u), is the card a genuine MFC Ev1? ", first_byte_Sum);
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static noncelistentry_t *SearchFor2ndByte(uint8_t b1, uint8_t b2) {
    noncelistentry_t *p = nonces[b1].first;
    while (p != NULL) {
        if ((p->nonce_enc >> 16 & 0xff) == b2) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

static bool timeout(void) {
    return (msclock() > last_sample_clock + sample_period);
}


static void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
*check_for_BitFlipProperties_thread(void *args) {
    uint8_t first_byte = ((uint8_t *)args)[0];
    uint8_t last_byte = ((uint8_t *)args)[1];
    uint8_t time_budget = ((uint8_t *)args)[2];

    if (hardnested_stage & CHECK_1ST_BYTES) {
        // for (uint16_t bitflip = 0x001; bitflip < 0x200; bitflip++) {
        for (uint16_t bitflip_idx = 0; bitflip_idx < num_1st_byte_effective_bitflips; bitflip_idx++) {
            uint16_t bitflip = all_effective_bitflip[bitflip_idx];
            if (time_budget && timeout()) {
#if defined (DEBUG_REDUCTION)
                PrintAndLogEx(INFO, "break at bitflip_idx " _YELLOW_("%d") " ...", bitflip_idx);
#endif
                return NULL;
            }
            for (uint16_t i = first_byte; i <= last_byte; i++) {

                if (nonces[i].BitFlips[bitflip] == 0 && nonces[i].BitFlips[bitflip ^ 0x100] == 0
                        && nonces[i].first != NULL && nonces[i ^ (bitflip & 0xff)].first != NULL) {

                    uint8_t parity1 = (nonces[i].first->par_enc) >> 3;                  // parity of first byte
                    uint8_t parity2 = (nonces[i ^ (bitflip & 0xff)].first->par_enc) >> 3; // parity of nonce with bits flipped

                    if ((parity1 == parity2 && !(bitflip & 0x100))          // bitflip
                            || (parity1 != parity2 && (bitflip & 0x100))) {     // not bitflip

                        nonces[i].BitFlips[bitflip] = 1;

                        for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {

                            if (bitflip_bitarrays[odd_even][bitflip] != NULL) {
                                uint32_t old_count = nonces[i].num_states_bitarray[odd_even];
                                nonces[i].num_states_bitarray[odd_even] = count_bitarray_AND(nonces[i].states_bitarray[odd_even], bitflip_bitarrays[odd_even][bitflip]);
                                if (nonces[i].num_states_bitarray[odd_even] != old_count) {
                                    nonces[i].all_bitflips_dirty[odd_even] = true;
                                }
                                // PrintAndLogEx(INFO, "bitflip: %d old: %d, new: %d ", bitflip, old_count, nonces[i].num_states_bitarray[odd_even]);
                            }
                        }
                    }
                }
            }
            ((uint8_t *)args)[1] = num_1st_byte_effective_bitflips - bitflip_idx - 1;  // bitflips still to go in stage 1
        }
    }

    ((uint8_t *)args)[1] = 0;  // stage 1 definitely completed

    if (hardnested_stage & CHECK_2ND_BYTES) {
        for (uint16_t bitflip_idx = num_1st_byte_effective_bitflips; bitflip_idx < num_all_effective_bitflips; bitflip_idx++) {
            uint16_t bitflip = all_effective_bitflip[bitflip_idx];
            if (time_budget && timeout()) {
#if defined (DEBUG_REDUCTION)
                PrintAndLogEx(INFO, "break at bitflip_idx " _YELLOW_("%d") " ...", bitflip_idx);
#endif
                return NULL;
            }
            for (uint16_t i = first_byte; i <= last_byte; i++) {
                // Check for Bit Flip Property of 2nd bytes
                if (nonces[i].BitFlips[bitflip] == 0) {
                    for (uint16_t j = 0; j < 256; j++) { // for each 2nd Byte
                        noncelistentry_t *byte1 = SearchFor2ndByte(i, j);
                        noncelistentry_t *byte2 = SearchFor2ndByte(i, j ^ (bitflip & 0xff));
                        if (byte1 != NULL && byte2 != NULL) {
                            uint8_t parity1 = byte1->par_enc >> 2 & 0x01; // parity of 2nd byte
                            uint8_t parity2 = byte2->par_enc >> 2 & 0x01; // parity of 2nd byte with bits flipped
                            if ((parity1 == parity2 && !(bitflip & 0x100)) // bitflip
                                    || (parity1 != parity2 && (bitflip & 0x100))) { // not bitflip
                                nonces[i].BitFlips[bitflip] = 1;
                                for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
                                    if (bitflip_bitarrays[odd_even][bitflip] != NULL) {
                                        uint32_t old_count = nonces[i].num_states_bitarray[odd_even];
                                        nonces[i].num_states_bitarray[odd_even] = count_bitarray_AND(nonces[i].states_bitarray[odd_even], bitflip_bitarrays[odd_even][bitflip]);
                                        if (nonces[i].num_states_bitarray[odd_even] != old_count) {
                                            nonces[i].all_bitflips_dirty[odd_even] = true;
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                // PrintAndLogEx(INFO, "states_bitarray[0][%" PRIu16 "] contains %d ones.\n", i, count_states(nonces[i].states_bitarray[EVEN_STATE]));
                // PrintAndLogEx(INFO, "states_bitarray[1][%" PRIu16 "] contains %d ones.\n", i, count_states(nonces[i].states_bitarray[ODD_STATE]));
            }
        }
    }

    return NULL;
}

static void check_for_BitFlipProperties(bool time_budget) {
    // create and run worker threads
    const size_t num_check_bitflip_threads = NUM_CHECK_BITFLIPS_THREADS;
    pthread_t thread_id[num_check_bitflip_threads];

    uint8_t args[num_check_bitflip_threads][3];
    uint16_t bytes_per_thread = (256 + (num_check_bitflip_threads / 2)) / num_check_bitflip_threads;
    for (uint32_t i = 0; i < num_check_bitflip_threads; i++) {
        args[i][0] = i * bytes_per_thread;
        args[i][1] = MIN(args[i][0] + bytes_per_thread - 1, 255);
        args[i][2] = time_budget;
    }
    // args[][] is uint8_t so max 255, no need to check it
    // args[num_check_bitflip_threads - 1][1] = MAX(args[num_check_bitflip_threads - 1][1], 255);

    // start threads
    for (uint32_t i = 0; i < num_check_bitflip_threads; i++) {
        pthread_create(&thread_id[i], NULL, check_for_BitFlipProperties_thread, args[i]);
    }

    // wait for threads to terminate:
    for (uint32_t i = 0; i < num_check_bitflip_threads; i++) {
        pthread_join(thread_id[i], NULL);
    }

    if (hardnested_stage & CHECK_2ND_BYTES) {
        hardnested_stage &= ~CHECK_1ST_BYTES; // we are done with 1st stage, except...
        for (uint32_t i = 0; i < num_check_bitflip_threads; i++) {
            if (args[i][1] != 0) {
                hardnested_stage |= CHECK_1ST_BYTES;  // ... when any of the threads didn't complete in time
                break;
            }
        }
    }
#if defined (DEBUG_REDUCTION)
    if (hardnested_stage & CHECK_1ST_BYTES) PrintAndLogEx(INFO, "stage 1 not completed yet\n");
#endif
}

static void update_nonce_data(bool time_budget) {
    check_for_BitFlipProperties(time_budget);
    update_allbitflips_array();
    update_sum_bitarrays(EVEN_STATE);
    update_sum_bitarrays(ODD_STATE);
    update_p_K();
    estimate_sum_a8();
}

static void apply_sum_a0(void) {
    uint32_t old_count = num_all_bitflips_bitarray[EVEN_STATE];
    num_all_bitflips_bitarray[EVEN_STATE] = count_bitarray_AND(all_bitflips_bitarray[EVEN_STATE], sum_a0_bitarrays[EVEN_STATE][first_byte_Sum]);
    if (num_all_bitflips_bitarray[EVEN_STATE] != old_count) {
        all_bitflips_bitarray_dirty[EVEN_STATE] = true;
    }
    old_count = num_all_bitflips_bitarray[ODD_STATE];
    num_all_bitflips_bitarray[ODD_STATE] = count_bitarray_AND(all_bitflips_bitarray[ODD_STATE], sum_a0_bitarrays[ODD_STATE][first_byte_Sum]);
    if (num_all_bitflips_bitarray[ODD_STATE] != old_count) {
        all_bitflips_bitarray_dirty[ODD_STATE] = true;
    }
}

static void simulate_MFplus_RNG(uint32_t test_cuid, uint64_t test_key, uint32_t *nt_enc, uint8_t *par_enc) {

    struct Crypto1State sim_cs = {0, 0};

    // init cryptostate with key:
    for (int8_t i = 47; i > 0; i -= 2) {
        sim_cs.odd  = sim_cs.odd  << 1 | BIT(test_key, (i - 1) ^ 7);
        sim_cs.even = sim_cs.even << 1 | BIT(test_key, i ^ 7);
    }

    *par_enc = 0;
    uint32_t nt = (rand() & 0xff) << 24 | (rand() & 0xff) << 16 | (rand() & 0xff) << 8 | (rand() & 0xff);

    for (int8_t byte_pos = 3; byte_pos >= 0; byte_pos--) {

        uint8_t nt_byte_dec = (nt >> (8 * byte_pos)) & 0xff;

        // encode the nonce byte
        uint8_t nt_byte_enc = crypto1_byte(&sim_cs, nt_byte_dec ^ (test_cuid >> (8 * byte_pos)), false) ^ nt_byte_dec;
        *nt_enc = (*nt_enc << 8) | nt_byte_enc;

        // the keystream bit to encode/decode the parity bit
        uint8_t ks_par = filter(sim_cs.odd);

        // determine the nt byte's parity and encode it
        uint8_t nt_byte_par_enc = ks_par ^ oddparity8(nt_byte_dec);
        *par_enc = (*par_enc << 1) | nt_byte_par_enc;
    }
}

static int simulate_acquire_nonces(void) {
    time_t time1 = time(NULL);
    last_sample_clock = 0;
    sample_period = 1000; // for simulation
    hardnested_stage = CHECK_1ST_BYTES;
    bool acquisition_completed = false;
    uint32_t total_num_nonces = 0;
    float brute_force_depth;
    bool reported_suma8 = false;

    cuid = (rand() & 0xff) << 24 | (rand() & 0xff) << 16 | (rand() & 0xff) << 8 | (rand() & 0xff);
    if (known_target_key == -1) {
        known_target_key = ((uint64_t)rand() & 0xfff) << 36 | ((uint64_t)rand() & 0xfff) << 24 | ((uint64_t)rand() & 0xfff) << 12 | ((uint64_t)rand() & 0xfff);
    }

    char progress_text[80];
    snprintf(progress_text, sizeof(progress_text), "Simulating key %012" PRIx64 ", cuid %08" PRIx32 " ...", known_target_key, cuid);
    hardnested_print_progress(0, progress_text, (float)(1LL << 47), 0);
    fprintf(fstats, "%012" PRIx64 ";%" PRIx32 ";", known_target_key, cuid);

    num_acquired_nonces = 0;

    do {
        uint32_t nt_enc = 0;
        uint8_t par_enc = 0;

        for (uint16_t i = 0; i < 113; i++) {
            simulate_MFplus_RNG(cuid, known_target_key, &nt_enc, &par_enc);
            num_acquired_nonces += add_nonce(nt_enc, par_enc);
            total_num_nonces++;
        }

        last_sample_clock = msclock();

        if (first_byte_num == 256) {
            if (hardnested_stage == CHECK_1ST_BYTES) {

                bool got_match = false;
                for (uint8_t i = 0; i < NUM_SUMS; i++) {
                    if (first_byte_Sum == sums[i]) {
                        first_byte_Sum = i;
                        got_match = true;
                        break;
                    }
                }

                if (got_match == false) {
                    PrintAndLogEx(FAILED, "No match for the First_Byte_Sum (%u), is the card a genuine MFC Ev1? ", first_byte_Sum);
                    return PM3_ESOFT;
                }

                hardnested_stage |= CHECK_2ND_BYTES;
                apply_sum_a0();
            }
            update_nonce_data(true);
            acquisition_completed = shrink_key_space(&brute_force_depth);
            if (!reported_suma8) {
                char progress_string[80];
                snprintf(progress_string, sizeof(progress_string), "Apply Sum property. Sum(a0) = %d", sums[first_byte_Sum]);
                hardnested_print_progress(num_acquired_nonces, progress_string, brute_force_depth, 0);
                reported_suma8 = true;
            } else {
                hardnested_print_progress(num_acquired_nonces, "Apply bit flip properties", brute_force_depth, 0);
            }
        } else {
            update_nonce_data(true);
            acquisition_completed = shrink_key_space(&brute_force_depth);
            hardnested_print_progress(num_acquired_nonces, "Apply bit flip properties", brute_force_depth, 0);
        }
    } while (!acquisition_completed);

    time_t end_time = time(NULL);
    // PrintAndLogEx(INFO, "Acquired a total of %" PRId32" nonces in %1.0f seconds (%1.0f nonces/minute)",
    // num_acquired_nonces,
    // difftime(end_time, time1),
    // difftime(end_time, time1)!=0.0?(float)total_num_nonces*60.0/difftime(end_time, time1):INFINITY
    // );

    fprintf(fstats, "%" PRIu32 ";%" PRIu32 ";%1.0f;", total_num_nonces, num_acquired_nonces, difftime(end_time, time1));
    return PM3_SUCCESS;
}

static int acquire_nonces(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, bool nonce_file_write, bool slow, char *filename) {

    last_sample_clock = msclock();
    hardnested_stage = CHECK_1ST_BYTES;
    num_acquired_nonces = 0;

    // initial rough estimate. Will be refined.
    sample_period = 2000;

    bool initialize = true;
    bool field_off = false;
    bool acquisition_completed = false;
    bool reported_suma8 = false;

    float brute_force_depth;

    FILE *fnonces = NULL;

    // init to ZERO
    PacketResponseNG resp = {
        .cmd = 0,
        .length = 0,
        .magic = 0,
        .status = 0,
        .crc = 0,
        .ng = false,
    };
    resp.oldarg[0] = 0;
    resp.oldarg[1] = 0;
    resp.oldarg[2] = 0;
    memset(resp.data.asBytes, 0, PM3_CMD_DATA_SIZE);

    uint8_t write_buf[9];
    char progress_text[80];

    do {

        if (field_off) {
            DropField();
            break;
        }

        uint32_t flags = 0;
        flags |= initialize ? 0x0001 : 0;
        flags |= slow ? 0x0002 : 0;
        flags |= field_off ? 0x0004 : 0;
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_MIFARE_ACQ_ENCRYPTED_NONCES, blockNo + keyType * 0x100, trgBlockNo + trgKeyType * 0x100, flags, key, 6);

        if (initialize) {

            if (WaitForResponseTimeout(CMD_ACK, &resp, 3000) == false) {
                DropField();
                return PM3_ETIMEOUT;
            }

            // error during nested_hard
            if (resp.oldarg[0]) {
                DropField();
                return resp.oldarg[0];
            }

            cuid = resp.oldarg[1];
            if (nonce_file_write && fnonces == NULL) {

                if ((fnonces = fopen(filename, "wb")) == NULL) {
                    PrintAndLogEx(WARNING, "Could not create file " _YELLOW_("%s"), filename);
                    DropField();
                    return PM3_EFILE;
                }

                snprintf(progress_text, 80, "Writing acquired nonces to binary file " _YELLOW_("%s"), filename);
                hardnested_print_progress(0, progress_text, (float)(1LL << 47), 0);
                num_to_bytes(cuid, 4, write_buf);
                fwrite(write_buf, 1, 4, fnonces);
                fwrite(&trgBlockNo, 1, 1, fnonces);
                fwrite(&trgKeyType, 1, 1, fnonces);
                fflush(fnonces);
            }
        }

        if (initialize == false) {

            uint16_t num_sampled_nonces = resp.oldarg[2];
            uint8_t *bufp = resp.data.asBytes;

            for (uint16_t i = 0; i < num_sampled_nonces; i += 2) {
                uint32_t nt_enc1 = bytes_to_num(bufp, 4);
                uint32_t nt_enc2 = bytes_to_num(bufp + 4, 4);
                uint8_t par_enc = bytes_to_num(bufp + 8, 1);

                //PrintAndLogEx(INFO, "Encrypted nonce: %08x, encrypted_parity: %02x\n", nt_enc1, par_enc >> 4);
                num_acquired_nonces += add_nonce(nt_enc1, par_enc >> 4);
                //PrintAndLogEx(INFO, "Encrypted nonce: %08x, encrypted_parity: %02x\n", nt_enc2, par_enc & 0x0f);
                num_acquired_nonces += add_nonce(nt_enc2, par_enc & 0x0f);

                if (nonce_file_write) {
                    fwrite(bufp, 1, 9, fnonces);
                    fflush(fnonces);
                }
                bufp += 9;
            }
            //total_num_nonces += num_sampled_nonces;

            if (first_byte_num == 256) {
                if (hardnested_stage == CHECK_1ST_BYTES) {
                    bool got_match = false;
                    for (uint8_t i = 0; i < NUM_SUMS; i++) {
                        if (first_byte_Sum == sums[i]) {
                            first_byte_Sum = i;
                            got_match = true;
                            break;
                        }
                    }

                    if (got_match == false) {
                        PrintAndLogEx(FAILED, "No match for the First_Byte_Sum (%u), is the card a genuine MFC Ev1? ", first_byte_Sum);
                        if (nonce_file_write) {
                            fclose(fnonces);
                        }
                        return PM3_EWRONGANSWER;
                    }

                    hardnested_stage |= CHECK_2ND_BYTES;
                    apply_sum_a0();
                }
                update_nonce_data(true);
                acquisition_completed = shrink_key_space(&brute_force_depth);
                if (!reported_suma8) {
                    char progress_string[80];
                    snprintf(progress_string, sizeof(progress_string), "Apply Sum property. Sum(a0) = %d", sums[first_byte_Sum]);
                    hardnested_print_progress(num_acquired_nonces, progress_string, brute_force_depth, 0);
                    reported_suma8 = true;
                } else {
                    hardnested_print_progress(num_acquired_nonces, "Apply bit flip properties", brute_force_depth, 0);
                }
            } else {
                update_nonce_data(true);
                acquisition_completed = shrink_key_space(&brute_force_depth);
                hardnested_print_progress(num_acquired_nonces, "Apply bit flip properties", brute_force_depth, 0);
            }
        }

        if (acquisition_completed) {
            field_off = true; // switch off field with next SendCommandOLD and then finish
        }

        if (initialize == false) {

            if (WaitForResponseTimeout(CMD_ACK, &resp, 3000) == false) {
                if (nonce_file_write) {
                    fclose(fnonces);
                }
                DropField();
                return PM3_ETIMEOUT;
            }

            // error during nested_hard
            if (resp.oldarg[0]) {
                if (nonce_file_write) {
                    fclose(fnonces);
                }
                DropField();
                return resp.oldarg[0];
            }
        }

        initialize = false;

        if (msclock() - last_sample_clock < sample_period) {
            sample_period = msclock() - last_sample_clock;
        }

        last_sample_clock = msclock();

    } while (field_off || acquisition_completed == false);

    if (nonce_file_write) {
        fclose(fnonces);
    }

    return PM3_SUCCESS;
}

static inline bool invariant_holds(uint_fast8_t byte_diff, uint_fast32_t state1, uint_fast32_t state2, uint_fast8_t bit, uint_fast8_t state_bit) {
    uint_fast8_t j_1_bit_mask = 0x01 << (bit - 1);
    uint_fast8_t bit_diff = byte_diff & j_1_bit_mask;                                               // difference of (j-1)th bit
    uint_fast8_t filter_diff = filter(state1 >> (4 - state_bit)) ^ filter(state2 >> (4 - state_bit)); // difference in filter function
    uint_fast8_t mask_y12_y13 = (0xc0 >> state_bit);
    uint_fast8_t state_bits_diff = (state1 ^ state2) & mask_y12_y13;                                // difference in state bits 12 and 13
    uint_fast8_t all_diff = evenparity8(bit_diff ^ state_bits_diff ^ filter_diff);                  // use parity function to XOR all bits
    return !all_diff;
}

static inline bool invalid_state(uint_fast8_t byte_diff, uint_fast32_t state1, uint_fast32_t state2, uint_fast8_t bit, uint_fast8_t state_bit) {
    uint_fast8_t j_bit_mask = (0x01 << bit);
    uint_fast8_t bit_diff = byte_diff & j_bit_mask;                                                 // difference of jth bit
    uint_fast8_t mask_y13_y16 = (0x48 >> state_bit);
    uint_fast8_t state_bits_diff = (state1 ^ state2) & mask_y13_y16;                                // difference in state bits 13 and 16
    uint_fast8_t all_diff = evenparity8(bit_diff ^ state_bits_diff);                                // use parity function to XOR all bits
    return all_diff;
}

static inline bool remaining_bits_match(uint_fast8_t num_common_bits, uint_fast8_t byte_diff, uint_fast32_t state1, uint_fast32_t state2, odd_even_t odd_even) {
    if (odd_even) {
        // odd bits
        switch (num_common_bits) {
            case 0:
                if (!invariant_holds(byte_diff, state1, state2, 1, 0)) return true;
            case 1:
                if (invalid_state(byte_diff, state1, state2, 1, 0)) return false;
            case 2:
                if (!invariant_holds(byte_diff, state1, state2, 3, 1)) return true;
            case 3:
                if (invalid_state(byte_diff, state1, state2, 3, 1)) return false;
            case 4:
                if (!invariant_holds(byte_diff, state1, state2, 5, 2)) return true;
            case 5:
                if (invalid_state(byte_diff, state1, state2, 5, 2)) return false;
            case 6:
                if (!invariant_holds(byte_diff, state1, state2, 7, 3)) return true;
            case 7:
                if (invalid_state(byte_diff, state1, state2, 7, 3)) return false;
        }
    } else {
        // even bits
        switch (num_common_bits) {
            case 0:
                if (invalid_state(byte_diff, state1, state2, 0, 0)) return false;
            case 1:
                if (!invariant_holds(byte_diff, state1, state2, 2, 1)) return true;
            case 2:
                if (invalid_state(byte_diff, state1, state2, 2, 1)) return false;
            case 3:
                if (!invariant_holds(byte_diff, state1, state2, 4, 2)) return true;
            case 4:
                if (invalid_state(byte_diff, state1, state2, 4, 2)) return false;
            case 5:
                if (!invariant_holds(byte_diff, state1, state2, 6, 3)) return true;
            case 6:
                if (invalid_state(byte_diff, state1, state2, 6, 3)) return false;
        }
    }

    return true; // valid state
}

static pthread_mutex_t statelist_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t book_of_work_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef enum {
    TO_BE_DONE,
    WORK_IN_PROGRESS,
    COMPLETED
} work_status_t;

static struct sl_cache_entry {
    uint32_t *sl;
    uint32_t len;
    work_status_t cache_status;
} sl_cache[NUM_PART_SUMS][NUM_PART_SUMS][2];

static void init_statelist_cache(void) {
    pthread_mutex_lock(&statelist_cache_mutex);
    for (uint16_t i = 0; i < NUM_PART_SUMS; i++) {
        for (uint16_t j = 0; j < NUM_PART_SUMS; j++) {
            for (uint16_t k = 0; k < 2; k++) {
                sl_cache[i][j][k].sl = NULL;
                sl_cache[i][j][k].len = 0;
                sl_cache[i][j][k].cache_status = TO_BE_DONE;
            }
        }
    }
    pthread_mutex_unlock(&statelist_cache_mutex);
}

static void free_statelist_cache(void) {
    pthread_mutex_lock(&statelist_cache_mutex);
    for (uint16_t i = 0; i < NUM_PART_SUMS; i++) {
        for (uint16_t j = 0; j < NUM_PART_SUMS; j++) {
            for (uint16_t k = 0; k < 2; k++) {
                free(sl_cache[i][j][k].sl);
            }
        }
    }
    pthread_mutex_unlock(&statelist_cache_mutex);
}


#ifdef DEBUG_KEY_ELIMINATION
static inline bool bitflips_match(uint8_t byte, uint32_t state, odd_even_t odd_even, bool quiet)
#else
static inline bool bitflips_match(uint8_t byte, uint32_t state, odd_even_t odd_even)
#endif
{
    uint32_t *bitset = nonces[byte].states_bitarray[odd_even];
    bool possible = test_bit24(bitset, state);
    if (!possible) {
#ifdef DEBUG_KEY_ELIMINATION
        if (!quiet && known_target_key != -1 && state == test_state[odd_even]) {
            PrintAndLogEx(INFO, "Initial state lists: " _YELLOW_("%s") " test state eliminated by bitflip property.", odd_even == EVEN_STATE ? "even" : "odd");
            snprintf(failstr, sizeof(failstr), "Initial " _YELLOW_("%s") " byte Bitflip property", odd_even == EVEN_STATE ? "even" : "odd");
        }
#endif
        return false;
    }

    return true;
}

static uint_fast8_t reverse(uint_fast8_t b) {
    return (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;
}

static bool all_bitflips_match(uint8_t byte, uint32_t state, odd_even_t odd_even) {
    uint32_t masks[2][8] = {
        {0x00fffff0, 0x00fffff8, 0x00fffff8, 0x00fffffc, 0x00fffffc, 0x00fffffe, 0x00fffffe, 0x00ffffff},
        {0x00fffff0, 0x00fffff0, 0x00fffff8, 0x00fffff8, 0x00fffffc, 0x00fffffc, 0x00fffffe, 0x00fffffe}
    };

    for (uint16_t i = 1; i < 256; i++) {
        uint_fast8_t bytes_diff = reverse(i); // start with most common bits
        uint_fast8_t byte2 = byte ^ bytes_diff;
        uint_fast8_t num_common = trailing_zeros(bytes_diff);
        uint32_t mask = masks[odd_even][num_common];
        bool found_match = false;
        for (uint8_t remaining_bits = 0; remaining_bits <= (~mask & 0xff); remaining_bits++) {
            if (remaining_bits_match(num_common, bytes_diff, state, (state & mask) | remaining_bits, odd_even)) {

# ifdef DEBUG_KEY_ELIMINATION
                if (bitflips_match(byte2, (state & mask) | remaining_bits, odd_even, true))
# else
                if (bitflips_match(byte2, (state & mask) | remaining_bits, odd_even))
# endif
                {
                    found_match = true;
                    break;
                }
            }
        }

        if (!found_match) {

# ifdef DEBUG_KEY_ELIMINATION
            if (known_target_key != -1 && state == test_state[odd_even]) {
                PrintAndLogEx(INFO, "all_bitflips_match() 1st Byte: %s test state (0x%06x): Eliminated. Bytes = %02x, %02x, Common Bits = %d\n",
                              odd_even == ODD_STATE ? "odd" : "even",
                              test_state[odd_even],
                              byte,
                              byte2,
                              num_common);
                if (failstr[0] == '\0') {
                    snprintf(failstr, sizeof(failstr), "Other 1st Byte %s, all_bitflips_match(), no match", odd_even ? "odd" : "even");
                }
            }
# endif
            return false;
        }
    }
    return true;
}

static void bitarray_to_list(uint8_t byte, uint32_t *bitarray, uint32_t *state_list, uint32_t *len, odd_even_t odd_even) {
    uint32_t *p = state_list;
    for (uint32_t state = next_state(bitarray, -1L); state < (1 << 24); state = next_state(bitarray, state)) {
        if (all_bitflips_match(byte, state, odd_even)) {
            *p++ = state;
        }
    }
    // add End Of List marker
    *p = 0xffffffff;
    *len = p - state_list;
}

static void add_cached_states(statelist_t *cands, uint16_t part_sum_a0, uint16_t part_sum_a8, odd_even_t odd_even) {
    cands->states[odd_even] = sl_cache[part_sum_a0 / 2][part_sum_a8 / 2][odd_even].sl;
    cands->len[odd_even] = sl_cache[part_sum_a0 / 2][part_sum_a8 / 2][odd_even].len;
}


static void add_matching_states(statelist_t *cands, uint8_t part_sum_a0, uint8_t part_sum_a8, odd_even_t odd_even) {

    const uint32_t worstcase_size = 1 << 20;

    cands->states[odd_even] = (uint32_t *)malloc(sizeof(uint32_t) * worstcase_size);
    if (cands->states[odd_even] == NULL) {
        PrintAndLogEx(ERR, "Out of memory error in add_matching_states() - statelist.\n");
        exit(4);
    }

    uint32_t *cands_bitarray = (uint32_t *)malloc_bitarray(sizeof(uint32_t) * worstcase_size);
    if (cands_bitarray == NULL) {
        PrintAndLogEx(ERR, "Out of memory error in add_matching_states() - bitarray.\n");
        free(cands->states[odd_even]);
        exit(4);
    }

    uint32_t *bitarray_a0 = part_sum_a0_bitarrays[odd_even][part_sum_a0 / 2];
    uint32_t *bitarray_a8 = part_sum_a8_bitarrays[odd_even][part_sum_a8 / 2];
    uint32_t *bitarray_bitflips = nonces[best_first_bytes[0]].states_bitarray[odd_even];

    bitarray_AND4(cands_bitarray, bitarray_a0, bitarray_a8, bitarray_bitflips);

    bitarray_to_list(best_first_bytes[0], cands_bitarray, cands->states[odd_even], &(cands->len[odd_even]), odd_even);

    if (cands->len[odd_even] == 0) {
        free(cands->states[odd_even]);
        cands->states[odd_even] = NULL;
    } else if (cands->len[odd_even] + 1 < worstcase_size) {
        cands->states[odd_even] = realloc(cands->states[odd_even], sizeof(uint32_t) * (cands->len[odd_even] + 1));
    }
    free_bitarray(cands_bitarray);

    pthread_mutex_lock(&statelist_cache_mutex);
    sl_cache[part_sum_a0 / 2][part_sum_a8 / 2][odd_even].sl = cands->states[odd_even];
    sl_cache[part_sum_a0 / 2][part_sum_a8 / 2][odd_even].len = cands->len[odd_even];
    sl_cache[part_sum_a0 / 2][part_sum_a8 / 2][odd_even].cache_status = COMPLETED;
    pthread_mutex_unlock(&statelist_cache_mutex);
    return;
}

static statelist_t *add_more_candidates(void) {
    statelist_t *new_candidates;
    if (candidates == NULL) {
        candidates = (statelist_t *)calloc(sizeof(statelist_t), sizeof(uint8_t));
        new_candidates = candidates;
    } else {
        new_candidates = candidates;
        while (new_candidates->next != NULL) {
            new_candidates = new_candidates->next;
        }
        new_candidates = new_candidates->next = (statelist_t *)calloc(sizeof(statelist_t), sizeof(uint8_t));
    }
    new_candidates->next = NULL;
    new_candidates->len[ODD_STATE] = 0;
    new_candidates->len[EVEN_STATE] = 0;
    new_candidates->states[ODD_STATE] = NULL;
    new_candidates->states[EVEN_STATE] = NULL;
    return new_candidates;
}

static void add_bitflip_candidates(uint8_t byte) {
    statelist_t *candidates1 = add_more_candidates();

    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t worstcase_size = nonces[byte].num_states_bitarray[odd_even] + 1;
        candidates1->states[odd_even] = (uint32_t *)calloc(worstcase_size, sizeof(uint32_t));
        if (candidates1->states[odd_even] == NULL) {
            PrintAndLogEx(ERR, "Out of memory error in add_bitflip_candidates()");
            exit(4);
        }

        bitarray_to_list(byte, nonces[byte].states_bitarray[odd_even], candidates1->states[odd_even], &(candidates1->len[odd_even]), odd_even);

        // slim down the allocated memory.
        if (candidates1->len[odd_even] + 1 < worstcase_size) {
            candidates1->states[odd_even] = realloc(candidates1->states[odd_even], sizeof(uint32_t) * (candidates1->len[odd_even] + 1));
        }
    }
    return;
}

static bool TestIfKeyExists(uint64_t key) {
    struct Crypto1State *pcs;
    pcs = crypto1_create(key);
    crypto1_byte(pcs, (cuid >> 24) ^ best_first_bytes[0], true);

    uint32_t state_odd = pcs->odd & 0x00ffffff;
    uint32_t state_even = pcs->even & 0x00ffffff;

    uint64_t count = 0;
    for (statelist_t *p = candidates; p != NULL; p = p->next) {
        bool found_odd = false;
        bool found_even = false;
        uint32_t *p_odd = p->states[ODD_STATE];
        uint32_t *p_even = p->states[EVEN_STATE];
        if (p_odd != NULL && p_even != NULL) {
            while (*p_odd != 0xffffffff) {
                if ((*p_odd & 0x00ffffff) == state_odd) {
                    found_odd = true;
                    break;
                }
                p_odd++;
            }
            while (*p_even != 0xffffffff) {
                if ((*p_even & 0x00ffffff) == state_even) {
                    found_even = true;
                }
                p_even++;
            }
            count += (uint64_t)(p_odd - p->states[ODD_STATE]) * (uint64_t)(p_even - p->states[EVEN_STATE]);
        }
        if (found_odd && found_even) {
            num_keys_tested += count;
            hardnested_print_progress(num_acquired_nonces, "(Test: Key found)", 0.0, 0);
            crypto1_destroy(pcs);
            return true;
        }
    }

    num_keys_tested += count;
    hardnested_print_progress(num_acquired_nonces, "(Test: Key NOT found)", 0.0, 0);
    crypto1_destroy(pcs);
    return false;
}

static work_status_t book_of_work[NUM_PART_SUMS][NUM_PART_SUMS][NUM_PART_SUMS][NUM_PART_SUMS];

static void init_book_of_work(void) {
    for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
        for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
            for (uint8_t r = 0; r < NUM_PART_SUMS; r++) {
                for (uint8_t s = 0; s < NUM_PART_SUMS; s++) {
                    book_of_work[p][q][r][s] = TO_BE_DONE;
                }
            }
        }
    }
}

static void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
*generate_candidates_worker_thread(void *args) {
    uint16_t *sum_args = (uint16_t *)args;
    uint16_t sum_a0 = sums[sum_args[0]];
    uint16_t sum_a8 = sums[sum_args[1]];
    // uint16_t my_thread_number = sums[2];

    bool there_might_be_more_work = true;
    do {
        there_might_be_more_work = false;
        for (uint8_t p = 0; p < NUM_PART_SUMS; p++) {
            for (uint8_t q = 0; q < NUM_PART_SUMS; q++) {
                if (2 * p * (16 - 2 * q) + (16 - 2 * p) * 2 * q == sum_a0) {
                    // PrintAndLogEx(INFO, "Reducing Partial Statelists (p,q) = (%d,%d) with lengths %d, %d",
                    // p, q, partial_statelist[p].len[ODD_STATE], partial_statelist[q].len[EVEN_STATE]);
                    for (uint8_t r = 0; r < NUM_PART_SUMS; r++) {
                        for (uint8_t s = 0; s < NUM_PART_SUMS; s++) {
                            if (2 * r * (16 - 2 * s) + (16 - 2 * r) * 2 * s == sum_a8) {
                                pthread_mutex_lock(&book_of_work_mutex);
                                if (book_of_work[p][q][r][s] != TO_BE_DONE) {  // this has been done or is currently been done by another thread. Look for some other work.
                                    pthread_mutex_unlock(&book_of_work_mutex);
                                    continue;
                                }

                                pthread_mutex_lock(&statelist_cache_mutex);
                                if (sl_cache[p][r][ODD_STATE].cache_status == WORK_IN_PROGRESS
                                        || sl_cache[q][s][EVEN_STATE].cache_status == WORK_IN_PROGRESS) { // defer until not blocked by another thread.
                                    pthread_mutex_unlock(&statelist_cache_mutex);
                                    pthread_mutex_unlock(&book_of_work_mutex);
                                    there_might_be_more_work = true;
                                    continue;
                                }

                                // we finally can do some work.
                                book_of_work[p][q][r][s] = WORK_IN_PROGRESS;
                                statelist_t *current_candidates = add_more_candidates();

                                // Check for cached results and add them first
                                bool odd_completed = false;
                                if (sl_cache[p][r][ODD_STATE].cache_status == COMPLETED) {
                                    add_cached_states(current_candidates, 2 * p, 2 * r, ODD_STATE);
                                    odd_completed = true;
                                }
                                bool even_completed = false;
                                if (sl_cache[q][s][EVEN_STATE].cache_status == COMPLETED) {
                                    add_cached_states(current_candidates, 2 * q, 2 * s, EVEN_STATE);
                                    even_completed = true;
                                }

                                bool work_required = true;

                                // if there had been two cached results, there is no more work to do
                                if (even_completed && odd_completed) {
                                    work_required = false;
                                }

                                // if there had been one cached empty result, there is no need to calculate the other part:
                                if (work_required) {
                                    if (even_completed && !current_candidates->len[EVEN_STATE]) {
                                        current_candidates->len[ODD_STATE] = 0;
                                        current_candidates->states[ODD_STATE] = NULL;
                                        work_required = false;
                                    }
                                    if (odd_completed && !current_candidates->len[ODD_STATE]) {
                                        current_candidates->len[EVEN_STATE] = 0;
                                        current_candidates->states[EVEN_STATE] = NULL;
                                        work_required = false;
                                    }
                                }

                                if (work_required == false) {
                                    pthread_mutex_unlock(&statelist_cache_mutex);
                                    pthread_mutex_unlock(&book_of_work_mutex);
                                } else {
                                    // we really need to calculate something
                                    if (even_completed) { // we had one cache hit with non-zero even states
                                        // PrintAndLogEx(INFO, "Thread #%u: start working on  odd states p=%2d, r=%2d...", my_thread_number, p, r);
                                        sl_cache[p][r][ODD_STATE].cache_status = WORK_IN_PROGRESS;
                                        pthread_mutex_unlock(&statelist_cache_mutex);
                                        pthread_mutex_unlock(&book_of_work_mutex);
                                        add_matching_states(current_candidates, 2 * p, 2 * r, ODD_STATE);
                                        work_required = false;
                                    } else if (odd_completed) { // we had one cache hit with non-zero odd_states
                                        // PrintAndLogEx(INFO, "Thread #%u: start working on even states q=%2d, s=%2d...", my_thread_number, q, s);
                                        sl_cache[q][s][EVEN_STATE].cache_status = WORK_IN_PROGRESS;
                                        pthread_mutex_unlock(&statelist_cache_mutex);
                                        pthread_mutex_unlock(&book_of_work_mutex);
                                        add_matching_states(current_candidates, 2 * q, 2 * s, EVEN_STATE);
                                        work_required = false;
                                    }
                                }

                                if (work_required) { // we had no cached result. Need to calculate both odd and even
                                    sl_cache[p][r][ODD_STATE].cache_status = WORK_IN_PROGRESS;
                                    sl_cache[q][s][EVEN_STATE].cache_status = WORK_IN_PROGRESS;
                                    pthread_mutex_unlock(&statelist_cache_mutex);
                                    pthread_mutex_unlock(&book_of_work_mutex);

                                    add_matching_states(current_candidates, 2 * p, 2 * r, ODD_STATE);
                                    if (current_candidates->len[ODD_STATE]) {
                                        // PrintAndLogEx(INFO, "Thread #%u: start working on even states q=%2d, s=%2d...", my_thread_number, q, s);
                                        add_matching_states(current_candidates, 2 * q, 2 * s, EVEN_STATE);
                                    } else { // no need to calculate even states yet
                                        pthread_mutex_lock(&statelist_cache_mutex);
                                        sl_cache[q][s][EVEN_STATE].cache_status = TO_BE_DONE;
                                        pthread_mutex_unlock(&statelist_cache_mutex);
                                        current_candidates->len[EVEN_STATE] = 0;
                                        current_candidates->states[EVEN_STATE] = NULL;
                                    }
                                }

                                // update book of work
                                pthread_mutex_lock(&book_of_work_mutex);
                                book_of_work[p][q][r][s] = COMPLETED;
                                pthread_mutex_unlock(&book_of_work_mutex);

                                // if ((uint64_t)current_candidates->len[ODD_STATE] * current_candidates->len[EVEN_STATE]) {
                                // PrintAndLogEx(INFO, "Candidates for p=%2u, q=%2u, r=%2u, s=%2u: %" PRIu32 " * %" PRIu32 " = %" PRIu64 " (2^%0.1f)\n",
                                // 2*p, 2*q, 2*r, 2*s, current_candidates->len[ODD_STATE], current_candidates->len[EVEN_STATE],
                                // (uint64_t)current_candidates->len[ODD_STATE] * current_candidates->len[EVEN_STATE],
                                // log((uint64_t)current_candidates->len[ODD_STATE] * current_candidates->len[EVEN_STATE])/log(2));
                                // uint32_t estimated_odd = estimated_num_states_part_sum(best_first_bytes[0], p, r, ODD_STATE);
                                // uint32_t estimated_even= estimated_num_states_part_sum(best_first_bytes[0], q, s, EVEN_STATE);
                                // uint64_t estimated_total = (uint64_t)estimated_odd * estimated_even;
                                // PrintAndLogEx(INFO, "Estimated: %" PRIu32 " * %" PRIu32 " = %" PRIu64 " (2^%0.1f)\n", estimated_odd, estimated_even, estimated_total, log(estimated_total) / log(2));
                                // if (estimated_odd < current_candidates->len[ODD_STATE] || estimated_even < current_candidates->len[EVEN_STATE]) {
                                // PrintAndLogEx(INFO, "############################################################################ERROR! ESTIMATED < REAL !!!\n");
                                // //exit(2);
                                // }
                                // }
                            }
                        }
                    }
                }
            }
        }
    } while (there_might_be_more_work);

    return NULL;
}


static void generate_candidates(uint8_t sum_a0_idx, uint8_t sum_a8_idx) {

    // create mutexes for accessing the statelist cache and our "book of work"
    pthread_mutex_init(&statelist_cache_mutex, NULL);
    pthread_mutex_init(&book_of_work_mutex, NULL);

    init_statelist_cache();
    init_book_of_work();

    // create and run worker threads
    const size_t num_reduction_working_threads = NUM_REDUCTION_WORKING_THREADS;
    pthread_t thread_id[num_reduction_working_threads];

    uint16_t sums1[num_reduction_working_threads][3];
    for (uint32_t i = 0; i < num_reduction_working_threads; i++) {
        sums1[i][0] = sum_a0_idx;
        sums1[i][1] = sum_a8_idx;
        sums1[i][2] = i + 1;
        pthread_create(thread_id + i, NULL, generate_candidates_worker_thread, sums1[i]);
    }

    // wait for threads to terminate:
    for (uint32_t i = 0; i < num_reduction_working_threads; i++) {
        pthread_join(thread_id[i], NULL);
    }

    maximum_states = 0;
    for (statelist_t *sl = candidates; sl != NULL; sl = sl->next) {
        maximum_states += (uint64_t)sl->len[ODD_STATE] * sl->len[EVEN_STATE];
    }

    for (uint8_t i = 0; i < NUM_SUMS; i++) {
        if (nonces[best_first_bytes[0]].sum_a8_guess[i].sum_a8_idx == sum_a8_idx) {
            nonces[best_first_bytes[0]].sum_a8_guess[i].num_states = maximum_states;
            break;
        }
    }
    update_expected_brute_force(best_first_bytes[0]);

    hardnested_print_progress(num_acquired_nonces, "Apply Sum(a8) and all bytes bitflip properties", nonces[best_first_bytes[0]].expected_num_brute_force, 0);
}

static void free_candidates_memory(statelist_t *sl) {
    if (sl == NULL)
        return;

    free_candidates_memory(sl->next);
    sl->len[0] = 0;
    sl->len[1] = 0;
    free(sl);
}

static void pre_XOR_nonces(void) {
    // prepare acquired nonces for faster brute forcing.

    // XOR the cryptoUID and its parity
    for (uint16_t i = 0; i < 256; i++) {
        noncelistentry_t *test_nonce = nonces[i].first;
        while (test_nonce != NULL) {
            test_nonce->nonce_enc ^= cuid;
            test_nonce->par_enc ^= oddparity8(cuid >>  0 & 0xff) << 0;
            test_nonce->par_enc ^= oddparity8(cuid >>  8 & 0xff) << 1;
            test_nonce->par_enc ^= oddparity8(cuid >> 16 & 0xff) << 2;
            test_nonce->par_enc ^= oddparity8(cuid >> 24 & 0xff) << 3;
            test_nonce = test_nonce->next;
        }
    }
}

static bool brute_force(uint64_t *found_key) {
    if (known_target_key != -1) {
        TestIfKeyExists(known_target_key);
    }
    return brute_force_bs(NULL, candidates, cuid, num_acquired_nonces, maximum_states, nonces, best_first_bytes, found_key);
}

static uint16_t SumProperty(struct Crypto1State *s) {
    uint16_t sum_odd = PartialSumProperty(s->odd, ODD_STATE);
    uint16_t sum_even = PartialSumProperty(s->even, EVEN_STATE);
    return (sum_odd * (16 - sum_even) + (16 - sum_odd) * sum_even);
}

static void Tests(void) {

    if (known_target_key == -1)
        return;

    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t *bitset = nonces[best_first_bytes[0]].states_bitarray[odd_even];
        if (!test_bit24(bitset, test_state[odd_even])) {
            PrintAndLogEx(WARNING, "BUG: known target key's " _YELLOW_("%s") " state is not member of first nonce byte's ( 0x%02x ) states_bitarray!",
                          odd_even == EVEN_STATE ? "even" : "odd ",
                          best_first_bytes[0]);
        }
    }
    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t *bitset = all_bitflips_bitarray[odd_even];
        if (!test_bit24(bitset, test_state[odd_even])) {
            PrintAndLogEx(WARNING, "BUG: known target key's " _YELLOW_("%s") " state is not member of all_bitflips_bitarray!",
                          odd_even == EVEN_STATE ? "even" : "odd ");
        }
    }
}

static void Tests2(void) {

    if (known_target_key == -1)
        return;

    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t *bitset = nonces[best_first_byte_smallest_bitarray].states_bitarray[odd_even];
        if (!test_bit24(bitset, test_state[odd_even])) {
            PrintAndLogEx(WARNING, "BUG: known target key's " _YELLOW_("%s") " state is not member of first nonce byte's ( 0x%02x ) states_bitarray!",
                          odd_even == EVEN_STATE ? "even" : "odd ",
                          best_first_byte_smallest_bitarray);
        }
    }

    for (odd_even_t odd_even = EVEN_STATE; odd_even <= ODD_STATE; odd_even++) {
        uint32_t *bitset = all_bitflips_bitarray[odd_even];
        if (!test_bit24(bitset, test_state[odd_even])) {
            PrintAndLogEx(WARNING, "BUG: known target key's " _YELLOW_("%s") " state is not member of all_bitflips_bitarray!",
                          odd_even == EVEN_STATE ? "even" : "odd ");
        }
    }
}

static uint16_t real_sum_a8 = 0;

static void set_test_state(uint8_t byte) {
    struct Crypto1State *pcs;
    pcs = crypto1_create(known_target_key);
    crypto1_byte(pcs, (cuid >> 24) ^ byte, true);
    test_state[ODD_STATE] = pcs->odd & 0x00ffffff;
    test_state[EVEN_STATE] = pcs->even & 0x00ffffff;
    real_sum_a8 = SumProperty(pcs);
    crypto1_destroy(pcs);
}

static void init_it_all(void) {
    memset(nonces, 0, sizeof(nonces));
    maximum_states = 0;
    best_first_byte_smallest_bitarray = 0;
    first_byte_Sum = 0;
    first_byte_num = 0;
    write_stats = false;
    all_bitflips_bitarray[0] = NULL;
    all_bitflips_bitarray[1] = NULL;
    num_all_bitflips_bitarray[0] = 0;
    num_all_bitflips_bitarray[1] = 0;
    all_bitflips_bitarray_dirty[0] = false;
    all_bitflips_bitarray_dirty[1] = false;
    last_sample_clock = 0;
    sample_period = 0;
    num_keys_tested = 0;
    candidates = NULL;
    num_acquired_nonces = 0;
    start_time = 0;
    num_effective_bitflips[0] = 0;
    num_effective_bitflips[1] = 0;
    num_all_effective_bitflips = 0;
    num_1st_byte_effective_bitflips = 0;
    hardnested_stage = CHECK_1ST_BYTES;
    known_target_key = 0;
    test_state[0] = 0;
    test_state[1] = 0;
    brute_force_per_second = 0;
    init_book_of_work();
    real_sum_a8 = 0;

    memset(effective_bitflip, 0, sizeof(effective_bitflip));
    memset(all_effective_bitflip, 0, sizeof(all_effective_bitflip));
    memset(bitflip_bitarrays, 0, sizeof(bitflip_bitarrays));
    memset(count_bitflip_bitarrays, 0, sizeof(count_bitflip_bitarrays));
    memset(part_sum_a0_bitarrays, 0, sizeof(part_sum_a0_bitarrays));
    memset(part_sum_a8_bitarrays, 0, sizeof(part_sum_a8_bitarrays));
    memset(sum_a0_bitarrays, 0, sizeof(sum_a0_bitarrays));
}

int mfnestedhard(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *trgkey, bool nonce_file_read, bool nonce_file_write, bool slow, int tests, uint64_t *foundkey, char *filename) {
    char progress_text[80];
    char instr_set[12] = {0};

    get_SIMD_instruction_set(instr_set);

    // initialize static arrays
    memset(part_sum_count, 0, sizeof(part_sum_count));
    init_it_all();

    srand((unsigned) time(NULL));
    brute_force_per_second = brute_force_benchmark();
    write_stats = false;

    if (tests) {
        // set the correct locale for the stats printing
        write_stats = true;
        setlocale(LC_NUMERIC, "");
        if ((fstats = fopen("hardnested_stats.txt", "a")) == NULL) {
            PrintAndLogEx(WARNING, "Could not create/open file " _YELLOW_("hardnested_stats.txt"));
            return PM3_EFILE;
        }

        for (uint32_t i = 0; i < tests; i++) {
            start_time = msclock();
            print_progress_header();
            snprintf(progress_text, sizeof(progress_text), "Brute force benchmark: %1.0f million (2^%1.1f) keys/s", brute_force_per_second / 1000000, log(brute_force_per_second) / log(2.0));
            hardnested_print_progress(0, progress_text, (float)(1LL << 47), 0);
            snprintf(progress_text, sizeof(progress_text), "Starting Test #%" PRIu32 " ...", i + 1);
            hardnested_print_progress(0, progress_text, (float)(1LL << 47), 0);

            if (trgkey != NULL) {
                known_target_key = bytes_to_num(trgkey, 6);
            } else {
                known_target_key = -1;
            }

            init_bitflip_bitarrays();
            init_part_sum_bitarrays();
            init_sum_bitarrays();
            init_allbitflips_array();
            init_nonce_memory();
            update_reduction_rate(0.0, true);

            int res = simulate_acquire_nonces();
            if (res != PM3_SUCCESS) {
                return res;
            }

            set_test_state(best_first_bytes[0]);

            Tests();
            free_bitflip_bitarrays();

            fprintf(fstats, "%" PRIu16 ";%1.1f;", sums[first_byte_Sum], log(p_K0[first_byte_Sum]) / log(2.0));
            fprintf(fstats, "%" PRIu16 ";%1.1f;", sums[nonces[best_first_bytes[0]].sum_a8_guess[0].sum_a8_idx], log(p_K[nonces[best_first_bytes[0]].sum_a8_guess[0].sum_a8_idx]) / log(2.0));
            fprintf(fstats, "%" PRIu16 ";", real_sum_a8);

#ifdef DEBUG_KEY_ELIMINATION
            failstr[0] = '\0';
#endif
            bool key_found = false;
            num_keys_tested = 0;
            uint32_t num_odd = nonces[best_first_byte_smallest_bitarray].num_states_bitarray[ODD_STATE];
            uint32_t num_even = nonces[best_first_byte_smallest_bitarray].num_states_bitarray[EVEN_STATE];
            float expected_brute_force1 = (float)num_odd * num_even / 2.0;
            float expected_brute_force2 = nonces[best_first_bytes[0]].expected_num_brute_force;
            fprintf(fstats, "%1.1f;%1.1f;", log(expected_brute_force1) / log(2.0), log(expected_brute_force2) / log(2.0));

            if (expected_brute_force1 < expected_brute_force2) {
                hardnested_print_progress(num_acquired_nonces, "(Ignoring Sum(a8) properties)", expected_brute_force1, 0);
                set_test_state(best_first_byte_smallest_bitarray);
                add_bitflip_candidates(best_first_byte_smallest_bitarray);
                Tests2();
                maximum_states = 0;
                for (statelist_t *sl = candidates; sl != NULL; sl = sl->next) {
                    maximum_states += (uint64_t)sl->len[ODD_STATE] * sl->len[EVEN_STATE];
                }

                best_first_bytes[0] = best_first_byte_smallest_bitarray;
                pre_XOR_nonces();
                prepare_bf_test_nonces(nonces, best_first_bytes[0]);

                key_found = brute_force(foundkey);
                free(candidates->states[ODD_STATE]);
                free(candidates->states[EVEN_STATE]);
                free_candidates_memory(candidates);
                candidates = NULL;
            } else {
                pre_XOR_nonces();
                prepare_bf_test_nonces(nonces, best_first_bytes[0]);
                for (uint8_t j = 0; j < NUM_SUMS && !key_found; j++) {
                    float expected_brute_force = nonces[best_first_bytes[0]].expected_num_brute_force;
                    snprintf(progress_text, sizeof(progress_text), "(%d. guess: Sum(a8) = %" PRIu16 ")", j + 1, sums[nonces[best_first_bytes[0]].sum_a8_guess[j].sum_a8_idx]);
                    hardnested_print_progress(num_acquired_nonces, progress_text, expected_brute_force, 0);
                    if (sums[nonces[best_first_bytes[0]].sum_a8_guess[j].sum_a8_idx] != real_sum_a8) {
                        snprintf(progress_text, sizeof(progress_text), "(Estimated Sum(a8) is WRONG! Correct Sum(a8) = %" PRIu16 ")", real_sum_a8);
                        hardnested_print_progress(num_acquired_nonces, progress_text, expected_brute_force, 0);
                    }
                    generate_candidates(first_byte_Sum, nonces[best_first_bytes[0]].sum_a8_guess[j].sum_a8_idx);

                    key_found = brute_force(foundkey);
                    free_statelist_cache();
                    free_candidates_memory(candidates);
                    candidates = NULL;
                    if (key_found == false) {
                        // update the statistics
                        nonces[best_first_bytes[0]].sum_a8_guess[j].prob = 0;
                        nonces[best_first_bytes[0]].sum_a8_guess[j].num_states = 0;
                        // and calculate new expected number of brute forces
                        update_expected_brute_force(best_first_bytes[0]);
                    }
                }
            }
#ifdef DEBUG_KEY_ELIMINATION
            fprintf(fstats, "%1.1f;%1.0f;%c;%s\n",
                    log(num_keys_tested) / log(2.0),
                    (float)num_keys_tested / brute_force_per_second,
                    key_found ? 'Y' : 'N',
                    failstr
                   );
#else
            fprintf(fstats, "%1.0f;%d\n",
                    log(num_keys_tested) / log(2.0),
                    (float)num_keys_tested / brute_force_per_second,
                    key_found
                   );
#endif

            free_nonces_memory();
            free_bitarray(all_bitflips_bitarray[ODD_STATE]);
            free_bitarray(all_bitflips_bitarray[EVEN_STATE]);
            free_sum_bitarrays();
            free_part_sum_bitarrays();
        }
        fclose(fstats);

    } else {

        start_time = msclock();
        print_progress_header();
        snprintf(progress_text, sizeof(progress_text), "Brute force benchmark: %1.0f million (2^%1.1f) keys/s", brute_force_per_second / 1000000, log(brute_force_per_second) / log(2.0));
        hardnested_print_progress(0, progress_text, (float)(1LL << 47), 0);
        init_bitflip_bitarrays();
        init_part_sum_bitarrays();
        init_sum_bitarrays();
        init_allbitflips_array();
        init_nonce_memory();
        update_reduction_rate(0.0, true);

        int res;
        if (nonce_file_read) {  // use pre-acquired data from file nonces.bin
            res = read_nonce_file(filename);
            if (res != PM3_SUCCESS) {
                free_bitflip_bitarrays();
                free_nonces_memory();
                free_bitarray(all_bitflips_bitarray[ODD_STATE]);
                free_bitarray(all_bitflips_bitarray[EVEN_STATE]);
                free_sum_bitarrays();
                free_part_sum_bitarrays();
                return res;
            }
            hardnested_stage = CHECK_1ST_BYTES | CHECK_2ND_BYTES;
            update_nonce_data(false);
            float brute_force_depth;
            shrink_key_space(&brute_force_depth);
        } else { // acquire nonces.
            res = acquire_nonces(blockNo, keyType, key, trgBlockNo, trgKeyType, nonce_file_write, slow, filename);
            if (res != PM3_SUCCESS) {
                free_bitflip_bitarrays();
                free_nonces_memory();
                free_bitarray(all_bitflips_bitarray[ODD_STATE]);
                free_bitarray(all_bitflips_bitarray[EVEN_STATE]);
                free_sum_bitarrays();
                free_part_sum_bitarrays();
                return res;
            }
        }

        if (trgkey != NULL) {
            known_target_key = bytes_to_num(trgkey, 6);
            set_test_state(best_first_bytes[0]);
        } else {
            known_target_key = -1;
        }

        Tests();

        free_bitflip_bitarrays();
        bool key_found = false;
        num_keys_tested = 0;
        uint32_t num_odd = nonces[best_first_byte_smallest_bitarray].num_states_bitarray[ODD_STATE];
        uint32_t num_even = nonces[best_first_byte_smallest_bitarray].num_states_bitarray[EVEN_STATE];
        float expected_brute_force1 = (float)num_odd * num_even / 2.0;
        float expected_brute_force2 = nonces[best_first_bytes[0]].expected_num_brute_force;

        if (expected_brute_force1 < expected_brute_force2) {
            hardnested_print_progress(num_acquired_nonces, "(Ignoring Sum(a8) properties)", expected_brute_force1, 0);
            set_test_state(best_first_byte_smallest_bitarray);
            add_bitflip_candidates(best_first_byte_smallest_bitarray);
            Tests2();
            maximum_states = 0;

            for (statelist_t *sl = candidates; sl != NULL; sl = sl->next) {
                maximum_states += (uint64_t)sl->len[ODD_STATE] * sl->len[EVEN_STATE];
            }

            best_first_bytes[0] = best_first_byte_smallest_bitarray;
            pre_XOR_nonces();
            prepare_bf_test_nonces(nonces, best_first_bytes[0]);

            key_found = brute_force(foundkey);
            free(candidates->states[ODD_STATE]);
            free(candidates->states[EVEN_STATE]);
            free_candidates_memory(candidates);
            candidates = NULL;
        } else {

            pre_XOR_nonces();
            prepare_bf_test_nonces(nonces, best_first_bytes[0]);

            for (uint8_t j = 0; j < NUM_SUMS && !key_found; j++) {
                float expected_brute_force = nonces[best_first_bytes[0]].expected_num_brute_force;
                snprintf(progress_text, sizeof(progress_text), "(%d. guess: Sum(a8) = %" PRIu16 ")", j + 1, sums[nonces[best_first_bytes[0]].sum_a8_guess[j].sum_a8_idx]);
                hardnested_print_progress(num_acquired_nonces, progress_text, expected_brute_force, 0);

                if (trgkey != NULL && sums[nonces[best_first_bytes[0]].sum_a8_guess[j].sum_a8_idx] != real_sum_a8) {
                    snprintf(progress_text, sizeof(progress_text), "(Estimated Sum(a8) is WRONG! Correct Sum(a8) = %" PRIu16 ")", real_sum_a8);
                    hardnested_print_progress(num_acquired_nonces, progress_text, expected_brute_force, 0);
                }

                generate_candidates(first_byte_Sum, nonces[best_first_bytes[0]].sum_a8_guess[j].sum_a8_idx);
                key_found = brute_force(foundkey);
                free_statelist_cache();
                free_candidates_memory(candidates);
                candidates = NULL;
                if (key_found == false) {
                    // update the statistics
                    nonces[best_first_bytes[0]].sum_a8_guess[j].prob = 0;
                    nonces[best_first_bytes[0]].sum_a8_guess[j].num_states = 0;
                    // and calculate new expected number of brute forces
                    update_expected_brute_force(best_first_bytes[0]);
                }
            }
        }

        free_nonces_memory();
        free_bitarray(all_bitflips_bitarray[ODD_STATE]);
        free_bitarray(all_bitflips_bitarray[EVEN_STATE]);
        free_sum_bitarrays();
        free_part_sum_bitarrays();

        return (key_found) ? PM3_SUCCESS : PM3_EFAILED;
    }

    return PM3_SUCCESS;
}
