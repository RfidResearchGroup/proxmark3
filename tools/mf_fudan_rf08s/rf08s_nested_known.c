
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "common.h"
#include "crapto1/crapto1.h"
#include "parity.h"

#define KEY_SPACE_SIZE (1 << 18)

typedef struct {
    uint32_t authuid;
    uint32_t nt;
    uint32_t nt_enc;
    uint8_t nt_par_enc;
} NtData;

static uint32_t hex_to_uint32(const char *hex_str) {
    return (uint32_t)strtoul(hex_str, NULL, 16);
}

static int bin_to_uint8_arr(const char *bin_str, uint8_t bit_arr[], uint8_t arr_size) {
    if (strlen(bin_str) != arr_size) {
        fprintf(stderr, "Error: Binary string (%s) length does not match array size (%i).\n", bin_str, arr_size);
        return 1;
    }

    for (uint8_t i = 0; i < arr_size; i++) {
        if (bin_str[i] == '0') {
            bit_arr[i] = 0;
        } else if (bin_str[i] == '1') {
            bit_arr[i] = 1;
        } else {
            fprintf(stderr, "Error: Invalid character '%c' in binary string.\n", bin_str[i]);
            return 1;
        }
    }
    return 0;
}

static uint64_t *generate_keys(uint64_t authuid, uint32_t nt, uint32_t nt_enc, uint32_t nt_par_enc, uint32_t *keyCount) {
    uint64_t *result_keys = (uint64_t *)malloc(KEY_SPACE_SIZE * sizeof(uint64_t));
    if (result_keys == NULL) {
        fprintf(stderr, "\nMalloc error in generate_and_intersect_keys!\n");
        return NULL;
    }

    struct Crypto1State *revstate, *revstate_start = NULL, *s = NULL;
    uint64_t lfsr = 0;
    uint32_t ks1 = nt ^ nt_enc;

    revstate = lfsr_recovery32(ks1, nt ^ authuid);
    if (revstate == NULL) {
        fprintf(stderr, "\nMalloc error in generate_keys!\n");
        free(result_keys);
        return NULL;
    }
    if (revstate_start == NULL) {
        revstate_start = revstate;
    }
    s = crypto1_create(0);
    if (s == NULL) {
        fprintf(stderr, "\nMalloc error in generate_keys!\n");
        free(result_keys);
        crypto1_destroy(revstate_start);
        return 0;
    }
    while ((revstate->odd != 0x0) || (revstate->even != 0x0)) {
        lfsr_rollback_word(revstate, nt ^ authuid, 0);
        crypto1_get_lfsr(revstate, &lfsr);

        // only filtering possibility: last parity bit ks in ks2
        uint32_t ks2;
        uint8_t lastpar1, lastpar2, kslastp;
        crypto1_init(s, lfsr);
        crypto1_word(s, nt ^ authuid, 0);
        ks2 = crypto1_word(s, 0, 0);
        lastpar1 = oddparity8(nt & 0xFF);
        kslastp = (ks2 >> 24) & 1;
        lastpar2 = (nt_par_enc & 1) ^ kslastp;
        if (lastpar1 == lastpar2) {
            result_keys[(*keyCount)++] = lfsr;
            if (*keyCount == KEY_SPACE_SIZE) {
                fprintf(stderr, "No space left on result_keys, abort! Increase KEY_SPACE_SIZE\n");
                break;
            }
        }
        revstate++;
    }
    crypto1_destroy(s);
    crypto1_destroy(revstate_start);
    revstate_start = NULL;
    return result_keys;
}

int main(int argc, char *const argv[]) {
    if (argc != 6) {
        int cmdlen = strlen(argv[0]);
        printf("Usage:\n  %s <uid:hex> <sector:dec> <nt:hex> <nt_enc:hex> <nt_par_err:bin>\n"
               "  parity example:  if for block 63 == sector 15, nt in trace is 7b! fc! 7a! 5b\n"
               "                   then nt_enc is 7bfc7a5b and nt_par_err is 1110\n"
               "Example:\n"
               "  %*s a13e4902 15 d14191b3 2e9e49fc 1111\n"
               "  %*s +uid     +s +nt      +nt_enc  +nt_par_err\n",
               argv[0], cmdlen, argv[0], cmdlen, "");
        return 1;
    }
    uint64_t *keys = NULL;
    uint32_t keyCount = 0;
    
    uint32_t authuid = hex_to_uint32(argv[1]);
    uint32_t sector = hex_to_uint32(argv[2]);
    uint32_t nt = hex_to_uint32(argv[3]);
    uint32_t nt_enc = hex_to_uint32(argv[4]);
    uint8_t nt_par_err_arr[4];
    if (bin_to_uint8_arr(argv[5], nt_par_err_arr, 4)) {
        return 1;
    }
    uint8_t nt_par_enc = ((nt_par_err_arr[0] ^ oddparity8((nt_enc >> 24) & 0xFF)) << 3) |
                            ((nt_par_err_arr[1] ^ oddparity8((nt_enc >> 16) & 0xFF)) << 2) |
                            ((nt_par_err_arr[2] ^ oddparity8((nt_enc >>  8) & 0xFF)) << 1) |
                            ((nt_par_err_arr[3] ^ oddparity8((nt_enc >>  0) & 0xFF)) << 0);
    printf("uid=%08x nt=%08x nt_enc=%08x nt_par_err=%i%i%i%i nt_par_enc=%i%i%i%i ks1=%08x\n", authuid, nt, nt_enc,
        nt_par_err_arr[0], nt_par_err_arr[1], nt_par_err_arr[2], nt_par_err_arr[3],
        (nt_par_enc >> 3)&1, (nt_par_enc >> 2)&1, (nt_par_enc >> 1)&1, nt_par_enc&1,
        nt ^ nt_enc);


    printf("Finding key candidates...\n");
    keys = generate_keys(authuid, nt, nt_enc, nt_par_enc, &keyCount);
    printf("Finding phase complete, found %i keys\n", keyCount);

    FILE* fptr;
    char filename[30];
    snprintf(filename, sizeof(filename), "keys_%08x_%02i_%08x.dic", authuid, sector, nt);

    fptr = fopen(filename, "w");
    if (fptr != NULL) {
        if (keyCount > 0) {
            for (uint32_t j = 0; j < keyCount; j++) {
                fprintf(fptr, "%012" PRIx64 "\n", keys[j]);
            }
        }
        fclose(fptr);
    } else {
        fprintf(stderr, "Warning: Cannot save keys in %s\n", filename);
    }
    if (keys != NULL) {
        free(keys);
    }
    return 0;
}
