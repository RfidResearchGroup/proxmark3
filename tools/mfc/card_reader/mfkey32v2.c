#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "crapto1/crapto1.h"
#include "util_posix.h"

int main(int argc, char *argv[]) {
    struct Crypto1State *s, *t;
    uint64_t key;     // recovered key
    uint32_t uid;     // serial number
    uint32_t nt0;      // tag challenge first
    uint32_t nt1;      // tag challenge second
    uint32_t nr0_enc; // first encrypted reader challenge
    uint32_t ar0_enc; // first encrypted reader response
    uint32_t nr1_enc; // second encrypted reader challenge
    uint32_t ar1_enc; // second encrypted reader response
    uint32_t ks2_0;   // first keystream used to encrypt reader response
    uint32_t ks2_1;   // second keystream used to encrypt reader response

    printf("MIFARE Classic key recovery - based 32 bits of keystream  VERSION2\n");
    printf("Recover key from two 32-bit reader authentication answers only\n");
    printf("This version implements Moebius two different nonce solution (like the supercard)\n\n");

    if (argc < 8) {
        printf("syntax: %s <uid> <{nt_0}> <{nr_0}> <{ar_0}> <{nt_1}> <{nr_1}> <{ar_1}>\n\n", argv[0]);
        return 1;
    }

    sscanf(argv[1], "%x", &uid);
    sscanf(argv[2], "%x", &nt0);
    sscanf(argv[3], "%x", &nr0_enc);
    sscanf(argv[4], "%x", &ar0_enc);
    sscanf(argv[5], "%x", &nt1);
    sscanf(argv[6], "%x", &nr1_enc);
    sscanf(argv[7], "%x", &ar1_enc);

    printf("Recovering key for:\n");
    printf("    uid: %08x\n", uid);
    printf("   nt_0: %08x\n", nt0);
    printf(" {nr_0}: %08x\n", nr0_enc);
    printf(" {ar_0}: %08x\n", ar0_enc);
    printf("   nt_1: %08x\n", nt1);
    printf(" {nr_1}: %08x\n", nr1_enc);
    printf(" {ar_1}: %08x\n", ar1_enc);

    // Generate lfsr successors of the tag challenge
    printf("\nLFSR successors of the tag challenges:\n");
    uint32_t ar0 = prng_successor(nt0, 64);
    uint32_t ar1 = prng_successor(nt1, 64);

    printf("   ar_0: %08x\n", ar0);
    printf("   ar_1: %08x\n", ar1);

    // Extract the keystream from the messages
    printf("\nKeystreams used to generate {ar_0} and {ar_1}:\n");
    ks2_0 = ar0_enc ^ ar0;
    printf("  ks2_0: %08x\n", ks2_0);
    ks2_1 = ar1_enc ^ ar1;
    printf("  ks2_1: %08x\n", ks2_1);

    s = lfsr_recovery32(ks2_0, 0);

    for (t = s; t->odd | t->even; ++t) {
        lfsr_rollback_word(t, 0, 0);
        lfsr_rollback_word(t, nr0_enc, 1);
        lfsr_rollback_word(t, uid ^ nt0, 0);
        crypto1_get_lfsr(t, &key);

        crypto1_word(t, uid ^ nt1, 0);
        crypto1_word(t, nr1_enc, 1);
        if (ks2_1 == crypto1_word(t, 0, 0)) {
            printf("\nFound Key: [%012" PRIx64 "]\n\n", key);
            break;
        }
    }
    free(s);
    return 0;
}
