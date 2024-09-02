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
    uint32_t nt;      // tag challenge
    uint32_t nr0_enc; // first encrypted reader challenge
    uint32_t ar0_enc; // first encrypted reader response
    uint32_t nr1_enc; // second encrypted reader challenge
    uint32_t ar1_enc; // second encrypted reader response
    uint32_t ks2_0;   // first keystream used to encrypt reader response
    uint32_t ks2_1;   // second keystream used to encrypt reader response

    printf("MIFARE Classic key recovery - based on 32 bits of keystream\n");
    printf("Recover key from two 32-bit reader authentication answers only!\n\n");

    if (argc < 7) {
        printf(" syntax: %s <uid> <nt> <{nr_0}> <{ar}_0> <{nr_1}> <{ar}_0>\n\n", argv[0]);
        return 1;
    }

    sscanf(argv[1], "%x", &uid);
    sscanf(argv[2], "%x", &nt);
    sscanf(argv[3], "%x", &nr0_enc);
    sscanf(argv[4], "%x", &ar0_enc);
    sscanf(argv[5], "%x", &nr1_enc);
    sscanf(argv[6], "%x", &ar1_enc);

    printf("Recovering key for:\n");
    printf("    uid: %08x\n", uid);
    printf("     nt: %08x\n", nt);
    printf(" {nr_0}: %08x\n", nr0_enc);
    printf(" {ar}_0: %08x\n", ar0_enc);
    printf(" {nr_1}: %08x\n", nr1_enc);
    printf(" {ar}_1: %08x\n", ar1_enc);

    // Generate lfsr successors of the tag challenge
    printf("\nLFSR successor of the tag challenge:\n");
    uint32_t ar = prng_successor(nt, 64);
    printf("     ar: %08x\n", ar);

    // Extract the keystream from the messages
    printf("\nKeystreams used to generate {ar}_0 and {ar}_1:\n");
    ks2_0 = ar0_enc ^ ar;
    printf("  ks2_0: %08x\n", ks2_0);
    ks2_1 = ar1_enc ^ ar;
    printf("  ks2_1: %08x\n", ks2_1);

    s = lfsr_recovery32(ks2_0, 0);

    for (t = s; t->odd | t->even; ++t) {
        lfsr_rollback_word(t, 0, 0);
        lfsr_rollback_word(t, nr0_enc, 1);
        lfsr_rollback_word(t, uid ^ nt, 0);
        crypto1_get_lfsr(t, &key);
        crypto1_word(t, uid ^ nt, 0);
        crypto1_word(t, nr1_enc, 1);
        if (ks2_1 == crypto1_word(t, 0, 0)) {
            printf("\nFound Key: [%012" PRIx64 "]\n\n", key);
            break;
        }
    }
    free(s);
    return 0;
}
