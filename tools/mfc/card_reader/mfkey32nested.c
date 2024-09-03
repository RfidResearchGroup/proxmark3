//  Doegox, 2024, cf https://eprint.iacr.org/2024/1275 for more info

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
    uint32_t nt;      // tag nonce
    uint32_t nt_enc;  // encrypted tag nonce
    uint32_t nr_enc;  // encrypted reader nonce
    uint32_t ar;      // reader response
    uint32_t ar_enc;  // encrypted reader response
    uint32_t ks0;     // keystream used to encrypt tag nonce
    uint32_t ks2;     // keystream used to encrypt reader response

    printf("MIFARE Classic key recovery - known nT scenario\n");
    printf("Recover key from one reader authentication answer only\n");

    if (argc != 6) {
        printf("syntax: %s <uid> <nt> <{nt}> <{nr}> <{ar}>\n\n", argv[0]);
        return 1;
    }

    sscanf(argv[1], "%x", &uid);
    sscanf(argv[2], "%x", &nt);
    sscanf(argv[3], "%x", &nt_enc);
    sscanf(argv[4], "%x", &nr_enc);
    sscanf(argv[5], "%x", &ar_enc);

    printf("Recovering key for:\n");
    printf("    uid: %08x\n", uid);
    printf("     nt: %08x\n", nt);
    printf("   {nt}: %08x\n", nt_enc);
    printf("   {nr}: %08x\n", nr_enc);
    printf("   {ar}: %08x\n", ar_enc);

    printf("\nLFSR successor of the tag challenge:\n");
    ar = prng_successor(nt, 64);
    printf("     ar: %08x\n", ar);

    printf("\nKeystream used to generate {nt}:\n");
    ks0 = nt_enc ^ nt;
    printf("    ks0: %08x\n", ks0);
    printf("\nKeystream used to generate {ar}:\n");
    ks2 = ar_enc ^ ar;
    printf("    ks2: %08x\n", ks2);

    s = lfsr_recovery32(ks0, uid ^ nt);

    for (t = s; t->odd | t->even; ++t) {
        crypto1_word(t, nr_enc, 1);
        if (ks2 == crypto1_word(t, 0, 0)) {
            lfsr_rollback_word(t, 0, 0);
            lfsr_rollback_word(t, nr_enc, 1);
            lfsr_rollback_word(t, uid ^ nt, 0);
            crypto1_get_lfsr(t, &key);
            printf("\nFound Key: [%012" PRIx64 "]\n\n", key);
            break;
        }
    }
    free(s);
    return 0;
}
