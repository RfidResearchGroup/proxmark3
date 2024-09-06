/*
 * ht2crack2search.c
 * this searches the sorted tables for the given RNG data, retrieves the matching
 * PRNG state, checks it is correct, and then rolls back the PRNG to recover the key
 *
 * Iceman 2024,
 * This is a multi threaded version. After discussions with mwalker33 about how to make this multi threaded
 * version he concluded that the file lookups would be ideal.  So we don't do it inside the individual file searches but
 * rather we can put each file to search in each thread instead. Come up with ways to make it faster!
 *
 * When testing remember OS cache fiddles with your mind and results. Running same test values will be much faster second run
 */

#include "ht2crackutils.h"
#include <pthread.h>
#include <stdbool.h>
#include <strings.h>

// a global mutex to prevent interlaced printing from different threads
pthread_mutex_t print_lock;

static int global_found = 0;
static int thread_count = 2;
static int g_bitoffset = 0;
static uint8_t g_rngmatch[6];
static uint8_t g_rngstate[6];

typedef struct {
    int len;
    uint8_t *data;
}  rngdata_t;

typedef struct thread_args {
    int thread;
    int idx;
    rngdata_t r;
} targs;

#define AEND            "\x1b[0m"
#define _RED_(s)        "\x1b[31m" s AEND
#define _GREEN_(s)      "\x1b[32m" s AEND
#define _YELLOW_(s)     "\x1b[33m" s AEND
#define _CYAN_(s)       "\x1b[36m" s AEND

#define INPUTFILE       "sorted/%02x/%02x.bin"
#define DATASIZE        10

static void print_hex(const uint8_t *data, const size_t len) {
    if (data == NULL || len == 0) return;

    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }

    printf("\n");
}

static int datacmp(const void *p1, const void *p2) {
    const void *d1 = p1;
    const void *d2 = p2;
    return memcmp(d1, d2, DATASIZE - 6);
}

static int loadrngdata(rngdata_t *r, char *file) {
    int fd;
    int i, j;
    int nibble;
    struct stat filestat;
    unsigned char *data;

    if (!r || !file) {
        printf("loadrngdata: invalid params\n");
        return 0;
    }

    fd = open(file, O_RDONLY);

    if (fd <= 0) {
        printf("cannot open file %s\n", file);
        exit(1);
    }

    if (fstat(fd, &filestat)) {
        printf("cannot stat file %s\n", file);
        exit(1);
    }

    if (filestat.st_size < 6) {
        printf("file %s is too small\n", file);
        exit(1);
    }

    data = mmap((caddr_t)0, filestat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        printf("cannot mmap file %s\n", file);
        exit(1);
    }

    r->len = filestat.st_size / 2;
//    printf("r->len = %d\n", r->len);

    r->data = (unsigned char *)calloc(1, r->len);
    if (!(r->data)) {
        printf("cannot calloc\n");
        exit(1);
    }

    j = 0;
    nibble = 0;
    for (i = 0; (i < filestat.st_size) && (j < r->len); i++) {
        if ((data[i] != 0x0a) && (data[i] != 0x0d) && (data[i] != 0x20)) {
            if (!nibble) {
                r->data[j] = hex2bin(data[i]) << 4;
                nibble = 1;
            } else {
                r->data[j] |= hex2bin(data[i]);
                nibble = 0;
                j++;
            }
        }
    }

    r->len = j;

    munmap(data, filestat.st_size);
    close(fd);

    return 1;
}

static int makecand(unsigned char *c, rngdata_t *r, int bitoffset) {
    int bytenum;
    int bitnum;
    int i;

    if (!c || !r || (bitoffset > ((r->len * 8) - 48))) {
        printf("makecand: invalid params\n");
        return 0;
    }

    bytenum = bitoffset / 8;
    bitnum = bitoffset % 8;

    for (i = 0; i < 6; i++) {
        if (!bitnum) {
            c[i] = r->data[bytenum + i];
        } else {
            c[i] = (r->data[bytenum + i] << bitnum) | (r->data[bytenum + i + 1] >> (8 - bitnum));
        }
    }

    return 1;
}

// test the candidate against the next or previous rng data
static int testcand(const unsigned char *f, const unsigned char *rt, int fwd) {
    Hitag_State hstate;
    int i;
    uint32_t ks1;
    uint32_t ks2;
    unsigned char buf[6];

    // build the prng state at the candidate
    hstate.shiftreg = 0;
    for (i = 0; i < 6; i++) {
        hstate.shiftreg = (hstate.shiftreg << 8) | f[i + 4];
    }
    buildlfsr(&hstate);

    if (fwd) {
        // roll forwards 48 bits
        hitag2_nstep(&hstate, 48);
    } else {
        // roll backwards 48 bits
        rollback(&hstate, 48);
        buildlfsr(&hstate);
    }

    // get 48 bits of RNG from the rolled to state
    ks1 = hitag2_nstep(&hstate, 24);
    ks2 = hitag2_nstep(&hstate, 24);

    writebuf(buf, ks1, 3);
    writebuf(buf + 3, ks2, 3);

    // compare them
    if (!memcmp(buf, rt, 6)) {
        return 1;
    } else {
        return 0;
    }
}

static int searchcand(unsigned char *c, unsigned char *rt, int fwd, unsigned char *m, unsigned char *s) {

    if (!c || !rt || !m || !s) {
        printf("searchcand: invalid params\n");
        return 0;
    }

    char file[64];
    unsigned char *data;
    unsigned char item[10];
    unsigned char *found = NULL;

    snprintf(file, sizeof(file), INPUTFILE, c[0], c[1]);

    int fd = open(file, O_RDONLY);
    if (fd <= 0) {
        printf("cannot open table file %s\n", file);
        exit(1);
    }

    struct stat filestat;
    if (fstat(fd, &filestat)) {
        printf("cannot stat file %s\n", file);
        exit(1);
    }

    data = mmap((caddr_t)0, filestat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        printf("cannot mmap file %s\n", file);
        exit(1);
    }

    memcpy(item, c + 2, 4);

    found = (unsigned char *)bsearch(item, data, filestat.st_size / DATASIZE, DATASIZE, datacmp);

    if (found) {

        // our candidate is in the table
        // go backwards and see if there are other matches
        while (((found - data) >= DATASIZE) && (!memcmp(found - DATASIZE, item, 4))) {
            found = found - DATASIZE;
        }

        // now test all matches
        while (((found - data) <= (filestat.st_size - DATASIZE)) && (!memcmp(found, item, 4))) {
            if (testcand(found, rt, fwd)) {
                memcpy(m, c, 2);
                memcpy(m + 2, found, 4);
                memcpy(s, found + 4, 6);

                munmap(data, filestat.st_size);
                close(fd);
                return 1;
            }

            found = found + DATASIZE;
        }
    }

    munmap(data, filestat.st_size);
    close(fd);

    return 0;

}

static void *brute_thread(void *arguments) {

    struct thread_args *args = (struct thread_args *) arguments;

    rngdata_t r;
    r.len = args->r.len;
    r.data = calloc(1, args->r.len);
    memcpy(r.data, args->r.data, args->r.len);

    int bitlen = (r.len * 8);

    for (int i = args->idx; i <= bitlen - 48; i += thread_count) {

        // print progress
        if ((i % 100) == 0) {
            pthread_mutex_lock(&print_lock);
            printf("searching on bit %d\n", i);
            pthread_mutex_unlock(&print_lock);
        }

        if (__atomic_load_n(&global_found, __ATOMIC_ACQUIRE) == 1) {
            break;
        }

        uint8_t l_cand[6] = {0};
        if (makecand(l_cand, &r, i) == 0) {
            pthread_mutex_lock(&print_lock);
            printf("cannot makecand, %d\n", i);
            pthread_mutex_unlock(&print_lock);
            break;
        }
//        printf("cand: %02x %02x %02x %02x %02x %02x : ", cand[0], cand[1], cand[2], cand[3], cand[4], cand[5]);
//        printbin(cand);

        int fwd = 0;
        /* make following or preceding RNG test data to confirm match */
        uint8_t l_rngtest[6] = {0};
        if (i < (bitlen - 96)) {

            if (makecand(l_rngtest, &r, i + 48) == 0) {
                pthread_mutex_lock(&print_lock);
                printf("cannot makecand rngtest %d + 48\n", i);
                pthread_mutex_unlock(&print_lock);
                break;
            }
            fwd = 1;

        } else {

            if (makecand(l_rngtest, &r, i - 48) == 0) {
                pthread_mutex_lock(&print_lock);
                printf("cannot makecand rngtest %d - 48\n", i);
                pthread_mutex_unlock(&print_lock);
                break;
            }
            fwd = 0;
        }

        uint8_t l_match[6] ;
        uint8_t l_state[6] ;
        if (searchcand(l_cand, l_rngtest, fwd, l_match, l_state)) {
            __sync_fetch_and_add(&global_found, 1);
            __sync_fetch_and_add(&g_bitoffset, i);
            memcpy(g_rngmatch, l_match, sizeof(l_match));
            memcpy(g_rngstate, l_state, sizeof(l_state));
            break;
        }
    }

    free(r.data);
    free(args->r.data);
    free(args);
    return NULL;
}

static void rollbackrng(Hitag_State *hstate, const unsigned char *s, int offset) {
    int i;

    if (!s) {
        printf("rollbackrng: invalid params\n");
        return;
    }

    // build prng at recovered offset
    hstate->shiftreg = 0;
    for (i = 0; i < 6; i++) {
        hstate->shiftreg = (hstate->shiftreg << 8) | s[i];
    }

    printf("recovered prng state at offset %d:\n", offset);
    printstate(hstate);

    // rollback to state after auth
    rollback(hstate, offset);

    // rollback through auth (aR, p3)
    rollback(hstate, 64);

    printf("prng state after initialisation:\n");
    printstate(hstate);


}

static uint64_t recoverkey(Hitag_State *hstate, char *uidstr, char *nRstr) {
    uint64_t key;
    uint64_t keyupper;
    uint32_t uid;
    uint32_t uidtmp;
    uint32_t nRenc;
    uint32_t nR;
    uint32_t nRxork;
    uint32_t b = 0;
    int i;

    // key lower 16 bits are lower 16 bits of prng state
    key = hstate->shiftreg & 0xffff;
    nRxork = (hstate->shiftreg >> 16) & 0xffffffff;
    uid = rev32(hexreversetoulong(uidstr));
    nRenc = rev32(hexreversetoulong(nRstr));

    uidtmp = uid;
    // rollback and extract bits b
    for (i = 0; i < 32; i++) {
        hstate->shiftreg = ((hstate->shiftreg) << 1) | ((uidtmp >> 31) & 0x1);
        uidtmp = uidtmp << 1;
        b = (b << 1) | fnf(hstate->shiftreg);
    }

    printf("end state:\n");
    printstate(hstate);
    printf("b:\t\t");
    printbin2(b, 32);
    printf("\n");
    printf("nRenc:\t\t");
    printbin2(nRenc, 32);
    printf("\n");

    nR = nRenc ^ b;

    printf("nR:\t\t");
    printbin2(nR, 32);
    printf("\n");

    keyupper = nRxork ^ nR;
    key = key | (keyupper << 16);
    printf("key:\t\t");
    printbin2(key, 48);
    printf("\n");

    return key;
}


int main(int argc, char *argv[]) {

    if (argc < 4) {
        printf("%s rngdatafile UID nR\n", argv[0]);
        exit(1);
    }

    rngdata_t rng;
    if (!loadrngdata(&rng, argv[1])) {
        printf("loadrngdata failed\n");
        exit(1);
    }

    char *uidstr;
    if (!strncmp(argv[2], "0x", 2)) {
        uidstr = argv[2] + 2;
    } else {
        uidstr = argv[2];
    }

    char *nRstr;
    if (!strncmp(argv[3], "0x", 2)) {
        nRstr = argv[3] + 2;
    } else {
        nRstr = argv[3];
    }

#if !defined(_WIN32) || !defined(__WIN32__)
    thread_count = sysconf(_SC_NPROCESSORS_CONF);
    if (thread_count < 2)
        thread_count = 2;
#endif  /* _WIN32 */

    printf("\nBruteforce using " _YELLOW_("%d") " threads\n", thread_count);

    pthread_t threads[thread_count];
    void *res;

    // create a mutex to avoid interlacing print commands from our different threads
    pthread_mutex_init(&print_lock, NULL);

    // findmatch(&rng, rngmatch, rngstate, &bitoffset)

    // threads
    for (int i = 0; i < thread_count; ++i) {
        targs *a = calloc(1, rng.len + sizeof(targs));
        a->r.data = calloc(1, rng.len);

        a->thread = i;
        a->idx = i;
        a->r.len = rng.len;
        memcpy(a->r.data, rng.data, rng.len);

        pthread_create(&threads[i], NULL, brute_thread, (void *)a);


    }

    // wait for threads to terminate:
    for (int i = 0; i < thread_count; ++i) {
        pthread_join(threads[i], &res);
        free(res);
    }

    if (global_found == false) {
        printf("\n" _RED_("!!!") " failed to find a key\n\n");
    } else {
        printf("Found match:\n");
        printf("rngmatch.... ");
        print_hex(g_rngmatch, sizeof(g_rngmatch));
        printf("rngstate.... ");
        print_hex(g_rngstate, sizeof(g_rngstate));
        printf("bitoffset... %d\n", g_bitoffset);

        Hitag_State hstate;
        rollbackrng(&hstate, g_rngstate, g_bitoffset);

        uint64_t keyrev = recoverkey(&hstate, uidstr, nRstr);
        uint64_t key = rev64(keyrev);

        printf("keyrev:\t\t");
        printbin2(key, 48);
        printf("\n");

        printf("KEY:\t\t");
        for (int i = 0; i < 6; i++) {
            printf("%02X", (int)(key & 0xff));
            key = key >> 8;
        }
        printf("\n");
    }
    // clean up mutex
    pthread_mutex_destroy(&print_lock);

    free(rng.data);
    return 0;
}


