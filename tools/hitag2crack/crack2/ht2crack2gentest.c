/*
 * ht2crack2gentests.c
 * this uses the RFIDler hitag2 PRNG code to generate test cases to test the tables
 */

#include "ht2crackutils.h"

static int makerandom(char *hex, unsigned int len, int fd) {
    unsigned char raw[32];
    int i;

    if (!hex) {
        printf("makerandom: hex is NULL\n");
        exit(1);
    }

    if (!len || (len > 32)) {
        printf("makerandom: len must be between 1 and 32 inclusive\n");
        exit(1);
    }

    if (read(fd, raw, len) != len) {
        printf("makerandom: cannot read random bytes\n");
        exit(1);
    }

    for (i = 0; i < len; i++) {
        snprintf(hex + (2 * i), 3, "%02X", raw[i]);
    }

    return 1;
}


int main(int argc, char *argv[]) {
    Hitag_State hstate;
    char key[32];
    char uid[32];
    char nR[32];
    char filename[256];
    int i, j;
    int numtests;
    int urandomfd;

    if (argc < 2) {
        printf("%s number\n", argv[0]);
        exit(1);
    }

    numtests = atoi(argv[1]);
    if (numtests <= 0) {
        printf("need positive number of tests\n");
        exit(1);
    }

    urandomfd = open("/dev/urandom", O_RDONLY);
    if (urandomfd <= 0) {
        printf("cannot open /dev/urandom\n");
        exit(1);
    }


    for (i = 0; i < numtests; i++) {

        makerandom(key, 6, urandomfd);
        makerandom(uid, 4, urandomfd);
        makerandom(nR, 4, urandomfd);
        snprintf(filename, sizeof(filename), "keystream.key-%s.uid-%s.nR-%s", key, uid, nR);

        FILE *fp = fopen(filename, "w");
        if (!fp) {
            printf("cannot open file '%s' for writing\n", filename);
            exit(1);
        }

        hstate.shiftreg = 0;
        hstate.lfsr = 0;

        hitag2_init(&hstate, rev64(hexreversetoulonglong(key)), rev32(hexreversetoulong(uid)), rev32(hexreversetoulong(nR)));

        hitag2_nstep(&hstate, 64);

        for (j = 0; j < 64; j++) {
            fprintf(fp, "%08X\n", hitag2_nstep(&hstate, 32));
        }

        fclose(fp);
    }
    return 0;
}


