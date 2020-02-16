#include <stdio.h>
#include <stdlib.h>


#include "HardwareProfile.h"
#include "rfidler.h"
#include "hitagcrypto.h"
#include "util.h"



int main(int argc, char *argv[])
{
    Hitag_State hstate;
    FILE *fp;
    char *line = NULL;
    size_t linelen = 0;
    long len = 0;
    char *nr = NULL;
    char *ar = NULL;
    uint32_t arval;
    uint32_t ks;
    char *key;
    char *uid;

    if (argc < 4) {
        printf("ht2test nRaRfile KEY UID\n");
        exit(1);
    }

    fp = fopen(argv[1], "r");
    if (!fp) {
        printf("cannot open file\n");
        exit(1);
    }

    if (!strncmp(argv[2], "0x", 2)) {
        key = argv[2] + 2;
    } else {
        key = argv[2];
    }

    if (!strncmp(argv[3], "0x", 2)) {
        uid = argv[3] + 2;
    } else {
        uid = argv[3];
    }

    while ((len = getline(&line, &linelen, fp)) > 0) {
        if (len > 16) {
            ar = strchr(line, ' ');
            *ar = 0x00;
            ar++;
            ar[strlen(ar)-1] = 0x00;
            if (!strncmp(line, "0x", 2)) {
                nr = line + 2;
            } else {
                nr = line;
            }
            hitag2_init(&hstate, rev64(hexreversetoulonglong(key)), rev32(hexreversetoulong(uid)), rev32(hexreversetoulong(nr)));

            arval = strtol(ar, NULL, 16);
            ks = hitag2_nstep(&hstate, 32);


            if ((arval ^ ks) != 0xffffffff) {
                printf("FAIL! nR = %s, aR = %s\n", line, ar);
            } else {
                printf("SUCCESS! nR = %s, aR = %s\n", line, ar);
            }
        }
    }

    fclose(fp);

    return 0;
}

