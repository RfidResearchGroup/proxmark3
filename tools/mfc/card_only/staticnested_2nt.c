#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "common.h"
#include "nested_util.h"
#include "crapto1/crapto1.h"


#define AEND  "\x1b[0m"
#define _RED_(s) "\x1b[31m" s AEND
#define _GREEN_(s) "\x1b[32m" s AEND
#define _YELLOW_(s) "\x1b[33m" s AEND
#define _CYAN_(s) "\x1b[36m" s AEND

static void pm3_staticnested(uint32_t uid, uint32_t nt1, uint32_t ks1,  uint32_t nt2, uint32_t ks2) {

    // calc keys
    struct Crypto1State *states = lfsr_recovery32_dual(ks1, nt1 ^ uid, ks2, nt2 ^ uid);
    if (states == NULL) {
        printf("Failed to allocate memory\n");
        return;
    }

    uint32_t keycnt = 0;
    for (struct Crypto1State *p = states; p->odd | p->even; p++) {
        keycnt++;
    }

    if (keycnt) {
        printf("PM3 Static nested --> Found " _YELLOW_("%u") " key candidates\n", keycnt);
        for (uint32_t k = 0; k < keycnt; k++) {
            uint64_t key64 = 0;
            lfsr_rollback_word(states + k, nt1 ^ uid, 0);
            crypto1_get_lfsr(states + k, &key64);
            printf("[ %u ] " _GREEN_("%012" PRIx64) "\n", k + 1, key64);
        }
    }
    free(states);
}

static int usage(const char *prog) {
    printf("\n");
    printf("\nProgram tries to recover keys from static encrypted nested MFC cards\n");
    printf("using two different implementations, Chameleon Ultra (CU) and Proxmark3.\n");
    printf("It uses the nonce, keystream sent from pm3 device to client.\n");
    printf("ie: NOT the CU data which is data in the trace.\n");
    printf("\n");
    printf("syntax:  %s <uid> <nt1> <ks1> <nt2> <ks2>\n\n", prog);
    printf("samples:\n");
    printf("\n");
    printf("  %s 461dce03 7eef3586 ffb02eda 322bc14d ffc875ca\n", prog);
    printf("  %s 461dce03 7eef3586 1fb6b496 322bc14d 1f4eebdd\n", prog);
    printf("  %s 461dce03 7eef3586 7fa28c7e 322bc14d 7f62b3d6\n", prog);
    printf("\n");
    return 1;
}

int main(int argc, char *const argv[]) {

    printf("\nMIFARE Classic static nested key recovery\n\n");

    if (argc < 5) return usage(argv[0]);

    printf("Init...\n");
    NtpKs1 *pNK = calloc(2, sizeof(NtpKs1));
    if (pNK == NULL) {
        printf("Failed to allocate memory\n");
        goto error;
    }

    uint32_t uid = 0;

    sscanf(argv[1], "%x", &uid);
    sscanf(argv[2], "%x", &pNK[0].ntp);
    sscanf(argv[3], "%x", &pNK[0].ks1);
    sscanf(argv[4], "%x", &pNK[1].ntp);
    sscanf(argv[5], "%x", &pNK[1].ks1);

    printf("uid... %08x\n", uid);
    printf("nt1... %08x\n", pNK[0].ntp);
    printf("ks1... %08x\n", pNK[0].ks1);
    printf("nt2... %08x\n", pNK[1].ntp);
    printf("ks2... %08x\n", pNK[1].ks1);

    // process all args.
    printf("Recovery...\n");

    uint32_t key_count = 0;
    uint64_t *keys = nested(pNK, 2, uid, &key_count);

    if (key_count) {
        printf("Ultra Static nested --> Found " _YELLOW_("%u") " key candidates\n", key_count);
        for (uint32_t k = 0; k < key_count; k++) {
            printf("[ %u ] " _GREEN_("%012" PRIx64) "\n", k + 1, keys[k]);
        }
    }

    pm3_staticnested(uid, pNK[0].ntp, pNK[0].ks1, pNK[1].ntp, pNK[1].ks1);

    fflush(stdout);
    free(keys);
    exit(EXIT_SUCCESS);
error:
    exit(EXIT_FAILURE);
}
