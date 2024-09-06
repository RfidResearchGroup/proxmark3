#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include "common.h"
#include "nested_util.h"
#include "crapto1/crapto1.h"


#define AEND  "\x1b[0m"
#define _RED_(s) "\x1b[31m" s AEND
#define _GREEN_(s) "\x1b[32m" s AEND
#define _YELLOW_(s) "\x1b[33m" s AEND
#define _CYAN_(s) "\x1b[36m" s AEND

typedef struct {
    union {
        struct Crypto1State *slhead;
        uint64_t *keyhead;
    } head;
    union {
        struct Crypto1State *sltail;
        uint64_t *keytail;
    } tail;
    uint32_t len;
    uint32_t uid;
    uint32_t blockNo;
    uint32_t keyType;
    uint32_t nt_enc;
    uint32_t ks1;
} StateList_t;


inline static int compare_uint64(const void *a, const void *b) {
    if (*(uint64_t *)b == *(uint64_t *)a) return 0;
    if (*(uint64_t *)b < * (uint64_t *)a) return 1;
    return -1;
}

// Compare 16 Bits out of cryptostate
inline static int compare16Bits(const void *a, const void *b) {
    if ((*(uint64_t *)b & 0x00ff000000ff0000) == (*(uint64_t *)a & 0x00ff000000ff0000)) return 0;
    if ((*(uint64_t *)b & 0x00ff000000ff0000) > (*(uint64_t *)a & 0x00ff000000ff0000)) return 1;
    return -1;
}

// create the intersection (common members) of two sorted lists. Lists are terminated by -1. Result will be in list1. Number of elements is returned.
static uint32_t intersection(uint64_t *listA, uint64_t *listB) {
    if (listA == NULL || listB == NULL)
        return 0;

    uint64_t *p1, *p2, *p3;
    p1 = p3 = listA;
    p2 = listB;

    while (*p1 != UINT64_C(-1) && *p2 != UINT64_C(-1)) {
        if (compare_uint64(p1, p2) == 0) {
            *p3++ = *p1++;
            p2++;
        } else {
            while (compare_uint64(p1, p2) < 0) ++p1;
            while (compare_uint64(p1, p2) > 0) ++p2;
        }
    }
    *p3 = UINT64_C(-1);
    return p3 - listA;
}

// wrapper function for multi-threaded lfsr_recovery32
static void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
*nested_worker_thread(void *arg) {
    struct Crypto1State *p1;
    StateList_t *statelist = arg;
    statelist->head.slhead = lfsr_recovery32(statelist->ks1, statelist->nt_enc ^ statelist->uid);

    for (p1 = statelist->head.slhead; p1->odd | p1->even; p1++) {};

    statelist->len = p1 - statelist->head.slhead;
    statelist->tail.sltail = --p1;

    qsort(statelist->head.slhead, statelist->len, sizeof(uint64_t), compare16Bits);

    return statelist->head.slhead;
}

static void pm3_staticnested(uint32_t uid, uint32_t nt1, uint32_t ks1,  uint32_t nt2, uint32_t ks2) {

    StateList_t statelists[2];
    struct Crypto1State *p1, * p2, * p3, * p4;

    for (uint8_t i = 0; i < 2; i++) {
        statelists[i].uid = uid;
    }

    statelists[0].nt_enc = nt1;
    statelists[0].ks1 = ks1;
    statelists[1].nt_enc = nt2;
    statelists[1].ks1 = ks2;

    // calc keys
    pthread_t thread_id[2];

    // create and run worker threads
    for (uint8_t i = 0; i < 2; i++) {
        pthread_create(thread_id + i, NULL, nested_worker_thread, &statelists[i]);
    }

    // wait for threads to terminate:
    for (uint8_t i = 0; i < 2; i++) {
        pthread_join(thread_id[i], (void *)&statelists[i].head.slhead);
    }

    // the first 16 Bits of the cryptostate already contain part of our key.
    // Create the intersection of the two lists based on these 16 Bits and
    // roll back the cryptostate
    p1 = p3 = statelists[0].head.slhead;
    p2 = p4 = statelists[1].head.slhead;

    while (p1 <= statelists[0].tail.sltail && p2 <= statelists[1].tail.sltail) {
        if (compare16Bits(p1, p2) == 0) {

            struct Crypto1State savestate;
            savestate = *p1;

            while (compare16Bits(p1, &savestate) == 0 && p1 <= statelists[0].tail.sltail) {
                *p3 = *p1;
                lfsr_rollback_word(p3, statelists[0].nt_enc ^ statelists[0].uid, 0);
                p3++;
                p1++;
            }
            savestate = *p2;

            while (compare16Bits(p2, &savestate) == 0 && p2 <= statelists[1].tail.sltail) {
                *p4 = *p2;
                lfsr_rollback_word(p4, statelists[1].nt_enc ^ statelists[1].uid, 0);
                p4++;
                p2++;
            }
        } else {
            while (compare16Bits(p1, p2) == -1) p1++;
            while (compare16Bits(p1, p2) == 1) p2++;
        }
    }

    p3->odd = -1;
    p3->even = -1;
    p4->odd = -1;
    p4->even = -1;
    statelists[0].len = p3 - statelists[0].head.slhead;
    statelists[1].len = p4 - statelists[1].head.slhead;
    statelists[0].tail.sltail = --p3;
    statelists[1].tail.sltail = --p4;

    // the statelists now contain possible keys. The key we are searching for must be in the
    // intersection of both lists
    qsort(statelists[0].head.keyhead, statelists[0].len, sizeof(uint64_t), compare_uint64);
    qsort(statelists[1].head.keyhead, statelists[1].len, sizeof(uint64_t), compare_uint64);
    // Create the intersection
    statelists[0].len = intersection(statelists[0].head.keyhead, statelists[1].head.keyhead);

    uint32_t keycnt = statelists[0].len;
    if (keycnt) {
        printf("PM3 Static nested --> Found " _YELLOW_("%u") " key candidates\n", keycnt);
        for (uint32_t k = 0; k < keycnt; k++) {
            uint64_t key64 = 0;
            crypto1_get_lfsr(statelists[0].head.slhead + k, &key64);
            printf("[ %u ] " _GREEN_("%012" PRIx64) "\n", k + 1, key64);
        }
    }
}

static int usage(void) {
    printf("\n");
    printf("\nProgram tries to recover keys from static encrypted nested MFC cards\n");
    printf("using two different implementations, Chameleon Ultra (CU) and Proxmark3.\n");
    printf("It uses the nonce, keystream sent from pm3 device to client.\n");
    printf("ie: NOT the CU data which is data in the trace.\n");
    printf("\n");
    printf("syntax:  staticnested <uid> <nt1> <ks1> <nt2> <ks2>\n\n");
    printf("samples:\n");
    printf("\n");
    printf("  ./staticnested 461dce03 7eef3586 ffb02eda 322bc14d ffc875ca\n");
    printf("  ./staticnested 461dce03 7eef3586 1fb6b496 322bc14d 1f4eebdd\n");
    printf("  ./staticnested 461dce03 7eef3586 7fa28c7e 322bc14d 7f62b3d6\n");
    printf("\n");
    return 1;
}

int main(int argc, char *const argv[]) {

    printf("\nMIFARE Classic static nested key recovery\n\n");

    if (argc < 5) return usage();

    printf("Init...\n");
    NtpKs1 *pNK = calloc(2, sizeof(NtpKs1));
    if (pNK == NULL) {
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
