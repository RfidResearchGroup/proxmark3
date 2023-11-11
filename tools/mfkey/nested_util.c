#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <ctype.h>
#include "parity.h"

#ifdef __WIN32
#include "windows.h"
#else
#include "unistd.h"
#endif

#include "pthread.h"
#include "nested_util.h"


#define MEM_CHUNK               10000
#define TRY_KEYS                50


typedef struct {
    uint64_t       key;
    int            count;
} countKeys;

typedef struct {
    NtpKs1 *pNK;
    uint32_t authuid;

    uint64_t *keys;
    uint32_t keyCount;

    uint32_t startPos;
    uint32_t endPos;
} RecPar;


static int compar_int(const void *a, const void *b) {
    return (*(uint64_t *)b - * (uint64_t *)a);
}

// Compare countKeys structure
static int compar_special_int(const void *a, const void *b) {
    return (((countKeys *)b)->count - ((countKeys *)a)->count);
}

// keys qsort and unique.
static countKeys *uniqsort(uint64_t *possibleKeys, uint32_t size) {
    unsigned int i, j = 0;
    int count = 0;
    countKeys *our_counts;

    qsort(possibleKeys, size, sizeof(uint64_t), compar_int);

    our_counts = calloc(size, sizeof(countKeys));
    if (our_counts == NULL) {
        printf("Memory allocation error for our_counts");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < size; i++) {
        if (possibleKeys[i + 1] == possibleKeys[i]) {
            count++;
        } else {
            our_counts[j].key = possibleKeys[i];
            our_counts[j].count = count;
            j++;
            count = 0;
        }
    }
    qsort(our_counts, j, sizeof(countKeys), compar_special_int);
    return (our_counts);
}

// nested decrypt
static void *nested_revover(void *args) {
    struct Crypto1State *revstate, * revstate_start = NULL;
    uint64_t lfsr = 0;
    uint32_t i, kcount = 0;
    bool is_ok = true;

    RecPar *rp = (RecPar *)args;

    rp->keyCount = 0;
    rp->keys = NULL;

    //printf("Start pos is %d, End pos is %d\r\n", rp->startPos, rp->endPos);

    for (i = rp->startPos; i < rp->endPos; i++) {
        uint32_t nt_probe = rp->pNK[i].ntp ^ rp->authuid;
        uint32_t ks1 = rp->pNK[i].ks1;

        /*
        printf("     ntp = %"PRIu32"\r\n", nt_probe);
        printf("     ks1 = %"PRIu32"\r\n", ks1);
        printf("\r\n");
        */

        // And finally recover the first 32 bits of the key
        revstate = lfsr_recovery32(ks1, nt_probe);
        if (revstate_start == NULL) {
            revstate_start = revstate;
        }

        while ((revstate->odd != 0x0) || (revstate->even != 0x0)) {
            lfsr_rollback_word(revstate, nt_probe, 0);
            crypto1_get_lfsr(revstate, &lfsr);
            if (((kcount % MEM_CHUNK) == 0) || (kcount >= rp->keyCount)) {
                rp->keyCount += MEM_CHUNK;
                // printf("New chunk by %d, sizeof %lu\n", kcount, rp->keyCount * sizeof(uint64_t));
                void *tmp = realloc(rp->keys, rp->keyCount * sizeof(uint64_t));
                if (tmp == NULL) {
                    printf("Memory allocation error for pk->possibleKeys");
                    rp->keyCount = 0;
                    is_ok = false;
                    break;
                }
                rp->keys = (uint64_t *)tmp;
            }
            rp->keys[kcount] = lfsr;
            kcount++;
            revstate++;
        }
        --kcount;
        free(revstate_start);
        revstate_start = NULL;
        if (!is_ok) {
            break;
        }
    }
    if (is_ok) {
        if (kcount != 0) {
            rp->keyCount = kcount;
            void *tmp = (uint64_t *)realloc(rp->keys, rp->keyCount * sizeof(uint64_t));
            if (tmp == NULL) {
                printf("Memory allocation error for pk->possibleKeys");
                rp->keyCount = 0;
                free(rp->keys);
            } else {
                rp->keys = tmp;
            }
        }
    } else {
        rp->keyCount = 0;
        free(rp->keys);
    }
    return NULL;
}

uint64_t *nested(NtpKs1 *pNK, uint32_t sizePNK, uint32_t authuid, uint32_t *keyCount) {
#define THREAD_MAX 4

    *keyCount = 0;
    uint32_t i, j, manyThread;
    uint64_t *keys = (uint64_t *)NULL;

    manyThread = THREAD_MAX;
    if (manyThread > sizePNK) {
        manyThread = sizePNK;
    }

    // pthread handle
    pthread_t *threads = calloc(sizePNK, sizeof(pthread_t));
    if (threads == NULL)  return NULL;

    // Param
    RecPar *pRPs = calloc(sizePNK, sizeof(RecPar));
    if (pRPs == NULL) {
        free(threads);
        return NULL;
    }

    uint32_t average = sizePNK / manyThread;
    uint32_t modules = sizePNK % manyThread;

    // Assign tasks
    for (i = 0, j = 0; i < manyThread; i++, j += average) {
        pRPs[i].pNK = pNK;
        pRPs[i].authuid = authuid;
        pRPs[i].startPos = j;
        pRPs[i].endPos = j + average;
        pRPs[i].keys = NULL;
        // last thread can decrypt more pNK
        if (i == (manyThread - 1) && modules > 0) {
            (pRPs[i].endPos) += modules;
        }
        pthread_create(&threads[i], NULL, nested_revover, &(pRPs[i]));
    }

    for (i = 0; i < manyThread; i++) {
        // wait thread exit...
        pthread_join(threads[i], NULL);
        *keyCount += pRPs[i].keyCount;
    }
    free(threads);

    if (*keyCount == 0) {
        printf("Didn't recover any keys.\r\n");
        free(pRPs);
        return NULL;
    }

    keys = calloc((*keyCount) * sizeof(uint64_t), sizeof(uint8_t));
    if (keys == NULL) {
        printf("Cannot allocate memory to merge keys.\r\n");
        free(pRPs);
        return NULL;
    }

    for (i = 0, j = 0; i < manyThread; i++) {
        if (pRPs[i].keyCount > 0) {
            // printf("The thread %d recover %d keys.\r\n", i, pRPs[i].keyCount);
            if (pRPs[i].keys != NULL) {
                memcpy(
                    keys + j,
                    pRPs[i].keys,
                    pRPs[i].keyCount * sizeof(uint64_t)
                );
                j += pRPs[i].keyCount;
                free(pRPs[i].keys);
            }
        }
    }

    countKeys *ck = uniqsort(keys, *keyCount);
    free(keys);
    keys = (uint64_t *)NULL;
    *keyCount = 0;

    if (ck == NULL) {
        printf("Cannot allocate memory for ck on uniqsort.");
        free(ck);
        free(pRPs);
        return NULL;
    }
    
    for (i = 0; i < TRY_KEYS; i++) {
        // We don't known this key, try to break it
        // This key can be found here two or more times
        if (ck[i].count > 0) {
            *keyCount += 1;
            void *tmp = realloc(keys, sizeof(uint64_t) * (*keyCount));
            if (tmp == NULL) {
                printf("Cannot allocate memory for keys on merge.");
                free(ck);
                free(keys);
                free(pRPs);
                return NULL;
            }

            keys = tmp;
            keys[*keyCount - 1] = ck[i].key;
        }
    }

    free(ck);
    free(pRPs);
    return keys;
}

// Return 1 if the nonce is invalid else return 0
uint8_t valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, uint8_t *parity) {
    return (
               (oddparity8((Nt >> 24) & 0xFF) == ((parity[0]) ^ oddparity8((NtEnc >> 24) & 0xFF) ^ BIT(Ks1, 16))) && \
               (oddparity8((Nt >> 16) & 0xFF) == ((parity[1]) ^ oddparity8((NtEnc >> 16) & 0xFF) ^ BIT(Ks1, 8))) && \
               (oddparity8((Nt >> 8) & 0xFF) == ((parity[2]) ^ oddparity8((NtEnc >> 8) & 0xFF) ^ BIT(Ks1, 0)))
           ) ? 1 : 0;
}
