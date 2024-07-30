
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

static uint32_t hex_to_uint32(const char *hex_str) {
    return (uint32_t)strtoul(hex_str, NULL, 16);
}

uint16_t i_lfsr16[1 << 16] = {0};
uint16_t s_lfsr16[1 << 16] = {0};

static void init_lfsr16_table(void) {
    uint16_t x = 1;
    for (uint16_t i=1; i; ++i) {
        i_lfsr16[(x & 0xff) << 8 | x >> 8] = i;
        s_lfsr16[i] = (x & 0xff) << 8 | x >> 8;
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
    }
}

// static uint16_t next_lfsr16(uint16_t nonce) {
//     return s_lfsr16[(i_lfsr16[nonce]+1) % 65535];
// }

static uint16_t prev_lfsr16(uint16_t nonce) {
    return s_lfsr16[(i_lfsr16[nonce]-1) % 65535];
}

static uint16_t compute_seednt16_nt32(uint32_t nt32, uint64_t key) {
    uint8_t a[] = {0, 8, 9, 4, 6, 11, 1, 15, 12, 5, 2, 13, 10, 14, 3, 7};
    uint8_t b[] = {0, 13, 1, 14, 4, 10, 15, 7, 5, 3, 8, 6, 9, 2, 12, 11};
    uint16_t nt = nt32 >> 16;
    uint8_t prev = 14;
    for (uint8_t i=0; i<prev; i++) {
        nt = prev_lfsr16(nt);
    }
    uint8_t prevoff = 8;
    bool odd = 1;

    for (uint8_t i=0; i<6*8; i+=8) {
        if (odd) {
            nt ^= (a[(key >> i) & 0xF]);
            nt ^= (b[(key >> i >> 4) & 0xF]) << 4;
        } else {
            nt ^= (b[(key >> i) & 0xF]);
            nt ^= (a[(key >> i >> 4) & 0xF]) << 4;
        }
        odd ^= 1;
        prev += prevoff;
        for (uint8_t j=0; j<prevoff; j++) {
            nt = prev_lfsr16(nt);
        }
    }
    return nt;
}

int main(int argc, char *const argv[]) {
    if (argc != 4) {
        printf("Usage:\n  %s <nt1:08x> <key1:012x> keys_<uid:08x>_<sector:02>_<nt2:08x>.dic\n"
               "  where dict file is produced by rf08s_nested_known *for the same UID and same sector* as provided nt and key\n",
               argv[0]);
        return 1;
    }
    uint32_t nt1 = hex_to_uint32(argv[1]);
    uint64_t key1 = 0;
    if (sscanf(argv[2], "%012" PRIx64, &key1) != 1) {
        fprintf(stderr, "Failed to parse key: %s", argv[2]);
        return 1;
    }

    char *filename= argv[3];
    uint32_t uid, sector, nt2;

    int result;
    result = sscanf(filename, "keys_%8x_%2d_%8x.dic", &uid, &sector, &nt2);
    if (result != 3) {
        fprintf(stderr, "Error: Failed to parse the filename %s.\n", filename);
        return 1;
    }
    if (nt1 == nt2) {
        fprintf(stderr, "Error: File must belong to different nonce.\n");
        return 1;
    }

    init_lfsr16_table();

    uint32_t keycount2 = 0;
    uint64_t* keys2 = NULL;

    FILE* fptr = fopen(filename, "r");
    if (fptr != NULL) {
        uint64_t buffer;
        while (fscanf(fptr, "%012" PRIx64, &buffer) == 1) {
            keycount2++;
        }

        keys2 = (uint64_t*)malloc(keycount2 * sizeof(uint64_t));
        if (keys2 == NULL) {
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
        fprintf(stderr, "Warning: Cannot open %s\n", filename);
        goto end;
    }

    printf("%s: %i keys loaded\n", filename, keycount2);

    uint32_t found = 0;
    uint16_t seednt1 = compute_seednt16_nt32(nt1, key1);
    for (uint32_t i = 0; i < keycount2; i++) {
        if (seednt1 == compute_seednt16_nt32(nt2, keys2[i])) {
            printf("MATCH: key2=%012" PRIx64 "\n", keys2[i]);
            found++;
        }
    }
    if (!found) {
        printf("No key found :(\n");
    }

end:
    if (keys2 != NULL)
        free(keys2);

    return 0;
}
