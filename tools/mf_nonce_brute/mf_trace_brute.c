//
//  bruteforce the upper 16bits of a partial key recovered from  mf_nonce_brute.
//  J-run's original idea was a two part recovery vector with first a offline trace and then online for 2 bytes.
//
//  This idea is two use only offline, to recover a nested authentication key.
//  Assumption,  we get a read/write command after a nested auth,  we need 22 bytes of data.
//  Iceman, 2021,
//

#define __STDC_FORMAT_MACROS

#if !defined(_WIN64)
#if defined(_WIN32) || defined(__WIN32__)
# define _USE_32BIT_TIME_T 1
#endif
#endif

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include "ctype.h"
#include <time.h>
#include "crapto1/crapto1.h"
#include "protocol.h"
#include "iso14443crc.h"

// a global mutex to prevent interlaced printing from different threads
pthread_mutex_t print_lock;

#define ENC_LEN  (4 + 16 + 2)
//--------------------- define options here

typedef struct thread_args {
    int thread;
    int idx;
    uint32_t uid;
    uint32_t part_key;
    uint32_t nt_enc;
    uint32_t nr_enc;
    uint8_t enc[ENC_LEN];  // next encrypted command + a full read/write
} targs;

//------------------------------------------------------------------
uint8_t cmds[] = {
    ISO14443A_CMD_READBLOCK,
    ISO14443A_CMD_WRITEBLOCK,
    MIFARE_AUTH_KEYA,
    MIFARE_AUTH_KEYB,
    MIFARE_CMD_INC,
    MIFARE_CMD_DEC,
    MIFARE_CMD_RESTORE,
    MIFARE_CMD_TRANSFER
};

int global_counter = 0;
int global_fin_flag = 0;
int global_found = 0;
int global_found_candidate = 0;
size_t thread_count = 2;

static int param_getptr(const char *line, int *bg, int *en, int paramnum) {
    int i;
    int len = strlen(line);

    *bg = 0;
    *en = 0;

    // skip spaces
    while (line[*bg] == ' ' || line[*bg] == '\t')(*bg)++;
    if (*bg >= len) {
        return 1;
    }

    for (i = 0; i < paramnum; i++) {
        while (line[*bg] != ' ' && line[*bg] != '\t' && line[*bg] != '\0')(*bg)++;
        while (line[*bg] == ' ' || line[*bg] == '\t')(*bg)++;

        if (line[*bg] == '\0') return 1;
    }

    *en = *bg;
    while (line[*en] != ' ' && line[*en] != '\t' && line[*en] != '\0')(*en)++;

    (*en)--;

    return 0;
}

static int param_gethex_to_eol(const char *line, int paramnum, uint8_t *data, int maxdatalen, int *datalen) {
    int bg, en;
    uint32_t temp;
    char buf[5] = {0};

    if (param_getptr(line, &bg, &en, paramnum)) return 1;

    *datalen = 0;

    int indx = bg;
    while (line[indx]) {
        if (line[indx] == '\t' || line[indx] == ' ') {
            indx++;
            continue;
        }

        if (isxdigit(line[indx])) {
            buf[strlen(buf) + 1] = 0x00;
            buf[strlen(buf)] = line[indx];
        } else {
            // if we have symbols other than spaces and hex
            return 1;
        }

        if (*datalen >= maxdatalen) {
            // if we dont have space in buffer and have symbols to translate
            return 2;
        }

        if (strlen(buf) >= 2) {
            sscanf(buf, "%x", &temp);
            data[*datalen] = (uint8_t)(temp & 0xff);
            *buf = 0;
            (*datalen)++;
        }

        indx++;
    }

    if (strlen(buf) > 0)
        //error when not completed hex bytes
        return 3;

    return 0;
}

static void hex_to_buffer(const uint8_t *buf, const uint8_t *hex_data, const size_t hex_len, const size_t hex_max_len,
                          const size_t min_str_len, const size_t spaces_between, bool uppercase) {

    if (buf == NULL) return;

    char *tmp = (char *)buf;
    size_t i;
    memset(tmp, 0x00, hex_max_len);

    size_t max_len = (hex_len > hex_max_len) ? hex_max_len : hex_len;

    for (i = 0; i < max_len; ++i, tmp += 2 + spaces_between) {
        sprintf(tmp, (uppercase) ? "%02X" : "%02x", (unsigned int) hex_data[i]);

        for (size_t j = 0; j < spaces_between; j++)
            sprintf(tmp + 2 + j, " ");
    }

    i *= (2 + spaces_between);

    size_t mlen = min_str_len > i ? min_str_len : 0;
    if (mlen > hex_max_len)
        mlen = hex_max_len;

    for (; i < mlen; i++, tmp += 1)
        sprintf(tmp, " ");

    // remove last space
    *tmp = '\0';
    return;
}

static char *sprint_hex_inrow_ex(const uint8_t *data, const size_t len, const size_t min_str_len) {
    static char buf[100] = {0};
    hex_to_buffer((uint8_t *)buf, data, len, sizeof(buf) - 1, min_str_len, 0, true);
    return buf;
}

static void *brute_thread(void *arguments) {

    //int shift = (int)arg;
    struct thread_args *args = (struct thread_args *) arguments;

    uint64_t key;     // recovered key candidate
    int found = 0;
    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs = &mpcs;

    uint8_t local_enc[ENC_LEN] = {0};
    memcpy(local_enc, args->enc, sizeof(local_enc));

    for (uint64_t count = args->idx; count < 0xFFFF; count += thread_count) {

        found = global_found;
        if (found) {
            break;
        }

        key = (count << 32 | args->part_key);

        // Init cipher with key
        pcs = crypto1_create(key);

        // NESTED decrypt nt with help of new key
//        if (args->use_nested)
//            crypto1_word(pcs, args->nt_enc ^ args->uid, 1) ^ args->nt_enc;
//        else
        crypto1_word(pcs, args->nt_enc ^ args->uid, 1);

        crypto1_word(pcs, args->nr_enc, 1);
        crypto1_word(pcs, 0, 0);
        crypto1_word(pcs, 0, 0);

        // decrypt 22 bytes
        uint8_t dec[ENC_LEN] = {0};
        for (int i = 0; i < ENC_LEN; i++)
            dec[i] = crypto1_byte(pcs, 0x00, 0) ^ local_enc[i];

        crypto1_deinit(pcs);

        if (CheckCrc14443(CRC_14443_A, dec, 4)) {

            // check crc-16 in the end

            if (CheckCrc14443(CRC_14443_A, dec + 4, 18)) {

                // lock this section to avoid interlacing prints from different threats
                pthread_mutex_lock(&print_lock);
                printf("\nValid Key found: [%012" PRIx64 "]\n", key);

                printf("enc:  %s\n", sprint_hex_inrow_ex(local_enc, ENC_LEN, 0));
                printf("      xx  crcA                                crcA\n");
                printf("dec:  %s\n", sprint_hex_inrow_ex(dec, ENC_LEN, 0));
                pthread_mutex_unlock(&print_lock);

                __sync_fetch_and_add(&global_found, 1);
            }
        }
    }
    free(args);
    return NULL;
}

static int usage(void) {
    printf(" syntax: mf_trace_brute <uid> <partial key> <nt enc> <nr enc> [<next_command + 18 bytes>]\n\n");
    return 1;
}

int main(int argc, char *argv[]) {
    printf("Mifare classic nested auth key recovery. Phase 2.\n");
    if (argc < 3) return usage();

    uint32_t uid = 0;      // serial number
    uint32_t part_key = 0; // last 4 keys of key
    uint32_t nt_enc = 0;   // noncce tag
    uint32_t nr_enc = 0;   // nonce reader encrypted

    sscanf(argv[1], "%x", &uid);
    sscanf(argv[2], "%x", &part_key);
    sscanf(argv[3], "%x", &nt_enc);
    sscanf(argv[4], "%x", &nr_enc);

    int enc_len = 0;
    uint8_t enc[ENC_LEN] = {0};  // next encrypted command + a full read/write
    param_gethex_to_eol(argv[5], 0, enc, sizeof(enc), &enc_len);

    printf("-------------------------------------------------\n");
    printf("uid.......... %08x\n", uid);
    printf("partial key.. %08x\n", part_key);
    printf("nt enc....... %08x\n", nt_enc);
    printf("nr enc....... %08x\n", nr_enc);
    printf("next encrypted cmd: %s\n", sprint_hex_inrow_ex(enc, ENC_LEN, 0));

    clock_t t1 = clock();

#if !defined(_WIN32) || !defined(__WIN32__)
    thread_count = sysconf(_SC_NPROCESSORS_CONF);
    if (thread_count < 2)
        thread_count = 2;
#endif  /* _WIN32 */

    printf("\nBruteforce using %zu threads to find upper 16bits of key\n", thread_count);

    pthread_t threads[thread_count];

    // create a mutex to avoid interlacing print commands from our different threads
    pthread_mutex_init(&print_lock, NULL);

    // threads
    for (int i = 0; i < thread_count; ++i) {
        struct thread_args *a = malloc(sizeof(struct thread_args));
        a->thread = i;
        a->idx = i;
        a->uid = uid;
        a->part_key = part_key;
        a->nt_enc = nt_enc;
        a->nr_enc = nr_enc;
        memcpy(a->enc, enc, sizeof(a->enc));
        pthread_create(&threads[i], NULL, brute_thread, (void *)a);
    }

    // wait for threads to terminate:
    for (int i = 0; i < thread_count; ++i)
        pthread_join(threads[i], NULL);

    if (!global_found && !global_found_candidate) {
        printf("\nFailed to find a key\n\n");
    }

    t1 = clock() - t1;
    if (t1 > 0)
        printf("Execution time: %.0f ticks\n", (float)t1);

    // clean up mutex
    pthread_mutex_destroy(&print_lock);
    return 0;
}
