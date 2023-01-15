//
//  bruteforce the upper 16bits of a partial key recovered from  mf_nonce_brute.
//  J-run's original idea was a two part recovery vector with first a offline trace and then online for 2 bytes.
//
//  This idea is two use only offline, to recover a nested authentication key.
//  Assumption,  we get a read/write command after a nested auth,  we need 22 bytes of data.
//  Iceman, 2021,
//

#define __STDC_FORMAT_MACROS

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include "ctype.h"
#include "crapto1/crapto1.h"
#include "protocol.h"
#include "iso14443crc.h"
#include <util_posix.h>

#define AEND  "\x1b[0m"
#define _RED_(s) "\x1b[31m" s AEND
#define _GREEN_(s) "\x1b[32m" s AEND
#define _YELLOW_(s) "\x1b[33m" s AEND
#define _CYAN_(s) "\x1b[36m" s AEND

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
    uint16_t enc_len;
    uint8_t enc[ENC_LEN];  // next encrypted command + a full read/write
} targs;

//------------------------------------------------------------------
uint8_t cmds[8][2] = {
    {ISO14443A_CMD_READBLOCK, 18},
    {ISO14443A_CMD_WRITEBLOCK, 18},
    {MIFARE_AUTH_KEYA, 0},
    {MIFARE_AUTH_KEYB, 0},
    {MIFARE_CMD_INC, 6},
    {MIFARE_CMD_DEC, 6},
    {MIFARE_CMD_RESTORE, 6},
    {MIFARE_CMD_TRANSFER, 0}
};

static int global_found = 0;
static int thread_count = 2;

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
            // if we don't have space in buffer and have symbols to translate
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

    char *tmp_base = (char *)buf;
    char *tmp = tmp_base;
    size_t i;

    size_t max_len = (hex_len > hex_max_len) ? hex_max_len : hex_len;

    for (i = 0; i < max_len; ++i, tmp += 2 + spaces_between) {
        snprintf(tmp, hex_max_len - (tmp - tmp_base), (uppercase) ? "%02X" : "%02x", (unsigned int) hex_data[i]);

        for (size_t j = 0; j < spaces_between; j++)
            snprintf(tmp + 2 + j, hex_max_len - (2 + j + (tmp - tmp_base)), " ");
    }

    i *= (2 + spaces_between);

    size_t mlen = min_str_len > i ? min_str_len : 0;
    if (mlen > hex_max_len)
        mlen = hex_max_len;

    for (; i < mlen; i++, tmp += 1)
        snprintf(tmp, hex_max_len - (tmp - tmp_base), " ");

    // remove last space
    *tmp = '\0';
}

static char *sprint_hex_inrow_ex(const uint8_t *data, const size_t len, const size_t min_str_len) {
    static char buf[100] = {0};
    hex_to_buffer((uint8_t *)buf, data, len, sizeof(buf) - 1, min_str_len, 0, true);
    return buf;
}

static bool checkValidCmdByte(uint8_t *cmd, uint16_t n) {

    bool ok = false;
    if (cmd == NULL)
        return false;
    for (int i = 0; i < 8; ++i) {
        if (cmd[0] == cmds[i][0]) {

            if (n >= 4)
                ok = CheckCrc14443(CRC_14443_A, cmd, 4);

            if (cmds[i][1] > 0 && n >= cmds[i][1])
                ok = CheckCrc14443(CRC_14443_A, cmd + 4, cmds[i][1]);

            if (ok) {
                return true;
            }
        }
    }
    return false;
}

static void *brute_thread(void *arguments) {

    struct thread_args *args = (struct thread_args *) arguments;
    uint64_t key = args->part_key;
    uint8_t local_enc[args->enc_len];
    memcpy(local_enc, args->enc, args->enc_len);

    for (uint64_t count = args->idx; count < 0xFFFF; count += thread_count) {

        if (__atomic_load_n(&global_found, __ATOMIC_ACQUIRE) == 1) {
            break;
        }

        key |= count << 32;

        // Init cipher with key
        struct Crypto1State *pcs = crypto1_create(key);

        // NESTED decrypt nt with help of new key
        crypto1_word(pcs, args->nt_enc ^ args->uid, 1);
        crypto1_word(pcs, args->nr_enc, 1);
        crypto1_word(pcs, 0, 0);
        crypto1_word(pcs, 0, 0);

        // decrypt 22 bytes
        uint8_t dec[args->enc_len];
        for (int i = 0; i < args->enc_len; i++)
            dec[i] = crypto1_byte(pcs, 0x00, 0) ^ local_enc[i];

        crypto1_destroy(pcs);

        if (checkValidCmdByte(dec, args->enc_len) == false) {
            continue;
        }
        __sync_fetch_and_add(&global_found, 1);

        // lock this section to avoid interlacing prints from different threats
        pthread_mutex_lock(&print_lock);
        printf("\nenc:  %s\n", sprint_hex_inrow_ex(local_enc, args->enc_len, 0));
        printf("dec:  %s\n", sprint_hex_inrow_ex(dec, args->enc_len, 0));
        printf("\nValid Key found [ " _GREEN_("%012" PRIx64) " ]\n\n", key);
        pthread_mutex_unlock(&print_lock);
        break;
    }

    free(args);
    return NULL;
}

static int usage(void) {
    printf(" syntax: mf_trace_brute <uid> <partial key> <nt enc> <nr enc> [<next_command + 18 bytes>]\n\n");
    return 1;
}

int main(int argc, char *argv[]) {
    printf("Mifare classic nested auth key recovery Phase 2\n");
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
    printf("uid.................. %08x\n", uid);
    printf("partial key.......... %08x\n", part_key);
    printf("nt enc............... %08x\n", nt_enc);
    printf("nr enc............... %08x\n", nr_enc);
    printf("next encrypted cmd... %s\n", sprint_hex_inrow_ex(enc, enc_len, 0));

    uint64_t t1 = msclock();

#if !defined(_WIN32) || !defined(__WIN32__)
    thread_count = sysconf(_SC_NPROCESSORS_CONF);
    if (thread_count < 2)
        thread_count = 2;
#endif  /* _WIN32 */

    printf("\nBruteforce using %d threads to find upper 16bits of key\n", thread_count);

    pthread_t threads[thread_count];

    // create a mutex to avoid interlacing print commands from our different threads
    pthread_mutex_init(&print_lock, NULL);

    // threads
    for (int i = 0; i < thread_count; ++i) {
        struct thread_args *a = calloc(1, sizeof(struct thread_args));
        a->thread = i;
        a->idx = i;
        a->uid = uid;
        a->part_key = part_key;
        a->nt_enc = nt_enc;
        a->nr_enc = nr_enc;
        a->enc_len = enc_len;
        memcpy(a->enc, enc, enc_len);
        pthread_create(&threads[i], NULL, brute_thread, (void *)a);
    }

    // wait for threads to terminate:
    for (int i = 0; i < thread_count; ++i)
        pthread_join(threads[i], NULL);

    if (global_found == false) {
        printf("\nFailed to find a key\n\n");
    }

    t1 = msclock() - t1;
    if (t1 > 0)
        printf("execution time " _YELLOW_("%.2f") " sec\n", (float)t1 / 1000.0);

    // clean up mutex
    pthread_mutex_destroy(&print_lock);
    return 0;
}
