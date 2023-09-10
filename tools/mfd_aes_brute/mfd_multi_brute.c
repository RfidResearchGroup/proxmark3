//  MIFARE bruteforce tool
//  It's Multi threaded and supports all DES/2TDEA/3TDEA/AES crypto authentication modes.
//  also supports six different LCG random generators.
//  as a consequece this tools also work on MIFARE Ultralight-C challenges
//
//
//  Based upon the bruteforcer from X41 D-Sec Gmbh
//
//  Copyright Iceman 2022
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
//#include <mbedtls/aes.h>
#include "util_posix.h"
#include "randoms.h"

#include "aes-ni.h"

#if defined(__APPLE__) || defined(__MACH__)
#else
#include "detectaes.h"
#endif


#define AEND  "\x1b[0m"
#define _RED_(s) "\x1b[31m" s AEND
#define _GREEN_(s) "\x1b[32m" s AEND
#define _YELLOW_(s) "\x1b[33m" s AEND
#define _CYAN_(s) "\x1b[36m" s AEND


static generator_t generators[] = {
    {"Borland",      make_key_borland_n},
    {"Recipies",     make_key_recipies_n},
    {"GlibC",        make_key_glibc_n},
    {"AnsiC",        make_key_ansic_n},
    {"Turbo Pascal", make_key_turbopascal_n},
    {"posix rand_r",          make_key_posix_rand_r_n},
    {"MS Visual/Quick C/C++",  make_key_ms_rand_r_n},
    {NULL, NULL}
};

#define ARRAYLEN(x) (sizeof(x)/sizeof((x)[0]))

// a global mutex to prevent interlaced printing from different threads
pthread_mutex_t print_lock;

static int global_found = 0;
static int thread_count = 2;

typedef struct thread_args {
    int thread;
    int idx;
    uint8_t generator_idx;
    uint8_t algo;
    uint64_t starttime;
    uint64_t stoptime;
    uint8_t tag[16];
    uint8_t rdr[32];
} targs;


// source https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Decrypting_the_Message
static void decrypt_aes(uint8_t ciphertext[], int ciphertext_len, uint8_t key[], uint8_t iv[], uint8_t plaintext[]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
//    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int len = 0;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

static void decrypt_3kdes(uint8_t ciphertext[], int ciphertext_len, uint8_t key[], uint8_t iv[], uint8_t plaintext[]) {
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int len = 0;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

static void decrypt_2kdes(uint8_t ciphertext[], int ciphertext_len, uint8_t key[], uint8_t iv[], uint8_t plaintext[]) {
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int len = 0;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

static void decrypt_des(uint8_t ciphertext[], int ciphertext_len, uint8_t key[], uint8_t iv[], uint8_t plaintext[]) {
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int len = 0;
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

static int hexstr_to_byte_array(char hexstr[], uint8_t bytes[], size_t byte_len) {
    size_t hexstr_len = strlen(hexstr);
    if (hexstr_len % 16) {
        return 1;
    }

    if (byte_len < (hexstr_len / 2)) {
        return 2;
    }

    char *pos = &hexstr[0];
    for (size_t count = 0; *pos != 0; count++) {
        sscanf(pos, "%2hhx", &bytes[count]);
        pos += 2;
    }
    return 0;
}

static void print_hex(const uint8_t *data, const size_t len) {
    if (data == NULL || len == 0) return;

    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }

    printf("\n");
}

static void print_time(uint64_t at) {

    time_t t = at;
    struct tm lt;

#if defined(_WIN32)
    (void)localtime_s(&lt, &t);
#else
    (void)localtime_r(&t, &lt);
#endif

    char res[70];
#if defined(__MINGW32__) || defined(__MINGW64__)
    strftime(res, sizeof(res), "('%Y-%m-%d %H:%M:%S')", &lt);
#else
    strftime(res, sizeof(res), "%s ('%Y-%m-%d %H:%M:%S')", &lt);
#endif
    printf("%s\n", res);
}

static void *brute_thread(void *arguments) {

    //const bool support_aesni = platform_aes_hw_available();

    struct thread_args *args = (struct thread_args *) arguments;

    uint64_t starttime = args->starttime;
    uint64_t stoptime = args->stoptime;
    uint8_t local_algo = args->algo;
    uint8_t gidx = args->generator_idx;
    uint8_t local_tag[16];
    uint8_t local_rdr[32];
    uint8_t keylen = 16;

    if (local_algo == 0) {
        memcpy(local_tag, args->tag, 8);
        memcpy(local_rdr, args->rdr, 16);
        keylen = 8;
    } else if (local_algo == 1) {
        memcpy(local_tag, args->tag, 8);
        memcpy(local_rdr, args->rdr, 16);
        keylen = 16;
    } else if (local_algo == 2) {
        memcpy(local_tag, args->tag, 16);
        memcpy(local_rdr, args->rdr, 32);
        keylen = 24;
    } else if (local_algo == 3) {
        memcpy(local_tag, args->tag, 16);
        memcpy(local_rdr, args->rdr, 32);
        keylen = 16;
    }

    for (uint64_t i = starttime + args->idx; i < stoptime; i += thread_count) {

        if (__atomic_load_n(&global_found, __ATOMIC_ACQUIRE) == 1) {
            break;
        }

        uint8_t key[keylen];
        generators[gidx].Parse(i, key, keylen);
        //make_key_borland_n(i, key, keylen);

        uint8_t iv[keylen << 1];
        uint8_t dec_tag[16] = {0x00};
        uint8_t dec_rdr[32] = {0x00};

        if (local_algo == 0) {
            decrypt_des(local_tag, 8, key, iv, dec_tag);
            decrypt_des(local_rdr, 16, key, local_tag, dec_rdr);

            // check rol byte first
            if (dec_tag[0] != dec_rdr[15]) continue;

            // compare rest
            if (dec_tag[1] != dec_rdr[8]) continue;
            if (dec_tag[2] != dec_rdr[9]) continue;
            if (dec_tag[3] != dec_rdr[10]) continue;
            if (dec_tag[4] != dec_rdr[11]) continue;
            if (dec_tag[5] != dec_rdr[12]) continue;
            if (dec_tag[6] != dec_rdr[13]) continue;
            if (dec_tag[7] != dec_rdr[14]) continue;

        } else if (local_algo == 1) {
            decrypt_2kdes(local_tag, 8, key, iv, dec_tag);
            decrypt_2kdes(local_rdr, 16, key, local_tag, dec_rdr);

            // check rol byte first
            if (dec_tag[0] != dec_rdr[15]) continue;

            // compare rest
            if (dec_tag[1] != dec_rdr[8]) continue;
            if (dec_tag[2] != dec_rdr[9]) continue;
            if (dec_tag[3] != dec_rdr[10]) continue;
            if (dec_tag[4] != dec_rdr[11]) continue;
            if (dec_tag[5] != dec_rdr[12]) continue;
            if (dec_tag[6] != dec_rdr[13]) continue;
            if (dec_tag[7] != dec_rdr[14]) continue;

        } else if (local_algo == 2) {
            decrypt_3kdes(local_tag, 16, key, iv, dec_tag);
            decrypt_3kdes(local_rdr, 32, key, local_tag, dec_rdr);

            // check rol byte first
            if (dec_tag[0] != dec_rdr[31]) continue;

            // compare rest
            if (dec_tag[1] != dec_rdr[16]) continue;
            if (dec_tag[2] != dec_rdr[17]) continue;
            if (dec_tag[3] != dec_rdr[18]) continue;
            if (dec_tag[4] != dec_rdr[19]) continue;
            if (dec_tag[5] != dec_rdr[20]) continue;
            if (dec_tag[6] != dec_rdr[21]) continue;
            if (dec_tag[7] != dec_rdr[22]) continue;
            if (dec_tag[8] != dec_rdr[23]) continue;
            if (dec_tag[9] != dec_rdr[24]) continue;
            if (dec_tag[10] != dec_rdr[25]) continue;
            if (dec_tag[11] != dec_rdr[26]) continue;
            if (dec_tag[12] != dec_rdr[27]) continue;
            if (dec_tag[13] != dec_rdr[28]) continue;
            if (dec_tag[14] != dec_rdr[29]) continue;
            if (dec_tag[15] != dec_rdr[30]) continue;

        } else if (local_algo == 3) {
            decrypt_aes(local_tag, 16, key, iv, dec_tag);
            decrypt_aes(local_rdr, 32, key, local_tag, dec_rdr);

            // check rol byte first
            if (dec_tag[0] != dec_rdr[31]) continue;

            // compare rest
            if (dec_tag[1] != dec_rdr[16]) continue;
            if (dec_tag[2] != dec_rdr[17]) continue;
            if (dec_tag[3] != dec_rdr[18]) continue;
            if (dec_tag[4] != dec_rdr[19]) continue;
            if (dec_tag[5] != dec_rdr[20]) continue;
            if (dec_tag[6] != dec_rdr[21]) continue;
            if (dec_tag[7] != dec_rdr[22]) continue;
            if (dec_tag[8] != dec_rdr[23]) continue;
            if (dec_tag[9] != dec_rdr[24]) continue;
            if (dec_tag[10] != dec_rdr[25]) continue;
            if (dec_tag[11] != dec_rdr[26]) continue;
            if (dec_tag[12] != dec_rdr[27]) continue;
            if (dec_tag[13] != dec_rdr[28]) continue;
            if (dec_tag[14] != dec_rdr[29]) continue;
            if (dec_tag[15] != dec_rdr[30]) continue;
        }

        __sync_fetch_and_add(&global_found, 1);

        // lock this section to avoid interlacing prints from different threats
        pthread_mutex_lock(&print_lock);
        printf("Found timestamp........ ");
        print_time(i);

        printf("Key.................... \x1b[32m");
        print_hex(key, keylen);
        printf(AEND);

        pthread_mutex_unlock(&print_lock);
        break;
    }
    free(args);
    return NULL;
}

static int usage(const char *s) {

    printf("\n");
    printf(_CYAN_("Multi Brute tool\n"));
    printf("Works on authentication challenges from MIFARE DESfire, MIFARE UL-C.\n");
    printf("If the key was generated by taking the Unixstamp as seed to a LCG random generator this software might find it.\n");
    printf("This version is multi-threaded, multi-crypto support and multi LCG generator support.\n");
    printf("\n");
    printf(_CYAN_("syntax") "\n");
    printf("  %s <crypto algo> <generator> <unix timestamp> <16 byte tag challenge> <32 byte reader response challenge>\n\n", s);
    printf("     crypt algo -  <DES|2KDES|3KDES|AES>\n");
    printf("     generator  -  <0-5>\n");
    printf("\n");
    printf(_CYAN_("samples") "\n");
    printf("     %s DES 0 1599999999 118565f6e5e6c839 d570fd1578079e6b22aaa187b99f0a2a\n", s);
    printf("     %s 2TDEA 0 1599999999 02bdc73fd33cc07d 0e2281d59686bda6a6c5ad218dbfaa8c\n", s);
    printf("     %s 3TDEA 0 1599999999 1fe1f0330e9da5407cd2bc9294e56a7e 920037b5e02872b2fd9a070eade2b172ddc0fe6b10e5e55dd32cebdcc94747b4 \n", s);
    printf("     %s AES 0 1599999999 bb6aea729414a5b1eff7b16328ce37fd 82f5f498dbc29f7570102397a2e5ef2b6dc14a864f665b3c54d11765af81e95c\n", s);
    printf("\n");
    return 1;
}

int main(int argc, char *argv[]) {

    if (argc != 6) {
        return usage(argv[0]);
    }

    char *algostr = argv[1];
    if (strlen(algostr) > 5 || strlen(algostr) < 3) {
        printf("No valid crypto algo\n");
        return 1;
    }

    int8_t algo = -1;
    if (strcasecmp(algostr, "des") == 0) {
        algo = 0;
    } else if (strcasecmp(algostr, "2tdea") == 0) {
        algo = 1;
    } else if (strcasecmp(algostr, "3tdea") == 0) {
        algo = 2;
    } else if (strcasecmp(algostr, "aes") == 0) {
        algo = 3;
    }

    if (algo == -1) {
        printf("No valid crypto algo\n");
        return 1;
    }

    uint8_t  g_idx = atoi(argv[2]);

    // -2 (zero index and last item is NULL);
    if (g_idx > ARRAYLEN(generators) - 2) {
        printf("generator index is out-of-range\n");
        return 1;
    }

    uint64_t start_time = 0;
    sscanf(argv[3], "%"PRIu64, &start_time);

    printf("Crypto algo............ " _GREEN_("%s") "\n", algostr);
    printf("LCR Random generator... " _GREEN_("%s") "\n", generators[g_idx].Name);

#if defined(__APPLE__) || defined(__MACH__)
#else
    bool support_aesni = platform_aes_hw_available();
    printf("AES-NI detected........ " _GREEN_("%s") "\n", (support_aesni) ? "yes" : "no");
#endif

    printf("Starting timestamp..... ");
    print_time(start_time);

    uint8_t tag_challenge[16] = {0x00};
    uint8_t rdr_resp_challenge[32] = {0x00};

    if (algo == 0) {
        if (hexstr_to_byte_array(argv[4], tag_challenge, 8))
            return 2;
        if (hexstr_to_byte_array(argv[5], rdr_resp_challenge, 16))
            return 3;

        printf("Tag Challenge.......... ");
        print_hex(tag_challenge, 8);

        printf("Rdr Resp & Challenge... ");
        print_hex(rdr_resp_challenge, 16);

    } else if (algo == 1) {
        if (hexstr_to_byte_array(argv[4], tag_challenge, 8))
            return 2;
        if (hexstr_to_byte_array(argv[5], rdr_resp_challenge, 16))
            return 3;

        printf("Tag Challenge.......... ");
        print_hex(tag_challenge, 8);

        printf("Rdr Resp & Challenge... ");
        print_hex(rdr_resp_challenge, 16);

    } else if (algo == 2) {
        if (hexstr_to_byte_array(argv[4], tag_challenge, 16))
            return 2;
        if (hexstr_to_byte_array(argv[5], rdr_resp_challenge, 32))
            return 3;

        printf("Tag Challenge.......... ");
        print_hex(tag_challenge, 16);

        printf("Rdr Resp & Challenge... ");
        print_hex(rdr_resp_challenge, 32);

    } else if (algo == 3) {
        if (hexstr_to_byte_array(argv[4], tag_challenge, 16))
            return 2;
        if (hexstr_to_byte_array(argv[5], rdr_resp_challenge, 32))
            return 3;

        printf("Tag Challenge.......... ");
        print_hex(tag_challenge, 16);

        printf("Rdr Resp & Challenge... ");
        print_hex(rdr_resp_challenge, 32);
    }

    uint64_t t1 = msclock();

#if !defined(_WIN32) || !defined(__WIN32__)
    thread_count = sysconf(_SC_NPROCESSORS_CONF);
    if (thread_count < 2)
        thread_count = 2;
#endif  /* _WIN32 */

    printf("\nBruteforce using " _YELLOW_("%d") " threads\n", thread_count);

    pthread_t threads[thread_count];
    void *res;

    // create a mutex to avoid interlacing print commands from our different threads
    pthread_mutex_init(&print_lock, NULL);

    // threads
    uint64_t stop_time = time(NULL);
    for (int i = 0; i < thread_count; ++i) {
        struct thread_args *a = calloc(1, sizeof(struct thread_args));
        a->thread = i;
        a->idx = i;
        a->generator_idx = g_idx;
        a->algo = (uint8_t)algo;
        a->starttime = start_time;
        a->stoptime = stop_time;

        if (algo == 0) {
            memcpy(a->tag, tag_challenge, 8);
            memcpy(a->rdr, rdr_resp_challenge, 16);
        } else if (algo == 1) {
            memcpy(a->tag, tag_challenge, 8);
            memcpy(a->rdr, rdr_resp_challenge, 16);
        } else if (algo == 2) {
            memcpy(a->tag, tag_challenge, 16);
            memcpy(a->rdr, rdr_resp_challenge, 32);
        } else if (algo == 3) {
            memcpy(a->tag, tag_challenge, 16);
            memcpy(a->rdr, rdr_resp_challenge, 32);
        }

        pthread_create(&threads[i], NULL, brute_thread, (void *)a);
    }

    // wait for threads to terminate:
    for (int i = 0; i < thread_count; ++i) {
        pthread_join(threads[i], &res);
        free(res);
    }

    if (global_found == false) {
        printf("\n" _RED_("!!!") " failed to find a key\n\n");
    }

    t1 = msclock() - t1;
    if (t1 > 0) {
        printf("Execution time " _YELLOW_("%.2f") " sec\n", (float)t1 / 1000.0);
    }

    // clean up mutex
    pthread_mutex_destroy(&print_lock);

    return 0;
}
