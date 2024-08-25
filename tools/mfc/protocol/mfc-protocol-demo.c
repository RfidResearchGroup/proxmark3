//  Example of CRYPTO-1 authentication protocol and nested authentication protocol
//  Doegox, 2024, cf https://eprint.iacr.org/2024/1275 Annexes 1 & 2 for more info

#include <stdio.h>
#include <inttypes.h>
#include "crapto1/crapto1.h"
#include "parity.h"

#define UID 0x0DB3FA11
#define NT  0xE0512BB5
#define NR  0x12345678
#define KEY1 0xFFFFFFFFFFFF
#define NESTED_NT 0xBF53BA5F
#define NESTED_NR  0x12345678
#define NESTED_KEY 0xFFFFFFFFFFFF

static void append_crc16_a(uint8_t *buf, uint32_t buflen) {
    if (buflen < 2) return;

    uint16_t crc = 0x6363;

    for (uint32_t i = 0; i < buflen - 2; i++) {
        crc ^= buf[i];

        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }

    buf[buflen - 2] = crc & 0xFF;
    buf[buflen - 1] = (crc >> 8) & 0xFF;
}

int main(void) {
    printf("Reader                          <>  Tag\n");
    printf("======                          <>  ===\n");
    uint32_t tag_uid = UID;
    printf("                                <-  uid (via anticol)                   < ");
    printf("%08X\n", tag_uid);
    uint32_t reader_uid = tag_uid;
    printf("s = crypto1_create(key)\n");
    uint64_t reader_ui64Key = KEY1;
    struct Crypto1State reader_state = {0, 0};
    crypto1_init(&reader_state, reader_ui64Key);
    uint8_t cmd[4] = {0x60, 0x00};
    append_crc16_a(cmd, sizeof(cmd));
    printf("auth A/B+blk + CRC              ->                                      > ");
    for (uint32_t i = 0; i < sizeof(cmd); i++) printf("%02X ", cmd[i]);
    printf("\n");
    printf("                                    s = crypto1_create(key)\n");
    uint64_t tag_ui64Key = KEY1;
    struct Crypto1State tag_state = {0, 0};
    crypto1_init(&tag_state, tag_ui64Key);
    printf("                                    gen nT                                ");
    uint32_t tag_nt = NT;
    printf("%08X\n", tag_nt);
    printf("                                    ks0 = crypto1_word(s, uid ^ nT, 0)    ");
    uint32_t tag_ks0 = crypto1_word(&tag_state, tag_uid ^ tag_nt, 0);
    printf("%08X\n", tag_ks0);
    printf("                                <-  nT                                  < ");
    uint8_t tag_nt1 = (tag_nt >> 24) & 0xFF;
    uint8_t tag_nt2 = (tag_nt >> 16) & 0xFF;
    uint8_t tag_nt3 = (tag_nt >> 8) & 0xFF;
    uint8_t tag_nt4 = (tag_nt >> 0) & 0xFF;
    printf("%02X  ", tag_nt1);
    printf("%02X  ", tag_nt2);
    printf("%02X  ", tag_nt3);
    printf("%02X  ", tag_nt4);
    printf("\n");
    uint32_t reader_nt = tag_nt;
    printf("ks0 = crypto1_word(s, uid ^ nT, 0)                                        ");
    uint32_t reader_ks0 = crypto1_word(&reader_state, reader_uid ^ reader_nt, 0);
    printf("%08X\n", reader_ks0);
    printf("Gen nR                                                                    ");
    uint32_t reader_nr = NR;
    printf("%08X\n", reader_nr);
    printf("ks1 = crypto1_word(s, nR, 0)                                              ");
    uint32_t reader_ks1 = crypto1_word(&reader_state, reader_nr, 0);
    printf("%08X\n", reader_ks1);
    printf("{nR} = nR ^ ks1                                                           ");
    uint32_t reader_nr_enc = reader_nr ^ reader_ks1;
    printf("%08X\n", reader_nr_enc);
    printf("aR = suc64(nT)                                                            ");
    uint32_t reader_ar = prng_successor(reader_nt, 64);
    printf("%08X\n", reader_ar);
    printf("ks2 = crypto1_word(s, 0, 0)                                               ");
    uint32_t reader_ks2 = crypto1_word(&reader_state, 0, 0);
    printf("%08X\n", reader_ks2);
    printf("{aR} = ks2 ^ aR                                                           ");
    uint32_t reader_ar_enc = reader_ks2 ^ reader_ar;
    printf("%08X\n", reader_ar_enc);
    uint32_t reader_ks_next_bit = filter(reader_state.odd);
    printf("{nR}|{aR}                       ->                                      > ");

    printf("%02X%s ", (reader_nr_enc >> 24) & 0xFF,
           oddparity8((reader_nr >> 24) & 0xFF) ==
           (oddparity8((reader_nr_enc >> 24) & 0xFF) ^ ((reader_ks1 >> 16) & 1)) ? " " : "!");
    printf("%02X%s ", (reader_nr_enc >> 16) & 0xFF,
           oddparity8((reader_nr >> 16) & 0xFF) ==
           (oddparity8((reader_nr_enc >> 16) & 0xFF) ^ ((reader_ks1 >> 8) & 1)) ? " " : "!");
    printf("%02X%s ", (reader_nr_enc >> 8) & 0xFF,
           oddparity8((reader_nr >> 8) & 0xFF) ==
           (oddparity8((reader_nr_enc >> 8) & 0xFF) ^ ((reader_ks1 >> 0) & 1)) ? " " : "!");
    printf("%02X%s ", (reader_nr_enc >> 0) & 0xFF,
           oddparity8((reader_nr >> 0) & 0xFF) ==
           (oddparity8((reader_nr_enc >> 0) & 0xFF) ^ ((reader_ks2 >> 24) & 1)) ? " " : "!");
    printf("%02X%s ", (reader_ar_enc >> 24) & 0xFF,
           oddparity8((reader_ar >> 24) & 0xFF) ==
           (oddparity8((reader_ar_enc >> 24) & 0xFF) ^ ((reader_ks2 >> 16) & 1)) ? " " : "!");
    printf("%02X%s ", (reader_ar_enc >> 16) & 0xFF,
           oddparity8((reader_ar >> 16) & 0xFF) ==
           (oddparity8((reader_ar_enc >> 16) & 0xFF) ^ ((reader_ks2 >> 8) & 1)) ? " " : "!");
    printf("%02X%s ", (reader_ar_enc >> 8) & 0xFF,
           oddparity8((reader_ar >> 8) & 0xFF) ==
           (oddparity8((reader_ar_enc >> 8) & 0xFF) ^ ((reader_ks2 >> 0) & 1)) ? " " : "!");
    printf("%02X%s ", (reader_ar_enc >> 0) & 0xFF,
           oddparity8((reader_ar >> 0) & 0xFF) ==
           (oddparity8((reader_ar_enc >> 0) & 0xFF) ^ reader_ks_next_bit) ? " " : "!");
    printf("\n");

    uint32_t tag_nr_enc = reader_nr_enc;
    uint32_t tag_ar_enc = reader_ar_enc;
    printf("                                    ks1 = crypto1_word(s, {nR}, 1)        ");
    uint32_t tag_ks1 = crypto1_word(&tag_state, tag_nr_enc, 1);
    printf("%08X\n", tag_ks1);
    printf("                                    nR = ks1 ^ {nR}                       ");
    uint32_t tag_nr = tag_ks1 ^ tag_nr_enc;
    printf("%08X\n", tag_nr);
    printf("                                    ks2 = crypto1_word(s, 0, 0)           ");
    uint32_t tag_ks2 = crypto1_word(&tag_state, 0, 0);
    printf("%08X\n", tag_ks2);
    printf("                                    aR = ks2 ^ {aR}                       ");
    uint32_t tag_ar = tag_ks2 ^ tag_ar_enc;
    printf("%08X\n", tag_ar);
    printf("                                    aR == suc64(nT) ?                     ");
    printf("%08X %s\n", prng_successor(tag_nt, 64), tag_ar == prng_successor(tag_nt, 64) ? "OK" : "FAIL");
    printf("                                    aT = suc96(nT)                        ");
    uint32_t tag_at = prng_successor(tag_nt, 96);
    printf("%08X\n", tag_at);
    printf("                                    ks3 = crypto1_word(s, 0, 0)           ");
    uint32_t tag_ks3 = crypto1_word(&tag_state, 0, 0);
    printf("%08X\n", tag_ks3);
    printf("                                    {aT} = ks3 ^ aT                       ");
    uint32_t tag_at_enc = tag_ks3 ^ tag_at;
    printf("%08X\n", tag_at_enc);
    uint32_t tag_ks_next_bit = filter(tag_state.odd);
    printf("                                 <- {aT}                                < ");
    printf("%02X%s ", (tag_at_enc >> 24) & 0xFF,
           oddparity8((tag_at >> 24) & 0xFF) ==
           (oddparity8((tag_at_enc >> 24) & 0xFF) ^ ((tag_ks3 >> 16) & 1)) ? " " : "!");
    printf("%02X%s ", (tag_at_enc >> 16) & 0xFF,
           oddparity8((tag_at >> 16) & 0xFF) ==
           (oddparity8((tag_at_enc >> 16) & 0xFF) ^ ((tag_ks3 >> 8) & 1)) ? " " : "!");
    printf("%02X%s ", (tag_at_enc >> 8) & 0xFF,
           oddparity8((tag_at >> 8) & 0xFF) ==
           (oddparity8((tag_at_enc >> 8) & 0xFF) ^ ((tag_ks3 >> 0) & 1)) ? " " : "!");
    printf("%02X%s ", (tag_at_enc >> 0) & 0xFF,
           oddparity8((tag_at >> 0) & 0xFF) ==
           (oddparity8((tag_at_enc >> 0) & 0xFF) ^ tag_ks_next_bit) ? " " : "!");
    printf("\n");
    uint32_t reader_at_enc = tag_at_enc;
    printf("ks3 = crypto1_word(s, 0, 0)                                               ");
    uint32_t reader_ks3 = crypto1_word(&reader_state, 0, 0);
    printf("%08X\n", reader_ks3);
    printf("aT = ks3 ^ {aT}                                                           ");
    uint32_t reader_at = reader_ks3 ^ reader_at_enc;
    printf("%08X\n", reader_at);
    printf("aT == suc96(nT) ?                                                         ");
    printf("%08X %s\n", prng_successor(reader_nt, 96), reader_at == prng_successor(tag_nt, 96) ? "OK" : "FAIL");
    printf("\n");
    printf("\n");

    // Nested Auth
    printf("ks4 = crypto1_word(s, 0, 0)                                               ");
    uint32_t reader_ks4 = crypto1_word(&reader_state, 0, 0);
    printf("%08X\n", reader_ks4);
    uint32_t reader_cmd = (cmd[0] << 24) | (cmd[1] << 16) | (cmd[2] << 8) | (cmd[3] << 0);
    uint32_t reader_cmd_enc = reader_ks4 ^ reader_cmd;
    printf("{cmd} = ks4 ^ cmd                                                         ");
    printf("%08X\n", reader_cmd_enc);
    reader_ks_next_bit = filter(reader_state.odd);
    printf("{auth A/B+blk}                  ->                                      > ");

    printf("%02X%s ", (reader_cmd_enc >> 24) & 0xFF,
           oddparity8((reader_cmd >> 24) & 0xFF) ==
           (oddparity8((reader_cmd_enc >> 24) & 0xFF) ^ ((reader_ks4 >> 16) & 1)) ? " " : "!");
    printf("%02X%s ", (reader_cmd_enc >> 16) & 0xFF,
           oddparity8((reader_cmd >> 16) & 0xFF) ==
           (oddparity8((reader_cmd_enc >> 16) & 0xFF) ^ ((reader_ks4 >> 8) & 1)) ? " " : "!");
    printf("%02X%s ", (reader_cmd_enc >> 8) & 0xFF,
           oddparity8((reader_cmd >> 8) & 0xFF) ==
           (oddparity8((reader_cmd_enc >> 8) & 0xFF) ^ ((reader_ks4 >> 0) & 1)) ? " " : "!");
    printf("%02X%s ", (reader_cmd_enc >> 0) & 0xFF,
           oddparity8((reader_cmd >> 0) & 0xFF) ==
           (oddparity8((reader_cmd_enc >> 0) & 0xFF) ^ reader_ks_next_bit) ? " " : "!");
    printf("\n");


    printf("                                    s = crypto1_create(key)\n");
    uint64_t tag2_ui64Key = NESTED_KEY;
    struct Crypto1State tag2_state = {0, 0};
    crypto1_init(&tag2_state, tag2_ui64Key);
    printf("                                    gen nT                                ");
    uint32_t tag2_nt = NESTED_NT;
    printf("%08X\n", tag2_nt);
    printf("                                    ks0 = crypto1_word(s, uid ^ nT, 0)    ");
    uint32_t tag2_ks0 = crypto1_word(&tag2_state, tag_uid ^ tag2_nt, 0);
    printf("%08X\n", tag2_ks0);
    uint32_t tag2_nt_enc = tag2_ks0 ^ tag2_nt;
    printf("                                    {nT} = ks0 ^ nT                       ");
    printf("%08X\n", tag2_nt_enc);
    uint32_t tag2_ks_next_bit = filter(tag2_state.odd);
    printf("                                <-  {nT}                                < ");
    printf("%02X%s ", (tag2_nt_enc >> 24) & 0xFF,
           oddparity8((tag2_nt >> 24) & 0xFF) ==
           (oddparity8((tag2_nt_enc >> 24) & 0xFF) ^ ((tag2_ks0 >> 16) & 1)) ? " " : "!");
    printf("%02X%s ", (tag2_nt_enc >> 16) & 0xFF,
           oddparity8((tag2_nt >> 16) & 0xFF) ==
           (oddparity8((tag2_nt_enc >> 16) & 0xFF) ^ ((tag2_ks0 >> 8) & 1)) ? " " : "!");
    printf("%02X%s ", (tag2_nt_enc >> 8) & 0xFF,
           oddparity8((tag2_nt >> 8) & 0xFF) ==
           (oddparity8((tag2_nt_enc >> 8) & 0xFF) ^ ((tag2_ks0 >> 0) & 1)) ? " " : "!");
    printf("%02X%s ", (tag2_nt_enc >> 0) & 0xFF,
           oddparity8((tag2_nt >> 0) & 0xFF) ==
           (oddparity8((tag2_nt_enc >> 0) & 0xFF) ^ tag2_ks_next_bit) ? " " : "!");
    printf("\n");
    printf("s = crypto1_create(key)\n");
    uint64_t reader2_ui64Key = NESTED_KEY;
    struct Crypto1State reader2_state = {0, 0};
    crypto1_init(&reader2_state, reader2_ui64Key);
    uint32_t reader2_nt_enc = tag2_nt_enc;

    printf("ks0 = crypto1_word(s, uid ^ {nT}, 1)                                      ");
    uint32_t reader2_ks0 = crypto1_word(&reader2_state, reader_uid ^ reader2_nt_enc, 1);
    printf("%08X\n", reader2_ks0);
    printf("nT = ks0 ^ {nT}                                                           ");
    uint32_t reader2_nt = reader2_ks0 ^ reader2_nt_enc;
    printf("%08X\n", reader2_nt);
    printf("Gen nR                                                                    ");
    uint32_t reader2_nr = NR;
    printf("%08X\n", reader2_nr);
    printf("ks1 = crypto1_word(s, nR, 0)                                              ");
    uint32_t reader2_ks1 = crypto1_word(&reader2_state, reader2_nr, 0);
    printf("%08X\n", reader2_ks1);
    printf("{nR} = nR ^ ks1                                                           ");
    uint32_t reader2_nr_enc = reader2_nr ^ reader2_ks1;
    printf("%08X\n", reader2_nr_enc);
    printf("aR = suc64(nT)                                                            ");
    uint32_t reader2_ar = prng_successor(reader2_nt, 64);
    printf("%08X\n", reader2_ar);
    printf("ks2 = crypto1_word(s, 0, 0)                                               ");
    uint32_t reader2_ks2 = crypto1_word(&reader2_state, 0, 0);
    printf("%08X\n", reader2_ks2);
    printf("{aR} = ks2 ^ aR                                                           ");
    uint32_t reader2_ar_enc = reader2_ks2 ^ reader2_ar;
    printf("%08X\n", reader2_ar_enc);
    uint32_t reader2_ks_next_bit = filter(reader2_state.odd);
    printf("{nR}|{aR}                       ->                                      > ");
    printf("%02X%s ", (reader2_nr_enc >> 24) & 0xFF,
           oddparity8((reader2_nr >> 24) & 0xFF) ==
           (oddparity8((reader2_nr_enc >> 24) & 0xFF) ^ ((reader2_ks1 >> 16) & 1)) ? " " : "!");
    printf("%02X%s ", (reader2_nr_enc >> 16) & 0xFF,
           oddparity8((reader2_nr >> 16) & 0xFF) ==
           (oddparity8((reader2_nr_enc >> 16) & 0xFF) ^ ((reader2_ks1 >> 8) & 1)) ? " " : "!");
    printf("%02X%s ", (reader2_nr_enc >> 8) & 0xFF,
           oddparity8((reader2_nr >> 8) & 0xFF) ==
           (oddparity8((reader2_nr_enc >> 8) & 0xFF) ^ ((reader2_ks1 >> 0) & 1)) ? " " : "!");
    printf("%02X%s ", (reader2_nr_enc >> 0) & 0xFF,
           oddparity8((reader2_nr >> 0) & 0xFF) ==
           (oddparity8((reader2_nr_enc >> 0) & 0xFF) ^ ((reader2_ks2 >> 24) & 1)) ? " " : "!");
    printf("%02X%s ", (reader2_ar_enc >> 24) & 0xFF,
           oddparity8((reader2_ar >> 24) & 0xFF) ==
           (oddparity8((reader2_ar_enc >> 24) & 0xFF) ^ ((reader2_ks2 >> 16) & 1)) ? " " : "!");
    printf("%02X%s ", (reader2_ar_enc >> 16) & 0xFF,
           oddparity8((reader2_ar >> 16) & 0xFF) ==
           (oddparity8((reader2_ar_enc >> 16) & 0xFF) ^ ((reader2_ks2 >> 8) & 1)) ? " " : "!");
    printf("%02X%s ", (reader2_ar_enc >> 8) & 0xFF,
           oddparity8((reader2_ar >> 8) & 0xFF) ==
           (oddparity8((reader2_ar_enc >> 8) & 0xFF) ^ ((reader2_ks2 >> 0) & 1)) ? " " : "!");
    printf("%02X%s ", (reader2_ar_enc >> 0) & 0xFF,
           oddparity8((reader2_ar >> 0) & 0xFF) ==
           (oddparity8((reader2_ar_enc >> 0) & 0xFF) ^ reader2_ks_next_bit) ? " " : "!");
    printf("\n");

    uint32_t tag2_nr_enc = reader2_nr_enc;
    uint32_t tag2_ar_enc = reader2_ar_enc;
    printf("                                    ks1 = crypto1_word(s, {nR}, 1)        ");
    uint32_t tag2_ks1 = crypto1_word(&tag2_state, tag2_nr_enc, 1);
    printf("%08X\n", tag2_ks1);
    printf("                                    nR = ks1 ^ {nR}                       ");
    uint32_t tag2_nr = tag2_ks1 ^ tag2_nr_enc;
    printf("%08X\n", tag2_nr);
    printf("                                    ks2 = crypto1_word(s, 0, 0)           ");
    uint32_t tag2_ks2 = crypto1_word(&tag2_state, 0, 0);
    printf("%08X\n", tag2_ks2);
    printf("                                    aR = ks2 ^ {aR}                       ");
    uint32_t tag2_ar = tag2_ks2 ^ tag2_ar_enc;
    printf("%08X\n", tag2_ar);
    printf("                                    aR == suc64(nT) ?                     ");
    printf("%08X %s\n", prng_successor(tag2_nt, 64), tag2_ar == prng_successor(tag2_nt, 64) ? "OK" : "FAIL");
    printf("                                    aT = suc96(nT)                        ");
    uint32_t tag2_at = prng_successor(tag2_nt, 96);
    printf("%08X\n", tag2_at);
    printf("                                    ks3 = crypto1_word(s, 0, 0)           ");
    uint32_t tag2_ks3 = crypto1_word(&tag2_state, 0, 0);
    printf("%08X\n", tag2_ks3);
    printf("                                    ks4 = crypto1_word(s, 0, 0)           ");
    uint32_t tag2_ks4 = crypto1_word(&tag2_state, 0, 0);
    printf("%08X\n", tag2_ks4);
    printf("                                    {aT} = ks3 ^ aT                       ");
    uint32_t tag2_at_enc = tag2_ks3 ^ tag2_at;
    printf("%08X\n", tag2_at_enc);
    printf("                                 <- {aT}                                < ");
    printf("%02X%s ", (tag2_at_enc >> 24) & 0xFF,
           oddparity8((tag2_at >> 24) & 0xFF) ==
           (oddparity8((tag2_at_enc >> 24) & 0xFF) ^ ((tag2_ks3 >> 16) & 1)) ? " " : "!");
    printf("%02X%s ", (tag2_at_enc >> 16) & 0xFF,
           oddparity8((tag2_at >> 16) & 0xFF) ==
           (oddparity8((tag2_at_enc >> 16) & 0xFF) ^ ((tag2_ks3 >> 8) & 1)) ? " " : "!");
    printf("%02X%s ", (tag2_at_enc >> 8) & 0xFF,
           oddparity8((tag2_at >> 8) & 0xFF) ==
           (oddparity8((tag2_at_enc >> 8) & 0xFF) ^ ((tag2_ks3 >> 0) & 1)) ? " " : "!");
    printf("%02X%s ", (tag2_at_enc >> 0) & 0xFF,
           oddparity8((tag2_at >> 0) & 0xFF) ==
           (oddparity8((tag2_at_enc >> 0) & 0xFF) ^ ((tag2_ks4 >> 24) & 1)) ? " " : "!");
    printf("\n");

    uint32_t reader2_at_enc = tag2_at_enc;
    printf("ks3 = crypto1_word(s, 0, 0)                                               ");
    uint32_t reader2_ks3 = crypto1_word(&reader2_state, 0, 0);
    printf("%08X\n", reader2_ks3);
    printf("aT = ks3 ^ {aT}                                                           ");
    uint32_t reader2_at = reader2_ks3 ^ reader2_at_enc;
    printf("%08X\n", reader2_at);
    printf("aT == suc96(nT) ?                                                         ");
    printf("%08X %s\n", prng_successor(reader2_nt, 96), reader2_at == prng_successor(tag2_nt, 96) ? "OK" : "FAIL");
    printf("\n");
    printf("\n");

    // Nested Auth
    printf("ks4 = crypto1_word(s, 0, 0)                                               ");
    uint32_t reader2_ks4 = crypto1_word(&reader2_state, 0, 0);
    printf("%08X\n", reader2_ks4);
    uint32_t reader2_cmd = (cmd[0] << 24) | (cmd[1] << 16) | (cmd[2] << 8) | (cmd[3] << 0);
    uint32_t reader2_cmd_enc = reader2_ks4 ^ reader2_cmd;
    printf("{cmd} = ks4 ^ cmd                                                         ");
    printf("%08X\n", reader2_cmd_enc);
    reader2_ks_next_bit = filter(reader2_state.odd);
    printf("{auth A/B+blk}                  ->                                      > ");

    printf("%02X%s ", (reader2_cmd_enc >> 24) & 0xFF,
           oddparity8((reader2_cmd >> 24) & 0xFF) ==
           (oddparity8((reader2_cmd_enc >> 24) & 0xFF) ^ ((reader2_ks4 >> 16) & 1)) ? " " : "!");
    printf("%02X%s ", (reader2_cmd_enc >> 16) & 0xFF,
           oddparity8((reader2_cmd >> 16) & 0xFF) ==
           (oddparity8((reader2_cmd_enc >> 16) & 0xFF) ^ ((reader2_ks4 >> 8) & 1)) ? " " : "!");
    printf("%02X%s ", (reader2_cmd_enc >> 8) & 0xFF,
           oddparity8((reader2_cmd >> 8) & 0xFF) ==
           (oddparity8((reader2_cmd_enc >> 8) & 0xFF) ^ ((reader2_ks4 >> 0) & 1)) ? " " : "!");
    printf("%02X%s ", (reader2_cmd_enc >> 0) & 0xFF,
           oddparity8((reader2_cmd >> 0) & 0xFF) ==
           (oddparity8((reader2_cmd_enc >> 0) & 0xFF) ^ reader2_ks_next_bit) ? " " : "!");
    printf("\n");

    return 0;
}
