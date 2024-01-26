//-----------------------------------------------------------------------------
// High frequency Xerox commands (ISO14443B)
//-----------------------------------------------------------------------------

#include "cmdhfxerox.h"

#include "fileutils.h"
#include "cmdtrace.h"
#include "cmdparser.h"      // command_t
#include "cliparser.h"
#include "comms.h"
#include "iso14b.h"
#include "crc16.h"
#include "commonutil.h"     // ARRAYLEN

#define TIMEOUT 2000
#define XEROX_BLOCK_SIZE    4

#define c2l(c,l)    (l = ((unsigned long)(*((c)++))), \
             l |= ((unsigned long)(*((c)++))) << 8L, \
             l |= ((unsigned long)(*((c)++))) << 16L, \
             l |= ((unsigned long)(*((c)++))) << 24L)

/* NOTE - c is not incremented as per c2l */
#define c2ln(c,l1,l2,n) { \
            c += n; \
            l1 = l2 = 0; \
            switch (n) { \
            case 8: l2 = ((unsigned long)(*(--(c)))) << 24L; \
            case 7: l2 |= ((unsigned long)(*(--(c)))) << 16L; \
            case 6: l2 |= ((unsigned long)(*(--(c)))) << 8L; \
            case 5: l2 |= ((unsigned long)(*(--(c)))); \
            case 4: l1 = ((unsigned long)(*(--(c)))) << 24L; \
            case 3: l1 |= ((unsigned long)(*(--(c)))) << 16L; \
            case 2: l1 |= ((unsigned long)(*(--(c)))) << 8L; \
            case 1: l1 |= ((unsigned long)(*(--(c)))); \
                } \
            }

#define l2c(l,c)    (*((c)++) = (uint8_t)(((l)) & 0xff), \
             *((c)++) = (uint8_t)(((l) >> 8L) & 0xff), \
             *((c)++) = (uint8_t)(((l) >> 16L) & 0xff), \
             *((c)++) = (uint8_t)(((l) >> 24L) & 0xff))

/* NOTE - c is not incremented as per l2c */
#define l2cn(l1,l2,c,n) { \
            c += n; \
            switch (n) { \
            case 8: *(--(c)) = (uint8_t)(((l2) >> 24L) & 0xff); \
            case 7: *(--(c)) = (uint8_t)(((l2) >> 16L) & 0xff); \
            case 6: *(--(c)) = (uint8_t)(((l2) >> 8L) & 0xff); \
            case 5: *(--(c)) = (uint8_t)(((l2)) & 0xff); \
            case 4: *(--(c)) = (uint8_t)(((l1) >> 24L) & 0xff); \
            case 3: *(--(c)) = (uint8_t)(((l1) >> 16L) & 0xff); \
            case 2: *(--(c)) = (uint8_t)(((l1) >> 8L) & 0xff); \
            case 1: *(--(c)) = (uint8_t)(((l1)) & 0xff); \
                } \
            }

/* NOTE - c is not incremented as per n2l */
#define n2ln(c,l1,l2,n) { \
            c += n; \
            l1 = l2 = 0; \
            switch (n) { \
            case 8: l2 = ((unsigned long)(*(--(c)))); \
            case 7: l2 |= ((unsigned long)(*(--(c)))) << 8; \
            case 6: l2 |= ((unsigned long)(*(--(c)))) << 16; \
            case 5: l2 |= ((unsigned long)(*(--(c)))) << 24; \
            case 4: l1 = ((unsigned long)(*(--(c)))); \
            case 3: l1 |= ((unsigned long)(*(--(c)))) << 8; \
            case 2: l1 |= ((unsigned long)(*(--(c)))) << 16; \
            case 1: l1 |= ((unsigned long)(*(--(c)))) << 24; \
                } \
            }

/* NOTE - c is not incremented as per l2n */
#define l2nn(l1,l2,c,n) { \
            c+=n; \
            switch (n) { \
            case 8: *(--(c)) = (uint8_t)(((l2)) & 0xff); \
            case 7: *(--(c)) = (uint8_t)(((l2) >> 8) & 0xff); \
            case 6: *(--(c)) = (uint8_t)(((l2) >> 16) & 0xff); \
            case 5: *(--(c)) = (uint8_t)(((l2) >> 24) & 0xff); \
            case 4: *(--(c)) = (uint8_t)(((l1)) & 0xff); \
            case 3: *(--(c)) = (uint8_t)(((l1) >> 8) & 0xff); \
            case 2: *(--(c)) = (uint8_t)(((l1) >> 16) & 0xff); \
            case 1: *(--(c)) = (uint8_t)(((l1) >> 24) & 0xff); \
                } \
            }

#define n2l(c,l)        (l = ((unsigned long)(*((c)++))) << 24L, \
                         l |= ((unsigned long)(*((c)++))) << 16L, \
                         l |= ((unsigned long)(*((c)++))) << 8L, \
                         l |= ((unsigned long)(*((c)++))))

#define l2n(l,c)        (*((c)++) = (uint8_t)(((l) >> 24L) & 0xff), \
                         *((c)++) = (uint8_t)(((l) >> 16L) & 0xff), \
                         *((c)++) = (uint8_t)(((l) >> 8L) & 0xff), \
                         *((c)++) = (uint8_t)(((l)) & 0xff))

#define C_RC2(n) \
    t = (x0 + (x1 & ~x3) + (x2 & x3) + *(p0++)) & 0xffff; \
    x0 = (t << 1) | (t >> 15); \
    t = (x1 + (x2 & ~x0) + (x3 & x0) + *(p0++)) & 0xffff; \
    x1 = (t << 2) | (t >> 14); \
    t = (x2 + (x3 & ~x1) + (x0 & x1) + *(p0++)) & 0xffff; \
    x2 = (t << 3) | (t >> 13); \
    t = (x3 + (x0 & ~x2) + (x1 & x2) + *(p0++)) & 0xffff; \
    x3 = (t << 5) | (t >> 11);

#define RC2_ENCRYPT 1
#define RC2_DECRYPT 0

typedef unsigned int RC2_INT;

typedef struct rc2_key_st {
    RC2_INT data[64];
} RC2_KEY;

static const uint8_t lut[256] = {
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79,
    0x4a, 0xa0, 0xd8, 0x9d, 0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
    0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2, 0x17, 0x9a, 0x59, 0xf5,
    0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22,
    0x5c, 0x6b, 0x4e, 0x82, 0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
    0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc, 0x12, 0x75, 0xca, 0x1f,
    0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b,
    0xbc, 0x94, 0x43, 0x03, 0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
    0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7, 0x08, 0xe8, 0xea, 0xde,
    0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e,
    0x04, 0x18, 0xa4, 0xec, 0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
    0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39, 0x99, 0x7c, 0x3a, 0x85,
    0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10,
    0x67, 0x6c, 0xba, 0xc9, 0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
    0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9, 0x0d, 0x38, 0x34, 0x1b,
    0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68,
    0xfe, 0x7f, 0xc1, 0xad,
};

static const uint8_t var_list[] = {0x1c, 0x1e, 0x20, 0x26, 0x28, 0x2a, 0x2c, 0x2e};

static uint8_t info_blocks[] = { 0x15, 0x16, 0x17, 0x18, 0x22 }; //Used for partnumber
static const char *xerox_c_type[] = { "drum", "yellow", "magenta", "cyan", "black" };


static int CmdHelp(const char *Cmd);
void RC2_set_key(RC2_KEY *key, int len, const unsigned char *data, int bits);
void RC2_encrypt(unsigned long *d, RC2_KEY *key);
void RC2_decrypt(unsigned long *d, RC2_KEY *key);
void RC2_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, RC2_KEY *ks, unsigned char *iv, int encrypt);


void RC2_set_key(RC2_KEY *key, int len, const unsigned char *data, int bits) {
    int i, j;
    unsigned char *k;
    RC2_INT *ki;
    unsigned int c, d;

    k = (unsigned char *) & (key->data[0]);
    *k = 0;                     /* for if there is a zero length key */

    if (len > 128)
        len = 128;

    if (bits <= 0)
        bits = 1024;

    if (bits > 1024)
        bits = 1024;

    for (i = 0; i < len; i++)
        k[i] = data[i];

    /* expand table */
    d = k[len - 1];
    j = 0;
    for (i = len; i < 128; i++, j++) {
        d = lut[(k[j] + d) & 0xff];
        k[i] = d;
    }

    /* hmm.... key reduction to 'bits' bits */

    j = (bits + 7) >> 3;
    i = 128 - j;
    c = (0xff >> (-bits & 0x07));

    d = lut[k[i] & c];
    k[i] = d;
    while (i--) {
        d = lut[k[i + j] ^ d];
        k[i] = d;
    }

    /* copy from bytes into RC2_INT's */
    ki = &(key->data[63]);
    for (i = 127; i >= 0; i -= 2)
        * (ki--) = ((k[i] << 8) | k[i - 1]) & 0xffff;
}

void RC2_encrypt(unsigned long *d, RC2_KEY *key) {
    int i, n;
    register RC2_INT *p0, *p1;
    register RC2_INT x0, x1, x2, x3;
    unsigned long l;

    l = d[0];
    x0 = (RC2_INT)l & 0xffff;
    x1 = (RC2_INT)(l >> 16L);
    l = d[1];
    x2 = (RC2_INT)l & 0xffff;
    x3 = (RC2_INT)(l >> 16L);

    n = 3;
    i = 5;

    p0 = p1 = &(key->data[0]);
    for (;;) {
        register RC2_INT t = (x0 + (x1 & ~x3) + (x2 & x3) + * (p0++)) & 0xffff;
        x0 = (t << 1) | (t >> 15);
        t = (x1 + (x2 & ~x0) + (x3 & x0) + * (p0++)) & 0xffff;
        x1 = (t << 2) | (t >> 14);
        t = (x2 + (x3 & ~x1) + (x0 & x1) + * (p0++)) & 0xffff;
        x2 = (t << 3) | (t >> 13);
        t = (x3 + (x0 & ~x2) + (x1 & x2) + * (p0++)) & 0xffff;
        x3 = (t << 5) | (t >> 11);

        if (--i == 0) {
            if (--n == 0) break;
            i = (n == 2) ? 6 : 5;

            x0 += p1[x3 & 0x3f];
            x1 += p1[x0 & 0x3f];
            x2 += p1[x1 & 0x3f];
            x3 += p1[x2 & 0x3f];
        }
    }

    d[0] = (unsigned long)(x0 & 0xffff) | ((unsigned long)(x1 & 0xffff) << 16L);
    d[1] = (unsigned long)(x2 & 0xffff) | ((unsigned long)(x3 & 0xffff) << 16L);
}

void RC2_decrypt(unsigned long *d, RC2_KEY *key) {
    int i, n;
    register RC2_INT *p0, *p1;
    register RC2_INT x0, x1, x2, x3;
    unsigned long l;

    l = d[0];
    x0 = (RC2_INT)l & 0xffff;
    x1 = (RC2_INT)(l >> 16L);
    l = d[1];
    x2 = (RC2_INT)l & 0xffff;
    x3 = (RC2_INT)(l >> 16L);

    n = 3;
    i = 5;

    p0 = &(key->data[63]);
    p1 = &(key->data[0]);
    for (;;) {
        register RC2_INT t = ((x3 << 11) | (x3 >> 5)) & 0xffff;
        x3 = (t - (x0 & ~x2) - (x1 & x2) - * (p0--)) & 0xffff;
        t = ((x2 << 13) | (x2 >> 3)) & 0xffff;
        x2 = (t - (x3 & ~x1) - (x0 & x1) - * (p0--)) & 0xffff;
        t = ((x1 << 14) | (x1 >> 2)) & 0xffff;
        x1 = (t - (x2 & ~x0) - (x3 & x0) - * (p0--)) & 0xffff;
        t = ((x0 << 15) | (x0 >> 1)) & 0xffff;
        x0 = (t - (x1 & ~x3) - (x2 & x3) - * (p0--)) & 0xffff;

        if (--i == 0) {
            if (--n == 0)
                break;

            i = (n == 2) ? 6 : 5;

            x3 = (x3 - p1[x2 & 0x3f]) & 0xffff;
            x2 = (x2 - p1[x1 & 0x3f]) & 0xffff;
            x1 = (x1 - p1[x0 & 0x3f]) & 0xffff;
            x0 = (x0 - p1[x3 & 0x3f]) & 0xffff;
        }
    }

    d[0] = (unsigned long)(x0 & 0xffff) | ((unsigned long)(x1 & 0xffff) << 16L);
    d[1] = (unsigned long)(x2 & 0xffff) | ((unsigned long)(x3 & 0xffff) << 16L);
}

void RC2_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
                     RC2_KEY *ks, unsigned char *iv, int encrypt) {
    register unsigned long tin0, tin1;
    register unsigned long tout0, tout1, xor0, xor1;
    register long l = length;
    unsigned long tin[2];

    if (encrypt) {

        c2l(iv, tout0);
        c2l(iv, tout1);
        iv -= 8;

        for (l -= 8; l >= 0; l -= 8) {
            c2l(in, tin0);
            c2l(in, tin1);
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0] = tin0;
            tin[1] = tin1;
            RC2_encrypt(tin, ks);
            tout0 = tin[0];
            l2c(tout0, out);
            tout1 = tin[1];
            l2c(tout1, out);
        }

        if (l != -8) {
            c2ln(in, tin0, tin1, l + 8);
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0] = tin0;
            tin[1] = tin1;
            RC2_encrypt(tin, ks);
            tout0 = tin[0];
            l2c(tout0, out);
            tout1 = tin[1];
            l2c(tout1, out);
        }

        l2c(tout0, iv);
        l2c(tout1, iv);

    } else {

        c2l(iv, xor0);
        c2l(iv, xor1);
        iv -= 8;

        for (l -= 8; l >= 0; l -= 8) {
            c2l(in, tin0);
            tin[0] = tin0;
            c2l(in, tin1);
            tin[1] = tin1;
            RC2_decrypt(tin, ks);
            tout0 = tin[0] ^ xor0;
            tout1 = tin[1] ^ xor1;
            l2c(tout0, out);
            l2c(tout1, out);
            xor0 = tin0;
            xor1 = tin1;
        }

        if (l != -8) {
            c2l(in, tin0);
            tin[0] = tin0;
            c2l(in, tin1);
            tin[1] = tin1;
            RC2_decrypt(tin, ks);
            tout0 = tin[0] ^ xor0;
            tout1 = tin[1] ^ xor1;
            l2cn(tout0, tout1, out, l + 8);
            xor0 = tin0;
            xor1 = tin1;
        }

        l2c(xor0, iv);
        l2c(xor1, iv);
    }
    tin0 = tin1 = tout0 = tout1 = xor0 = xor1 = 0;
    tin[0] = tin[1] = 0;
}

static int switch_off_field(void) {
    SetISODEPState(ISODEP_INACTIVE);
    iso14b_raw_cmd_t packet = {
        .flags = ISO14B_DISCONNECT,
        .timeout = 0,
        .rawlen = 0,
    };
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    return PM3_SUCCESS;
}

static int xerox_select_card(iso14b_card_select_t *card, bool disconnect) {

    if (card == NULL) {
        return PM3_EINVARG;
    }

    int8_t retry = 2;
    while (retry--) {

        iso14b_raw_cmd_t packet = {
            .flags = (ISO14B_CONNECT | ISO14B_SELECT_XRX ),
            .timeout = 0,
            .rawlen = 0,
        };

        if (disconnect) {
            packet.flags |= ISO14B_DISCONNECT;
        }

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
            continue;
        }

        if (resp.status == PM3_SUCCESS) {
            memcpy(card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
            return resp.status;
        }
    } // retry

    PrintAndLogEx(FAILED, "command execution timeout");
    return PM3_ESOFT;
}

static inline char dec_digit(uint8_t dig) {
    return (dig <= 9) ? dig + '0' : '?';
}

static void xerox_generate_partno(const uint8_t *data, char *pn) {
    pn[0]  = dec_digit(data[0] >> 4);
    pn[1]  = dec_digit(data[0] & 0xF);
    pn[2]  = dec_digit(data[1] >> 4);

    char sym = ((data[1] & 0xF) << 4) | (data[2] >> 4);
    pn[3]  = (sym >= 'A' && sym <= 'Z') ? sym : '?';

    pn[4]  = dec_digit(data[2] & 0xF);
    pn[5]  = dec_digit(data[3] >> 4);
    pn[6]  = dec_digit(data[3] & 0xF);
    pn[7]  = dec_digit(data[4] >> 4);
    pn[8]  = dec_digit(data[4] & 0xF);
    pn[9]  = '-';
    pn[10] = dec_digit(data[5] >> 4);
    pn[11] = dec_digit(data[5] & 0xF);
    pn[12] = 0;
}

static void xerox_print_hdr(void) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------- " _CYAN_("tag memory") " ---------");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "block#   | data         | ascii");
    PrintAndLogEx(INFO, "---------+--------------+----------");
}

static void xerox_print(uint8_t *data, uint16_t datalen, bool dense_output) {

    uint16_t blockno = datalen / XEROX_BLOCK_SIZE;

    bool in_repeated_block = false;


    for (int i = 0; i < blockno; i++) {
        // suppress repeating blocks, truncate as such that the first and last block with the same data is shown
        // but the blocks in between are replaced with a single line of "......" if dense_output is enabled
        uint8_t *blk = data + (i * XEROX_BLOCK_SIZE);
        if (dense_output &&
                (i > 3) &&
                (i < (blockno - 1)) &&
                (in_repeated_block == false) &&
                (memcmp(blk, blk - XEROX_BLOCK_SIZE, XEROX_BLOCK_SIZE) == 0) &&
                (memcmp(blk, blk + XEROX_BLOCK_SIZE, XEROX_BLOCK_SIZE) == 0) &&
                (memcmp(blk, blk + (XEROX_BLOCK_SIZE * 2), XEROX_BLOCK_SIZE) == 0)
           ) {
            // we're in a user block that isn't the first user block nor last two user blocks,
            // and the current block data is the same as the previous and next two block
            in_repeated_block = true;
            PrintAndLogEx(INFO, "  ......");
        } else if (in_repeated_block &&
                   (memcmp(blk, blk + XEROX_BLOCK_SIZE, XEROX_BLOCK_SIZE) || i == blockno)
                  ) {
            // in a repeating block, but the next block doesn't match anymore, or we're at the end block
            in_repeated_block = false;
        }

        if (in_repeated_block == false) {
            PrintAndLogEx(INFO,
                          "%3d/0x%02X | %s | %s",
                          i,
                          i,
                          sprint_hex(data + (i * XEROX_BLOCK_SIZE), XEROX_BLOCK_SIZE),
                          sprint_ascii(data + (i * XEROX_BLOCK_SIZE), XEROX_BLOCK_SIZE)
                         );
        }
    }
}

static void xerox_print_footer(void) {
    PrintAndLogEx(INFO, "---------+--------------+----------");
    PrintAndLogEx(NORMAL, "");
}


// structure and database for uid -> tagtype lookups
typedef struct {
    //General details
    const char *partnumber;

    //Toner related details
    const char *color; // cyan, magenta, gold, silver, clear, white, fluo

    const char *region; // DMO, WW, NA/ESG (NA - North America, MNA - Metred North America, DMO - Developing Markets, XE - Europe
    const char *ms; // sold, metered

    //Drum related details
    const char *r; // Interchangeability with drumtray(s): color, black, both
} xerox_part_t;

// Additional data based on model DCP 550/560/570/C60/C70, PrimeLink C9065/C9070, WC 7965/7975 (Color)
// https://gist.github.com/JeroenSteen/4b45886b8d87fa0530af9b0364e6b277
// Todo: import data as actual JSON-file, and find a way to seperate toner/drums (with inheritance of consumable as type)
static const xerox_part_t xerox_part_mappings[] = {
    //Toner items
    {"006R01532", "cyan", "DMO", "sold", ""},
    {"006R01660", "cyan", "DMO", "sold", ""},
    {"006R01739", "cyan", "DMO", "sold", ""},
    {"006R01524", "cyan", "WW", "metered", ""},
    {"006R01528", "cyan", "NA/ESG", "sold", ""},
    {"006R01656", "cyan", "NA/ESG", "sold", ""},
    {"006R01735", "cyan", "NA/ESG", "sold", ""},

    {"006R01531", "magenta", "DMO", "sold", ""},
    {"006R01661", "magenta", "DMO", "sold", ""},
    {"006R01740", "magenta", "DMO", "sold", ""},
    {"006R01523", "magenta", "WW", "metered", ""},
    {"006R01527", "magenta", "NA/ESG", "sold", ""},
    {"006R01657", "magenta", "NA/ESG", "sold", ""},
    {"006R01736", "magenta", "NA/ESG", "sold", ""},

    {"006R01530", "yellow", "DMO", "sold", ""},
    {"006R01662", "yellow", "DMO", "sold", ""},
    {"006R01741", "yellow", "DMO", "sold", ""},
    {"006R01522", "yellow", "WW", "metered", ""},
    {"006R01526", "yellow", "NA/ESG", "sold", ""},
    {"006R01658", "yellow", "NA/ESG", "sold", ""},
    {"006R01737", "yellow", "NA/ESG", "sold", ""},

    {"006R01529", "black", "DMO", "sold", ""},
    {"006R01659", "black", "DMO", "sold", ""},
    {"006R01738", "black", "DMO", "sold", ""},
    {"006R01521", "black", "WW", "metered", ""},
    {"006R01525", "black", "NA/ESG", "sold", ""},
    {"006R01655", "black", "NA/ESG", "sold", ""},
    {"006R01734", "black", "NA/ESG", "sold", ""},

    //Drum items
    {"013R00663", "", "", "", "black"},
    {"013R00664", "", "", "", "color"},

    {"", "", "", "", ""} // must be the last entry
};

// get a product description based on the UID
// returns description of the best match
static const xerox_part_t *get_xerox_part_info(const char *pn) {
    for (int i = 0; i < ARRAYLEN(xerox_part_mappings); i++) {
        // Todo: make str_startswith, accept additional "Maximum number of characters to compare"
        if (strncmp(pn, xerox_part_mappings[i].partnumber, strlen(pn) - 3) == 0) {
            return &xerox_part_mappings[i];
        }
    }
    //No match, return default
    return &xerox_part_mappings[ARRAYLEN(xerox_part_mappings) - 1];
}

int read_xerox_uid(bool loop, bool verbose) {

    do {
        iso14b_card_select_t card;
        int status = xerox_select_card(&card, true);

        if (loop) {
            if (status != PM3_SUCCESS) {
                continue;
            }
        }

        if (status == PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, " UID..... %s", sprint_hex(card.uid, card.uidlen));
            PrintAndLogEx(SUCCESS, " ATQB.... %s", sprint_hex(card.atqb, sizeof(card.atqb)));
        } else {
            if (verbose) {
                PrintAndLogEx(WARNING, "no tag found");
            }
            return PM3_ESOFT;
        }

    } while (loop && kbd_enter_pressed() == false);

    return PM3_SUCCESS;
}

static void xerox_print_info(uint8_t *d) {

    char pn[13];
    xerox_generate_partno(d, pn);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------- " _CYAN_("tag info") " -----------");
    PrintAndLogEx(SUCCESS, " PartNo....... " _YELLOW_("%s"), pn);
    PrintAndLogEx(SUCCESS, " Date......... %02d.%02d.%02d", d[8], d[9], d[10]);
    PrintAndLogEx(SUCCESS, " Serial....... %d", (d[14] << 16) | (d[13] << 8) | d[12]);
    PrintAndLogEx(SUCCESS, " Type......... %s", (d[18] <= 4) ? xerox_c_type[d[18]] : "Unknown");

    const xerox_part_t *item = get_xerox_part_info(pn);
    if (strlen(item->partnumber) > 0) {

        if (strcmp(xerox_c_type[d[18]], "drum") == 0) {

            PrintAndLogEx(SUCCESS, " Consumable... drum");
            PrintAndLogEx(SUCCESS, " Slots........ %s", item->r); // Interchangeability
        } else {
            PrintAndLogEx(SUCCESS, " Consumable... toner");
            PrintAndLogEx(SUCCESS, " Region....... %s", item->region);
            PrintAndLogEx(SUCCESS, " M/s.......... %s", item->ms);
        }
    }
}


// Assumes the card is already selected.
static int read_xerox_block(iso14b_card_select_t *card, uint8_t blockno, uint8_t *out) {

    if (card == NULL || out == NULL) {
        return PM3_EINVARG;
    }

    uint8_t approx_len = (2 + card->uidlen + 1);
    iso14b_raw_cmd_t *packet = (iso14b_raw_cmd_t *)calloc(1, sizeof(iso14b_raw_cmd_t) + approx_len);
    if (packet == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    // set up the read command
    packet->flags = (ISO14B_APPEND_CRC | ISO14B_RAW);
    packet->raw[packet->rawlen++] = 0x02;
    packet->raw[packet->rawlen++] = (blockno < 12) ? ISO14443B_XEROX_READ_BLK : ISO14443B_XEROX_EXT_READ_BLK;

    // uid
    memcpy(packet->raw + packet->rawlen, card->uid, card->uidlen);
    packet->rawlen += card->uidlen;

    // block to read
    packet->raw[packet->rawlen++] = blockno;


    int res = PM3_ESOFT;
    // read loop
    for (int retry = 0; retry < 2; retry++) {
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t) + packet->rawlen);
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000) == false) {
            continue;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "trying one more time");
            continue;
        }

        // sanity checks
        if (resp.length < 7) {
            PrintAndLogEx(FAILED, "trying one more time, wrong length");
            continue;
        }

        uint8_t *d = resp.data.asBytes;
        if (check_crc(CRC_14443_B, d, 7) == false) {
            PrintAndLogEx(FAILED, "trying one more time, CRC ( " _RED_("fail") " )");
            continue;
        }

        if (d[0] != 0x02) {
            PrintAndLogEx(FAILED, "Tag returned Error %x %x", d[0], d[1]);
            res = PM3_ERFTRANS;
            break;
        }

        memcpy(out, d + 1, XEROX_BLOCK_SIZE);
        res = PM3_SUCCESS;
        break;
    }
    return res;
}

static int CmdHFXeroxReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf xerox reader",
                  "Act as a 14443B reader to identify a Fuji Xerox based tag\n"
                  "ISO/IEC 14443 type B based communications",
                  "hf xerox reader\n"
                  "hf xerox reader -@ \n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    bool cm = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    return read_xerox_uid(cm, verbose);
}

static int CmdHFXeroxInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf xerox info",
                  "Tag information for Fuji Xerox based tags\n"
                  "ISO/IEC 14443 type B based communications",
                  "hf xerox info"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    iso14b_card_select_t card;
    int status = xerox_select_card(&card, false);
    if (status != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(FAILED, "Fuji/Xerox tag select failed");
        }
        return status;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " UID..... %s", sprint_hex(card.uid, card.uidlen));
    PrintAndLogEx(SUCCESS, " ATQB.... %s", sprint_hex(card.atqb, sizeof(card.atqb)));

    uint8_t data[sizeof(info_blocks) * XEROX_BLOCK_SIZE] = {0};

    // special blocks to read.
    for (int i = 0; i < sizeof(i); i++) {

        status = read_xerox_block(&card, info_blocks[i], data + (i * XEROX_BLOCK_SIZE));
        if (status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Fuji/Xerox tag read failed");
            break;
        }
    }

    switch_off_field();
    xerox_print_info(data);
    return status;
}

static int CmdHFXeroxDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf xerox dump",
                  "Dump all memory from a Fuji/Xerox tag\n"
                  "ISO/IEC 14443 type B based communications",
                  "hf xerox dump\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename to save dump to"),
        arg_lit0("d", "decrypt", "decrypt secret blocks"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool decrypt = arg_get_lit(ctx, 2);
    bool nosave = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    bool dense_output = (g_session.dense_output || arg_get_lit(ctx, 3));
    CLIParserFree(ctx);

    iso14b_card_select_t card;
    int status = xerox_select_card(&card, false);
    if (status != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(FAILED, "Fuji/Xerox tag select failed");
        }
        return status;
    }

    PrintAndLogEx(INFO, "Reading memory from tag UID " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
    PrintAndLogEx(INFO, "" NOLF);

    uint8_t data[256 * XEROX_BLOCK_SIZE] = {0};

    uint16_t blockno = 0;
    for (; blockno < 0x100; blockno++) {

        int res = read_xerox_block(&card, blockno, data + (blockno * XEROX_BLOCK_SIZE));
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Fuji/Xerox tag read failed");
            break;
        }

        PrintAndLogEx(INPLACE, "blk %3d", blockno);
    }

    switch_off_field();

    PrintAndLogEx(NORMAL, "");

    if (blockno != 0x100) {
        PrintAndLogEx(FAILED, "dump failed at block " _RED_("%d"), blockno);
    }

    if (decrypt) {
        PrintAndLogEx(INFO, "Decrypting secret blocks...");

        RC2_KEY exp_key;
        uint8_t k1[8], iv[8], k2[8], decr[8];

        k1[0] = data[8];
        k1[1] = data[5];
        k1[2] = data[6];
        k1[3] = data[7];
        k1[4] = data[(0x18 * XEROX_BLOCK_SIZE) + 0];
        k1[5] = data[(0x18 * XEROX_BLOCK_SIZE) + 1];
        k1[6] = data[(0x22 * XEROX_BLOCK_SIZE) + 0];
        k1[7] = 0;

        RC2_set_key(&exp_key, 8, k1, 64);

        memset(iv, 0, sizeof(iv));
        iv[0] = k1[6];
        iv[1] = k1[7];
        iv[2] = 1;

        RC2_cbc_encrypt(k1, k2, 8, &exp_key, iv, RC2_ENCRYPT);

        memcpy(k1, k2, sizeof(k1));

        k1[2] = k2[3] ^ data[(0x22 * XEROX_BLOCK_SIZE) + 0];
        k1[3] = k2[4] ^ data[(0x22 * XEROX_BLOCK_SIZE) + 1]; // first_key[7];
        k1[5] = k2[1] ^ 0x01;       // 01 = crypto method? rfid[23][2]

        RC2_set_key(&exp_key, 8, k1, 64);

        for (int n = 0; n < sizeof(var_list); n++) {

            uint8_t dadr = var_list[n];

            if (dadr + 1 >= blockno) {
                PrintAndLogEx(INFO, "secret block %02X skipped.", dadr);
                continue;
            }

            memset(iv, 0, sizeof(iv));
            iv[0] = dadr;

            RC2_cbc_encrypt(&data[dadr * XEROX_BLOCK_SIZE], decr, 8, &exp_key, iv, RC2_DECRYPT);

            memcpy(&data[dadr * XEROX_BLOCK_SIZE], decr, 8);

            int b;
            uint16_t cs, csd;

            // calc checksum
            for (b = 0, cs = 0; b < sizeof(decr) - 2; b += 2) {
                cs += decr[b] | (decr[b + 1] << 8);
            }

            cs = ~cs;
            csd = (decr[7] << 8) | decr[6];

            if (cs != csd) {
                PrintAndLogEx(FAILED, "Secret block %02X checksum " _RED_("failed"), dadr);
            }
        }
    }

    xerox_print_hdr();
    xerox_print(data, blockno * XEROX_BLOCK_SIZE, dense_output);
    xerox_print_footer();

    if (nosave) {
        PrintAndLogEx(INFO, "Called with no save option");
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }

    if (0 == filename[0]) { // generate filename from uid
        char *fptr = filename;
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += snprintf(fptr, sizeof(filename), "hf-xerox-");
        FillFileNameByUID(fptr
                          , SwapEndian64(card.uid, card.uidlen, 8)
                          , (decrypt) ? "-dump-dec" : "-dump"
                          , card.uidlen
                         );
    }

    pm3_save_dump(filename, data, blockno * XEROX_BLOCK_SIZE, jsf14b_v2);
    return PM3_SUCCESS;
}

static int CmdHFXeroxView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf xerox view",
                  "Print a Fuji/Xerox dump file (bin/eml/json)\n"
                  "note:\n"
                  "  - command expects the filename to contain a UID\n"
                  "    which is needed to determine card memory type",
                  "hf xerox view -f hf-xerox-0102030405060708-dump.bin"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 2);
    bool dense_output = (g_session.dense_output || arg_get_lit(ctx, 3));
    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = (XEROX_BLOCK_SIZE * 0x100);
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, (XEROX_BLOCK_SIZE * 0x100));
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint16_t blockno = bytes_read / XEROX_BLOCK_SIZE;

    if (verbose) {
        PrintAndLogEx(INFO, "File size %zu bytes, file blocks %d (0x%x)", bytes_read, blockno, blockno);
    }

    // 5 different blocks is used
    uint8_t tmp[5 * XEROX_BLOCK_SIZE] = {0};
    for (uint8_t i = 0; i < ARRAYLEN(info_blocks); i++) {
        memcpy(tmp + (i * XEROX_BLOCK_SIZE), dump + (info_blocks[i] * XEROX_BLOCK_SIZE), XEROX_BLOCK_SIZE);
    }
    xerox_print_info(tmp);

    xerox_print_hdr();
    xerox_print(dump, bytes_read, dense_output);
    xerox_print_footer();

    free(dump);
    return PM3_SUCCESS;
}

static int CmdHFXeroxList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf 14b", "14b -c");
}

static int CmdHFXeroxRdBl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf xerox rdbl",
                  "Read a Fuji/Xerox tag block\n",
                  "hf xerox rdbl -b 1"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("b", "blk", "<dec>", "page number (0-255)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int blockno = arg_get_int_def(ctx, 1, 0);
    CLIParserFree(ctx);

    iso14b_card_select_t card;
    int status = xerox_select_card(&card, false);
    if (status != PM3_SUCCESS) {
        switch_off_field();
        return status;
    }

    uint8_t block[XEROX_BLOCK_SIZE] = {0};
    status = read_xerox_block(&card, (uint8_t)blockno, block);
    switch_off_field();

    if (status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "%i | %s", blockno, sprint_hex_ascii(block, sizeof(block)));
    } else {
        PrintAndLogEx(FAILED, "Fuji/Xerox tag read failed");
    }
    return status;
}

static command_t CommandTable[] = {
    {"help",      CmdHelp,           AlwaysAvailable, "This help"},
    {"list",      CmdHFXeroxList,    AlwaysAvailable, "List ISO-14443B history"},
    {"--------",  CmdHelp,           AlwaysAvailable, "----------------------- " _CYAN_("general") " -----------------------"},
    {"info",      CmdHFXeroxInfo,    IfPm3Iso14443b,  "Short info on Fuji/Xerox tag"},
    {"dump",      CmdHFXeroxDump,    IfPm3Iso14443b,  "Read all memory pages of an Fuji/Xerox tag, save to file"},
    {"reader",    CmdHFXeroxReader,  IfPm3Iso14443b,  "Act like a Fuji/Xerox reader"},
    {"view",      CmdHFXeroxView,    AlwaysAvailable, "Display content from tag dump file"},
    {"rdbl",      CmdHFXeroxRdBl,    IfPm3Iso14443b,  "Read Fuji/Xerox block"},
//    {"wrbl",    CmdHFXeroxWrBl,  IfPm3Iso14443b,  "Write Fuji/Xerox block"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFXerox(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
