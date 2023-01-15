//-----------------------------------------------------------------------------
// High frequency Xerox commands (ISO14443B)
//-----------------------------------------------------------------------------

#include "cmdhfxerox.h"

#include "fileutils.h"

#include "cmdparser.h"    // command_t
#include "cliparser.h"
#include "comms.h"
#include "iso14b.h"
#include "crc16.h"

#define TIMEOUT 2000


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

static int findXerox(iso14b_card_select_t *card, bool disconnect) {

    if (card == NULL)
        return PM3_EINVARG;

    int8_t retry = 3;
    while (retry--) {

        iso14b_raw_cmd_t packet = {
            .flags = (ISO14B_CONNECT | ISO14B_SELECT_XRX | (disconnect ? ISO14B_DISCONNECT : 0)),
            .timeout = 0,
            .rawlen = 0,
        };
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {

            if (resp.oldarg[0] == 0) {
                memcpy(card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
            }
            return resp.oldarg[0];
        }
    } // retry

//    switch_off_field();
    PrintAndLogEx(FAILED, "command execution timeout");
    return PM3_ESOFT;
}

static uint8_t info_blocks[] = { 0x15, 0x16, 0x17, 0x18, 0x22 };
static const char *c_type[] = { "drum", "yellow", "magenta", "cyan", "black" };

static inline char dec_digit(uint8_t dig) {
    return (dig <= 9) ? dig + '0' : '?';
}

static void gen_pn(const uint8_t *data, char *pn) {
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

int read_xerox_uid(bool loop, bool verbose) {

    do {
        iso14b_card_select_t card;
        int status = findXerox(&card, true);

        if (loop) {
            if (status != PM3_SUCCESS) {
                continue;
            }
        } else {

            if (status == PM3_SUCCESS) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(SUCCESS, " UID    : %s", sprint_hex(card.uid, card.uidlen));
                PrintAndLogEx(SUCCESS, " ATQB   : %s", sprint_hex(card.atqb, sizeof(card.atqb)));
            } else {
                return PM3_ESOFT;
            }
        }

    } while (loop && kbd_enter_pressed() == false);

    return PM3_SUCCESS;
}

static int CmdHFXeroxReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf xerox reader",
                  "Act as a 14443B reader to identify a tag",
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
                  "Tag information for ISO/IEC 14443 type B / XEROX based tags",
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
    int status = findXerox(&card, false);
    if (status != PM3_SUCCESS) {
        switch_off_field();
        if (verbose) {
            PrintAndLogEx(FAILED, "Fuji/Xerox tag select failed");
        }
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " UID    : %s", sprint_hex(card.uid, card.uidlen));
    PrintAndLogEx(SUCCESS, " ATQB   : %s", sprint_hex(card.atqb, sizeof(card.atqb)));

    iso14b_raw_cmd_t *packet = (iso14b_raw_cmd_t *)calloc(1, sizeof(iso14b_raw_cmd_t) + 11);
    if (packet == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    int blocknum = 0;
    uint8_t data[sizeof(info_blocks) * 4] = {0};

    // set up the read command
    packet->flags = (ISO14B_APPEND_CRC | ISO14B_RAW);
    packet->rawlen = 11;
    packet->raw[0] = 0x02;
    packet->raw[1] = 0x20;          // set command: read mem
    memcpy(packet->raw + 2, card.uid, 8);       // store uid

    for (int retry = 0; (retry < 5 && blocknum < sizeof(info_blocks)); retry++) {

        packet->raw[10] = info_blocks[blocknum];

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t) + packet->rawlen);
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000)) {
            /*
            PrintAndLogEx(INFO, "%X %X %X %X %X %I64X %I64X %I64X %X %X %X %c",
            resp.cmd, resp.length, resp.magic, resp.status, resp.crc, resp.oldarg[0], resp.oldarg[1], resp.oldarg[2],
            resp.data.asBytes[0], resp.data.asBytes[1], resp.data.asBytes[2], resp.ng ? 't' : 'f');
            */

            // 14b raw command send data_len instead of status
            if (/*resp.status != 0 ||*/ resp.length < 7) {
                PrintAndLogEx(FAILED, "retrying one more time");
                continue;
            }

            uint8_t *recv = resp.data.asBytes;

            if (check_crc(CRC_14443_B, recv, 7) == false) {
                PrintAndLogEx(FAILED, "crc fail, retrying one more time");
                continue;
            }

            if (recv[0] != 2) {
                PrintAndLogEx(FAILED, "Tag returned Error %x %x", recv[0], recv[1]);
                break;
            }

            memcpy(data + (blocknum * 4), resp.data.asBytes + 1, 4);

            retry = 0;
            blocknum++;
        }
    }

    switch_off_field();
    free(packet);

    if (blocknum != sizeof(info_blocks)) {
        PrintAndLogEx(FAILED, "Fuji/Xerox tag read failed");
        return PM3_ERFTRANS;
    }

    char pn[13];
    gen_pn(data, pn);
    PrintAndLogEx(SUCCESS, " PartNo : %s", pn);
    PrintAndLogEx(SUCCESS, " Date   : %02d.%02d.%02d", data[8], data[9], data[10]);
    PrintAndLogEx(SUCCESS, " Serial : %d", (data[14] << 16) | (data[13] << 8) | data[12]);
    PrintAndLogEx(SUCCESS, " Type   : %s", (data[18] <= 4) ? c_type[data[18]] : "Unknown");

    return PM3_SUCCESS;
}

static int CmdHFXeroxDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf xerox dump",
                  "Dump all memory from a Fuji/Xerox tag",
                  "hf xerox dump\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename to save dump to"),
        arg_lit0("d", "decrypt", "decrypt secret blocks"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool decrypt = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);

    iso14b_raw_cmd_t *packet = (iso14b_raw_cmd_t *)calloc(1, sizeof(iso14b_raw_cmd_t) + 11);
    if (packet == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    iso14b_card_select_t card;
    int status = findXerox(&card, false);   // remain RF on
    if (status != PM3_SUCCESS) {
        free(packet);
        switch_off_field();
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(INFO, "Reading memory from tag UID " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));

    int blocknum = 1;           // block 0 all zeros
    uint8_t data[256 * 4] = {0};

    // set up the read command
    packet->flags = (ISO14B_APPEND_CRC | ISO14B_RAW);
    packet->rawlen = 11;
    packet->raw[0] = 0x02;
    memcpy(packet->raw + 2, card.uid, 8);       // store uid

    PrintAndLogEx(INFO, "." NOLF);

    for (int retry = 0; (retry < 5 && blocknum < 0x100); retry++) {

        packet->raw[1]  = (blocknum < 12) ? 0x30 : 0x20;    // set command: read ext mem or read mem
        packet->raw[10] = blocknum & 0xFF;

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t) + packet->rawlen);
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000)) {
            /*
            PrintAndLogEx(INFO, "%X %X %X %X %X %I64X %I64X %I64X %X %X %X %c",
            resp.cmd, resp.length, resp.magic, resp.status, resp.crc, resp.oldarg[0], resp.oldarg[1], resp.oldarg[2],
            resp.data.asBytes[0], resp.data.asBytes[1], resp.data.asBytes[2], resp.ng ? 't' : 'f');
            */
            if (/*resp.status != 0 ||*/ resp.length < 7) {  // 14b raw command send data_len instead of status
                PrintAndLogEx(FAILED, "retrying one more time");
                continue;
            }

            uint8_t *recv = resp.data.asBytes;

            if (check_crc(CRC_14443_B, recv, 7) == false) {
                PrintAndLogEx(FAILED, "crc fail, retrying one more time");
                continue;
            }

            if (recv[0] != 2) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(FAILED, "Tag returned Error %x %x", recv[0], recv[1]);
                break;
            }

            memcpy(data + (blocknum * 4), resp.data.asBytes + 1, 4);

            retry = 0;
            blocknum++;

            PrintAndLogEx(NORMAL, "." NOLF);
            fflush(stdout);
//            PrintAndLogEx(INPLACE, "blk %3d", blocknum);
        }
    }

    switch_off_field();

    free(packet);

    PrintAndLogEx(NORMAL, "");

    if (blocknum != 0x100)
        PrintAndLogEx(FAILED, "dump failed at block %d", blocknum);

    if (decrypt) {
        PrintAndLogEx(INFO, "Decrypting secret blocks...");

        RC2_KEY exp_key;
        uint8_t k1[8], iv[8], k2[8], decr[8];

        k1[0] = data[8];
        k1[1] = data[5];
        k1[2] = data[6];
        k1[3] = data[7];
        k1[4] = data[0x18 * 4 + 0];
        k1[5] = data[0x18 * 4 + 1];
        k1[6] = data[0x22 * 4 + 0];
        k1[7] = 0;

        RC2_set_key(&exp_key, 8, k1, 64);

        memset(iv, 0, sizeof(iv));
        iv[0] = k1[6];
        iv[1] = k1[7];
        iv[2] = 1;

        RC2_cbc_encrypt(k1, k2, 8, &exp_key, iv, RC2_ENCRYPT);

        memcpy(k1, k2, sizeof(k1));

        k1[2] = k2[3] ^ data[0x22 * 4 + 0];
        k1[3] = k2[4] ^ data[0x22 * 4 + 1]; // first_key[7];
        k1[5] = k2[1] ^ 0x01;       // 01 = crypto method? rfid[23][2]

        RC2_set_key(&exp_key, 8, k1, 64);

        for (int n = 0; n < sizeof(var_list); n++) {

            uint8_t dadr = var_list[n];

            if (dadr + 1 >= blocknum) {
                PrintAndLogEx(INFO, "secret block %02X skipped.", dadr);
                continue;
            }

            memset(iv, 0, sizeof(iv));
            iv[0] = dadr;

            RC2_cbc_encrypt(&data[dadr * 4], decr, 8, &exp_key, iv, RC2_DECRYPT);

            memcpy(&data[dadr * 4], decr, 8);

            int b;
            uint16_t cs, csd;

            // calc checksum
            for (b = 0, cs = 0; b < sizeof(decr) - 2; b += 2)   cs += decr[b] | (decr[b + 1] << 8);
            cs = ~cs;
            csd = (decr[7] << 8) | decr[6];

            if (cs != csd) {
                PrintAndLogEx(FAILED, "secret block %02X checksum failed.", dadr);
            }
        }
    }

    PrintAndLogEx(INFO, "block#   | data         | ascii");
    PrintAndLogEx(INFO, "---------+--------------+----------");

    for (int i = 0; i < blocknum; i++) {
        PrintAndLogEx(INFO,
                      "%3d/0x%02X | %s | %s",
                      i,
                      i,
                      sprint_hex(data + (i * 4), 4),
                      sprint_ascii(data + (i * 4), 4)
                     );
    }
    PrintAndLogEx(INFO, "---------+--------------+----------");
    PrintAndLogEx(NORMAL, "");

    if (0 == filename[0]) { // generate filename from uid
        /*
                PrintAndLogEx(INFO, "Using UID as filename");

                sprintf(filename, "hf-xerox-%02X%02X%02X%02X%02X%02X%02X%02X-dump%s",
                    card.uid[7],card.uid[6],card.uid[5],card.uid[4],card.uid[3],card.uid[2],card.uid[1],card.uid[0],
                    decrypt ? "-dec" : "");
        */
        char *fptr = filename;
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += snprintf(fptr, sizeof(filename), "hf-xerox-");
        FillFileNameByUID(fptr, SwapEndian64(card.uid, card.uidlen, 8), decrypt ? "-dump-dec" : "-dump", card.uidlen);
    }

    size_t datalen = blocknum * 4;
    saveFile(filename, ".bin", data, datalen);
    saveFileEML(filename, data, datalen, 4);
//    saveFileJSON(filename, jsf15, data, datalen, NULL);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,           AlwaysAvailable, "This help"},
    {"info",    CmdHFXeroxInfo,    IfPm3Iso14443b,  "Short info on Fuji/Xerox tag"},
    {"reader",  CmdHFXeroxReader,  IfPm3Iso14443b,  "Act like a Fuji/Xerox reader"},
    {"dump",    CmdHFXeroxDump,    IfPm3Iso14443b,  "Read all memory pages of an Fuji/Xerox tag, save to file"},
//    {"rdbl",    CmdHFXeroxRdBl,  IfPm3Iso14443b,  "Read Fuji/Xerox block"},
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
