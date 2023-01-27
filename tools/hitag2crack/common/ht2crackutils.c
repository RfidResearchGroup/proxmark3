#include <string.h>
#include <stdio.h>
#include "ht2crackutils.h"

// writes a value into a buffer as a series of bytes
void writebuf(unsigned char *buf, uint64_t val, uint16_t len) {
    for (int i = len - 1; i >= 0; i--) {
        char c = val & 0xff;
        buf[i] = c;
        val >>= 8;
    }
}


/* simple hexdump for testing purposes */
void shexdump(unsigned char *data, int data_len) {
    int i;

    if (!data || (data_len <= 0)) {
        printf("shexdump: invalid parameters\n");
        return;
    }

    printf("Hexdump from %p:\n", data);

    for (i = 0; i < data_len; i++) {
        if ((i % HEX_PER_ROW) == 0) {
            printf("\n0x%04x: ", i);
        }
        printf("%02x ", data[i]);
    }
    printf("\n\n");
}



void printbin(const unsigned char *c) {
    if (!c) {
        printf("printbin: invalid params\n");
        return;
    }
    for (int i = 0; i < 6; i++) {
        unsigned char x = c[i];
        for (int j = 0; j < 8; j++) {
            printf("%d", (x & 0x80) >> 7);
            x = x << 1;
        }
    }
    printf("\n");
}

void printbin2(uint64_t val, unsigned int size) {

    uint64_t mask = 1;
    mask = mask << (size - 1);

    for (int i = 0; i < size; i++) {
        if (val & mask) {
            printf("1");
        } else {
            printf("0");
        }
        val <<= 1;
    }
}

void printstate(Hitag_State *hstate) {
    printf("shiftreg =\t");
    printbin2(hstate->shiftreg, 48);
    printf("\n");
}

// convert hex char to binary
unsigned char hex2bin(unsigned char c) {
    if ((c >= '0') && (c <= '9')) {
        return (c - '0');
    } else if ((c >= 'a') && (c <= 'f')) {
        return (c - 'a' + 10);
    } else if ((c >= 'A') && (c <= 'F')) {
        return (c - 'A' + 10);
    } else {
        return 0;
    }
}

// return a single bit from a value
int bitn(uint64_t x, int bit) {
    uint64_t bitmask = 1;
    bitmask = bitmask << bit;

    if (x & bitmask) {
        return 1;
    } else {
        return 0;
    }
}


// the sub-function R that rollback depends upon
int fnR(uint64_t x) {
    // renumbered bits because my state is 0-47, not 1-48
    return (bitn(x, 1) ^ bitn(x, 2) ^ bitn(x, 5) ^ bitn(x, 6) ^ bitn(x, 7) ^
            bitn(x, 15) ^ bitn(x, 21) ^ bitn(x, 22) ^ bitn(x, 25) ^ bitn(x, 29) ^ bitn(x, 40) ^
            bitn(x, 41) ^ bitn(x, 42) ^ bitn(x, 45) ^ bitn(x, 46) ^ bitn(x, 47));
}

// the rollback function that lets us go backwards in time
void rollback(Hitag_State *hstate, unsigned int steps) {
    for (int i = 0; i < steps; i++) {
        hstate->shiftreg = ((hstate->shiftreg << 1) & 0xffffffffffff) | fnR(hstate->shiftreg);
    }
}

// the three filter sub-functions that feed fnf
int fa(unsigned int i) {
    return bitn(0x2C79, i);
}

int fb(unsigned int i) {
    return bitn(0x6671, i);
}

int fc(unsigned int i) {
    return bitn(0x7907287B, i);
}

// the filter function that generates a bit of output from the prng state
int fnf(uint64_t s) {
    unsigned int x1, x2, x3, x4, x5, x6;

    x1 = (bitn(s,  2) << 0) | (bitn(s,  3) << 1) | (bitn(s,  5) << 2) | (bitn(s,  6) << 3);
    x2 = (bitn(s,  8) << 0) | (bitn(s, 12) << 1) | (bitn(s, 14) << 2) | (bitn(s, 15) << 3);
    x3 = (bitn(s, 17) << 0) | (bitn(s, 21) << 1) | (bitn(s, 23) << 2) | (bitn(s, 26) << 3);
    x4 = (bitn(s, 28) << 0) | (bitn(s, 29) << 1) | (bitn(s, 31) << 2) | (bitn(s, 33) << 3);
    x5 = (bitn(s, 34) << 0) | (bitn(s, 43) << 1) | (bitn(s, 44) << 2) | (bitn(s, 46) << 3);

    x6 = (fa(x1) << 0) | (fb(x2) << 1) | (fb(x3) << 2) | (fb(x4) << 3) | (fa(x5) << 4);

    return fc(x6);
}

// builds the lfsr for the prng (quick calcs for hitag2_nstep())
void buildlfsr(Hitag_State *hstate) {
    if (hstate == NULL)
        return;
    uint64_t state = hstate->shiftreg;
    uint64_t temp = state ^ (state >> 1);
    hstate->lfsr = state ^ (state >>  6) ^ (state >> 16)
                   ^ (state >> 26) ^ (state >> 30) ^ (state >> 41)
                   ^ (temp >>  2) ^ (temp >>  7) ^ (temp >> 22)
                   ^ (temp >> 42) ^ (temp >> 46);
}

// convert byte-reversed 8 digit hex to unsigned long
unsigned long hexreversetoulong(char *hex) {
    unsigned long ret = 0L;
    unsigned int x;
    char i;

    if (strlen(hex) != 8)
        return 0L;

    for (i = 0 ; i < 4 ; ++i) {
        if (sscanf(hex, "%2X", &x) != 1) {
            return 0L;
        }
        ret += ((unsigned long) x) << i * 8;
        hex += 2;
    }
    return ret;
}

// convert byte-reversed 12 digit hex to unsigned long
unsigned long long hexreversetoulonglong(char *hex) {
    char tmp[9];

    // this may seem an odd way to do it, but weird compiler issues were
    // breaking direct conversion!

    tmp[8] = '\0';
    memset(tmp + 4, '0', 4);
    memcpy(tmp, hex + 8, 4);
    unsigned long long ret = hexreversetoulong(tmp);
    ret <<= 32;
    memcpy(tmp, hex, 8);
    ret += hexreversetoulong(tmp);
    return ret;
}
