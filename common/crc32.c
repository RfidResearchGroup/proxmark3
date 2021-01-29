#include "crc32.h"

#define htole32(x) (x)
#define CRC32_PRESET 0xFFFFFFFF

static void crc32_byte(uint32_t *crc, const uint8_t value);

static void crc32_byte(uint32_t *crc, const uint8_t value) {
    /* x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1 */
    const uint32_t poly = 0xEDB88320;

    *crc ^= value;
    for (int current_bit = 7; current_bit >= 0; current_bit--) {
        int bit_out = (*crc) & 0x00000001;
        *crc >>= 1;
        if (bit_out)
            *crc ^= poly;
    }
}

void crc32_ex(const uint8_t *d, const size_t n, uint8_t *crc) {
    uint32_t c = CRC32_PRESET;
    for (size_t i = 0; i < n; i++) {
        crc32_byte(&c, d[i]);
    }
    crc[0] = (uint8_t) c;
    crc[1] = (uint8_t)(c >> 8);
    crc[2] = (uint8_t)(c >> 16);
    crc[3] = (uint8_t)(c >> 24);
}


void crc32_append(uint8_t *d, const size_t n) {
    crc32_ex(d, n, d + n);
}
