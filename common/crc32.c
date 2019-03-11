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

void crc32_ex(const uint8_t *data, const size_t len, uint8_t *crc) {
    uint32_t desfire_crc = CRC32_PRESET;
    for (size_t i = 0; i < len; i++) {
        crc32_byte(&desfire_crc, data[i]);
    }

    *((uint32_t *)(crc)) = htole32(desfire_crc);
}

void crc32_append(uint8_t *data, const size_t len) {
    crc32_ex(data, len, data + len);
}
