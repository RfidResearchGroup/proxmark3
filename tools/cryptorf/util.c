#include "util.h"
#include <stdio.h>

void num_to_bytes(uint64_t n, size_t len, uint8_t *dst) {
    while (len--) {
        dst[len] = (uint8_t)n;
        n >>= 8;
    }
}

void print_bytes(const uint8_t *pbtData, const size_t szLen) {
    size_t uiPos;
    for (uiPos = 0; uiPos < szLen; uiPos++) {
        printf("%02x ", pbtData[uiPos]);
        if (uiPos > 20) {
            printf("...");
            break;
        }
    }
    printf("\n");
}
