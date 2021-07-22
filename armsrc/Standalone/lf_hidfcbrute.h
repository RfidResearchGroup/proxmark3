#ifndef __LF_HIDFCBRUTE_H
#define __LF_HIDFCBRUTE_H

#include <stdint.h>

void hid_calculate_checksum_and_set(uint32_t *high, uint32_t *low, uint32_t cardnum, uint32_t fc);

#endif /* __LF_HIDFCBRUTE_H */
