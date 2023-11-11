#ifndef NESTED_H__
#define NESTED_H__

#include "crapto1/crapto1.h"

typedef struct {
    uint32_t ntp;
    uint32_t ks1;
} NtpKs1;


uint8_t valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, uint8_t *parity);
uint64_t *nested(NtpKs1 *pNK, uint32_t sizePNK, uint32_t authuid, uint32_t *keyCount);

#endif