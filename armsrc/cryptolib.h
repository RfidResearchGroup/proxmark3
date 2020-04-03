#ifndef _CRYPTOLIB_H_
#define _CRYPTOLIB_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define null 0

typedef unsigned char byte_t;
typedef long long unsigned int ui64;

// A nibble is actually only 4 bits, but there is no such type ;)
typedef byte_t nibble;

typedef struct {
    uint64_t l;
    uint64_t m;
    uint64_t r;
    nibble b0;
    nibble b1;
    nibble b1l;
    nibble b1r;
    nibble b1s;
} crypto_state_t;
typedef crypto_state_t *crypto_state;

void print_crypto_state(const char *text, crypto_state s);
void cm_auth(const byte_t *Gc, const byte_t *Ci, const byte_t *Q, byte_t *Ch, byte_t *Ci_1, byte_t *Ci_2, crypto_state s);
void cm_encrypt(const byte_t offset, const byte_t len, const byte_t *pt, byte_t *ct, crypto_state s);
void cm_decrypt(const byte_t offset, const byte_t len, const byte_t *ct, byte_t *pt, crypto_state s);
void cm_grind_read_system_zone(const byte_t offset, const byte_t len, const byte_t *pt, crypto_state s);
void cm_grind_set_user_zone(const byte_t zone, crypto_state s);
void cm_mac(byte_t *mac, crypto_state s);
void cm_password(const byte_t *pt, byte_t *ct, crypto_state s);
void RAMFUNC next(size_t repeat, byte_t in, crypto_state s);

#endif // _CRYPTOLIB_H_
