#ifndef HT2CRACKUTILS_H
#define HT2CRACKUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#ifndef __MINGW64__
# include <sys/mman.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "hitagcrypto.h"

#define HEX_PER_ROW 16

void writebuf(unsigned char *buf, uint64_t val, uint16_t len);
void shexdump(unsigned char *data, int data_len);
void printbin(const unsigned char *c);
void printbin2(uint64_t val, unsigned int size);
void printstate(Hitag_State *hstate);
unsigned char hex2bin(unsigned char c);
int bitn(uint64_t x, int bit);
int fnR(uint64_t x);
void rollback(Hitag_State *hstate, unsigned int steps);
int fa(unsigned int i);
int fb(unsigned int i);
int fc(unsigned int i);
int fnf(uint64_t s);
void buildlfsr(Hitag_State *hstate);

/*
 * Hitag Crypto support macros
 * These macros reverse the bit order in a byte, or *within* each byte of a
 * 16 , 32 or 64 bit unsigned integer. (Not across the whole 16 etc bits.)
 */
#define rev8(X)   ((((X) >> 7) &1) + (((X) >> 5) &2) + (((X) >> 3) &4) \
                  + (((X) >> 1) &8) + (((X) << 1) &16) + (((X) << 3) &32) \
                  + (((X) << 5) &64) + (((X) << 7) &128) )
#define rev16(X)  (rev8 (X) + (rev8 (X >> 8) << 8))
#define rev32(X)  (rev16(X) + (rev16(X >> 16) << 16))
#define rev64(X)  (rev32(X) + (rev32(X >> 32) << 32))
unsigned long hexreversetoulong(char *hex);
unsigned long long hexreversetoulonglong(char *hex);

#endif /* HT2CRACKUTILS_H */
