#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "HardwareProfile.h"
#include "rfidler.h"
#include "util.h"

#include "hitagcrypto.h"

#define HEX_PER_ROW 16



void writebuf(unsigned char *buf, uint64_t val, unsigned int len);
void shexdump(unsigned char *data, int data_len);
void printbin(unsigned char *c);
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
