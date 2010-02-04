#ifndef DATA_H__
#define DATA_H__

#include <stdint.h>

#define SAMPLE_BUFFER_SIZE 64

extern uint8_t sample_buf[SAMPLE_BUFFER_SIZE];
#define arraylen(x) (sizeof(x)/sizeof((x)[0]))

void GetFromBigBuf(uint8_t *dest, int bytes);

#endif
