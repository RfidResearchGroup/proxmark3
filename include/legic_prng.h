#ifndef LEGIC_PRNG_H__
#define LEGIC_PRNG_H__

#include <stdint.h>
extern void legic_prng_init(uint8_t init);
extern void legic_prng_forward(int count);
extern uint8_t legic_prng_get_bit();

#endif

