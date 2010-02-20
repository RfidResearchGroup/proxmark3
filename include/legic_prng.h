#ifndef __LEGIC_PRNG_H
#define __LEGIC_PRNG_H

#include <stdint.h>
extern void legic_prng_init(uint8_t init);
extern void legic_prng_forward(int count);
extern uint8_t legic_prng_get_bit();

#endif

