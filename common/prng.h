//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// Burtle Prng - Modified.   42iterations instead of 20.
// ref: http://burtleburtle.net/bob/rand/smallprng.html
//-----------------------------------------------------------------------------

#ifndef __PRNG_H
#define __PRNG_H
#include <stdint.h>
#include <stddef.h>
typedef struct prng_ctx {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} prng_ctx;

//uint32_t burtle_get( prng_ctx *x );
uint32_t burtle_get_mod(prng_ctx *x);
void burtle_init_mod(prng_ctx *x, uint32_t seed);
void burtle_init(prng_ctx *x, uint32_t seed);

uint32_t GetSimplePrng(uint32_t seed);
#endif /* __PRNG_H */
