#include "random.h"

static uint32_t g_nextrandom;

/* Generates a (non-cryptographically secure) 32-bit random number.
 *
 * We don't have an implementation of the "rand" function. Instead we use a
 * method of seeding with the time it took to call "autoseed" from first run.
 *
 * https://github.com/Proxmark/proxmark3/pull/209/commits/f9c1dcd9f6e68a8c07cffed697a9c4c8caed6015
 *
 * Iceman,  rand needs to be fast.
 * https://software.intel.com/en-us/articles/fast-random-number-generator-on-the-intel-pentiumr-4-processor/
 */

inline void fast_prand() {
    fast_prandEx(GetTickCount());
}
inline void fast_prandEx(uint32_t seed) {
    g_nextrandom = seed;
}

uint32_t prand() {
// g_nextrandom *= 6364136223846793005;
// g_nextrandom += 1;
//return (uint32_t)(g_nextrandom >> 32) % 0xffffffff;
    g_nextrandom = (214013 * g_nextrandom + 2531011);
    return (g_nextrandom >> 16) & 0xFFFF;
}

