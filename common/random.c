#include "random.h"

 uint64_t next_random = 1;

/* Generates a (non-cryptographically secure) 32-bit random number.
 *
 * We don't have an implementation of the "rand" function. Instead we use a
 * method of seeding with the time it took to call "autoseed" from first run.
 * 
 * https://github.com/Proxmark/proxmark3/pull/209/commits/f9c1dcd9f6e68a8c07cffed697a9c4c8caed6015
 */
uint32_t prand() {
	if (next_random == 1)
		next_random = GetTickCount();

	next_random *= 6364136223846793005;
	next_random += 1;
	
	return (uint32_t)(next_random >> 32) % 0xffffffff;
}

