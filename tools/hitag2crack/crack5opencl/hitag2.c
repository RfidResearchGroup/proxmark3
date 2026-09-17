#include <stdio.h>
#include "ht2crack5opencl.h"
#include "hitagcrypto.h"
#include "ht2crackutils.h"
#include "hitag2.h"

//#if FORCE_HITAG2_FULL == 0

// try state

// todo, changes arguments, only what is needed
bool try_state(uint64_t s, uint32_t uid, uint32_t aR2, uint32_t nR1, uint32_t nR2, uint64_t *key) {
#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("s : %lu, uid: %u, aR2: %u, nR1: %u, nR2: %u\n", s, uid, aR2, nR1, nR2);
    fflush(stdout);
#endif

    Hitag_State hstate;
    uint64_t keyrev, nR1xk;
    uint32_t b = 0;

    hstate.shiftreg = s;

    //rollback(&hstate, 2);
    hstate.shiftreg = (uint64_t)(((hstate.shiftreg << 1) & 0xffffffffffff) | (uint64_t)fnR(hstate.shiftreg));
    hstate.shiftreg = (uint64_t)(((hstate.shiftreg << 1) & 0xffffffffffff) | (uint64_t)fnR(hstate.shiftreg));

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("shiftreg : %lu\n", hstate.shiftreg);
    fflush(stdout);
#endif

    // recover key
    keyrev = hstate.shiftreg & 0xffff;
    nR1xk = (hstate.shiftreg >> 16) & 0xffffffff;

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("keyrev: %lu, nR1xk: %lu\n", keyrev, nR1xk);
    fflush(stdout);
#endif

    for (int i = 0; i < 32; i++) {
        hstate.shiftreg = ((hstate.shiftreg) << 1) | ((uid >> (31 - i)) & 0x1);
        b = (b << 1) | (unsigned int) fnf(hstate.shiftreg);
    }

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("shiftreg: %lu\n", hstate.shiftreg);
    fflush(stdout);
#endif

    keyrev |= (nR1xk ^ nR1 ^ b) << 16;

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("keyrev: %lu\n", keyrev);
    fflush(stdout);
#endif

    // test key
    hitag2_init(&hstate, keyrev, uid, nR2);
    if ((aR2 ^ hitag2_nstep(&hstate, 32)) == 0xffffffff) {
        *key = rev64(keyrev);

#if DEBUGME >= 2
#if ENABLE_EMOJ == 1
        printf("\nKey found ╭☞  ");
#else
        printf("\nKey found: ");
#endif
        for (int i = 0; i < 6; i++) {
            printf("%02X", (uint8_t)(*key & 0xff));
            *key = *key >> 8;
        }
        printf("\n");
#endif
        return true;
    }

    return false;
}

//#endif // FORCE_HITAG2_FULL = 0
