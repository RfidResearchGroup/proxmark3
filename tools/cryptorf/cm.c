/*
 *
 * CryptoMemory simulation
 *
 * Copyright (C) 2010, Flavio D. Garcia, Peter van Rossum, Roel Verdult
 * and Ronny Wichers Schreur. Radboud University Nijmegen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include "cryptolib.h"
#include "util.h"
#ifdef _MSC_VER
// avoid scanf warnings in Visual Studio
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#endif

int main(int argc, const char *argv[]) {
    // Cryptomemory state
    crypto_state_t s;

    // Main authentication values
    uint8_t     Q[8]; // Reader key-auth random
    uint8_t    Gc[8]; // Secret seed
    uint8_t    Ci[8]; // Card random (last state)
    uint8_t    Ch[8]; // Reader answer (challenge)
    uint8_t  Ci_1[8]; // Card answer
    uint8_t  Ci_2[8]; // Session key

    // Session authentication values
    uint8_t    Qs[8]; // Reader session-auth random
    uint8_t   Chs[8]; // Reader session-answer (challenge)
    uint8_t Ci_1s[8]; // Card answer for session
    uint8_t Ci_2s[8]; // Is this used?

    // Various argument options
    uint64_t nGc; // Card secret
    uint64_t nCi; // Card random
    uint64_t nQ; // Reader main-random
    uint64_t nQs; // Reader session-random

    // Show header and help syntax
    printf("CryptoMemory simulator - (c) Radboud University Nijmegen\n");
    if (argc < 5) {
        printf("\nsyntax: cm <Gc> <Ci> <Q> <Q(s)>\n");
        return 1;
    }

    // Parse arguments
    sscanf(argv[1], "%016" SCNx64, &nGc);
    num_to_bytes(nGc, 8, Gc);
    sscanf(argv[2], "%016" SCNx64, &nCi);
    num_to_bytes(nCi, 8, Ci);
    sscanf(argv[3], "%016" SCNx64, &nQ);
    num_to_bytes(nQ, 8, Q);
    sscanf(argv[4], "%016" SCNx64, &nQs);
    num_to_bytes(nQs, 8, Qs);

    // Calculate authentication
    cm_auth(Gc, Ci, Q, Ch, Ci_1, Ci_2, &s);

    printf("\nAuthenticate\n");
    printf("     Gc: ");
    print_bytes(Gc, 8);
    printf("     Ci: ");
    print_bytes(Ci, 8);
    printf("      Q: ");
    print_bytes(Q, 8);
    printf("     Ch: ");
    print_bytes(Ch, 8);
    printf("   Ci+1: ");
    print_bytes(Ci_1, 8);
    printf("   Ci+2: ");
    print_bytes(Ci_2, 8);

    cm_auth(Ci_2, Ci_1, Qs, Chs, Ci_1s, Ci_2s, &s);

    printf("\nVerify Crypto (Session Key)\n");
    printf("  Gc(s): ");
    print_bytes(Ci_2, 8);
    printf("  Ci(s): ");
    print_bytes(Ci_1, 8);
    printf("   Q(s): ");
    print_bytes(Qs, 8);
    printf("  Ch(s): ");
    print_bytes(Chs, 8);
    printf("Ci+1(s): ");
    print_bytes(Ci_1s, 8);
    printf("Ci+2(s): ");
    print_bytes(Ci_2s, 8);

    printf("\n");
    return 0;
}
