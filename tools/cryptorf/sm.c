/*
 *
 * SecureMemory simulation
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
    size_t pos;

    uint8_t    Q[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // Reader random
    uint8_t   Gc[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // Secret seed
    uint8_t   Ci[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // Card random (last state)
    uint8_t   Ch[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // Reader answer
    uint8_t Ci_1[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // Card answer

    // Various argument options
    uint64_t nGc; // Card secret
    uint64_t nCi; // Card random
    uint64_t nQ; // Reader main-random

    // Show header and help syntax
    printf("SecureMemory simulator - (c) Radboud University Nijmegen\n");
    if (argc < 4) {
        printf("\nsyntax: sm <Gc> <Ci> <Q>\n");
        return 1;
    }

    // Parse arguments
    sscanf(argv[1], "%016" SCNx64, &nGc);
    num_to_bytes(nGc, 8, Gc);
    sscanf(argv[2], "%016" SCNx64, &nCi);
    num_to_bytes(nCi, 8, Ci);
    sscanf(argv[3], "%016" SCNx64, &nQ);
    num_to_bytes(nQ, 8, Q);

    // Calculate authentication
    sm_auth(Gc, Ci, Q, Ch, Ci_1, &s);

    printf("\nAuthentication info\n\n");
    printf("  Gc: ");
    print_bytes(Gc, 8);
    printf("  Ci: ");
    print_bytes(Ci, 8);
    printf("   Q: ");
    print_bytes(Q, 8);
    printf("  Ch: ");
    print_bytes(Ch, 8);
    printf("Ci+1: ");
    print_bytes(Ci_1, 8);
    printf("\n");
    printf("  Ks: ");
    for (pos = 0; pos < 8; pos++) {
        printf("%02x ", Ci_1[pos]);
        printf("%02x ", Ch[pos]);
    }
    printf("\n\n");

    return 0;
}
