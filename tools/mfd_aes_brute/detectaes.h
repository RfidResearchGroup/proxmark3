// Checks if CPU has support of AES instructions
//
// @author kryukov@frtk.ru
//
// Source code from:
//
// https://github.com/pavelkryukov/putty-aes-ni/blob/master/aescpuid.c
//
// MIT License
// Copyright (c) 2012-2021 Pavel Kryukov, Maxim Kuznetsov, and Svyatoslav Kuzmich
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#include <stdbool.h>
#include <stdio.h>

#if defined(__x86_64__) || defined(__i386)

#if defined(__clang__) || defined(__GNUC__)

#include <cpuid.h>
static bool platform_aes_hw_available(void) {
    unsigned int CPUInfo[4];
    __cpuid(1, CPUInfo[0], CPUInfo[1], CPUInfo[2], CPUInfo[3]);
    return (CPUInfo[2] & (1 << 25)) != 0 && (CPUInfo[2] & (1 << 19)) != 0; /* Check AES and SSE4.1 */
}

#else /* defined(__clang__) || defined(__GNUC__) */

static bool platform_aes_hw_available(void) {
    unsigned int CPUInfo[4];
    __cpuid(CPUInfo, 1);
    return (CPUInfo[2] & (1 << 25)) != 0 && (CPUInfo[2] & (1 << 19)) != 0; /* Check AES and SSE4.1 */
}

#endif /* defined(__clang__) || defined(__GNUC__) */

#else /* defined(__x86_64__) || defined(__i386) */


#include <sys/auxv.h>
#include <asm/hwcap.h>

static bool platform_aes_hw_available(void) {
#if defined HWCAP_AES
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#elif defined HWCAP2_AES
    return (getauxval(AT_HWCAP2) & HWCAP2_AES) != 0;

#else
    return false;
#endif
}

#endif /* defined(__x86_64__) || defined(__i386) */
