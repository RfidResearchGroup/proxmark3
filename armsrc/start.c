//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Mar 2006
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Just vector to AppMain(). This is in its own file so that I can place it
// with the linker script.
//-----------------------------------------------------------------------------

#ifndef __START_H
#define __START_H

#include "proxmark3_arm.h"
#include "appmain.h"
#ifndef WITH_NO_COMPRESSION
#include "lz4.h"
#endif
#include "BigBuf.h"
#include "string.h"
#include "ticks.h"

extern common_area_t g_common_area;
extern uint32_t __data_src_start__[], __data_start__[], __data_end__[], __bss_start__[], __bss_end__[];

#ifndef WITH_NO_COMPRESSION
static void uncompress_data_section(void) {
    int avail_in;
    memcpy(&avail_in, __data_src_start__, sizeof(int));
    int avail_out = (uint32_t)__data_end__ - (uint32_t)__data_start__;  // uncompressed size. Correct.
    // uncompress data segment to RAM
    char *p = (char *)__data_src_start__;
    int res = LZ4_decompress_safe(p + 4, (char *)__data_start__, avail_in, avail_out);
    if (res < 0) {
        while (true) {
            LED_A_INV();
            LED_B_INV();
            LED_C_INV();
            LED_D_INV();
            SpinDelay(200);
        }
    }
    // save the size of the compressed data section
    g_common_area.arg1 = avail_in;
}
#endif

void __attribute__((section(".startos"))) Vector(void);
void Vector(void) {
    /* Stack should have been set up by the bootloader */

    if (g_common_area.magic != COMMON_AREA_MAGIC || g_common_area.version != 1) {
        /* Initialize common area */
        memset(&g_common_area, 0, sizeof(g_common_area));
        g_common_area.magic = COMMON_AREA_MAGIC;
        g_common_area.version = 1;
    }
    g_common_area.flags.osimage_present = 1;

    /* Set up data segment: Copy from flash to ram */
#ifdef WITH_NO_COMPRESSION
    uint32_t *data_src = __data_src_start__;
    uint32_t *data_dst = __data_start__;
    while (data_dst < __data_end__) *data_dst++ = *data_src++;
#else
    uncompress_data_section();
#endif

    /* Set up (that is: clear) BSS. */
    uint32_t *bss_dst = __bss_start__;
    while (bss_dst < __bss_end__) *bss_dst++ = 0;

    AppMain();
}
#endif
