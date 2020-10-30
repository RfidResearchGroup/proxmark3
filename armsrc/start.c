//-----------------------------------------------------------------------------
// Jonathan Westhues, Mar 2006
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Just vector to AppMain(). This is in its own file so that I can place it
// with the linker script.
//-----------------------------------------------------------------------------

#ifndef __START_H
#define __START_H

#include "proxmark3_arm.h"
#include "appmain.h"
#include "lz4.h"
#include "BigBuf.h"
#include "string.h"

static uint8_t *next_free_memory;
extern struct common_area common_area;
extern char __data_src_start__, __data_start__, __data_end__, __bss_start__, __bss_end__;

static void uncompress_data_section(void) {
    next_free_memory = BigBuf_get_addr();
    int avail_in;
    memcpy(&avail_in, &__data_start__, sizeof(int));
    int avail_out = &__data_end__ - &__data_start__;  // uncompressed size. Correct.
    // uncompress data segment to RAM
    uintptr_t p = (uintptr_t)&__data_src_start__;
    int res = LZ4_decompress_safe((char *)p + 4, &__data_start__, avail_in, avail_out);

    if (res < 0)
        return;
    // save the size of the compressed data section
    common_area.arg1 = res;
}

void __attribute__((section(".startos"))) Vector(void);
void Vector(void) {
    /* Stack should have been set up by the bootloader */

    uncompress_data_section();

    /* Set up (that is: clear) BSS. */
    char *dst = &__bss_start__;
    char *end = &__bss_end__;
    while (dst < end) *dst++ = 0;

    AppMain();
}
#endif
