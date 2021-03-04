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
#ifndef WITH_NO_COMPRESSION
#include "lz4.h"
#endif
#include "BigBuf.h"
#include "string.h"

extern struct common_area common_area;
extern char __data_src_start__, __data_start__, __data_end__, __bss_start__, __bss_end__;

#ifndef WITH_NO_COMPRESSION
static void uncompress_data_section(void) {
    int avail_in;
    memcpy(&avail_in, &__data_src_start__, sizeof(int));
    int avail_out = &__data_end__ - &__data_start__;  // uncompressed size. Correct.
    // uncompress data segment to RAM
    uintptr_t p = (uintptr_t)&__data_src_start__;
    int res = LZ4_decompress_safe((char *)p + 4, &__data_start__, avail_in, avail_out);

    if (res < 0)
        return;
    // save the size of the compressed data section
    common_area.arg1 = avail_in;
}
#endif

void __attribute__((section(".startos"))) Vector(void);
void Vector(void) {
    /* Stack should have been set up by the bootloader */

    if (common_area.magic != COMMON_AREA_MAGIC || common_area.version != 1) {
        /* Initialize common area */
        memset(&common_area, 0, sizeof(common_area));
        common_area.magic = COMMON_AREA_MAGIC;
        common_area.version = 1;
    }
    common_area.flags.osimage_present = 1;

    /* Set up data segment: Copy from flash to ram */
#ifdef WITH_NO_COMPRESSION
    char *data_src = &__data_src_start__;
    char *data_dst = &__data_start__;
    char *data_end = &__data_end__;
    while (data_dst < data_end) *data_dst++ = *data_src++;
#else
    uncompress_data_section();
#endif

    /* Set up (that is: clear) BSS. */
    char *bss_dst = &__bss_start__;
    char *bss_end = &__bss_end__;
    while (bss_dst < bss_end) *bss_dst++ = 0;

    AppMain();
}
#endif
