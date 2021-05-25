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
extern uint32_t __data_src_start__[], __data_start__[], __data_end__[], __bss_start__[], __bss_end__[];

#ifndef WITH_NO_COMPRESSION
static void uncompress_data_section(void) {
    int avail_in;
    memcpy(&avail_in, __data_src_start__, sizeof(int));
    int avail_out = (uint32_t)__data_end__ - (uint32_t)__data_start__;  // uncompressed size. Correct.
    // uncompress data segment to RAM
    char *p = (char *)__data_src_start__;
    int res = LZ4_decompress_safe(p + 4, (char *)__data_start__, avail_in, avail_out);

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
