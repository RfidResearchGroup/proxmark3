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

#include "proxmark3.h"
#include "apps.h"
#include "zlib.h"
#include "BigBuf.h"

static uint8_t *next_free_memory;
extern struct common_area common_area;
extern char __data_src_start__, __data_start__, __data_end__, __bss_start__, __bss_end__;


static voidpf inflate_malloc(voidpf opaque, uInt items, uInt size)
{
	uint8_t *allocated_memory;
	
	allocated_memory = next_free_memory;
	next_free_memory += items*size;
	return allocated_memory;
}


static void inflate_free(voidpf opaque, voidpf address)
{
	// nothing to do
	
}

static void uncompress_data_section(void)
{
	z_stream data_section;

	next_free_memory = BigBuf_get_addr();
	
	// initialize zstream structure
	data_section.next_in = (uint8_t *) &__data_src_start__;
	data_section.avail_in = &__data_end__ - &__data_start__;  // uncompressed size. Wrong but doesn't matter.
	data_section.next_out = (uint8_t *) &__data_start__;
	data_section.avail_out = &__data_end__ - &__data_start__;  // uncompressed size. Correct.
	data_section.zalloc = &inflate_malloc;
	data_section.zfree = &inflate_free;
	data_section.opaque = NULL;

	// initialize zlib for inflate
	inflateInit2(&data_section, 15);

	// uncompress data segment to RAM
	inflate(&data_section, Z_FINISH);
	
	// save the size of the compressed data section
	common_area.arg1 = data_section.total_in;
}


void __attribute__((section(".startos"))) Vector(void)
{
	/* Stack should have been set up by the bootloader */
	// char *src;
	char *dst, *end;
	
	uncompress_data_section();

	/* Set up (that is: clear) BSS. */
	dst = &__bss_start__;
	end = &__bss_end__;
	while(dst < end) *dst++ = 0;

	// Set up data segment: Copy from flash to ram
	// src = &__data_src_start__;
	// dst = &__data_start__;
	// end = &__data_end__;
	// while(dst < end) *dst++ = *src++;


	AppMain();
}
