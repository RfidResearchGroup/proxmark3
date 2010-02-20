//-----------------------------------------------------------------------------
// Just vector to AppMain(). This is in its own file so that I can place it
// with the linker script.
// Jonathan Westhues, Mar 2006
//-----------------------------------------------------------------------------
#include "proxmark3.h"
#include "apps.h"

extern char __data_start__, __data_src_start__,  __data_end__, __bss_start__, __bss_end__;
void __attribute__((section(".startos"))) Vector(void)
{
	/* Stack should have been set up by the bootloader */
	char *src, *dst, *end;

	/* Set up (that is: clear) BSS. */
	dst = &__bss_start__;
	end = &__bss_end__;
	while(dst < end) *dst++ = 0;

	/* Set up data segment: Copy from flash to ram */
	src = &__data_src_start__;
	dst = &__data_start__;
	end = &__data_end__;
	while(dst < end) *dst++ = *src++;

	AppMain();
}
