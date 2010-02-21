//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Helper function for launching the bootloader from FLASH
//-----------------------------------------------------------------------------

#include <proxmark3.h>

extern char __bootphase2_src_start__, __bootphase2_start__, __bootphase2_end__;
void __attribute__((section(".bootphase1"))) CopyBootToRAM(void)
{
	int i;

	volatile uint32_t *s = (volatile uint32_t *)&__bootphase2_src_start__;
	volatile uint32_t *d = (volatile uint32_t *)&__bootphase2_start__;
	unsigned int l = (int)&__bootphase2_end__ - (int)&__bootphase2_start__;

	for(i = 0; i < l/sizeof(uint32_t); i++) *d++ = *s++;
}
