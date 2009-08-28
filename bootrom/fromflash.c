#include <proxmark3.h>

void __attribute__((section(".bootphase1"))) CopyBootToRAM(void)
{
	int i;

	volatile DWORD *s = (volatile DWORD *)0x200;
	volatile DWORD *d = (volatile DWORD *)0x200000;

	for(i = 0; i < 1024; i++) *d++ = *s++;
}
