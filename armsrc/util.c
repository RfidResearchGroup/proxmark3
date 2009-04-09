//-----------------------------------------------------------------------------
// Utility functions used in many places, not specific to any piece of code.
// Jonathan Westhues, Sept 2005
//-----------------------------------------------------------------------------
#include <proxmark3.h>
#include "apps.h"

void *memcpy(void *dest, const void *src, int len)
{
	BYTE *d = dest;
	const BYTE *s = src;
	while((len--) > 0) {
		*d = *s;
		d++;
		s++;
	}
	return dest;
}

void *memset(void *dest, int c, int len)
{
	BYTE *d = dest;
	while((len--) > 0) {
		*d = c;
		d++;
	}
	return dest;
}

int memcmp(const void *av, const void *bv, int len)
{
	const BYTE *a = av;
	const BYTE *b = bv;

	while((len--) > 0) {
		if(*a != *b) {
			return *a - *b;
		}
		a++;
		b++;
	}
	return 0;
}

int strlen(char *str)
{
	int l = 0;
	while(*str) {
		l++;
		str++;
	}
	return l;
}
