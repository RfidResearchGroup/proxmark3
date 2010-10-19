//-----------------------------------------------------------------------------
// Jonathan Westhues, Sept 2005
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Common string.h functions
//-----------------------------------------------------------------------------

#include "string.h"
#include <stdint.h>

void *memcpy(void *dest, const void *src, int len)
{
	uint8_t *d = dest;
	const uint8_t *s = src;
	while((len--) > 0) {
		*d = *s;
		d++;
		s++;
	}
	return dest;
}

void *memset(void *dest, int c, int len)
{
	uint8_t *d = dest;
	while((len--) > 0) {
		*d = c;
		d++;
	}
	return dest;
}

int memcmp(const void *av, const void *bv, int len)
{
	const uint8_t *a = av;
	const uint8_t *b = bv;

	while((len--) > 0) {
		if(*a != *b) {
			return *a - *b;
		}
		a++;
		b++;
	}
	return 0;
}

int strlen(const char *str)
{
	int l = 0;
	while(*str) {
		l++;
		str++;
	}
	return l;
}

char* strncat(char *dest, const char *src, unsigned int n)
{
	unsigned int dest_len = strlen(dest);
	unsigned int i;

	for (i = 0 ; i < n && src[i] != '\0' ; i++)
		dest[dest_len + i] = src[i];
	dest[dest_len + i] = '\0';

	return dest;
}

char* strcat(char *dest, const char *src)
{
	unsigned int dest_len = strlen(dest);
	unsigned int i;

	for (i = 0 ; src[i] != '\0' ; i++)
		dest[dest_len + i] = src[i];
	dest[dest_len + i] = '\0';

	return dest;
}
////////////////////////////////////////// code to do 'itoa'

/* reverse:  reverse string s in place */
void strreverse(char s[])
{
    int c, i, j;

    for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

/* itoa:  convert n to characters in s */
void itoa(int n, char s[])
{
    int i, sign;

    if ((sign = n) < 0)  /* record sign */
        n = -n;          /* make n positive */
    i = 0;
    do {       /* generate digits in reverse order */
        s[i++] = n % 10 + '0';   /* get next digit */
    } while ((n /= 10) > 0);     /* delete it */
    if (sign < 0)
        s[i++] = '-';
    s[i] = '\0';
    strreverse(s);
}

//////////////////////////////////////// END 'itoa' CODE
