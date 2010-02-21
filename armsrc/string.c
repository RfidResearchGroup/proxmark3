/* Implementations of the common string.h functions */
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
