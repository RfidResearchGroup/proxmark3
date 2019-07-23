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

void *memcpy(void *dest, const void *src, int len) {
    uint8_t *d = dest;
    const uint8_t *s = src;
    while ((len--) > 0) {
        *d = *s;
        d++;
        s++;
    }
    return dest;
}

void *memset(void *dest, int c, int len) {
    uint8_t *d = dest;
    while ((len--) > 0) {
        *d = c;
        d++;
    }
    return dest;
}

int memcmp(const void *av, const void *bv, int len) {
    const uint8_t *a = av;
    const uint8_t *b = bv;

    while ((len--) > 0) {
        if (*a != *b) {
            return *a - *b;
        }
        a++;
        b++;
    }
    return 0;
}

void memxor(uint8_t *dest, uint8_t *src, size_t len) {
    for (; len > 0; len--, dest++, src++)
        *dest ^= *src;
}

int strlen(const char *str) {
    const char *p;
    for (p = str; *p != '\0'; ++p) {
    }
    return p - str;
}

char *strncat(char *dest, const char *src, unsigned int n) {
    unsigned int dest_len = strlen(dest);
    unsigned int i;

    for (i = 0 ; i < n && src[i] != '\0' ; i++)
        dest[dest_len + i] = src[i];
    dest[dest_len + i] = '\0';

    return dest;
}

char *strcat(char *dest, const char *src) {
    unsigned int dest_len = strlen(dest);
    unsigned int i;

    for (i = 0 ; src[i] != '\0' ; i++)
        dest[dest_len + i] = src[i];
    dest[dest_len + i] = '\0';

    return dest;
}
////////////////////////////////////////// code to do 'itoa'

/* reverse:  reverse string s in place */
void strreverse(char s[]) {
    int j = strlen(s) - 1;

    for (int i = 0; i < j; i++, j--) {
        int c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

/* itoa:  convert n to characters in s */
void itoa(int n, char s[]) {
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



char *strcpy(char *dst, const char *src)
    {
      char *save = dst;

      for (; (*dst = *src) != '\0'; ++src, ++dst);
      return save;
    }

char *strncpy(char *dst, const char *src, size_t n)
 {
     if (n != 0) {
         char *d = dst;
         const char *s = src;

         do {
             if ((*d++ = *s++) == 0) {
                 /* NUL pad the remaining n-1 bytes */
                 while (--n) {
                    *d++ = 0;
                 }
                 break;
             }
         } while (--n);
    }
     return dst;
 }

int strcmp(const char *s1, const char *s2)
{
    while (*s1 == *s2++) {
        if (*s1++ == 0) {
            return (0);
        }
    }
    return (*(unsigned char *) s1 - *(unsigned char *) --s2);
}

char* __strtok_r(char*, const char*, char**);

char* __strtok_r(char* s, const char* delim, char** last)
{
	char *spanp, *tok;
	int c, sc;

	if(s == NULL && (s = *last) == NULL)
		return (NULL);

/*
 * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
 */
cont:
	c = *s++;
	for(spanp = (char*)delim; (sc = *spanp++) != 0;)
	{
		if(c == sc)
			goto cont;
	}

	if(c == 0)
	{ /* no non-delimiter characters */
		*last = NULL;
		return (NULL);
	}
	tok = s - 1;

	/*
	 * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
	 * Note that delim must have one NUL; we stop if we see that, too.
	 */
	for(;;)
	{
		c = *s++;
		spanp = (char*)delim;
		do
		{
			if((sc = *spanp++) == c)
			{
				if(c == 0)
					s = NULL;
				else
					s[-1] = '\0';
				*last = s;
				return (tok);
			}
		} while(sc != 0);
	}
	/* NOTREACHED */
}

char* strtok(char* s, const char* delim)
{
	static char* last;

	return (__strtok_r(s, delim, &last));
}
