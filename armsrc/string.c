//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
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

void *memmove(void *dest, const void *src, size_t len) {
    char *d = dest;
    const char *s = src;
    if (d < s)
        while (len--)
            *d++ = *s++;
    else {
        char *lasts = (char *)s + (len - 1);
        char *lastd = d + (len - 1);
        while (len--)
            *lastd-- = *lasts--;
    }
    return dest;
}

void *memset(void *dest, uint8_t c, int len) {
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
    for (p = str; *p != '\0'; ++p) {};
    return p - str;
}

char *strncat(char *dest, const char *src, unsigned int n) {
    int dest_len = strlen(dest);
    unsigned int i;

    for (i = 0 ; i < n && src[i] != '\0' ; i++)
        dest[dest_len + i] = src[i];

    dest[dest_len + i] = '\0';

    return dest;
}

char *strcat(char *dest, const char *src) {
    int dest_len = strlen(dest);
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
        char c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

/* itoa:  convert n to characters in s */
void itoa(int n, char s[]) {
    int sign;
    if ((sign = n) < 0)  /* record sign */
        n = -n;          /* make n positive */

    int i = 0;
    do {       /* generate digits in reverse order */
        s[i++] = n % 10 + '0';   /* get next digit */
    } while ((n /= 10) > 0);     /* delete it */
    if (sign < 0)
        s[i++] = '-';
    s[i] = '\0';
    strreverse(s);
}

//////////////////////////////////////// END 'itoa' CODE



char *strcpy(char *dst, const char *src) {
    char *save = dst;

    for (; (*dst = *src) != '\0'; ++src, ++dst);
    return save;
}

char *strncpy(char *dst, const char *src, size_t n) {
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

int strcmp(const char *s1, const char *s2) {
    while (*s1 == *s2++) {
        if (*s1++ == 0) {
            return (0);
        }
    }
    return (*(unsigned char *) s1 - * (unsigned char *) --s2);
}

char *__strtok_r(char *, const char *, char **);

char *__strtok_r(char *s, const char *delim, char **last) {
    char *spanp, *tok;
    int c, sc;

    if (s == NULL && (s = *last) == NULL)
        return (NULL);

    /*
     * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
     */
cont:
    c = *s++;
    for (spanp = (char *)delim; (sc = *spanp++) != 0;) {
        if (c == sc)
            goto cont;
    }

    if (c == 0) {
        /* no non-delimiter characters */
        *last = NULL;
        return (NULL);
    }
    tok = s - 1;

    /*
     * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
     * Note that delim must have one NUL; we stop if we see that, too.
     */
    for (;;) {
        c = *s++;
        spanp = (char *)delim;
        do {
            if ((sc = *spanp++) == c) {
                if (c == 0)
                    s = NULL;
                else
                    s[-1] = '\0';
                *last = s;
                return (tok);
            }
        } while (sc != 0);
    }
    /* NOTREACHED */
}

char *strtok(char *s, const char *delim) {
    static char *last;

    return (__strtok_r(s, delim, &last));
}


char *strchr(const char *s, int c) {
    while (*s != (char)c)
        if (!*s++)
            return 0;
    return (char *)s;
}

size_t strspn(const char *s1, const char *s2) {
    size_t ret = 0;
    while (*s1 && strchr(s2, *s1++))
        ret++;
    return ret;
}

char *strrchr(const char *s, int c) {
    const char *ret = 0;
    do {
        if (*s == (char)c)
            ret = s;
    } while (*s++);
    return (char *)ret;
}

size_t strcspn(const char *s1, const char *s2) {
    size_t ret = 0;
    while (*s1)
        if (strchr(s2, *s1))
            return ret;
        else
            s1++, ret++;
    return ret;
}

char *strpbrk(const char *s1, const char *s2) {
    while (*s1)
        if (strchr(s2, *s1++))
            return (char *)--s1;
    return 0;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    while (n--)
        if (*s1++ != *s2++)
            return *(unsigned char *)(s1 - 1) - *(unsigned char *)(s2 - 1);
    return 0;
}




#define isspace(a) __extension__ ({ unsigned char bb__isspace = (a) - 9; bb__isspace == (' ' - 9) || bb__isspace <= (13 - 9); })

unsigned long strtoul(const char *p, char **out_p, int base) {
    unsigned long v = 0;

    while (isspace(*p))
        p++;
    if (((base == 16) || (base == 0)) &&
            ((*p == '0') && ((p[1] == 'x') || (p[1] == 'X')))) {
        p += 2;
        base = 16;
    }
    if (base == 0) {
        if (*p == '0')
            base = 8;
        else
            base = 10;
    }
    while (1) {
        char c = *p;
        if ((c >= '0') && (c <= '9') && (c - '0' < base))
            v = (v * base) + (c - '0');
        else if ((c >= 'a') && (c <= 'z') && (c - 'a' + 10 < base))
            v = (v * base) + (c - 'a' + 10);
        else if ((c >= 'A') && (c <= 'Z') && (c - 'A' + 10 < base))
            v = (v * base) + (c - 'A' + 10);
        else
            break;
        p++;
    }

    if (out_p) *out_p = (char *)p;
    return v;
}

long strtol(const char *p, char **out_p, int base) {
    long v = 0;
    int is_neg = 0;

    while (isspace(*p))
        p++;
    if (*p == '-')
        is_neg = 1, p++;
    else if (*p == '+')
        is_neg = 0;
    if (((base == 16) || (base == 0)) &&
            ((*p == '0') && ((p[1] == 'x') || (p[1] == 'X')))) {
        p += 2;
        base = 16;
    }
    if (base == 0) {
        if (*p == '0')
            base = 8;
        else
            base = 10;
    }
    while (1) {
        char c = *p;
        if ((c >= '0') && (c <= '9') && (c - '0' < base))
            v = (v * base) + (c - '0');
        else if ((c >= 'a') && (c <= 'z') && (c - 'a' + 10 < base))
            v = (v * base) + (c - 'a' + 10);
        else if ((c >= 'A') && (c <= 'Z') && (c - 'A' + 10 < base))
            v = (v * base) + (c - 'A' + 10);
        else
            break;
        p++;
    }
    if (is_neg)
        v = -v;
    if (out_p) *out_p = (char *)p;
    return v;
}

char c_tolower(int c) {
    // (int)a = 97, (int)A = 65
    // (a)97 - (A)65 = 32
    // therefore 32 + 65 = a
    return c > 64 && c < 91 ? c + 32 : c;
}

char c_isprint(unsigned char c) {
    if (c >= 0x20 && c <= 0x7e)
        return 1;
    return 0;
}
