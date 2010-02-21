#ifndef __STRING_H
#define __STRING_H

int strlen(const char *str);
void *memcpy(void *dest, const void *src, int len);
void *memset(void *dest, int c, int len);
int memcmp(const void *av, const void *bv, int len);
char *strncat(char *dest, const char *src, unsigned int n);

#endif /* __STRING_H */