#include <stdio.h>
#include <stdint.h>

void print_hex(const uint8_t * data, const size_t len)
{
	size_t i;

	for (i=0; i < len; i++)
		printf("%02x ", data[i]);

	printf("\n");
}

char * sprint_hex(const uint8_t * data, const size_t len) {
	static char buf[1024];
	char * tmp = buf;
	size_t i;

	for (i=0; i < len && i < 1024/3; i++, tmp += 3)
		sprintf(tmp, "%02x ", data[i]);

	return buf;
}
