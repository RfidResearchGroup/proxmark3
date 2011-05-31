//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// utilities
//-----------------------------------------------------------------------------

#include "util.h"

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

void num_to_bytes(uint64_t n, size_t len, uint8_t* dest)
{
	while (len--) {
		dest[len] = (uint8_t) n;
		n >>= 8;
	}
}

uint64_t bytes_to_num(uint8_t* src, size_t len)
{
	uint64_t num = 0;
	while (len--)
	{
		num = (num << 8) | (*src);
		src++;
	}
	return num;
}
