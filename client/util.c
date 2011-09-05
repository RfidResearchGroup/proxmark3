//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// utilities
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "util.h"

#ifndef WIN32
#include <termios.h>
#include <sys/ioctl.h> 
int ukbhit(void)
{
  int cnt = 0;
  int error;
  static struct termios Otty, Ntty;


  tcgetattr( 0, &Otty);
  Ntty = Otty;

  Ntty.c_iflag          = 0;       /* input mode                */
  Ntty.c_oflag          = 0;       /* output mode               */
  Ntty.c_lflag         &= ~ICANON; /* raw mode */
  Ntty.c_cc[VMIN]       = CMIN;    /* minimum time to wait      */
  Ntty.c_cc[VTIME]      = CTIME;   /* minimum characters to wait for */

  if (0 == (error = tcsetattr(0, TCSANOW, &Ntty))) {
    error += ioctl(0, FIONREAD, &cnt);
    error += tcsetattr(0, TCSANOW, &Otty);
  }

  return ( error == 0 ? cnt : -1 );
}

#else
#include <conio.h>
int ukbhit(void) {
	return kbhit();
}
#endif


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

//  -------------------------------------------------------------------------
//  string parameters lib
//  -------------------------------------------------------------------------

//  -------------------------------------------------------------------------
//  line     - param line
//  bg, en   - symbol numbers in param line of beginning an ending parameter
//  paramnum - param number (from 0)
//  -------------------------------------------------------------------------
int param_getptr(const char *line, int *bg, int *en, int paramnum)
{
	int i;
	int len = strlen(line);
	
	*bg = 0;
	*en = 0;
	
  // skip spaces
	while (line[*bg] ==' ' || line[*bg]=='\t') (*bg)++;
	if (*bg >= len) {
		return 1;
	}

	for (i = 0; i < paramnum; i++) {
		while (line[*bg]!=' ' && line[*bg]!='\t' && line[*bg] != '\0') (*bg)++;
		while (line[*bg]==' ' || line[*bg]=='\t') (*bg)++;
		
		if (line[*bg] == '\0') return 1;
	}
	
	*en = *bg;
	while (line[*en] != ' ' && line[*en] != '\t' && line[*en] != '\0') (*en)++;
	
	(*en)--;

	return 0;
}

char param_getchar(const char *line, int paramnum)
{
	int bg, en;
	
	if (param_getptr(line, &bg, &en, paramnum)) return 0x00;

	return line[bg];
}

uint8_t param_get8(const char *line, int paramnum)
{
	return param_get8ex(line, paramnum, 10, 0);
}

uint8_t param_get8ex(const char *line, int paramnum, int deflt, int base)
{
	int bg, en;

	if (!param_getptr(line, &bg, &en, paramnum)) 
		return strtol(&line[bg], NULL, base) & 0xff;
	else
		return deflt;
}

uint32_t param_get32ex(const char *line, int paramnum, int deflt, int base)
{
	int bg, en;

	if (!param_getptr(line, &bg, &en, paramnum)) 
		return strtol(&line[bg], NULL, base);
	else
		return deflt;
}

uint64_t param_get64ex(const char *line, int paramnum, int deflt, int base)
{
	int bg, en;

	if (!param_getptr(line, &bg, &en, paramnum)) 
		return strtol(&line[bg], NULL, base);
	else
		return deflt;

	return 0;
}

int param_gethex(const char *line, int paramnum, uint8_t * data, int hexcnt)
{
	int bg, en, temp, i;

	if (hexcnt % 2)
		return 1;
	
	if (param_getptr(line, &bg, &en, paramnum)) return 1;

	if (en - bg + 1 != hexcnt) 
		return 1;

	for(i = 0; i < hexcnt; i += 2) {
		if (!(isxdigit(line[bg + i]) && isxdigit(line[bg + i + 1])) )	return 1;
		
		sscanf((char[]){line[bg + i], line[bg + i + 1], 0}, "%X", &temp);
		data[i / 2] = temp & 0xff;
	}	

	return 0;
}
