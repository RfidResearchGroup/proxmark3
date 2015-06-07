/*----------------------------------------------------------------------

    Replacement for Unix "getopt()", for DOS/Windows/etc.

    getopt.c 1.3 2003/09/17 16:17:59

    Copyright (C) 1998, 2003 by David A. Hinds -- All Rights Reserved

    This file is part of ASPEX.

    ASPEX is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    ASPEX is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ASPEX; if not, write to the Free Software Foundation,
    Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

----------------------------------------------------------------------*/

#include "string.h"
#include "stdio.h"
#include "getopt.h"

char *optarg;
int optind = 1, opterr, optopt;
int pos = 0;
int getopt(int argc, char *argv[], const char *optstring)
{
    //static int pos = 0;
    char *str;
    
    if (pos == 0) {
	if ((optind >= argc) || (*argv[optind] != '-'))
	    return EOF;
	pos = 1;
	if (argv[optind][pos] == '\0')
	    return EOF;
    }
    
    str = strchr(optstring, argv[optind][pos]);
    if (str == NULL) {
	optopt = argv[optind][pos];
	if (opterr)
	    fprintf(stderr, "%s: illegal option -- %c\n", argv[0],
		    optopt);
	return '?';
    }
    
    if (str[1] == ':') {
	if (argv[optind][pos+1] != '\0') {
	    optarg = &argv[optind][pos+1];
	    return *str;
	}
	optind++;
	if (optind >= argc) {
	    optopt = *str;
	    if (opterr)
		fprintf(stderr, "%s: option requires an argument -- %c\n",
			argv[0], optopt);
	    return '?';
	}
	optarg = argv[optind];
	optind++; pos = 0;
	return *str;
    }
    else {
	pos++;
	if (argv[optind][pos] == '\0') {
	    optind++;
	    pos = 0;
	}
	return *str;
    }
}
