/*
    getopt.h 1.2 2003/09/17 16:17:59

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
*/

extern char *optarg;
extern int optind, opterr, optopt, pos;
int getopt(int argc, char *argv[], const char *optstring);
