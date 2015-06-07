/* bmpbit.c
 * Greg Cook, 9/Apr/2015
 */

/* CRC RevEng, an arbitrary-precision CRC calculator and algorithm finder
 * Copyright (C) 2010, 2011, 2012, 2013, 2014, 2015  Gregory Cook
 *
 * This file is part of CRC RevEng.
 *
 * CRC RevEng is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CRC RevEng is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with CRC RevEng.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef BMPTST
#  include <stdio.h>
#  include <stdlib.h>
#else
#  define FILE void
#endif
#include "reveng.h"

#if (defined BMPTST) || (BMP_BIT < 32)
/* Size in bits of a bmp_t.  Not necessarily a power of two. */
int bmpbit;

/* The highest power of two that is strictly less than BMP_BIT.
 * Initialises the index of a binary search for set bits in a bmp_t.
 * (Computed correctly for BMP_BIT >= 2)
 */
int bmpsub;

void
setbmp(void) {
	/* Initialise BMP_BIT and BMP_SUB for the local architecture. */
	bmp_t bmpmax = ~(bmp_t) 0;

	bmpbit = 0; bmpsub = 1;

	while(bmpmax) {
		bmpmax <<= 1;
		++bmpbit;
	}

	while((bmpsub | (bmpsub - 1)) < bmpbit - 1)
		bmpsub <<= 1;
}
#endif

#ifdef BMPTST
int
main(int argc, char *argv[]) {
	/* check the compile-time bitmap width is correct, otherwise
	 * searches run forever. */
#  if BMP_BIT > 0
	setbmp();
	if(BMP_BIT != bmpbit || BMP_SUB != bmpsub) {
		fprintf(stderr,"reveng: configuration fault.  Update "
			"config.h with these definitions and "
			"recompile:\n"
			"\t#define BMP_BIT   %d\n"
			"\t#define BMP_SUB   %d\n",
			bmpbit, bmpsub);
		exit(EXIT_FAILURE);
	}
#  endif /* BMP_BIT > 0 */
	/* check the bitmap constant macro */
	if(~(bmp_t) 0 != ~BMP_C(0)) {
		fprintf(stderr, "reveng: configuration fault.  Edit "
			"the definition of BMP_C() in config.h to "
			"match BMP_T and recompile.\n");
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}

#endif /* BMPTST */
