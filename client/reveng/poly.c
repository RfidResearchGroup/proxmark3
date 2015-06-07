/* poly.c
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

/* 2015-04-03: added direct mode to strtop()
 * 2014-01-11: added LOFS(), RNDUP()
 * 2013-09-16: SIZE(), IDX(), OFS() macros bitshift if BMP_POF2
 * 2013-02-07: conditional non-2^n fix, pmpar() return mask constant type
 * 2013-01-17: fixed pfirst(), plast() for non-2^n BMP_BIT
 * 2012-07-16: added pident()
 * 2012-05-23: added pmpar()
 * 2012-03-03: internal lookup tables stored better
 * 2012-03-02: fixed full-width masking in filtop()
 * 2011-09-06: added prevch()
 * 2011-08-27: fixed zero test in piter()
 * 2011-01-17: fixed ANSI C warnings, uses bmp_t type
 * 2011-01-15: palloc() and praloc() gracefully handle lengths slightly
 *	       less than ULONG_MAX
 * 2011-01-15: strtop() error on invalid argument. pkchop() special case
 *	       when argument all zeroes
 * 2011-01-14: added pkchop()
 * 2011-01-04: fixed bogus final length calculation in wide pcrc()
 * 2011-01-02: faster, more robust prcp()
 * 2011-01-01: commented functions, full const declarations, all-LUT rev()
 * 2010-12-26: renamed CRC RevEng
 * 2010-12-18: removed pmods(), finished pcrc(), added piter()
 * 2010-12-17: roughed out pcrc(). difficult, etiam aberat musa heri :(
 * 2010-12-15: added psnorm(), psncmp(); optimised pnorm(); fix to praloc()
 * 2010-12-14: strtop() resets count between passes
 * 2010-12-12: added pright()
 * 2010-12-11: filtop won't read more than length bits
 * 2010-12-10: finished filtop. 26 public functions
 * 2010-12-05: finished strtop, pxsubs; unit tests
 * 2010-12-02: project started
 */

/* Note: WELL-FORMED poly_t objects have a valid bitmap pointer pointing
 * to a malloc()-ed array of at least as many bits as stated in its
 * length field.  Any poly_t with a length of 0 is also a WELL-FORMED
 * poly_t (whatever value the bitmap pointer has.)
 * All poly_t objects passed to and from functions must be WELL-FORMED
 * unless otherwise stated.
 *
 * CLEAN (or CANONICAL) poly_t objects are WELL-FORMED objects in which
 * all spare bits in the bitmap word containing the last bit are zero.
 * (Any excess allocated words will not be accessed.)
 *
 * SEMI-NORMALISED poly_t objects are CLEAN objects in which the last
 * bit, at position (length - 1), is one.
 *
 * NORMALISED poly_t objects are SEMI-NORMALISED objects in which the
 * first bit is one.
 *
 * pfree() should be called on every poly_t object (including
 * those returned by functions) after its last use.
 * As always, free() should be called on every malloc()-ed string after
 * its last use.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "reveng.h"

static bmp_t getwrd(const poly_t poly, unsigned long iter);
static bmp_t rev(bmp_t accu, int bits);
static void prhex(char **spp, bmp_t bits, int flags, int bperhx);

static const poly_t pzero = PZERO;

/* word number (0..m-1) of var'th bit (0..n-1) */
#if BMP_POF2 >= 5
#  define IDX(var) ((var) >> BMP_POF2)
#else
#  define IDX(var) ((var) / BMP_BIT)
#endif

/* size of polynomial with var bits */
#if BMP_POF2 >= 5
#  define SIZE(var) ((BMP_BIT - 1UL + (var)) >> BMP_POF2)
#else
#  define SIZE(var) ((BMP_BIT - 1UL + (var)) / BMP_BIT)
#endif

/* polynomial length rounded up to BMP_BIT */
#ifdef BMP_POF2
#  define RNDUP(var) (~(BMP_BIT - 1UL) & (BMP_BIT - 1UL + (var)))
#else
#  define RNDUP(var) ((BMP_BIT - (var) % BMP_BIT) % BMP_BIT + (var))
#endif

/* bit offset (0..BMP_BIT-1, 0 = LSB) of var'th bit (0..n-1) */
#ifdef BMP_POF2
#  define OFS(var) ((int) ((BMP_BIT - 1UL) & ~(var)))
#else
#  define OFS(var) ((int) (BMP_BIT - 1UL - (var) % BMP_BIT))
#endif

/* bit offset (0..BMP_BIT-1, 0 = MSB) of var'th bit (0..n-1) */
#ifdef BMP_POF2
#  define LOFS(var) ((int) ((BMP_BIT - 1UL) & (var)))
#else
#  define LOFS(var) ((int) ((var) % BMP_BIT))
#endif

poly_t
filtop(FILE *input, unsigned long length, int flags, int bperhx) {
	/* reads binary data from input into a poly_t until EOF or until
	 * length bits are read.  Characters are read until
	 * ceil(bperhx / CHAR_BIT) bits are collected; if P_LTLBYT is
	 * set in flags then the first character contains the LSB,
	 * otherwise the last one does.  The least significant bperhx
	 * bits are taken, reflected (if P_REFIN) and appended to the
	 * result, then more characters are read.  The maximum number of
	 * characters read is
	 *   floor(length / bperhx) * ceil(bperhx / * CHAR_BIT).
	 * The returned poly_t is CLEAN.
	 */

	bmp_t accu = BMP_C(0);
	bmp_t mask = bperhx == BMP_BIT ? ~BMP_C(0) : (BMP_C(1) << bperhx) - BMP_C(1);
	unsigned long iter = 0UL, idx;
	int cmask = ~(~0 << CHAR_BIT), c;
	int count = 0, ofs;
	poly_t poly = PZERO;
	if(bperhx == 0) return(poly);

	length -= length % bperhx;
	palloc(&poly, length); /* >= 0 */

	while(iter < length && (c = fgetc(input)) != EOF) {
		if(flags & P_LTLBYT)
			accu |= (bmp_t) (c & cmask) << count;
		else
			accu = (accu << CHAR_BIT) | (bmp_t) (c & cmask);
		count += CHAR_BIT;
		if(count >= bperhx) {
			/* the low bperhx bits of accu contain bits of the poly.*/
			iter += bperhx;
			count = 0;
			if(flags & P_REFIN)
				accu = rev(accu, bperhx);
			accu &= mask;

			/* iter >= bperhx > 0 */
			idx = IDX(iter - 1UL);
			ofs = OFS(iter - 1UL);
			poly.bitmap[idx] |= accu << ofs;
			if(ofs + bperhx > BMP_BIT) {
				poly.bitmap[idx-1] |= accu >> (BMP_BIT - ofs);
			}
			accu = BMP_C(0); /* only needed for P_LTLBYT */
		}
	}
	praloc(&poly, iter);
	return(poly);
}

poly_t
strtop(const char *string, int flags, int bperhx) {
	/* Converts a hex or character string to a poly_t.
	 * Each character is converted to a hex nibble yielding 4 bits
	 * unless P_DIRECT, when each character yields CHAR_BIT bits.
	 * Nibbles and characters are accumulated left-to-right
	 * unless P_DIRECT && P_LTLBYT, when they are accumulated
	 * right-to-left without reflection.
	 * As soon as at least bperhx bits are accumulated, the
	 * rightmost bperhx bits are reflected (if P_REFIN)
	 * and appended to the poly.  When !P_DIRECT:
	 * bperhx=8 reads hex nibbles in pairs
	 * bperhx=7 reads hex nibbles in pairs and discards
	 *   b3 of first nibble
	 * bperhx=4 reads hex nibbles singly
	 * bperhx=3 reads octal
	 * bperhx=1 reads longhand binary
	 * in theory if !P_REFIN, bperhx can be any multiple of 4
	 * with equal effect
	 * The returned poly_t is CLEAN.
	 */

	/* make two passes, one to determine the poly size
	 * one to populate the bitmap
	 */
	unsigned long length = 1UL, idx;
	bmp_t accu;
	bmp_t mask = bperhx == BMP_BIT ? ~BMP_C(0) : (BMP_C(1) << bperhx) - BMP_C(1);
	int pass, count, ofs;
	int cmask = ~(~0 << CHAR_BIT), c;
	const char *s;

	poly_t poly = PZERO;
	if(bperhx > BMP_BIT || bperhx <= 0 || string == NULL || *string == '\0')
		return(poly);

	for(pass=0; pass<2 && length > 0UL; ++pass) {
		s = string;
		length = 0UL;
		count = 0;
		accu = BMP_C(0);
		while((c = *s++)) {
			if(flags & P_DIRECT) {
				if(flags & P_LTLBYT)
					accu |= (bmp_t) (c & cmask) << count;
				else
					accu = (accu << CHAR_BIT) | (bmp_t) (c & cmask);
				count += CHAR_BIT;
			} else {
				if(c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
				accu <<= 4;
				count += 4;
				switch(c) {
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						accu |= (bmp_t) c - '0';
						break;
					case 'A':
					case 'a':
						accu |= BMP_C(0xa);
						break;
					case 'B':
					case 'b':
						accu |= BMP_C(0xb);
						break;
					case 'C':
					case 'c':
						accu |= BMP_C(0xc);
						break;
					case 'D':
					case 'd':
						accu |= BMP_C(0xd);
						break;
					case 'E':
					case 'e':
						accu |= BMP_C(0xe);
						break;
					case 'F':
					case 'f':
						accu |= BMP_C(0xf);
						break;
					default:
						uerror("invalid character in hexadecimal argument");
				}
			}

			if(count >= bperhx) {
				/* the low bperhx bits of accu contain bits of the poly.
				 * in pass 0, increment length by bperhx.
				 * in pass 1, put the low bits of accu into the bitmap. */
				length += bperhx;
				count = 0;
				if(pass == 1) {
					if(flags & P_REFIN)
						accu = rev(accu, bperhx);
					accu &= mask;

					/* length >= bperhx > 0 */
					idx = IDX(length - 1);
					ofs = OFS(length - 1);
					poly.bitmap[idx] |= accu << ofs;
					if(ofs + bperhx > BMP_BIT)
						poly.bitmap[idx-1] |= accu >> (BMP_BIT - ofs);
					accu = BMP_C(0); /* only needed for P_LTLBYT */
				}
			}
		}
		if(pass == 0) palloc(&poly, length);
	}
	return(poly);
}

char *
ptostr(const poly_t poly, int flags, int bperhx) {
	/* Returns a malloc()-ed string containing a hexadecimal
	 * representation of poly. See phxsubs().
	 */
	return(pxsubs(poly, flags, bperhx, 0UL, poly.length));
}

char *
pxsubs(const poly_t poly, int flags, int bperhx, unsigned long start, unsigned long end) {
	/* Returns a malloc()-ed string containing a hexadecimal
	 * representation of a portion of poly, from bit offset start to
	 * (end - 1) inclusive.  The output is grouped into words of
	 * bperhx bits each.  If P_RTJUST then the first word is padded
	 * with zeroes at the MSB end to make a whole number of words,
	 * otherwise the last word is padded at the LSB end.  After
	 * justification the bperhx bits of each word are reversed (if
	 * P_REFOUT) and printed as a hex sequence, with words
	 * optionally separated by spaces (P_SPACE).
	 * If end exceeds the length of poly then zero bits are appended
	 * to make up the difference, in which case poly must be CLEAN.
	 */
	char *string, *sptr;
	unsigned long size, iter;
	bmp_t accu;
	bmp_t mask = bperhx == BMP_BIT ? ~BMP_C(0) : (BMP_C(1) << bperhx) - BMP_C(1);
	int cperhx, part;

	if(bperhx <= 0 || bperhx > BMP_BIT) return(NULL);

	if(start > poly.length) start = poly.length;
	if(end > poly.length) end = poly.length;
	if(end < start) end = start;

	cperhx = (bperhx + 3) >> 2;
	if(flags & P_SPACE) ++cperhx;

	size = (end - start + bperhx - 1UL) / bperhx;
	size *= cperhx;
	if(!size || ~flags & P_SPACE) ++size; /* for trailing null */

	if(!(sptr = string = (char *) malloc(size)))
		uerror("cannot allocate memory for string");

	size = end - start;
	part = (int) size % bperhx;
	if(part && flags & P_RTJUST) {
		iter = start + part;
		accu = getwrd(poly, iter - 1UL) & ((BMP_C(1) << part) - BMP_C(1));
		if(flags & P_REFOUT)
			/* best to reverse over bperhx rather than part, I think
			 * e.g. converting a 7-bit poly to 8-bit little-endian hex
			 */
			accu = rev(accu, bperhx);
		prhex(&sptr, accu, flags, bperhx);
		if(flags & P_SPACE && size > iter) *sptr++ = ' ';
	} else {
		iter = start;
	}

	while((iter+=bperhx) <= end) {
		accu = getwrd(poly, iter - 1UL) & mask;
		if(flags & P_REFOUT)
			accu = rev(accu, bperhx);
		prhex(&sptr, accu, flags, bperhx);
		if(flags & P_SPACE && size > iter) *sptr++ = ' ';
	}

	if(part && ~flags & P_RTJUST) {
		accu = getwrd(poly, end - 1UL);
		if(flags & P_REFOUT)
			accu = rev(accu, part);
		else
			accu = accu << (bperhx - part) & mask;
		prhex(&sptr, accu, flags, bperhx);
	}
	*sptr = '\0';
	return(string);
}

poly_t
pclone(const poly_t poly) {
	/* Returns a freestanding copy of poly.  Does not clean poly or
	 * the result.
	 */
	poly_t clone = PZERO;

	pcpy(&clone, poly);
	return(clone);
}

void
pcpy(poly_t *dest, const poly_t src) {
	/* Assigns (copies) src into dest.  Does not clean src or dest.
	 */
	unsigned long iter, idx;

	praloc(dest, src.length);
	for(iter=0UL, idx=0UL; iter < src.length; iter += BMP_BIT, ++idx)
		dest->bitmap[idx] = src.bitmap[idx];
}

void
pcanon(poly_t *poly) {
	/* Converts poly into a CLEAN object by freeing unused bitmap words
	 * and clearing any bits in the last word beyond the last bit.
	 * The length field has absolute priority over the contents of the bitmap.
	 * Canonicalisation differs from normalisation in that leading and trailing
	 * zero terms are significant and preserved.
	 * poly may or may not be WELL-FORMED.
	 */
	praloc(poly, poly->length);
}

void
pnorm(poly_t *poly) {
	/* Converts poly into a NORMALISED object by removing leading
	 * and trailing zeroes, so that the polynomial starts and ends
	 * with significant terms.
	 * poly may or may not be WELL-FORMED.
	 */
	unsigned long first;

	/* call pcanon() here so pfirst() and plast() return the correct
	 * results
	 */
	pcanon(poly);
	first = pfirst(*poly);
	if(first)
		pshift(poly, *poly, 0UL, first, plast(*poly), 0UL);
	else
		praloc(poly, plast(*poly));
}

void
psnorm(poly_t *poly) {
	/* Converts poly into a SEMI-NORMALISED object by removing
	 * trailing zeroes, so that the polynomial ends with a
	 * significant term.
	 * poly may or may not be WELL-FORMED.
	 */

	/* call pcanon() here so plast() returns the correct result */
	pcanon(poly);
	praloc(poly, plast(*poly));
}

void
pchop(poly_t *poly) {
	/* Normalise poly, then chop off the highest significant term
	 * (produces a SEMI-NORMALISED object).  poly becomes a suitable
	 * divisor for pcrc().
	 * poly may or may not be WELL-FORMED.
	 */

	 /* call pcanon() here so pfirst() and plast() return correct
	  * results
	  */
	pcanon(poly);
	pshift(poly, *poly, 0UL, pfirst(*poly) + 1UL, plast(*poly), 0UL);
}

void
pkchop(poly_t *poly) {
	/* Convert poly from Koopman notation to chopped form (produces
	 * a SEMI-NORMALISED object).  poly becomes a suitable divisor
	 * for pcrc().
	 * poly may or may not be WELL-FORMED.
	 */
	unsigned long first;

	/* call pcanon() here so pfirst() returns the correct result */
	pcanon(poly);
	first = pfirst(*poly);
	if(first >= poly->length) {
		pfree(poly);
		return;
	}
	pshift(poly, *poly, 0UL, first + 1UL, poly->length, 1UL);
	piter(poly);
}

unsigned long
plen(const poly_t poly) {
	/* Return length of polynomial.
	 * poly may or may not be WELL-FORMED.
	 */
	return(poly.length);
}

int
pcmp(const poly_t *a, const poly_t *b) {
	/* Compares poly_t objects for identical sizes and contents.
	 * a and b must be CLEAN.
	 * Defines a total order relation for sorting, etc. although
	 * mathematically, polynomials of equal degree are no greater or
	 * less than one another.
	 */
	unsigned long iter;
	bmp_t *aptr, *bptr;

	if(!a || !b) return(!b - !a);
	if(a->length < b->length) return(-1);
	if(a->length > b->length) return(1);
	aptr = a->bitmap;
	bptr = b->bitmap;
	for(iter=0UL; iter < a->length; iter += BMP_BIT) {
		if(*aptr < *bptr)
			return(-1);
		if(*aptr++ > *bptr++)
			return(1);
	}
	return(0);
}

int
psncmp(const poly_t *a, const poly_t *b) {
	/* Compares polys for identical effect, i.e. as though the
	 * shorter poly were padded with zeroes to the length of the
	 * longer.
	 * a and b must still be CLEAN, therefore psncmp() is *not*
	 * identical to pcmp() on semi-normalised polys as psnorm()
	 * clears the slack space.
	 */
	unsigned long length, iter, idx;
	bmp_t aword, bword;
	if(!a || !b) return(!b - !a);
	length = (a->length > b->length) ? a->length : b->length;
	for(iter = 0UL, idx = 0UL; iter < length; iter += BMP_BIT, ++idx) {
		aword = (iter < a->length) ? a->bitmap[idx] : BMP_C(0);
		bword = (iter < b->length) ? b->bitmap[idx] : BMP_C(0);
		if(aword < bword)
			return(-1);
		if(aword > bword)
			return(1);
	}
	return(0);
}


int
ptst(const poly_t poly) {
	/* Tests whether a polynomial equals zero.  Returns 0 if equal,
	 * a nonzero value otherwise.
	 * poly must be CLEAN.
	 */
	unsigned long iter;
	bmp_t *bptr;
	if(!poly.bitmap) return(0);
	for(iter = 0UL, bptr = poly.bitmap; iter < poly.length; iter += BMP_BIT)
		if(*bptr++) return(1);
	return(0);
}

unsigned long
pfirst(const poly_t poly) {
	/* Returns the index of the first nonzero term in poly.  If none
	 * is found, returns the length of poly.
	 * poly must be CLEAN.
	 */
	unsigned long idx = 0UL, size = SIZE(poly.length);
	bmp_t accu = BMP_C(0); /* initialiser for Acorn C */
	unsigned int probe = BMP_SUB, ofs = 0;

	while(idx < size && !(accu = poly.bitmap[idx])) ++idx;
	if(idx >= size) return(poly.length);
	while(probe) {
#ifndef BMP_POF2
		while((ofs | probe) >= (unsigned int) BMP_BIT) probe >>= 1;
#endif
		if(accu >> (ofs | probe)) ofs |= probe;
		probe >>= 1;
	}

	return(BMP_BIT - 1UL - ofs + idx * BMP_BIT);
}

unsigned long
plast(const poly_t poly) {
	/* Returns 1 plus the index of the last nonzero term in poly.
	 * If none is found, returns zero.
	 * poly must be CLEAN.
	 */
	unsigned long idx, size = SIZE(poly.length);
	bmp_t accu;
	unsigned int probe = BMP_SUB, ofs = 0;

	if(!poly.length) return(0UL);
	idx = size - 1UL;
	while(idx && !(accu = poly.bitmap[idx])) --idx;
	if(!idx && !(accu = poly.bitmap[idx])) return(0UL);
	/* now accu == poly.bitmap[idx] and contains last significant term */
	while(probe) {
#ifndef BMP_POF2
		while((ofs | probe) >= (unsigned int) BMP_BIT) probe >>= 1;
#endif
		if(accu << (ofs | probe)) ofs |= probe;
		probe >>= 1;
	}

	return(idx * BMP_BIT + ofs + 1UL);
}

poly_t
psubs(const poly_t src, unsigned long head, unsigned long start, unsigned long end, unsigned long tail) {
	poly_t dest = PZERO;
	pshift(&dest, src, head, start, end, tail);
	return(dest);
}

void
pright(poly_t *poly, unsigned long length) {
	/* Trims or extends poly to length at the left edge, prepending
	 * zeroes if necessary.  Analogous to praloc() except the
	 * rightmost terms of poly are preserved.
	 * On entry, poly may or may not be WELL-FORMED.
	 * On exit, poly is CLEAN.
	 */

	if(length > poly->length)
		pshift(poly, *poly, length - poly->length, 0UL, poly->length, 0UL);
	else if(length < poly->length)
		pshift(poly, *poly, 0UL, poly->length - length, poly->length, 0UL);
	else
		praloc(poly, poly->length);
}

void
pshift(poly_t *dest, const poly_t src, unsigned long head, unsigned long start, unsigned long end, unsigned long tail) {
	/* copies bits start to end-1 of src to dest, plus the number of leading and trailing zeroes given by head and tail.
	 * end may exceed the length of src in which case more zeroes are appended.
	 * dest may point to src, in which case the poly is edited in place.
	 * On exit, dest is CLEAN.
	 */

	unsigned long length, fulllength, size, fullsize, iter, idx, datidx;
	/* condition inputs; end, head and tail may be any value */
	if(end < start) end = start;

	length = end - start + head;
	fulllength = length + tail;
	if(fulllength > src.length)
		praloc(dest, fulllength);
	else
		praloc(dest, src.length);

	/* number of words in new poly */
	size = SIZE(length);
	fullsize = SIZE(fulllength);
	/* array index of first word ending up with source material */
	datidx = IDX(head);

	if(head > start && end > start) {
		/* shifting right, size > 0 */
		/* index of the source bit ending up in the LSB of the last word
		 * size * BMP_BIT >= length > head > 0 */
		iter = size * BMP_BIT - head - 1UL;
		for(idx = size - 1UL; idx > datidx; iter -= BMP_BIT, --idx)
			dest->bitmap[idx] = getwrd(src, iter);
		dest->bitmap[idx] = getwrd(src, iter);
		/* iter == size * BMP_BIT - head - 1 - BMP_BIT * (size - 1 - datidx)
		 *      == BMP_BIT * (size - size + 1 + datidx) - head - 1
		 *      == BMP_BIT * (1 + head / BMP_BIT) - head - 1
		 *      == BMP_BIT + head - head % BMP_BIT - head - 1
		 *      == BMP_BIT - head % BMP_BIT - 1
		 *      >= 0
		 */
	} else if(head <= start) {
		/* shifting left or copying */
		/* index of the source bit ending up in the LSB of bitmap[idx] */
		iter = start - head + BMP_BIT - 1UL;
		for(idx = datidx; idx < size; iter += BMP_BIT, ++idx)
			dest->bitmap[idx] = getwrd(src, iter);
	}

	/* clear head */
	for(idx = 0UL; idx < datidx; ++idx)
		dest->bitmap[idx] = BMP_C(0);
	if(size)
		dest->bitmap[datidx] &= ~BMP_C(0) >> LOFS(head);

	/* clear tail */
	if(LOFS(length))
		dest->bitmap[size - 1UL] &= ~(~BMP_C(0) >> LOFS(length));
	for(idx = size; idx < fullsize; ++idx)
		dest->bitmap[idx] = BMP_C(0);

	/* call praloc to shrink poly if required */
	if(dest->length > fulllength)
		praloc(dest, fulllength);
}

void
ppaste(poly_t *dest, const poly_t src, unsigned long skip, unsigned long seek, unsigned long end, unsigned long fulllength) {
	/* pastes terms of src, starting from skip, to positions seek to end-1 of dest
	 * then sets length of dest to fulllength (>= end)
	 * to paste n terms of src, give end = seek + n
	 * to truncate dest at end of paste, set fulllength = end
	 * to avoid truncating, set fulllength = plen(*dest)
	 * dest may point to src, in which case the poly is edited in place.
	 * src must be CLEAN in the case that the end is overrun.
	 * On exit, dest is CLEAN.
	 */
	bmp_t mask;
	unsigned long seekidx, endidx, iter;
	int seekofs;
	if(end < seek) end = seek;
	if(fulllength < end) fulllength = end;

	/* expand dest if necessary. don't shrink as dest may be src */
	if(fulllength > dest->length)
		praloc(dest, fulllength);
	seekidx = IDX(seek);
	endidx = IDX(end);
	seekofs = OFS(seek);
	/* index of the source bit ending up in the LSB of the first modified word */
	iter = skip + seekofs;
	if(seekidx == endidx) {
		/* paste affects one word (traps end = seek case) */
		mask = ((BMP_C(1) << seekofs) - (BMP_C(1) << OFS(end))) << 1;
		dest->bitmap[seekidx] = (dest->bitmap[seekidx] & ~mask) | (getwrd(src, iter) & mask);
	} else if(seek > skip) {
		/* shifting right */
		/* index of the source bit ending up in the LSB of the last modified word */
		iter += (endidx - seekidx) * BMP_BIT;
		mask = ~BMP_C(0) >> LOFS(end);
		dest->bitmap[endidx] = (dest->bitmap[endidx] & mask) | (getwrd(src, iter) & ~mask);
		for(iter -= BMP_BIT, --endidx; endidx > seekidx; iter -= BMP_BIT, --endidx)
			dest->bitmap[endidx] = getwrd(src, iter);
		mask = ~BMP_C(0) >> LOFS(seek);
		dest->bitmap[endidx] = (dest->bitmap[endidx] & ~mask) | (getwrd(src, iter) & mask);
		/* iter == skip + seekofs + (endidx - seekidx) * BMP_BIT - BMP_BIT * (endidx - seekidx)
		 *      == skip + seekofs + BMP_BIT * (endidx - seekidx - endidx + seekidx)
		 *      == skip + seekofs
		 *      >= 0
		 */
	} else {
		/* shifting left or copying */
		mask = ~BMP_C(0) >> LOFS(seek);
		dest->bitmap[seekidx] = (dest->bitmap[seekidx] & ~mask) | (getwrd(src, iter) & mask);
		for(iter += BMP_BIT, ++seekidx; seekidx < endidx; iter += BMP_BIT, ++seekidx)
			dest->bitmap[seekidx] = getwrd(src, iter);
		mask = ~BMP_C(0) >> LOFS(end);
		dest->bitmap[seekidx] = (dest->bitmap[seekidx] & mask) | (getwrd(src, iter) & ~mask);
	}
	/* shrink poly if required */
	if(dest->length > fulllength)
		praloc(dest, fulllength);
}

void
pdiff(poly_t *dest, const poly_t src, unsigned long ofs) {
	/* Subtract src from dest (modulo 2) at offset ofs.
	 * In modulo 2 arithmetic, subtraction is equivalent to addition
	 * We include an alias for those who wish to retain the distinction
	 * src and dest must be CLEAN.
	 */
	psum(dest, src, ofs);
}

void
psum(poly_t *dest, const poly_t src, unsigned long ofs) {
	/* Adds src to dest (modulo 2) at offset ofs.
	 * When ofs == dest->length, catenates src on to dest.
	 * src and dest must be CLEAN.
	 */
	unsigned long fulllength, idx, iter, end;

	fulllength = ofs + src.length;
	if(fulllength > dest->length)
		praloc(dest, fulllength);
	/* array index of first word in dest to be modified */
	idx = IDX(ofs);
	/* index of bit in src to be added to LSB of dest->bitmap[idx] */
	iter = OFS(ofs);
	/* stop value for iter */
	end = BMP_BIT - 1UL + src.length;
	for(; iter < end; iter += BMP_BIT, ++idx)
		dest->bitmap[idx] ^= getwrd(src, iter);
}

void
prev(poly_t *poly) {
	/* Reverse or reciprocate a polynomial.
	 * On exit, poly is CLEAN.
	 */
	unsigned long leftidx = 0UL, rightidx = SIZE(poly->length);
	unsigned long ofs = LOFS(BMP_BIT - LOFS(poly->length));
	unsigned long fulllength = poly->length + ofs;
	bmp_t accu;

	if(ofs)
		/* removable optimisation */
		if(poly->length < (unsigned long) BMP_BIT) {
			*poly->bitmap = rev(*poly->bitmap >> ofs, (int) poly->length) << ofs;
			return;
		}

		/* claim remaining bits of last word (as we use public function pshift()) */
		poly->length = fulllength;

	/* reverse and swap words in the array, leaving it right-justified */
	while(leftidx < rightidx) {
		/* rightidx > 0 */
		accu = rev(poly->bitmap[--rightidx], BMP_BIT);
		poly->bitmap[rightidx] = rev(poly->bitmap[leftidx], BMP_BIT);
		poly->bitmap[leftidx++] = accu;
	}
	/* shift polynomial to left edge if required */
	if(ofs)
		pshift(poly, *poly, 0UL, ofs, fulllength, 0UL);
}

void
prevch(poly_t *poly, int bperhx) {
	/* Reverse each group of bperhx bits in a polynomial.
	 * Does not clean poly.
	 */
	unsigned long iter = 0, idx, ofs;
	bmp_t mask, accu;

	if(bperhx < 2 || bperhx > BMP_BIT)
		return;
	if(poly->length % bperhx)
		praloc(poly, bperhx - (poly->length % bperhx) + poly->length);
	mask = ~BMP_C(0) >> (BMP_BIT - bperhx);
	for(iter = (unsigned long) (bperhx - 1); iter < poly->length; iter += bperhx) {
		accu = getwrd(*poly, iter) & mask;
		accu ^= rev(accu, bperhx);
		idx = IDX(iter);
		ofs = OFS(iter);
		poly->bitmap[idx] ^= accu << ofs;
		if(ofs + bperhx > (unsigned int) BMP_BIT)
			/* (BMP_BIT - 1UL - (iter) % BMP_BIT) + bperhx > BMP_BIT
			 * (-1UL - (iter) % BMP_BIT) + bperhx > 0
			 * (- (iter % BMP_BIT)) + bperhx > 1
			 * - (iter % BMP_BIT) > 1 - bperhx
			 * iter % BMP_BIT < bperhx - 1, iter >= bperhx - 1
			 * iter >= BMP_BIT
			 * idx >= 1
			 */
			poly->bitmap[idx-1] ^= accu >> (BMP_BIT - ofs);
	}
}

void
prcp(poly_t *poly) {
	/* Reciprocate a chopped polynomial.  Use prev() on whole
	 * polynomials.
	 * On exit, poly is SEMI-NORMALISED.
	 */
	unsigned long first;

	praloc(poly, RNDUP(poly->length));
	prev(poly);
	first = pfirst(*poly);
	if(first >= poly->length) {
		pfree(poly);
		return;
	}
	pshift(poly, *poly, 0UL, first + 1UL, poly->length, 1UL);
	piter(poly);
}

void
pinv(poly_t *poly) {
	/* Invert a polynomial, i.e. add 1 (modulo 2) to the coefficient of each term
	 * on exit, poly is CLEAN.
	 */
	unsigned long idx, size = SIZE(poly->length);

	for(idx = 0UL; idx<size; ++idx)
		poly->bitmap[idx] = ~poly->bitmap[idx];
	if(LOFS(poly->length))
		poly->bitmap[size - 1UL] &= ~(~BMP_C(0) >> LOFS(poly->length));
}

poly_t
pmod(const poly_t dividend, const poly_t divisor) {
	/* Divide dividend by normalised divisor and return the remainder
	 * This function generates a temporary 'chopped' divisor for pcrc()
	 * If calling repeatedly with a constant divisor, produce a chopped copy
	 * with pchop() and call pcrc() directly for higher efficiency.
	 * dividend and divisor must be CLEAN.
	 */

	/* perhaps generate an error if divisor is zero */
	poly_t subdivisor = psubs(divisor, 0UL, pfirst(divisor) + 1UL, plast(divisor), 0UL);
	poly_t result = pcrc(dividend, subdivisor, pzero, pzero, 0);
	pfree(&subdivisor);
	return(result);
}

poly_t
pcrc(const poly_t message, const poly_t divisor, const poly_t init, const poly_t xorout, int flags) {
	/* Divide message by divisor and return the remainder.
	 * init is added to divisor, highest terms aligned, before
	 * division.
	 * xorout is added to the remainder, highest terms aligned.
	 * If P_MULXN is set in flags, message is multiplied by x^n
	 * (i.e. trailing zeroes equal to the CRC width are appended)
	 * before adding init and division.  Set P_MULXN for most CRC
	 * calculations.
	 * All inputs must be CLEAN.
	 * If all inputs are CLEAN, the returned poly_t will be CLEAN.
	 */
	unsigned long max = 0UL, iter, ofs, resiter;
	bmp_t probe, rem, dvsr, *rptr, *sptr;
	const bmp_t *bptr, *eptr;
	poly_t result = PZERO;

	if(flags & P_MULXN)
		max = message.length;
	else if(message.length > divisor.length)
		max = message.length - divisor.length;
	bptr=message.bitmap;
	eptr=message.bitmap+SIZE(message.length);
	probe=~(~BMP_C(0) >> 1);
	if(divisor.length <= (unsigned long) BMP_BIT
		&& init.length <= (unsigned long) BMP_BIT) {
		rem = init.length ? *init.bitmap : BMP_C(0);
		dvsr = divisor.length ? *divisor.bitmap : BMP_C(0);
		for(iter = 0UL, ofs = 0UL; iter < max; ++iter, --ofs) {
			if(!ofs) {
				ofs = BMP_BIT;
				rem ^= *bptr++;
			}
			if(rem & probe)
				rem = (rem << 1) ^ dvsr;
			else
				rem <<= 1;
		}
		if(bptr < eptr)
			/* max < message.length */
			rem ^= *bptr >> OFS(BMP_BIT - 1UL + max);
		if(init.length > max && init.length - max > divisor.length) {
			palloc(&result, init.length - max);
			*result.bitmap = rem;
		} else if(divisor.length) {
			palloc(&result, divisor.length);
			*result.bitmap = rem;
		}
	} else {
		/* allocate maximum size plus one word for shifted divisors and one word containing zero.
		 * This also ensures that result[1] exists
		 */
		palloc(&result, (init.length > divisor.length ? init.length : divisor.length) + (unsigned long) (BMP_BIT << 1));
		/*if there is content in init, there will be an extra word in result to clear it */
		psum(&result, init, 0UL);
		if(max)
			*result.bitmap ^= *bptr++;
		for(iter = 0UL, ofs = 0UL; iter < max; ++iter, probe >>= 1) {
			if(!probe) {
				probe = ~(~BMP_C(0) >> 1);
				ofs = 0UL;
				sptr = rptr = result.bitmap;
				++sptr;
				/* iter < max <= message.length, so bptr is valid
				 * shift result one word to the left, splicing in a message word
				 * and clearing the last active word
				 */
				*rptr++ = *sptr++ ^ *bptr++;
				for(resiter = (unsigned long) (BMP_BIT << 1); resiter < result.length; resiter += BMP_BIT)
					*rptr++ = *sptr++;
			}
			++ofs;
			if(*result.bitmap & probe)
				psum(&result, divisor, ofs);
		}
		rptr = result.bitmap;
		++rptr;
		while(bptr < eptr)
			*rptr++ ^= *bptr++;
		/* 0 <= ofs <= BMP_BIT, location of the first bit of the result */
		pshift(&result, result, 0UL, ofs, (init.length > max + divisor.length ? init.length - max - divisor.length : 0UL) + divisor.length + ofs, 0UL);
	}
	psum(&result, xorout, 0UL);
	return(result);
}

int
piter(poly_t *poly) {
	/* Replace poly with the 'next' polynomial of equal length.
	 * Returns zero if the next polynomial is all zeroes, a nonzero
	 * value otherwise.
	 * Does not clean poly.
	 */
	bmp_t *bptr;
	if(!poly->length) return(0);

	bptr = poly->bitmap + IDX(poly->length - 1UL);
	*bptr += BMP_C(1) << OFS(poly->length - 1UL);
	while(bptr != poly->bitmap && !*bptr)
		++(*--bptr);
	return(*bptr != BMP_C(0));
}

void
palloc(poly_t *poly, unsigned long length) {
	/* Replaces poly with a CLEAN object of the specified length,
	 * consisting of all zeroes.
	 * It is safe to call with length = 0, in which case the object
	 * is freed.
	 * poly may or may not be WELL-FORMED.
	 * On exit, poly is CLEAN.
	 */
	unsigned long size = SIZE(length);

	poly->length = 0UL;
	free(poly->bitmap);
	poly->bitmap = NULL;
	if(!length) return;
	if(!size)
		size = IDX(length) + 1UL;
	poly->bitmap = (bmp_t *) calloc(size, sizeof(bmp_t));
	if(poly->bitmap) {
		poly->length = length;
	} else
		uerror("cannot allocate memory for poly");
}

void
pfree(poly_t *poly) {
	/* Frees poly's bitmap storage and sets poly equal to the empty
	 * polynomial (PZERO).
	 * poly may or may not be WELL-FORMED.
	 * On exit, poly is CLEAN.
	 */

	/* palloc(poly, 0UL); */

	poly->length = 0UL;
	free(poly->bitmap);
	poly->bitmap = NULL;
}

void
praloc(poly_t *poly, unsigned long length) {
	/* Trims or extends poly to length at the right edge, appending
	 * zeroes if necessary.
	 * On entry, poly may or may not be WELL-FORMED.
	 * On exit, poly is CLEAN.
	 */
	unsigned long oldsize, size = SIZE(length);
	if(!poly) return;
	if(!length) {
		poly->length = 0UL;
		free(poly->bitmap);
		poly->bitmap = NULL;
		return;
	}
	if(!size)
		size = IDX(length) + 1UL;
	if(!poly->bitmap)
		poly->length = 0UL;
	oldsize = SIZE(poly->length);
	if(oldsize != size)
		/* reallocate if array pointer is null or array resized */
		poly->bitmap = (bmp_t *) realloc((void *)poly->bitmap, size * sizeof(bmp_t));
	if(poly->bitmap) {
		if(poly->length < length) {
			/* poly->length >= 0, length > 0, size > 0.
			 * poly expanded. clear old last word and all new words
			 */
			if(LOFS(poly->length))
				poly->bitmap[oldsize - 1UL] &= ~(~BMP_C(0) >> LOFS(poly->length));
			while(oldsize < size)
				poly->bitmap[oldsize++] = BMP_C(0);
		} else if(LOFS(length))
			/* poly->length >= length > 0.
			 * poly shrunk. clear new last word
			 */
			poly->bitmap[size - 1UL] &= ~(~BMP_C(0) >> LOFS(length));
		poly->length = length;
	} else
		uerror("cannot reallocate memory for poly");
}

int
pmpar(const poly_t poly, const poly_t mask) {
	/* Return even parity of poly masked with mask.
	 * Poly and mask must be CLEAN.
	 */
	bmp_t res = BMP_C(0);
	int i = BMP_SUB;
	const bmp_t *pptr = poly.bitmap, *mptr = mask.bitmap;
	const bmp_t *const pend = poly.bitmap + SIZE(poly.length);
	const bmp_t *const mend = mask.bitmap + SIZE(mask.length);

	while(pptr < pend && mptr < mend)
		res ^= *pptr++ & *mptr++;
	do
		res ^= res >> i;
	while(i >>= 1);

	return((int) (res & BMP_C(1)));
}

int
pident(const poly_t a, const poly_t b) {
	/* Return nonzero if a and b have the same length
	 * and point to the same bitmap.
	 * a and b need not be CLEAN.
	 */
	return(a.length == b.length && a.bitmap == b.bitmap);
}

/* Private functions */

static bmp_t
getwrd(const poly_t poly, unsigned long iter) {
	/* Fetch unaligned word from poly where LSB of result is
	 * bit iter of the bitmap (counting from zero).  If iter exceeds
	 * the length of poly then zeroes are appended as necessary.
	 * Factored from ptostr().
	 * poly must be CLEAN.
	 */
	bmp_t accu = BMP_C(0);
	unsigned long idx, size;
	int ofs;

	idx = IDX(iter);
	ofs = OFS(iter);
	size = SIZE(poly.length);

	if(idx < size)
		accu |= poly.bitmap[idx] >> ofs;
	if(idx && idx <= size && ofs > 0)
		accu |= poly.bitmap[idx - 1UL] << (BMP_BIT - ofs);
	return(accu);
}

static bmp_t
rev(bmp_t accu, int bits) {
	/* Returns the bitmap word argument with the given number of
	 * least significant bits reversed and the rest cleared.
	 */
	static const unsigned char revtab[256] = {
		0x00,0x80,0x40,0xc0,0x20,0xa0,0x60,0xe0,
		0x10,0x90,0x50,0xd0,0x30,0xb0,0x70,0xf0,
		0x08,0x88,0x48,0xc8,0x28,0xa8,0x68,0xe8,
		0x18,0x98,0x58,0xd8,0x38,0xb8,0x78,0xf8,
		0x04,0x84,0x44,0xc4,0x24,0xa4,0x64,0xe4,
		0x14,0x94,0x54,0xd4,0x34,0xb4,0x74,0xf4,
		0x0c,0x8c,0x4c,0xcc,0x2c,0xac,0x6c,0xec,
		0x1c,0x9c,0x5c,0xdc,0x3c,0xbc,0x7c,0xfc,
		0x02,0x82,0x42,0xc2,0x22,0xa2,0x62,0xe2,
		0x12,0x92,0x52,0xd2,0x32,0xb2,0x72,0xf2,
		0x0a,0x8a,0x4a,0xca,0x2a,0xaa,0x6a,0xea,
		0x1a,0x9a,0x5a,0xda,0x3a,0xba,0x7a,0xfa,
		0x06,0x86,0x46,0xc6,0x26,0xa6,0x66,0xe6,
		0x16,0x96,0x56,0xd6,0x36,0xb6,0x76,0xf6,
		0x0e,0x8e,0x4e,0xce,0x2e,0xae,0x6e,0xee,
		0x1e,0x9e,0x5e,0xde,0x3e,0xbe,0x7e,0xfe,
		0x01,0x81,0x41,0xc1,0x21,0xa1,0x61,0xe1,
		0x11,0x91,0x51,0xd1,0x31,0xb1,0x71,0xf1,
		0x09,0x89,0x49,0xc9,0x29,0xa9,0x69,0xe9,
		0x19,0x99,0x59,0xd9,0x39,0xb9,0x79,0xf9,
		0x05,0x85,0x45,0xc5,0x25,0xa5,0x65,0xe5,
		0x15,0x95,0x55,0xd5,0x35,0xb5,0x75,0xf5,
		0x0d,0x8d,0x4d,0xcd,0x2d,0xad,0x6d,0xed,
		0x1d,0x9d,0x5d,0xdd,0x3d,0xbd,0x7d,0xfd,
		0x03,0x83,0x43,0xc3,0x23,0xa3,0x63,0xe3,
		0x13,0x93,0x53,0xd3,0x33,0xb3,0x73,0xf3,
		0x0b,0x8b,0x4b,0xcb,0x2b,0xab,0x6b,0xeb,
		0x1b,0x9b,0x5b,0xdb,0x3b,0xbb,0x7b,0xfb,
		0x07,0x87,0x47,0xc7,0x27,0xa7,0x67,0xe7,
		0x17,0x97,0x57,0xd7,0x37,0xb7,0x77,0xf7,
		0x0f,0x8f,0x4f,0xcf,0x2f,0xaf,0x6f,0xef,
		0x1f,0x9f,0x5f,0xdf,0x3f,0xbf,0x7f,0xff
	};
	bmp_t result = BMP_C(0);
	while(bits > 8) {
		bits -= 8;
		result = result << 8 | revtab[accu & 0xff];
		accu >>= 8;
	}
	result = result << bits | (bmp_t) (revtab[accu & 0xff] >> (8 - bits));
	return(result);
}

static void
prhex(char **spp, bmp_t bits, int flags, int bperhx) {
	/* Appends a hexadecimal string representing the bperhx least
	 * significant bits of bits to an external string.
	 * spp points to a character pointer that in turn points to the
	 * end of a hex string being built.  prhex() advances this
	 * second pointer by the number of characters written.
	 * The unused MSBs of bits MUST be cleared.
	 * Set P_UPPER in flags to write A-F in uppercase.
	 */
	static const char hex[] = "0123456789abcdef0123456789ABCDEF";
	const int upper = (flags & P_UPPER ? 0x10 : 0);
	while(bperhx > 0) {
		bperhx -= ((bperhx + 3) & 3) + 1;
		*(*spp)++ = hex[(bits >> bperhx & BMP_C(0xf)) | upper];
	}
}
