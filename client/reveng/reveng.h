/* reveng.h
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

#ifndef REVENG_H
#define REVENG_H 1

/* Configuration options */

#include "config.h"

#ifndef BMP_T
#  error config.h: BMP_T must be defined as unsigned long or a longer unsigned type
#endif

#ifndef BMP_C
#  error config.h: BMP_C() must define a BMP_T constant
#endif

#if !defined PRESETS && !defined BMPMACRO
#  undef BMP_BIT
#  undef BMP_SUB
#endif

#undef BMP_POF2

#ifdef BMP_BIT
#  ifndef BMP_SUB
#    error config.h: BMP_SUB must be defined as the highest power of two that is strictly less than BMP_BIT
#  elif BMP_BIT < 32
#    error config.h: BMP_BIT must be at least 32
#  elif BMP_SUB < 16
#    error config.h: BMP_SUB must be at least 16
#  elif (BMP_SUB >= BMP_BIT || BMP_SUB << 1 < BMP_BIT || BMP_SUB & (BMP_SUB - 1))
#    error config.h: BMP_SUB must be defined as the highest power of two that is strictly less than BMP_BIT
#  else /* BMP_SUB */
#    define SETBMP()
#  endif /* BMP_SUB */
#  if BMP_BIT == 32
#    define BMP_POF2 5
#  elif BMP_BIT == 64
#    define BMP_POF2 6
#  elif BMP_BIT == 128
#    define BMP_POF2 7
#  elif BMP_BIT == 256
#    define BMP_POF2 8
#  elif BMP_BIT == 512
#    define BMP_POF2 9
#  elif BMP_BIT == 1024
#    define BMP_POF2 10
#  elif BMP_BIT == 2048
#    define BMP_POF2 11
#  elif BMP_BIT == 4096
#    define BMP_POF2 12
#  elif BMP_BIT == 8192
#    define BMP_POF2 13
#  elif BMP_BIT == 16384
#    define BMP_POF2 14
#  elif BMP_BIT == 32768
#    define BMP_POF2 15
#  elif BMP_BIT == 65536
#    define BMP_POF2 16
/* may extend list as required */
#  elif (BMP_BIT & (BMP_BIT - 1)) == 0
#    define BMP_POF2 1
#  endif
#else /* BMP_BIT */
#  define BMP_BIT bmpbit
#  define BMP_SUB bmpsub
#  define SETBMP() setbmp()
#endif /* BMP_BIT */

/* Global definitions */

/* CRC RevEng version string */
#define VERSION "1.3.0"

/* bmpbit.c */
typedef BMP_T bmp_t;

extern int bmpbit, bmpsub;
extern void setbmp(void);

/* poly.c */
#define P_REFIN      1
#define P_REFOUT     2
#define P_MULXN      4
#define P_RTJUST     8
#define P_UPPER     16
#define P_SPACE     32
#define P_LTLBYT    64
#define P_DIRECT   128

/* default flags */
#define P_BE     (P_RTJUST | P_MULXN)
#define P_LE     (P_REFIN | P_REFOUT | P_MULXN)
#define P_BELE   (P_REFOUT | P_MULXN)
#define P_LEBE   (P_REFIN | P_RTJUST | P_MULXN)

/* A poly_t constant representing the polynomial 0. */
#define PZERO {0UL, (bmp_t *) 0}

typedef struct {
	unsigned long length;	/* number of significant bits */
	bmp_t *bitmap;		/* bitmap, MSB first, */
				/* left-justified in each word */
} poly_t;

extern poly_t filtop(FILE *input, unsigned long length, int flags, int bperhx);
extern poly_t strtop(const char *string, int flags, int bperhx);
extern char *ptostr(const poly_t poly, int flags, int bperhx);
extern char *pxsubs(const poly_t poly, int flags, int bperhx, unsigned long start, unsigned long end);
extern poly_t pclone(const poly_t poly);
extern void pcpy(poly_t *dest, const poly_t src);
extern void pcanon(poly_t *poly);
extern void pnorm(poly_t *poly);
extern void psnorm(poly_t *poly);
extern void pchop(poly_t *poly);
extern void pkchop(poly_t *poly);
extern unsigned long plen(const poly_t poly);
extern int pcmp(const poly_t *a, const poly_t *b);
extern int psncmp(const poly_t *a, const poly_t *b);
extern int ptst(const poly_t poly);
extern unsigned long pfirst(const poly_t poly);
extern unsigned long plast(const poly_t poly);
extern poly_t psubs(const poly_t src, unsigned long head, unsigned long start, unsigned long end, unsigned long tail);
extern void pright(poly_t *poly, unsigned long length);
extern void pshift(poly_t *dest, const poly_t src, unsigned long head, unsigned long start, unsigned long end, unsigned long tail);
extern void ppaste(poly_t *dest, const poly_t src, unsigned long skip, unsigned long seek, unsigned long end, unsigned long fulllength);
extern void pdiff(poly_t *dest, const poly_t src, unsigned long ofs);
extern void psum(poly_t *dest, const poly_t src, unsigned long ofs);
extern void prev(poly_t *poly);
extern void prevch(poly_t *poly, int bperhx);
extern void prcp(poly_t *poly);
extern void pinv(poly_t *poly);
extern poly_t pmod(const poly_t dividend, const poly_t divisor);
extern poly_t pcrc(const poly_t message, const poly_t divisor, const poly_t init, const poly_t xorout, int flags);
extern int piter(poly_t *poly);
extern void palloc(poly_t *poly, unsigned long length);
extern void pfree(poly_t *poly);
extern void praloc(poly_t *poly, unsigned long length);
extern int pmpar(const poly_t poly, const poly_t mask);
extern int pident(const poly_t a, const poly_t b);

/* model.c */
#define M_OVERWR   256

typedef struct {
	poly_t spoly;		/* polynomial with highest-order term removed. length determines CRC width */
	poly_t init;		/* initial register value. length == poly.length */
	int flags;		/* P_REFIN and P_REFOUT indicate reflected input/output */
	poly_t xorout;		/* final register XOR mask. length == poly.length */
	poly_t check;		/* optional check value, the CRC of the UTF-8 string "123456789" */
	const char *name;	/* optional canonical name of the model */
} model_t;

extern void mcpy(model_t *dest, const model_t *src);
extern void mfree(model_t *model);
extern int mcmp(const model_t *a, const model_t *b);
extern int mbynam(model_t *dest, const char *key);
extern void mbynum(model_t *dest, int num);
extern int mcount(void);
extern char *mnames(void);
extern char *mtostr(const model_t *model);
extern void mmatch(model_t *model, int flags);
extern void mcanon(model_t *model);
extern void mcheck(model_t *model);
extern void mrev(model_t *model);
extern void mnovel(model_t *model);

/* reveng.c */
#define R_HAVEP    512
#define R_HAVEI   1024
#define R_HAVERI  2048
#define R_HAVERO  4096
#define R_HAVEX   8192
#define R_HAVEQ  16384

#define R_SPMASK 0x7FFFFFFUL

extern model_t *reveng(const model_t *guess, const poly_t qpoly, int rflags, int args, const poly_t *argpolys);

/* cli.c */
#define C_INFILE  1
#define C_FORCE   2
#define C_RESULT  4

#define BUFFER 32768

extern int reveng_main(int argc, char *argv[]);
extern void ufound(const model_t *model);
extern void uerror(const char *msg);
extern void uprog(const poly_t gpoly, int flags, unsigned long seq);

#endif /* REVENG_H */
