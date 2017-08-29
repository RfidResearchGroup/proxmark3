/* cli.c
 * Greg Cook, 19/Feb/2017
 */

/* CRC RevEng: arbitrary-precision CRC calculator and algorithm finder
 * Copyright (C) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017
 * Gregory Cook
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
 * along with CRC RevEng.  If not, see <https://www.gnu.org/licenses/>.
 */

/* 2017-02-18: -G ignored if R_HAVEP
 * 2017-02-05: added -G
 * 2016-06-27: -P sets width like -k
 * 2015-04-03: added -z
 * 2013-09-16: do not search with -M
 * 2013-06-11: uprog() suppresses first progress report
 * 2013-04-22: uprog() prints poly same as mtostr()
 * 2013-02-07: added -q, uprog(), removed -W, R_ODDLY
 * 2012-05-24: -D dumps parameters of all models
 * 2012-03-03: added code to test sort order of model table
 * 2012-02-20: set stdin to binary (MinGW). offer -D if preset unknown.
 * 2011-09-06: -s reads arguments once. stdin not closed.
 * 2011-09-06: fixed bad argument-freeing loops.
 * 2011-08-27: validates BMP_C()
 * 2011-08-26: validates BMPBIT and BMPSUB
 * 2011-08-25: fixed Init/Xorout reflection logic in -V and -v
 * 2011-01-17: fixed ANSI C warnings
 * 2011-01-15: added NOFORCE
 * 2011-01-14: added -k, -P
 * 2011-01-10: reorganised switches, added -V, -X
 * 2010-12-26: renamed CRC RevEng
 * 2010-12-18: implemented -c, -C
 * 2010-12-14: added and implemented -d, -D, fixed -ipx entry
 * 2010-12-11: implemented -e. first tests
 * 2010-12-10: finalised option processing. started input validation
 * 2010-12-07: started cli
 */

#include <stdio.h>
#include <stdlib.h>
#include "getopt.h"
#ifdef _WIN32
#  include <io.h>
#  include <fcntl.h>
#  ifndef STDIN_FILENO
#    define STDIN_FILENO 0
#  endif /* STDIN_FILENO */
#endif /* _WIN32 */

#include "reveng.h"

static FILE *oread(const char *);
static poly_t rdpoly(const char *, int, int);
static void usage(void);

static const char *myname = "reveng"; /* name of our program */

int reveng_main(int argc, char *argv[]) {
	/* Command-line interface for CRC RevEng.
	 * Process options and switches in the argument list and
	 * run the required function.
	 */

	/* default values */
	model_t model = MZERO;
	int ibperhx = 8, obperhx = 8;
	int rflags = 0, uflags = 0; /* search and UI flags */

	unsigned long width = 0UL;
	int c, mode = 0, args, psets, pass;
	poly_t apoly, crc, qpoly = PZERO, *apolys, *pptr = NULL, *qptr = NULL;
	model_t pset = model, *candmods, *mptr;
	char *string;

	myname = argv[0];

	/* stdin must be binary */
#ifdef _WIN32
	_setmode(STDIN_FILENO, _O_BINARY);
#endif /* _WIN32 */

	SETBMP();

	pos=0;
	optind=1;
	do {
		c=getopt(argc, argv, "?A:BDFGLMP:SVXa:bcdefhi:k:lm:p:q:rstuvw:x:yz");
		switch(c) {
			case 'A': /* A: bits per output character */
			case 'a': /* a: bits per character */
				if((obperhx = atoi(optarg)) > BMP_BIT) {
					fprintf(stderr,"%s: argument to -%c must be between 1 and %d\n", myname, c, BMP_BIT);
					return 0;
					//exit(EXIT_FAILURE);
				}
				if(c == 'a') ibperhx = obperhx;
				break;
			case 'b': /* b  big-endian (RefIn = false, RefOut = false ) */
				model.flags &= ~P_REFIN;
				rflags |= R_HAVERI;
				/* fall through: */
			case 'B': /* B  big-endian output (RefOut = false) */
				model.flags &= ~P_REFOUT;
				rflags |= R_HAVERO;
				mnovel(&model);
				/* fall through: */
			case 'r': /* r  right-justified */
				model.flags |= P_RTJUST;
				break;
			case 'c': /* c  calculate CRC */
			case 'D': /* D  list primary model names */
			case 'd': /* d  dump CRC model */
			case 'e': /* e  echo arguments */
			case 's': /* s  search for algorithm */
			case 'v': /* v  calculate reversed CRC */
				if(mode) {
					fprintf(stderr,"%s: more than one mode switch specified.  Use %s -h for help.\n", myname, myname);
					return 0;
					//exit(EXIT_FAILURE);
				}
				mode = c;
				break;
			case 'F': /* F  skip preset model check pass */
#ifndef NOFORCE
				uflags |= C_NOPCK;
#endif
				break;
			case 'f': /* f  arguments are filenames */
				uflags |= C_INFILE;
				break;
			case 'G': /* G  skip brute force search pass */
				uflags |= C_NOBFS;
				break;
			case 'h': /* h  get help / usage */
			case 'u': /* u  get help / usage */
			case '?': /* ?  get help / usage */
			default:
				usage();
				return 0;
				//exit(EXIT_FAILURE);
				break;
			case 'i': /* i: Init value */
				pptr = &model.init;
				rflags |= R_HAVEI;
				goto ipqx;
			case 'k': /* k: polynomial in Koopman notation */
			case 'P': /* P: reversed polynomial */
				pfree(&model.spoly);
				model.spoly = strtop(optarg, 0, 4);
				pkchop(&model.spoly);
				width = plen(model.spoly);
				rflags |= R_HAVEP;
				if(c == 'P')
					prcp(&model.spoly);
				mnovel(&model);
				break;
			case 'l': /* l  little-endian input and output */
				model.flags |= P_REFIN;
				rflags |= R_HAVERI;
				/* fall through: */
			case 'L': /* L  little-endian output */
				model.flags |= P_REFOUT;
				rflags |= R_HAVERO;
				mnovel(&model);
				/* fall through: */
			case 't': /* t  left-justified */
				model.flags &= ~P_RTJUST;
				break;
			case 'm': /* m: select preset CRC model */
				if(!(c = mbynam(&model, optarg))) {
					fprintf(stderr,"%s: preset model '%s' not found.  Use %s -D to list presets.\n", myname, optarg, myname);
					return 0;
					//exit(EXIT_FAILURE);
				}
				if(c < 0){
					uerror("no preset models available");
					return 0;
				}
				/* must set width so that parameter to -ipx is not zeroed */
				width = plen(model.spoly);
				rflags |= R_HAVEP | R_HAVEI | R_HAVERI | R_HAVERO | R_HAVEX;
				break;
			case 'M': /* M  non-augmenting algorithm */
				model.flags &= ~P_MULXN;
				break;
			case 'p': /* p: polynomial */
				pptr = &model.spoly;
				rflags &= ~R_HAVEQ;
				rflags |= R_HAVEP;
ipqx:
				pfree(pptr);
				*pptr = strtop(optarg, 0, 4);
				pright(pptr, width);
				mnovel(&model);
				break;
			case 'q': /* q: range end polynomial */
				pptr = &qpoly;
				rflags &= ~R_HAVEP;
				rflags |= R_HAVEQ;
				goto ipqx;
			case 'S': /* s  space between output characters */
				model.flags |= P_SPACE;
				break;
			case 'V': /* v  reverse algorithm */
				/* Distinct from the -v switch as the
				 * user will have to reverse his or her
				 * own arguments.  The user cannot dump
				 * the model generated by -v either.
				 */
				mrev(&model);
				break;
			case 'w': /* w: CRC width = order - 1 */
				/* no validation, WONTFIX */
				width = (unsigned long) atol(optarg);
				break;
			case 'X': /* X  print uppercase hex */
				model.flags |= P_UPPER;
				break;
			case 'x': /* x: XorOut value */
				pptr = &model.xorout;
				rflags |= R_HAVEX;
				goto ipqx;
			case 'y': /* y  little-endian byte order in files */
				model.flags |= P_LTLBYT;
				break;
			case 'z': /* z  raw binary arguments */
				model.flags |= P_DIRECT;
				break;
			case -1: /* no more options, continue */
				;
		}
	} while(c != -1);

	/* canonicalise the model, so the one we dump is the one we
	 * calculate with (not with -s, spoly may be blank which will
	 * normalise to zero and clear init and xorout.)
	 */
	if(mode != 's')
		mcanon(&model);

	switch(mode) {
		case 'v': /* v  calculate reversed CRC */
			/* Distinct from the -V switch as this causes
			 * the arguments and output to be reversed as well.
			 */
			/* reciprocate Poly */
			prcp(&model.spoly);

			/* mrev() does:
			 *   if(refout) prev(init); else prev(xorout);
			 * but here the entire argument polynomial is
			 * reflected, not just the characters, so RefIn
			 * and RefOut are not inverted as with -V.
			 * Consequently Init is the mirror image of the
			 * one resulting from -V, and so we have:
			 */
			if(~model.flags & P_REFOUT) {
				prev(&model.init);
				prev(&model.xorout);
			}

			/* swap init and xorout */
			apoly = model.init;
			model.init = model.xorout;
			model.xorout = apoly;

			/* fall through: */
		case 'c': /* c  calculate CRC */

			/* validate inputs */
			/* if(plen(model.spoly) == 0) {
			 *	fprintf(stderr,"%s: no polynomial specified for -%c (add -w WIDTH -p POLY)\n", myname, mode);
			 *	exit(EXIT_FAILURE);
			 * }
			 */

			/* in the Williams model, xorout is applied after the refout stage.
			 * as refout is part of ptostr(), we reverse xorout here.
			 */
			if(model.flags & P_REFOUT)
				prev(&model.xorout);

			for(; optind < argc; ++optind) {
				if(uflags & C_INFILE)
					apoly = rdpoly(argv[optind], model.flags, ibperhx);
				else
					apoly = strtop(argv[optind], model.flags, ibperhx);

				if(mode == 'v')
					prev(&apoly);

				crc = pcrc(apoly, model.spoly, model.init, model.xorout, model.flags);

				if(mode == 'v')
					prev(&crc);

				string = ptostr(crc, model.flags, obperhx);
				puts(string);
				free(string);
				pfree(&crc);
				pfree(&apoly);
			}
			break;
		case 'D': /* D  dump all models */
			args = mcount();
			if(!args){
				uerror("no preset models available");
				return 0;
			}
			do {
				mbynum(&model, --args);
				ufound(&model);
			} while(args);
			break;
		case 'd': /* d  dump CRC model */
			/* maybe we don't want to do this:
			 * either attaching names to arbitrary models or forcing to a preset
			 * mmatch(&model, M_OVERWR);
			 */
			if(~model.flags & P_MULXN){
				uerror("not a Williams model compliant algorithm");
				return 0;
			}
			string = mtostr(&model);
			puts(string);
			free(string);
			break;
		case 'e': /* e  echo arguments */
			for(; optind < argc; ++optind) {
				if(uflags & C_INFILE)
					apoly = rdpoly(argv[optind], model.flags, ibperhx);
				else
					apoly = strtop(argv[optind], model.flags, ibperhx);

				psum(&apoly, model.init, 0UL);
				string = ptostr(apoly, model.flags, obperhx);
				puts(string);
				free(string);
				pfree(&apoly);
			}
			break;
		case 's': /* s  search for algorithm */
			if(!width){
				uerror("must specify positive -k or -w before -s");
				return 0;
			}
			if(~model.flags & P_MULXN){
				uerror("cannot search for non-Williams compliant models");
				return 0;
			}
			praloc(&model.spoly, width);
			praloc(&model.init, width);
			praloc(&model.xorout, width);
			if(!plen(model.spoly))
				palloc(&model.spoly, width);
			else
				width = plen(model.spoly);

			/* special case if qpoly is zero, search to end of range */
			if(!ptst(qpoly))
				rflags &= ~R_HAVEQ;

			/* allocate argument array */
			args = argc - optind;
			if(!(apolys = malloc(args * sizeof(poly_t)))){
				uerror("cannot allocate memory for argument list");
				return 0;
			}

			for(pptr = apolys; optind < argc; ++optind) {
				if(uflags & C_INFILE)
					*pptr++ = rdpoly(argv[optind], model.flags, ibperhx);
				else
					*pptr++ = strtop(argv[optind], model.flags, ibperhx);
			}
			/* exit value of pptr is used hereafter! */

			/* if endianness not specified, try
			 * little-endian then big-endian.
			 * NB: crossed-endian algorithms will not be
			 * searched.
			 */

			/* scan against preset models */
			if(~uflags & C_NOPCK) {
				pass = 0;
				do {
					psets = mcount();
					while(psets) {
						mbynum(&pset, --psets);
						/* skip if different width, or refin or refout don't match */
						if(plen(pset.spoly) != width || (model.flags ^ pset.flags) & (P_REFIN | P_REFOUT))
							continue;
						/* skip if the preset doesn't match specified parameters */
						if(rflags & R_HAVEP && pcmp(&model.spoly, &pset.spoly))
							continue;
						if(rflags & R_HAVEI && psncmp(&model.init, &pset.init))
							continue;
						if(rflags & R_HAVEX && psncmp(&model.xorout, &pset.xorout))
							continue;
						apoly = pclone(pset.xorout);
						if(pset.flags & P_REFOUT)
							prev(&apoly);
						for(qptr = apolys; qptr < pptr; ++qptr) {
							crc = pcrc(*qptr, pset.spoly, pset.init, apoly, 0);
							if(ptst(crc)) {
								pfree(&crc);
								break;
							} else
								pfree(&crc);
						}
						pfree(&apoly);
						if(qptr == pptr) {
							/* the selected model solved all arguments */
							ufound(&pset);
							uflags |= C_RESULT;
						}
					}
					mfree(&pset);

					/* toggle refIn/refOut and reflect arguments */
					if(~rflags & R_HAVERI) {
						model.flags ^= P_REFIN | P_REFOUT;
						for(qptr = apolys; qptr < pptr; ++qptr)
							prevch(qptr, ibperhx);
					}
				} while(~rflags & R_HAVERI && ++pass < 2);
			}
			if(uflags & C_RESULT) {
				for(qptr = apolys; qptr < pptr; ++qptr)
					pfree(qptr);
				return 1;
				//exit(EXIT_SUCCESS);
			}
			if(uflags & C_NOBFS && ~rflags & R_HAVEP) {
				uerror("no models found");
				return 0;
				//break;
			}
			if(!(model.flags & P_REFIN) != !(model.flags & P_REFOUT)){
				uerror("cannot search for crossed-endian models");
				return 0;
			}
			pass = 0;
			do {
				mptr = candmods = reveng(&model, qpoly, rflags, args, apolys);
				if(mptr && plen(mptr->spoly))
					uflags |= C_RESULT;
				while(mptr && plen(mptr->spoly)) {
					/* results were printed by the callback
					 * string = mtostr(mptr);
					 * puts(string);
					 * free(string);
					 */
					mfree(mptr++);
				}
				free(candmods);
				if(~rflags & R_HAVERI) {
					model.flags ^= P_REFIN | P_REFOUT;
					for(qptr = apolys; qptr < pptr; ++qptr)
						prevch(qptr, ibperhx);
				}
			} while(~rflags & R_HAVERI && ++pass < 2);
			for(qptr = apolys; qptr < pptr; ++qptr)
				pfree(qptr);
			free(apolys);
			if(~uflags & C_RESULT)
				uerror("no models found");
			break;
		default:  /* no mode specified */
			fprintf(stderr, "%s: no mode switch specified. Use %s -h for help.\n", myname, myname);
			return 0;
			//exit(EXIT_FAILURE);
	}

	return 1;
	//exit(EXIT_SUCCESS);
}

void
ufound(const model_t *model) {
	/* Callback function to report each model found */
	char *string;

	if(!model) return;
	/* generated models will be canonical */
	string = mtostr(model);
	puts(string);
	free(string);
}

void
uerror(const char *msg) {
	/* Callback function to report fatal errors */
	fprintf(stderr, "%s: %s\n", myname, msg);
	return;
	//exit(EXIT_FAILURE);
}

void
uprog(const poly_t gpoly, int flags, unsigned long seq) {
	/* Callback function to report search progress */
	char *string;

	/* Suppress first report in CLI */
	if(!seq)
		return;
	string = ptostr(gpoly, P_RTJUST, 4);
	fprintf(stderr, "%s: searching: width=%ld  poly=0x%s  refin=%s  refout=%s\n",
			myname, plen(gpoly), string,
			(flags & P_REFIN ? "true" : "false"),
			(flags & P_REFOUT ? "true" : "false")
			);
	free(string);
}

static poly_t
rdpoly(const char *name, int flags, int bperhx) {
	/* read poly from file in chunks and report errors */

	poly_t apoly = PZERO, chunk = PZERO;
	FILE *input;

	input = oread(name);
	while(!feof(input) && !ferror(input)) {
		chunk = filtop(input, BUFFER, flags, bperhx);
		psum(&apoly, chunk, plen(apoly));
		pfree(&chunk);
	}
	if(ferror(input)) {
		fprintf(stderr,"%s: error condition on file '%s'\n", myname, name);
		exit(EXIT_FAILURE);
	}
	/* close file unless stdin */
	if(input == stdin)
		/* reset EOF condition */
		clearerr(input);
	else if(fclose(input)) {
		fprintf(stderr,"%s: error closing file '%s'\n", myname, name);
		exit(EXIT_FAILURE);
	}
	return(apoly);
}

static FILE *
oread(const char *name) {
	/* open file for reading and report errors */
	FILE *handle;

	/* recognise special name '-' as standard input */
	if(*name == '-' && name[1] == '\0')
		return(stdin);
	if(!(handle = fopen(name, "rb"))) {
		fprintf(stderr, "%s: cannot open '%s' for reading\n", myname, name);
		return 0;
		//exit(EXIT_FAILURE);
	}
	return(handle);
}

static void
usage(void) {
	/* print usage if asked, or if syntax incorrect */
	fprintf(stderr,
			"CRC RevEng: arbitrary-precision CRC calculator and algorithm finder\n"
			"Usage:\t");
	fputs(myname, stderr);
	fprintf(stderr,
			"\t-cdDesvhu? [-bBfFGlLMrStVXyz]\n"
			"\t\t[-a BITS] [-A OBITS] [-i INIT] [-k KPOLY] [-m MODEL]\n"
			"\t\t[-p POLY] [-P RPOLY] [-q QPOLY] [-w WIDTH] [-x XOROUT]\n"
			"\t\t[STRING...]\n"
			"Options:\n"
			"\t-a BITS\t\tbits per character (1 to %d)\n"
			"\t-A OBITS\tbits per output character (1 to %d)\n"
			"\t-i INIT\t\tinitial register value\n"
			"\t-k KPOLY\tgenerator in Koopman notation (implies WIDTH)\n"
			"\t-m MODEL\tpreset CRC algorithm\n"
			"\t-p POLY\t\tgenerator or search range start polynomial\n"
			"\t-P RPOLY\treversed generator polynomial (implies WIDTH)\n",
			BMP_BIT, BMP_BIT);
	fprintf(stderr,
			"\t-q QPOLY\tsearch range end polynomial\n"
			"\t-w WIDTH\tregister size, in bits\n"
			"\t-x XOROUT\tfinal register XOR value\n"
			"Modifier switches:\n"
			"\t-b big-endian CRC\t\t-B big-endian CRC output\n"
			"\t-f read files named in STRINGs\t-F skip preset model check pass\n"
			"\t-G skip brute force search pass\t-l little-endian CRC\n"
			"\t-L little-endian CRC output\t-M non-augmenting algorithm\n"
			"\t-r right-justified output\t-S print spaces between characters\n"
			"\t-t left-justified output\t-V reverse algorithm only\n"
			"\t-X print uppercase hexadecimal\t-y low bytes first in files\n"
			"\t-z raw binary STRINGs\n");
	fprintf(stderr,
			"Mode switches:\n"
			"\t-c calculate CRCs\t\t-d dump algorithm parameters\n"
			"\t-D list preset algorithms\t-e echo (and reformat) input\n"
			"\t-s search for algorithm\t\t-v calculate reversed CRCs\n"
			"\t-g search for alg given hex+crc\t-h | -u | -? show this help\n"
			"Common Use Examples:\n"
			"\t   reveng -g 01020304e3\n"
			"\t      Searches for a known/common crc preset that computes the crc\n"
			"\t      on the end of the given hex string\n"
			"\t   reveng -w 8 -s 01020304e3 010204039d\n"
			"\t      Searches for any possible 8 bit width crc calc that computes\n"
			"\t      the crc on the end of the given hex string(s)\n"
			"\t   reveng -m CRC-8 -c 01020304\n"
			"\t      Calculates the crc-8 of the given hex string\n"
			"\t   reveng -D\n"
			"\t      Outputs a list of all known/common crc models with their\n"
			"\t      preset values\n"
			"\n"
			"Copyright (C) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017  Gregory Cook\n"
			"This is free software; see the source for copying conditions.  There is NO\n"
			"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
			"Version "
			VERSION
			"\t\t\t\t  <http://reveng.sourceforge.net/>\n");
}
