//-----------------------------------------------------------------------------
// Copyright (C) 2015 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CRC Calculations from the software reveng commands
//-----------------------------------------------------------------------------

#include <stdlib.h>
#ifdef _WIN32
#  include <io.h>
#  include <fcntl.h>
#  ifndef STDIN_FILENO
#    define STDIN_FILENO 0
#  endif /* STDIN_FILENO */
#endif /* _WIN32 */

#include <stdio.h>
#include <string.h>
//#include <stdlib.h>
//#include <ctype.h>
#include "cmdmain.h"
#include "cmdcrc.h"
#include "reveng/reveng.h"
#include "ui.h"
#include "util.h"

#define MAX_ARGS 20

int uerr(char *msg){
	PrintAndLog("%s",msg);
	return 0;
}

int split(char *str, char *arr[MAX_ARGS]){
    int beginIndex = 0;
    int endIndex;
    int maxWords = MAX_ARGS;
    int wordCnt = 0;

    while(1){
        while(isspace(str[beginIndex])){
            ++beginIndex;
        }
        if(str[beginIndex] == '\0')
            break;
        endIndex = beginIndex;
        while (str[endIndex] && !isspace(str[endIndex])){
            ++endIndex;
        }
        int len = endIndex - beginIndex;
        char *tmp = calloc(len + 1, sizeof(char));
        memcpy(tmp, &str[beginIndex], len);
        arr[wordCnt++] = tmp;
        //PrintAndLog("cnt: %d, %s",wordCnt-1, arr[wordCnt-1]);
        beginIndex = endIndex;
        if (wordCnt == maxWords)
            break;
    }
    return wordCnt;
}

int CmdCrc(const char *Cmd)
{
	char name[] = {"reveng "};
	char Cmd2[50 + 7];
	memcpy(Cmd2, name, 7);
	memcpy(Cmd2 + 7, Cmd, 50);
	char *argv[MAX_ARGS];
	int argc = split(Cmd2, argv);
	//PrintAndLog("argc: %d, %s %s Cmd: %s",argc, argv[0], Cmd2, Cmd);
	reveng_main(argc, argv);
	for(int i = 0; i < argc; ++i){
		//puts(arr[i]);
		free(argv[i]);
	}

  return 0; 
}

int GetModels(char *Models[], int *count, uint32_t *width){
	/* default values */
	static model_t model = {
		PZERO,		/* no CRC polynomial, user must specify */
		PZERO,		/* Init = 0 */
		P_BE,		/* RefIn = false, RefOut = false, plus P_RTJUST setting in reveng.h */
		PZERO,		/* XorOut = 0 */
		PZERO,		/* check value unused */
		NULL		/* no model name */
	};

	int ibperhx = 8;//, obperhx = 8;
	int rflags = 0, uflags = 0; /* search and UI flags */
	poly_t apoly, crc, qpoly = PZERO, *apolys = NULL, *pptr = NULL, *qptr = NULL;
	model_t pset = model, *candmods, *mptr;

	/* stdin must be binary */
	#ifdef _WIN32
		_setmode(STDIN_FILENO, _O_BINARY);
	#endif /* _WIN32 */

	SETBMP();
	
	int args = 0, psets, pass;
	int Cnt = 0;
	if (*width == 0) { //reveng -D
		*count = mcount();
		if(!*count)
			return uerr("no preset models available");

		for(int mode = 0; mode < *count; ++mode) {
			mbynum(&model, mode);
			mcanon(&model);
			size_t size = (model.name && *model.name) ? strlen(model.name) : 6;
			char *tmp = calloc(size+1, sizeof(char));
			if (tmp==NULL)
				return uerr("out of memory?");

			memcpy(tmp, model.name, size);
			Models[mode] = tmp;
		}
		mfree(&model);
	} else { //reveng -s

			if(~model.flags & P_MULXN)
				return uerr("cannot search for non-Williams compliant models");

			praloc(&model.spoly, *width);
			praloc(&model.init, *width);
			praloc(&model.xorout, *width);
			if(!plen(model.spoly))
				palloc(&model.spoly, *width);
			else
				*width = plen(model.spoly);

			/* special case if qpoly is zero, search to end of range */
			if(!ptst(qpoly))
				rflags &= ~R_HAVEQ;

			/* if endianness not specified, try
			 * little-endian then big-endian.
			 * NB: crossed-endian algorithms will not be
			 * searched.
			 */
			/* scan against preset models */
			if(~uflags & C_FORCE) {
				pass = 0;
				Cnt = 0;
				do {
					psets = mcount();

					while(psets) {
						mbynum(&pset, --psets);
						
						/* skip if different width, or refin or refout don't match */
						if(plen(pset.spoly) != *width || (model.flags ^ pset.flags) & (P_REFIN | P_REFOUT))
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
							mcanon(&pset);
							
							size_t size = (pset.name && *pset.name) ? strlen(pset.name) : 6;
							//PrintAndLog("Size: %d, %s, count: %d",size,pset.name, Cnt);
							char *tmp = calloc(size+1, sizeof(char));

							if (tmp == NULL){
								PrintAndLog("out of memory?");
								return 0;
							}
							memcpy(tmp, pset.name, size);
							Models[Cnt++] = tmp;
							*count = Cnt;
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
			}
			if(!(model.flags & P_REFIN) != !(model.flags & P_REFOUT))
				return uerr("cannot search for crossed-endian models");

			pass = 0;
			do {
				mptr = candmods = reveng(&model, qpoly, rflags, args, apolys);
				if(mptr && plen(mptr->spoly))
					uflags |= C_RESULT;
				while(mptr && plen(mptr->spoly)) {
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
				return uerr("no models found");
			mfree(&model);

	}
	return 1;
}

//-c || -v
//inModel = valid model name string - CRC-8
//inHexStr = input hex string to calculate crc on
//reverse = reverse calc option if true
//endian = {0 = calc default endian input and output, b = big endian input and output, B = big endian output, r = right justified
//          l = little endian input and output, L = little endian output only, t = left justified}
//result = calculated crc hex string
int RunModel(char *inModel, char *inHexStr, bool reverse, char endian, char *result){
	/* default values */
	static model_t model = {
		PZERO,		// no CRC polynomial, user must specify
		PZERO,		// Init = 0
		P_BE,		  // RefIn = false, RefOut = false, plus P_RTJUST setting in reveng.h
		PZERO,		// XorOut = 0
		PZERO,		// check value unused 
		NULL		  // no model name 
	};
	int ibperhx = 8, obperhx = 8;
	int rflags = 0; // search flags 
	int c;
	unsigned long width = 0UL;
	poly_t apoly, crc;

	char *string;

	// stdin must be binary
	#ifdef _WIN32
		_setmode(STDIN_FILENO, _O_BINARY);
	#endif /* _WIN32 */

	SETBMP();
	//set model
	if(!(c = mbynam(&model, inModel))) {
		PrintAndLog("error: preset model '%s' not found.  Use reveng -D to list presets.", inModel);
		return 0;
	}
	if(c < 0)
		return uerr("no preset models available");

	// must set width so that parameter to -ipx is not zeroed 
	width = plen(model.spoly);
	rflags |= R_HAVEP | R_HAVEI | R_HAVERI | R_HAVERO | R_HAVEX;
	
	//set flags
	switch (endian) {
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
	}

	mcanon(&model);

	if (reverse) {
		// v  calculate reversed CRC
		/* Distinct from the -V switch as this causes
		 * the arguments and output to be reversed as well.
		 */
		// reciprocate Poly
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

		// swap init and xorout
		apoly = model.init;
		model.init = model.xorout;
		model.xorout = apoly;
	}
	// c  calculate CRC

	/* in the Williams model, xorout is applied after the refout stage.
	 * as refout is part of ptostr(), we reverse xorout here.
	 */
	if(model.flags & P_REFOUT)
		prev(&model.xorout);

	apoly = strtop(inHexStr, model.flags, ibperhx);

	if(reverse)
		prev(&apoly);

	crc = pcrc(apoly, model.spoly, model.init, model.xorout, model.flags);

	if(reverse)
		prev(&crc);

	string = ptostr(crc, model.flags, obperhx);
	for (int i = 0; i < 50; i++){
		result[i] = string[i];
		if (result[i]==0) break;
	}
	free(string);
	pfree(&crc);
	pfree(&apoly);
	return 1;
}
