//-----------------------------------------------------------------------------
// Borrowed initially from https://reveng.sourceforge.io/
// Copyright (C) Greg Cook 2019
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// CRC Calculations
//-----------------------------------------------------------------------------
#include "cmdcrc.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef _WIN32
#  include <io.h>
#  include <fcntl.h>
#  ifndef STDIN_FILENO
#    define STDIN_FILENO 0
#  endif /* STDIN_FILENO */
#endif /* _WIN32 */

#include "reveng.h"
#include "ui.h"
#include "util.h"
#include "pm3_cmd.h"

#define MAX_ARGS 20

static int split(char *str, char *arr[MAX_ARGS]) {
    int beginIndex = 0;
    int wordCnt = 0;

    while (1) {
        while (isspace(str[beginIndex])) {
            ++beginIndex;
        }
        if (str[beginIndex] == '\0') {
            break;
        }
        int endIndex = beginIndex;
        while (str[endIndex] && !isspace(str[endIndex])) {
            ++endIndex;
        }
        int len = endIndex - beginIndex;
        char *tmp = calloc(len + 1, sizeof(char));
        memcpy(tmp, &str[beginIndex], len);
        arr[wordCnt++] = tmp;
        beginIndex = endIndex;
        if (wordCnt == MAX_ARGS)
            break;
    }
    return wordCnt;
}

//returns array of model names and the count of models returning
//  as well as a width array for the width of each model
int GetModels(char *Models[], int *count, uint8_t *width) {
    /* default values */
    static model_t model = MZERO;

    poly_t apoly, crc, qpoly = PZERO, *apolys = NULL, *pptr = NULL, *qptr = NULL;
    model_t pset = model;

    /* stdin must be binary */
#ifdef _WIN32
    _setmode(STDIN_FILENO, _O_BINARY);
#endif /* _WIN32 */

    SETBMP();

    if (width[0] == 0) { //reveng -D
        *count = mcount();
        if (!*count) {
            PrintAndLogEx(WARNING, "no preset models available");
            return 0;
        }
        for (int mode = 0; mode < *count; ++mode) {
            mbynum(&model, mode);
            mcanon(&model);
            size_t size = (model.name && *model.name) ? strlen(model.name) : 7;
            char *tmp = calloc(size + 1, sizeof(char));
            if (tmp == NULL) {
                PrintAndLogEx(WARNING, "out of memory?");
                return 0;
            }
            if (model.name != NULL) {
                memcpy(tmp, model.name, size);
                Models[mode] = tmp;
                width[mode] = plen(model.spoly);
            } else {
                free(tmp);
            }
        }
        mfree(&model);
    } else { //reveng -s

        int ibperhx = 8;//, obperhx = 8;
        int rflags = 0, uflags = 0; /* search and UI flags */
        if (~model.flags & P_MULXN) {
            PrintAndLogEx(WARNING, "cannot search for non-Williams compliant models");
            return 0;
        }
        praloc(&model.spoly, (unsigned long)width[0]);
        praloc(&model.init, (unsigned long)width[0]);
        praloc(&model.xorout, (unsigned long)width[0]);

        if (!plen(model.spoly))
            palloc(&model.spoly, (unsigned long)width[0]);
        else
            width[0] = (uint8_t)plen(model.spoly);

        /* special case if qpoly is zero, search to end of range */
        if (!ptst(qpoly))
            rflags &= ~R_HAVEQ;

        int pass;

        /* if endianness not specified, try
         * little-endian then big-endian.
         * NB: crossed-endian algorithms will not be
         * searched.
         */
        /* scan against preset models */
        if (~uflags & C_NOPCK) {
            pass = 0;
            int Cnt = 0;
            do {
                int psets = mcount();

                while (psets) {
                    mbynum(&pset, --psets);

                    /* skip if different width, or refin or refout don't match */
                    if (plen(pset.spoly) != width[0] || (model.flags ^ pset.flags) & (P_REFIN | P_REFOUT))
                        continue;
                    /* skip if the preset doesn't match specified parameters */
                    if (rflags & R_HAVEP && pcmp(&model.spoly, &pset.spoly))
                        continue;
                    if (rflags & R_HAVEI && psncmp(&model.init, &pset.init))
                        continue;
                    if (rflags & R_HAVEX && psncmp(&model.xorout, &pset.xorout))
                        continue;

                    //for additional args (not used yet, maybe future?)
                    apoly = pclone(pset.xorout);

                    if (pset.flags & P_REFOUT)
                        prev(&apoly);


                    for (qptr = apolys; qptr < pptr; ++qptr) {
                        crc = pcrc(*qptr, pset.spoly, pset.init, apoly, 0);
                        if (ptst(crc)) {
                            pfree(&crc);
                            break;
                        }
                        pfree(&crc);
                    }
                    pfree(&apoly);

                    if (qptr == pptr) {

                        /* the selected model solved all arguments */
                        mcanon(&pset);

                        size_t size = (pset.name && *pset.name) ? strlen(pset.name) : 7;
                        //PrintAndLogEx(NORMAL, "Size: %d, %s, count: %d",size,pset.name, Cnt);
                        char *tmp = calloc(size + 1, sizeof(char));
                        if (tmp == NULL) {
                            PrintAndLogEx(WARNING, "out of memory?");
                            return 0;
                        }
                        width[Cnt] = width[0];
                        memcpy(tmp, pset.name, size);
                        Models[Cnt++] = tmp;
                        *count = Cnt;
                        uflags |= C_RESULT;
                    }
                }
                mfree(&pset);

                /* toggle refIn/refOut and reflect arguments */
                if (~rflags & R_HAVERI) {
                    model.flags ^= P_REFIN | P_REFOUT;
                    for (qptr = apolys; qptr < pptr; ++qptr) {
                        prevch(qptr, ibperhx);
                    }
                }
            } while (~rflags & R_HAVERI && ++pass < 2);
        }
        //got everything now free the memory...

        if (uflags & C_RESULT) {
            for (qptr = apolys; qptr < pptr; ++qptr) {
                pfree(qptr);
            }
        }
        if (uflags & C_NOBFS && ~rflags & R_HAVEP) {
            PrintAndLogEx(WARNING, "no models found");
            return 0;
        }

        if (!(model.flags & P_REFIN) != !(model.flags & P_REFOUT)) {
            PrintAndLogEx(WARNING, "cannot search for crossed-endian models");
            return 0;
        }
        pass = 0;
        int args = 0;
        do {
            model_t *candmods = reveng(&model, qpoly, rflags, args, apolys);
            model_t *mptr = candmods;
            if (mptr && plen(mptr->spoly)) {
                uflags |= C_RESULT;
            }
            while (mptr && plen(mptr->spoly)) {
                mfree(mptr++);
            }
            free(candmods);
            if (~rflags & R_HAVERI) {
                model.flags ^= P_REFIN | P_REFOUT;
                for (qptr = apolys; qptr < pptr; ++qptr) {
                    prevch(qptr, ibperhx);
                }
            }
        } while (~rflags & R_HAVERI && ++pass < 2);

        for (qptr = apolys; qptr < pptr; ++qptr) {
            pfree(qptr);
        }
        free(apolys);
        mfree(&model);

        if (~uflags & C_RESULT) {
            PrintAndLogEx(WARNING, "no models found");
            return 0;
        }
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
int RunModel(char *inModel, char *inHexStr, bool reverse, char endian, char *result) {
    /* default values */
    static model_t model = MZERO;

    int ibperhx = 8, obperhx = 8;
//    int rflags = 0; // search flags
    poly_t apoly, crc;

    char *string;

    // stdin must be binary
#ifdef _WIN32
    _setmode(STDIN_FILENO, _O_BINARY);
#endif /* _WIN32 */

    SETBMP();
    //set model
    int c = mbynam(&model, inModel);
    if (!c) {
        PrintAndLogEx(ERR, "error: preset model '%s' not found.  Use reveng -D to list presets. [%d]", inModel, c);
        return 0;
    }
    if (c < 0) {
        PrintAndLogEx(WARNING, "no preset models available");
        return 0;
    }
//    rflags |= R_HAVEP | R_HAVEI | R_HAVERI | R_HAVERO | R_HAVEX;

    //set flags
    switch (endian) {
        case 'b': /* b  big-endian (RefIn = false, RefOut = false ) */
            model.flags &= ~P_REFIN;
        //rflags |= R_HAVERI;
        /* fall through: */
        case 'B': /* B  big-endian output (RefOut = false) */
            model.flags &= ~P_REFOUT;
            //rflags |= R_HAVERO;
            mnovel(&model);
        /* fall through: */
        case 'r': /* r  right-justified */
            model.flags |= P_RTJUST;
            break;
        case 'l': /* l  little-endian input and output */
            model.flags |= P_REFIN;
        //rflags |= R_HAVERI;
        /* fall through: */
        case 'L': /* L  little-endian output */
            model.flags |= P_REFOUT;
            //rflags |= R_HAVERO;
            mnovel(&model);
        /* fall through: */
        case 't': /* t  left-justified */
            model.flags &= ~P_RTJUST;
            break;
    }
    /* canonicalise the model, so the one we dump is the one we
     * calculate with (not with -s, spoly may be blank which will
     * normalise to zero and clear init and xorout.)
     */
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
        if (~model.flags & P_REFOUT) {
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
    if (model.flags & P_REFOUT)
        prev(&model.xorout);

    apoly = strtop(inHexStr, model.flags, ibperhx);

    if (reverse)
        prev(&apoly);

    crc = pcrc(apoly, model.spoly, model.init, model.xorout, model.flags);

    if (reverse)
        prev(&crc);

    string = ptostr(crc, model.flags, obperhx);
    for (int i = 0; i < 50; i++) {
        result[i] = string[i];
        if (result[i] == 0) break;
    }
    free(string);
    pfree(&crc);
    pfree(&apoly);
    return 1;
}
/*
//test call to RunModel
static int CmdrevengTestC(const char *Cmd) {
    int cmdp = 0;
    char inModel[30] = {0x00};
    char inHexStr[30] = {0x00};
    char result[30];
    int dataLen;
    char endian = 0;
    dataLen = param_getstr(Cmd, cmdp++, inModel, sizeof(inModel));
    if (dataLen < 4) return 0;
    dataLen = param_getstr(Cmd, cmdp++, inHexStr, sizeof(inHexStr));
    if (dataLen < 4) return 0;
    bool reverse = (param_get8(Cmd, cmdp++)) ? true : false;
    endian = param_getchar(Cmd, cmdp++);

    //PrintAndLogEx(NORMAL, "mod: %s, hex: %s, rev %d", inModel, inHexStr, reverse);
    int ans = RunModel(inModel, inHexStr, reverse, endian, result);
    if (!ans) return 0;

    PrintAndLogEx(SUCCESS, "result: %s", result);
    return 1;
}
*/
//returns a calloced string (needs to be freed)
static char *SwapEndianStr(const char *inStr, const size_t len, const uint8_t blockSize) {
    char *tmp = calloc(len + 1, sizeof(char));
    for (uint8_t block = 0; block < (uint8_t)(len / blockSize); block++) {
        for (size_t i = 0; i < blockSize; i += 2) {
            tmp[i + (blockSize * block)] = inStr[(blockSize - 1 - i - 1) + (blockSize * block)];
            tmp[i + (blockSize * block) + 1] = inStr[(blockSize - 1 - i) + (blockSize * block)];
        }
    }
    return tmp;
}

// takes hex string in and searches for a matching result (hex string must include checksum)
static int CmdrevengSearch(const char *Cmd) {

#define NMODELS 106

    char inHexStr[256] = {0x00};
    int dataLen = param_getstr(Cmd, 0, inHexStr, sizeof(inHexStr));
    if (dataLen < 4) return 0;

    // these two arrays, must match preset size.
    char *Models[NMODELS];
    uint8_t width[NMODELS] = {0};
    int count = 0;

    char result[50 + 1] = {0};
    char revResult[50 + 1] = {0};
    int ans = GetModels(Models, &count, width);
    bool found = false;
    if (!ans) {
        for (int i = 0; i < count; i++) {
            free(Models[i]);
        }
        return 0;
    }

    // try each model and get result
    for (int i = 0; i < count; i++) {
        /*if (found) {
            free(Models[i]);
            continue;
        }*/
        // round up to # of characters in this model's crc
        uint8_t crcChars = ((width[i] + 7) / 8) * 2;
        // can't test a model that has more crc digits than our data
        if (crcChars >= dataLen) {
            free(Models[i]);
            continue;
        }

        PrintAndLogEx(DEBUG
                      , "DEBUG: dataLen %d, crcChars %u,  width[i] %u"
                      , dataLen
                      , crcChars
                      , width[i]
                     );

        if (crcChars == 0) {
            free(Models[i]);
            continue;
        }

        memset(result, 0, sizeof(result));
        char *inCRC = calloc(crcChars + 1, sizeof(char));
        if (inCRC == NULL) {
            return 0;
        }

        memcpy(inCRC, inHexStr + (dataLen - crcChars), crcChars);

        char *outHex = calloc(dataLen - crcChars + 1, sizeof(char));
        if (outHex == NULL) {
            free(inCRC);
            return 0;
        }

        memcpy(outHex, inHexStr, dataLen - crcChars);

        ans = RunModel(Models[i], outHex, false, 0, result);
        if (ans) {
            // test for match
            if (memcmp(result, inCRC, crcChars) == 0) {
                PrintAndLogEx(SUCCESS, "\nfound possible match\nmodel: %s | value: %s\n", Models[i], result);
                //optional - stop searching if found...
                found = true;
            } else {
                if (crcChars > 2) {
                    char *swapEndian = SwapEndianStr(result, crcChars, crcChars);
                    if (memcmp(swapEndian, inCRC, crcChars) == 0) {
                        PrintAndLogEx(SUCCESS, "\nfound possible match\nmodel: %s | value endian swapped: %s\n", Models[i], swapEndian);
                        // optional - stop searching if found...
                        found = true;
                    }
                    free(swapEndian);
                }
            }
        }
        ans = RunModel(Models[i], outHex, true, 0, revResult);
        if (ans) {
            // test for match
            if (memcmp(revResult, inCRC, crcChars) == 0) {
                PrintAndLogEx(SUCCESS, "\nfound possible match\nmodel reversed: %s | value: %s\n", Models[i], revResult);
                // optional - stop searching if found...
                found = true;
            } else {
                if (crcChars > 2) {
                    char *swapEndian = SwapEndianStr(revResult, crcChars, crcChars);
                    if (memcmp(swapEndian, inCRC, crcChars) == 0) {
                        PrintAndLogEx(SUCCESS, "\nfound possible match\nmodel reversed: %s | value endian swapped: %s\n", Models[i], swapEndian);
                        // optional - stop searching if found...
                        found = true;
                    }
                    free(swapEndian);
                }
            }
        }
        free(inCRC);
        free(outHex);
        free(Models[i]);
    }

    if (found == false)
        PrintAndLogEx(FAILED, "\nno matches found\n");

    return PM3_SUCCESS;
}

int CmdCrc(const char *Cmd) {
    char c[100 + 7];
    snprintf(c, sizeof(c), "reveng ");
    snprintf(c + strlen(c), sizeof(c) - strlen(c), Cmd, strlen(Cmd));

    char *argv[MAX_ARGS];
    int argc = split(c, argv);

    if (argc == 3 && memcmp(argv[1], "-g", 2) == 0) {
        CmdrevengSearch(argv[2]);
    } else {
        reveng_main(argc, argv);
    }

    for (int i = 0; i < argc; ++i) {
        free(argv[i]);
    }
    return PM3_SUCCESS;
}

