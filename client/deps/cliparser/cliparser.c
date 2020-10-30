//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Command line parser core commands
//-----------------------------------------------------------------------------

#include "cliparser.h"
#include <string.h>
#include <stdlib.h>
#include <util.h>   // Get color constants
#include <ui.h>     // get PrintAndLogEx
#include <ctype.h>  // tolower
#include <inttypes.h> // PRIu64

#ifndef ARRAYLEN
# define ARRAYLEN(x) (sizeof(x)/sizeof((x)[0]))
#endif

// Custom Colors
// To default the color return s
#define _SectionTagColor_(s) _GREEN_(s)
#define _ExampleColor_(s) _YELLOW_(s)
#define _CommandColor_(s) _RED_(s)
#define _DescriptionColor_(s) _CYAN_(s)
#define _ArgColor_(s) s
#define _ArgHelpColor_(s) s
// End Custom Colors
// Option width set to 30 to allow option descriptions to align.  approx line 74
// Example width set to 50 to allow help descriptions to align.  approx line 93

int CLIParserInit(CLIParserContext **ctx, const char *vprogramName, const char *vprogramHint, const char *vprogramHelp) {
    *ctx = malloc(sizeof(CLIParserContext));
    if (!*ctx) {
        printf("ERROR: Insufficient memory\n");
        fflush(stdout);
        return 2;
    }
    (*ctx)->argtable = NULL;
    (*ctx)->argtableLen = 0;
    (*ctx)->programName = vprogramName;
    (*ctx)->programHint = vprogramHint;
    (*ctx)->programHelp = vprogramHelp;
    memset((*ctx)->buf, 0x00, sizeof((*ctx)->buf));
    return 0;
}

int CLIParserParseArg(CLIParserContext *ctx, int argc, char **argv, void *vargtable[], size_t vargtableLen, bool allowEmptyExec) {
    int nerrors;

    ctx->argtable = vargtable;
    ctx->argtableLen = vargtableLen;

    /* verify the argtable[] entries were allocated sucessfully */
    if (arg_nullcheck(ctx->argtable) != 0) {
        /* NULL entries were detected, some allocations must have failed */
        PrintAndLogEx(ERR, "ERROR: Insufficient memory\n");
        fflush(stdout);
        return 2;
    }
    /* Parse the command line as defined by argtable[] */
    nerrors = arg_parse(argc, argv, ctx->argtable);

    /* special case: '--help' takes precedence over error reporting */
    if ((argc < 2 && !allowEmptyExec) || ((struct arg_lit *)(ctx->argtable)[0])->count > 0) { // help must be the first record
        if (ctx->programHint)
            PrintAndLogEx(NORMAL, "\n"_DescriptionColor_("%s"), ctx->programHint);

        PrintAndLogEx(NORMAL, "\n"_SectionTagColor_("usage:"));
        PrintAndLogEx(NORMAL, "    "_CommandColor_("%s")NOLF, ctx->programName);
        arg_print_syntax(stdout, ctx->argtable, "\n\n");

        PrintAndLogEx(NORMAL, _SectionTagColor_("options:"));

        arg_print_glossary(stdout, ctx->argtable, "    "_ArgColor_("%-30s")" "_ArgHelpColor_("%s")"\n");

        PrintAndLogEx(NORMAL, "");
        if (ctx->programHelp) {
            PrintAndLogEx(NORMAL, _SectionTagColor_("examples/notes:"));
            char *buf = NULL;
            int idx = 0;
            buf = realloc(buf, strlen(ctx->programHelp) + 1); // more then enough as we are splitting

            char *p2; // pointer to split example from comment.
            int egWidth = 30;
            for (int i = 0; i <= strlen(ctx->programHelp); i++) {  // <= so to get string terminator.
                buf[idx++] = ctx->programHelp[i];
                if ((ctx->programHelp[i] == '\n') || (ctx->programHelp[i] == 0x00)) {
                    buf[idx - 1] = 0x00;
                    p2 = strstr(buf, "->"); // See if the example has a comment.
                    if (p2 != NULL) {
                        *(p2 - 1) = 0x00;

                        if (strlen(buf) > 28)
                            egWidth = strlen(buf) + 5;
                        else
                            egWidth = 30;

                        PrintAndLogEx(NORMAL, "    "_ExampleColor_("%-*s")" %s", egWidth, buf, p2);
                    } else {
                        PrintAndLogEx(NORMAL, "    "_ExampleColor_("%-*s"), egWidth, buf);
                    }
                    idx = 0;
                }
            }

            PrintAndLogEx(NORMAL, "");
            free(buf);
        }

        fflush(stdout);
        return 1;
    }

    /* If the parser returned any errors then display them and exit */
    if (nerrors > 0) {
        /* Display the error details contained in the arg_end struct.*/
        arg_print_errors(stdout, ((struct arg_end *)(ctx->argtable)[vargtableLen - 1]), ctx->programName);
        PrintAndLogEx(WARNING, "Try '%s --help' for more information.\n", ctx->programName);
        fflush(stdout);
        return 3;
    }

    return 0;
}

enum ParserState {
    PS_FIRST,
    PS_ARGUMENT,
    PS_OPTION,
};

#define isSpace(c)(c == ' ' || c == '\t')

int CLIParserParseString(CLIParserContext *ctx, const char *str, void *vargtable[], size_t vargtableLen, bool allowEmptyExec) {
    return CLIParserParseStringEx(ctx, str, vargtable, vargtableLen, allowEmptyExec, false);
}

int CLIParserParseStringEx(CLIParserContext *ctx, const char *str, void *vargtable[], size_t vargtableLen, bool allowEmptyExec, bool clueData) {
    int argc = 0;
    char *argv[200] = {NULL};

    int len = strlen(str);
    memset(ctx->buf, 0x00, ARRAYLEN(ctx->buf));
    char *bufptr = ctx->buf;
    char *spaceptr = NULL;
    enum ParserState state = PS_FIRST;

    argv[argc++] = bufptr;
    // param0 = program name
    memcpy(ctx->buf, ctx->programName, strlen(ctx->programName) + 1); // with 0x00
    bufptr += strlen(ctx->programName) + 1;
    if (len)
        argv[argc++] = bufptr;

    // parse params
    for (int i = 0; i < len; i++) {
        switch (state) {
            case PS_FIRST: // first char
                if (!clueData || str[i] == '-') { // first char before space is '-' - next element - option OR not "clueData" for not-option fields
                    state = PS_OPTION;

                    if (spaceptr) {
                        bufptr = spaceptr;
                        *bufptr = 0x00;
                        bufptr++;
                        argv[argc++] = bufptr;
                    }
                }
                spaceptr = NULL;
            case PS_ARGUMENT:
                if (state == PS_FIRST)
                    state = PS_ARGUMENT;
                if (isSpace(str[i])) {
                    spaceptr = bufptr;
                    state = PS_FIRST;
                }
                *bufptr = str[i];
                bufptr++;
                break;
            case PS_OPTION:
                if (isSpace(str[i])) {
                    state = PS_FIRST;

                    *bufptr = 0x00;
                    bufptr++;
                    argv[argc++] = bufptr;
                    break;
                }

                *bufptr = str[i];
                bufptr++;
                break;
        }
    }

    return CLIParserParseArg(ctx, argc, argv, vargtable, vargtableLen, allowEmptyExec);
}

// convertors
int CLIParamHexToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen) {
    *datalen = 0;

    int tmplen = 0;
    uint8_t tmpstr[(256 * 2) + 1] = {0};

    // concat all strings in argstr into tmpstr[]
    //
    int res = CLIParamStrToBuf(argstr, tmpstr, sizeof(tmpstr), &tmplen);
    if (res) {
        return res;
    }
    if (tmplen == 0) {
        return res;
    }

    res = param_gethex_to_eol((char *)tmpstr, 0, data, maxdatalen, datalen);
    switch (res) {
        case 1:
            printf("Parameter error: Invalid HEX value\n");
            break;
        case 2:
            printf("Parameter error: parameter too large\n");
            break;
        case 3:
            printf("Parameter error: Hex string must have EVEN number of digits\n");
            break;
    }
    fflush(stdout);
    return res;
}

int CLIParamStrToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen) {
    *datalen = 0;
    if (!argstr->count)
        return 0;

    uint8_t tmpstr[(256 * 2) + 1] = {0};
    int ibuf = 0;

    for (int i = 0; i < argstr->count; i++) {

        int len = strlen(argstr->sval[i]);

        if (len > ((sizeof(tmpstr) / 2) - ibuf)) {
            printf("Parameter error: string too long (%i chars), expect MAX %zu chars\n", len + ibuf, (sizeof(tmpstr) / 2));
            fflush(stdout);
            return 2;
        }

        memcpy(&tmpstr[ibuf], argstr->sval[i], len);

        ibuf += len;
    }

    ibuf = MIN(ibuf, (sizeof(tmpstr) / 2));
    tmpstr[ibuf] = 0;

    if (ibuf == 0)
        return 0;

    if (ibuf > maxdatalen) {
        printf("Parameter error: string too long (%i chars), expected MAX %i chars\n", ibuf, maxdatalen);
        fflush(stdout);
        return 2;
    }

    memcpy(data, tmpstr, ibuf + 1);
    *datalen = ibuf;
    return 0;
}

uint64_t arg_get_u64_hexstr_def(CLIParserContext *ctx, uint8_t paramnum, uint64_t def) {
    uint64_t rv = 0;
    uint8_t data[8];
    int datalen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, paramnum), data, sizeof(data), &datalen);
    if (res == 0 && datalen > 0) {
        for (uint8_t i = 0; i < datalen; i++) {
            rv <<= 8;
            rv |= data[i];
        }
    } else  {
        rv = def;
    }   
    return rv;
}


