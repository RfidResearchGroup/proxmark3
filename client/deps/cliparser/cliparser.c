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
#include <util.h>       // color constants
#include <ui.h>         // PrintAndLogEx
#include <ctype.h>      // tolower
#include <inttypes.h>   // PRIu64

#ifndef ARRAYLEN
# define ARRAYLEN(x) (sizeof(x)/sizeof((x)[0]))
#endif

// Custom Colors
// To default the color return s
#define _SectionTagColor_(s)    _GREEN_(s)
#define _ExampleColor_(s)       _YELLOW_(s)
#define _CommandColor_(s)       _RED_(s)
#define _DescriptionColor_(s)   _CYAN_(s)
#define _ArgColor_(s) s
#define _ArgHelpColor_(s) s
// End Custom Colors
// Option width set to 30 to allow option descriptions to align.  approx line 74
// Example width set to 50 to allow help descriptions to align.  approx line 93

int CLIParserInit(CLIParserContext **ctx, const char *vprogramName, const char *vprogramHint, const char *vprogramHelp) {
    *ctx = calloc(sizeof(CLIParserContext), sizeof(uint8_t));
    if (*ctx == NULL) {
        PrintAndLogEx(ERR, "ERROR: Insufficient memory\n");
        return 2;
    }

    (*ctx)->argtable = NULL;
    (*ctx)->argtableLen = 0;
    (*ctx)->programName = vprogramName;
    (*ctx)->programHint = vprogramHint;
    (*ctx)->programHelp = vprogramHelp;
    memset((*ctx)->buf, 0x00, sizeof((*ctx)->buf));

    return PM3_SUCCESS;
}

void CLIParserPrintHelp(CLIParserContext *ctx) {
    if (ctx->programHint) {
        PrintAndLogEx(NORMAL, "\n"_DescriptionColor_("%s"), ctx->programHint);
    }

    PrintAndLogEx(NORMAL, "\n"_SectionTagColor_("usage:"));
    PrintAndLogEx(NORMAL, "    "_CommandColor_("%s")NOLF, ctx->programName);
    arg_print_syntax(stdout, ctx->argtable, "\n\n");

    PrintAndLogEx(NORMAL, _SectionTagColor_("options:"));
    arg_print_glossary(stdout, ctx->argtable, "    "_ArgColor_("%-30s")" "_ArgHelpColor_("%s")"\n");
    PrintAndLogEx(NORMAL, "");

    if (ctx->programHelp) {

        // allocate more then enough memory as we are splitting
        char *s = calloc(strlen(ctx->programHelp) + 1, sizeof(uint8_t));
        if (s == NULL) {
            PrintAndLogEx(FAILED, "cannot allocate memory");
            return;
        }

        PrintAndLogEx(NORMAL, _SectionTagColor_("examples/notes:"));

        // pointer to split example from comment.
        char *p2;

        int idx = 0;
        int egWidth = 30;
        for (int i = 0; i <= strlen(ctx->programHelp); i++) {  // <= so to get string terminator.

            s[idx++] = ctx->programHelp[i];

            if ((ctx->programHelp[i] == '\n') || (ctx->programHelp[i] == 0x00)) {

                s[idx - 1] = 0x00;
                p2 = strstr(s, "->"); // See if the example has a comment.

                if (p2 != NULL) {
                    *(p2 - 1) = 0x00;

                    if (strlen(s) > 28)
                        egWidth = strlen(s) + 5;
                    else
                        egWidth = 30;

                    PrintAndLogEx(NORMAL, "    "_ExampleColor_("%-*s")" %s", egWidth, s, p2);
                } else {
                    PrintAndLogEx(NORMAL, "    "_ExampleColor_("%-*s"), egWidth, s);
                }

                idx = 0;
            }
        }
        free(s);
        PrintAndLogEx(NORMAL, "");
    }
    fflush(stdout);
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
        CLIParserPrintHelp(ctx);
        return 1;
    }

    /* If the parser returned any errors then display them and exit */
    if (nerrors > 0) {
        /* Display the error details contained in the arg_end struct.*/
        arg_print_errors(stdout, ((struct arg_end *)(ctx->argtable)[vargtableLen - 1]), ctx->programName);
        PrintAndLogEx(WARNING, "Try " _YELLOW_("'%s --help'") " for more information.\n", ctx->programName);
        fflush(stdout);
        return 3;
    }

    return PM3_SUCCESS;
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
    char *argv[MAX_INPUT_ARG_LENGTH] = {NULL};

    int len = strlen(str);

    memset(ctx->buf, 0x00, ARRAYLEN(ctx->buf));

    char *bufptr = ctx->buf;
    char *bufptrend = ctx->buf + ARRAYLEN(ctx->buf) - 1;
    char *spaceptr = NULL;
    enum ParserState state = PS_FIRST;

    argv[argc++] = bufptr;
    // param0 = program name + with 0x00
    memcpy(ctx->buf, ctx->programName, strlen(ctx->programName) + 1);

    bufptr += strlen(ctx->programName) + 1;
    if (len) {
        argv[argc++] = bufptr;
    }

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
        if (bufptr > bufptrend) {
            PrintAndLogEx(ERR, "ERROR: Line too long\n");
            fflush(stdout);
            return 2;
        }
    }

    return CLIParserParseArg(ctx, argc, argv, vargtable, vargtableLen, allowEmptyExec);
}

// convertors
int CLIParamHexToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen) {
    *datalen = 0;

    int tmplen = 0;
    uint8_t tmpstr[MAX_INPUT_ARG_LENGTH + 1] = {0};

    // concat all strings in argstr into tmpstr[]
    int res = CLIParamStrToBuf(argstr, tmpstr, sizeof(tmpstr), &tmplen);
    if (res || (tmplen == 0)) {
        return res;
    }

    res = param_gethex_to_eol((char *)tmpstr, 0, data, maxdatalen, datalen);
    switch (res) {
        case 1:
            PrintAndLogEx(ERR, "Parameter error: Invalid HEX value\n");
            break;
        case 2:
            PrintAndLogEx(ERR, "Parameter error: parameter too large\n");
            break;
        case 3:
            PrintAndLogEx(ERR, "Parameter error: Hex string must have EVEN number of digits\n");
            break;
    }
    return res;
}

int CLIParamBinToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen) {
    *datalen = 0;

    int tmplen = 0;
    uint8_t tmpstr[MAX_INPUT_ARG_LENGTH + 1] = {0};

    // concat all strings in argstr into tmpstr[]
    //
    int res = CLIParamStrToBuf(argstr, tmpstr, sizeof(tmpstr), &tmplen);
    if (res || tmplen == 0) {
        return res;
    }

    res = param_getbin_to_eol((char *)tmpstr, 0, data, maxdatalen, datalen);
    switch (res) {
        case 1:
            PrintAndLogEx(ERR, "Parameter error: Invalid BINARY value\n");
            break;
        case 2:
            PrintAndLogEx(ERR, "Parameter error: parameter too large\n");
            break;
    }
    return res;
}

int CLIParamStrToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen) {
    *datalen = 0;
    if (!argstr->count)
        return 0;

    uint8_t tmpstr[MAX_INPUT_ARG_LENGTH + 1] = {0};
    int ibuf = 0;

    for (int i = 0; i < argstr->count; i++) {

        int len = strlen(argstr->sval[i]);

        if (len > ((sizeof(tmpstr) / 2) - ibuf)) {
            PrintAndLogEx(ERR, "Parameter error: string too long (%i chars), expect MAX %zu chars\n", len + ibuf, (sizeof(tmpstr) / 2));
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
        PrintAndLogEx(ERR, "Parameter error: string too long (%i chars), expected MAX %i chars\n", ibuf, maxdatalen);
        return 2;
    }

    memcpy(data, tmpstr, ibuf + 1);
    *datalen = ibuf;
    return 0;
}

int CLIGetOptionList(struct arg_str *argstr, const CLIParserOption *option_array, int *value) {
    char data[200] = {0};
    int datalen = 200;
    int res = CLIParamStrToBuf(argstr, (uint8_t *)data, sizeof(data), &datalen);
    if (res)
        return res;

    // no data to check - we do not touch *value, just return
    if (datalen == 0)
        return 0;

    str_lower(data);

    int val = -1;
    int cntr = 0;
    for (int i = 0; (i < CLI_MAX_OPTLIST_LEN) && (option_array[i].text != NULL); i++) {
        // exact match
        if (strcmp(option_array[i].text, data) == 0) {
            *value = option_array[i].code;
            return 0;
        }
        // partial match
        if (strncmp(option_array[i].text, data, datalen) == 0) {
            val = option_array[i].code;
            cntr++;
        }
    }

    // check partial match
    if (cntr == 0) {
        PrintAndLogEx(ERR, "Parameter error: No similar option to `%s`. Valid options: %s\n", argstr->sval[0], argstr->hdr.datatype);
        return 20;
    }
    if (cntr > 1) {
        PrintAndLogEx(ERR, "Parameter error: Several options fit to `%s`. Valid options: %s\n", argstr->sval[0], argstr->hdr.datatype);
        return 21;
    }

    *value = val;
    return 0;
}

const char *CLIGetOptionListStr(const CLIParserOption *option_array, int value) {
    static const char *errmsg = "n/a";

    for (int i = 0; (i < CLI_MAX_OPTLIST_LEN) && (option_array[i].text != NULL); i++) {
        if (option_array[i].code == value) {
            return option_array[i].text;
        }
    }
    return errmsg;
}


// hexstr ->  u64,  w optional len input and default value fallback.
// 0 = failed
// 1 = OK
// 3 = optional param - not set
uint64_t arg_get_u64_hexstr_def(CLIParserContext *ctx, uint8_t paramnum, uint64_t def) {
    uint64_t rv = 0;
    uint8_t d[8];
    int dlen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, paramnum), d, sizeof(d), &dlen);
    if (res == 0 && dlen > 0) {
        for (int i = 0; i < dlen; i++) {
            rv <<= 8;
            rv |= d[i];
        }
    } else  {
        rv = def;
    }
    return rv;
}

// hexstr ->  u64,  w optional len input and default value fallback.
// 0 = failed
// 1 = OK
// 2 = wrong len param, use default
// 3 = optional param,  if fail, use default.
int arg_get_u64_hexstr_def_nlen(CLIParserContext *ctx, uint8_t paramnum, uint64_t def, uint64_t *out, uint8_t nlen, bool optional) {
    int n = 0;
    uint8_t d[nlen];
    int res = CLIParamHexToBuf(arg_get_str(ctx, paramnum), d, sizeof(d), &n);
    if (res == 0 && n == nlen) {
        uint64_t rv = 0;
        for (uint8_t i = 0; i < n; i++) {
            rv <<= 8;
            rv |= d[i];
        }
        *out = rv;
        return 1;
    } else if (res == 0 && n) {
        *out = def;
        return 2;
    } else if (res == 0 && n == 0 && optional) {
        *out = def;
        return 3;
    }
    return 0;
}

int arg_get_u32_hexstr_def(CLIParserContext *ctx, uint8_t paramnum, uint32_t def, uint32_t *out) {
    return arg_get_u32_hexstr_def_nlen(ctx, paramnum, def, out, 4, false);
}

int arg_get_u32_hexstr_def_nlen(CLIParserContext *ctx, uint8_t paramnum, uint32_t def, uint32_t *out, uint8_t nlen, bool optional) {
    int n = 0;
    uint8_t d[nlen];
    int res = CLIParamHexToBuf(arg_get_str(ctx, paramnum), d, sizeof(d), &n);
    if (res == 0 && n == nlen) {
        uint32_t rv = 0;
        for (uint8_t i = 0; i < n; i++) {
            rv <<= 8;
            rv |= d[i];
        }
        *out = rv;
        return 1;
    } else if (res == 0 && n) {
        *out = def;
        return 2;
    } else if (res == 0 && n == 0 && optional) {
        *out = def;
        return 3;
    }
    return 0;
}

