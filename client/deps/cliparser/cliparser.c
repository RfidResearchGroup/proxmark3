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
        printf("ERROR: Insufficient memory\n");
        fflush(stdout);
        return 2;
    }
    /* Parse the command line as defined by argtable[] */
    nerrors = arg_parse(argc, argv, ctx->argtable);

    /* special case: '--help' takes precedence over error reporting */
    if ((argc < 2 && !allowEmptyExec) || ((struct arg_lit *)(ctx->argtable)[0])->count > 0) { // help must be the first record
        printf("Usage: %s", ctx->programName);
        arg_print_syntaxv(stdout, ctx->argtable, "\n");
        if (ctx->programHint)
            printf("%s\n\n", ctx->programHint);
        arg_print_glossary(stdout, ctx->argtable, "    %-20s %s\n");
        printf("\n");
        if (ctx->programHelp)
            printf("%s \n", ctx->programHelp);

        fflush(stdout);
        return 1;
    }

    /* If the parser returned any errors then display them and exit */
    if (nerrors > 0) {
        /* Display the error details contained in the arg_end struct.*/
        arg_print_errors(stdout, ((struct arg_end *)(ctx->argtable)[vargtableLen - 1]), ctx->programName);
        printf("Try '%s --help' for more information.\n", ctx->programName);
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
    char buf[500] = {0};
    memset(ctx->buf, 0x00, 500);
    char *bufptr = buf;
    char *spaceptr = NULL;
    enum ParserState state = PS_FIRST;

    argv[argc++] = bufptr;
    // param0 = program name
    memcpy(buf, ctx->programName, strlen(ctx->programName) + 1); // with 0x00
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

void CLIParserFree(CLIParserContext *ctx) {
    arg_freetable(ctx->argtable, ctx->argtableLen);
    free(ctx);
}

// convertors
int CLIParamHexToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen) {
    *datalen = 0;

    int ibuf = 0;
    uint8_t tmp_buf[256] = {0};
    int res = CLIParamStrToBuf(argstr, tmp_buf, maxdatalen * 2, &ibuf); // *2 because here HEX
    if (res) {
        printf("Parameter error: buffer overflow.\n");
        fflush(stdout);
        return res;
    }
    if (ibuf == 0) {
        return res;
    }

    switch (param_gethex_to_eol((char *)tmp_buf, 0, data, maxdatalen, datalen)) {
        case 1:
            printf("Parameter error: Invalid HEX value.\n");
            fflush(stdout);
            return 1;
        case 2:
            printf("Parameter error: parameter too large.\n");
            fflush(stdout);
            return 2;
        case 3:
            printf("Parameter error: Hex string must have even number of digits.\n");
            fflush(stdout);
            return 3;
    }

    return 0;
}

int CLIParamStrToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen) {
    *datalen = 0;
    if (!argstr->count)
        return 0;

    uint8_t tmp_buf[256] = {0};
    int ibuf = 0;

    for (int i = 0; i < argstr->count; i++) {
        int len = strlen(argstr->sval[i]);
        memcpy(&tmp_buf[ibuf], argstr->sval[i], len);
        ibuf += len;
    }
    tmp_buf[ibuf] = 0;

    if (!ibuf)
        return 0;

    if (ibuf > maxdatalen) {
        fflush(stdout);
        return 2;
    }

    memcpy(data, tmp_buf, ibuf);
    *datalen = ibuf;
    return 0;
}


