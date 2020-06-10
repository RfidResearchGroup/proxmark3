//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Command line parser core commands
//-----------------------------------------------------------------------------

#ifndef __CLIPARSER_H
#define __CLIPARSER_H
#include "argtable3.h"
#include <stdlib.h>
#include "util.h"

#define arg_param_begin arg_lit0("hH",  "help",    "This help")
#define arg_param_end arg_end(20)

#define arg_getsize(a)      (sizeof(a) / sizeof(a[0]))
#define arg_get_lit(ctx, n)      (((struct arg_lit*)((ctx)->argtable)[n])->count)
#define arg_get_int_count(ctx, n)(((struct arg_int*)((ctx)->argtable)[n])->count)
#define arg_get_int(ctx, n)      (((struct arg_int*)((ctx)->argtable)[n])->ival[0])
#define arg_get_int_def(ctx, n, def)(arg_get_int_count((ctx), n) ? (arg_get_int((ctx), n)) : (def))
#define arg_get_str(ctx, n)      ((struct arg_str*)((ctx)->argtable)[n])
#define arg_get_str_len(ctx, n)  (strlen(((struct arg_str*)((ctx)->argtable)[n])->sval[0]))

#define arg_strx1(shortopts, longopts, datatype, glossary) (arg_strn((shortopts), (longopts), (datatype), 1, 250, (glossary)))
#define arg_strx0(shortopts, longopts, datatype, glossary) (arg_strn((shortopts), (longopts), (datatype), 0, 250, (glossary)))

#define CLIParserFree(ctx)        if ((ctx)) {arg_freetable(ctx->argtable, ctx->argtableLen); free((ctx)); (ctx)=NULL;}
#define CLIExecWithReturn(ctx, cmd, atbl, ifempty)    if (CLIParserParseString(ctx, cmd, atbl, arg_getsize(atbl), ifempty)) {CLIParserFree((ctx)); return PM3_ESOFT;}
#define CLIGetHexBLessWithReturn(ctx, paramnum, data, datalen, delta) if (CLIParamHexToBuf(arg_get_str(ctx, paramnum), data, sizeof(data) - (delta), datalen)) {CLIParserFree((ctx)); return PM3_ESOFT;}
#define CLIGetHexWithReturn(ctx, paramnum, data, datalen) if (CLIParamHexToBuf(arg_get_str(ctx, paramnum), data, sizeof(data), datalen)) {CLIParserFree((ctx)); return PM3_ESOFT;}
#define CLIGetStrWithReturn(ctx, paramnum, data, datalen) if (CLIParamStrToBuf(arg_get_str(ctx, paramnum), data, sizeof(data), datalen)) {CLIParserFree((ctx)); return PM3_ESOFT;}

typedef struct {
    void **argtable;
    size_t argtableLen;
    const char *programName;
    const char *programHint;
    const char *programHelp;
    char buf[500];
} CLIParserContext;
int CLIParserInit(CLIParserContext **ctx, const char *vprogramName, const char *vprogramHint, const char *vprogramHelp);
int CLIParserParseString(CLIParserContext *ctx, const char *str, void *vargtable[], size_t vargtableLen, bool allowEmptyExec);
int CLIParserParseStringEx(CLIParserContext *ctx, const char *str, void *vargtable[], size_t vargtableLen, bool allowEmptyExec, bool clueData);
int CLIParserParseArg(CLIParserContext *ctx, int argc, char **argv, void *vargtable[], size_t vargtableLen, bool allowEmptyExec);

int CLIParamHexToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen);
int CLIParamStrToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen);
#endif
