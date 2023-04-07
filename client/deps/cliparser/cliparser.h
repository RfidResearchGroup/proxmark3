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
#include <stdbool.h>
#include "util.h"

#define arg_param_begin arg_lit0("h",  "help",    "This help")
#define arg_param_end arg_end(20)

#define arg_getsize(a)              (sizeof(a) / sizeof(a[0]))
#define arg_get_lit(ctx, n)         (((struct arg_lit*)((ctx)->argtable)[(n)])->count)

#define arg_get_int_count(ctx, n)   (((struct arg_int*)((ctx)->argtable)[(n)])->count)
#define arg_get_int(ctx, n)         (((struct arg_int*)((ctx)->argtable)[(n)])->ival[0])
#define arg_get_int_def(ctx, n, def)(arg_get_int_count((ctx), (n)) ? (arg_get_int((ctx), (n))) : (def))

#define arg_get_dbl_count(ctx, n)   (((struct arg_dbl*)((ctx)->argtable)[(n)])->count)
#define arg_get_dbl(ctx, n)         (((struct arg_dbl*)((ctx)->argtable)[(n)])->dval[0])
#define arg_get_dbl_def(ctx, n, def)(arg_get_dbl_count((ctx), (n)) ? (arg_get_dbl((ctx), (n))) : (def))

#define arg_get_u32(ctx, n)          (uint32_t)(((struct arg_u64*)((ctx)->argtable)[(n)])->uval[0])
#define arg_get_u32_def(ctx, n, def) (arg_get_u64_count((ctx), (n)) ? (arg_get_u32((ctx), (n))) : (uint32_t)(def))

#define arg_get_u64_count(ctx, n)    (((struct arg_u64*)((ctx)->argtable)[(n)])->count)
#define arg_get_u64(ctx, n)          (((struct arg_u64*)((ctx)->argtable)[(n)])->uval[0])
#define arg_get_u64_def(ctx, n, def) (arg_get_u64_count((ctx), (n)) ? (arg_get_u64((ctx), (n))) : (uint64_t)(def))

#define arg_get_str(ctx, n)          ((struct arg_str*)((ctx)->argtable)[(n)])
#define arg_get_str_len(ctx, n)      (strlen(((struct arg_str*)((ctx)->argtable)[(n)])->sval[0]))

#define arg_strx1(shortopts, longopts, datatype, glossary) (arg_strn((shortopts), (longopts), (datatype), 1, 250, (glossary)))
#define arg_strx0(shortopts, longopts, datatype, glossary) (arg_strn((shortopts), (longopts), (datatype), 0, 250, (glossary)))

#define CLIParserFree(ctx)        if ((ctx)) {arg_freetable((ctx)->argtable, (ctx)->argtableLen); free((ctx)); (ctx)=NULL;}

#define CLIExecWithReturn(ctx, cmd, atbl, ifempty)    if (CLIParserParseString((ctx), (cmd), (atbl), arg_getsize((atbl)), (ifempty))) {CLIParserFree((ctx)); return PM3_ESOFT;}

#define CLIGetHexBLessWithReturn(ctx, paramnum, data, datalen, delta) if (CLIParamHexToBuf(arg_get_str((ctx), (paramnum)), (data), sizeof((data)) - (delta), (datalen))) {CLIParserFree((ctx)); return PM3_ESOFT;}

#define CLIGetHexWithReturn(ctx, paramnum, data, datalen) if (CLIParamHexToBuf(arg_get_str((ctx), (paramnum)), (data), sizeof((data)), (datalen))) {CLIParserFree((ctx)); return PM3_ESOFT;}

#define CLIGetStrWithReturn(ctx, paramnum, data, datalen) if (CLIParamStrToBuf(arg_get_str((ctx), (paramnum)), (data), (*datalen), (datalen))) {CLIParserFree((ctx)); return PM3_ESOFT;}

#define CLIGetOptionListWithReturn(ctx, paramnum, option_array, option_array_len, value) if (CLIGetOptionList(arg_get_str((ctx), (paramnum)), (option_array), (option_array_len), (value))) {CLIParserFree((ctx)); return PM3_ESOFT;}

#define MAX_INPUT_ARG_LENGTH    4096


typedef struct {
    void **argtable;
    size_t argtableLen;
    const char *programName;
    const char *programHint;
    const char *programHelp;
    char buf[MAX_INPUT_ARG_LENGTH + 60];
} CLIParserContext;

#define CLI_MAX_OPTLIST_LEN    50
// option list needs to have NULL at the last record int the field `text`
typedef struct {
    int code;
    const char *text;
} CLIParserOption;

int CLIParserInit(CLIParserContext **ctx, const char *vprogramName, const char *vprogramHint, const char *vprogramHelp);
void CLIParserPrintHelp(CLIParserContext *ctx);
int CLIParserParseString(CLIParserContext *ctx, const char *str, void *vargtable[], size_t vargtableLen, bool allowEmptyExec);
int CLIParserParseStringEx(CLIParserContext *ctx, const char *str, void *vargtable[], size_t vargtableLen, bool allowEmptyExec, bool clueData);
int CLIParserParseArg(CLIParserContext *ctx, int argc, char **argv, void *vargtable[], size_t vargtableLen, bool allowEmptyExec);

int CLIParamHexToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen);
int CLIParamStrToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen);
int CLIParamBinToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen);

// names in the CLIParserOption array must be in the lowercase format
int CLIGetOptionList(struct arg_str *argstr, const CLIParserOption *option_array, int *value);
const char *CLIGetOptionListStr(const CLIParserOption *option_array, int value);

uint64_t arg_get_u64_hexstr_def(CLIParserContext *ctx, uint8_t paramnum, uint64_t def);
int arg_get_u64_hexstr_def_nlen(CLIParserContext *ctx, uint8_t paramnum, uint64_t def, uint64_t *out, uint8_t nlen, bool optional);
int arg_get_u32_hexstr_def(CLIParserContext *ctx, uint8_t paramnum, uint32_t def, uint32_t *out);
int arg_get_u32_hexstr_def_nlen(CLIParserContext *ctx, uint8_t paramnum, uint32_t def, uint32_t *out, uint8_t nlen, bool optional);

#define CP_SUCCESS_OPTIONAL  1
#define CP_SUCCESS           0
#define CP_ENOPARAM         -1
#define CP_WRONGLEN         -2

#endif
