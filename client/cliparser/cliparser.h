//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Command line parser core commands
//-----------------------------------------------------------------------------

#include "argtable3.h"
#include "util.h"
#include <stdbool.h>

#define arg_param_begin arg_lit0("hH",  "help",    "print this help and exit")
#define arg_param_end arg_end(20)

#define arg_getsize(a) (sizeof(a) / sizeof(a[0]))
#define arg_get_lit(n)(((struct arg_lit*)argtable[n])->count)
#define arg_get_int_count(n)(((struct arg_int*)argtable[n])->count)
#define arg_get_int(n)(((struct arg_int*)argtable[n])->ival[0])
#define arg_get_int_def(n,def)(arg_get_int_count(n)?(arg_get_int(n)):(def))
#define arg_get_str(n)((struct arg_str*)argtable[n])
#define arg_get_str_len(n)(strlen(((struct arg_str*)argtable[n])->sval[0]))

#define arg_strx1(shortopts, longopts, datatype, glossary) (arg_strn((shortopts), (longopts), (datatype), 1, 250, (glossary)))
#define arg_strx0(shortopts, longopts, datatype, glossary) (arg_strn((shortopts), (longopts), (datatype), 0, 250, (glossary)))

#define CLIExecWithReturn(cmd, atbl, ifempty) if (CLIParserParseString(cmd, atbl, arg_getsize(atbl), ifempty)){CLIParserFree();return 0;}
#define CLIGetHexBLessWithReturn(paramnum, data, datalen, delta) if (CLIParamHexToBuf(arg_get_str(paramnum), data, sizeof(data) - (delta), datalen)) {CLIParserFree();return 1;}
#define CLIGetHexWithReturn(paramnum, data, datalen) if (CLIParamHexToBuf(arg_get_str(paramnum), data, sizeof(data), datalen)) {CLIParserFree();return 1;}
#define CLIGetStrWithReturn(paramnum, data, datalen) if (CLIParamStrToBuf(arg_get_str(paramnum), data, sizeof(data), datalen)) {CLIParserFree();return 1;}

extern int CLIParserInit(char *vprogramName, char *vprogramHint, char *vprogramHelp);
extern int CLIParserParseString(const char *str, void *argtable[], size_t vargtableLen, bool allowEmptyExec);
extern int CLIParserParseStringEx(const char *str, void *vargtable[], size_t vargtableLen, bool allowEmptyExec, bool clueData);
extern int CLIParserParseArg(int argc, char **argv, void *argtable[], size_t vargtableLen, bool allowEmptyExec);
extern void CLIParserFree();

extern int CLIParamHexToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen);
extern int CLIParamStrToBuf(struct arg_str *argstr, uint8_t *data, int maxdatalen, int *datalen);
