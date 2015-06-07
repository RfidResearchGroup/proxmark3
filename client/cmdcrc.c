//-----------------------------------------------------------------------------
// Copyright (C) 2015 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CRC Calculations from the software reveng commands
//-----------------------------------------------------------------------------

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

