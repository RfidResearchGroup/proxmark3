//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// UI utilities
//-----------------------------------------------------------------------------

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <readline/readline.h>

#include "ui.h"

double CursorScaleFactor;
int PlotGridX, PlotGridY, PlotGridXdefault= 64, PlotGridYdefault= 64;
int offline;

static char *logfilename = "proxmark3.log";

void PrintAndLog(char *fmt, ...)
{
	char *saved_line;
	int saved_point;
  va_list argptr, argptr2;
  static FILE *logfile = NULL;
  static int logging=1;

  if (logging && !logfile) {
    logfile=fopen(logfilename, "a");
    if (!logfile) {
      fprintf(stderr, "Can't open logfile, logging disabled!\n");
      logging=0;
    }
  }
	
	int need_hack = (rl_readline_state & RL_STATE_READCMD) > 0;

	if (need_hack) {
		saved_point = rl_point;
		saved_line = rl_copy_text(0, rl_end);
		rl_save_prompt();
		rl_replace_line("", 0);
		rl_redisplay();
	}
	
  va_start(argptr, fmt);
  va_copy(argptr2, argptr);
  vprintf(fmt, argptr);
  printf("          "); // cleaning prompt
  va_end(argptr);
  printf("\n");

	if (need_hack) {
		rl_restore_prompt();
		rl_replace_line(saved_line, 0);
		rl_point = saved_point;
		rl_redisplay();
		free(saved_line);
	}
	
  if (logging && logfile) {
    vfprintf(logfile, fmt, argptr2);
    fprintf(logfile,"\n");
    fflush(logfile);
  }
  va_end(argptr2);
}

void SetLogFilename(char *fn)
{
  logfilename = fn;
}
