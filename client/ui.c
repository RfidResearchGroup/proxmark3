#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "ui.h"

double CursorScaleFactor;
int PlotGridX, PlotGridY;
int offline;

static char *logfilename = "proxmark3.log";

void PrintAndLog(char *fmt, ...)
{
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

  va_start(argptr, fmt);
  va_copy(argptr2, argptr);
  vprintf(fmt, argptr);
  va_end(argptr);
  printf("\n");
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
