#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "proxgui.h"
#include "translate.h"
#include "../winsrc/prox.h"

int GraphBuffer[MAX_GRAPH_TRACE_LEN];
int GraphTraceLen;
double CursorScaleFactor;
int CommandFinished;

static char *logfilename = "proxmark3.log";

void PrintToScrollback(char *fmt, ...) {
	va_list argptr;
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
	vprintf(fmt, argptr);
	printf("\n");
	if (logging && logfile) {
#if 0
		char zeit[25];
		time_t jetzt_t;
		struct tm *jetzt;

		jetzt_t = time(NULL);
		jetzt = localtime(&jetzt_t);
		strftime(zeit, 25, "%b %e %T", jetzt);

		fprintf(logfile,"%s ", zeit);
#endif
		vfprintf(logfile, fmt, argptr);
		fprintf(logfile,"\n");
		fflush(logfile);
	}
	va_end(argptr);
}

void setlogfilename(char *fn)
{
	logfilename = fn;
}
