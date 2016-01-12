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
#include <stdbool.h>
#include <time.h>
#include <readline/readline.h>
#include <pthread.h>
#include "loclass/cipherutils.h"
#include "ui.h"
#include "cmdmain.h"
#include "cmddata.h"
#include "graph.h"
#define M_PI 3.14159265358979323846264338327

double CursorScaleFactor;
int PlotGridX, PlotGridY, PlotGridXdefault= 64, PlotGridYdefault= 64;
int offline;
int flushAfterWrite = 0;
extern pthread_mutex_t print_lock;

static char *logfilename = "proxmark3.log";

void PrintAndLog(char *fmt, ...)
{
	char *saved_line;
	int saved_point;
	va_list argptr, argptr2;
	static FILE *logfile = NULL;
	static int logging = 1;

	// lock this section to avoid interlacing prints from different threats
	pthread_mutex_lock(&print_lock);
  
	if (logging && !logfile) {
		logfile = fopen(logfilename, "a");
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

	if (flushAfterWrite == 1) {
		fflush(NULL);
	}
	//release lock
	pthread_mutex_unlock(&print_lock);  
}

void SetLogFilename(char *fn) {
  logfilename = fn;
}
 
void iceFsk3(int * data, const size_t len){

	int i,j;
	
	int * output =  (int* ) malloc(sizeof(int) * len);	
	memset(output, 0x00, len);
	float fc           = 0.1125f;          // center frequency
	size_t adjustedLen = len;
	
    // create very simple low-pass filter to remove images (2nd-order Butterworth)
    float complex iir_buf[3] = {0,0,0};
    float b[3] = {0.003621681514929,  0.007243363029857, 0.003621681514929};
    float a[3] = {1.000000000000000, -1.822694925196308, 0.837181651256023};
    
    float sample           = 0;      // input sample read from file
    float complex x_prime  = 1.0f;   // save sample for estimating frequency
    float complex x;
		
	for (i=0; i<adjustedLen; ++i) {

		sample = data[i]+128;
		
        // remove DC offset and mix to complex baseband
        x = (sample - 127.5f) * cexpf( _Complex_I * 2 * M_PI * fc * i );

        // apply low-pass filter, removing spectral image (IIR using direct-form II)
        iir_buf[2] = iir_buf[1];
        iir_buf[1] = iir_buf[0];
        iir_buf[0] = x - a[1]*iir_buf[1] - a[2]*iir_buf[2];
        x          = b[0]*iir_buf[0] +
                     b[1]*iir_buf[1] +
                     b[2]*iir_buf[2];
					 
        // compute instantaneous frequency by looking at phase difference
        // between adjacent samples
        float freq = cargf(x*conjf(x_prime));
        x_prime = x;    // retain this sample for next iteration

		output[i] =(freq > 0)? 10 : -10;
    } 

	// show data
	for (j=0; j<adjustedLen; ++j)
		data[j] = output[j];
		
	CmdLtrim("30");
	adjustedLen -= 30;
	
	// zero crossings.
	for (j=0; j<adjustedLen; ++j){
		if ( data[j] == 10) break;
	}
	int startOne =j;
	
	for (;j<adjustedLen; ++j){
		if ( data[j] == -10 ) break;
	}
	int stopOne = j-1;
	
	int fieldlen = stopOne-startOne;
	
	fieldlen = (fieldlen == 39 || fieldlen == 41)? 40 : fieldlen;
	fieldlen = (fieldlen == 59 || fieldlen == 51)? 50 : fieldlen;
	if ( fieldlen != 40 && fieldlen != 50){
		printf("Detected field Length: %d \n", fieldlen);
		printf("Can only handle 40 or 50.  Aborting...\n");
		free(output);
		return;
	}
	
	// FSK sequence start == 000111
	int startPos = 0;
	for (i =0; i<adjustedLen; ++i){
		int dec = 0;
		for ( j = 0; j < 6*fieldlen; ++j){
			dec += data[i + j];
		}
		if (dec == 0) {
			startPos = i;
			break;
		}
	}
	
	printf("000111 position: %d \n", startPos);

	startPos += 6*fieldlen+5;
	
	int bit =0;
	printf("BINARY\n");
	printf("R/40 :  ");
	for (i =startPos ; i < adjustedLen; i += 40){
		bit = data[i]>0 ? 1:0;
		printf("%d", bit );
	}
	printf("\n");	
	
	printf("R/50 :  ");
	for (i =startPos ; i < adjustedLen; i += 50){
		bit = data[i]>0 ? 1:0;
		printf("%d", bit );	}
	printf("\n");	
	
	free(output);
}

float complex cexpf (float complex Z)
{
  float complex  Res;
  double rho = exp (__real__ Z);
  __real__ Res = rho * cosf(__imag__ Z);
  __imag__ Res = rho * sinf(__imag__ Z);
  return Res;
}
