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

#include "ui.h"
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
 
void iceIIR_Butterworth(int *data, const size_t len){

	int i,j;
	
	int * output =  (int* ) malloc(sizeof(int) * len);	
	if ( !output ) return;
	
	// clear mem
	memset(output, 0x00, len);
	
	size_t adjustedLen = len;
	float fc = 0.1125f;          // center frequency
		
    // create very simple low-pass filter to remove images (2nd-order Butterworth)
    float complex iir_buf[3] = {0,0,0};
    float b[3] = {0.003621681514929,  0.007243363029857, 0.003621681514929};
    float a[3] = {1.000000000000000, -1.822694925196308, 0.837181651256023};
    
    float sample           = 0;      // input sample read from array
    float complex x_prime  = 1.0f;   // save sample for estimating frequency
    float complex x;
		
	for (i = 0; i < adjustedLen; ++i) {

		sample = data[i];
		
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

		output[i] =(freq > 0) ? 127 : -127;
    } 

	// show data
	//memcpy(data, output, adjustedLen);
	for (j=0; j<adjustedLen; ++j)
		data[j] = output[j];
	
	free(output);
}

void iceSimple_Filter(int *data, const size_t len, uint8_t k){
// ref: http://www.edn.com/design/systems-design/4320010/A-simple-software-lowpass-filter-suits-embedded-system-applications
// parameter K
#define FILTER_SHIFT 4 

	int32_t filter_reg = 0;
	int16_t input, output;
	int8_t shift = (k <=8 ) ? k : FILTER_SHIFT;

	for (int i = 0; i < len; ++i){

		input = data[i];
		// Update filter with current sample
		filter_reg = filter_reg - (filter_reg >> shift) + input;

		// Scale output for unity gain
		output = filter_reg >> shift;
		data[i] = output;
	}
}

float complex cexpf (float complex Z)
{
  float complex  Res;
  double rho = exp (__real__ Z);
  __real__ Res = rho * cosf(__imag__ Z);
  __imag__ Res = rho * sinf(__imag__ Z);
  return Res;
}
