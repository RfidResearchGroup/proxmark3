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
//#include <liquid/liquid.h>
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

void SetLogFilename(char *fn)
{
  logfilename = fn;
}

int manchester_decode( int * data, const size_t len, uint8_t * dataout,  size_t dataoutlen){
	
	int bitlength = 0;
	int clock, high, low, startindex;
	low = startindex = 0;
	high = 1;
	uint8_t * bitStream =  (uint8_t* ) malloc(sizeof(uint8_t) * dataoutlen);	
	memset(bitStream, 0x00, dataoutlen);	
	
	/* Detect high and lows */
	DetectHighLowInGraph(&high, &low, TRUE); 

	/* get clock */
	clock = GetAskClock("",false, false);

	startindex = DetectFirstTransition(data, len, high);
  
	if (high != 1)
		// decode "raw"
		bitlength = ManchesterConvertFrom255(data, len, bitStream, dataoutlen, high, low, clock, startindex);
	else
		// decode manchester
		bitlength = ManchesterConvertFrom1(data, len, bitStream, dataoutlen, clock, startindex);

	memcpy(dataout, bitStream, bitlength);
	free(bitStream);
	return bitlength;
}
 
 int DetectFirstTransition(const int * data, const size_t len, int threshold){

	int i = 0;
	/* now look for the first threshold */
	for (; i < len; ++i) {
		if (data[i] == threshold) {
			break;
		}
	}
	return i;
 }

 int ManchesterConvertFrom255(const int * data, const size_t len, uint8_t * dataout, int dataoutlen, int high, int low, int clock, int startIndex){

	int i, j, z, hithigh, hitlow, bitIndex, startType;
	i = 0;
	bitIndex = 0;
	
	int isDamp = 0;
	int damplimit = (int)((high / 2) * 0.3);
	int dampHi =  (high/2)+damplimit;
	int dampLow = (high/2)-damplimit;
	int firstST = 0;

	// i = clock frame of data
	for (; i < (int)(len/clock); i++)
	{
		hithigh = 0;
		hitlow = 0;
		startType = -1;
		z = startIndex + (i*clock);
		isDamp = 0;
			
		/* Find out if we hit both high and low peaks */
		for (j = 0; j < clock; j++)
		{		
			if (data[z+j] == high){
				hithigh = 1;
				if ( startType == -1)
					startType = 1;
			}
			
			if (data[z+j] == low ){
				hitlow = 1;
				if ( startType == -1)
					startType = 0;
			} 
		
			if (hithigh && hitlow)
			  break;
		}
		
		// No high value found, are we in a dampening field?
		if ( !hithigh ) {
			//PrintAndLog(" # Entering damp test at index : %d (%d)", z+j, j);
			for (j = 0; j < clock; j++) {
				if ( 
				     (data[z+j] <= dampHi && data[z+j] >= dampLow)
				   ){
				   isDamp++;
				}
			}
		}

		/*  Manchester Switching..
			0: High -> Low   
			1: Low -> High  
		*/
		if (startType == 0)
			dataout[bitIndex++] = 1;
		else if (startType == 1) 
			dataout[bitIndex++] = 0;
		else
			dataout[bitIndex++] = 2;
			
		if ( isDamp > clock/2 ) {
			firstST++;
		}
		
		if ( firstST == 4)
			break;
		if ( bitIndex >= dataoutlen-1 )
			break;
	}
	return bitIndex;
 }
 
 int ManchesterConvertFrom1(const int * data, const size_t len, uint8_t * dataout,int dataoutlen, int clock, int startIndex){

	int i,j, bitindex, lc, tolerance, warnings;
	warnings = 0;
	int upperlimit = len*2/clock+8;
	i = startIndex;
	j = 0;
	tolerance = clock/4;
	uint8_t decodedArr[len];
	
	/* Detect duration between 2 successive transitions */
	for (bitindex = 1; i < len; i++) {
	
		if (data[i-1] != data[i]) {
			lc = i - startIndex;
			startIndex = i;

			// Error check: if bitindex becomes too large, we do not
			// have a Manchester encoded bitstream or the clock is really wrong!
			if (bitindex > upperlimit ) {
				PrintAndLog("Error: the clock you gave is probably wrong, aborting.");
				return 0;
			}
			// Then switch depending on lc length:
			// Tolerance is 1/4 of clock rate (arbitrary)
			if (abs((lc-clock)/2) < tolerance) {
				// Short pulse : either "1" or "0"
				decodedArr[bitindex++] = data[i-1];
			} else if (abs(lc-clock) < tolerance) {
				// Long pulse: either "11" or "00"
				decodedArr[bitindex++] = data[i-1];
				decodedArr[bitindex++] = data[i-1];
			} else {
				++warnings;
				PrintAndLog("Warning: Manchester decode error for pulse width detection.");
				if (warnings > 10) {
					PrintAndLog("Error: too many detection errors, aborting.");
					return 0; 
				}
			}
		}
	}
	
	/* 
	* We have a decodedArr of "01" ("1") or "10" ("0")
	* parse it into final decoded dataout
    */ 
    for (i = 0; i < bitindex; i += 2) {

	    if ((decodedArr[i] == 0) && (decodedArr[i+1] == 1)) {
			dataout[j++] = 1;
		} else if ((decodedArr[i] == 1) && (decodedArr[i+1] == 0)) {
			dataout[j++] = 0;
		} else {
			i++;
			warnings++;
			PrintAndLog("Unsynchronized, resync...");
			PrintAndLog("(too many of those messages mean the stream is not Manchester encoded)");

			if (warnings > 10) {	
				PrintAndLog("Error: too many decode errors, aborting.");
				return 0;
			}
		}
    }
	
	PrintAndLog("%s", sprint_hex(dataout, j));
	return j;
 }
 
 void ManchesterDiffDecodedString(const uint8_t* bitstream, size_t len, uint8_t invert){
	/* 
	* We have a bitstream of "01" ("1") or "10" ("0")
	* parse it into final decoded bitstream
    */ 
	int i, j, warnings; 
	uint8_t decodedArr[(len/2)+1];

	j = warnings = 0;
	
	uint8_t lastbit = 0;
	
    for (i = 0; i < len; i += 2) {
	
		uint8_t first = bitstream[i];
		uint8_t second = bitstream[i+1];

		if ( first == second ) {
			++i;
			++warnings;
			if (warnings > 10) {
				PrintAndLog("Error: too many decode errors, aborting.");
				return;
			}
		} 
		else if ( lastbit != first ) {
			decodedArr[j++] = 0 ^ invert;
		}
		else {
			decodedArr[j++] = 1 ^ invert;
		}
		lastbit = second;
    }
	
	PrintAndLog("%s", sprint_hex(decodedArr, j));
}
 
void PrintPaddedManchester( uint8_t* bitStream, size_t len, size_t blocksize){

	PrintAndLog(" Manchester decoded  : %d bits", len);
	  
	uint8_t mod = len % blocksize;
	uint8_t div = len / blocksize;
	int i;
  
	// Now output the bitstream to the scrollback by line of 16 bits
	for (i = 0; i < div*blocksize; i+=blocksize) {
		PrintAndLog(" %s", sprint_bin(bitStream+i,blocksize) );
	}
	
	if ( mod > 0 )
		PrintAndLog(" %s", sprint_bin(bitStream+i, mod) );	
}

/* Sliding DFT
   Smooths out 
*/ 
void iceFsk2(int * data, const size_t len){

	int i, j;
	int * output =  (int* ) malloc(sizeof(int) * len);	
	memset(output, 0x00, len);

	// for (i=0; i<len-5; ++i){
		// for ( j=1; j <=5; ++j) {
			// output[i] += data[i*j];
		// }
		// output[i] /= 5;
	// }
	int rest = 127;
	int tmp =0;
	for (i=0; i<len; ++i){
		if ( data[i] < 127)
			output[i] = 0;
		else {
			tmp =  (100 * (data[i]-rest)) / rest;
			output[i] = (tmp > 60)? 100:0;
		}
	}
	
	for (j=0; j<len; ++j)
		data[j] = output[j];
		
	free(output);
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
