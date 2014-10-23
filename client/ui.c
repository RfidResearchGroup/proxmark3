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

//#include <liquid/liquid.h>
#define M_PI 3.14159265358979323846264338327

double CursorScaleFactor;
int PlotGridX, PlotGridY, PlotGridXdefault= 64, PlotGridYdefault= 64;
int offline;
int flushAfterWrite = 0;  //buzzy
extern pthread_mutex_t print_lock;

static char *logfilename = "proxmark3.log";

void PrintAndLog(char *fmt, ...)
{
	char *saved_line;
	int saved_point;
	va_list argptr, argptr2;
	static FILE *logfile = NULL;
	static int logging=1;

	// lock this section to avoid interlacing prints from different threats
	pthread_mutex_lock(&print_lock);
  
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

	if (flushAfterWrite == 1)  //buzzy
	{
		fflush(NULL);
	}
	//release lock
	pthread_mutex_unlock(&print_lock);  
}

void SetLogFilename(char *fn)
{
  logfilename = fn;
}

int manchester_decode( int * data, const size_t len, uint8_t * dataout){
	
	int bitlength = 0;
	int i, clock, high, low, startindex;
	low = startindex = 0;
	high = 1;
	uint8_t bitStream[len];
	
	memset(bitStream, 0x00, len);
	
	/* Detect high and lows */
	for (i = 0; i < len; i++) {
		if (data[i] > high)
			high = data[i];
		else if (data[i] < low)
			low = data[i];
	}
	
	/* get clock */
	clock = GetT55x7Clock( data, len, high );	
	startindex = DetectFirstTransition(data, len, high);
  
	PrintAndLog(" Clock       : %d", clock);
	PrintAndLog(" startindex  : %d", startindex);
	
	if (high != 1)
		bitlength = ManchesterConvertFrom255(data, len, bitStream, high, low, clock, startindex);
	else
		bitlength= ManchesterConvertFrom1(data, len, bitStream, clock, startindex);

	memcpy(dataout, bitStream, bitlength);
	return bitlength;
}

 int GetT55x7Clock( const int * data, const size_t len, int peak ){ 
 
 	int i,lastpeak,clock;
	clock = 0xFFFF;
	lastpeak = 0;
	
	/* Detect peak if we don't have one */
	if (!peak) {
		for (i = 0; i < len; ++i) {
			if (data[i] > peak) {
				peak = data[i];
			}
		}
	}
	
	for (i = 1; i < len; ++i) {
		/* if this is the beginning of a peak */
		if ( data[i-1] != data[i] &&  data[i] == peak) {
		  /* find lowest difference between peaks */
			if (lastpeak && i - lastpeak < clock)
				clock = i - lastpeak;
			lastpeak = i;
		}
	}
	//return clock;  
 	//defaults clock to precise values.
	switch(clock){
		case 8:
		case 16:
		case 32:
		case 40:
		case 50:
		case 64:
		case 100:
		case 128:
		return clock;
		break;
		default:  break;
	}
	
	//PrintAndLog(" Found Clock : %d  - trying to adjust", clock);
	
	// When detected clock is 31 or 33 then then return 
	int clockmod = clock%8;
	if ( clockmod == 7 ) 
		clock += 1;
	else if ( clockmod == 1 )
		clock -= 1;
	
	return clock;
 }
 
 int DetectFirstTransition(const int * data, const size_t len, int threshold){

	int i =0;
	/* now look for the first threshold */
	for (; i < len; ++i) {
		if (data[i] == threshold) {
			break;
		}
	}
	return i;
 }

 int ManchesterConvertFrom255(const int * data, const size_t len, uint8_t * dataout, int high, int low, int clock, int startIndex){

	int i, j, z, hithigh, hitlow, bitIndex, startType;
	i = 0;
	bitIndex = 0;
	
	int isDamp = 0;
	int damplimit = (int)((high / 2) * 0.3);
	int dampHi =  (high/2)+damplimit;
	int dampLow = (high/2)-damplimit;
	int firstST = 0;

	// i = clock frame of data
	for (; i < (int)(len / clock); i++)
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
			for (j = 0; j < clock; j++)
			{
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
	}
	return bitIndex;
 }
 
 int ManchesterConvertFrom1(const int * data, const size_t len, uint8_t * dataout, int clock, int startIndex){

	PrintAndLog(" Path B");
 
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

void iceFsk(int * data, const size_t len){

	//34359738  == 125khz   (2^32 / 125) =
	
    // parameters
    float phase_offset      = 0.00f;   // carrier phase offset
    float frequency_offset  = 0.30f;   // carrier frequency offset
    float wn                = 0.01f;   // pll bandwidth
    float zeta              = 0.707f;  // pll damping factor
    float K                 = 1000;    // pll loop gain
    size_t n                = len;     // number of samples

    // generate loop filter parameters (active PI design)
    float t1 = K/(wn*wn);   // tau_1
    float t2 = 2*zeta/wn;   // tau_2

    // feed-forward coefficients (numerator)
    float b0 = (4*K/t1)*(1.+t2/2.0f);
    float b1 = (8*K/t1);
    float b2 = (4*K/t1)*(1.-t2/2.0f);

    // feed-back coefficients (denominator)
    //    a0 =  1.0  is implied
    float a1 = -2.0f;
    float a2 =  1.0f;

    // filter buffer
    float v0=0.0f, v1=0.0f, v2=0.0f;
    
    // initialize states
    float phi     = phase_offset;  // input signal's initial phase
    float phi_hat = 0.0f;      // PLL's initial phase
    
    unsigned int i;
    float complex x,y;
	float complex output[n];
	
	for (i=0; i<n; i++) {
		// INPUT SIGNAL
		x = data[i];
		phi += frequency_offset;
		
		// generate complex sinusoid
		y = cosf(phi_hat) + _Complex_I*sinf(phi_hat);

		output[i] = y;

		// compute error estimate
		float delta_phi = cargf( x * conjf(y) );

		
        // print results to standard output
        printf("  %6u %12.8f %12.8f %12.8f %12.8f %12.8f\n",
                  i,
                  crealf(x), cimagf(x),
                  crealf(y), cimagf(y),
                  delta_phi);
	
		// push result through loop filter, updating phase estimate

		// advance buffer
		v2 = v1;  // shift center register to upper register
		v1 = v0;  // shift lower register to center register

		// compute new lower register
		v0 = delta_phi - v1*a1 - v2*a2;

		// compute new output
		phi_hat = v0*b0 + v1*b1 + v2*b2;

	}

	for (i=0; i<len; ++i){
		data[i] = (int)crealf(output[i]);
	}
}

/* Sliding DFT
   Smooths out 
*/ 
void iceFsk2(int * data, const size_t len){

	int i, j;
	int output[len];
	
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
}

void iceFsk3(int * data, const size_t len){

	int i,j;
	int output[len];
    float fc            = 0.1125f;          // center frequency

    // create very simple low-pass filter to remove images (2nd-order Butterworth)
    float complex iir_buf[3] = {0,0,0};
    float b[3] = {0.003621681514929,  0.007243363029857, 0.003621681514929};
    float a[3] = {1.000000000000000, -1.822694925196308, 0.837181651256023};
    
    // process entire input file one sample at a time
    float         sample      = 0;      // input sample read from file
    float complex x_prime     = 1.0f;   // save sample for estimating frequency
    float complex x;
		
	for (i=0; i<len; ++i) {

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

		output[i] =(freq > 0)? 10 : -10;
    } 

	// show data
	for (j=0; j<len; ++j)
		data[j] = output[j];
		
	CmdLtrim("30");
	
	// zero crossings.
	for (j=0; j<len; ++j){
		if ( data[j] == 10) break;
	}
	int startOne =j;
	
	for (;j<len; ++j){
		if ( data[j] == -10 ) break;
	}
	int stopOne = j-1;
	
	int fieldlen = stopOne-startOne;
	
	fieldlen = (fieldlen == 39 || fieldlen == 41)? 40 : fieldlen;
	fieldlen = (fieldlen == 59 || fieldlen == 51)? 50 : fieldlen;
	if ( fieldlen != 40 && fieldlen != 50){
		printf("Detected field Length: %d \n", fieldlen);
		printf("Can only handle len 40 or 50.  Aborting...");
		return;
	}
	
	// FSK sequence start == 000111
	int startPos = 0;
	for (i =0; i<len; ++i){
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
	for (i =startPos ; i < len; i += 40){
		bit = data[i]>0 ? 1:0;
		printf("%d", bit );
	}
	printf("\n");	
	
	printf("R/50 :  ");
	for (i =startPos ; i < len; i += 50){
		bit = data[i]>0 ? 1:0;
		printf("%d", bit );	}
	printf("\n");	
	
}

float complex cexpf (float complex Z)
{
  float complex  Res;
  double rho = exp (__real__ Z);
  __real__ Res = rho * cosf(__imag__ Z);
  __imag__ Res = rho * sinf(__imag__ Z);
  return Res;
}
