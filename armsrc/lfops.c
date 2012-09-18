//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Miscellaneous routines for low frequency tag operations.
// Tags supported here so far are Texas Instruments (TI), HID
// Also routines for raw mode reading/simulating of LF waveform
//-----------------------------------------------------------------------------

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "hitag2.h"
#include "crc16.h"
#include "string.h"

void AcquireRawAdcSamples125k(int at134khz)
{
	if (at134khz)
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
	else
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);

	// Connect the A/D to the peak-detected low-frequency path.
	SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

	// Give it a bit of time for the resonant antenna to settle.
	SpinDelay(50);

	// Now set up the SSC to get the ADC samples that are now streaming at us.
	FpgaSetupSsc();

	// Now call the acquisition routine
	DoAcquisition125k();
}

// split into two routines so we can avoid timing issues after sending commands //
void DoAcquisition125k(void)
{
	uint8_t *dest = (uint8_t *)BigBuf;
	int n = sizeof(BigBuf);
	int i;

	memset(dest, 0, n);
	i = 0;
	for(;;) {
		if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) {
			AT91C_BASE_SSC->SSC_THR = 0x43;
			LED_D_ON();
		}
		if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
			dest[i] = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			i++;
			LED_D_OFF();
			if (i >= n) break;
		}
	}
	Dbprintf("buffer samples: %02x %02x %02x %02x %02x %02x %02x %02x ...",
			dest[0], dest[1], dest[2], dest[3], dest[4], dest[5], dest[6], dest[7]);
}

void ModThenAcquireRawAdcSamples125k(int delay_off, int period_0, int period_1, uint8_t *command)
{
	int at134khz;

	/* Make sure the tag is reset */
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelay(2500);

	// see if 'h' was specified
	if (command[strlen((char *) command) - 1] == 'h')
		at134khz = TRUE;
	else
		at134khz = FALSE;

	if (at134khz)
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
	else
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);

	// Give it a bit of time for the resonant antenna to settle.
	SpinDelay(50);
	// And a little more time for the tag to fully power up
	SpinDelay(2000);

	// Now set up the SSC to get the ADC samples that are now streaming at us.
	FpgaSetupSsc();

	// now modulate the reader field
	while(*command != '\0' && *command != ' ') {
		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
		LED_D_OFF();
		SpinDelayUs(delay_off);
		if (at134khz)
			FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
		else
			FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz

		FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
		LED_D_ON();
		if(*(command++) == '0')
			SpinDelayUs(period_0);
		else
			SpinDelayUs(period_1);
	}
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LED_D_OFF();
	SpinDelayUs(delay_off);
	if (at134khz)
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
	else
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);

	// now do the read
	DoAcquisition125k();
}

/* blank r/w tag data stream
...0000000000000000 01111111
1010101010101010101010101010101010101010101010101010101010101010
0011010010100001
01111111
101010101010101[0]000...

[5555fe852c5555555555555555fe0000]
*/
void ReadTItag(void)
{
	// some hardcoded initial params
	// when we read a TI tag we sample the zerocross line at 2Mhz
	// TI tags modulate a 1 as 16 cycles of 123.2Khz
	// TI tags modulate a 0 as 16 cycles of 134.2Khz
	#define FSAMPLE 2000000
	#define FREQLO 123200
	#define FREQHI 134200

	signed char *dest = (signed char *)BigBuf;
	int n = sizeof(BigBuf);
//	int *dest = GraphBuffer;
//	int n = GraphTraceLen;

	// 128 bit shift register [shift3:shift2:shift1:shift0]
	uint32_t shift3 = 0, shift2 = 0, shift1 = 0, shift0 = 0;

	int i, cycles=0, samples=0;
	// how many sample points fit in 16 cycles of each frequency
	uint32_t sampleslo = (FSAMPLE<<4)/FREQLO, sampleshi = (FSAMPLE<<4)/FREQHI;
	// when to tell if we're close enough to one freq or another
	uint32_t threshold = (sampleslo - sampleshi + 1)>>1;

	// TI tags charge at 134.2Khz
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz

	// Place FPGA in passthrough mode, in this mode the CROSS_LO line
	// connects to SSP_DIN and the SSP_DOUT logic level controls
	// whether we're modulating the antenna (high)
	// or listening to the antenna (low)
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_PASSTHRU);

	// get TI tag data into the buffer
	AcquireTiType();

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

	for (i=0; i<n-1; i++) {
		// count cycles by looking for lo to hi zero crossings
		if ( (dest[i]<0) && (dest[i+1]>0) ) {
			cycles++;
			// after 16 cycles, measure the frequency
			if (cycles>15) {
				cycles=0;
				samples=i-samples; // number of samples in these 16 cycles

				// TI bits are coming to us lsb first so shift them
				// right through our 128 bit right shift register
			  shift0 = (shift0>>1) | (shift1 << 31);
			  shift1 = (shift1>>1) | (shift2 << 31);
			  shift2 = (shift2>>1) | (shift3 << 31);
			  shift3 >>= 1;

				// check if the cycles fall close to the number
				// expected for either the low or high frequency
				if ( (samples>(sampleslo-threshold)) && (samples<(sampleslo+threshold)) ) {
					// low frequency represents a 1
					shift3 |= (1<<31);
				} else if ( (samples>(sampleshi-threshold)) && (samples<(sampleshi+threshold)) ) {
					// high frequency represents a 0
				} else {
					// probably detected a gay waveform or noise
					// use this as gaydar or discard shift register and start again
					shift3 = shift2 = shift1 = shift0 = 0;
				}
				samples = i;

				// for each bit we receive, test if we've detected a valid tag

				// if we see 17 zeroes followed by 6 ones, we might have a tag
				// remember the bits are backwards
				if ( ((shift0 & 0x7fffff) == 0x7e0000) ) {
					// if start and end bytes match, we have a tag so break out of the loop
					if ( ((shift0>>16)&0xff) == ((shift3>>8)&0xff) ) {
						cycles = 0xF0B; //use this as a flag (ugly but whatever)
						break;
					}
				}
			}
		}
	}

	// if flag is set we have a tag
	if (cycles!=0xF0B) {
		DbpString("Info: No valid tag detected.");
	} else {
	  // put 64 bit data into shift1 and shift0
	  shift0 = (shift0>>24) | (shift1 << 8);
	  shift1 = (shift1>>24) | (shift2 << 8);

		// align 16 bit crc into lower half of shift2
	  shift2 = ((shift2>>24) | (shift3 << 8)) & 0x0ffff;

		// if r/w tag, check ident match
		if ( shift3&(1<<15) ) {
			DbpString("Info: TI tag is rewriteable");
			// only 15 bits compare, last bit of ident is not valid
			if ( ((shift3>>16)^shift0)&0x7fff ) {
				DbpString("Error: Ident mismatch!");
			} else {
				DbpString("Info: TI tag ident is valid");
			}
		} else {
			DbpString("Info: TI tag is readonly");
		}

		// WARNING the order of the bytes in which we calc crc below needs checking
		// i'm 99% sure the crc algorithm is correct, but it may need to eat the
		// bytes in reverse or something
		// calculate CRC
		uint32_t crc=0;

	 	crc = update_crc16(crc, (shift0)&0xff);
		crc = update_crc16(crc, (shift0>>8)&0xff);
		crc = update_crc16(crc, (shift0>>16)&0xff);
		crc = update_crc16(crc, (shift0>>24)&0xff);
		crc = update_crc16(crc, (shift1)&0xff);
		crc = update_crc16(crc, (shift1>>8)&0xff);
		crc = update_crc16(crc, (shift1>>16)&0xff);
		crc = update_crc16(crc, (shift1>>24)&0xff);

		Dbprintf("Info: Tag data: %x%08x, crc=%x",
			(unsigned int)shift1, (unsigned int)shift0, (unsigned int)shift2 & 0xFFFF);
		if (crc != (shift2&0xffff)) {
			Dbprintf("Error: CRC mismatch, expected %x", (unsigned int)crc);
		} else {
			DbpString("Info: CRC is good");
		}
	}
}

void WriteTIbyte(uint8_t b)
{
	int i = 0;

	// modulate 8 bits out to the antenna
	for (i=0; i<8; i++)
	{
		if (b&(1<<i)) {
			// stop modulating antenna
			LOW(GPIO_SSC_DOUT);
			SpinDelayUs(1000);
			// modulate antenna
			HIGH(GPIO_SSC_DOUT);
			SpinDelayUs(1000);
		} else {
			// stop modulating antenna
			LOW(GPIO_SSC_DOUT);
			SpinDelayUs(300);
			// modulate antenna
			HIGH(GPIO_SSC_DOUT);
			SpinDelayUs(1700);
		}
	}
}

void AcquireTiType(void)
{
	int i, j, n;
	// tag transmission is <20ms, sampling at 2M gives us 40K samples max
	// each sample is 1 bit stuffed into a uint32_t so we need 1250 uint32_t
	#define TIBUFLEN 1250

	// clear buffer
	memset(BigBuf,0,sizeof(BigBuf));

	// Set up the synchronous serial port
	AT91C_BASE_PIOA->PIO_PDR = GPIO_SSC_DIN;
	AT91C_BASE_PIOA->PIO_ASR = GPIO_SSC_DIN;

	// steal this pin from the SSP and use it to control the modulation
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;

	AT91C_BASE_SSC->SSC_CR = AT91C_SSC_SWRST;
	AT91C_BASE_SSC->SSC_CR = AT91C_SSC_RXEN | AT91C_SSC_TXEN;

	// Sample at 2 Mbit/s, so TI tags are 16.2 vs. 14.9 clocks long
	// 48/2 = 24 MHz clock must be divided by 12
	AT91C_BASE_SSC->SSC_CMR = 12;

	AT91C_BASE_SSC->SSC_RCMR = SSC_CLOCK_MODE_SELECT(0);
	AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(32) | AT91C_SSC_MSBF;
	AT91C_BASE_SSC->SSC_TCMR = 0;
	AT91C_BASE_SSC->SSC_TFMR = 0;

	LED_D_ON();

	// modulate antenna
	HIGH(GPIO_SSC_DOUT);

	// Charge TI tag for 50ms.
	SpinDelay(50);

	// stop modulating antenna and listen
	LOW(GPIO_SSC_DOUT);

	LED_D_OFF();

	i = 0;
	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
			BigBuf[i] = AT91C_BASE_SSC->SSC_RHR;	// store 32 bit values in buffer
			i++; if(i >= TIBUFLEN) break;
		}
		WDT_HIT();
	}

	// return stolen pin to SSP
	AT91C_BASE_PIOA->PIO_PDR = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_ASR = GPIO_SSC_DIN | GPIO_SSC_DOUT;

	char *dest = (char *)BigBuf;
	n = TIBUFLEN*32;
	// unpack buffer
	for (i=TIBUFLEN-1; i>=0; i--) {
		for (j=0; j<32; j++) {
			if(BigBuf[i] & (1 << j)) {
				dest[--n] = 1;
			} else {
				dest[--n] = -1;
			}
		}
	}
}

// arguments: 64bit data split into 32bit idhi:idlo and optional 16bit crc
// if crc provided, it will be written with the data verbatim (even if bogus)
// if not provided a valid crc will be computed from the data and written.
void WriteTItag(uint32_t idhi, uint32_t idlo, uint16_t crc)
{
	if(crc == 0) {
	 	crc = update_crc16(crc, (idlo)&0xff);
		crc = update_crc16(crc, (idlo>>8)&0xff);
		crc = update_crc16(crc, (idlo>>16)&0xff);
		crc = update_crc16(crc, (idlo>>24)&0xff);
		crc = update_crc16(crc, (idhi)&0xff);
		crc = update_crc16(crc, (idhi>>8)&0xff);
		crc = update_crc16(crc, (idhi>>16)&0xff);
		crc = update_crc16(crc, (idhi>>24)&0xff);
	}
	Dbprintf("Writing to tag: %x%08x, crc=%x",
		(unsigned int) idhi, (unsigned int) idlo, crc);

	// TI tags charge at 134.2Khz
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
	// Place FPGA in passthrough mode, in this mode the CROSS_LO line
	// connects to SSP_DIN and the SSP_DOUT logic level controls
	// whether we're modulating the antenna (high)
	// or listening to the antenna (low)
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_PASSTHRU);
	LED_A_ON();

	// steal this pin from the SSP and use it to control the modulation
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;

	// writing algorithm:
	// a high bit consists of a field off for 1ms and field on for 1ms
	// a low bit consists of a field off for 0.3ms and field on for 1.7ms
	// initiate a charge time of 50ms (field on) then immediately start writing bits
	// start by writing 0xBB (keyword) and 0xEB (password)
	// then write 80 bits of data (or 64 bit data + 16 bit crc if you prefer)
	// finally end with 0x0300 (write frame)
	// all data is sent lsb firts
	// finish with 15ms programming time

	// modulate antenna
	HIGH(GPIO_SSC_DOUT);
	SpinDelay(50);	// charge time

	WriteTIbyte(0xbb); // keyword
	WriteTIbyte(0xeb); // password
	WriteTIbyte( (idlo    )&0xff );
	WriteTIbyte( (idlo>>8 )&0xff );
	WriteTIbyte( (idlo>>16)&0xff );
	WriteTIbyte( (idlo>>24)&0xff );
	WriteTIbyte( (idhi    )&0xff );
	WriteTIbyte( (idhi>>8 )&0xff );
	WriteTIbyte( (idhi>>16)&0xff );
	WriteTIbyte( (idhi>>24)&0xff ); // data hi to lo
	WriteTIbyte( (crc     )&0xff ); // crc lo
	WriteTIbyte( (crc>>8  )&0xff ); // crc hi
	WriteTIbyte(0x00); // write frame lo
	WriteTIbyte(0x03); // write frame hi
	HIGH(GPIO_SSC_DOUT);
	SpinDelay(50);	// programming time

	LED_A_OFF();

	// get TI tag data into the buffer
	AcquireTiType();

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	DbpString("Now use tiread to check");
}

void SimulateTagLowFrequency(int period, int gap, int ledcontrol)
{
	int i;
	uint8_t *tab = (uint8_t *)BigBuf;
    
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT);
    
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT | GPIO_SSC_CLK;
    
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_CLK;
    
#define SHORT_COIL()	LOW(GPIO_SSC_DOUT)
#define OPEN_COIL()		HIGH(GPIO_SSC_DOUT)
    
	i = 0;
	for(;;) {
		while(!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK)) {
			if(BUTTON_PRESS()) {
				DbpString("Stopped");
				return;
			}
			WDT_HIT();
		}
        
		if (ledcontrol)
			LED_D_ON();
        
		if(tab[i])
			OPEN_COIL();
		else
			SHORT_COIL();
        
		if (ledcontrol)
			LED_D_OFF();
        
		while(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK) {
			if(BUTTON_PRESS()) {
				DbpString("Stopped");
				return;
			}
			WDT_HIT();
		}
        
		i++;
		if(i == period) {
			i = 0;
			if (gap) {
				SHORT_COIL();
				SpinDelayUs(gap);
			}
		}
	}
}

#define DEBUG_FRAME_CONTENTS 1
void SimulateTagLowFrequencyBidir(int divisor, int t0)
{
}

// compose fc/8 fc/10 waveform
static void fc(int c, int *n) {
	uint8_t *dest = (uint8_t *)BigBuf;
	int idx;

	// for when we want an fc8 pattern every 4 logical bits
	if(c==0) {
		dest[((*n)++)]=1;
		dest[((*n)++)]=1;
		dest[((*n)++)]=0;
		dest[((*n)++)]=0;
		dest[((*n)++)]=0;
		dest[((*n)++)]=0;
		dest[((*n)++)]=0;
		dest[((*n)++)]=0;
	}
	//	an fc/8  encoded bit is a bit pattern of  11000000  x6 = 48 samples
	if(c==8) {
		for (idx=0; idx<6; idx++) {
			dest[((*n)++)]=1;
			dest[((*n)++)]=1;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
		}
	}

	//	an fc/10 encoded bit is a bit pattern of 1110000000 x5 = 50 samples
	if(c==10) {
		for (idx=0; idx<5; idx++) {
			dest[((*n)++)]=1;
			dest[((*n)++)]=1;
			dest[((*n)++)]=1;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
			dest[((*n)++)]=0;
		}
	}
}

// prepare a waveform pattern in the buffer based on the ID given then
// simulate a HID tag until the button is pressed
void CmdHIDsimTAG(int hi, int lo, int ledcontrol)
{
	int n=0, i=0;
	/*
	 HID tag bitstream format
	 The tag contains a 44bit unique code. This is sent out MSB first in sets of 4 bits
	 A 1 bit is represented as 6 fc8 and 5 fc10 patterns
	 A 0 bit is represented as 5 fc10 and 6 fc8 patterns
	 A fc8 is inserted before every 4 bits
	 A special start of frame pattern is used consisting a0b0 where a and b are neither 0
	 nor 1 bits, they are special patterns (a = set of 12 fc8 and b = set of 10 fc10)
	*/

	if (hi>0xFFF) {
		DbpString("Tags can only have 44 bits.");
		return;
	}
	fc(0,&n);
	// special start of frame marker containing invalid bit sequences
	fc(8,  &n);	fc(8,  &n);	// invalid
	fc(8,  &n);	fc(10, &n); // logical 0
	fc(10, &n);	fc(10, &n); // invalid
	fc(8,  &n);	fc(10, &n); // logical 0

	WDT_HIT();
	// manchester encode bits 43 to 32
	for (i=11; i>=0; i--) {
		if ((i%4)==3) fc(0,&n);
		if ((hi>>i)&1) {
			fc(10, &n);	fc(8,  &n);		// low-high transition
		} else {
			fc(8,  &n);	fc(10, &n);		// high-low transition
		}
	}

	WDT_HIT();
	// manchester encode bits 31 to 0
	for (i=31; i>=0; i--) {
		if ((i%4)==3) fc(0,&n);
		if ((lo>>i)&1) {
			fc(10, &n);	fc(8,  &n);		// low-high transition
		} else {
			fc(8,  &n);	fc(10, &n);		// high-low transition
		}
	}

	if (ledcontrol)
		LED_A_ON();
	SimulateTagLowFrequency(n, 0, ledcontrol);

	if (ledcontrol)
		LED_A_OFF();
}


// loop to capture raw HID waveform then FSK demodulate the TAG ID from it
void CmdHIDdemodFSK(int findone, int *high, int *low, int ledcontrol)
{
	uint8_t *dest = (uint8_t *)BigBuf;
	int m=0, n=0, i=0, idx=0, found=0, lastval=0;
	uint32_t hi=0, lo=0;

	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);

	// Connect the A/D to the peak-detected low-frequency path.
	SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

	// Give it a bit of time for the resonant antenna to settle.
	SpinDelay(50);

	// Now set up the SSC to get the ADC samples that are now streaming at us.
	FpgaSetupSsc();

	for(;;) {
		WDT_HIT();
		if (ledcontrol)
			LED_A_ON();
		if(BUTTON_PRESS()) {
			DbpString("Stopped");
			if (ledcontrol)
				LED_A_OFF();
			return;
		}

		i = 0;
		m = sizeof(BigBuf);
		memset(dest,128,m);
		for(;;) {
			if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
				AT91C_BASE_SSC->SSC_THR = 0x43;
				if (ledcontrol)
					LED_D_ON();
			}
			if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
				dest[i] = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
				// we don't care about actual value, only if it's more or less than a
				// threshold essentially we capture zero crossings for later analysis
				if(dest[i] < 127) dest[i] = 0; else dest[i] = 1;
				i++;
				if (ledcontrol)
					LED_D_OFF();
				if(i >= m) {
					break;
				}
			}
		}

		// FSK demodulator

		// sync to first lo-hi transition
		for( idx=1; idx<m; idx++) {
			if (dest[idx-1]<dest[idx])
				lastval=idx;
				break;
		}
		WDT_HIT();

		// count cycles between consecutive lo-hi transitions, there should be either 8 (fc/8)
		// or 10 (fc/10) cycles but in practice due to noise etc we may end up with with anywhere
		// between 7 to 11 cycles so fuzz it by treat anything <9 as 8 and anything else as 10
		for( i=0; idx<m; idx++) {
			if (dest[idx-1]<dest[idx]) {
				dest[i]=idx-lastval;
				if (dest[i] <= 8) {
						dest[i]=1;
				} else {
						dest[i]=0;
				}

				lastval=idx;
				i++;
			}
		}
		m=i;
		WDT_HIT();

		// we now have a set of cycle counts, loop over previous results and aggregate data into bit patterns
		lastval=dest[0];
		idx=0;
		i=0;
		n=0;
		for( idx=0; idx<m; idx++) {
			if (dest[idx]==lastval) {
				n++;
			} else {
				// a bit time is five fc/10 or six fc/8 cycles so figure out how many bits a pattern width represents,
				// an extra fc/8 pattern preceeds every 4 bits (about 200 cycles) just to complicate things but it gets
				// swallowed up by rounding
				// expected results are 1 or 2 bits, any more and it's an invalid manchester encoding
				// special start of frame markers use invalid manchester states (no transitions) by using sequences
				// like 111000
				if (dest[idx-1]) {
					n=(n+1)/6;			// fc/8 in sets of 6
				} else {
					n=(n+1)/5;			// fc/10 in sets of 5
				}
				switch (n) {			// stuff appropriate bits in buffer
					case 0:
					case 1:	// one bit
						dest[i++]=dest[idx-1];
						break;
					case 2: // two bits
						dest[i++]=dest[idx-1];
						dest[i++]=dest[idx-1];
						break;
					case 3: // 3 bit start of frame markers
						dest[i++]=dest[idx-1];
						dest[i++]=dest[idx-1];
						dest[i++]=dest[idx-1];
						break;
					// When a logic 0 is immediately followed by the start of the next transmisson
					// (special pattern) a pattern of 4 bit duration lengths is created.
					case 4:
						dest[i++]=dest[idx-1];
						dest[i++]=dest[idx-1];
						dest[i++]=dest[idx-1];
						dest[i++]=dest[idx-1];
						break;
					default:	// this shouldn't happen, don't stuff any bits
						break;
				}
				n=0;
				lastval=dest[idx];
			}
		}
		m=i;
		WDT_HIT();

		// final loop, go over previously decoded manchester data and decode into usable tag ID
		// 111000 bit pattern represent start of frame, 01 pattern represents a 1 and 10 represents a 0
		for( idx=0; idx<m-6; idx++) {
			// search for a start of frame marker
			if ( dest[idx] && dest[idx+1] && dest[idx+2] && (!dest[idx+3]) && (!dest[idx+4]) && (!dest[idx+5]) )
			{
				found=1;
				idx+=6;
				if (found && (hi|lo)) {
					Dbprintf("TAG ID: %x%08x (%d)",
						(unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF);
					/* if we're only looking for one tag */
					if (findone)
					{
						*high = hi;
						*low = lo;
						return;
					}
					hi=0;
					lo=0;
					found=0;
				}
			}
			if (found) {
				if (dest[idx] && (!dest[idx+1]) ) {
					hi=(hi<<1)|(lo>>31);
					lo=(lo<<1)|0;
				} else if ( (!dest[idx]) && dest[idx+1]) {
					hi=(hi<<1)|(lo>>31);
					lo=(lo<<1)|1;
				} else {
					found=0;
					hi=0;
					lo=0;
				}
				idx++;
			}
			if ( dest[idx] && dest[idx+1] && dest[idx+2] && (!dest[idx+3]) && (!dest[idx+4]) && (!dest[idx+5]) )
			{
				found=1;
				idx+=6;
				if (found && (hi|lo)) {
					Dbprintf("TAG ID: %x%08x (%d)",
						(unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF);
					/* if we're only looking for one tag */
					if (findone)
					{
						*high = hi;
						*low = lo;
						return;
					}
					hi=0;
					lo=0;
					found=0;
				}
			}
		}
		WDT_HIT();
	}
}

/*------------------------------
 * T5555/T5557/T5567 routines
 *------------------------------
 */

/* T55x7 configuration register definitions */
#define T55x7_POR_DELAY			0x00000001
#define T55x7_ST_TERMINATOR		0x00000008
#define T55x7_PWD			0x00000010
#define T55x7_MAXBLOCK_SHIFT		5
#define T55x7_AOR			0x00000200
#define T55x7_PSKCF_RF_2		0
#define T55x7_PSKCF_RF_4		0x00000400
#define T55x7_PSKCF_RF_8		0x00000800
#define T55x7_MODULATION_DIRECT		0
#define T55x7_MODULATION_PSK1		0x00001000
#define T55x7_MODULATION_PSK2		0x00002000
#define T55x7_MODULATION_PSK3		0x00003000
#define T55x7_MODULATION_FSK1		0x00004000
#define T55x7_MODULATION_FSK2		0x00005000
#define T55x7_MODULATION_FSK1a		0x00006000
#define T55x7_MODULATION_FSK2a		0x00007000
#define T55x7_MODULATION_MANCHESTER	0x00008000
#define T55x7_MODULATION_BIPHASE	0x00010000
#define T55x7_BITRATE_RF_8		0
#define T55x7_BITRATE_RF_16		0x00040000
#define T55x7_BITRATE_RF_32		0x00080000
#define T55x7_BITRATE_RF_40		0x000C0000
#define T55x7_BITRATE_RF_50		0x00100000
#define T55x7_BITRATE_RF_64		0x00140000
#define T55x7_BITRATE_RF_100		0x00180000
#define T55x7_BITRATE_RF_128		0x001C0000

/* T5555 (Q5) configuration register definitions */
#define T5555_ST_TERMINATOR		0x00000001
#define T5555_MAXBLOCK_SHIFT		0x00000001
#define T5555_MODULATION_MANCHESTER	0
#define T5555_MODULATION_PSK1		0x00000010
#define T5555_MODULATION_PSK2		0x00000020
#define T5555_MODULATION_PSK3		0x00000030
#define T5555_MODULATION_FSK1		0x00000040
#define T5555_MODULATION_FSK2		0x00000050
#define T5555_MODULATION_BIPHASE	0x00000060
#define T5555_MODULATION_DIRECT		0x00000070
#define T5555_INVERT_OUTPUT		0x00000080
#define T5555_PSK_RF_2			0
#define T5555_PSK_RF_4			0x00000100
#define T5555_PSK_RF_8			0x00000200
#define T5555_USE_PWD			0x00000400
#define T5555_USE_AOR			0x00000800
#define T5555_BITRATE_SHIFT		12
#define T5555_FAST_WRITE		0x00004000
#define T5555_PAGE_SELECT		0x00008000

/*
 * Relevant times in microsecond
 * To compensate antenna falling times shorten the write times
 * and enlarge the gap ones.
 */
#define START_GAP 250
#define WRITE_GAP 160
#define WRITE_0   144 // 192
#define WRITE_1   400 // 432 for T55x7; 448 for E5550

// Write one bit to card
void T55xxWriteBit(int bit)
{
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
	if (bit == 0)
		SpinDelayUs(WRITE_0);
	else
		SpinDelayUs(WRITE_1);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelayUs(WRITE_GAP);
}

// Write one card block in page 0, no lock
void T55xxWriteBlock(int Data, int Block)
{
	unsigned int i;

	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);

	// Give it a bit of time for the resonant antenna to settle.
	// And for the tag to fully power up
	SpinDelay(150);

	// Now start writting
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelayUs(START_GAP);

	// Opcode
	T55xxWriteBit(1);
	T55xxWriteBit(0); //Page 0
	// Lock bit
	T55xxWriteBit(0);

	// Data
	for (i = 0x80000000; i != 0; i >>= 1)
		T55xxWriteBit(Data & i);

	// Page
	for (i = 0x04; i != 0; i >>= 1)
		T55xxWriteBit(Block & i);

	// Now perform write (nominal is 5.6 ms for T55x7 and 18ms for E5550,
	// so wait a little more)
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
	SpinDelay(20);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
}

// Copy HID id to card and setup block 0 config
void CopyHIDtoT55x7(int hi, int lo)
{
	int data1, data2, data3;

	// Ensure no more than 44 bits supplied
	if (hi>0xFFF) {
		DbpString("Tags can only have 44 bits.");
		return;
	}

	// Build the 3 data blocks for supplied 44bit ID
	data1 = 0x1D000000; // load preamble

	for (int i=0;i<12;i++) {
		if (hi & (1<<(11-i)))
			data1 |= (1<<(((11-i)*2)+1)); // 1 -> 10
		else
			data1 |= (1<<((11-i)*2)); // 0 -> 01
	}

	data2 = 0;
	for (int i=0;i<16;i++) {
		if (lo & (1<<(31-i)))
			data2 |= (1<<(((15-i)*2)+1)); // 1 -> 10
		else
			data2 |= (1<<((15-i)*2)); // 0 -> 01
	}

	data3 = 0;
	for (int i=0;i<16;i++) {
		if (lo & (1<<(15-i)))
			data3 |= (1<<(((15-i)*2)+1)); // 1 -> 10
		else
			data3 |= (1<<((15-i)*2)); // 0 -> 01
	}

	// Program the 3 data blocks for supplied 44bit ID
	// and the block 0 for HID format
	T55xxWriteBlock(data1,1);
	T55xxWriteBlock(data2,2);
	T55xxWriteBlock(data3,3);

	// Config for HID (RF/50, FSK2a, Maxblock=3)
	T55xxWriteBlock(T55x7_BITRATE_RF_50    |
			T55x7_MODULATION_FSK2a |
			3 << T55x7_MAXBLOCK_SHIFT,
			0);

	DbpString("DONE!");
}

// Define 9bit header for EM410x tags
#define EM410X_HEADER		0x1FF
#define EM410X_ID_LENGTH	40

void WriteEM410x(uint32_t card, uint32_t id_hi, uint32_t id_lo)
{
	int i, id_bit;
	uint64_t id = EM410X_HEADER;
	uint64_t rev_id = 0;	// reversed ID
	int c_parity[4];	// column parity
	int r_parity = 0;	// row parity

	// Reverse ID bits given as parameter (for simpler operations)
	for (i = 0; i < EM410X_ID_LENGTH; ++i) {
		if (i < 32) {
			rev_id = (rev_id << 1) | (id_lo & 1);
			id_lo >>= 1;
		} else {
			rev_id = (rev_id << 1) | (id_hi & 1);
			id_hi >>= 1;
		}
	}

	for (i = 0; i < EM410X_ID_LENGTH; ++i) {
		id_bit = rev_id & 1;

		if (i % 4 == 0) {
			// Don't write row parity bit at start of parsing
			if (i)
				id = (id << 1) | r_parity;
			// Start counting parity for new row
			r_parity = id_bit;
		} else {
			// Count row parity
			r_parity ^= id_bit;
		}

		// First elements in column?
		if (i < 4)
			// Fill out first elements
			c_parity[i] = id_bit;
		else
			// Count column parity
			c_parity[i % 4] ^= id_bit;

		// Insert ID bit
		id = (id << 1) | id_bit;
		rev_id >>= 1;
	}

	// Insert parity bit of last row
	id = (id << 1) | r_parity;

	// Fill out column parity at the end of tag
	for (i = 0; i < 4; ++i)
		id = (id << 1) | c_parity[i];

	// Add stop bit
	id <<= 1;

	Dbprintf("Started writing %s tag ...", card ? "T55x7":"T5555");
	LED_D_ON();

	// Write EM410x ID
	T55xxWriteBlock((uint32_t)(id >> 32), 1);
	T55xxWriteBlock((uint32_t)id, 2);

	// Config for EM410x (RF/64, Manchester, Maxblock=2)
	if (card)
		// Writing configuration for T55x7 tag
		T55xxWriteBlock(T55x7_BITRATE_RF_64	    |
				T55x7_MODULATION_MANCHESTER |
				2 << T55x7_MAXBLOCK_SHIFT,
				0);
	else
		// Writing configuration for T5555(Q5) tag
		T55xxWriteBlock(0x1F << T5555_BITRATE_SHIFT |
				T5555_MODULATION_MANCHESTER   |
				2 << T5555_MAXBLOCK_SHIFT,
				0);

	LED_D_OFF();
	Dbprintf("Tag %s written with 0x%08x%08x\n", card ? "T55x7":"T5555",
					(uint32_t)(id >> 32), (uint32_t)id);
}

// Clone Indala 64-bit tag by UID to T55x7
void CopyIndala64toT55x7(int hi, int lo)
{

	//Program the 2 data blocks for supplied 64bit UID
	// and the block 0 for Indala64 format
	T55xxWriteBlock(hi,1);
	T55xxWriteBlock(lo,2);
	//Config for Indala (RF/32;PSK1 with RF/2;Maxblock=2)
	T55xxWriteBlock(T55x7_BITRATE_RF_32    |
			T55x7_MODULATION_PSK1 |
			2 << T55x7_MAXBLOCK_SHIFT,
			0);
	//Alternative config for Indala (Extended mode;RF/32;PSK1 with RF/2;Maxblock=2;Inverse data)
//	T5567WriteBlock(0x603E1042,0);

	DbpString("DONE!");

}	

void CopyIndala224toT55x7(int uid1, int uid2, int uid3, int uid4, int uid5, int uid6, int uid7)
{

	//Program the 7 data blocks for supplied 224bit UID
	// and the block 0 for Indala224 format
	T55xxWriteBlock(uid1,1);
	T55xxWriteBlock(uid2,2);
	T55xxWriteBlock(uid3,3);
	T55xxWriteBlock(uid4,4);
	T55xxWriteBlock(uid5,5);
	T55xxWriteBlock(uid6,6);
	T55xxWriteBlock(uid7,7);
	//Config for Indala (RF/32;PSK1 with RF/2;Maxblock=7)
	T55xxWriteBlock(T55x7_BITRATE_RF_32    |
			T55x7_MODULATION_PSK1 |
			7 << T55x7_MAXBLOCK_SHIFT,
			0);
	//Alternative config for Indala (Extended mode;RF/32;PSK1 with RF/2;Maxblock=7;Inverse data)
//	T5567WriteBlock(0x603E10E2,0);

	DbpString("DONE!");

}
