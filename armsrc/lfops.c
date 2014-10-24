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

// split into two routines so we can avoid timing issues after sending commands //
void DoAcquisition125k_internal(int trigger_threshold,bool silent)
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
			LED_D_OFF();
			if (trigger_threshold != -1 && dest[i] < trigger_threshold)
				continue;
			else
				trigger_threshold = -1;
			if (++i >= n) break;
		}
	}
	if(!silent)
	{
		Dbprintf("buffer samples: %02x %02x %02x %02x %02x %02x %02x %02x ...",
				dest[0], dest[1], dest[2], dest[3], dest[4], dest[5], dest[6], dest[7]);
		
	}
}
void DoAcquisition125k(int trigger_threshold)
{
	DoAcquisition125k_internal(trigger_threshold, false);
}

//void SetupToAcquireRawAdcSamples(int divisor)
void LFSetupFPGAForADC(int divisor, bool lf_field)
{
	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
	if ( (divisor == 1) || (divisor < 0) || (divisor > 255) )
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
	else if (divisor == 0)
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	else
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, divisor);

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | (lf_field ? FPGA_LF_ADC_READER_FIELD : 0));

	// Connect the A/D to the peak-detected low-frequency path.
	SetAdcMuxFor(GPIO_MUXSEL_LOPKD);
	// Give it a bit of time for the resonant antenna to settle.
	SpinDelay(50);
	// Now set up the SSC to get the ADC samples that are now streaming at us.
	FpgaSetupSsc();
}

void AcquireRawAdcSamples125k(int divisor)
{
	LFSetupFPGAForADC(divisor, true);
	// Now call the acquisition routine
	DoAcquisition125k_internal(-1,false);
}
void SnoopLFRawAdcSamples(int divisor, int trigger_threshold)
{
	LFSetupFPGAForADC(divisor, false);
	DoAcquisition125k(trigger_threshold, false);
}


}

void ModThenAcquireRawAdcSamples125k(int delay_off, int period_0, int period_1, uint8_t *command)
{
	int at134khz;

	/* Make sure the tag is reset */
	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
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

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);

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

		FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
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

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);

	// now do the read
	DoAcquisition125k(-1);
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
	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
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
	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);	
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
    
	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
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

size_t fsk_demod(uint8_t * dest, size_t size)
{
	uint32_t last_transition = 0;
	uint32_t idx = 1;

	// we don't care about actual value, only if it's more or less than a
	// threshold essentially we capture zero crossings for later analysis
	uint8_t threshold_value = 127;

	// sync to first lo-hi transition, and threshold

	//Need to threshold first sample
	if(dest[0] < threshold_value) dest[0] = 0;
	else dest[0] = 1;

	size_t numBits = 0;
	// count cycles between consecutive lo-hi transitions, there should be either 8 (fc/8)
	// or 10 (fc/10) cycles but in practice due to noise etc we may end up with with anywhere
	// between 7 to 11 cycles so fuzz it by treat anything <9 as 8 and anything else as 10
	for(idx = 1; idx < size; idx++) {
		// threshold current value
		if (dest[idx] < threshold_value) dest[idx] = 0;
		else dest[idx] = 1;

		// Check for 0->1 transition
		if (dest[idx-1] < dest[idx]) { // 0 -> 1 transition

			if (idx-last_transition <  9) {
					dest[numBits]=1;
			} else {
					dest[numBits]=0;
			}
			last_transition = idx;
			numBits++;
		}
	}
	return numBits; //Actually, it returns the number of bytes, but each byte represents a bit: 1 or 0
}


size_t aggregate_bits(uint8_t *dest,size_t size, uint8_t h2l_crossing_value,uint8_t l2h_crossing_value, uint8_t maxConsequtiveBits )
{
	uint8_t lastval=dest[0];
	uint32_t idx=0;
	size_t numBits=0;
	uint32_t n=1;

	for( idx=1; idx < size; idx++) {

		if (dest[idx]==lastval) {
			n++;
			continue;
		}
		//if lastval was 1, we have a 1->0 crossing
		if ( dest[idx-1] ) {
			n=(n+1) / h2l_crossing_value;
		} else {// 0->1 crossing
			n=(n+1) / l2h_crossing_value;
		}
		if (n == 0) n = 1;

		if(n < maxConsequtiveBits)
		{
			memset(dest+numBits, dest[idx-1] , n);
			numBits += n;
		}
		n=0;
		lastval=dest[idx];
	}//end for

	return numBits;

}
// loop to capture raw HID waveform then FSK demodulate the TAG ID from it
void CmdHIDdemodFSK(int findone, int *high, int *low, int ledcontrol)
{
	uint8_t *dest = (uint8_t *)BigBuf;

	size_t size=0,idx=0; //, found=0;
	uint32_t hi2=0, hi=0, lo=0;


	while(!BUTTON_PRESS()) {

		// Configure to go in 125Khz listen mode
		LFSetupFPGAForADC(0, true)

		WDT_HIT();
		if (ledcontrol) LED_A_ON();

		DoAcquisition125k_internal(true);
		size  = sizeof(BigBuf);

		// FSK demodulator
		size = fsk_demod(dest, size);
		WDT_HIT();

		// we now have a set of cycle counts, loop over previous results and aggregate data into bit patterns
		// 1->0 : fc/8 in sets of 6
		// 0->1 : fc/10 in sets of 5
		size = aggregate_bits(dest,size, 6,5,5);

		WDT_HIT();

		// final loop, go over previously decoded manchester data and decode into usable tag ID
		// 111000 bit pattern represent start of frame, 01 pattern represents a 1 and 10 represents a 0
		uint8_t frame_marker_mask[] = {1,1,1,0,0,0};
		int numshifts = 0;
		idx = 0;
		while( idx + sizeof(frame_marker_mask) < size) {
			// search for a start of frame marker
			if ( memcmp(dest+idx, frame_marker_mask, sizeof(frame_marker_mask)) == 0)
			{ // frame marker found
				idx+=sizeof(frame_marker_mask);

				while(dest[idx] != dest[idx+1] && idx < size-2)
				{	// Keep going until next frame marker (or error)
					// Shift in a bit. Start by shifting high registers
					hi2 = (hi2<<1)|(hi>>31);
					hi = (hi<<1)|(lo>>31);
					//Then, shift in a 0 or one into low
					if (dest[idx] && !dest[idx+1])	// 1 0
						lo=(lo<<1)|0;
					else // 0 1
						lo=(lo<<1)|
								1;
					numshifts ++;
					idx += 2;
				}
				//Dbprintf("Num shifts: %d ", numshifts);
				// Hopefully, we read a tag and	 hit upon the next frame marker
				if ( memcmp(dest+idx, frame_marker_mask, sizeof(frame_marker_mask)) == 0)
				{
					if (hi2 != 0){
						Dbprintf("TAG ID: %x%08x%08x (%d)",
							 (unsigned int) hi2, (unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF);
					}
					else {
						Dbprintf("TAG ID: %x%08x (%d)",
						 (unsigned int) hi, (unsigned int) lo, (unsigned int) (lo>>1) & 0xFFFF);
					}
				}

				// reset
				hi2 = hi = lo = 0;
				numshifts = 0;
			}else
			{
				idx++;
			}
		}
		WDT_HIT();

	}
	DbpString("Stopped");
	if (ledcontrol) LED_A_OFF();
}

uint32_t bytebits_to_byte(uint8_t* src, int numbits)
{
	uint32_t num = 0;
	for(int i = 0 ; i < numbits ; i++)
	{
		num = (num << 1) | (*src);
		src++;
	}
	return num;
}


void CmdIOdemodFSK(int findone, int *high, int *low, int ledcontrol)
{
	uint8_t *dest = (uint8_t *)BigBuf;

	size_t size=0, idx=0;
	uint32_t code=0, code2=0;


	while(!BUTTON_PRESS()) {

		// Configure to go in 125Khz listen mode
		LFSetupFPGAForADC(0, true);

		WDT_HIT();
		if (ledcontrol) LED_A_ON();

		DoAcquisition125k_internal(true);
		size  = sizeof(BigBuf);

		// FSK demodulator
		size = fsk_demod(dest, size);
		WDT_HIT();

		// we now have a set of cycle counts, loop over previous results and aggregate data into bit patterns
		// 1->0 : fc/8 in sets of 7
		// 0->1 : fc/10 in sets of 6
		size = aggregate_bits(dest, size, 7,6,13);

		WDT_HIT();
		
		//Handle the data
 	    uint8_t mask[] = {0,0,0,0,0,0,0,0,0,1};
		for( idx=0; idx < size - 64; idx++) {

 	    	if ( memcmp(dest + idx, mask, sizeof(mask)) ) continue;

		    Dbprintf("%d%d%d%d%d%d%d%d",dest[idx],   dest[idx+1],   dest[idx+2],dest[idx+3],dest[idx+4],dest[idx+5],dest[idx+6],dest[idx+7]);
		    Dbprintf("%d%d%d%d%d%d%d%d",dest[idx+8], dest[idx+9], dest[idx+10],dest[idx+11],dest[idx+12],dest[idx+13],dest[idx+14],dest[idx+15]);			  
		    Dbprintf("%d%d%d%d%d%d%d%d",dest[idx+16],dest[idx+17],dest[idx+18],dest[idx+19],dest[idx+20],dest[idx+21],dest[idx+22],dest[idx+23]);
		    Dbprintf("%d%d%d%d%d%d%d%d",dest[idx+24],dest[idx+25],dest[idx+26],dest[idx+27],dest[idx+28],dest[idx+29],dest[idx+30],dest[idx+31]);
		    Dbprintf("%d%d%d%d%d%d%d%d",dest[idx+32],dest[idx+33],dest[idx+34],dest[idx+35],dest[idx+36],dest[idx+37],dest[idx+38],dest[idx+39]);
		    Dbprintf("%d%d%d%d%d%d%d%d",dest[idx+40],dest[idx+41],dest[idx+42],dest[idx+43],dest[idx+44],dest[idx+45],dest[idx+46],dest[idx+47]);
		    Dbprintf("%d%d%d%d%d%d%d%d",dest[idx+48],dest[idx+49],dest[idx+50],dest[idx+51],dest[idx+52],dest[idx+53],dest[idx+54],dest[idx+55]);
		    Dbprintf("%d%d%d%d%d%d%d%d",dest[idx+56],dest[idx+57],dest[idx+58],dest[idx+59],dest[idx+60],dest[idx+61],dest[idx+62],dest[idx+63]);
			
		    code = bytebits_to_byte(dest+idx,32);
		    code2 = bytebits_to_byte(dest+idx+32,32); 

		    short version = bytebits_to_byte(dest+idx+14,4); 
		    char unknown = bytebits_to_byte(dest+idx+19,8) ;
		    uint16_t number = bytebits_to_byte(dest+idx+36,9); 
		    
		    Dbprintf("XSF(%02d)%02x:%d (%08x%08x)",version,unknown,number,code,code2);
		    if (ledcontrol)	LED_D_OFF();
		
			// if we're only looking for one tag 
			if (findone){
				LED_A_OFF();
				return;
			}		
		}
		WDT_HIT();
	}
	DbpString("Stopped");
	if (ledcontrol) LED_A_OFF();
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
	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
	if (bit == 0)
		SpinDelayUs(WRITE_0);
	else
		SpinDelayUs(WRITE_1);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelayUs(WRITE_GAP);
}

// Write one card block in page 0, no lock
void T55xxWriteBlock(uint32_t Data, uint32_t Block, uint32_t Pwd, uint8_t PwdMode)
{
	unsigned int i;

	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);

	// Give it a bit of time for the resonant antenna to settle.
	// And for the tag to fully power up
	SpinDelay(150);

	// Now start writting
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelayUs(START_GAP);

	// Opcode
	T55xxWriteBit(1);
	T55xxWriteBit(0); //Page 0
  if (PwdMode == 1){
    // Pwd
    for (i = 0x80000000; i != 0; i >>= 1)
      T55xxWriteBit(Pwd & i);
  }
	// Lock bit
	T55xxWriteBit(0);

	// Data
	for (i = 0x80000000; i != 0; i >>= 1)
		T55xxWriteBit(Data & i);

	// Block
	for (i = 0x04; i != 0; i >>= 1)
		T55xxWriteBit(Block & i);

	// Now perform write (nominal is 5.6 ms for T55x7 and 18ms for E5550,
	// so wait a little more)
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
	SpinDelay(20);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
}

// Read one card block in page 0
void T55xxReadBlock(uint32_t Block, uint32_t Pwd, uint8_t PwdMode)
{
	uint8_t *dest = (uint8_t *)BigBuf;
	int m=0, i=0;
  
	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
	m = sizeof(BigBuf);
  // Clear destination buffer before sending the command
	memset(dest, 128, m);
	// Connect the A/D to the peak-detected low-frequency path.
	SetAdcMuxFor(GPIO_MUXSEL_LOPKD);
	// Now set up the SSC to get the ADC samples that are now streaming at us.
	FpgaSetupSsc();
  
	LED_D_ON();
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
  
	// Give it a bit of time for the resonant antenna to settle.
	// And for the tag to fully power up
	SpinDelay(150);
  
	// Now start writting
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelayUs(START_GAP);
  
	// Opcode
	T55xxWriteBit(1);
	T55xxWriteBit(0); //Page 0
	if (PwdMode == 1){
		// Pwd
		for (i = 0x80000000; i != 0; i >>= 1)
			T55xxWriteBit(Pwd & i);
	}
	// Lock bit
	T55xxWriteBit(0);
	// Block
	for (i = 0x04; i != 0; i >>= 1)
		T55xxWriteBit(Block & i);
  
  // Turn field on to read the response
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
  
	// Now do the acquisition
	i = 0;
	for(;;) {
		if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) {
			AT91C_BASE_SSC->SSC_THR = 0x43;
		}
		if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
			dest[i] = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			// we don't care about actual value, only if it's more or less than a
			// threshold essentially we capture zero crossings for later analysis
      //			if(dest[i] < 127) dest[i] = 0; else dest[i] = 1;
			i++;
			if (i >= m) break;
		}
	}
  
  FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF); // field off
	LED_D_OFF();
	DbpString("DONE!");
}

// Read card traceability data (page 1)
void T55xxReadTrace(void){
	uint8_t *dest = (uint8_t *)BigBuf;
	int m=0, i=0;
  
	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
	m = sizeof(BigBuf);
  // Clear destination buffer before sending the command
	memset(dest, 128, m);
	// Connect the A/D to the peak-detected low-frequency path.
	SetAdcMuxFor(GPIO_MUXSEL_LOPKD);
	// Now set up the SSC to get the ADC samples that are now streaming at us.
	FpgaSetupSsc();
  
	LED_D_ON();
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
  
	// Give it a bit of time for the resonant antenna to settle.
	// And for the tag to fully power up
	SpinDelay(150);
  
	// Now start writting
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelayUs(START_GAP);
  
	// Opcode
	T55xxWriteBit(1);
	T55xxWriteBit(1); //Page 1
  
  // Turn field on to read the response
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
  
	// Now do the acquisition
	i = 0;
	for(;;) {
		if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) {
			AT91C_BASE_SSC->SSC_THR = 0x43;
		}
		if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
			dest[i] = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			i++;
			if (i >= m) break;
		}
	}
  
  FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF); // field off
	LED_D_OFF();
	DbpString("DONE!");
}

/*-------------- Cloning routines -----------*/
// Copy HID id to card and setup block 0 config
void CopyHIDtoT55x7(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT)
{
	int data1=0, data2=0, data3=0, data4=0, data5=0, data6=0; //up to six blocks for long format
	int last_block = 0;
  
  if (longFMT){
	  // Ensure no more than 84 bits supplied
	  if (hi2>0xFFFFF) {
		  DbpString("Tags can only have 84 bits.");
		  return;
	  }
    // Build the 6 data blocks for supplied 84bit ID
    last_block = 6;
    data1 = 0x1D96A900; // load preamble (1D) & long format identifier (9E manchester encoded)
	  for (int i=0;i<4;i++) {
		  if (hi2 & (1<<(19-i)))
			  data1 |= (1<<(((3-i)*2)+1)); // 1 -> 10
		  else
			  data1 |= (1<<((3-i)*2)); // 0 -> 01
	  }
    
  	data2 = 0;
  	for (int i=0;i<16;i++) {
  		if (hi2 & (1<<(15-i)))
  			data2 |= (1<<(((15-i)*2)+1)); // 1 -> 10
  		else
  			data2 |= (1<<((15-i)*2)); // 0 -> 01
    }
    
  	data3 = 0;
  	for (int i=0;i<16;i++) {
  		if (hi & (1<<(31-i)))
  			data3 |= (1<<(((15-i)*2)+1)); // 1 -> 10
  		else
  			data3 |= (1<<((15-i)*2)); // 0 -> 01
  	}
    
  	data4 = 0;
  	for (int i=0;i<16;i++) {
  		if (hi & (1<<(15-i)))
  			data4 |= (1<<(((15-i)*2)+1)); // 1 -> 10
  		else
  			data4 |= (1<<((15-i)*2)); // 0 -> 01
    }
    
  	data5 = 0;
  	for (int i=0;i<16;i++) {
  		if (lo & (1<<(31-i)))
  			data5 |= (1<<(((15-i)*2)+1)); // 1 -> 10
  		else
  			data5 |= (1<<((15-i)*2)); // 0 -> 01
  	}
    
  	data6 = 0;
  	for (int i=0;i<16;i++) {
  		if (lo & (1<<(15-i)))
  			data6 |= (1<<(((15-i)*2)+1)); // 1 -> 10
  		else
  			data6 |= (1<<((15-i)*2)); // 0 -> 01
    }
  }
  else {
	  // Ensure no more than 44 bits supplied
	  if (hi>0xFFF) {
		  DbpString("Tags can only have 44 bits.");
		  return;
	  }
    
  	// Build the 3 data blocks for supplied 44bit ID
  	last_block = 3;
  	
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
  }
  
	LED_D_ON();
	// Program the data blocks for supplied ID
	// and the block 0 for HID format
	T55xxWriteBlock(data1,1,0,0);
	T55xxWriteBlock(data2,2,0,0);
	T55xxWriteBlock(data3,3,0,0);
	
	if (longFMT) { // if long format there are 6 blocks
	  T55xxWriteBlock(data4,4,0,0);
	  T55xxWriteBlock(data5,5,0,0);
	  T55xxWriteBlock(data6,6,0,0);
  }
  
	// Config for HID (RF/50, FSK2a, Maxblock=3 for short/6 for long)
	T55xxWriteBlock(T55x7_BITRATE_RF_50    |
                  T55x7_MODULATION_FSK2a |
                  last_block << T55x7_MAXBLOCK_SHIFT,
                  0,0,0);
  
	LED_D_OFF();
	
	DbpString("DONE!");
}

void CopyIOtoT55x7(uint32_t hi, uint32_t lo, uint8_t longFMT)
{
   int data1=0, data2=0; //up to six blocks for long format
  	
    data1 = hi;  // load preamble
    data2 = lo;
    
    LED_D_ON();
    // Program the data blocks for supplied ID
    // and the block 0 for HID format
    T55xxWriteBlock(data1,1,0,0);
    T55xxWriteBlock(data2,2,0,0);
	
    //Config Block
    T55xxWriteBlock(0x00147040,0,0,0);
    LED_D_OFF();
	
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
	uint32_t clock = 0;

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
	T55xxWriteBlock((uint32_t)(id >> 32), 1, 0, 0);
	T55xxWriteBlock((uint32_t)id, 2, 0, 0);

	// Config for EM410x (RF/64, Manchester, Maxblock=2)
	if (card) {
		// Clock rate is stored in bits 8-15 of the card value
		clock = (card & 0xFF00) >> 8;
		Dbprintf("Clock rate: %d", clock);
		switch (clock)
		{
			case 32:
				clock = T55x7_BITRATE_RF_32;
				break;
			case 16:
				clock = T55x7_BITRATE_RF_16;
				break;
			case 0:
				// A value of 0 is assumed to be 64 for backwards-compatibility
				// Fall through...
			case 64:
				clock = T55x7_BITRATE_RF_64;
				break;      
			default:
				Dbprintf("Invalid clock rate: %d", clock);
				return;
		}

		// Writing configuration for T55x7 tag
		T55xxWriteBlock(clock	    |
				T55x7_MODULATION_MANCHESTER |
				2 << T55x7_MAXBLOCK_SHIFT,
				0, 0, 0);
  }
	else
		// Writing configuration for T5555(Q5) tag
		T55xxWriteBlock(0x1F << T5555_BITRATE_SHIFT |
				T5555_MODULATION_MANCHESTER   |
				2 << T5555_MAXBLOCK_SHIFT,
				0, 0, 0);

	LED_D_OFF();
	Dbprintf("Tag %s written with 0x%08x%08x\n", card ? "T55x7":"T5555",
					(uint32_t)(id >> 32), (uint32_t)id);
}

// Clone Indala 64-bit tag by UID to T55x7
void CopyIndala64toT55x7(int hi, int lo)
{

	//Program the 2 data blocks for supplied 64bit UID
	// and the block 0 for Indala64 format
	T55xxWriteBlock(hi,1,0,0);
	T55xxWriteBlock(lo,2,0,0);
	//Config for Indala (RF/32;PSK1 with RF/2;Maxblock=2)
	T55xxWriteBlock(T55x7_BITRATE_RF_32    |
			T55x7_MODULATION_PSK1 |
			2 << T55x7_MAXBLOCK_SHIFT,
			0, 0, 0);
	//Alternative config for Indala (Extended mode;RF/32;PSK1 with RF/2;Maxblock=2;Inverse data)
//	T5567WriteBlock(0x603E1042,0);

	DbpString("DONE!");

}	

void CopyIndala224toT55x7(int uid1, int uid2, int uid3, int uid4, int uid5, int uid6, int uid7)
{

	//Program the 7 data blocks for supplied 224bit UID
	// and the block 0 for Indala224 format
	T55xxWriteBlock(uid1,1,0,0);
	T55xxWriteBlock(uid2,2,0,0);
	T55xxWriteBlock(uid3,3,0,0);
	T55xxWriteBlock(uid4,4,0,0);
	T55xxWriteBlock(uid5,5,0,0);
	T55xxWriteBlock(uid6,6,0,0);
	T55xxWriteBlock(uid7,7,0,0);
	//Config for Indala (RF/32;PSK1 with RF/2;Maxblock=7)
	T55xxWriteBlock(T55x7_BITRATE_RF_32    |
			T55x7_MODULATION_PSK1 |
			7 << T55x7_MAXBLOCK_SHIFT,
			0,0,0);
	//Alternative config for Indala (Extended mode;RF/32;PSK1 with RF/2;Maxblock=7;Inverse data)
//	T5567WriteBlock(0x603E10E2,0);

	DbpString("DONE!");

}


#define abs(x) ( ((x)<0) ? -(x) : (x) )
#define max(x,y) ( x<y ? y:x)

int DemodPCF7931(uint8_t **outBlocks) {
	uint8_t BitStream[256];
	uint8_t Blocks[8][16];
	uint8_t *GraphBuffer = (uint8_t *)BigBuf;
	int GraphTraceLen = sizeof(BigBuf);
	int i, j, lastval, bitidx, half_switch;
	int clock = 64;
	int tolerance = clock / 8;
	int pmc, block_done;
	int lc, warnings = 0;
	int num_blocks = 0;
	int lmin=128, lmax=128;
	uint8_t dir;
	
	AcquireRawAdcSamples125k(0);
	
	lmin = 64;
	lmax = 192;
	
	i = 2;
	
	/* Find first local max/min */
	if(GraphBuffer[1] > GraphBuffer[0]) {
    while(i < GraphTraceLen) {
      if( !(GraphBuffer[i] > GraphBuffer[i-1]) && GraphBuffer[i] > lmax)
        break;
      i++;
    }
    dir = 0;
	}
	else {
    while(i < GraphTraceLen) {
      if( !(GraphBuffer[i] < GraphBuffer[i-1]) && GraphBuffer[i] < lmin)
        break;
      i++;
    }
    dir = 1;
	}
	
	lastval = i++;
	half_switch = 0;
	pmc = 0;
	block_done = 0;
	
	for (bitidx = 0; i < GraphTraceLen; i++)
	{
    if ( (GraphBuffer[i-1] > GraphBuffer[i] && dir == 1 && GraphBuffer[i] > lmax) || (GraphBuffer[i-1] < GraphBuffer[i] && dir == 0 && GraphBuffer[i] < lmin))
    {
      lc = i - lastval;
      lastval = i;
      
      // Switch depending on lc length:
      // Tolerance is 1/8 of clock rate (arbitrary)
      if (abs(lc-clock/4) < tolerance) {
        // 16T0
        if((i - pmc) == lc) { /* 16T0 was previous one */
          /* It's a PMC ! */
          i += (128+127+16+32+33+16)-1;
          lastval = i;
          pmc = 0;
          block_done = 1;
        }
        else {
          pmc = i;
        }
      } else if (abs(lc-clock/2) < tolerance) {
        // 32TO
        if((i - pmc) == lc) { /* 16T0 was previous one */
          /* It's a PMC ! */
          i += (128+127+16+32+33)-1;
          lastval = i;
          pmc = 0;
          block_done = 1;
        }
        else if(half_switch == 1) {
          BitStream[bitidx++] = 0;
          half_switch = 0;
        }
        else
          half_switch++;
      } else if (abs(lc-clock) < tolerance) {
        // 64TO
        BitStream[bitidx++] = 1;
      } else {
        // Error
        warnings++;
        if (warnings > 10)
        {
          Dbprintf("Error: too many detection errors, aborting.");
          return 0;
        }
      }
      
      if(block_done == 1) {
        if(bitidx == 128) {
          for(j=0; j<16; j++) {
            Blocks[num_blocks][j] = 128*BitStream[j*8+7]+
            64*BitStream[j*8+6]+
            32*BitStream[j*8+5]+
            16*BitStream[j*8+4]+
            8*BitStream[j*8+3]+
            4*BitStream[j*8+2]+
            2*BitStream[j*8+1]+
            BitStream[j*8];
          }
          num_blocks++;
        }
        bitidx = 0;
        block_done = 0;
        half_switch = 0;
      }
      if (GraphBuffer[i-1] > GraphBuffer[i]) dir=0;
      else dir = 1;
    }
    if(bitidx==255)
      bitidx=0;
    warnings = 0;
    if(num_blocks == 4) break;
	}
	memcpy(outBlocks, Blocks, 16*num_blocks);
	return num_blocks;
}

int IsBlock0PCF7931(uint8_t *Block) {
	// Assume RFU means 0 :)
	if((memcmp(Block, "\x00\x00\x00\x00\x00\x00\x00\x01", 8) == 0) && memcmp(Block+9, "\x00\x00\x00\x00\x00\x00\x00", 7) == 0) // PAC enabled
    return 1;
	if((memcmp(Block+9, "\x00\x00\x00\x00\x00\x00\x00", 7) == 0) && Block[7] == 0) // PAC disabled, can it *really* happen ?
    return 1;
	return 0;
}

int IsBlock1PCF7931(uint8_t *Block) {
	// Assume RFU means 0 :)
	if(Block[10] == 0 && Block[11] == 0 && Block[12] == 0 && Block[13] == 0)
    if((Block[14] & 0x7f) <= 9 && Block[15] <= 9)
      return 1;
	
	return 0;
}

#define ALLOC 16

void ReadPCF7931() {
	uint8_t Blocks[8][17];
	uint8_t tmpBlocks[4][16];
	int i, j, ind, ind2, n;
	int num_blocks = 0;
	int max_blocks = 8;
	int ident = 0;
	int error = 0;
	int tries = 0;
	
	memset(Blocks, 0, 8*17*sizeof(uint8_t));
	
	do {
    memset(tmpBlocks, 0, 4*16*sizeof(uint8_t));
    n = DemodPCF7931((uint8_t**)tmpBlocks);
    if(!n)
      error++;
    if(error==10 && num_blocks == 0) {
      Dbprintf("Error, no tag or bad tag");
      return;
    }
    else if (tries==20 || error==10) {
      Dbprintf("Error reading the tag");
      Dbprintf("Here is the partial content");
      goto end;
    }
    
    for(i=0; i<n; i++)
      Dbprintf("(dbg) %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
               tmpBlocks[i][0], tmpBlocks[i][1], tmpBlocks[i][2], tmpBlocks[i][3], tmpBlocks[i][4], tmpBlocks[i][5], tmpBlocks[i][6], tmpBlocks[i][7],
               tmpBlocks[i][8], tmpBlocks[i][9], tmpBlocks[i][10], tmpBlocks[i][11], tmpBlocks[i][12], tmpBlocks[i][13], tmpBlocks[i][14], tmpBlocks[i][15]);
    if(!ident) {
      for(i=0; i<n; i++) {
        if(IsBlock0PCF7931(tmpBlocks[i])) {
          // Found block 0 ?
          if(i < n-1 && IsBlock1PCF7931(tmpBlocks[i+1])) {
            // Found block 1!
            // \o/
            ident = 1;
            memcpy(Blocks[0], tmpBlocks[i], 16);
            Blocks[0][ALLOC] = 1;
            memcpy(Blocks[1], tmpBlocks[i+1], 16);
            Blocks[1][ALLOC] = 1;
            max_blocks = max((Blocks[1][14] & 0x7f), Blocks[1][15]) + 1;
            // Debug print
            Dbprintf("(dbg) Max blocks: %d", max_blocks);
            num_blocks = 2;
            // Handle following blocks
            for(j=i+2, ind2=2; j!=i; j++, ind2++, num_blocks++) {
              if(j==n) j=0;
              if(j==i) break;
              memcpy(Blocks[ind2], tmpBlocks[j], 16);
              Blocks[ind2][ALLOC] = 1;
            }
            break;
          }
        }
      }
    }
    else {
      for(i=0; i<n; i++) { // Look for identical block in known blocks
        if(memcmp(tmpBlocks[i], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16)) { // Block is not full of 00
          for(j=0; j<max_blocks; j++) {
            if(Blocks[j][ALLOC] == 1 && !memcmp(tmpBlocks[i], Blocks[j], 16)) {
              // Found an identical block
              for(ind=i-1,ind2=j-1; ind >= 0; ind--,ind2--) {
                if(ind2 < 0)
                  ind2 = max_blocks;
                if(!Blocks[ind2][ALLOC]) { // Block ind2 not already found
                  // Dbprintf("Tmp %d -> Block %d", ind, ind2);
                  memcpy(Blocks[ind2], tmpBlocks[ind], 16);
                  Blocks[ind2][ALLOC] = 1;
                  num_blocks++;
                  if(num_blocks == max_blocks) goto end;
                }
              }
              for(ind=i+1,ind2=j+1; ind < n; ind++,ind2++) {
                if(ind2 > max_blocks)
                  ind2 = 0;
                if(!Blocks[ind2][ALLOC]) { // Block ind2 not already found
                  // Dbprintf("Tmp %d -> Block %d", ind, ind2);
                  memcpy(Blocks[ind2], tmpBlocks[ind], 16);
                  Blocks[ind2][ALLOC] = 1;
                  num_blocks++;
                  if(num_blocks == max_blocks) goto end;
                }
              }
            }
          }
        }
      }
    }
    tries++;
    if (BUTTON_PRESS()) return;
	} while (num_blocks != max_blocks);
end:
	Dbprintf("-----------------------------------------");
	Dbprintf("Memory content:");
	Dbprintf("-----------------------------------------");
	for(i=0; i<max_blocks; i++) {
    if(Blocks[i][ALLOC]==1)
      Dbprintf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
               Blocks[i][0], Blocks[i][1], Blocks[i][2], Blocks[i][3], Blocks[i][4], Blocks[i][5], Blocks[i][6], Blocks[i][7],
               Blocks[i][8], Blocks[i][9], Blocks[i][10], Blocks[i][11], Blocks[i][12], Blocks[i][13], Blocks[i][14], Blocks[i][15]);
    else
      Dbprintf("<missing block %d>", i);
	}
	Dbprintf("-----------------------------------------");
	
	return ;
}


//-----------------------------------
// EM4469 / EM4305 routines
//-----------------------------------
#define FWD_CMD_LOGIN 0xC //including the even parity, binary mirrored
#define FWD_CMD_WRITE 0xA
#define FWD_CMD_READ 0x9
#define FWD_CMD_DISABLE 0x5


uint8_t forwardLink_data[64]; //array of forwarded bits
uint8_t * forward_ptr; //ptr for forward message preparation
uint8_t fwd_bit_sz; //forwardlink bit counter
uint8_t * fwd_write_ptr; //forwardlink bit pointer

//====================================================================
// prepares command bits
// see EM4469 spec
//====================================================================
//--------------------------------------------------------------------
uint8_t Prepare_Cmd( uint8_t cmd ) {
  //--------------------------------------------------------------------
  
  *forward_ptr++ = 0; //start bit
  *forward_ptr++ = 0; //second pause for 4050 code
  
  *forward_ptr++ = cmd;
  cmd >>= 1;
  *forward_ptr++ = cmd;
  cmd >>= 1;
  *forward_ptr++ = cmd;
  cmd >>= 1;
  *forward_ptr++ = cmd;
  
  return 6; //return number of emited bits
}

//====================================================================
// prepares address bits
// see EM4469 spec
//====================================================================

//--------------------------------------------------------------------
uint8_t Prepare_Addr( uint8_t addr ) {
  //--------------------------------------------------------------------
  
  register uint8_t line_parity;
  
  uint8_t i;
  line_parity = 0;
  for(i=0;i<6;i++) {
    *forward_ptr++ = addr;
    line_parity ^= addr;
    addr >>= 1;
  }
  
  *forward_ptr++ = (line_parity & 1);
  
  return 7; //return number of emited bits
}

//====================================================================
// prepares data bits intreleaved with parity bits
// see EM4469 spec
//====================================================================

//--------------------------------------------------------------------
uint8_t Prepare_Data( uint16_t data_low, uint16_t data_hi) {
  //--------------------------------------------------------------------
  
  register uint8_t line_parity;
  register uint8_t column_parity;
  register uint8_t i, j;
  register uint16_t data;
  
  data = data_low;
  column_parity = 0;
  
  for(i=0; i<4; i++) {
    line_parity = 0;
    for(j=0; j<8; j++) {
      line_parity ^= data;
      column_parity ^= (data & 1) << j;
      *forward_ptr++ = data;
      data >>= 1;
    }
    *forward_ptr++ = line_parity;
    if(i == 1)
      data = data_hi;
  }
  
  for(j=0; j<8; j++) {
    *forward_ptr++ = column_parity;
    column_parity >>= 1;
  }
  *forward_ptr = 0;
  
  return 45; //return number of emited bits
}

//====================================================================
// Forward Link send function
// Requires: forwarLink_data filled with valid bits (1 bit per byte)
// fwd_bit_count set with number of bits to be sent
//====================================================================
void SendForward(uint8_t fwd_bit_count) {
  
  fwd_write_ptr = forwardLink_data;
  fwd_bit_sz = fwd_bit_count;
  
  LED_D_ON();
  
  //Field on
  FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
  FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
  FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
  
  // Give it a bit of time for the resonant antenna to settle.
  // And for the tag to fully power up
  SpinDelay(150);
  
  // force 1st mod pulse (start gap must be longer for 4305)
  fwd_bit_sz--; //prepare next bit modulation
  fwd_write_ptr++;
  FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF); // field off
  SpinDelayUs(55*8); //55 cycles off (8us each)for 4305
  FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
  FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);//field on
  SpinDelayUs(16*8); //16 cycles on (8us each)
  
  // now start writting
  while(fwd_bit_sz-- > 0) { //prepare next bit modulation
    if(((*fwd_write_ptr++) & 1) == 1)
      SpinDelayUs(32*8); //32 cycles at 125Khz (8us each)
    else {
      //These timings work for 4469/4269/4305 (with the 55*8 above)
      FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF); // field off
      SpinDelayUs(23*8); //16-4 cycles off (8us each)
      FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
      FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);//field on
      SpinDelayUs(9*8); //16 cycles on (8us each)
    }
  }
}

void EM4xLogin(uint32_t Password) {
  
  uint8_t fwd_bit_count;
  
  forward_ptr = forwardLink_data;
  fwd_bit_count = Prepare_Cmd( FWD_CMD_LOGIN );
  fwd_bit_count += Prepare_Data( Password&0xFFFF, Password>>16 );
  
  SendForward(fwd_bit_count);
  
  //Wait for command to complete
  SpinDelay(20);
  
}

void EM4xReadWord(uint8_t Address, uint32_t Pwd, uint8_t PwdMode) {
  
  uint8_t fwd_bit_count;
  uint8_t *dest = (uint8_t *)BigBuf;
  int m=0, i=0;
  
  //If password mode do login
  if (PwdMode == 1) EM4xLogin(Pwd);
  
  forward_ptr = forwardLink_data;
  fwd_bit_count = Prepare_Cmd( FWD_CMD_READ );
  fwd_bit_count += Prepare_Addr( Address );
  
  m = sizeof(BigBuf);
  // Clear destination buffer before sending the command
  memset(dest, 128, m);
  // Connect the A/D to the peak-detected low-frequency path.
  SetAdcMuxFor(GPIO_MUXSEL_LOPKD);
  // Now set up the SSC to get the ADC samples that are now streaming at us.
  FpgaSetupSsc();
  
  SendForward(fwd_bit_count);
  
  // Now do the acquisition
  i = 0;
  for(;;) {
    if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) {
      AT91C_BASE_SSC->SSC_THR = 0x43;
    }
    if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
      dest[i] = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
      i++;
      if (i >= m) break;
    }
  }
  FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF); // field off
  LED_D_OFF();
}

void EM4xWriteWord(uint32_t Data, uint8_t Address, uint32_t Pwd, uint8_t PwdMode) {
  
  uint8_t fwd_bit_count;
  
  //If password mode do login
  if (PwdMode == 1) EM4xLogin(Pwd);
  
  forward_ptr = forwardLink_data;
  fwd_bit_count = Prepare_Cmd( FWD_CMD_WRITE );
  fwd_bit_count += Prepare_Addr( Address );
  fwd_bit_count += Prepare_Data( Data&0xFFFF, Data>>16 );
  
  SendForward(fwd_bit_count);
  
  //Wait for write to complete
  SpinDelay(20);
  FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF); // field off
  LED_D_OFF();
}
