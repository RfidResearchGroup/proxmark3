//-----------------------------------------------------------------------------
// Miscellaneous routines for low frequency tag operations.
// Tags supported here so far are Texas Instruments (TI), HID
// Also routines for raw mode reading/simulating of LF waveform
//
//-----------------------------------------------------------------------------
#include <proxmark3.h>
#include "apps.h"
#include "hitag2.h"
#include "../common/crc16.c"

void AcquireRawAdcSamples125k(BOOL at134khz)
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
	BYTE *dest = (BYTE *)BigBuf;
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
			dest[i] = (BYTE)AT91C_BASE_SSC->SSC_RHR;
			i++;
			LED_D_OFF();
			if (i >= n) break;
		}
	}
	Dbprintf("buffer samples: %02x %02x %02x %02x %02x %02x %02x %02x ...",
			dest[0], dest[1], dest[2], dest[3], dest[4], dest[5], dest[6], dest[7]);
}

void ModThenAcquireRawAdcSamples125k(int delay_off, int period_0, int period_1, BYTE *command)
{
	BOOL at134khz;

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
	DWORD shift3 = 0, shift2 = 0, shift1 = 0, shift0 = 0;

	int i, cycles=0, samples=0;
	// how many sample points fit in 16 cycles of each frequency
	DWORD sampleslo = (FSAMPLE<<4)/FREQLO, sampleshi = (FSAMPLE<<4)/FREQHI;
	// when to tell if we're close enough to one freq or another
	DWORD threshold = (sampleslo - sampleshi + 1)>>1;

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
		DWORD crc=0;

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

void WriteTIbyte(BYTE b)
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
	// each sample is 1 bit stuffed into a DWORD so we need 1250 DWORDS
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
void WriteTItag(DWORD idhi, DWORD idlo, WORD crc)
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

void SimulateTagLowFrequency(int period, int ledcontrol)
{
	int i;
	BYTE *tab = (BYTE *)BigBuf;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_SIMULATOR);

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
		if(i == period) i = 0;
	}
}

/* Provides a framework for bidirectional LF tag communication
 * Encoding is currently Hitag2, but the general idea can probably
 * be transferred to other encodings.
 * 
 * The new FPGA code will, for the LF simulator mode, give on SSC_FRAME
 * (PA15) a thresholded version of the signal from the ADC. Setting the
 * ADC path to the low frequency peak detection signal, will enable a
 * somewhat reasonable receiver for modulation on the carrier signal
 * that is generated by the reader. The signal is low when the reader
 * field is switched off, and high when the reader field is active. Due
 * to the way that the signal looks like, mostly only the rising edge is
 * useful, your mileage may vary.
 * 
 * Neat perk: PA15 can not only be used as a bit-banging GPIO, but is also
 * TIOA1, which can be used as the capture input for timer 1. This should
 * make it possible to measure the exact edge-to-edge time, without processor
 * intervention.
 * 
 * Arguments: divisor is the divisor to be sent to the FPGA (e.g. 95 for 125kHz)
 * t0 is the carrier frequency cycle duration in terms of MCK (384 for 125kHz)
 * 
 * The following defines are in carrier periods: 
 */
#define HITAG_T_0_MIN 15 /* T[0] should be 18..22 */ 
#define HITAG_T_1_MIN 24 /* T[1] should be 26..30 */
#define HITAG_T_EOF   40 /* T_EOF should be > 36 */
#define HITAG_T_WRESP 208 /* T_wresp should be 204..212 */

static void hitag_handle_frame(int t0, int frame_len, char *frame);
//#define DEBUG_RA_VALUES 1
#define DEBUG_FRAME_CONTENTS 1
void SimulateTagLowFrequencyBidir(int divisor, int t0)
{
#if DEBUG_RA_VALUES || DEBUG_FRAME_CONTENTS
	int i = 0;
#endif
	char frame[10];
	int frame_pos=0;
	
	DbpString("Starting Hitag2 emulator, press button to end");
	hitag2_init();
	
	/* Set up simulator mode, frequency divisor which will drive the FPGA
	 * and analog mux selection.
	 */
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_SIMULATOR);
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, divisor);
	SetAdcMuxFor(GPIO_MUXSEL_LOPKD);
	RELAY_OFF();
	
	/* Set up Timer 1:
	 * Capture mode, timer source MCK/2 (TIMER_CLOCK1), TIOA is external trigger,
	 * external trigger rising edge, load RA on rising edge of TIOA, load RB on rising
	 * edge of TIOA. Assign PA15 to TIOA1 (peripheral B)
	 */
	
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC1);
	AT91C_BASE_PIOA->PIO_BSR = GPIO_SSC_FRAME;
	AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
	AT91C_BASE_TC1->TC_CMR =	TC_CMR_TCCLKS_TIMER_CLOCK1 |
								AT91C_TC_ETRGEDG_RISING |
								AT91C_TC_ABETRG |
								AT91C_TC_LDRA_RISING |
								AT91C_TC_LDRB_RISING;
	AT91C_BASE_TC1->TC_CCR =	AT91C_TC_CLKEN |
								AT91C_TC_SWTRG;
	
	/* calculate the new value for the carrier period in terms of TC1 values */
	t0 = t0/2;
	
	int overflow = 0;
	while(!BUTTON_PRESS()) {
		WDT_HIT();
		if(AT91C_BASE_TC1->TC_SR & AT91C_TC_LDRAS) {
			int ra = AT91C_BASE_TC1->TC_RA;
			if((ra > t0*HITAG_T_EOF) | overflow) ra = t0*HITAG_T_EOF+1;
#if DEBUG_RA_VALUES
			if(ra > 255 || overflow) ra = 255;
			((char*)BigBuf)[i] = ra;
			i = (i+1) % 8000;
#endif
			
			if(overflow || (ra > t0*HITAG_T_EOF) || (ra < t0*HITAG_T_0_MIN)) {
				/* Ignore */
			} else if(ra >= t0*HITAG_T_1_MIN ) {
				/* '1' bit */
				if(frame_pos < 8*sizeof(frame)) {
					frame[frame_pos / 8] |= 1<<( 7-(frame_pos%8) );
					frame_pos++;
				}
			} else if(ra >= t0*HITAG_T_0_MIN) {
				/* '0' bit */
				if(frame_pos < 8*sizeof(frame)) {
					frame[frame_pos / 8] |= 0<<( 7-(frame_pos%8) );
					frame_pos++;
				}
			}
			
			overflow = 0;
			LED_D_ON();
		} else {
			if(AT91C_BASE_TC1->TC_CV > t0*HITAG_T_EOF) {
				/* Minor nuisance: In Capture mode, the timer can not be
				 * stopped by a Compare C. There's no way to stop the clock
				 * in software, so we'll just have to note the fact that an
				 * overflow happened and the next loaded timer value might
				 * have wrapped. Also, this marks the end of frame, and the
				 * still running counter can be used to determine the correct
				 * time for the start of the reply.
				 */ 
				overflow = 1;
				
				if(frame_pos > 0) {
					/* Have a frame, do something with it */
#if DEBUG_FRAME_CONTENTS
					((char*)BigBuf)[i++] = frame_pos;
					memcpy( ((char*)BigBuf)+i, frame, 7);
					i+=7;
					i = i % sizeof(BigBuf);
#endif
					hitag_handle_frame(t0, frame_pos, frame);
					memset(frame, 0, sizeof(frame));
				}
				frame_pos = 0;

			}
			LED_D_OFF();
		}
	}
	DbpString("All done");
}

static void hitag_send_bit(int t0, int bit) {
	if(bit == 1) {
		/* Manchester: Loaded, then unloaded */
		LED_A_ON();
		SHORT_COIL();
		while(AT91C_BASE_TC1->TC_CV < t0*15);
		OPEN_COIL();
		while(AT91C_BASE_TC1->TC_CV < t0*31);
		LED_A_OFF();
	} else if(bit == 0) {
		/* Manchester: Unloaded, then loaded */
		LED_B_ON();
		OPEN_COIL();
		while(AT91C_BASE_TC1->TC_CV < t0*15);
		SHORT_COIL();
		while(AT91C_BASE_TC1->TC_CV < t0*31);
		LED_B_OFF();
	}
	AT91C_BASE_TC1->TC_CCR = AT91C_TC_SWTRG; /* Reset clock for the next bit */
	
}
static void hitag_send_frame(int t0, int frame_len, const char const * frame, int fdt)
{
	OPEN_COIL();
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
	
	/* Wait for HITAG_T_WRESP carrier periods after the last reader bit,
	 * not that since the clock counts since the rising edge, but T_wresp is
	 * with respect to the falling edge, we need to wait actually (T_wresp - T_g)
	 * periods. The gap time T_g varies (4..10).
	 */
	while(AT91C_BASE_TC1->TC_CV < t0*(fdt-8));

	int saved_cmr = AT91C_BASE_TC1->TC_CMR;
	AT91C_BASE_TC1->TC_CMR &= ~AT91C_TC_ETRGEDG; /* Disable external trigger for the clock */
	AT91C_BASE_TC1->TC_CCR = AT91C_TC_SWTRG; /* Reset the clock and use it for response timing */
	
	int i;
	for(i=0; i<5; i++)
		hitag_send_bit(t0, 1); /* Start of frame */
	
	for(i=0; i<frame_len; i++) {
		hitag_send_bit(t0, !!(frame[i/ 8] & (1<<( 7-(i%8) ))) );
	}
	
	OPEN_COIL();
	AT91C_BASE_TC1->TC_CMR = saved_cmr;
}

/* Callback structure to cleanly separate tag emulation code from the radio layer. */
static int hitag_cb(const char* response_data, const int response_length, const int fdt, void *cb_cookie)
{
	hitag_send_frame(*(int*)cb_cookie, response_length, response_data, fdt);
	return 0;
}
/* Frame length in bits, frame contents in MSBit first format */
static void hitag_handle_frame(int t0, int frame_len, char *frame)
{
	hitag2_handle_command(frame, frame_len, hitag_cb, &t0);
}

// compose fc/8 fc/10 waveform
static void fc(int c, int *n) {
	BYTE *dest = (BYTE *)BigBuf;
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
	SimulateTagLowFrequency(n, ledcontrol);

	if (ledcontrol)
		LED_A_OFF();
}


// loop to capture raw HID waveform then FSK demodulate the TAG ID from it
void CmdHIDdemodFSK(int findone, int *high, int *low, int ledcontrol)
{
	BYTE *dest = (BYTE *)BigBuf;
	int m=0, n=0, i=0, idx=0, found=0, lastval=0;
	DWORD hi=0, lo=0;

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
				dest[i] = (BYTE)AT91C_BASE_SSC->SSC_RHR;
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
