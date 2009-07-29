//-----------------------------------------------------------------------------
// Miscellaneous routines for low frequency tag operations.
// Tags supported here so far are Texas Instruments (TI), HID
// Also routines for raw mode reading/simulating of LF waveform
//
//-----------------------------------------------------------------------------
#include <proxmark3.h>
#include "apps.h"
#include "../common/crc16.c"

void AcquireRawAdcSamples125k(BOOL at134khz)
{
	if(at134khz) {
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
		FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
	} else {
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
		FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
	}

	// Connect the A/D to the peak-detected low-frequency path.
	SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

	// Give it a bit of time for the resonant antenna to settle.
	SpinDelay(50);

	// Now set up the SSC to get the ADC samples that are now streaming at us.
	FpgaSetupSsc();

	// Now call the acquisition routine
	DoAcquisition125k(at134khz);
}

// split into two routines so we can avoid timing issues after sending commands //
void DoAcquisition125k(BOOL at134khz)
{
	BYTE *dest = (BYTE *)BigBuf;
	int n = sizeof(BigBuf);
	int i;

	memset(dest,0,n);
	i = 0;
	for(;;) {
		if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
			SSC_TRANSMIT_HOLDING = 0x43;
			LED_D_ON();
		}
		if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
			dest[i] = (BYTE)SSC_RECEIVE_HOLDING;
			i++;
			LED_D_OFF();
			if(i >= n) {
				break;
			}
		}
	}
	DbpIntegers(dest[0], dest[1], at134khz);
}

void ModThenAcquireRawAdcSamples125k(int delay_off,int period_0,int period_1,BYTE *command)
{
	BOOL at134khz;

	// see if 'h' was specified
	if(command[strlen((char *) command) - 1] == 'h')
		at134khz= TRUE;
	else
		at134khz= FALSE;

	if(at134khz) {
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
		FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
	} else {
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
		FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
	}

	// Give it a bit of time for the resonant antenna to settle.
	SpinDelay(50);

	// Now set up the SSC to get the ADC samples that are now streaming at us.
	FpgaSetupSsc();

	// now modulate the reader field
	while(*command != '\0' && *command != ' ')
		{
		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
		LED_D_OFF();
		SpinDelayUs(delay_off);
		if(at134khz) {
			FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
			FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
		} else {
			FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
			FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
		}
		LED_D_ON();
		if(*(command++) == '0')
			SpinDelayUs(period_0);
		else
			SpinDelayUs(period_1);
		}
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LED_D_OFF();
	SpinDelayUs(delay_off);
	if(at134khz) {
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
		FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
	} else {
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz
		FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
	}

	// now do the read
	DoAcquisition125k(at134khz);
}

void AcquireTiType(void)
{
	int i;
	// tag transmission is <20ms, sampling at 2M gives us 40K samples max
	// each sample is 1 bit stuffed into a DWORD so we need 1250 DWORDS
	int n = 1250;

	// clear buffer
	DbpIntegers((DWORD)BigBuf, sizeof(BigBuf), 0x12345678);
	memset(BigBuf,0,sizeof(BigBuf));

	// Set up the synchronous serial port
  PIO_DISABLE = (1<<GPIO_SSC_DIN);
  PIO_PERIPHERAL_A_SEL = (1<<GPIO_SSC_DIN);

	// steal this pin from the SSP and use it to control the modulation
  PIO_ENABLE = (1<<GPIO_SSC_DOUT);
	PIO_OUTPUT_ENABLE	= (1<<GPIO_SSC_DOUT);

  SSC_CONTROL = SSC_CONTROL_RESET;
  SSC_CONTROL = SSC_CONTROL_RX_ENABLE | SSC_CONTROL_TX_ENABLE;

  // Sample at 2 Mbit/s, so TI tags are 16.2 vs. 14.9 clocks long
  // 48/2 = 24 MHz clock must be divided by 12
  SSC_CLOCK_DIVISOR = 12;

  SSC_RECEIVE_CLOCK_MODE = SSC_CLOCK_MODE_SELECT(0);
	SSC_RECEIVE_FRAME_MODE = SSC_FRAME_MODE_BITS_IN_WORD(32) | SSC_FRAME_MODE_MSB_FIRST;
	SSC_TRANSMIT_CLOCK_MODE = 0;
	SSC_TRANSMIT_FRAME_MODE = 0;

	LED_D_ON();

	// modulate antenna
	PIO_OUTPUT_DATA_SET = (1<<GPIO_SSC_DOUT);

	// Charge TI tag for 50ms.
	SpinDelay(50);

	// stop modulating antenna and listen
	PIO_OUTPUT_DATA_CLEAR = (1<<GPIO_SSC_DOUT);

	LED_D_OFF();

	i = 0;
	for(;;) {
			if(SSC_STATUS & SSC_STATUS_RX_READY) {
					BigBuf[i] = SSC_RECEIVE_HOLDING;	// store 32 bit values in buffer
					i++; if(i >= n) return;
			}
			WDT_HIT();
	}

	// return stolen pin to SSP
	PIO_DISABLE = (1<<GPIO_SSC_DOUT);
	PIO_PERIPHERAL_A_SEL = (1<<GPIO_SSC_DIN) | (1<<GPIO_SSC_DOUT);
}

void ReadTItag()
{
}

void WriteTIbyte(BYTE b)
{
	int i = 0;

	// modulate 8 bits out to the antenna
	for (i=0; i<8; i++)
	{
		if (b&(1<<i)) {
			// stop modulating antenna
			PIO_OUTPUT_DATA_CLEAR = (1<<GPIO_SSC_DOUT);
			SpinDelayUs(1000);
			// modulate antenna
			PIO_OUTPUT_DATA_SET = (1<<GPIO_SSC_DOUT);
			SpinDelayUs(1000);
		} else {
			// stop modulating antenna
			PIO_OUTPUT_DATA_CLEAR = (1<<GPIO_SSC_DOUT);
			SpinDelayUs(300);
			// modulate antenna
			PIO_OUTPUT_DATA_SET = (1<<GPIO_SSC_DOUT);
			SpinDelayUs(1700);
		}
	}
}

void AcquireRawBitsTI(void)
{
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
}

// arguments: 64bit data split into 32bit idhi:idlo and optional 16bit crc
// if crc provided, it will be written with the data verbatim (even if bogus)
// if not provided a valid crc will be computed from the data and written.
void WriteTItag(DWORD idhi, DWORD idlo, WORD crc)
{

	// WARNING the order of the bytes in which we calc crc below needs checking
	// i'm 99% sure the crc algorithm is correct, but it may need to eat the
	// bytes in reverse or something

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
	DbpString("Writing the following data to tag:");
	DbpIntegers(idhi, idlo, crc);

	// TI tags charge at 134.2Khz
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
	// Place FPGA in passthrough mode, in this mode the CROSS_LO line
	// connects to SSP_DIN and the SSP_DOUT logic level controls
	// whether we're modulating the antenna (high)
	// or listening to the antenna (low)
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_PASSTHRU);
	LED_A_ON();

	// steal this pin from the SSP and use it to control the modulation
  PIO_ENABLE = (1<<GPIO_SSC_DOUT);
	PIO_OUTPUT_ENABLE	= (1<<GPIO_SSC_DOUT);

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
	PIO_OUTPUT_DATA_SET = (1<<GPIO_SSC_DOUT);
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
	PIO_OUTPUT_DATA_SET = (1<<GPIO_SSC_DOUT);
	SpinDelay(50);	// programming time

	LED_A_OFF();

	// get TI tag data into the buffer
	AcquireTiType();

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	DbpString("Now use tibits and tidemod");
}

void SimulateTagLowFrequency(int period, int ledcontrol)
{
	int i;
	BYTE *tab = (BYTE *)BigBuf;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_SIMULATOR);

	PIO_ENABLE = (1 << GPIO_SSC_DOUT) | (1 << GPIO_SSC_CLK);

	PIO_OUTPUT_ENABLE = (1 << GPIO_SSC_DOUT);
	PIO_OUTPUT_DISABLE = (1 << GPIO_SSC_CLK);

#define SHORT_COIL()	LOW(GPIO_SSC_DOUT)
#define OPEN_COIL()	HIGH(GPIO_SSC_DOUT)

	i = 0;
	for(;;) {
		while(!(PIO_PIN_DATA_STATUS & (1<<GPIO_SSC_CLK))) {
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

		while(PIO_PIN_DATA_STATUS & (1<<GPIO_SSC_CLK)) {
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
			if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
				SSC_TRANSMIT_HOLDING = 0x43;
				if (ledcontrol)
					LED_D_ON();
			}
			if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
				dest[i] = (BYTE)SSC_RECEIVE_HOLDING;
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
					DbpString("TAG ID");
					DbpIntegers(hi, lo, (lo>>1)&0xffff);
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
					DbpString("TAG ID");
					DbpIntegers(hi, lo, (lo>>1)&0xffff);
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
