//-----------------------------------------------------------------------------
// The main application code. This is the first thing called after start.c
// executes.
// Jonathan Westhues, Mar 2006
// Edits by Gerhard de Koning Gans, Sep 2007 (##)
//-----------------------------------------------------------------------------


#include <proxmark3.h>
#include <stdlib.h>
#include "apps.h"
#ifdef WITH_LCD
#include "fonts.h"
#include "LCD.h"
#endif

// The large multi-purpose buffer, typically used to hold A/D samples,
// maybe pre-processed in some way.
DWORD BigBuf[16000];
int usbattached = 0;

//=============================================================================
// A buffer where we can queue things up to be sent through the FPGA, for
// any purpose (fake tag, as reader, whatever). We go MSB first, since that
// is the order in which they go out on the wire.
//=============================================================================

BYTE ToSend[256];
int ToSendMax;
static int ToSendBit;


void BufferClear(void)
{
	memset(BigBuf,0,sizeof(BigBuf));
	DbpString("Buffer cleared");
}

void ToSendReset(void)
{
	ToSendMax = -1;
	ToSendBit = 8;
}

void ToSendStuffBit(int b)
{
	if(ToSendBit >= 8) {
		ToSendMax++;
		ToSend[ToSendMax] = 0;
		ToSendBit = 0;
	}

	if(b) {
		ToSend[ToSendMax] |= (1 << (7 - ToSendBit));
	}

	ToSendBit++;

	if(ToSendBit >= sizeof(ToSend)) {
		ToSendBit = 0;
		DbpString("ToSendStuffBit overflowed!");
	}
}

//=============================================================================
// Debug print functions, to go out over USB, to the usual PC-side client.
//=============================================================================

void DbpString(char *str)
{
	/* this holds up stuff unless we're connected to usb */
//	if (!usbattached)
//		return;

	UsbCommand c;
	c.cmd = CMD_DEBUG_PRINT_STRING;
	c.ext1 = strlen(str);
	memcpy(c.d.asBytes, str, c.ext1);

	UsbSendPacket((BYTE *)&c, sizeof(c));
	// TODO fix USB so stupid things like this aren't req'd
	SpinDelay(50);
}

void DbpIntegers(int x1, int x2, int x3)
{
	/* this holds up stuff unless we're connected to usb */
//	if (!usbattached)
//		return;

	UsbCommand c;
	c.cmd = CMD_DEBUG_PRINT_INTEGERS;
	c.ext1 = x1;
	c.ext2 = x2;
	c.ext3 = x3;

	UsbSendPacket((BYTE *)&c, sizeof(c));
	// XXX
	SpinDelay(50);
}

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

//-----------------------------------------------------------------------------
// Read a TI-type tag. We assume that the tag has already been illuminated,
// and that the exciting signal has been turned off. That means that we just
// acquire the `one-bit DAC' bits from the comparator.
//-----------------------------------------------------------------------------
void AcquireTiType(void)
{
	int i;
	int n = sizeof(BigBuf);

	// clear buffer
	memset(BigBuf,0,sizeof(BigBuf));

  // Set up the synchronous serial port
  PIO_DISABLE = (1<<GPIO_SSC_DIN);
  PIO_PERIPHERAL_A_SEL = (1<<GPIO_SSC_DIN);

  SSC_CONTROL = SSC_CONTROL_RESET;
  SSC_CONTROL = SSC_CONTROL_RX_ENABLE | SSC_CONTROL_TX_ENABLE;

  // Sample at 2 Mbit/s, so TI tags are 16.2 vs. 14.9 clocks long
  // 48/2 = 24 MHz clock must be divided by 12
  SSC_CLOCK_DIVISOR = 12;

  SSC_RECEIVE_CLOCK_MODE = SSC_CLOCK_MODE_SELECT(0);
  SSC_RECEIVE_FRAME_MODE = SSC_FRAME_MODE_BITS_IN_WORD(32) | SSC_FRAME_MODE_MSB_FIRST;
  SSC_TRANSMIT_CLOCK_MODE = 0;
  SSC_TRANSMIT_FRAME_MODE = 0;

  i = 0;
  for(;;) {
      if(SSC_STATUS & SSC_STATUS_RX_READY) {
          BigBuf[i] = SSC_RECEIVE_HOLDING;	// store 32 bit values in buffer
          i++; if(i >= n) return;
      }
      WDT_HIT();
  }
}

void AcquireRawBitsTI(void)
{
	LED_D_ON();
	// TI tags charge at 134.2Khz
	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 88); //134.8Khz
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);

	// Charge TI tag for 50ms.
	SpinDelay(50);
	LED_D_OFF();

	LED_A_ON();
	// Place FPGA in passthrough mode so as to stop driving the LF coil,
	// in this mode the CROSS_LO line connects to SSP_DIN
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_PASSTHRU);

	// get TI tag data into the buffer
	AcquireTiType();

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LED_A_OFF();
}

//-----------------------------------------------------------------------------
// Read an ADC channel and block till it completes, then return the result
// in ADC units (0 to 1023). Also a routine to average 32 samples and
// return that.
//-----------------------------------------------------------------------------
static int ReadAdc(int ch)
{
	DWORD d;

	ADC_CONTROL = ADC_CONTROL_RESET;
	ADC_MODE = ADC_MODE_PRESCALE(32) | ADC_MODE_STARTUP_TIME(16) |
		ADC_MODE_SAMPLE_HOLD_TIME(8);
	ADC_CHANNEL_ENABLE = ADC_CHANNEL(ch);

	ADC_CONTROL = ADC_CONTROL_START;
	while(!(ADC_STATUS & ADC_END_OF_CONVERSION(ch)))
		;
	d = ADC_CHANNEL_DATA(ch);

	return d;
}

static int AvgAdc(int ch)
{
	int i;
	int a = 0;

	for(i = 0; i < 32; i++) {
		a += ReadAdc(ch);
	}

	return (a + 15) >> 5;
}

void MeasureAntennaTuning(void)
{
	BYTE *dest = (BYTE *)BigBuf;
	int i, ptr = 0, adcval = 0, peak = 0, peakv = 0, peakf = 0;;
	int vLf125 = 0, vLf134 = 0, vHf = 0;	// in mV

	UsbCommand c;

	DbpString("Measuring antenna characteristics, please wait.");
	memset(BigBuf,0,sizeof(BigBuf));

/*
 * Sweeps the useful LF range of the proxmark from
 * 46.8kHz (divisor=255) to 600kHz (divisor=19) and
 * read the voltage in the antenna, the result left
 * in the buffer is a graph which should clearly show
 * the resonating frequency of your LF antenna
 * ( hopefully around 95 if it is tuned to 125kHz!)
 */
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER);
	for (i=255; i>19; i--) {
		FpgaSendCommand(FPGA_CMD_SET_DIVISOR, i);
		SpinDelay(20);
		// Vref = 3.3V, and a 10000:240 voltage divider on the input
		// can measure voltages up to 137500 mV
		adcval = ((137500 * AvgAdc(ADC_CHAN_LF)) >> 10);
		if (i==95) 	vLf125 = adcval; // voltage at 125Khz
		if (i==89) 	vLf134 = adcval; // voltage at 134Khz

		dest[i] = adcval>>8; // scale int to fit in byte for graphing purposes
		if(dest[i] > peak) {
			peakv = adcval;
			peak = dest[i];
			peakf = i;
			ptr = i;
		}
	}

	// Let the FPGA drive the high-frequency antenna around 13.56 MHz.
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	SpinDelay(20);
	// Vref = 3300mV, and an 10:1 voltage divider on the input
	// can measure voltages up to 33000 mV
	vHf = (33000 * AvgAdc(ADC_CHAN_HF)) >> 10;

	c.cmd = CMD_MEASURED_ANTENNA_TUNING;
	c.ext1 = (vLf125 << 0) | (vLf134 << 16);
	c.ext2 = vHf;
	c.ext3 = peakf | (peakv << 16);
	UsbSendPacket((BYTE *)&c, sizeof(c));
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
static void CmdHIDsimTAG(int hi, int lo, int ledcontrol)
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
static void CmdHIDdemodFSK(int findone, int *high, int *low, int ledcontrol)
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

void SimulateTagHfListen(void)
{
	BYTE *dest = (BYTE *)BigBuf;
	int n = sizeof(BigBuf);
	BYTE v = 0;
	int i;
	int p = 0;

	// We're using this mode just so that I can test it out; the simulated
	// tag mode would work just as well and be simpler.
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ | FPGA_HF_READER_RX_XCORR_SNOOP);

	// We need to listen to the high-frequency, peak-detected path.
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	FpgaSetupSsc();

	i = 0;
	for(;;) {
		if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
			SSC_TRANSMIT_HOLDING = 0xff;
		}
		if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
			BYTE r = (BYTE)SSC_RECEIVE_HOLDING;

			v <<= 1;
			if(r & 1) {
				v |= 1;
			}
			p++;

			if(p >= 8) {
				dest[i] = v;
				v = 0;
				p = 0;
				i++;

				if(i >= n) {
					break;
				}
			}
		}
	}
	DbpString("simulate tag (now type bitsamples)");
}

void UsbPacketReceived(BYTE *packet, int len)
{
	UsbCommand *c = (UsbCommand *)packet;

	switch(c->cmd) {
		case CMD_ACQUIRE_RAW_ADC_SAMPLES_125K:
			AcquireRawAdcSamples125k(c->ext1);
			break;

		case CMD_MOD_THEN_ACQUIRE_RAW_ADC_SAMPLES_125K:
			ModThenAcquireRawAdcSamples125k(c->ext1,c->ext2,c->ext3,c->d.asBytes);
			break;

		case CMD_ACQUIRE_RAW_BITS_TI_TYPE:
			AcquireRawBitsTI();
			break;

		case CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693:
			AcquireRawAdcSamplesIso15693();
			break;

		case CMD_BUFF_CLEAR:
			BufferClear();
			break;

		case CMD_READER_ISO_15693:
			ReaderIso15693(c->ext1);
			break;

		case CMD_SIMTAG_ISO_15693:
			SimTagIso15693(c->ext1);
			break;

		case CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443:
			AcquireRawAdcSamplesIso14443(c->ext1);
			break;

		case CMD_READ_SRI512_TAG:
			ReadSRI512Iso14443(c->ext1);
			break;

		case CMD_READER_ISO_14443a:
			ReaderIso14443a(c->ext1);
			break;

		case CMD_SNOOP_ISO_14443:
			SnoopIso14443();
			break;

		case CMD_SNOOP_ISO_14443a:
			SnoopIso14443a();
			break;

		case CMD_SIMULATE_TAG_HF_LISTEN:
			SimulateTagHfListen();
			break;

		case CMD_SIMULATE_TAG_ISO_14443:
			SimulateIso14443Tag();
			break;

		case CMD_SIMULATE_TAG_ISO_14443a:
			SimulateIso14443aTag(c->ext1, c->ext2);  // ## Simulate iso14443a tag - pass tag type & UID
			break;

		case CMD_MEASURE_ANTENNA_TUNING:
			MeasureAntennaTuning();
			break;

		case CMD_LISTEN_READER_FIELD:
			ListenReaderField(c->ext1);
			break;

		case CMD_HID_DEMOD_FSK:
			CmdHIDdemodFSK(0, 0, 0, 1);				// Demodulate HID tag
			break;

		case CMD_HID_SIM_TAG:
			CmdHIDsimTAG(c->ext1, c->ext2, 1);					// Simulate HID tag by ID
			break;

		case CMD_FPGA_MAJOR_MODE_OFF:		// ## FPGA Control
			FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
			SpinDelay(200);
			LED_D_OFF(); // LED D indicates field ON or OFF
			break;

		case CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K:
		case CMD_DOWNLOAD_RAW_BITS_TI_TYPE: {
			UsbCommand n;
			if(c->cmd == CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K) {
				n.cmd = CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K;
			} else {
				n.cmd = CMD_DOWNLOADED_RAW_BITS_TI_TYPE;
			}
			n.ext1 = c->ext1;
			memcpy(n.d.asDwords, BigBuf+c->ext1, 12*sizeof(DWORD));
			UsbSendPacket((BYTE *)&n, sizeof(n));
			break;
		}
		case CMD_DOWNLOADED_SIM_SAMPLES_125K: {
			BYTE *b = (BYTE *)BigBuf;
			memcpy(b+c->ext1, c->d.asBytes, 48);
			break;
		}
		case CMD_SIMULATE_TAG_125K:
			LED_A_ON();
			SimulateTagLowFrequency(c->ext1, 1);
			LED_A_OFF();
			break;
#ifdef WITH_LCD
		case CMD_LCD_RESET:
			LCDReset();
			break;
#endif
		case CMD_READ_MEM:
			ReadMem(c->ext1);
			break;
		case CMD_SET_LF_DIVISOR:
			FpgaSendCommand(FPGA_CMD_SET_DIVISOR, c->ext1);
			break;
#ifdef WITH_LCD
		case CMD_LCD:
			LCDSend(c->ext1);
			break;
#endif
        case CMD_SETUP_WRITE:
		case CMD_FINISH_WRITE:
		case CMD_HARDWARE_RESET:
			USB_D_PLUS_PULLUP_OFF();
			SpinDelay(1000);
			SpinDelay(1000);
			RSTC_CONTROL = RST_CONTROL_KEY | RST_CONTROL_PROCESSOR_RESET;
			for(;;) {
				// We're going to reset, and the bootrom will take control.
			}
			break;


		default:
			DbpString("unknown command");
			break;
	}
}

void ReadMem(int addr)
{
	const DWORD *data = ((DWORD *)addr);
	int i;

	DbpString("Reading memory at address");
	DbpIntegers(0, 0, addr);
	for (i = 0; i < 8; i+= 2)
		DbpIntegers(0, data[i], data[i+1]);
}

void AppMain(void)
{
	memset(BigBuf,0,sizeof(BigBuf));
	SpinDelay(100);

	LED_D_OFF();
	LED_C_OFF();
	LED_B_OFF();
	LED_A_OFF();

	UsbStart();

	// The FPGA gets its clock from us from PCK0 output, so set that up.
	PIO_PERIPHERAL_B_SEL = (1 << GPIO_PCK0);
	PIO_DISABLE = (1 << GPIO_PCK0);
	PMC_SYS_CLK_ENABLE = PMC_SYS_CLK_PROGRAMMABLE_CLK_0;
	// PCK0 is PLL clock / 4 = 96Mhz / 4 = 24Mhz
	PMC_PROGRAMMABLE_CLK_0 = PMC_CLK_SELECTION_PLL_CLOCK |
		PMC_CLK_PRESCALE_DIV_4;
	PIO_OUTPUT_ENABLE = (1 << GPIO_PCK0);

	// Reset SPI
	SPI_CONTROL = SPI_CONTROL_RESET;
	// Reset SSC
	SSC_CONTROL = SSC_CONTROL_RESET;

	// Load the FPGA image, which we have stored in our flash.
	FpgaDownloadAndGo();

#ifdef WITH_LCD

	LCDInit();

	// test text on different colored backgrounds
	LCDString(" The quick brown fox  ",	&FONT6x8,1,1+8*0,WHITE  ,BLACK );
	LCDString("  jumped over the     ",	&FONT6x8,1,1+8*1,BLACK  ,WHITE );
	LCDString("     lazy dog.        ",	&FONT6x8,1,1+8*2,YELLOW ,RED   );
	LCDString(" AaBbCcDdEeFfGgHhIiJj ",	&FONT6x8,1,1+8*3,RED    ,GREEN );
	LCDString(" KkLlMmNnOoPpQqRrSsTt ",	&FONT6x8,1,1+8*4,MAGENTA,BLUE  );
	LCDString("UuVvWwXxYyZz0123456789",	&FONT6x8,1,1+8*5,BLUE   ,YELLOW);
	LCDString("`-=[]_;',./~!@#$%^&*()",	&FONT6x8,1,1+8*6,BLACK  ,CYAN  );
	LCDString("     _+{}|:\\\"<>?     ",&FONT6x8,1,1+8*7,BLUE  ,MAGENTA);

	// color bands
	LCDFill(0, 1+8* 8, 132, 8, BLACK);
	LCDFill(0, 1+8* 9, 132, 8, WHITE);
	LCDFill(0, 1+8*10, 132, 8, RED);
	LCDFill(0, 1+8*11, 132, 8, GREEN);
	LCDFill(0, 1+8*12, 132, 8, BLUE);
	LCDFill(0, 1+8*13, 132, 8, YELLOW);
	LCDFill(0, 1+8*14, 132, 8, CYAN);
	LCDFill(0, 1+8*15, 132, 8, MAGENTA);

#endif

	for(;;) {
		usbattached = UsbPoll(FALSE);
		WDT_HIT();

		if (BUTTON_HELD(1000) > 0)
			SamyRun();
	}
}


// samy's sniff and repeat routine
void SamyRun()
{
	DbpString("Stand-alone mode! No PC necessary.");

	// 3 possible options? no just 2 for now
#define OPTS 2

	int high[OPTS], low[OPTS];

	// Oooh pretty -- notify user we're in elite samy mode now
	LED(LED_RED,	200);
	LED(LED_ORANGE, 200);
	LED(LED_GREEN,	200);
	LED(LED_ORANGE, 200);
	LED(LED_RED,	200);
	LED(LED_ORANGE, 200);
	LED(LED_GREEN,	200);
	LED(LED_ORANGE, 200);
	LED(LED_RED,	200);

	int selected = 0;
	int playing = 0;

	// Turn on selected LED
	LED(selected + 1, 0);

	for (;;)
	{
		usbattached = UsbPoll(FALSE);
		WDT_HIT();

		// Was our button held down or pressed?
		int button_pressed = BUTTON_HELD(1000);
		SpinDelay(300);

		// Button was held for a second, begin recording
		if (button_pressed > 0)
		{
			LEDsoff();
			LED(selected + 1, 0);
			LED(LED_RED2, 0);

			// record
			DbpString("Starting recording");

			// wait for button to be released
			while(BUTTON_PRESS())
				WDT_HIT();

			/* need this delay to prevent catching some weird data */
			SpinDelay(500);

			CmdHIDdemodFSK(1, &high[selected], &low[selected], 0);
			DbpString("Recorded");
			DbpIntegers(selected, high[selected], low[selected]);

			LEDsoff();
			LED(selected + 1, 0);
			// Finished recording

			// If we were previously playing, set playing off
			// so next button push begins playing what we recorded
			playing = 0;
		}

		// Change where to record (or begin playing)
		else if (button_pressed)
		{
			// Next option if we were previously playing
			if (playing)
				selected = (selected + 1) % OPTS;
			playing = !playing;

			LEDsoff();
			LED(selected + 1, 0);

			// Begin transmitting
			if (playing)
			{
				LED(LED_GREEN, 0);
				DbpString("Playing");
				// wait for button to be released
				while(BUTTON_PRESS())
					WDT_HIT();
				DbpIntegers(selected, high[selected], low[selected]);
				CmdHIDsimTAG(high[selected], low[selected], 0);
				DbpString("Done playing");
				if (BUTTON_HELD(1000) > 0)
					{
					DbpString("Exiting");
					LEDsoff();
					return;
					}

				/* We pressed a button so ignore it here with a delay */
				SpinDelay(300);

				// when done, we're done playing, move to next option
				selected = (selected + 1) % OPTS;
				playing = !playing;
				LEDsoff();
				LED(selected + 1, 0);
			}
			else
				while(BUTTON_PRESS())
					WDT_HIT();
		}
	}
}


// listen for external reader
void ListenReaderField(int limit)
{
	int lf_av, lf_av_new, lf_baseline= 0, lf_count= 0;
	int hf_av, hf_av_new,  hf_baseline= 0, hf_count= 0;

#define LF_ONLY		1
#define HF_ONLY		2

	LED_A_OFF();
	LED_B_OFF();
	LED_C_OFF();
	LED_D_OFF();

	lf_av= ReadAdc(ADC_CHAN_LF);

	if(limit != HF_ONLY)
		{
		DbpString("LF 125/134 Baseline:");
		DbpIntegers(lf_av,0,0);
		lf_baseline= lf_av;
		}

	hf_av= ReadAdc(ADC_CHAN_HF);


	if (limit != LF_ONLY)
		{
		DbpString("HF 13.56 Baseline:");
		DbpIntegers(hf_av,0,0);
		hf_baseline= hf_av;
		}

	for(;;)
		{
		if(BUTTON_PRESS())
			{
			DbpString("Stopped");
			LED_B_OFF();
			LED_D_OFF();
			return;
			}
		WDT_HIT();


		if (limit != HF_ONLY)
			{
			if (abs(lf_av - lf_baseline) > 10)
				LED_D_ON();
			else
				LED_D_OFF();
			++lf_count;
			lf_av_new= ReadAdc(ADC_CHAN_LF);
			// see if there's a significant change
			if(abs(lf_av - lf_av_new) > 10)
				{
				DbpString("LF 125/134 Field Change:");
				DbpIntegers(lf_av,lf_av_new,lf_count);
				lf_av= lf_av_new;
				lf_count= 0;
				}
			}

		if (limit != LF_ONLY)
			{
			if (abs(hf_av - hf_baseline) > 10)
				LED_B_ON();
			else
				LED_B_OFF();
			++hf_count;
			hf_av_new= ReadAdc(ADC_CHAN_HF);
			// see if there's a significant change
			if(abs(hf_av - hf_av_new) > 10)
				{
				DbpString("HF 13.56 Field Change:");
				DbpIntegers(hf_av,hf_av_new,hf_count);
				hf_av= hf_av_new;
				hf_count= 0;
				}
			}
		}
}
