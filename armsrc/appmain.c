//-----------------------------------------------------------------------------
// The main application code. This is the first thing called after start.c
// executes.
// Jonathan Westhues, Mar 2006
// Edits by Gerhard de Koning Gans, Sep 2007 (##)
//-----------------------------------------------------------------------------
#include <proxmark3.h>
#include "apps.h"
#include "fonts.h"
#include "LCD.h"

// The large multi-purpose buffer, typically used to hold A/D samples,
// maybe pre-processed in some way.
DWORD BigBuf[16000];

//=============================================================================
// A buffer where we can queue things up to be sent through the FPGA, for
// any purpose (fake tag, as reader, whatever). We go MSB first, since that
// is the order in which they go out on the wire.
//=============================================================================

BYTE ToSend[256];
int ToSendMax;
static int ToSendBit;

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
	BYTE *dest = (BYTE *)BigBuf;
	int n = sizeof(BigBuf);
	int i;

	memset(dest,0,n);

	if(at134khz) {
		FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER | FPGA_LF_READER_USE_134_KHZ);
	} else {
		FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER | FPGA_LF_READER_USE_125_KHZ);
	}

	// Connect the A/D to the peak-detected low-frequency path.
	SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

	// Give it a bit of time for the resonant antenna to settle.
	SpinDelay(50);

	// Now set up the SSC to get the ADC samples that are now streaming at us.
	FpgaSetupSsc();

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

//-----------------------------------------------------------------------------
// Read an ADC channel and block till it completes, then return the result
// in ADC units (0 to 1023). Also a routine to average sixteen samples and
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
// Impedances are Zc = 1/(j*omega*C), in ohms
#define LF_TUNING_CAP_Z	1273	//  1 nF @ 125   kHz
#define HF_TUNING_CAP_Z	235		// 50 pF @ 13.56 MHz

	int vLf125, vLf134, vHf;	// in mV

	UsbCommand c;

	// Let the FPGA drive the low-frequency antenna around 125 kHz.
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER | FPGA_LF_READER_USE_125_KHZ);
	SpinDelay(20);
	vLf125 = AvgAdc(4);
	// Vref = 3.3V, and a 10000:240 voltage divider on the input
	// can measure voltages up to 137500 mV
	vLf125 = (137500 * vLf125) >> 10;

	// Let the FPGA drive the low-frequency antenna around 134 kHz.
	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER | FPGA_LF_READER_USE_134_KHZ);
	SpinDelay(20);
	vLf134 = AvgAdc(4);
	// Vref = 3.3V, and a 10000:240 voltage divider on the input
	// can measure voltages up to 137500 mV
	vLf134 = (137500 * vLf134) >> 10;

	// Let the FPGA drive the high-frequency antenna around 13.56 MHz.
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	SpinDelay(20);
	vHf = AvgAdc(5);
	// Vref = 3300mV, and an 10:1 voltage divider on the input
	// can measure voltages up to 33000 mV
	vHf = (33000 * vHf) >> 10;

	c.cmd = CMD_MEASURED_ANTENNA_TUNING;
	c.ext1 = (vLf125 << 0) | (vLf134 << 16);
	c.ext2 = vHf;
	c.ext3 = (LF_TUNING_CAP_Z << 0) | (HF_TUNING_CAP_Z << 16);
	UsbSendPacket((BYTE *)&c, sizeof(c));
}

void SimulateTagLowFrequency(int period)
{
	int i;
	BYTE *tab = (BYTE *)BigBuf;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_SIMULATOR);

	PIO_ENABLE = (1 << GPIO_SSC_DOUT) | (1 << GPIO_SSC_CLK);

	PIO_OUTPUT_ENABLE = (1 << GPIO_SSC_DOUT);
	PIO_OUTPUT_DISABLE = (1 << GPIO_SSC_CLK);

#define SHORT_COIL()	LOW(GPIO_SSC_DOUT)
#define OPEN_COIL()		HIGH(GPIO_SSC_DOUT)

	i = 0;
	for(;;) {
		while(!(PIO_PIN_DATA_STATUS & (1<<GPIO_SSC_CLK))) {
			if(BUTTON_PRESS()) {
				return;
			}
			WDT_HIT();
		}

		LED_D_ON();
		if(tab[i]) {
			OPEN_COIL();
		} else {
			SHORT_COIL();
		}
		LED_D_OFF();

		while(PIO_PIN_DATA_STATUS & (1<<GPIO_SSC_CLK)) {
			if(BUTTON_PRESS()) {
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
static void CmdHIDsimTAG(int hi, int lo)
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

	LED_A_ON();
	SimulateTagLowFrequency(n);
	LED_A_OFF();
}

// loop to capture raw HID waveform then FSK demodulate the TAG ID from it
static void CmdHIDdemodFSK(void)
{
	BYTE *dest = (BYTE *)BigBuf;
	int m=0, n=0, i=0, idx=0, found=0, lastval=0;
	DWORD hi=0, lo=0;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_READER | FPGA_LF_READER_USE_125_KHZ);

	// Connect the A/D to the peak-detected low-frequency path.
	SetAdcMuxFor(GPIO_MUXSEL_LOPKD);

	// Give it a bit of time for the resonant antenna to settle.
	SpinDelay(50);

	// Now set up the SSC to get the ADC samples that are now streaming at us.
	FpgaSetupSsc();

	for(;;) {
		WDT_HIT();
		LED_A_ON();
		if(BUTTON_PRESS()) {
			LED_A_OFF();
			return;
		}

		i = 0;
		m = sizeof(BigBuf);
		memset(dest,128,m);
		for(;;) {
			if(SSC_STATUS & (SSC_STATUS_TX_READY)) {
				SSC_TRANSMIT_HOLDING = 0x43;
				LED_D_ON();
			}
			if(SSC_STATUS & (SSC_STATUS_RX_READY)) {
				dest[i] = (BYTE)SSC_RECEIVE_HOLDING;
				// we don't care about actual value, only if it's more or less than a
				// threshold essentially we capture zero crossings for later analysis
				if(dest[i] < 127) dest[i] = 0; else dest[i] = 1;
				i++;
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

		case CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693:
			AcquireRawAdcSamplesIso15693();
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

		case CMD_HID_DEMOD_FSK:
			CmdHIDdemodFSK();				// Demodulate HID tag
			break;

		case CMD_HID_SIM_TAG:
			CmdHIDsimTAG(c->ext1, c->ext2);					// Simulate HID tag by ID
			break;

		case CMD_FPGA_MAJOR_MODE_OFF:		// ## FPGA Control
			LED_C_ON();
			FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
			SpinDelay(200);
			LED_C_OFF();
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
			SimulateTagLowFrequency(c->ext1);
			LED_A_OFF();
			break;

		case CMD_LCD_RESET:
			LCDReset();
			break;

		case CMD_LCD:
			LCDSend(c->ext1);
			break;

        case CMD_SETUP_WRITE:
		case CMD_FINISH_WRITE:
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

	for(;;) {
		UsbPoll(FALSE);
		WDT_HIT();
	}
}

void SpinDelay(int ms)
{
	int ticks = (48000*ms) >> 10;

	// Borrow a PWM unit for my real-time clock
	PWM_ENABLE = PWM_CHANNEL(0);
	// 48 MHz / 1024 gives 46.875 kHz
	PWM_CH_MODE(0) = PWM_CH_MODE_PRESCALER(10);
	PWM_CH_DUTY_CYCLE(0) = 0;
	PWM_CH_PERIOD(0) = 0xffff;

	WORD start = (WORD)PWM_CH_COUNTER(0);

	for(;;) {
		WORD now = (WORD)PWM_CH_COUNTER(0);
		if(now == (WORD)(start + ticks)) {
			return;
		}
		WDT_HIT();
	}
}
