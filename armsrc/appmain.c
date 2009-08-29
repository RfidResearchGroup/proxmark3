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
	if (!UsbConnected())
		return;

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
	if (!UsbConnected())
		return;

	UsbCommand c;
	c.cmd = CMD_DEBUG_PRINT_INTEGERS;
	c.ext1 = x1;
	c.ext2 = x2;
	c.ext3 = x3;

	UsbSendPacket((BYTE *)&c, sizeof(c));
	// XXX
	SpinDelay(50);
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

void ReadMem(int addr)
{
	const DWORD *data = ((DWORD *)addr);
	int i;

	DbpString("Reading memory at address");
	DbpIntegers(0, 0, addr);
	for (i = 0; i < 8; i+= 2)
		DbpIntegers(0, data[i], data[i+1]);
}

/* osimage version information is linked in */
extern struct version_information version_information;
/* bootrom version information is pointed to from _bootphase1_version_pointer */
extern char _bootphase1_version_pointer, _flash_start, _flash_end;
void SendVersion(void)
{
	char temp[48]; /* Limited data payload in USB packets */
	DbpString("Prox/RFID mark3 RFID instrument");
	
	/* Try to find the bootrom version information. Expect to find a pointer at 
	 * symbol _bootphase1_version_pointer, perform slight sanity checks on the
	 * pointer, then use it.
	 */
	void *bootrom_version = *(void**)&_bootphase1_version_pointer;
	if( bootrom_version < (void*)&_flash_start || bootrom_version >= (void*)&_flash_end ) {
		DbpString("bootrom version information appears invalid");
	} else {
		FormatVersionInformation(temp, sizeof(temp), "bootrom: ", bootrom_version);
		DbpString(temp);
	}
	
	FormatVersionInformation(temp, sizeof(temp), "os: ", &version_information);
	DbpString(temp);
	
	FpgaGatherVersion(temp, sizeof(temp));
	DbpString(temp);
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
		UsbPoll(FALSE);
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


/*
OBJECTIVE
Listen and detect an external reader. Determine the best location
for the antenna.

INSTRUCTIONS:
Inside the ListenReaderField() function, there is two mode.
By default, when you call the function, you will enter mode 1.
If you press the PM3 button one time, you will enter mode 2.
If you press the PM3 button a second time, you will exit the function.

DESCRIPTION OF MODE 1:
This mode just listens for an external reader field and lights up green
for HF and/or red for LF. This is the original mode of the detectreader
function.

DESCRIPTION OF MODE 2:
This mode will visually represent, using the LEDs, the actual strength of the
current compared to the maximum current detected. Basically, once you know
what kind of external reader is present, it will help you spot the best location to place
your antenna. You will probably not get some good results if there is a LF and a HF reader
at the same place! :-)

LIGHT SCHEME USED:
*/
static const char LIGHT_SCHEME[] = {
		0x0, /* ----     | No field detected */
		0x1, /* X---     | 14% of maximum current detected */
		0x2, /* -X--     | 29% of maximum current detected */
		0x4, /* --X-     | 43% of maximum current detected */
		0x8, /* ---X     | 57% of maximum current detected */
		0xC, /* --XX     | 71% of maximum current detected */
		0xE, /* -XXX     | 86% of maximum current detected */
		0xF, /* XXXX     | 100% of maximum current detected */
};
static const int LIGHT_LEN = sizeof(LIGHT_SCHEME)/sizeof(LIGHT_SCHEME[0]);

void ListenReaderField(int limit)
{
	int lf_av, lf_av_new, lf_baseline= 0, lf_count= 0, lf_max;
	int hf_av, hf_av_new,  hf_baseline= 0, hf_count= 0, hf_max;
	int mode=1, display_val, display_max, i;

#define LF_ONLY		1
#define HF_ONLY		2

	LEDsoff();

	lf_av=lf_max=ReadAdc(ADC_CHAN_LF);

	if(limit != HF_ONLY) {
		DbpString("LF 125/134 Baseline:");
		DbpIntegers(lf_av,0,0);
		lf_baseline= lf_av;
	}

	hf_av=hf_max=ReadAdc(ADC_CHAN_HF);

	if (limit != LF_ONLY) {
		DbpString("HF 13.56 Baseline:");
		DbpIntegers(hf_av,0,0);
		hf_baseline= hf_av;
	}

	for(;;) {
		if (BUTTON_PRESS()) {
			SpinDelay(500);
			switch (mode) {
				case 1:
					mode=2;
					DbpString("Signal Strength Mode");
					break;
				case 2:
				default:
					DbpString("Stopped");
					LEDsoff();
					return;
					break;
			}
		}
		WDT_HIT();

		if (limit != HF_ONLY) {
			if(mode==1) {
				if (abs(lf_av - lf_baseline) > 10) LED_D_ON();
				else                               LED_D_OFF();
			}
			
			++lf_count;
			lf_av_new= ReadAdc(ADC_CHAN_LF);
			// see if there's a significant change
			if(abs(lf_av - lf_av_new) > 10) {
				DbpString("LF 125/134 Field Change:");
				DbpIntegers(lf_av,lf_av_new,lf_count);
				lf_av= lf_av_new;
				if (lf_av > lf_max)
					lf_max = lf_av;
				lf_count= 0;
			}
		}

		if (limit != LF_ONLY) {
			if (mode == 1){
				if (abs(hf_av - hf_baseline) > 10) LED_B_ON();
				else                               LED_B_OFF();
			}
			
			++hf_count;
			hf_av_new= ReadAdc(ADC_CHAN_HF);
			// see if there's a significant change
			if(abs(hf_av - hf_av_new) > 10) {
				DbpString("HF 13.56 Field Change:");
				DbpIntegers(hf_av,hf_av_new,hf_count);
				hf_av= hf_av_new;
				if (hf_av > hf_max)
					hf_max = hf_av;
				hf_count= 0;
			}
		}
		
		if(mode == 2) {
			if (limit == LF_ONLY) {
				display_val = lf_av;
				display_max = lf_max;
			} else if (limit == HF_ONLY) {
				display_val = hf_av;
				display_max = hf_max;
			} else { /* Pick one at random */
				if( (hf_max - hf_baseline) > (lf_max - lf_baseline) ) {
					display_val = hf_av;
					display_max = hf_max;
				} else {
					display_val = lf_av;
					display_max = lf_max;
				}
			}
			for (i=0; i<LIGHT_LEN; i++) {
				if (display_val >= ((display_max/LIGHT_LEN)*i) && display_val <= ((display_max/LIGHT_LEN)*(i+1))) {
					if (LIGHT_SCHEME[i] & 0x1) LED_C_ON(); else LED_C_OFF();
					if (LIGHT_SCHEME[i] & 0x2) LED_A_ON(); else LED_A_OFF();
					if (LIGHT_SCHEME[i] & 0x4) LED_B_ON(); else LED_B_OFF();
					if (LIGHT_SCHEME[i] & 0x8) LED_D_ON(); else LED_D_OFF();
					break;
				}
			}
		}
	}
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

		case CMD_READ_TI_TYPE:
			ReadTItag();
			break;

		case CMD_WRITE_TI_TYPE:
			WriteTItag(c->ext1,c->ext2,c->ext3);
			break;

		case CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K: {
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
		case CMD_READ_MEM:
			ReadMem(c->ext1);
			break;
		case CMD_SET_LF_DIVISOR:
			FpgaSendCommand(FPGA_CMD_SET_DIVISOR, c->ext1);
			break;
		case CMD_VERSION:
			SendVersion();
			break;
		case CMD_LF_SIMULATE_BIDIR:
			SimulateTagLowFrequencyBidir(c->ext1, c->ext2);
			break;
#ifdef WITH_LCD
		case CMD_LCD_RESET:
			LCDReset();
			break;
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
		UsbPoll(FALSE);
		WDT_HIT();

		if (BUTTON_HELD(1000) > 0)
			SamyRun();
	}
}
