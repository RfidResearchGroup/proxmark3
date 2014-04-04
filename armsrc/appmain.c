//-----------------------------------------------------------------------------
// Jonathan Westhues, Mar 2006
// Edits by Gerhard de Koning Gans, Sep 2007 (##)
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// The main application code. This is the first thing called after start.c
// executes.
//-----------------------------------------------------------------------------

#include "usb_cdc.h"
#include "cmd.h"

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "printf.h"
#include "string.h"

#include <stdarg.h>

#include "legicrf.h"
#include <hitag2.h>

#ifdef WITH_LCD
 #include "LCD.h"
#endif

#define abs(x) ( ((x)<0) ? -(x) : (x) )

//=============================================================================
// A buffer where we can queue things up to be sent through the FPGA, for
// any purpose (fake tag, as reader, whatever). We go MSB first, since that
// is the order in which they go out on the wire.
//=============================================================================

uint8_t ToSend[512];
int ToSendMax;
static int ToSendBit;
struct common_area common_area __attribute__((section(".commonarea")));

void BufferClear(void)
{
	memset(BigBuf,0,sizeof(BigBuf));
	Dbprintf("Buffer cleared (%i bytes)",sizeof(BigBuf));
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
  byte_t len = strlen(str);
  cmd_send(CMD_DEBUG_PRINT_STRING,len,0,0,(byte_t*)str,len);
//	/* this holds up stuff unless we're connected to usb */
//	if (!UsbConnected())
//		return;
//
//	UsbCommand c;
//	c.cmd = CMD_DEBUG_PRINT_STRING;
//	c.arg[0] = strlen(str);
//	if(c.arg[0] > sizeof(c.d.asBytes)) {
//		c.arg[0] = sizeof(c.d.asBytes);
//	}
//	memcpy(c.d.asBytes, str, c.arg[0]);
//
//	UsbSendPacket((uint8_t *)&c, sizeof(c));
//	// TODO fix USB so stupid things like this aren't req'd
//	SpinDelay(50);
}

#if 0
void DbpIntegers(int x1, int x2, int x3)
{
  cmd_send(CMD_DEBUG_PRINT_INTEGERS,x1,x2,x3,0,0);
//	/* this holds up stuff unless we're connected to usb */
//	if (!UsbConnected())
//		return;
//
//	UsbCommand c;
//	c.cmd = CMD_DEBUG_PRINT_INTEGERS;
//	c.arg[0] = x1;
//	c.arg[1] = x2;
//	c.arg[2] = x3;
//
//	UsbSendPacket((uint8_t *)&c, sizeof(c));
//	// XXX
//	SpinDelay(50);
}
#endif

void Dbprintf(const char *fmt, ...) {
// should probably limit size here; oh well, let's just use a big buffer
	char output_string[128];
	va_list ap;

	va_start(ap, fmt);
	kvsprintf(fmt, output_string, 10, ap);
	va_end(ap);

	DbpString(output_string);
}

// prints HEX & ASCII
void Dbhexdump(int len, uint8_t *d, bool bAsci) {
	int l=0,i;
	char ascii[9];
    
	while (len>0) {
		if (len>8) l=8;
		else l=len;
		
		memcpy(ascii,d,l);
		ascii[l]=0;
		
		// filter safe ascii
		for (i=0;i<l;i++)
			if (ascii[i]<32 || ascii[i]>126) ascii[i]='.';
        
		if (bAsci) {
			Dbprintf("%-8s %*D",ascii,l,d," ");
		} else {
			Dbprintf("%*D",l,d," ");
		}
        
		len-=8;
		d+=8;		
	}
}

//-----------------------------------------------------------------------------
// Read an ADC channel and block till it completes, then return the result
// in ADC units (0 to 1023). Also a routine to average 32 samples and
// return that.
//-----------------------------------------------------------------------------
static int ReadAdc(int ch)
{
	uint32_t d;

	AT91C_BASE_ADC->ADC_CR = AT91C_ADC_SWRST;
	AT91C_BASE_ADC->ADC_MR =
		ADC_MODE_PRESCALE(32) |
		ADC_MODE_STARTUP_TIME(16) |
		ADC_MODE_SAMPLE_HOLD_TIME(8);
	AT91C_BASE_ADC->ADC_CHER = ADC_CHANNEL(ch);

	AT91C_BASE_ADC->ADC_CR = AT91C_ADC_START;
	while(!(AT91C_BASE_ADC->ADC_SR & ADC_END_OF_CONVERSION(ch)))
		;
	d = AT91C_BASE_ADC->ADC_CDR[ch];

	return d;
}

int AvgAdc(int ch) // was static - merlok
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
	uint8_t *dest = (uint8_t *)BigBuf+FREE_BUFFER_OFFSET;
	int i, adcval = 0, peak = 0, peakv = 0, peakf = 0; //ptr = 0 
	int vLf125 = 0, vLf134 = 0, vHf = 0;	// in mV

//	UsbCommand c;

  LED_B_ON();
	DbpString("Measuring antenna characteristics, please wait...");
	memset(dest,0,sizeof(FREE_BUFFER_SIZE));

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
    WDT_HIT();
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
			//ptr = i;
		}
	}

  LED_A_ON();
	// Let the FPGA drive the high-frequency antenna around 13.56 MHz.
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
	SpinDelay(20);
	// Vref = 3300mV, and an 10:1 voltage divider on the input
	// can measure voltages up to 33000 mV
	vHf = (33000 * AvgAdc(ADC_CHAN_HF)) >> 10;

//	c.cmd = CMD_MEASURED_ANTENNA_TUNING;
//	c.arg[0] = (vLf125 << 0) | (vLf134 << 16);
//	c.arg[1] = vHf;
//	c.arg[2] = peakf | (peakv << 16);

  DbpString("Measuring complete, sending report back to host");
  cmd_send(CMD_MEASURED_ANTENNA_TUNING,vLf125|(vLf134<<16),vHf,peakf|(peakv<<16),0,0);
//	UsbSendPacket((uint8_t *)&c, sizeof(c));
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
  LED_A_OFF();
  LED_B_OFF();
  return;
}

void MeasureAntennaTuningHf(void)
{
	int vHf = 0;	// in mV

	DbpString("Measuring HF antenna, press button to exit");

	for (;;) {
		// Let the FPGA drive the high-frequency antenna around 13.56 MHz.
		FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR);
		SpinDelay(20);
		// Vref = 3300mV, and an 10:1 voltage divider on the input
		// can measure voltages up to 33000 mV
		vHf = (33000 * AvgAdc(ADC_CHAN_HF)) >> 10;

		Dbprintf("%d mV",vHf);
		if (BUTTON_PRESS()) break;
	}
	DbpString("cancelled");
}


void SimulateTagHfListen(void)
{
	uint8_t *dest = (uint8_t *)BigBuf+FREE_BUFFER_OFFSET;
	uint8_t v = 0;
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
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0xff;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			uint8_t r = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

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

				if(i >= FREE_BUFFER_SIZE) {
					break;
				}
			}
		}
	}
	DbpString("simulate tag (now type bitsamples)");
}

void ReadMem(int addr)
{
	const uint8_t *data = ((uint8_t *)addr);

	Dbprintf("%x: %02x %02x %02x %02x %02x %02x %02x %02x",
		addr, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
}

/* osimage version information is linked in */
extern struct version_information version_information;
/* bootrom version information is pointed to from _bootphase1_version_pointer */
extern char *_bootphase1_version_pointer, _flash_start, _flash_end;
void SendVersion(void)
{
	char temp[256]; /* Limited data payload in USB packets */
	DbpString("Prox/RFID mark3 RFID instrument");

	/* Try to find the bootrom version information. Expect to find a pointer at
	 * symbol _bootphase1_version_pointer, perform slight sanity checks on the
	 * pointer, then use it.
	 */
	char *bootrom_version = *(char**)&_bootphase1_version_pointer;
	if( bootrom_version < &_flash_start || bootrom_version >= &_flash_end ) {
		DbpString("bootrom version information appears invalid");
	} else {
		FormatVersionInformation(temp, sizeof(temp), "bootrom: ", bootrom_version);
		DbpString(temp);
	}

	FormatVersionInformation(temp, sizeof(temp), "os: ", &version_information);
	DbpString(temp);

	FpgaGatherVersion(temp, sizeof(temp));
	DbpString(temp);
	// Send Chip ID
	cmd_send(CMD_ACK,*(AT91C_DBGU_CIDR),0,0,NULL,0);
}

#ifdef WITH_LF
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
//		UsbPoll(FALSE);
		usb_poll();
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
			Dbprintf("Recorded %x %x %x", selected, high[selected], low[selected]);

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
				Dbprintf("%x %x %x", selected, high[selected], low[selected]);
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
#endif

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
		Dbprintf("LF 125/134 Baseline: %d", lf_av);
		lf_baseline = lf_av;
	}

	hf_av=hf_max=ReadAdc(ADC_CHAN_HF);

	if (limit != LF_ONLY) {
		Dbprintf("HF 13.56 Baseline: %d", hf_av);
		hf_baseline = hf_av;
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
				Dbprintf("LF 125/134 Field Change: %x %x %x", lf_av, lf_av_new, lf_count);
				lf_av = lf_av_new;
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
				Dbprintf("HF 13.56 Field Change: %x %x %x", hf_av, hf_av_new, hf_count);
				hf_av = hf_av_new;
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

void UsbPacketReceived(uint8_t *packet, int len)
{
	UsbCommand *c = (UsbCommand *)packet;

//  Dbprintf("received %d bytes, with command: 0x%04x and args: %d %d %d",len,c->cmd,c->arg[0],c->arg[1],c->arg[2]);
  
	switch(c->cmd) {
#ifdef WITH_LF
		case CMD_ACQUIRE_RAW_ADC_SAMPLES_125K:
			AcquireRawAdcSamples125k(c->arg[0]);
			cmd_send(CMD_ACK,0,0,0,0,0);
			break;
		case CMD_MOD_THEN_ACQUIRE_RAW_ADC_SAMPLES_125K:
			ModThenAcquireRawAdcSamples125k(c->arg[0],c->arg[1],c->arg[2],c->d.asBytes);
			break;
		case CMD_HID_DEMOD_FSK:
			CmdHIDdemodFSK(0, 0, 0, 1);					// Demodulate HID tag
			break;
		case CMD_HID_SIM_TAG:
			CmdHIDsimTAG(c->arg[0], c->arg[1], 1);					// Simulate HID tag by ID
			break;
		case CMD_HID_CLONE_TAG: // Clone HID tag by ID to T55x7
			CopyHIDtoT55x7(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes[0]);
			break;
		case CMD_IO_DEMOD_FSK:
			CmdIOdemodFSK(1, 0, 0, 1);					// Demodulate IO tag
			break;
		case CMD_IO_CLONE_TAG: // Clone IO tag by ID to T55x7
			CopyIOtoT55x7(c->arg[0], c->arg[1], c->d.asBytes[0]);
			break;
		case CMD_EM410X_WRITE_TAG:
			WriteEM410x(c->arg[0], c->arg[1], c->arg[2]);
			break;
		case CMD_READ_TI_TYPE:
			ReadTItag();
			break;
		case CMD_WRITE_TI_TYPE:
			WriteTItag(c->arg[0],c->arg[1],c->arg[2]);
			break;
		case CMD_SIMULATE_TAG_125K:
			LED_A_ON();
			SimulateTagLowFrequency(c->arg[0], c->arg[1], 1);
			LED_A_OFF();
			break;
		case CMD_LF_SIMULATE_BIDIR:
			SimulateTagLowFrequencyBidir(c->arg[0], c->arg[1]);
			break;
		case CMD_INDALA_CLONE_TAG:					// Clone Indala 64-bit tag by UID to T55x7
			CopyIndala64toT55x7(c->arg[0], c->arg[1]);					
			break;
		case CMD_INDALA_CLONE_TAG_L:					// Clone Indala 224-bit tag by UID to T55x7
			CopyIndala224toT55x7(c->d.asDwords[0], c->d.asDwords[1], c->d.asDwords[2], c->d.asDwords[3], c->d.asDwords[4], c->d.asDwords[5], c->d.asDwords[6]);
			break;
		case CMD_T55XX_READ_BLOCK:
			T55xxReadBlock(c->arg[1], c->arg[2],c->d.asBytes[0]);
			break;
		case CMD_T55XX_WRITE_BLOCK:
			T55xxWriteBlock(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes[0]);
			break;
		case CMD_T55XX_READ_TRACE: // Clone HID tag by ID to T55x7
			T55xxReadTrace();
			break;
		case CMD_PCF7931_READ: // Read PCF7931 tag
			ReadPCF7931();
			cmd_send(CMD_ACK,0,0,0,0,0);
//      	UsbSendPacket((uint8_t*)&ack, sizeof(ack));
			break;
		case CMD_EM4X_READ_WORD:
			EM4xReadWord(c->arg[1], c->arg[2],c->d.asBytes[0]);
			break;
		case CMD_EM4X_WRITE_WORD:
			EM4xWriteWord(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes[0]);
			break;
#endif

#ifdef WITH_HITAG
		case CMD_SNOOP_HITAG: // Eavesdrop Hitag tag, args = type
			SnoopHitag(c->arg[0]);
			break;
		case CMD_SIMULATE_HITAG: // Simulate Hitag tag, args = memory content
			SimulateHitagTag((bool)c->arg[0],(byte_t*)c->d.asBytes);
			break;
		case CMD_READER_HITAG: // Reader for Hitag tags, args = type and function
			ReaderHitag((hitag_function)c->arg[0],(hitag_data*)c->d.asBytes);
			break;
#endif
            
#ifdef WITH_ISO15693
		case CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693:
			AcquireRawAdcSamplesIso15693();
			break;
		case CMD_RECORD_RAW_ADC_SAMPLES_ISO_15693:
			RecordRawAdcSamplesIso15693();
			break;
			
		case CMD_ISO_15693_COMMAND:
			DirectTag15693Command(c->arg[0],c->arg[1],c->arg[2],c->d.asBytes);
			break;
					
		case CMD_ISO_15693_FIND_AFI:
			BruteforceIso15693Afi(c->arg[0]);
			break;	
			
		case CMD_ISO_15693_DEBUG:
			SetDebugIso15693(c->arg[0]);
			break;

		case CMD_READER_ISO_15693:
			ReaderIso15693(c->arg[0]);
			break;
		case CMD_SIMTAG_ISO_15693:
			SimTagIso15693(c->arg[0]);
			break;
#endif

#ifdef WITH_LEGICRF
		case CMD_SIMULATE_TAG_LEGIC_RF:
			LegicRfSimulate(c->arg[0], c->arg[1], c->arg[2]);
			break;

		case CMD_WRITER_LEGIC_RF:
			LegicRfWriter(c->arg[1], c->arg[0]);
			break;

		case CMD_READER_LEGIC_RF:
			LegicRfReader(c->arg[0], c->arg[1]);
			break;
#endif

#ifdef WITH_ISO14443b
		case CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443:
			AcquireRawAdcSamplesIso14443(c->arg[0]);
			break;
		case CMD_READ_SRI512_TAG:
			ReadSTMemoryIso14443(0x0F);
			break;
		case CMD_READ_SRIX4K_TAG:
			ReadSTMemoryIso14443(0x7F);
			break;
		case CMD_SNOOP_ISO_14443:
			SnoopIso14443();
			break;
		case CMD_SIMULATE_TAG_ISO_14443:
			SimulateIso14443Tag();
			break;
		case CMD_ISO_14443B_COMMAND:
			SendRawCommand14443B(c->arg[0],c->arg[1],c->arg[2],c->d.asBytes);
			break;
#endif

#ifdef WITH_ISO14443a
		case CMD_SNOOP_ISO_14443a:
			SnoopIso14443a(c->arg[0]);
			break;
		case CMD_READER_ISO_14443a:
			ReaderIso14443a(c);
			break;
		case CMD_SIMULATE_TAG_ISO_14443a:
			SimulateIso14443aTag(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);  // ## Simulate iso14443a tag - pass tag type & UID
			break;
		case CMD_EPA_PACE_COLLECT_NONCE:
			EPA_PACE_Collect_Nonce(c);
			break;
			
		case CMD_READER_MIFARE:
            ReaderMifare(c->arg[0]);
			break;
		case CMD_MIFARE_READBL:
			MifareReadBlock(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		case CMD_MIFAREU_READBL:
			MifareUReadBlock(c->arg[0],c->d.asBytes);
			break;
		case CMD_MIFAREU_READCARD:
			MifareUReadCard(c->arg[0],c->d.asBytes);
                        break;
		case CMD_MIFARE_READSC:
			MifareReadSector(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		case CMD_MIFARE_WRITEBL:
			MifareWriteBlock(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		case CMD_MIFAREU_WRITEBL_COMPAT:
			MifareUWriteBlock(c->arg[0], c->d.asBytes);
                        break;
		case CMD_MIFAREU_WRITEBL:
                        MifareUWriteBlock_Special(c->arg[0], c->d.asBytes);
                        break;
		case CMD_MIFARE_NESTED:
			MifareNested(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		case CMD_MIFARE_CHKKEYS:
			MifareChkKeys(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		case CMD_SIMULATE_MIFARE_CARD:
			Mifare1ksim(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		
		// emulator
		case CMD_MIFARE_SET_DBGMODE:
			MifareSetDbgLvl(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		case CMD_MIFARE_EML_MEMCLR:
			MifareEMemClr(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		case CMD_MIFARE_EML_MEMSET:
			MifareEMemSet(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		case CMD_MIFARE_EML_MEMGET:
			MifareEMemGet(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		case CMD_MIFARE_EML_CARDLOAD:
			MifareECardLoad(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
			
		// Work with "magic Chinese" card
		case CMD_MIFARE_EML_CSETBLOCK:
			MifareCSetBlock(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
		case CMD_MIFARE_EML_CGETBLOCK:
			MifareCGetBlock(c->arg[0], c->arg[1], c->arg[2], c->d.asBytes);
			break;
			
		// mifare sniffer
		case CMD_MIFARE_SNIFFER:
			SniffMifare(c->arg[0]);
			break;
#endif

#ifdef WITH_ICLASS
		// Makes use of ISO14443a FPGA Firmware
		case CMD_SNOOP_ICLASS:
			SnoopIClass();
			break;
		case CMD_SIMULATE_TAG_ICLASS:
			SimulateIClass(c->arg[0], c->d.asBytes);
			break;
		case CMD_READER_ICLASS:
			ReaderIClass(c->arg[0]);
			break;
#endif

		case CMD_SIMULATE_TAG_HF_LISTEN:
			SimulateTagHfListen();
			break;

		case CMD_BUFF_CLEAR:
			BufferClear();
			break;

		case CMD_MEASURE_ANTENNA_TUNING:
			MeasureAntennaTuning();
			break;

		case CMD_MEASURE_ANTENNA_TUNING_HF:
			MeasureAntennaTuningHf();
			break;

		case CMD_LISTEN_READER_FIELD:
			ListenReaderField(c->arg[0]);
			break;

		case CMD_FPGA_MAJOR_MODE_OFF:		// ## FPGA Control
			FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
			SpinDelay(200);
			LED_D_OFF(); // LED D indicates field ON or OFF
			break;

		case CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K:
//			UsbCommand n;
//			if(c->cmd == CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K) {
//				n.cmd = CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K;
//			} else {
//				n.cmd = CMD_DOWNLOADED_RAW_BITS_TI_TYPE;
//			}
//			n.arg[0] = c->arg[0];
      //			memcpy(n.d.asBytes, BigBuf+c->arg[0], 48); // 12*sizeof(uint32_t)
      //			LED_B_ON();
      //      usb_write((uint8_t *)&n, sizeof(n));
      //			UsbSendPacket((uint8_t *)&n, sizeof(n));
      //			LED_B_OFF();

			LED_B_ON();
			for(size_t i=0; i<c->arg[1]; i += USB_CMD_DATA_SIZE) {
				size_t len = MIN((c->arg[1] - i),USB_CMD_DATA_SIZE);
				cmd_send(CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K,i,len,0,((byte_t*)BigBuf)+c->arg[0]+i,len);
			}
			// Trigger a finish downloading signal with an ACK frame
			cmd_send(CMD_ACK,0,0,0,0,0);
			LED_B_OFF();
			break;

		case CMD_DOWNLOADED_SIM_SAMPLES_125K: {
			uint8_t *b = (uint8_t *)BigBuf;
			memcpy(b+c->arg[0], c->d.asBytes, 48);
			//Dbprintf("copied 48 bytes to %i",b+c->arg[0]);
//			UsbSendPacket((uint8_t*)&ack, sizeof(ack));
			cmd_send(CMD_ACK,0,0,0,0,0);
			break;
		}	
		case CMD_READ_MEM:
			ReadMem(c->arg[0]);
			break;

		case CMD_SET_LF_DIVISOR:
			FpgaSendCommand(FPGA_CMD_SET_DIVISOR, c->arg[0]);
			break;

		case CMD_SET_ADC_MUX:
			switch(c->arg[0]) {
				case 0: SetAdcMuxFor(GPIO_MUXSEL_LOPKD); break;
				case 1: SetAdcMuxFor(GPIO_MUXSEL_LORAW); break;
				case 2: SetAdcMuxFor(GPIO_MUXSEL_HIPKD); break;
				case 3: SetAdcMuxFor(GPIO_MUXSEL_HIRAW); break;
			}
			break;

		case CMD_VERSION:
			SendVersion();
			break;

#ifdef WITH_LCD
		case CMD_LCD_RESET:
			LCDReset();
			break;
		case CMD_LCD:
			LCDSend(c->arg[0]);
			break;
#endif
		case CMD_SETUP_WRITE:
		case CMD_FINISH_WRITE:
		case CMD_HARDWARE_RESET:
			usb_disable();
			SpinDelay(1000);
			SpinDelay(1000);
			AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
			for(;;) {
				// We're going to reset, and the bootrom will take control.
			}
			break;

		case CMD_START_FLASH:
			if(common_area.flags.bootrom_present) {
				common_area.command = COMMON_AREA_COMMAND_ENTER_FLASH_MODE;
			}
			usb_disable();
			AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
			for(;;);
			break;

		case CMD_DEVICE_INFO: {
			uint32_t dev_info = DEVICE_INFO_FLAG_OSIMAGE_PRESENT | DEVICE_INFO_FLAG_CURRENT_MODE_OS;
			if(common_area.flags.bootrom_present) dev_info |= DEVICE_INFO_FLAG_BOOTROM_PRESENT;
//			UsbSendPacket((uint8_t*)&c, sizeof(c));
			cmd_send(CMD_DEVICE_INFO,dev_info,0,0,0,0);	
			break;
		}
		default:
			Dbprintf("%s: 0x%04x","unknown command:",c->cmd);
			break;
	}
}

void  __attribute__((noreturn)) AppMain(void)
{
	SpinDelay(100);

	if(common_area.magic != COMMON_AREA_MAGIC || common_area.version != 1) {
		/* Initialize common area */
		memset(&common_area, 0, sizeof(common_area));
		common_area.magic = COMMON_AREA_MAGIC;
		common_area.version = 1;
	}
	common_area.flags.osimage_present = 1;

	LED_D_OFF();
	LED_C_OFF();
	LED_B_OFF();
	LED_A_OFF();

  // Init USB device`
  usb_enable();
//	UsbStart();

	// The FPGA gets its clock from us from PCK0 output, so set that up.
	AT91C_BASE_PIOA->PIO_BSR = GPIO_PCK0;
	AT91C_BASE_PIOA->PIO_PDR = GPIO_PCK0;
	AT91C_BASE_PMC->PMC_SCER = AT91C_PMC_PCK0;
	// PCK0 is PLL clock / 4 = 96Mhz / 4 = 24Mhz
	AT91C_BASE_PMC->PMC_PCKR[0] = AT91C_PMC_CSS_PLL_CLK |
		AT91C_PMC_PRES_CLK_4;
	AT91C_BASE_PIOA->PIO_OER = GPIO_PCK0;

	// Reset SPI
	AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SWRST;
	// Reset SSC
	AT91C_BASE_SSC->SSC_CR = AT91C_SSC_SWRST;

	// Load the FPGA image, which we have stored in our flash.
	FpgaDownloadAndGo();

	StartTickCount();
  	
#ifdef WITH_LCD
	LCDInit();
#endif

  byte_t rx[sizeof(UsbCommand)];
	size_t rx_len;
  
	for(;;) {
    if (usb_poll()) {
      rx_len = usb_read(rx,sizeof(UsbCommand));
      if (rx_len) {
        UsbPacketReceived(rx,rx_len);
      }
    }
//		UsbPoll(FALSE);

		WDT_HIT();

#ifdef WITH_LF
		if (BUTTON_HELD(1000) > 0)
			SamyRun();
#endif
	}
}
