/*
 * LEGIC RF simulation code
 *  
 * (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
 */

#include <proxmark3.h>

#include "apps.h"
#include "legicrf.h"

static struct legic_frame {
	int num_bytes;
	int num_bits;
	char data[10];
} current_frame;
static char response = 0x2b; /* 1101 01 */

static void frame_send(char *response, int num_bytes, int num_bits)
{
#if 0
	/* Use the SSC to send a response. 8-bit transfers, LSBit first, 100us per bit */
#else 
	/* Bitbang the response */
	AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
	
	/* Wait for the frame start */
	while(AT91C_BASE_TC1->TC_CV < 490) ;
	
	int i;
	for(i=0; i<(num_bytes*8+num_bits); i++) {
		int nextbit = AT91C_BASE_TC1->TC_CV + 150;
		int bit = response[i/8] & (1<<(i%8));
		if(bit) 
			AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;
		else
			AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
		while(AT91C_BASE_TC1->TC_CV < nextbit) ;
	}
	AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
#endif
}

static void frame_respond(struct legic_frame *f)
{
	LED_D_ON();
	if(f->num_bytes == 0 && f->num_bits == 7) {
		/* This seems to be the initial dialogue, just send 6 bits of static data */
		frame_send(&response, 0, 6);
	}
	LED_D_OFF();
}

static void frame_append_bit(struct legic_frame *f, int bit)
{
	if(f->num_bytes >= (int)sizeof(f->data))
		return; /* Overflow, won't happen */
	f->data[f->num_bytes] |= (bit<<f->num_bits);
	f->num_bits++;
	if(f->num_bits > 7) {
		f->num_bits = 0;
		f->num_bytes++;
	}
}

static int frame_is_empty(struct legic_frame *f)
{
	return( (f->num_bytes + f->num_bits) <= 4 );
}

static void frame_handle(struct legic_frame *f)
{
	if( !frame_is_empty(f) ) {
		frame_respond(f);
	}
}

static void frame_clean(struct legic_frame *f)
{
	if(!frame_is_empty(f)) 
		memset(f->data, 0, sizeof(f->data));
	f->num_bits = 0;
	f->num_bytes = 0;
}

static void emit(int bit)
{
	if(bit == -1) {
		frame_handle(&current_frame);
		frame_clean(&current_frame);
	} else if(bit == 0) {
		frame_append_bit(&current_frame, 0);
	} else if(bit == 1) {
		frame_append_bit(&current_frame, 1);
	}
}

void LegicRfSimulate(void)
{
	/* ADC path high-frequency peak detector, FPGA in high-frequency simulator mode, 
	 * modulation mode set to 212kHz subcarrier. We are getting the incoming raw
	 * envelope waveform on DIN and should send our response on DOUT.
	 * 
	 * The LEGIC RF protocol is pulse-pause-encoding from reader to card, so we'll
	 * measure the time between two rising edges on DIN, and no encoding on the
	 * subcarrier from card to reader, so we'll just shift out our verbatim data
	 * on DOUT, 1 bit is 100us. The time from reader to card frame is still unclear,
	 * seems to be 300us-ish.
	 */
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_212K);
	
	/* Bitbang the receiver */
	AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_DIN;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DIN;
	
	/* Set up Timer 1 to use for measuring time between pulses. Since we're bit-banging
	 * this it won't be terribly accurate but should be good enough.
	 */
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC1);
	AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
	AT91C_BASE_TC1->TC_CMR = TC_CMR_TCCLKS_TIMER_CLOCK3;
	AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
	int old_level = 0;

/* At TIMER_CLOCK3 (MCK/32) */
#define	BIT_TIME_1 150
#define BIT_TIME_0 90
#define BIT_TIME_FUZZ 20
	
	int active = 0;
	while(!BUTTON_PRESS()) {
		int level = !!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN);
		int time = AT91C_BASE_TC1->TC_CV;
		
		if(level != old_level) {
			if(level == 1) {
				AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
				if(time > (BIT_TIME_1-BIT_TIME_FUZZ) && time < (BIT_TIME_1+BIT_TIME_FUZZ)) {
					/* 1 bit */
					emit(1);
					active = 1;
				} else if(time > (BIT_TIME_0-BIT_TIME_FUZZ) && time < (BIT_TIME_0+BIT_TIME_FUZZ)) {
					/* 0 bit */
					emit(0);
					active = 0;
				} else {
					/* invalid */
					emit(-1);
					active = 0;
				}
			}
		}
		
		if(time >= (BIT_TIME_1+2*BIT_TIME_FUZZ) && active) {
			/* Frame end */
			emit(-1);
			active = 0;
		}
		
		if(time >= (20*BIT_TIME_1) && (AT91C_BASE_TC1->TC_SR & AT91C_TC_CLKSTA)) {
			AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;
		}
		
		
		old_level = level;
		WDT_HIT();
	}
}
