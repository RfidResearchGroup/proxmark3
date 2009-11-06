/*
 * LEGIC RF simulation code
 *  
 * (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
 */

#include <proxmark3.h>

#include "apps.h"
#include "legicrf.h"
#include "unistd.h"
#include "stdint.h"

static struct legic_frame {
	int bits;
	uint16_t data;
} current_frame;
AT91PS_TC timer;

static void setup_timer(void)
{
	/* Set up Timer 1 to use for measuring time between pulses. Since we're bit-banging
	 * this it won't be terribly accurate but should be good enough.
	 */
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC1);
	timer = AT91C_BASE_TC1;
	timer->TC_CCR = AT91C_TC_CLKDIS;
	timer->TC_CMR = TC_CMR_TCCLKS_TIMER_CLOCK3;
	timer->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

/* At TIMER_CLOCK3 (MCK/32) */
#define	RWD_TIME_1 150     /* RWD_TIME_PAUSE off, 80us on = 100us */
#define RWD_TIME_0 90      /* RWD_TIME_PAUSE off, 40us on = 60us */
#define RWD_TIME_PAUSE 30  /* 20us */
#define RWD_TIME_FUZZ 20   /* rather generous 13us, since the peak detector + hysteresis fuzz quite a bit */
#define TAG_TIME_BIT 150   /* 100us for every bit */
#define TAG_TIME_WAIT 490  /* time from RWD frame end to tag frame start, experimentally determined */

}

#define FUZZ_EQUAL(value, target, fuzz) ((value) > ((target)-(fuzz)) && (value) < ((target)+(fuzz)))

static const struct legic_frame queries[] = {
		{7, 0x55}, /* 1010 101 */
};

static const struct legic_frame responses[] = {
		{6, 0x3b}, /* 1101 11 */
};

/* Send a frame in tag mode, the FPGA must have been set up by
 * LegicRfSimulate
 */
static void frame_send_tag(uint16_t response, int bits)
{
#if 0
	/* Use the SSC to send a response. 8-bit transfers, LSBit first, 100us per bit */
#else 
	/* Bitbang the response */
	AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
	
	/* Wait for the frame start */
	while(timer->TC_CV < TAG_TIME_WAIT) ;
	
	int i;
	for(i=0; i<bits; i++) {
		int nextbit = timer->TC_CV + TAG_TIME_BIT;
		int bit = response & 1;
		response = response >> 1;
		if(bit) 
			AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;
		else
			AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
		while(timer->TC_CV < nextbit) ;
	}
	AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
#endif
}

/* Send a frame in reader mode, the FPGA must have been set up by
 * LegicRfReader
 */
static void frame_send_rwd(uint16_t data, int bits)
{
	/* Start clock */
	timer->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
	while(timer->TC_CV > 1) ; /* Wait till the clock has reset */
	
	int i;
	for(i=0; i<bits; i++) {
		int starttime = timer->TC_CV;
		int pause_end = starttime + RWD_TIME_PAUSE, bit_end;
		int bit = data & 1;
		data = data >> 1;
		
		if(bit) {
			bit_end = starttime + RWD_TIME_1;
		} else {
			bit_end = starttime + RWD_TIME_0;
		}
		
		/* RWD_TIME_PAUSE time off, then some time on, so that the complete bit time is
		 * RWD_TIME_x, where x is the bit to be transmitted */
		AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
		while(timer->TC_CV < pause_end) ;
		AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;
		while(timer->TC_CV < bit_end) ;
	}
	
	{
		/* One final pause to mark the end of the frame */
		int pause_end = timer->TC_CV + RWD_TIME_PAUSE;
		AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
		while(timer->TC_CV < pause_end) ;
		AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;
	}
	
	/* Reset the timer, to measure time until the start of the tag frame */
	timer->TC_CCR = AT91C_TC_SWTRG;
}

/* Receive a frame from the card in reader emulation mode, the FPGA and
 * timer must have been set up by LegicRfReader and frame_send_rwd.
 * 
 * The LEGIC RF protocol from card to reader does not include explicit
 * frame start/stop information or length information. The reader must
 * know beforehand how many bits it wants to receive. (Notably: a card
 * sending a stream of 0-bits is indistinguishable from no card present.)
 * 
 * Receive methodology: There is a fancy correlator in hi_read_rx_xcorr, but
 * I'm not smart enough to use it. Instead I have patched hi_read_tx to output
 * the ADC signal with hysteresis on SSP_DIN. Bit-bang that signal and look
 * for edges. Count the edges in each bit interval. If they are approximately
 * 0 this was a 0-bit, if they are approximately equal to the number of edges
 * expected for a 212kHz subcarrier, this was a 1-bit. For timing we use the
 * timer that's still running from frame_send_rwd in order to get a synchronization
 * with the frame that we just sent.
 * 
 * FIXME: Because we're relying on the hysteresis to just do the right thing 
 * the range is severely reduced (and you'll probably also need a good antenna).
 * So this should be fixed some time in the future for a proper receiver. 
 */
static void frame_receive_rwd(struct legic_frame * const f, int bits)
{
	uint16_t the_bit = 1;  /* Use a bitmask to save on shifts */
	uint16_t data=0;
	int i, old_level=0, edges=0;
	int next_bit_at = TAG_TIME_WAIT;
	
	
	if(bits > 16)
		bits = 16;

	AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_DIN;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DIN;

	while(timer->TC_CV < next_bit_at) ;
	next_bit_at += TAG_TIME_BIT;
	
	for(i=0; i<bits; i++) {
		edges = 0;
		while(timer->TC_CV < next_bit_at) {
			int level = (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN);
			if(level != old_level)
				edges++;
			old_level = level;
		}
		next_bit_at += TAG_TIME_BIT;
		
		if(edges > 20 && edges < 60) { /* expected are 42 edges */
			data |= the_bit;
		}
		
		
		the_bit <<= 1;
	}
	
	f->data = data;
	f->bits = bits;
}

/* Figure out a response to a frame in tag mode */
static void frame_respond_tag(struct legic_frame const * const f)
{
	LED_D_ON();
	int i, r_size;
	uint16_t r_data;
	
	for(i=0; i<sizeof(queries)/sizeof(queries[0]); i++) {
		if(f->bits == queries[i].bits && f->data == queries[i].data) {
			r_data = responses[i].data;
			r_size = responses[i].bits;
			break;
		}
	}
	
	if(r_size != 0) {
		frame_send_tag(r_data, r_size);
		LED_A_ON();
	} else {
		LED_A_OFF();
	}
	
	LED_D_OFF();
}

static void frame_append_bit(struct legic_frame * const f, int bit)
{
	if(f->bits >= 15)
		return; /* Overflow, won't happen */
	f->data |= (bit<<f->bits);
	f->bits++;
}

static int frame_is_empty(struct legic_frame const * const f)
{
	return( f->bits <= 4 );
}

/* Handle (whether to respond) a frame in tag mode */
static void frame_handle_tag(struct legic_frame const * const f)
{
	if(f->bits == 6) {
		/* Short path */
		return;
	}
	if( !frame_is_empty(f) ) {
		frame_respond_tag(f);
	}
}

static void frame_clean(struct legic_frame * const f)
{
	f->data = 0;
	f->bits = 0;
}

enum emit_mode { 
	EMIT_RWD, /* Emit in tag simulation mode, e.g. the source is the RWD */
	EMIT_TAG  /* Emit in reader simulation mode, e.g. the source is the TAG */
}; 
static void emit(enum emit_mode mode, int bit)
{
	if(bit == -1) {
		if(mode == EMIT_RWD) {
			frame_handle_tag(&current_frame);
		}
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
	
	setup_timer();
	
	int old_level = 0;
	int active = 0;
	
	while(!BUTTON_PRESS()) {
		int level = !!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN);
		int time = timer->TC_CV;
		
		if(level != old_level) {
			if(level == 1) {
				timer->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
				if(FUZZ_EQUAL(time, RWD_TIME_1, RWD_TIME_FUZZ)) {
					/* 1 bit */
					emit(EMIT_RWD, 1);
					active = 1;
					LED_B_ON();
				} else if(FUZZ_EQUAL(time, RWD_TIME_0, RWD_TIME_FUZZ)) {
					/* 0 bit */
					emit(EMIT_RWD, 0);
					active = 1;
					LED_B_ON();
				} else if(active) {
					/* invalid */
					emit(EMIT_RWD, -1);
					active = 0;
					LED_B_OFF();
				}
			}
		}
		
		if(time >= (RWD_TIME_1+RWD_TIME_FUZZ) && active) {
			/* Frame end */
			emit(EMIT_RWD, -1);
			active = 0;
			LED_B_OFF();
		}
		
		if(time >= (20*RWD_TIME_1) && (timer->TC_SR & AT91C_TC_CLKSTA)) {
			timer->TC_CCR = AT91C_TC_CLKDIS;
		}
		
		
		old_level = level;
		WDT_HIT();
	}
}

void LegicRfReader(void)
{
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX);
	
	/* Bitbang the transmitter */
	AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
	
	setup_timer();
	
	while(!BUTTON_PRESS()) {
		/* Switch on carrier and let the tag charge for 1ms */
		AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;
		SpinDelay(1);
		
		LED_A_ON();
		frame_send_rwd(queries[0].data, queries[0].bits);
		LED_A_OFF();
		
		frame_clean(&current_frame);
		LED_B_ON();
		frame_receive_rwd(&current_frame, responses[0].bits);
		LED_B_OFF();
		
		/* Switch off carrier, make sure tag is reset */
		AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
		SpinDelay(10);
		
		WDT_HIT();
	}
	
}
