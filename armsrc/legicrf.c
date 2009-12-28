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

static void frame_clean(struct legic_frame * const f)
{
	f->data = 0;
	f->bits = 0;
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
