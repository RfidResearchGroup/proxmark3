/*
 * LEGIC RF simulation code
 *  
 * (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
 */

#include <proxmark3.h>

#include "apps.h"
#include "legicrf.h"
#include <stdint.h>

#include "legic_prng.h"
#include "crc.h"

static struct legic_frame {
	int bits;
	uint32_t data;
} current_frame;

static crc_t legic_crc;

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
static void frame_send_rwd(uint32_t data, int bits)
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

		if(bit ^ legic_prng_get_bit()) {
			bit_end = starttime + RWD_TIME_1;
		} else {
			bit_end = starttime + RWD_TIME_0;
		}
		
		/* RWD_TIME_PAUSE time off, then some time on, so that the complete bit time is
		 * RWD_TIME_x, where x is the bit to be transmitted */
		AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
		while(timer->TC_CV < pause_end) ;
		AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;
		legic_prng_forward(1); /* bit duration is longest. use this time to forward the lfsr */
		
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
	while(timer->TC_CV > 1) ; /* Wait till the clock has reset */
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
static void frame_receive_rwd(struct legic_frame * const f, int bits, int crypt)
{
	uint32_t the_bit = 1;  /* Use a bitmask to save on shifts */
	uint32_t data=0;
	int i, old_level=0, edges=0;
	int next_bit_at = TAG_TIME_WAIT;
	
	
	if(bits > 16)
		bits = 16;

	AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_DIN;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DIN;

	/* we have some time now, precompute the cipher
         * since we cannot compute it on the fly while reading */
	legic_prng_forward(2);

	if(crypt)
	{
		for(i=0; i<bits; i++) {
			data |= legic_prng_get_bit() << i;
			legic_prng_forward(1);
		}
	}

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
			data ^= the_bit;
		}

		the_bit <<= 1;
	}
	
	f->data = data;
	f->bits = bits;
	
	/* Reset the timer, to synchronize the next frame */
	timer->TC_CCR = AT91C_TC_SWTRG;
	while(timer->TC_CV > 1) ; /* Wait till the clock has reset */
}

static void frame_clean(struct legic_frame * const f)
{
	f->data = 0;
	f->bits = 0;
}

static uint32_t perform_setup_phase_rwd(int iv)
{
	
	/* Switch on carrier and let the tag charge for 1ms */
	AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;
	SpinDelay(1);
	
	legic_prng_init(0); /* no keystream yet */
	frame_send_rwd(iv, 7);
        legic_prng_init(iv);
	
	frame_clean(&current_frame);
	frame_receive_rwd(&current_frame, 6, 1);
	legic_prng_forward(1); /* we wait anyways */
	while(timer->TC_CV < 387) ; /* ~ 258us */
	frame_send_rwd(0x19, 6);

	return current_frame.data;
}

static void LegicCommonInit(void) {
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX);
	
	/* Bitbang the transmitter */
	AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
	
	setup_timer();
	
	crc_init(&legic_crc, 4, 0x19 >> 1, 0x5, 0);
}

static void switch_off_tag_rwd(void)
{
	/* Switch off carrier, make sure tag is reset */
	AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
	SpinDelay(10);
	
	WDT_HIT();
}
/* calculate crc for a legic command */
static int LegicCRC(int byte_index, int value, int cmd_sz) {
	crc_clear(&legic_crc);
	crc_update(&legic_crc, 1, 1); /* CMD_READ */
	crc_update(&legic_crc, byte_index, cmd_sz-1);
	crc_update(&legic_crc, value, 8);
	return crc_finish(&legic_crc);
}

int legic_read_byte(int byte_index, int cmd_sz) {
	int byte;

	legic_prng_forward(4); /* we wait anyways */
    	while(timer->TC_CV < 387) ; /* ~ 258us + 100us*delay */

	frame_send_rwd(1 | (byte_index << 1), cmd_sz);
	frame_clean(&current_frame);

	frame_receive_rwd(&current_frame, 12, 1);

	byte = current_frame.data & 0xff;
	if( LegicCRC(byte_index, byte, cmd_sz) != (current_frame.data >> 8) ) {
		Dbprintf("!!! crc mismatch: expected %x but got %x !!!", LegicCRC(byte_index, current_frame.data & 0xff, cmd_sz), current_frame.data >> 8);
		return -1;
	}

	return byte;
}

/* legic_write_byte() is not included, however it's trivial to implement
 * and here are some hints on what remains to be done:
 *
 *  * assemble a write_cmd_frame with crc and send it
 *  * wait until the tag sends back an ACK ('1' bit unencrypted)
 *  * forward the prng based on the timing
 */


void LegicRfReader(int offset, int bytes) {
	int byte_index=0, cmd_sz=0, card_sz=0;
	
	LegicCommonInit();

	memset(BigBuf, 0, 1024);
	
	DbpString("setting up legic card");
	uint32_t tag_type = perform_setup_phase_rwd(0x55);
	switch(tag_type) {
		case 0x1d:
			DbpString("MIM 256 card found, reading card ...");
	                cmd_sz = 9;
			card_sz = 256;
			break;
		case 0x3d:
			DbpString("MIM 1024 card found, reading card ...");
	                cmd_sz = 11;
			card_sz = 1024;
			break;
		default:
			Dbprintf("Unknown card format: %x",tag_type);
 			switch_off_tag_rwd();
	                return;
	}
	if(bytes == -1) {
		bytes = card_sz;
	}
        if(bytes+offset >= card_sz) {
		bytes = card_sz-offset;
        }

	switch_off_tag_rwd(); //we lost to mutch time with dprintf
	perform_setup_phase_rwd(0x55);

	while(byte_index < bytes) {
                int r = legic_read_byte(byte_index+offset, cmd_sz);
                if(r == -1) {
			Dbprintf("aborting");
 			switch_off_tag_rwd();
	                return;
		}
		((uint8_t*)BigBuf)[byte_index] = r;
		byte_index++;
	}
	switch_off_tag_rwd();
	Dbprintf("Card read, use 'hf legic decode' or 'data hexsamples %d' to view results", (bytes+7) & ~7);
}

