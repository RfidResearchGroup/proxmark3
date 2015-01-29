//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC RF simulation code
//-----------------------------------------------------------------------------

#include "../include/proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"

#include "legicrf.h"
#include "../include/legic_prng.h"
#include "../common/crc.h"

static struct legic_frame {
	int bits;
	uint32_t data;
} current_frame;

static enum {
  STATE_DISCON,
  STATE_IV,
  STATE_CON,
} legic_state;

static crc_t    legic_crc;
static int      legic_read_count;
static uint32_t legic_prng_bc;
static uint32_t legic_prng_iv;

static int      legic_phase_drift;
static int      legic_frame_drift;
static int      legic_reqresp_drift;

AT91PS_TC timer;
AT91PS_TC prng_timer;

static void setup_timer(void)
{
	/* Set up Timer 1 to use for measuring time between pulses. Since we're bit-banging
	 * this it won't be terribly accurate but should be good enough.
	 */
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC1);
	timer = AT91C_BASE_TC1;
	timer->TC_CCR = AT91C_TC_CLKDIS;
	timer->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK;
	timer->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

	/* 
     * Set up Timer 2 to use for measuring time between frames in 
     * tag simulation mode. Runs 4x faster as Timer 1
	 */
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC2);
    prng_timer = AT91C_BASE_TC2;
    prng_timer->TC_CCR = AT91C_TC_CLKDIS;
	prng_timer->TC_CMR = AT91C_TC_CLKS_TIMER_DIV2_CLOCK;
    prng_timer->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
}

/* At TIMER_CLOCK3 (MCK/32) */
#define	RWD_TIME_1 150     /* RWD_TIME_PAUSE off, 80us on = 100us */
#define RWD_TIME_0 90      /* RWD_TIME_PAUSE off, 40us on = 60us */
#define RWD_TIME_PAUSE 30  /* 20us */
#define RWD_TIME_FUZZ 20   /* rather generous 13us, since the peak detector + hysteresis fuzz quite a bit */
#define TAG_TIME_BIT 150   /* 100us for every bit */
#define TAG_TIME_WAIT 490  /* time from RWD frame end to tag frame start, experimentally determined */

#define SIM_DIVISOR  586   /* prng_time/SIM_DIVISOR count prng needs to be forwared */
#define SIM_SHIFT    900   /* prng_time+SIM_SHIFT shift of delayed start */

#define SESSION_IV 0x55
#define OFFSET_LOG 1024

#define FUZZ_EQUAL(value, target, fuzz) ((value) > ((target)-(fuzz)) && (value) < ((target)+(fuzz)))

/* Generate Keystream */
static uint32_t get_key_stream(int skip, int count)
{
  uint32_t key=0; int i;

  /* Use int to enlarge timer tc to 32bit */
  legic_prng_bc += prng_timer->TC_CV;
  prng_timer->TC_CCR = AT91C_TC_SWTRG;

  /* If skip == -1, forward prng time based */
  if(skip == -1) {
     i  = (legic_prng_bc+SIM_SHIFT)/SIM_DIVISOR; /* Calculate Cycles based on timer */
     i -= legic_prng_count(); /* substract cycles of finished frames */
     i -= count; /* substract current frame length, rewidn to bedinning */
     legic_prng_forward(i);
  } else {
     legic_prng_forward(skip);
  }

  /* Write Time Data into LOG */
  uint8_t *BigBuf = BigBuf_get_addr();
  if(count == 6) { i = -1; } else { i = legic_read_count; }
  BigBuf[OFFSET_LOG+128+i] = legic_prng_count();
  BigBuf[OFFSET_LOG+256+i*4]   = (legic_prng_bc >> 0) & 0xff;
  BigBuf[OFFSET_LOG+256+i*4+1] = (legic_prng_bc >> 8) & 0xff;
  BigBuf[OFFSET_LOG+256+i*4+2] = (legic_prng_bc >>16) & 0xff;
  BigBuf[OFFSET_LOG+256+i*4+3] = (legic_prng_bc >>24) & 0xff;
  BigBuf[OFFSET_LOG+384+i] = count;

  /* Generate KeyStream */
  for(i=0; i<count; i++) {
    key |= legic_prng_get_bit() << i;
    legic_prng_forward(1);
  }
  return key;
}

/* Send a frame in tag mode, the FPGA must have been set up by
 * LegicRfSimulate
 */
static void frame_send_tag(uint16_t response, int bits, int crypt)
{
   /* Bitbang the response */
   AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
   AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
   AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
        
   /* Use time to crypt frame */
   if(crypt) {
      legic_prng_forward(2); /* TAG_TIME_WAIT -> shift by 2 */
      int i; int key = 0;
      for(i=0; i<bits; i++) {
         key |= legic_prng_get_bit() << i;
         legic_prng_forward(1);
      }
      //Dbprintf("key = 0x%x", key);
      response = response ^ key;
   }

   /* Wait for the frame start */
   while(timer->TC_CV < (TAG_TIME_WAIT - 30)) ;
       
   int i;
   for(i=0; i<bits; i++) {
      int nextbit = timer->TC_CV + TAG_TIME_BIT;
      int bit = response & 1;
      response = response >> 1;
      if(bit) {
         AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;
      } else {
         AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
      }
      while(timer->TC_CV < nextbit) ;
   }
   AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
}

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
	
	if(bits > 32) {
		bits = 32;
    }

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

static void frame_append_bit(struct legic_frame * const f, int bit)
{
   if(f->bits >= 31) {
       return; /* Overflow, won't happen */
   }
   f->data |= (bit<<f->bits);
   f->bits++;
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
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
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
		Dbprintf("!!! crc mismatch: expected %x but got %x !!!", 
           LegicCRC(byte_index, current_frame.data & 0xff, cmd_sz), current_frame.data >> 8);
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
int legic_write_byte(int byte, int addr, int addr_sz) {
    //do not write UID, CRC, DCF
    if(addr <= 0x06) { 
		return 0;
	}

	//== send write command ==============================
	crc_clear(&legic_crc);
	crc_update(&legic_crc, 0, 1); /* CMD_WRITE */
	crc_update(&legic_crc, addr, addr_sz);
	crc_update(&legic_crc, byte, 8);

	uint32_t crc = crc_finish(&legic_crc);
	uint32_t cmd = ((crc     <<(addr_sz+1+8)) //CRC
                   |(byte    <<(addr_sz+1))   //Data
                   |(addr    <<1)             //Address
                   |(0x00    <<0));           //CMD = W
    uint32_t cmd_sz = addr_sz+1+8+4;          //crc+data+cmd

    legic_prng_forward(2); /* we wait anyways */
    while(timer->TC_CV < 387) ; /* ~ 258us */
	frame_send_rwd(cmd, cmd_sz);

	//== wait for ack ====================================
    int t, old_level=0, edges=0;
    int next_bit_at =0;
	while(timer->TC_CV < 387) ; /* ~ 258us */
    for(t=0; t<80; t++) {
        edges = 0;
		next_bit_at += TAG_TIME_BIT;
        while(timer->TC_CV < next_bit_at) {
            int level = (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN);
            if(level != old_level) {
                edges++;
			}
            old_level = level;
        }
        if(edges > 20 && edges < 60) { /* expected are 42 edges */
			int t = timer->TC_CV;
			int c = t/TAG_TIME_BIT;
			timer->TC_CCR = AT91C_TC_SWTRG;
			while(timer->TC_CV > 1) ; /* Wait till the clock has reset */
			legic_prng_forward(c);
        	return 0;
        }
    }
    timer->TC_CCR = AT91C_TC_SWTRG;
    while(timer->TC_CV > 1) ; /* Wait till the clock has reset */
	return -1;
}

int LegicRfReader(int offset, int bytes) {
	int byte_index=0, cmd_sz=0, card_sz=0;

	LegicCommonInit();

	uint8_t *BigBuf = BigBuf_get_addr();
	memset(BigBuf, 0, 1024);

	DbpString("setting up legic card");
	uint32_t tag_type = perform_setup_phase_rwd(SESSION_IV);
	switch_off_tag_rwd(); //we lose to mutch time with dprintf
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
			return -1;
	}
	if(bytes == -1) {
		bytes = card_sz;
	}
	if(bytes+offset >= card_sz) {
		bytes = card_sz-offset;
	}

	perform_setup_phase_rwd(SESSION_IV);

	LED_B_ON();
	while(byte_index < bytes) {
		int r = legic_read_byte(byte_index+offset, cmd_sz);
		if(r == -1 ||BUTTON_PRESS()) {
           	DbpString("operation aborted");
 			switch_off_tag_rwd();
	        LED_B_OFF();
       		LED_C_OFF();
	        return -1;
		}
		BigBuf[byte_index] = r;
        WDT_HIT();
		byte_index++;
		if(byte_index & 0x10) LED_C_ON(); else LED_C_OFF();
	}
	LED_B_OFF();
    LED_C_OFF();
	switch_off_tag_rwd();
	Dbprintf("Card read, use 'hf legic decode' or");
    Dbprintf("'data hexsamples %d' to view results", (bytes+7) & ~7);
    return 0;
}

void LegicRfWriter(int bytes, int offset) {
	int byte_index=0, addr_sz=0;
	uint8_t *BigBuf = BigBuf_get_addr();

	LegicCommonInit();
	
	DbpString("setting up legic card");
	uint32_t tag_type = perform_setup_phase_rwd(SESSION_IV);
	switch_off_tag_rwd();
	switch(tag_type) {
		case 0x1d:
			if(offset+bytes > 0x100) {
				Dbprintf("Error: can not write to 0x%03.3x on MIM 256", offset+bytes);
				return;
			}
			addr_sz = 8;
			Dbprintf("MIM 256 card found, writing 0x%02.2x - 0x%02.2x ...", offset, offset+bytes);
			break;
		case 0x3d:
			if(offset+bytes > 0x400) {
          		Dbprintf("Error: can not write to 0x%03.3x on MIM 1024", offset+bytes);
           		return;
          	}
			addr_sz = 10;
			Dbprintf("MIM 1024 card found, writing 0x%03.3x - 0x%03.3x ...", offset, offset+bytes);
			break;
		default:
			Dbprintf("No or unknown card found, aborting");
            return;
	}

    LED_B_ON();
	perform_setup_phase_rwd(SESSION_IV);
    legic_prng_forward(2);
	while(byte_index < bytes) {
		int r = legic_write_byte(BigBuf[byte_index+offset], byte_index+offset, addr_sz);
		if((r != 0) || BUTTON_PRESS()) {
			Dbprintf("operation aborted @ 0x%03.3x", byte_index);
			switch_off_tag_rwd();
			LED_B_OFF();
			LED_C_OFF();
			return;
		}
        WDT_HIT();
		byte_index++;
        if(byte_index & 0x10) LED_C_ON(); else LED_C_OFF();
	}
    LED_B_OFF();
    LED_C_OFF();
    DbpString("write successful");
}

int timestamp;

/* Handle (whether to respond) a frame in tag mode */
static void frame_handle_tag(struct legic_frame const * const f)
{
	uint8_t *BigBuf = BigBuf_get_addr();

   /* First Part of Handshake (IV) */
   if(f->bits == 7) {
     if(f->data == SESSION_IV) {
        LED_C_ON();
        prng_timer->TC_CCR = AT91C_TC_SWTRG;
        legic_prng_init(f->data);
        frame_send_tag(0x3d, 6, 1); /* 0x3d^0x26 = 0x1b */
        legic_state = STATE_IV;
        legic_read_count = 0;
        legic_prng_bc = 0;
        legic_prng_iv = f->data;
 
        /* TIMEOUT */
        timer->TC_CCR = AT91C_TC_SWTRG;
        while(timer->TC_CV > 1);
        while(timer->TC_CV < 280);
        return;
      } else if((prng_timer->TC_CV % 50) > 40) {
        legic_prng_init(f->data);
        frame_send_tag(0x3d, 6, 1);
        SpinDelay(20);
        return;
     }
   }

   /* 0x19==??? */
   if(legic_state == STATE_IV) {
      if((f->bits == 6) && (f->data == (0x19 ^ get_key_stream(1, 6)))) {
         legic_state = STATE_CON;

         /* TIMEOUT */
         timer->TC_CCR = AT91C_TC_SWTRG;
         while(timer->TC_CV > 1);
         while(timer->TC_CV < 200);
         return;
      } else {
         legic_state = STATE_DISCON;
         LED_C_OFF();
         Dbprintf("0x19 - Frame: %03.3x", f->data);
         return;
      }
   }

   /* Read */
   if(f->bits == 11) {
      if(legic_state == STATE_CON) {
         int key   = get_key_stream(-1, 11); //legic_phase_drift, 11);
         int addr  = f->data ^ key; addr = addr >> 1;
         int data = BigBuf[addr];
         int hash = LegicCRC(addr, data, 11) << 8;
         BigBuf[OFFSET_LOG+legic_read_count] = (uint8_t)addr;
         legic_read_count++;

         //Dbprintf("Data:%03.3x, key:%03.3x, addr: %03.3x, read_c:%u", f->data, key, addr, read_c);
         legic_prng_forward(legic_reqresp_drift);

         frame_send_tag(hash | data, 12, 1);

         /* SHORT TIMEOUT */
         timer->TC_CCR = AT91C_TC_SWTRG;
         while(timer->TC_CV > 1);
         legic_prng_forward(legic_frame_drift);
         while(timer->TC_CV < 180);
         return;
      }
   }

   /* Write */
   if(f->bits == 23) {
      int key   = get_key_stream(-1, 23); //legic_frame_drift, 23);
      int addr  = f->data ^ key; addr = addr >> 1; addr = addr & 0x3ff;
      int data  = f->data ^ key; data = data >> 11; data = data & 0xff;

      /* write command */
      legic_state = STATE_DISCON;
      LED_C_OFF();
      Dbprintf("write - addr: %x, data: %x", addr, data);
      return;
   }

   if(legic_state != STATE_DISCON) {
      Dbprintf("Unexpected: sz:%u, Data:%03.3x, State:%u, Count:%u", f->bits, f->data, legic_state, legic_read_count);
      int i;
      Dbprintf("IV: %03.3x", legic_prng_iv);
      for(i = 0; i<legic_read_count; i++) {
         Dbprintf("Read Nb: %u, Addr: %u", i, BigBuf[OFFSET_LOG+i]);
      }

      for(i = -1; i<legic_read_count; i++) {
         uint32_t t;
         t  = BigBuf[OFFSET_LOG+256+i*4];
         t |= BigBuf[OFFSET_LOG+256+i*4+1] << 8;
         t |= BigBuf[OFFSET_LOG+256+i*4+2] <<16;
         t |= BigBuf[OFFSET_LOG+256+i*4+3] <<24;

         Dbprintf("Cycles: %u, Frame Length: %u, Time: %u", 
            BigBuf[OFFSET_LOG+128+i],
            BigBuf[OFFSET_LOG+384+i],
            t);
      }
   }
   legic_state = STATE_DISCON; 
   legic_read_count = 0;
   SpinDelay(10);
   LED_C_OFF();
   return; 
}

/* Read bit by bit untill full frame is received
 * Call to process frame end answer
 */
static void emit(int bit)
{
  if(bit == -1) {
     if(current_frame.bits <= 4) {
        frame_clean(&current_frame);
     } else {
        frame_handle_tag(&current_frame);
        frame_clean(&current_frame);
     }
     WDT_HIT();
  } else if(bit == 0) {
    frame_append_bit(&current_frame, 0);
  } else if(bit == 1) {
    frame_append_bit(&current_frame, 1);
  }
}

void LegicRfSimulate(int phase, int frame, int reqresp)
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

   if(phase < 0) {
      int i;
      for(i=0; i<=reqresp; i++) {
         legic_prng_init(SESSION_IV);
         Dbprintf("i=%u, key 0x%3.3x", i, get_key_stream(i, frame));
      }
      return;
   }

   legic_phase_drift = phase;
   legic_frame_drift = frame;
   legic_reqresp_drift = reqresp;

   FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
   SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
   FpgaSetupSsc();
   FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_212K);
   
   /* Bitbang the receiver */
   AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_DIN;
   AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DIN;
   
   setup_timer();
   crc_init(&legic_crc, 4, 0x19 >> 1, 0x5, 0);
   
   int old_level = 0;
   int active = 0;
   legic_state = STATE_DISCON;

   LED_B_ON();
   DbpString("Starting Legic emulator, press button to end");
   while(!BUTTON_PRESS()) {
      int level = !!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN);
      int time = timer->TC_CV;
                
      if(level != old_level) {
         if(level == 1) {
            timer->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
            if(FUZZ_EQUAL(time, RWD_TIME_1, RWD_TIME_FUZZ)) {
               /* 1 bit */
               emit(1);
               active = 1;
               LED_A_ON();
            } else if(FUZZ_EQUAL(time, RWD_TIME_0, RWD_TIME_FUZZ)) {
               /* 0 bit */
               emit(0);
               active = 1;
               LED_A_ON();
            } else if(active) {
               /* invalid */
               emit(-1);
               active = 0;
               LED_A_OFF();
            }
         }
      }

      if(time >= (RWD_TIME_1+RWD_TIME_FUZZ) && active) {
         /* Frame end */
         emit(-1);
         active = 0;
         LED_A_OFF();
      }
                
      if(time >= (20*RWD_TIME_1) && (timer->TC_SR & AT91C_TC_CLKSTA)) {
         timer->TC_CCR = AT91C_TC_CLKDIS;
      }
                
      old_level = level;
      WDT_HIT();
   }
   DbpString("Stopped");
   LED_B_OFF();
   LED_A_OFF();
   LED_C_OFF();
}

