//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC RF simulation code
//-----------------------------------------------------------------------------

#include "legicrf.h"

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

int timestamp;

AT91PS_TC timer;
AT91PS_TC prng_timer;

static void setup_timer(void) {
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
#define TAG_TIME_WAIT 490  /* 490 time from RWD frame end to tag frame start, experimentally determined */

#define SIM_DIVISOR  586   /* prng_time/SIM_DIVISOR count prng needs to be forwared */
#define SIM_SHIFT    900   /* prng_time+SIM_SHIFT shift of delayed start */

#define SESSION_IV 0x55
#define OFFSET_LOG 1024

#define FUZZ_EQUAL(value, target, fuzz) ((value) > ((target)-(fuzz)) && (value) < ((target)+(fuzz)))

// ~ 258us + 100us*delay
#define WAIT_387	WAIT(387)
#define WAIT(delay) 	while(timer->TC_CV < (delay) );


// ToDo: define a meaningful maximum size for auth_table. The bigger this is, the lower will be the available memory for traces. 
// Historically it used to be FREE_BUFFER_SIZE, which was 2744.
#define LEGIC_CARD_MEMSIZE 1024
static uint8_t* cardmem;

/*
The new tracelog..
	// Traceformat:
	// 32 bits timestamp (little endian)
	// 16 bits duration (little endian)
	// 16 bits data length (little endian, Highest Bit used as readerToTag flag)
	// y Bytes data
	// x Bytes parity (one byte per 8 bytes data)
*/
 
/* Generate Keystream */
static uint32_t get_key_stream(int skip, int count)
{
	uint32_t key = 0;
	int i;

	// Use int to enlarge timer tc to 32bit
	legic_prng_bc += prng_timer->TC_CV;

	// reset the prng timer.
	prng_timer->TC_CCR = AT91C_TC_SWTRG;
	while(prng_timer->TC_CV > 1) ;

	/* If skip == -1, forward prng time based */
	if(skip == -1) {
		i  = (legic_prng_bc + SIM_SHIFT)/SIM_DIVISOR; /* Calculate Cycles based on timer */
		i -= legic_prng_count(); /* substract cycles of finished frames */
		i -= count; /* substract current frame length, rewind to beginning */
		legic_prng_forward(i);
	} else {
		legic_prng_forward(skip);
	}

	i = (count == 6) ? -1 : legic_read_count;

	/* Write Time Data into LOG */
	// uint8_t *BigBuf = BigBuf_get_addr();
	// BigBuf[OFFSET_LOG+128+i] = legic_prng_count();
	// BigBuf[OFFSET_LOG+256+i*4]   = (legic_prng_bc >> 0) & 0xff;
	// BigBuf[OFFSET_LOG+256+i*4+1] = (legic_prng_bc >> 8) & 0xff;
	// BigBuf[OFFSET_LOG+256+i*4+2] = (legic_prng_bc >>16) & 0xff;
	// BigBuf[OFFSET_LOG+256+i*4+3] = (legic_prng_bc >>24) & 0xff;
	// BigBuf[OFFSET_LOG+384+i] = count;

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
      int key = 0;
      for(int i = 0; i < bits; i++) {
         key |= legic_prng_get_bit() << i;
         legic_prng_forward(1);
      }
      response = response ^ key;
   }

   /* Wait for the frame start */
   //while(timer->TC_CV < (TAG_TIME_WAIT - 30)) ;
   WAIT( TAG_TIME_WAIT - 30)

   uint8_t bit = 0;
   for(int i = 0; i < bits; i++) {
      int nextbit = timer->TC_CV + TAG_TIME_BIT;
      bit = response & 1;
      response >>= 1;
	  
      if (bit)
         AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;
      else
         AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
      
      //while(timer->TC_CV < nextbit) ;
	  WAIT(nextbit)
   }
   AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
}

// Starts Clock and waits until its reset
static void ResetClock(void){
	timer->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
	while(timer->TC_CV > 1) ;
}

/* Send a frame in reader mode, the FPGA must have been set up by
 * LegicRfReader
 */
static void frame_send_rwd(uint32_t data, uint8_t bits){

	uint8_t bit = 0;	
	uint32_t starttime = 0, pause_end = 0, bit_end = 0, temp = data;
	ResetClock();
	
	for(int i = 0; i < bits; i++) {

		starttime = timer->TC_CV;		
		pause_end = starttime + RWD_TIME_PAUSE;
		bit = temp & 1;
		temp >>= 1;

		if(bit ^ legic_prng_get_bit())
			bit_end = starttime + RWD_TIME_1;
		else
			bit_end = starttime + RWD_TIME_0;
		
		/* RWD_TIME_PAUSE time off, then some time on, so that the complete bit time is
		 * RWD_TIME_x, where x is the bit to be transmitted */
		AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;

		WAIT( pause_end )
		
		AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;

		// bit duration is longest. use this time to forward the lfsr
		legic_prng_forward(1); 

		WAIT( bit_end )
	}

	// One final pause to mark the end of the frame
	pause_end = timer->TC_CV + RWD_TIME_PAUSE;
	
	AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
	
	WAIT(pause_end)
	
	AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;

	// log
	uint8_t cmdbytes[2] = { (data & 0xFF), 0 };
	if ( bits > 8 ) {
		cmdbytes[1] = (data >> 8 ) & 0xFF;
		LogTrace(cmdbytes, 2, 0, timer->TC_CV, NULL, TRUE);
	} else {
		LogTrace(cmdbytes, 1, 0, timer->TC_CV, NULL, TRUE);
	}
	/* Reset the timer, to measure time until the start of the tag frame */
	ResetClock();
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
	uint32_t starttime = timer->TC_CV;
	
	uint32_t the_bit = 1;  
	uint32_t data = 0;/* Use a bitmask to save on shifts */
	int i, old_level = 0, edges = 0;
	int next_bit_at = TAG_TIME_WAIT;
	int level = 0;
	
	if(bits > 32) bits = 32;

	AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_DIN;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DIN;

	/* we have some time now, precompute the cipher
     * since we cannot compute it on the fly while reading */
	legic_prng_forward(2);

	if(crypt) {
		for(i=0; i<bits; i++) {
			data |= legic_prng_get_bit() << i;
			legic_prng_forward(1);
		}
	}

	// QUESTION: how long did those extra calls to logtrace take?
	WAIT(next_bit_at)

	next_bit_at += TAG_TIME_BIT;

	for(i=0; i<bits; i++) {
		edges = 0;
		while(timer->TC_CV < next_bit_at) {
			level = (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN);
			if(level != old_level)
				edges++;
			old_level = level;
		}
		next_bit_at += TAG_TIME_BIT;
		
		// We expect 42 edges 
		if(edges > 20 && edges < 60) { 
			data ^= the_bit;
		}
		the_bit <<= 1;
	}

	f->data = data;
	f->bits = bits;
		
	// log
	uint8_t cmdbytes[] = { (data & 0xFF), (data >> 8) & 0xFF };
	LogTrace(cmdbytes, 2, starttime, timer->TC_CV, NULL, FALSE);
	
	// Reset the timer, to synchronize the next frame
	ResetClock();
}

static void frame_append_bit(struct legic_frame * const f, int bit) {
	// Overflow, won't happen
   if (f->bits >= 31) return;
  
   f->data |= (bit << f->bits);
   f->bits++;
}

static void frame_clean(struct legic_frame * const f) {
	f->data = 0;
	f->bits = 0;
}

// Setup pm3 as a Legic Reader
static uint32_t perform_setup_phase_rwd(uint8_t iv) {

	// Switch on carrier and let the tag charge for 1ms
	AT91C_BASE_PIOA->PIO_SODR = GPIO_SSC_DOUT;
	SpinDelay(20);  // was 1ms before. 

	// no keystream yet
	legic_prng_init(0);

	frame_send_rwd(iv, 7);
	
	legic_prng_init(iv);

	frame_clean(&current_frame);
	
	frame_receive_rwd(&current_frame, 6, 1);

	 // we wait anyways
	legic_prng_forward(3);
	
	WAIT(387)

	// Send obsfuscated acknowledgment frame.
	// 0x19 = MIM22
	// 0x39 = MIM256, MIM1024
	if ( current_frame.data == 0x0D ){
		frame_send_rwd(0x19, 6);
	}else{
		frame_send_rwd(0x39, 6);
	}

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

	// reserve a cardmem,  meaning we can use the tracelog function in bigbuff easier.
	cardmem = BigBuf_malloc(LEGIC_CARD_MEMSIZE);
	memset(cardmem, 0x00, LEGIC_CARD_MEMSIZE);

	clear_trace();
	set_tracing(TRUE);
	
	setup_timer();

	crc_init(&legic_crc, 4, 0x19 >> 1, 0x5, 0);
}

/* Switch off carrier, make sure tag is reset */
static void switch_off_tag_rwd(void) {
	AT91C_BASE_PIOA->PIO_CODR = GPIO_SSC_DOUT;
	SpinDelay(10);
	WDT_HIT();
}

// calculate crc4 for a legic READ command 
// 5,8,10 address size.
static int LegicCRC(uint16_t byte_index, uint8_t value, uint8_t cmd_sz) {
	crc_clear(&legic_crc);
	crc_update(&legic_crc, LEGIC_READ, 1);
	crc_update(&legic_crc, byte_index, cmd_sz-1);
	crc_update(&legic_crc, value, 8);
	return crc_finish(&legic_crc);
}

#define LEGIC_READ 0x01
#define LEGIC_WRITE 0x00

int legic_read_byte(int byte_index, int cmd_sz) {

	int calcCrc = 0, crc = 0;
	uint8_t byte = 0;
	uint32_t cmd = (byte_index << 1) | LEGIC_READ;

	WAIT_387

	// send read command
	frame_send_rwd(cmd, cmd_sz);

	frame_clean(&current_frame);

	// receive
	frame_receive_rwd(&current_frame, 12, 1);

	byte = current_frame.data & 0xff;
	calcCrc = LegicCRC(byte_index, byte, cmd_sz);
	crc = (current_frame.data >> 8);

	if( calcCrc != crc ) {
		Dbprintf("!!! crc mismatch: expected %x but got %x !!!",  calcCrc, crc);
		return -1;
	}

	// we wait anyways
	legic_prng_forward(4); 
	return byte;
}

/* 
 * - assemble a write_cmd_frame with crc and send it
 * - wait until the tag sends back an ACK ('1' bit unencrypted)
 * - forward the prng based on the timing
 */
//int legic_write_byte(int byte, int addr, int addr_sz, int PrngCorrection) {
int legic_write_byte(int byte, int addr, int addr_sz) {

    //do not write UID, CRC at offset 0-4.
	if(addr <= 0x04) return 0;

	// crc
	crc_clear(&legic_crc);
	crc_update(&legic_crc, 0, 1); /* CMD_WRITE */
	crc_update(&legic_crc, addr, addr_sz);
	crc_update(&legic_crc, byte, 8);
	uint32_t crc = crc_finish(&legic_crc);

	// send write command
	uint32_t cmd = ((crc     <<(addr_sz+1+8)) //CRC
                   |(byte    <<(addr_sz+1))   //Data
                   |(addr    <<1)             //Address
                   |(0x00    <<0));           //CMD = W
    uint32_t cmd_sz = addr_sz+1+8+4;          //crc+data+cmd

    legic_prng_forward(2); /* we wait anyways */
	
    while(timer->TC_CV < 387) ; /* ~ 258us */
	
	frame_send_rwd(cmd, cmd_sz);
  
// wllm-rbnt doesnt have these
//	AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_DIN;
//	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DIN;

	// wait for ack
    int t, old_level = 0, edges = 0;
    int next_bit_at = 0;

	while(timer->TC_CV < 387) ; /* ~ 258us */

    for( t = 0; t < 80; t++) {
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
			int c = t / TAG_TIME_BIT;
			
			ResetClock();
			legic_prng_forward(c);
        	return 0;
        }
    }

	ResetClock();
	return -1;
}

int LegicRfReader(int offset, int bytes, int iv) {
	
	// ice_legic_setup();
	// ice_legic_select_card();
	// return 0;
	int byte_index = 0, cmd_sz = 0, card_sz = 0;	   							   

	LegicCommonInit();

	if ( MF_DBGLEVEL >= 2) DbpString("setting up legic card");

	uint32_t tag_type = perform_setup_phase_rwd(iv);

	 //we lose to mutch time with dprintf
	switch_off_tag_rwd();

	switch(tag_type) {
		case 0x0d:
			if ( MF_DBGLEVEL >= 2) DbpString("MIM22 card found, reading card ...");
            cmd_sz = 6;
			card_sz = 22;
			break;
		case 0x1d:
			if ( MF_DBGLEVEL >= 2) DbpString("MIM256 card found, reading card ...");
            cmd_sz = 9;
			card_sz = 256;
			break;
		case 0x3d:
			if ( MF_DBGLEVEL >= 2) DbpString("MIM1024 card found, reading card ...");
            cmd_sz = 11;
			card_sz = 1024;
			break;
		default:
			if ( MF_DBGLEVEL >= 1) Dbprintf("Unknown card format: %x",tag_type);
			return -1;
	}
	if(bytes == -1)
		bytes = card_sz;

	if(bytes+offset >= card_sz)
		bytes = card_sz - offset;

	perform_setup_phase_rwd(iv);

	legic_prng_forward(2);

	LED_B_ON();
	while(byte_index < bytes) {
		int r = legic_read_byte(byte_index+offset, cmd_sz);
		if(r == -1 || BUTTON_PRESS()) {			
           	switch_off_tag_rwd();
	        LEDsoff();
	        if ( MF_DBGLEVEL >= 2) DbpString("operation aborted");
			return -1;
		}
		cardmem[byte_index] = r;
        WDT_HIT();
		byte_index++;		
	}

	switch_off_tag_rwd();
	LEDsoff();
	
	if ( MF_DBGLEVEL >= 1) Dbprintf("Card read, use 'hf legic decode' or");
    if ( MF_DBGLEVEL >= 1) Dbprintf("'data hexsamples %d' to view results", (bytes+7) & ~7);
    return 0;
}

/*int _LegicRfWriter(int offset, int bytes, int addr_sz, uint8_t *BigBuf, int RoundBruteforceValue) {
	int byte_index=0;

    LED_B_ON();
	perform_setup_phase_rwd(SESSION_IV);
    //legic_prng_forward(2);
	while(byte_index < bytes) {
		int r;

		//check if the DCF should be changed
		if ( (offset == 0x05) && (bytes == 0x02) ) {
			//write DCF in reverse order (addr 0x06 before 0x05)
			r = legic_write_byte(BigBuf[(0x06-byte_index)], (0x06-byte_index), addr_sz, RoundBruteforceValue);
			//legic_prng_forward(1);
			if(r == 0) {
				byte_index++;
				r = legic_write_byte(BigBuf[(0x06-byte_index)], (0x06-byte_index), addr_sz, RoundBruteforceValue);
			}
			//legic_prng_forward(1);
		}
		else {
			r = legic_write_byte(BigBuf[byte_index+offset], byte_index+offset, addr_sz, RoundBruteforceValue);
		}
		if((r != 0) || BUTTON_PRESS()) {
			Dbprintf("operation aborted @ 0x%03.3x", byte_index);
	switch_off_tag_rwd();
			LED_B_OFF();
			LED_C_OFF();
			return -1;
		}

        WDT_HIT();
		byte_index++;
        if(byte_index & 0x10) LED_C_ON(); else LED_C_OFF();
	}
    LED_B_OFF();
    LED_C_OFF();
    DbpString("write successful");
    return 0;
}*/

void LegicRfWriter(int offset, int bytes, int iv) {

	int byte_index = 0, addr_sz = 0;
	
	iv = (iv <=0 ) ? SESSION_IV : iv;										  

	LegicCommonInit();
	
	if ( MF_DBGLEVEL >= 2) 	DbpString("setting up legic card");
	
	uint32_t tag_type = perform_setup_phase_rwd(iv);
	
	switch_off_tag_rwd();
	
	switch(tag_type) {
		case 0x0d:
			if(offset+bytes > 22) {
				Dbprintf("Error: can not write to 0x%03.3x on MIM22", offset+bytes);
				return;
			}
			addr_sz = 5;
			if ( MF_DBGLEVEL >= 2) Dbprintf("MIM22 card found, writing 0x%02.2x - 0x%02.2x ...", offset, offset+bytes);
			break;
		case 0x1d:
			if(offset+bytes > 0x100) {
				Dbprintf("Error: can not write to 0x%03.3x on MIM256", offset+bytes);
				return;
			}
			addr_sz = 8;
			if ( MF_DBGLEVEL >= 2) Dbprintf("MIM256 card found, writing 0x%02.2x - 0x%02.2x ...", offset, offset+bytes);
			break;
		case 0x3d:
			if(offset+bytes > 0x400) {
          		Dbprintf("Error: can not write to 0x%03.3x on MIM1024", offset+bytes);
           		return;
          	}
			addr_sz = 10;
			if ( MF_DBGLEVEL >= 2) Dbprintf("MIM1024 card found, writing 0x%03.3x - 0x%03.3x ...", offset, offset+bytes);
			break;
		default:
			Dbprintf("No or unknown card found, aborting");
            return;
	}

    LED_B_ON();
	perform_setup_phase_rwd(iv);
	while(byte_index < bytes) {
		int r;

		//check if the DCF should be changed
		if ( ((byte_index+offset) == 0x05) && (bytes >= 0x02) ) {
			//write DCF in reverse order (addr 0x06 before 0x05)
			r = legic_write_byte(cardmem[(0x06-byte_index)], (0x06-byte_index), addr_sz);

			// write second byte on success...
			if(r == 0) {
				byte_index++;
				r = legic_write_byte(cardmem[(0x06-byte_index)], (0x06-byte_index), addr_sz);
			}
		}
		else {
			r = legic_write_byte(cardmem[byte_index+offset], byte_index+offset, addr_sz);
		}
		
		if((r != 0) || BUTTON_PRESS()) {
			Dbprintf("operation aborted @ 0x%03.3x", byte_index);
			switch_off_tag_rwd();
			LEDsoff();
			return;
		}

        WDT_HIT();
		byte_index++;
	}
	LEDsoff();
    if ( MF_DBGLEVEL >= 1) DbpString("write successful");
}

void LegicRfRawWriter(int address, int byte, int iv) {

	int byte_index = 0, addr_sz = 0;
												  
	iv = (iv <= 0) ? SESSION_IV : iv;
	
	LegicCommonInit();
	
	if ( MF_DBGLEVEL >= 2) DbpString("setting up legic card");
	
	uint32_t tag_type = perform_setup_phase_rwd(iv);
	
	switch_off_tag_rwd();
	
	switch(tag_type) {
		case 0x0d:
			if(address > 22) {
				Dbprintf("Error: can not write to 0x%03.3x on MIM22", address);
				return;
			}
			addr_sz = 5;
			if ( MF_DBGLEVEL >= 2) Dbprintf("MIM22 card found, writing at addr 0x%02.2x - value 0x%02.2x ...", address, byte);
			break;
		case 0x1d:
			if(address > 0x100) {
				Dbprintf("Error: can not write to 0x%03.3x on MIM256", address);
				return;
			}
			addr_sz = 8;
			if ( MF_DBGLEVEL >= 2) Dbprintf("MIM256 card found, writing at addr 0x%02.2x - value 0x%02.2x ...", address, byte);
			break;
		case 0x3d:
			if(address > 0x400) {
          		Dbprintf("Error: can not write to 0x%03.3x on MIM1024", address);
           		return;
          	}
			addr_sz = 10;
			if ( MF_DBGLEVEL >= 2) Dbprintf("MIM1024 card found, writing at addr 0x%03.3x - value 0x%03.3x ...", address, byte);
			break;
		default:
			Dbprintf("No or unknown card found, aborting");
            return;
	}
	
	Dbprintf("integer value: %d address: %d  addr_sz: %d", byte, address, addr_sz);
    LED_B_ON();
	
	perform_setup_phase_rwd(iv);
    //legic_prng_forward(2);
		
	int r = legic_write_byte(byte, address, addr_sz);
		
	if((r != 0) || BUTTON_PRESS()) {
		Dbprintf("operation aborted @ 0x%03.3x (%1d)", byte_index, r);
		switch_off_tag_rwd();
		LEDsoff();
		return;
	}

    LEDsoff();
    if ( MF_DBGLEVEL >= 1) DbpString("write successful");
}

/* Handle (whether to respond) a frame in tag mode
 * Only called when simulating a tag.
 */
static void frame_handle_tag(struct legic_frame const * const f)
{
	uint8_t *BigBuf = BigBuf_get_addr();

   /* First Part of Handshake (IV) */
   if(f->bits == 7) {

        LED_C_ON();
        
		prng_timer->TC_CCR = AT91C_TC_SWTRG;
		while(prng_timer->TC_CV > 1) ;
		
        legic_prng_init(f->data);
        frame_send_tag(0x3d, 6, 1); /* 0x3d^0x26 = 0x1b */
        legic_state = STATE_IV;
        legic_read_count = 0;
        legic_prng_bc = 0;
        legic_prng_iv = f->data;
 
        /* TIMEOUT */
		ResetClock();
		
        //while(timer->TC_CV < 280);
		WAIT(280)
        return;
   }

   /* 0x19==??? */
   if(legic_state == STATE_IV) {
      int local_key = get_key_stream(3, 6);
      int xored = 0x39 ^ local_key;
      if((f->bits == 6) && (f->data == xored)) {
         legic_state = STATE_CON;

         /* TIMEOUT */
		 ResetClock();
		 
         //while(timer->TC_CV < 200);
		 WAIT(200)
		 
         return;
      } else {
         legic_state = STATE_DISCON;
         LED_C_OFF();
         Dbprintf("iv: %02x frame: %02x key: %02x xored: %02x", legic_prng_iv, f->data, local_key, xored);
         return;
      }
   }

   /* Read */
   if(f->bits == 11) {
      if(legic_state == STATE_CON) {
         int key   = get_key_stream(2, 11); //legic_phase_drift, 11);
         int addr  = f->data ^ key; addr = addr >> 1;
         int data = BigBuf[addr];
         int hash = LegicCRC(addr, data, 11) << 8;
         BigBuf[OFFSET_LOG+legic_read_count] = (uint8_t)addr;
         legic_read_count++;

         //Dbprintf("Data:%03.3x, key:%03.3x, addr: %03.3x, read_c:%u", f->data, key, addr, read_c);
         legic_prng_forward(legic_reqresp_drift);

         frame_send_tag(hash | data, 12, 1);

         /* TIMEOUT */
		 ResetClock();
		 
         legic_prng_forward(2);
         //while(timer->TC_CV < 180);
		 WAIT(180)
		 
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
static void emit(int bit) {

	switch (bit) {
		case 1:
			frame_append_bit(&current_frame, 1);
			break;			
		case 0:
			frame_append_bit(&current_frame, 0);
			break;
		default: 
			if(current_frame.bits <= 4) {
				frame_clean(&current_frame);
			} else {
				frame_handle_tag(&current_frame);
				frame_clean(&current_frame);
			}
			WDT_HIT();
			break;
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
   
	while(!BUTTON_PRESS() && !usb_poll_validate_length()) {
		int level = !!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN);
		int time = timer->TC_CV;

		if(level != old_level) {
			if(level == 1) {
				timer->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
				
				if (FUZZ_EQUAL(time, RWD_TIME_1, RWD_TIME_FUZZ)) {
					/* 1 bit */
					emit(1);
					active = 1;
					LED_A_ON();
				} else if (FUZZ_EQUAL(time, RWD_TIME_0, RWD_TIME_FUZZ)) {
					/* 0 bit */
					emit(0);
					active = 1;
					LED_A_ON();
				} else if (active) {
					/* invalid */
					emit(-1);
					active = 0;
					LED_A_OFF();
				}
			}
		}

		/* Frame end */
		if(time >= (RWD_TIME_1+RWD_TIME_FUZZ) && active) {
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
	if ( MF_DBGLEVEL >= 1) DbpString("Stopped");
	LEDsoff();
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
// Code up a string of octets at layer 2 (including CRC, we don't generate
// that here) so that they can be transmitted to the reader. Doesn't transmit
// them yet, just leaves them ready to send in ToSend[].
//-----------------------------------------------------------------------------
// static void CodeLegicAsTag(const uint8_t *cmd, int len)
// {
	// int i;

	// ToSendReset();

	// // Transmit a burst of ones, as the initial thing that lets the
	// // reader get phase sync. This (TR1) must be > 80/fs, per spec,
	// // but tag that I've tried (a Paypass) exceeds that by a fair bit,
	// // so I will too.
	// for(i = 0; i < 20; i++) {
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
	// }

	// // Send SOF.
	// for(i = 0; i < 10; i++) {
		// ToSendStuffBit(0);
		// ToSendStuffBit(0);
		// ToSendStuffBit(0);
		// ToSendStuffBit(0);
	// }
	// for(i = 0; i < 2; i++) {
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
	// }

	// for(i = 0; i < len; i++) {
		// int j;
		// uint8_t b = cmd[i];

		// // Start bit
		// ToSendStuffBit(0);
		// ToSendStuffBit(0);
		// ToSendStuffBit(0);
		// ToSendStuffBit(0);

		// // Data bits
		// for(j = 0; j < 8; j++) {
			// if(b & 1) {
				// ToSendStuffBit(1);
				// ToSendStuffBit(1);
				// ToSendStuffBit(1);
				// ToSendStuffBit(1);
			// } else {
				// ToSendStuffBit(0);
				// ToSendStuffBit(0);
				// ToSendStuffBit(0);
				// ToSendStuffBit(0);
			// }
			// b >>= 1;
		// }

		// // Stop bit
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
	// }

	// // Send EOF.
	// for(i = 0; i < 10; i++) {
		// ToSendStuffBit(0);
		// ToSendStuffBit(0);
		// ToSendStuffBit(0);
		// ToSendStuffBit(0);
	// }
	// for(i = 0; i < 2; i++) {
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
		// ToSendStuffBit(1);
	// }

	// // Convert from last byte pos to length
	// ToSendMax++;
// }

//-----------------------------------------------------------------------------
// The software UART that receives commands from the reader, and its state
// variables.
//-----------------------------------------------------------------------------
static struct {
	enum {
		STATE_UNSYNCD,
		STATE_GOT_FALLING_EDGE_OF_SOF,
		STATE_AWAITING_START_BIT,
		STATE_RECEIVING_DATA
	}       state;
	uint16_t shiftReg;
	int     bitCnt;
	int     byteCnt;
	int     byteCntMax;
	int     posCnt;
	uint8_t *output;
} Uart;

/* Receive & handle a bit coming from the reader.
 *
 * This function is called 4 times per bit (every 2 subcarrier cycles).
 * Subcarrier frequency fs is 212kHz, 1/fs = 4,72us, i.e. function is called every 9,44us
 *
 * LED handling:
 * LED A -> ON once we have received the SOF and are expecting the rest.
 * LED A -> OFF once we have received EOF or are in error state or unsynced
 *
 * Returns: true if we received a EOF
 *          false if we are still waiting for some more
 */
// static RAMFUNC int HandleLegicUartBit(uint8_t bit)
// {
	// switch(Uart.state) {
		// case STATE_UNSYNCD:
			// if(!bit) {
				// // we went low, so this could be the beginning of an SOF
				// Uart.state = STATE_GOT_FALLING_EDGE_OF_SOF;
				// Uart.posCnt = 0;
				// Uart.bitCnt = 0;
			// }
			// break;

		// case STATE_GOT_FALLING_EDGE_OF_SOF:
			// Uart.posCnt++;
			// if(Uart.posCnt == 2) {	// sample every 4 1/fs in the middle of a bit
				// if(bit) {
					// if(Uart.bitCnt > 9) {
						// // we've seen enough consecutive
						// // zeros that it's a valid SOF
						// Uart.posCnt = 0;
						// Uart.byteCnt = 0;
						// Uart.state = STATE_AWAITING_START_BIT;
						// LED_A_ON(); // Indicate we got a valid SOF
					// } else {
						// // didn't stay down long enough
						// // before going high, error
						// Uart.state = STATE_UNSYNCD;
					// }
				// } else {
					// // do nothing, keep waiting
				// }
				// Uart.bitCnt++;
			// }
			// if(Uart.posCnt >= 4) Uart.posCnt = 0;
			// if(Uart.bitCnt > 12) {
				// // Give up if we see too many zeros without
				// // a one, too.
				// LED_A_OFF();
				// Uart.state = STATE_UNSYNCD;
			// }
			// break;

		// case STATE_AWAITING_START_BIT:
			// Uart.posCnt++;
			// if(bit) {
				// if(Uart.posCnt > 50/2) {	// max 57us between characters = 49 1/fs, max 3 etus after low phase of SOF = 24 1/fs
					// // stayed high for too long between
					// // characters, error
					// Uart.state = STATE_UNSYNCD;
				// }
			// } else {
				// // falling edge, this starts the data byte
				// Uart.posCnt = 0;
				// Uart.bitCnt = 0;
				// Uart.shiftReg = 0;
				// Uart.state = STATE_RECEIVING_DATA;
			// }
			// break;

		// case STATE_RECEIVING_DATA:
			// Uart.posCnt++;
			// if(Uart.posCnt == 2) {
				// // time to sample a bit
				// Uart.shiftReg >>= 1;
				// if(bit) {
					// Uart.shiftReg |= 0x200;
				// }
				// Uart.bitCnt++;
			// }
			// if(Uart.posCnt >= 4) {
				// Uart.posCnt = 0;
			// }
			// if(Uart.bitCnt == 10) {
				// if((Uart.shiftReg & 0x200) && !(Uart.shiftReg & 0x001))
				// {
					// // this is a data byte, with correct
					// // start and stop bits
					// Uart.output[Uart.byteCnt] = (Uart.shiftReg >> 1) & 0xff;
					// Uart.byteCnt++;

					// if(Uart.byteCnt >= Uart.byteCntMax) {
						// // Buffer overflowed, give up
						// LED_A_OFF();
						// Uart.state = STATE_UNSYNCD;
					// } else {
						// // so get the next byte now
						// Uart.posCnt = 0;
						// Uart.state = STATE_AWAITING_START_BIT;
					// }
				// } else if (Uart.shiftReg == 0x000) {
					// // this is an EOF byte
					// LED_A_OFF(); // Finished receiving
					// Uart.state = STATE_UNSYNCD;
					// if (Uart.byteCnt != 0) {
					// return TRUE;
					// }
				// } else {
					// // this is an error
					// LED_A_OFF();
					// Uart.state = STATE_UNSYNCD;
				// }
			// }
			// break;

		// default:
			// LED_A_OFF();
			// Uart.state = STATE_UNSYNCD;
			// break;
	// }

	// return FALSE;
// }


static void UartReset() {
	Uart.byteCntMax = 3;
	Uart.state = STATE_UNSYNCD;
	Uart.byteCnt = 0;
	Uart.bitCnt = 0;
	Uart.posCnt = 0;
	memset(Uart.output, 0x00, 3);
}

// static void UartInit(uint8_t *data) {
	// Uart.output = data;
	// UartReset();
// }

//=============================================================================
// An LEGIC reader. We take layer two commands, code them
// appropriately, and then send them to the tag. We then listen for the
// tag's response, which we leave in the buffer to be demodulated on the
// PC side.
//=============================================================================

static struct {
	enum {
		DEMOD_UNSYNCD,
		DEMOD_PHASE_REF_TRAINING,
		DEMOD_AWAITING_FALLING_EDGE_OF_SOF,
		DEMOD_GOT_FALLING_EDGE_OF_SOF,
		DEMOD_AWAITING_START_BIT,
		DEMOD_RECEIVING_DATA
	}       state;
	int     bitCount;
	int     posCount;
	int     thisBit;
	uint16_t  shiftReg;
	uint8_t   *output;
	int     len;
	int     sumI;
	int     sumQ;
} Demod;

/*
 * Handles reception of a bit from the tag
 *
 * This function is called 2 times per bit (every 4 subcarrier cycles).
 * Subcarrier frequency fs is 212kHz, 1/fs = 4,72us, i.e. function is called every 9,44us
 *
 * LED handling:
 * LED C -> ON once we have received the SOF and are expecting the rest.
 * LED C -> OFF once we have received EOF or are unsynced
 *
 * Returns: true if we received a EOF
 *          false if we are still waiting for some more
 *
 */

 #ifndef SUBCARRIER_DETECT_THRESHOLD
 # define SUBCARRIER_DETECT_THRESHOLD	8
 #endif
 
 // Subcarrier amplitude v = sqrt(ci^2 + cq^2), approximated here by max(abs(ci),abs(cq)) + 1/2*min(abs(ci),abs(cq)))
#ifndef CHECK_FOR_SUBCARRIER
# define CHECK_FOR_SUBCARRIER() { v = MAX(ai, aq) + MIN(halfci, halfcq); }
#endif

// The soft decision on the bit uses an estimate of just the
// quadrant of the reference angle, not the exact angle.
// Subcarrier amplitude v = sqrt(ci^2 + cq^2), approximated here by max(abs(ci),abs(cq)) + 1/2*min(abs(ci),abs(cq)))
#define MAKE_SOFT_DECISION() { \
		if(Demod.sumI > 0) \
			v = ci; \
		else \
			v = -ci; \
		\
		if(Demod.sumQ > 0) \
			v += cq; \
		else \
			v -= cq; \
		\
	}

static RAMFUNC int HandleLegicSamplesDemod(int ci, int cq)
{
	int v = 0;
	int ai = ABS(ci);
	int aq = ABS(cq);
	int halfci = (ai >> 1);
	int halfcq = (aq >> 1);

	switch(Demod.state) {
		case DEMOD_UNSYNCD:
			
			CHECK_FOR_SUBCARRIER()
			
			if(v > SUBCARRIER_DETECT_THRESHOLD) {	// subcarrier detected
				Demod.state = DEMOD_PHASE_REF_TRAINING;
				Demod.sumI = ci;
				Demod.sumQ = cq;
				Demod.posCount = 1;
			}
			break;

		case DEMOD_PHASE_REF_TRAINING:
			if(Demod.posCount < 8) {
			
				CHECK_FOR_SUBCARRIER()
				
				if (v > SUBCARRIER_DETECT_THRESHOLD) {
					// set the reference phase (will code a logic '1') by averaging over 32 1/fs.
					// note: synchronization time > 80 1/fs
					Demod.sumI += ci;
					Demod.sumQ += cq;
					++Demod.posCount;
				} else {
					// subcarrier lost
					Demod.state = DEMOD_UNSYNCD;
				}
			} else {
				Demod.state = DEMOD_AWAITING_FALLING_EDGE_OF_SOF;
			}
			break;

		case DEMOD_AWAITING_FALLING_EDGE_OF_SOF:

			MAKE_SOFT_DECISION()

			//Dbprintf("ICE: %d %d %d %d %d", v, Demod.sumI, Demod.sumQ, ci, cq );
			// logic '0' detected
			if (v <= 0) {
				
				Demod.state = DEMOD_GOT_FALLING_EDGE_OF_SOF;
			
				// start of SOF sequence
				Demod.posCount = 0;
			} else {
				// maximum length of TR1 = 200 1/fs
				if(Demod.posCount > 25*2) Demod.state = DEMOD_UNSYNCD;
			}
			++Demod.posCount;
			break;

		case DEMOD_GOT_FALLING_EDGE_OF_SOF:
			++Demod.posCount;

			MAKE_SOFT_DECISION()

			if(v > 0) {
				// low phase of SOF too short (< 9 etu). Note: spec is >= 10, but FPGA tends to "smear" edges
				if(Demod.posCount < 10*2) { 
					Demod.state = DEMOD_UNSYNCD;
				} else {
					LED_C_ON(); // Got SOF
					Demod.state = DEMOD_AWAITING_START_BIT;
					Demod.posCount = 0;
					Demod.len = 0;
				}
			} else {
				// low phase of SOF too long (> 12 etu)
				if(Demod.posCount > 13*2) { 
					Demod.state = DEMOD_UNSYNCD;
					LED_C_OFF();
				}
			}
			break;

		case DEMOD_AWAITING_START_BIT:
			++Demod.posCount;
			
			MAKE_SOFT_DECISION()
			
			if(v > 0) {
				// max 19us between characters = 16 1/fs, max 3 etu after low phase of SOF = 24 1/fs
				if(Demod.posCount > 3*2) { 
					Demod.state = DEMOD_UNSYNCD;
					LED_C_OFF();
				}
			} else {
				// start bit detected
				Demod.bitCount = 0;
				Demod.posCount = 1;				// this was the first half
				Demod.thisBit = v;
				Demod.shiftReg = 0;
				Demod.state = DEMOD_RECEIVING_DATA;
			}
			break;

		case DEMOD_RECEIVING_DATA:
		
			MAKE_SOFT_DECISION()
			
			if(Demod.posCount == 0) {
				// first half of bit
				Demod.thisBit = v;
				Demod.posCount = 1;
			} else {
				// second half of bit
				Demod.thisBit += v;
				Demod.shiftReg >>= 1;
				// logic '1'
				if(Demod.thisBit > 0) 
					Demod.shiftReg |= 0x200;
				
				++Demod.bitCount;
				
				if(Demod.bitCount == 10) {
					
					uint16_t s = Demod.shiftReg;
					
					if((s & 0x200) && !(s & 0x001)) { 
						// stop bit == '1', start bit == '0'
						uint8_t b = (s >> 1);
						Demod.output[Demod.len] = b;
						++Demod.len;
						Demod.state = DEMOD_AWAITING_START_BIT;
					} else {
						Demod.state = DEMOD_UNSYNCD;
						LED_C_OFF();
						
						if(s == 0x000) {
							// This is EOF (start, stop and all data bits == '0'
							return TRUE;
						}
					}
				}
				Demod.posCount = 0;
			}
			break;

		default:
			Demod.state = DEMOD_UNSYNCD;
			LED_C_OFF();
			break;
	}
	return FALSE;
}

// Clear out the state of the "UART" that receives from the tag.
static void DemodReset() {
	Demod.len = 0;
	Demod.state = DEMOD_UNSYNCD;
	Demod.posCount = 0;
	Demod.sumI = 0;
	Demod.sumQ = 0;
	Demod.bitCount = 0;
	Demod.thisBit = 0;
	Demod.shiftReg = 0;
	memset(Demod.output, 0x00, 3);
}

static void DemodInit(uint8_t *data) {
	Demod.output = data;
	DemodReset();
}

/*
 *  Demodulate the samples we received from the tag, also log to tracebuffer
 *  quiet: set to 'TRUE' to disable debug output
 */
 #define LEGIC_DMA_BUFFER_SIZE 256
static void GetSamplesForLegicDemod(int n, bool quiet)
{
	int max = 0;
	bool gotFrame = FALSE;
	int lastRxCounter = LEGIC_DMA_BUFFER_SIZE;
	int	ci, cq, samples = 0;

	BigBuf_free();

	// And put the FPGA in the appropriate mode
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_QUARTER_FREQ);

	// The response (tag -> reader) that we're receiving.
	// Set up the demodulator for tag -> reader responses.
	DemodInit(BigBuf_malloc(MAX_FRAME_SIZE));
	
	// The DMA buffer, used to stream samples from the FPGA
	int8_t *dmaBuf = (int8_t*) BigBuf_malloc(LEGIC_DMA_BUFFER_SIZE);
	int8_t *upTo = dmaBuf;

	// Setup and start DMA.
	if ( !FpgaSetupSscDma((uint8_t*) dmaBuf, LEGIC_DMA_BUFFER_SIZE) ){
		if (MF_DBGLEVEL > 1) Dbprintf("FpgaSetupSscDma failed. Exiting"); 
		return;
	}	

	// Signal field is ON with the appropriate LED:
	LED_D_ON();
	for(;;) {
		int behindBy = lastRxCounter - AT91C_BASE_PDC_SSC->PDC_RCR;
		if(behindBy > max) max = behindBy;

		while(((lastRxCounter-AT91C_BASE_PDC_SSC->PDC_RCR) & (LEGIC_DMA_BUFFER_SIZE-1)) > 2) {
			ci = upTo[0];
			cq = upTo[1];
			upTo += 2;
			if(upTo >= dmaBuf + LEGIC_DMA_BUFFER_SIZE) {
				upTo = dmaBuf;
				AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) upTo;
				AT91C_BASE_PDC_SSC->PDC_RNCR = LEGIC_DMA_BUFFER_SIZE;
			}
			lastRxCounter -= 2;
			if(lastRxCounter <= 0)
				lastRxCounter = LEGIC_DMA_BUFFER_SIZE;

			samples += 2;

			gotFrame = HandleLegicSamplesDemod(ci , cq );
			if ( gotFrame )
				break;
		}

		if(samples > n || gotFrame)
			break;
	}

	FpgaDisableSscDma();

	if (!quiet && Demod.len == 0) {
		Dbprintf("max behindby = %d, samples = %d, gotFrame = %d, Demod.len = %d, Demod.sumI = %d, Demod.sumQ = %d",
			max,
			samples, 
			gotFrame, 
			Demod.len, 
			Demod.sumI, 
			Demod.sumQ
		);
	}

	//Tracing
	if (Demod.len > 0) {
		uint8_t parity[MAX_PARITY_SIZE] = {0x00};
		LogTrace(Demod.output, Demod.len, 0, 0, parity, FALSE);
	}
}
//-----------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitForLegic(void)
{
	int c;

	FpgaSetupSsc();
	
	while(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))
		AT91C_BASE_SSC->SSC_THR = 0xff;

	// Signal field is ON with the appropriate Red LED
	LED_D_ON();

	// Signal we are transmitting with the Green LED
	LED_B_ON();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX | FPGA_HF_READER_TX_SHALLOW_MOD);
	
	for(c = 0; c < 10;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0xff;
			c++;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			volatile uint32_t r = AT91C_BASE_SSC->SSC_RHR;
			(void)r;
		}
		WDT_HIT();
	}

	c = 0;
	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = ToSend[c];
			legic_prng_forward(1); // forward the lfsr 
			c++;
			if(c >= ToSendMax) {
				break;
			}
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			volatile uint32_t r = AT91C_BASE_SSC->SSC_RHR;
			(void)r;
		}
		WDT_HIT();
	}
	LED_B_OFF();
}


//-----------------------------------------------------------------------------
// Code a layer 2 command (string of octets, including CRC) into ToSend[],
// so that it is ready to transmit to the tag using TransmitForLegic().
//-----------------------------------------------------------------------------
static void CodeLegicBitsAsReader(const uint8_t *cmd, uint8_t cmdlen, int bits)
{
	int i, j;
	uint8_t b;

	ToSendReset();

	// Send SOF
	for(i = 0; i < 7; i++)
		ToSendStuffBit(1);


	for(i = 0; i < cmdlen; i++) {
		// Start bit
		ToSendStuffBit(0);

		// Data bits
		b = cmd[i];
		for(j = 0; j < bits; j++) {
			if(b & 1) {
				ToSendStuffBit(1);
			} else {
				ToSendStuffBit(0);
			}
			b >>= 1;
		}
	}
	
	// Convert from last character reference to length
	++ToSendMax;
}

/**
  Convenience function to encode, transmit and trace Legic comms
  **/
static void CodeAndTransmitLegicAsReader(const uint8_t *cmd, uint8_t cmdlen, int bits)
{
	CodeLegicBitsAsReader(cmd, cmdlen, bits);
	TransmitForLegic();
	if (tracing) {
		uint8_t parity[1] = {0x00};
		LogTrace(cmd, cmdlen, 0, 0, parity, TRUE);
	}
}

int ice_legic_select_card()
{
	//int cmd_size=0, card_size=0;
	uint8_t wakeup[] = { 0x7F };
	uint8_t getid[] = {0x19};

	legic_prng_init(SESSION_IV);

	// first, wake up the tag, 7bits
	CodeAndTransmitLegicAsReader(wakeup, sizeof(wakeup), 7);

	GetSamplesForLegicDemod(1000, TRUE);

	// frame_clean(&current_frame);
	//frame_receive_rwd(&current_frame, 6, 1);

	legic_prng_forward(1); /* we wait anyways */
	
	//while(timer->TC_CV < 387) ; /* ~ 258us */
	//frame_send_rwd(0x19, 6);
	CodeAndTransmitLegicAsReader(getid, sizeof(getid), 8);
	GetSamplesForLegicDemod(1000, TRUE);

	//if (Demod.len < 14) return 2; 
	Dbprintf("CARD TYPE: %02x  LEN: %d", Demod.output[0], Demod.len);

	switch(Demod.output[0]) {
		case 0x1d:
			DbpString("MIM 256 card found");
            // cmd_size = 9;
			// card_size = 256;
			break;
		case 0x3d:
			DbpString("MIM 1024 card found");
            // cmd_size = 11;
			// card_size = 1024;
			break;
		default:
			return -1;
	}
	
	// if(bytes == -1)
		// bytes = card_size;

	// if(bytes + offset >= card_size)
		// bytes = card_size - offset;	
	
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	set_tracing(FALSE);
	return 1;
}

// Set up LEGIC communication
void ice_legic_setup() {

	// standard things.
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	BigBuf_free(); BigBuf_Clear_ext(false);
	clear_trace();
	set_tracing(TRUE);
	DemodReset();
	UartReset();
	
	// Set up the synchronous serial port
	FpgaSetupSsc();

	// connect Demodulated Signal to ADC:
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Signal field is on with the appropriate LED
    LED_D_ON();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX | FPGA_HF_READER_TX_SHALLOW_MOD);
	SpinDelay(20);
	// Start the timer
	//StartCountSspClk();
	
	// initalize CRC 
	crc_init(&legic_crc, 4, 0x19 >> 1, 0x5, 0);

	// initalize prng
	legic_prng_init(0);
}