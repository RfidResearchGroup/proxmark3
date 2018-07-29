//-----------------------------------------------------------------------------
// (c) 2009 Henryk Plötz <henryk@ploetzli.ch>
//     2016 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEGIC RF simulation code
//-----------------------------------------------------------------------------
#include "legicrf.h"

static struct legic_frame {
	uint8_t bits;
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




// At TIMER_CLOCK3 (MCK/32)
// testing calculating in ticks. 1.5ticks = 1us 
#define	RWD_TIME_1 120		// READER_TIME_PAUSE 20us off, 80us on = 100us  80 * 1.5 == 120ticks
#define RWD_TIME_0 60		// READER_TIME_PAUSE 20us off, 40us on = 60us   40 * 1.5 == 60ticks 
#define RWD_TIME_PAUSE 30	// 20us == 20 * 1.5 == 30ticks */
#define TAG_BIT_PERIOD 142	// 100us == 100 * 1.5 == 150ticks
#define TAG_FRAME_WAIT 495  // 330us from READER frame end to TAG frame start. 330 * 1.5 == 495

#define RWD_TIME_FUZZ 20   // rather generous 13us, since the peak detector + hysteresis fuzz quite a bit

#define SIM_DIVISOR  586   /* prng_time/SIM_DIVISOR count prng needs to be forwared */
#define SIM_SHIFT    900   /* prng_time+SIM_SHIFT shift of delayed start */

#define OFFSET_LOG 1024

#define FUZZ_EQUAL(value, target, fuzz) ((value) > ((target)-(fuzz)) && (value) < ((target)+(fuzz)))

#ifndef SHORT_COIL
# define SHORT_COIL	 LOW(GPIO_SSC_DOUT);
#endif
#ifndef OPEN_COIL
# define OPEN_COIL	HIGH(GPIO_SSC_DOUT);
#endif
#ifndef LINE_IN
# define LINE_IN  AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DIN;
#endif
// Pause pulse,  off in 20us / 30ticks,
// ONE / ZERO bit pulse,  
//    one == 80us / 120ticks
//    zero == 40us / 60ticks
#ifndef COIL_PULSE
# define COIL_PULSE(x) \
	do { \
		SHORT_COIL; \
		WaitTicks( (RWD_TIME_PAUSE) ); \
		OPEN_COIL; \
		WaitTicks((x)); \
	} while (0); 
#endif

// ToDo: define a meaningful maximum size for auth_table. The bigger this is, the lower will be the available memory for traces. 
// Historically it used to be FREE_BUFFER_SIZE, which was 2744.
#define LEGIC_CARD_MEMSIZE 1024
static uint8_t* cardmem;

static void frame_append_bit(struct legic_frame * const f, uint8_t bit) {
	// Overflow, won't happen
   if (f->bits >= 31) return;
  
   f->data |= (bit << f->bits);
   f->bits++;
}

static void frame_clean(struct legic_frame * const f) {
	f->data = 0;
	f->bits = 0;
}



}

/* Generate Keystream */
uint32_t get_key_stream(int skip, int count) {

	int i;

	// Use int to enlarge timer tc to 32bit
	legic_prng_bc += prng_timer->TC_CV;

	// reset the prng timer.

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

	/* Generate KeyStream */
	return legic_prng_get_bits(count);
}

/* Send a frame in tag mode, the FPGA must have been set up by
 * LegicRfSimulate
 */
void frame_send_tag(uint16_t response, uint8_t bits) {

	uint16_t mask = 1;
	
	/* Bitbang the response */
	SHORT_COIL;
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;

	 /* TAG_FRAME_WAIT -> shift by 2 */
	legic_prng_forward(3);
	response ^= legic_prng_get_bits(bits);

	/* Wait for the frame start */
	WaitTicks( TAG_FRAME_WAIT );

	for (; mask < BITMASK(bits); mask <<= 1) {	
		if (response & mask)
			OPEN_COIL
		else
			SHORT_COIL
		WaitTicks(TAG_BIT_PERIOD);
   }
   SHORT_COIL;
}

/* Send a frame in reader mode, the FPGA must have been set up by
 * LegicRfReader
 */
void frame_sendAsReader(uint32_t data, uint8_t bits){

	uint32_t starttime = GET_TICKS, send = 0, mask = 1;
	
	// xor lsfr onto data.
	send = data ^ legic_prng_get_bits(bits);
				
	for (; mask < BITMASK(bits); mask <<= 1) {	
		if (send & mask)
			COIL_PULSE(RWD_TIME_1)
		else
			COIL_PULSE(RWD_TIME_0)
	}

	// Final pause to mark the end of the frame
	COIL_PULSE(0);
	
	// log
	uint8_t cmdbytes[] = {bits, BYTEx(data,0), BYTEx(data,1), BYTEx(data,2), BYTEx(send,0), BYTEx(send,1), BYTEx(send,2)};
	LogTrace(cmdbytes, sizeof(cmdbytes), starttime, GET_TICKS, NULL, true);
}

/* Receive a frame from the card in reader emulation mode, the FPGA and
 * timer must have been set up by LegicRfReader and frame_sendAsReader.
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
 * timer that's still running from frame_sendAsReader in order to get a synchronization
 * with the frame that we just sent.
 *
 * FIXME: Because we're relying on the hysteresis to just do the right thing
 * the range is severely reduced (and you'll probably also need a good antenna).
 * So this should be fixed some time in the future for a proper receiver.
 */
static void frame_receiveAsReader(struct legic_frame * const f, uint8_t bits) {

	if ( bits > 32 ) return;
	
	uint8_t i = bits, edges = 0;	
	uint32_t the_bit = 1, next_bit_at = 0, data = 0;
	uint32_t old_level = 0;
	volatile uint32_t level = 0;
	
	frame_clean(f);
	
	// calibrate the prng.
	legic_prng_forward(2);
	data = legic_prng_get_bits(bits);
	
	//FIXED time between sending frame and now listening frame. 330us
	uint32_t starttime = GET_TICKS;
	// its about 9+9 ticks delay from end-send to here.
	WaitTicks( 477 );

	next_bit_at = GET_TICKS + TAG_BIT_PERIOD;

	while ( i-- ){
		edges = 0;
		while  ( GET_TICKS < next_bit_at) {

			level = (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN);
			
			if (level != old_level)
				++edges;
			
			old_level = level;
		}		

		next_bit_at += TAG_BIT_PERIOD;
		
		// We expect 42 edges (ONE)
		if ( edges > 20 )
			data ^= the_bit;

		the_bit <<= 1;	
	}

	// output
	f->data = data;
	f->bits = bits;
	
	// log
	uint8_t cmdbytes[] = {bits,	BYTEx(data, 0),	BYTEx(data, 1)};
	LogTrace(cmdbytes, sizeof(cmdbytes), starttime, GET_TICKS, NULL, false);
}

// Setup pm3 as a Legic Reader
static uint32_t setup_phase_reader(uint8_t iv) {
	
	// Switch on carrier and let the tag charge for 5ms
	HIGH(GPIO_SSC_DOUT);
	WaitUS(5000);
	
	ResetTicks();
	
	legic_prng_init(0);
	
	// send IV handshake
	frame_sendAsReader(iv, 7);

	// tag and reader has same IV.
	legic_prng_init(iv);

	frame_receiveAsReader(&current_frame, 6);

	// 292us (438t) - fixed delay before sending ack.
	// minus log and stuff 100tick?
	WaitTicks(338);
	legic_prng_forward(3); 
	
	// Send obsfuscated acknowledgment frame.
	// 0x19 = 0x18 MIM22, 0x01 LSB READCMD 
	// 0x39 = 0x38 MIM256, MIM1024 0x01 LSB READCMD 
	switch ( current_frame.data  ) {
		case 0x0D: frame_sendAsReader(0x19, 6); break;
		case 0x1D: 
		case 0x3D: frame_sendAsReader(0x39, 6); break;
		default: break;
	}

	legic_prng_forward(2);
	return current_frame.data;
}

void LegicCommonInit(bool clear_mem) {

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX);
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	/* Bitbang the transmitter */
	SHORT_COIL;
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_DIN;
	
	// reserve a cardmem,  meaning we can use the tracelog function in bigbuff easier.
	cardmem = BigBuf_get_EM_addr();
	if ( clear_mem )
		memset(cardmem, 0x00, LEGIC_CARD_MEMSIZE);

	clear_trace();
	set_tracing(true);
	crc_init(&legic_crc, 4, 0x19 >> 1, 0x5, 0);
	
	StartTicks();
}

// Switch off carrier, make sure tag is reset
static void switch_off_tag_rwd(void) {
	SHORT_COIL;
	WaitUS(20);
	WDT_HIT();
}

// calculate crc4 for a legic READ command 
static uint32_t legic4Crc(uint8_t cmd, uint16_t byte_index, uint8_t value, uint8_t cmd_sz) {
	crc_clear(&legic_crc);	
	uint32_t temp =  (value << cmd_sz) | (byte_index << 1) | cmd;
	crc_update(&legic_crc, temp, cmd_sz + 8 );
	return crc_finish(&legic_crc);
}

int legic_read_byte( uint16_t index, uint8_t cmd_sz) {

	uint8_t byte, crc, calcCrc = 0;
	uint32_t cmd = (index << 1) | LEGIC_READ;
	
	// 90ticks = 60us (should be 100us but crc calc takes time.)
	//WaitTicks(330); // 330ticks prng(4) - works
	WaitTicks(240); // 240ticks prng(3) - works
	
	frame_sendAsReader(cmd, cmd_sz);
	frame_receiveAsReader(&current_frame, 12);

	// CRC check. 
	byte = BYTEx(current_frame.data, 0);
	crc = BYTEx(current_frame.data, 1);
	calcCrc = legic4Crc(LEGIC_READ, index, byte, cmd_sz);

	if( calcCrc != crc ) {
		Dbprintf("!!! crc mismatch: %x != %x !!!",  calcCrc, crc);
		return -1;
	}

	legic_prng_forward(3);
	return byte;
}

/* 
 * - assemble a write_cmd_frame with crc and send it
 * - wait until the tag sends back an ACK ('1' bit unencrypted)
 * - forward the prng based on the timing
 */
bool legic_write_byte(uint16_t index, uint8_t byte, uint8_t addr_sz) {

	bool isOK = false;
	int8_t i = 40;
	uint8_t edges = 0;
	uint8_t	cmd_sz = addr_sz+1+8+4; //crc+data+cmd;
	uint32_t steps = 0, next_bit_at, start, crc, old_level = 0;

	crc = legic4Crc(LEGIC_WRITE, index, byte, addr_sz+1);

	// send write command
	uint32_t cmd = LEGIC_WRITE;
	cmd |= index << 1;			  // index
	cmd |= byte  << (addr_sz+1);  // Data	
	cmd	|= (crc & 0xF ) << (addr_sz+1+8); 	// CRC
	
	WaitTicks(240);
	
	frame_sendAsReader(cmd, cmd_sz);
	
	LINE_IN;

	start = GET_TICKS;

	// ACK,  - one single "1" bit after 3.6ms
	// 3.6ms = 3600us * 1.5 = 5400ticks.
	WaitTicks(5400);
	
	next_bit_at = GET_TICKS + TAG_BIT_PERIOD;
	
    while ( i-- ) {
		WDT_HIT();
        edges = 0;
        while ( GET_TICKS < next_bit_at) {
			
            volatile uint32_t level = (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN);
            
			if (level != old_level)
                ++edges;

            old_level = level;
        }
		
		next_bit_at += TAG_BIT_PERIOD;
		
		// We expect 42 edges (ONE)
        if(edges > 20 ) {
			steps = ( (GET_TICKS - start) / TAG_BIT_PERIOD);			
			legic_prng_forward(steps);
        	isOK = true;
			goto OUT;
        }
    }
		
OUT: ;
	legic_prng_forward(1);
	
	uint8_t cmdbytes[] = {1, isOK, BYTEx(steps, 0), BYTEx(steps, 1) };
	LogTrace(cmdbytes, sizeof(cmdbytes), start, GET_TICKS, NULL, false);
	return isOK;
}

int LegicRfReader(uint16_t offset, uint16_t len, uint8_t iv) {
	
	uint16_t i = 0;
	uint8_t isOK = 1;
	legic_card_select_t card;
	
	LegicCommonInit(true);
	
	if ( legic_select_card_iv(&card, iv) ) {
		isOK = 0;
		goto OUT;
	}

	if (len + offset > card.cardsize)
		len = card.cardsize - offset;

	LED_B_ON();
	while (i < len) {
		int r = legic_read_byte(offset + i, card.cmdsize);
		
		if (r == -1 || BUTTON_PRESS()) {			
	        if ( MF_DBGLEVEL >= 2) DbpString("operation aborted");
			isOK = 0;
			goto OUT;
		}
		cardmem[i++] = r;
        WDT_HIT();
	}

OUT:	
	WDT_HIT();
	switch_off_tag_rwd();
	LEDsoff();
	cmd_send(CMD_ACK, isOK, len, 0, cardmem, len);
    return 0;
}

void LegicRfWriter(uint16_t offset, uint16_t len, uint8_t iv, uint8_t *data) {

	#define LOWERLIMIT 4
	uint8_t isOK = 1, msg = 0;
	legic_card_select_t card;
	
	// uid NOT is writeable.
	if ( offset <= LOWERLIMIT ) {
		isOK = 0;
		goto OUT;
	}
	
	LegicCommonInit(false);
	
	if ( legic_select_card_iv(&card, iv) ) {
		isOK = 0;
		msg = 1;
		goto OUT;
	}
	
	if ( len + offset > card.cardsize)
		len = card.cardsize - offset;

    LED_B_ON();	
	while( len > 0 ) {
		--len;		
		if ( !legic_write_byte( len + offset, data[len], card.addrsize) ) {
			Dbprintf("operation failed | %02X | %02X | %02X", len + offset, len, data[len] );
			isOK = 0;
			goto OUT;
		}
		WDT_HIT();
	}
OUT:
	cmd_send(CMD_ACK, isOK, msg,0,0,0);
	switch_off_tag_rwd();
	LEDsoff();	
}

int legic_select_card_iv(legic_card_select_t *p_card, uint8_t iv){

	if ( p_card == NULL ) return 1;
	
	p_card->tagtype = setup_phase_reader(iv);
	
	switch(p_card->tagtype) {
		case 0x0d:
            p_card->cmdsize = 6;
			p_card->addrsize = 5;
			p_card->cardsize = 22;
			break;
		case 0x1d:
			p_card->cmdsize = 9;
			p_card->addrsize = 8;
			p_card->cardsize = 256;
			break;
		case 0x3d:
            p_card->cmdsize = 11;
			p_card->addrsize = 10;
			p_card->cardsize = 1024;
			break;
		default: 
		    p_card->cmdsize = 0;
			p_card->addrsize = 0;
			p_card->cardsize = 0;
			return 2;
	}
	return 0;
}
int legic_select_card(legic_card_select_t *p_card){
	return legic_select_card_iv(p_card, 0x01);
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

void LegicRfInfo(void){

	int r;
	
	uint8_t buf[sizeof(legic_card_select_t)] = {0x00};
	legic_card_select_t *card = (legic_card_select_t*) buf;
	
	LegicCommonInit(false);

	if ( legic_select_card(card) ) {
		cmd_send(CMD_ACK,0,0,0,0,0);
		goto OUT;
	}

	// read UID bytes
	for ( uint8_t i = 0; i < sizeof(card->uid); ++i) {
		r = legic_read_byte(i, card->cmdsize);
		if ( r == -1 ) {
			cmd_send(CMD_ACK,0,0,0,0,0);
			goto OUT;
		}
		card->uid[i] = r & 0xFF;
	}

	// MCC byte.
	r = legic_read_byte(4, card->cmdsize);
	uint32_t calc_mcc =  CRC8Legic(card->uid, 4);;
	if ( r != calc_mcc) {
		cmd_send(CMD_ACK,0,0,0,0,0);
		goto OUT;
	}
	
	// OK
	cmd_send(CMD_ACK, 1, 0, 0, buf, sizeof(legic_card_select_t));

OUT:
	switch_off_tag_rwd();
	LEDsoff();
}

/* Handle (whether to respond) a frame in tag mode
 * Only called when simulating a tag.
 */
static void frame_handle_tag(struct legic_frame const * const f)
{
	// log
	//uint8_t cmdbytes[] = {bits,	BYTEx(data, 0),	BYTEx(data, 1)};
	//LogTrace(cmdbytes, sizeof(cmdbytes), starttime, GET_TICKS, NULL, false);
	//Dbprintf("ICE: enter frame_handle_tag: %02x ", f->bits);
		
	/* First Part of Handshake (IV) */
	if(f->bits == 7) {

		LED_C_ON();

		// Reset prng timer
		//ResetTimer(prng_timer);
		ResetTicks();

		// IV from reader.
		legic_prng_init(f->data);
		
		Dbprintf("ICE: IV: %02x ", f->data);
		
		// We should have three tagtypes with three different answers.
		legic_prng_forward(2);
		//frame_send_tag(0x3d, 6); /* MIM1024 0x3d^0x26 = 0x1B */
		frame_send_tag(0x1d, 6); // MIM256
		
		legic_state = STATE_IV;
		legic_read_count = 0;
		legic_prng_bc = 0;
		legic_prng_iv = f->data;

		//ResetTimer(timer);
		//WaitUS(280);
		WaitTicks(388);
		return;
	}

   /* 0x19==??? */
   if(legic_state == STATE_IV) {
      uint32_t local_key = get_key_stream(3, 6);
      int xored = 0x39 ^ local_key;
      if((f->bits == 6) && (f->data == xored)) {
         legic_state = STATE_CON;

		 ResetTimer(timer);
		 WaitTicks(300);
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
         uint32_t key = get_key_stream(2, 11); //legic_phase_drift, 11);
         uint16_t addr = f->data ^ key; 
		 addr >>= 1;
         uint8_t data = cardmem[addr];
		 
         uint32_t crc = legic4Crc(LEGIC_READ, addr, data, 11) << 8;

         //legic_read_count++;
         //legic_prng_forward(legic_reqresp_drift);

         frame_send_tag(crc | data, 12);
		 //ResetTimer(timer);
         legic_prng_forward(2);
		 WaitTicks(330);
         return;
      }
   }

   /* Write */
   if (f->bits == 23 || f->bits == 21 ) {
      uint32_t key  = get_key_stream(-1, 23); //legic_frame_drift, 23);
      uint16_t addr = f->data ^ key; 
	  addr >>= 1; 
	  addr &= 0x3ff;
      uint32_t data = f->data ^ key; 
	  data >>= 11; 
	  data &= 0xff;

	  cardmem[addr] = data;
      /* write command */
      legic_state = STATE_DISCON;
      LED_C_OFF();
      Dbprintf("write - addr: %x, data: %x", addr, data);
	  // should send a ACK after 3.6ms 
      return;
   }

   if(legic_state != STATE_DISCON) {
      Dbprintf("Unexpected: sz:%u, Data:%03.3x, State:%u, Count:%u", f->bits, f->data, legic_state, legic_read_count);
      Dbprintf("IV: %03.3x", legic_prng_iv);
   }

	legic_state = STATE_DISCON; 
	legic_read_count = 0;
	WaitMS(10);
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
   * seems to be 330us.
   */
		
	int old_level = 0, active = 0;
	volatile int32_t level = 0;
	
	legic_state = STATE_DISCON;
	legic_phase_drift = phase;
	legic_frame_drift = frame;
	legic_reqresp_drift = reqresp;


	/* to get the stream of bits from FPGA in sim mode.*/
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	// Set up the synchronous serial port
	//FpgaSetupSsc();
	// connect Demodulated Signal to ADC:
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_212K);
	//FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_NO_MODULATION);

	#define LEGIC_DMA_BUFFER 256
	// The DMA buffer, used to stream samples from the FPGA
	//uint8_t *dmaBuf = BigBuf_malloc(LEGIC_DMA_BUFFER);
	//uint8_t *data = dmaBuf;
	// Setup and start DMA.
	// if ( !FpgaSetupSscDma((uint8_t*) dmaBuf, LEGIC_DMA_BUFFER) ){
		// if (MF_DBGLEVEL > 1) Dbprintf("FpgaSetupSscDma failed. Exiting"); 
		// return;
	// }

	//StartCountSspClk();
	/* Bitbang the receiver */
	AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_DIN;
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DIN;

	// need a way to determine which tagtype we are simulating
	
	// hook up emulator memory  
	cardmem = BigBuf_get_EM_addr();
	
	clear_trace();
	set_tracing(true);

	crc_init(&legic_crc, 4, 0x19 >> 1, 0x5, 0);

	StartTicks();

	LED_B_ON();
	DbpString("Starting Legic emulator, press button to end");
	
	/*
	 * The mode FPGA_HF_SIMULATOR_MODULATE_212K works like this.
	 * - A 1-bit input to the FPGA becomes 8 pulses on 212kHz (fc/64) (18.88us).
	 * - A 0-bit input to the FPGA becomes an unmodulated time of 18.88us
	 *
	 * In this mode the SOF can be written as 00011101 = 0x1D
	 * The EOF can be written as 10111000 = 0xb8
	 * A logic 1 is 01
	 * A logic 0 is 10
	volatile uint8_t b;
	uint8_t i = 0;
	while( !BUTTON_PRESS() ) {
		WDT_HIT();

		// not sending anything.
        if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
            AT91C_BASE_SSC->SSC_THR = 0x00;
        }

		// receive
		if ( AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY ) {
			b = (uint8_t) AT91C_BASE_SSC->SSC_RHR;
			bd[i] = b;
			++i;
	//		if(OutOfNDecoding(b & 0x0f))
	//				*len = Uart.byteCnt;
			}
		
	}
	 */

	while(!BUTTON_PRESS() && !usb_poll_validate_length()) {
		
		level = !!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN);

		uint32_t time = GET_TICKS;

		if (level != old_level) {
			if (level == 1) {

				//Dbprintf("start, %u ", time);
				StartTicks();
				// did we get a signal 
				if (FUZZ_EQUAL(time, RWD_TIME_1, RWD_TIME_FUZZ)) {
					// 1 bit 
					emit(1);
					active = 1;
					LED_A_ON();
				} else if (FUZZ_EQUAL(time, RWD_TIME_0, RWD_TIME_FUZZ)) {
					// 0 bit 
					emit(0);
					active = 1;
					LED_A_ON();
				} else if (active) {
					// invalid 
					emit(-1);
					active = 0;
					LED_A_OFF();
				}
			}
		}

	
		/* Frame end */
		if(time >= (RWD_TIME_1 + RWD_TIME_FUZZ) && active) {
			emit(-1);
			active = 0;
			LED_A_OFF();
		}

		/*
		* Disable the counter, Then wait for the clock to acknowledge the
		* shutdown in its status register. Reading the SR has the
		* side-effect of clearing any pending state in there.
		*/
		//if(time >= (20*RWD_TIME_1) && (timer->TC_SR & AT91C_TC_CLKSTA))
		if(time >= (20 * RWD_TIME_1) )
			StopTicks();

		old_level = level;
		WDT_HIT();
}

	WDT_HIT();
	DbpString("LEGIC Prime emulator stopped");
	switch_off_tag_rwd();
	FpgaDisableSscDma();
	LEDsoff();
	cmd_send(CMD_ACK, 1, 0, 0, 0, 0);
}
}

}