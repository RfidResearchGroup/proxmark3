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

AT91PS_TC timer;
AT91PS_TC prng_timer;

/*
static void setup_timer(void) {
	// Set up Timer 1 to use for measuring time between pulses. Since we're bit-banging
	// this it won't be terribly accurate but should be good enough.
	//
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC1);
	timer = AT91C_BASE_TC1;
	timer->TC_CCR = AT91C_TC_CLKDIS;
	timer->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK;
	timer->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

	// 
    // Set up Timer 2 to use for measuring time between frames in 
    // tag simulation mode. Runs 4x faster as Timer 1
	//
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_TC2);
    prng_timer = AT91C_BASE_TC2;
    prng_timer->TC_CCR = AT91C_TC_CLKDIS;
	prng_timer->TC_CMR = AT91C_TC_CLKS_TIMER_DIV2_CLOCK;
    prng_timer->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
}

	AT91C_BASE_PMC->PMC_PCER |= (0x1 << 12) | (0x1 << 13) | (0x1 << 14);
	AT91C_BASE_TCB->TCB_BMR = AT91C_TCB_TC0XC0S_NONE | AT91C_TCB_TC1XC1S_TIOA0 | AT91C_TCB_TC2XC2S_NONE;

	// fast clock
	AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS; // timer disable
	AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK | // MCK(48MHz)/32 -- tick=1.5mks
								AT91C_TC_WAVE | AT91C_TC_WAVESEL_UP_AUTO | AT91C_TC_ACPA_CLEAR |
								AT91C_TC_ACPC_SET | AT91C_TC_ASWTRG_SET;
	AT91C_BASE_TC0->TC_RA = 1;
	AT91C_BASE_TC0->TC_RC = 0xBFFF + 1; // 0xC000
	
*/

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

// Prng works when waiting in 99.1us cycles.
// and while sending/receiving in bit frames (100, 60)
/*static void CalibratePrng( uint32_t time){
	// Calculate Cycles based on timer 100us
	uint32_t i =  (time - sendFrameStop) / 100 ;

	// substract cycles of finished frames
	int k =  i - legic_prng_count()+1; 

	// substract current frame length, rewind to beginning
	if ( k > 0 )
		legic_prng_forward(k);
}
*/

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
// Work with emulator memory
// 
// Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_HF) here although FPGA is not
// involved in dealing with emulator memory. But if it is called later, it might
// destroy the Emulator Memory.
//-----------------------------------------------------------------------------
// arg0 = offset
// arg1 = num of bytes
void LegicEMemSet(uint32_t arg0, uint32_t arg1, uint8_t *data) {
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	legic_emlset_mem(data, arg0, arg1);
}
// arg0 = offset
// arg1 = num of bytes
void LegicEMemGet(uint32_t arg0, uint32_t arg1) {
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	uint8_t buf[USB_CMD_DATA_SIZE] = {0x00};
	legic_emlget_mem(buf, arg0, arg1);
	LED_B_ON();
	cmd_send(CMD_ACK, arg0, arg1, 0, buf, USB_CMD_DATA_SIZE);
	LED_B_OFF();
}
void legic_emlset_mem(uint8_t *data, int offset, int numofbytes) {
	cardmem = BigBuf_get_EM_addr();
	memcpy(cardmem + offset, data, numofbytes);
}
void legic_emlget_mem(uint8_t *data, int offset, int numofbytes) {
	cardmem = BigBuf_get_EM_addr();
	memcpy(data, cardmem + offset, numofbytes);
}

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
/*
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
*/
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

	// return false;
// }
/*

static void UartReset() {
	Uart.byteCntMax = 3;
	Uart.state = STATE_UNSYNCD;
	Uart.byteCnt = 0;
	Uart.bitCnt = 0;
	Uart.posCnt = 0;
	memset(Uart.output, 0x00, 3);
}
*/
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
/*
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
*/
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
 
/*
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
							return true;
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
	return false;
}
*/
/*
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
*/

/*
 *  Demodulate the samples we received from the tag, also log to tracebuffer
 *  quiet: set to 'TRUE' to disable debug output
 */
 
 /*
 #define LEGIC_DMA_BUFFER_SIZE 256

 static void GetSamplesForLegicDemod(int n, bool quiet)
{
	int max = 0;
	bool gotFrame = false;
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
		LogTrace(Demod.output, Demod.len, 0, 0, parity, false);
	}
}

*/

//-----------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
//-----------------------------------------------------------------------------
/*
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
*/

//-----------------------------------------------------------------------------
// Code a layer 2 command (string of octets, including CRC) into ToSend[],
// so that it is ready to transmit to the tag using TransmitForLegic().
//-----------------------------------------------------------------------------
/*
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
*/
/**
  Convenience function to encode, transmit and trace Legic comms
  **/
/*
  static void CodeAndTransmitLegicAsReader(const uint8_t *cmd, uint8_t cmdlen, int bits)
{
	CodeLegicBitsAsReader(cmd, cmdlen, bits);
	TransmitForLegic();
	if (tracing) {
		uint8_t parity[1] = {0x00};
		LogTrace(cmd, cmdlen, 0, 0, parity, true);
	}
}

*/
// Set up LEGIC communication
/*
void ice_legic_setup() {

	// standard things.
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	BigBuf_free(); BigBuf_Clear_ext(false);
	clear_trace();
	set_tracing(true);
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
*/