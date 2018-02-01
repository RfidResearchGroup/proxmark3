//-----------------------------------------------------------------------------
// Jonathan Westhues, split Nov 2006
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443B. This includes both the reader software and
// the `fake tag' modes.
//-----------------------------------------------------------------------------
#include "iso14443b.h"

#ifndef FWT_TIMEOUT_14B
// defaults to 2000ms
# define FWT_TIMEOUT_14B 35312
#endif
#ifndef ISO14443B_DMA_BUFFER_SIZE
# define ISO14443B_DMA_BUFFER_SIZE 256
#endif
#ifndef RECEIVE_MASK
# define RECEIVE_MASK  (ISO14443B_DMA_BUFFER_SIZE-1)
#endif

// Guard Time (per 14443-2)
#ifndef TR0
# define TR0 0
#endif

// Synchronization time (per 14443-2)
#ifndef TR1
# define TR1 0
#endif
// Frame Delay Time PICC to PCD  (per 14443-3 Amendment 1)
#ifndef TR2
# define TR2 0
#endif

// 4sample
#define SEND4STUFFBIT(x) ToSendStuffBit(x);ToSendStuffBit(x);ToSendStuffBit(x);ToSendStuffBit(x);
//#define SEND4STUFFBIT(x) ToSendStuffBit(x);
 // iceman, this threshold value,  what makes 8 a good amplitude for this IQ values? 
#ifndef SUBCARRIER_DETECT_THRESHOLD
# define SUBCARRIER_DETECT_THRESHOLD	8
#endif

static void iso14b_set_timeout(uint32_t timeout);
static void iso14b_set_maxframesize(uint16_t size);

// the block number for the ISO14443-4 PCB  (used with APDUs)
static uint8_t pcb_blocknum = 0;
static uint32_t iso14b_timeout = FWT_TIMEOUT_14B;

//=============================================================================
// An ISO 14443 Type B tag. We listen for commands from the reader, using
// a UART kind of thing that's implemented in software. When we get a
// frame (i.e., a group of bytes between SOF and EOF), we check the CRC.
// If it's good, then we can do something appropriate with it, and send
// a response.
//=============================================================================


//-----------------------------------------------------------------------------
// The software UART that receives commands from the reader, and its state variables.
//-----------------------------------------------------------------------------
static struct {
	enum {
		STATE_UNSYNCD,
		STATE_GOT_FALLING_EDGE_OF_SOF,
		STATE_AWAITING_START_BIT,
		STATE_RECEIVING_DATA
	}       state;
	uint16_t shiftReg;
	int      bitCnt;
	int      byteCnt;
	int      byteCntMax;
	int      posCnt;
	uint8_t  *output;
} Uart;

static void UartReset() {
	Uart.state = STATE_UNSYNCD;
	Uart.shiftReg = 0;
	Uart.bitCnt = 0;
	Uart.byteCnt = 0;
	Uart.byteCntMax = MAX_FRAME_SIZE;
	Uart.posCnt = 0;
}

static void UartInit(uint8_t *data) {
	Uart.output = data;
	UartReset();
//		memset(Uart.output, 0x00, MAX_FRAME_SIZE);
}

//-----------------------------------------------------------------------------
// The software Demod that receives commands from the tag, and its state variables.
//-----------------------------------------------------------------------------
static struct {
	enum {
		DEMOD_UNSYNCD,
		DEMOD_PHASE_REF_TRAINING,
		DEMOD_AWAITING_FALLING_EDGE_OF_SOF,
		DEMOD_GOT_FALLING_EDGE_OF_SOF,
		DEMOD_AWAITING_START_BIT,
		DEMOD_RECEIVING_DATA
	}       state;
	uint16_t bitCount;
	int      posCount;
	int      thisBit;
/* this had been used to add RSSI (Received Signal Strength Indication) to traces. Currently not implemented.
	int     metric;
	int     metricN;
*/
	uint16_t shiftReg;
	uint8_t  *output;
	uint16_t len;
	int      sumI;
	int      sumQ;
	uint32_t startTime, endTime;
} Demod;

// Clear out the state of the "UART" that receives from the tag.
static void DemodReset() {
	Demod.state = DEMOD_UNSYNCD;
	Demod.bitCount = 0;
	Demod.posCount = 0;
	Demod.thisBit = 0;
	Demod.shiftReg = 0;
	Demod.len = 0;
	Demod.sumI = 0;
	Demod.sumQ = 0;
	Demod.startTime = 0;
	Demod.endTime = 0;	
}

static void DemodInit(uint8_t *data) {
	Demod.output = data;
	DemodReset();
	//	memset(Demod.output, 0x00, MAX_FRAME_SIZE); 
}


/*
* 9.4395 us = 1 ETU  and clock is about 1.5 us
* 13560000Hz 
* 1000ms/s
* timeout in ETUs (time to transfer 1 bit, 9.4395 us)
*
* Formula to calculate FWT (in ETUs) by timeout (in ms):
* fwt = 13560000 * 1000 / (8*16) * timeout; 
* Sample:  3sec == 3000ms
*  13560000 * 1000 / (8*16) * 3000  == 
*    13560000000 / 384000 = 35312 FWT
* @param timeout is in frame wait time, fwt, measured in ETUs
*/ 
static void iso14b_set_timeout(uint32_t timeout) {
	#define MAX_TIMEOUT 40542464 	// 13560000Hz * 1000ms / (2^32-1) * (8*16)
	if(timeout > MAX_TIMEOUT)
		timeout = MAX_TIMEOUT;

	iso14b_timeout = timeout;
	if(MF_DBGLEVEL >= 3) Dbprintf("ISO14443B Timeout set to %ld fwt", iso14b_timeout);
}
static void iso14b_set_maxframesize(uint16_t size) {
	if (size > 256)
		size = MAX_FRAME_SIZE;
	
	Uart.byteCntMax = size;
	if(MF_DBGLEVEL >= 3) Dbprintf("ISO14443B Max frame size set to %d bytes", Uart.byteCntMax);
}

//-----------------------------------------------------------------------------
// Code up a string of octets at layer 2 (including CRC, we don't generate
// that here) so that they can be transmitted to the reader. Doesn't transmit
// them yet, just leaves them ready to send in ToSend[].
//-----------------------------------------------------------------------------
static void CodeIso14443bAsTag(const uint8_t *cmd, int len) {
	/* ISO 14443 B
	*
	* Reader to card | ASK  - Amplitude Shift Keying Modulation (PCD to PICC for Type B) (NRZ-L encodig)
	* Card to reader | BPSK - Binary Phase Shift Keying Modulation, (PICC to PCD for Type B)
	*
	* fc - carrier frequency 13.56mHz
	* TR0 - Guard Time per 14443-2
	* TR1 - Synchronization Time per 14443-2
	* TR2 - PICC to PCD Frame Delay Time (per 14443-3 Amendment 1)
	*
	* Elementary Time Unit (ETU) is
	* - 128 Carrier Cycles (9.4395 µS) = 8 Subcarrier Units 
	* - 1 ETU = 1 bit
	* - 10 ETU = 1 startbit, 8 databits, 1 stopbit (10bits length)
	* - startbit is a 0
	* - stopbit is a 1
	*
	* Start of frame (SOF) is
	* - [10-11] ETU of ZEROS, unmodulated time
	* - [2-3] ETU of ONES,  
	*
	* End of frame (EOF) is
	* - [10-11] ETU of ZEROS, unmodulated time
	*
	*  -TO VERIFY THIS BELOW-
	* The mode FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_BPSK which we use to simulate tag
	* works like this:  
	* - A 1-bit input to the FPGA becomes 8 pulses at 847.5kHz (1.18µS / pulse) == 9.44us
	* - A 0-bit input to the FPGA becomes an unmodulated time of 1.18µS  or does it become 8 nonpulses for 9.44us
	*
	* FPGA doesn't seem to work with ETU.  It seems to work with pulse / duration instead.
	* 
	* Card sends data ub 847.e kHz subcarrier
	* subcar |duration| FC division
	* -------+--------+------------
	* 106kHz | 9.44µS | FC/128
	* 212kHz | 4.72µS | FC/64
	* 424kHz | 2.36µS | FC/32
	* 848kHz | 1.18µS | FC/16
	* -------+--------+------------
	*
	*  Reader data transmission:
	*   - no modulation ONES
	*   - SOF
	*   - Command, data and CRC_B
	*   - EOF
	*   - no modulation ONES
	*
	*  Card data transmission
	*   - TR1
	*   - SOF
	*   - data  (each bytes is:  1startbit, 8bits, 1stopbit)
	*   - CRC_B
	*   - EOF
	*
	* FPGA implementation :
	* At this point only Type A is implemented. This means that we are using a
	* bit rate of 106 kbit/s, or fc/128. Oversample by 4, which ought to make
	* things practical for the ARM (fc/32, 423.8 kbits/s, ~50 kbytes/s)
	*
	*/
	
	int i,j;
	uint8_t b;
	
	ToSendReset();

	// Transmit a burst of ones, as the initial thing that lets the
	// reader get phase sync. 
	// This loop is TR1, per specification
	// TR1 minimum must be > 80/fs
	// TR1 maximum 200/fs 
	// 80/fs < TR1 < 200/fs
	// 10 ETU < TR1 < 24 ETU

	// Send SOF.
	// 10-11 ETU * 4times samples ZEROS
	for(i = 0; i < 10; i++) { SEND4STUFFBIT(0); }
	//for(i = 0; i < 10; i++) { ToSendStuffBit(0); }
	
	// 2-3 ETU * 4times samples ONES
	for(i = 0; i < 3; i++)  { SEND4STUFFBIT(1); }
	//for(i = 0; i < 3; i++)  { ToSendStuffBit(1); }
	
	// data
	for(i = 0; i < len; ++i) {
		
		// Start bit
		SEND4STUFFBIT(0);
		//ToSendStuffBit(0);

		// Data bits
		b = cmd[i];
		for(j = 0; j < 8; ++j) {
			// if(b & 1) { 
				// SEND4STUFFBIT(1); 
				// //ToSendStuffBit(1);
			// } else {
				// SEND4STUFFBIT(0);
				// //ToSendStuffBit(0);
			// }
			SEND4STUFFBIT( b & 1 );
			b >>= 1;
		}

		// Stop bit
		SEND4STUFFBIT(1);
		//ToSendStuffBit(1);
		
		// Extra Guard bit
		// For PICC it ranges 0-18us (1etu = 9us)
		SEND4STUFFBIT(1);
		//ToSendStuffBit(1);
	}

	// Send EOF.
	// 10-11 ETU * 4 sample rate = ZEROS
	for(i = 0; i < 10; i++) { SEND4STUFFBIT(0); }
	//for(i = 0; i < 10; i++) { ToSendStuffBit(0); }
	
	// why this?
	for(i = 0; i < 40; i++) { SEND4STUFFBIT(1); }
	//for(i = 0; i < 40; i++) { ToSendStuffBit(1); }
	
	// Convert from last byte pos to length
	++ToSendMax;
}


/* Receive & handle a bit coming from the reader.
 *
 * This function is called 4 times per bit (every 2 subcarrier cycles).
 * Subcarrier frequency fs is 848kHz, 1/fs = 1,18us, i.e. function is called every 2,36us
 *
 * LED handling:
 * LED A -> ON once we have received the SOF and are expecting the rest.
 * LED A -> OFF once we have received EOF or are in error state or unsynced
 *
 * Returns: true if we received a EOF
 *          false if we are still waiting for some more
 */
static RAMFUNC int Handle14443bReaderUartBit(uint8_t bit) {
	switch (Uart.state) {
		case STATE_UNSYNCD:
			if (!bit) {
				// we went low, so this could be the beginning of an SOF
				Uart.state = STATE_GOT_FALLING_EDGE_OF_SOF;
				Uart.posCnt = 0;
				Uart.bitCnt = 0;
			}
			break;

		case STATE_GOT_FALLING_EDGE_OF_SOF:
			Uart.posCnt++;
			if (Uart.posCnt == 2) {	// sample every 4 1/fs in the middle of a bit
				if (bit) {
					if (Uart.bitCnt > 9) {
						// we've seen enough consecutive
						// zeros that it's a valid SOF
						Uart.posCnt = 0;
						Uart.byteCnt = 0;
						Uart.state = STATE_AWAITING_START_BIT;
						LED_A_ON(); // Indicate we got a valid SOF
					} else {
						// didn't stay down long enough before going high, error
						Uart.state = STATE_UNSYNCD;
					}
				} else {
					// do nothing, keep waiting
				}
				Uart.bitCnt++;
			}
			if (Uart.posCnt >= 4) Uart.posCnt = 0;
			if (Uart.bitCnt > 12) {
				// Give up if we see too many zeros without a one, too.
				LED_A_OFF();
				Uart.state = STATE_UNSYNCD;
			}
			break;

		case STATE_AWAITING_START_BIT:
			Uart.posCnt++;
			if (bit) {
				if (Uart.posCnt > 50/2) {	// max 57us between characters = 49 1/fs, max 3 etus after low phase of SOF = 24 1/fs
					// stayed high for too long between characters, error
					Uart.state = STATE_UNSYNCD;
				}
			} else {
				// falling edge, this starts the data byte
				Uart.posCnt = 0;
				Uart.bitCnt = 0;
				Uart.shiftReg = 0;
				Uart.state = STATE_RECEIVING_DATA;
			}
			break;

		case STATE_RECEIVING_DATA:
			Uart.posCnt++;
			if (Uart.posCnt == 2) {
				// time to sample a bit
				Uart.shiftReg >>= 1;
				if (bit) {
					Uart.shiftReg |= 0x200;
				}
				Uart.bitCnt++;
			}
			if (Uart.posCnt >= 4) {
				Uart.posCnt = 0;
			}
			if (Uart.bitCnt == 10) {
				if ((Uart.shiftReg & 0x200) && !(Uart.shiftReg & 0x001))
				{
					// this is a data byte, with correct
					// start and stop bits
					Uart.output[Uart.byteCnt] = (Uart.shiftReg >> 1) & 0xff;
					Uart.byteCnt++;

					if (Uart.byteCnt >= Uart.byteCntMax) {
						// Buffer overflowed, give up
						LED_A_OFF();
						Uart.state = STATE_UNSYNCD;
					} else {
						// so get the next byte now
						Uart.posCnt = 0;
						Uart.state = STATE_AWAITING_START_BIT;
					}
				} else if (Uart.shiftReg == 0x000) {
					// this is an EOF byte
					LED_A_OFF(); // Finished receiving
					Uart.state = STATE_UNSYNCD;
					if (Uart.byteCnt != 0)
						return true;
					
				} else {
					// this is an error
					LED_A_OFF();
					Uart.state = STATE_UNSYNCD;
				}
			}
			break;

		default:
			LED_A_OFF();
			Uart.state = STATE_UNSYNCD;
			break;
	}
	return false;
}

//-----------------------------------------------------------------------------
// Receive a command (from the reader to us, where we are the simulated tag),
// and store it in the given buffer, up to the given maximum length. Keeps
// spinning, waiting for a well-framed command, until either we get one
// (returns true) or someone presses the pushbutton on the board (false).
//
// Assume that we're called with the SSC (to the FPGA) and ADC path set
// correctly.
//-----------------------------------------------------------------------------
static int GetIso14443bCommandFromReader(uint8_t *received, uint16_t *len) {
	// Set FPGA mode to "simulated ISO 14443B tag", no modulation (listen
	// only, since we are receiving, not transmitting).
	// Signal field is off with the appropriate LED
	LED_D_OFF();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_NO_MODULATION);
		
	StartCountSspClk();
	
	volatile uint8_t b = 0;

	// clear receiving shift register and holding register
	// What does this loop do? Is it TR1?
	// loop is a wait/delay  ? 
   	/*
	for(uint8_t c = 0; c < 10;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0xFF;
			++c;
		}
			
		if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			b = (uint16_t)(AT91C_BASE_SSC->SSC_RHR); (void)b;
		}
	}
	*/
	
	// Now run a `software UART' on the stream of incoming samples.
	UartInit(received);

	uint8_t mask;
	while( !BUTTON_PRESS() ) {
		WDT_HIT();

		if ( AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY ) {
			b = (uint8_t) AT91C_BASE_SSC->SSC_RHR;
			for ( mask = 0x80; mask != 0; mask >>= 1) {
				if ( Handle14443bReaderUartBit(b & mask)) {
					*len = Uart.byteCnt;
					return true;
				}
			}
		}
	}	
	return false;
}

void ClearFpgaShiftingRegisters(void){

	volatile uint8_t b;

	// clear receiving shift register and holding register
	while(!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY)) {};

	b = AT91C_BASE_SSC->SSC_RHR; (void) b;

	while(!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY)) {};

	b = AT91C_BASE_SSC->SSC_RHR; (void) b;
			
	// wait for the FPGA to signal fdt_indicator == 1 (the FPGA is ready to queue new data in its delay line)
	for (uint8_t j = 0; j < 5; j++) {	// allow timeout - better late than never
		while(!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY));
		if (AT91C_BASE_SSC->SSC_RHR) break;
	}
	
	// Clear TXRDY:
	//AT91C_BASE_SSC->SSC_THR = 0xFF;
}

void WaitForFpgaDelayQueueIsEmpty( uint16_t delay ){
	// Ensure that the FPGA Delay Queue is empty before we switch to TAGSIM_LISTEN again:
	uint8_t fpga_queued_bits = delay >> 3;  // twich /8 ??   >>3, 
	for (uint8_t i = 0; i <= fpga_queued_bits/8 + 1; ) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0xFF;
			i++;
		}
	}
}

static void TransmitFor14443b_AsTag( uint8_t *response, uint16_t len) {

	volatile uint32_t b;
	
	// Signal field is off with the appropriate LED
	LED_D_OFF();
	//uint16_t fpgasendQueueDelay = 0;
	
	// Modulate BPSK
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_BPSK);
	SpinDelay(40);
	
	ClearFpgaShiftingRegisters();
	
	FpgaSetupSsc();

	// Transmit the response.
	for(uint16_t i = 0; i < len;) {
		if(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) {
			AT91C_BASE_SSC->SSC_THR = response[++i];
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			b = AT91C_BASE_SSC->SSC_RHR;(void)b;
		}			
	}
	
	//WaitForFpgaDelayQueueIsEmpty(fpgasendQueueDelay);
	AT91C_BASE_SSC->SSC_THR = 0xFF;		
}	
//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
void SimulateIso14443bTag(uint32_t pupi) {

	// setup device.
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	// Set up the synchronous serial port
	FpgaSetupSsc();
	// connect Demodulated Signal to ADC:
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	
	// allocate command receive buffer
	BigBuf_free(); BigBuf_Clear_ext(false);

	clear_trace(); //sim
	set_tracing(true);

	uint16_t len, cmdsReceived = 0;
	int cardSTATE = SIM_NOFIELD;
	int vHf = 0;	// in mV
	// uint32_t time_0 = 0;
	// uint32_t t2r_time = 0;
	// uint32_t r2t_time = 0;
	uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);	
	
	// the only commands we understand is WUPB, AFI=0, Select All, N=1:
//	static const uint8_t cmdWUPB[] = { ISO14443B_REQB, 0x00, 0x08, 0x39, 0x73 }; // WUPB
	// ... and REQB, AFI=0, Normal Request, N=1:
//	static const uint8_t cmdREQB[] = { ISO14443B_REQB, 0x00, 0x00, 0x71, 0xFF }; // REQB
	// ... and ATTRIB
//	static const uint8_t cmdATTRIB[] = { ISO14443B_ATTRIB, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // ATTRIB

	// ... if not PUPI/UID is supplied we always respond with ATQB, PUPI = 820de174, Application Data = 0x20381922,
	// supports only 106kBit/s in both directions, max frame size = 32Bytes,
	// supports ISO14443-4, FWI=8 (77ms), NAD supported, CID not supported:
	uint8_t respATQB[] = { 	0x50, 0x82, 0x0d, 0xe1, 0x74, 0x20, 0x38, 0x19, 
							0x22, 0x00, 0x21, 0x85, 0x5e, 0xd7 };
							
	// response to HLTB and ATTRIB
	static const uint8_t respOK[] = {0x00, 0x78, 0xF0};

	// ...PUPI/UID supplied from user. Adjust ATQB response accordingly
	if ( pupi > 0 ) {
		num_to_bytes(pupi, 4, respATQB+1);
		AddCrc14B(respATQB, 12);
	}

	// prepare "ATQB" tag answer (encoded):
	CodeIso14443bAsTag(respATQB, sizeof(respATQB));
	uint8_t *encodedATQB = BigBuf_malloc(ToSendMax);
	uint16_t encodedATQBLen = ToSendMax;
	memcpy(encodedATQB, ToSend, ToSendMax); 

	
	// prepare "OK" tag answer (encoded):
	CodeIso14443bAsTag(respOK, sizeof(respOK));
	uint8_t *encodedOK = BigBuf_malloc(ToSendMax);
	uint16_t encodedOKLen = ToSendMax;	
	memcpy(encodedOK, ToSend, ToSendMax); 
	
	// Simulation loop
	while (!BUTTON_PRESS() && !usb_poll_validate_length()) {
		WDT_HIT();

		// find reader field
		if (cardSTATE == SIM_NOFIELD) {
			vHf = (MAX_ADC_HF_VOLTAGE * AvgAdc(ADC_CHAN_HF)) >> 10;
			if ( vHf > MF_MINFIELDV ) {
				cardSTATE = SIM_IDLE; 
				LED_A_ON();
			}
		} 
		if (cardSTATE == SIM_NOFIELD) continue;

		// Get reader command
		if (!GetIso14443bCommandFromReader(receivedCmd, &len)) {
			Dbprintf("button pressed, received %d commands", cmdsReceived);
			break;
		}

		// ISO14443-B protocol states:
		// REQ or WUP request in ANY state 
		// WUP in HALTED state
		if (len == 5 ) {
				if ( (receivedCmd[0] == ISO14443B_REQB && (receivedCmd[2] & 0x8)== 0x8 && cardSTATE == SIM_HALTED) ||
            	      receivedCmd[0] == ISO14443B_REQB ){
				LogTrace(receivedCmd, len, 0, 0, NULL, true);						  
				cardSTATE = SIM_SELECTING;
			}
		}
		
		/*
		* How should this flow go?
		*  REQB or WUPB
		*   send response  ( waiting for Attrib)
		*  ATTRIB
		*   send response  ( waiting for commands 7816) 
		*  HALT
		    send halt response ( waiting for wupb )
		*/
		
		switch (cardSTATE) {
			//case SIM_NOFIELD:
			case SIM_HALTED:
			case SIM_IDLE: {
				LogTrace(receivedCmd, len, 0, 0, NULL, true);	
				break;
			}
			case SIM_SELECTING: {
				TransmitFor14443b_AsTag( encodedATQB, encodedATQBLen );
				LogTrace(respATQB, sizeof(respATQB), 0, 0, NULL, false);
				cardSTATE = SIM_WORK;
				break;
			}
			case SIM_HALTING: {
				TransmitFor14443b_AsTag( encodedOK, encodedOKLen );
				LogTrace(respOK, sizeof(respOK), 0, 0, NULL, false);
				cardSTATE = SIM_HALTED;
				break;
			}
			case SIM_ACKNOWLEDGE: {
				TransmitFor14443b_AsTag( encodedOK, encodedOKLen );
				LogTrace(respOK, sizeof(respOK), 0, 0, NULL, false);
				cardSTATE = SIM_IDLE;			
				break;
			}
			case SIM_WORK: {
				if ( len == 7 && receivedCmd[0] == ISO14443B_HALT ) {
					cardSTATE = SIM_HALTED;
				} else if ( len == 11 && receivedCmd[0] == ISO14443B_ATTRIB ) {
					cardSTATE = SIM_ACKNOWLEDGE;
				} else {
					// Todo:
					// - SLOT MARKER
					// - ISO7816
					// - emulate with a memory dump
					Dbprintf("new cmd from reader: len=%d, cmdsRecvd=%d", len, cmdsReceived);

					// CRC Check
					if (len >= 3){ // if crc exists
						
						if (!check_crc(CRC_14443_B, receivedCmd, len))
							DbpString("+++CRC fail");
						else
							DbpString("CRC passes");
					}
					cardSTATE = SIM_IDLE; 
				}
				break;
			}
			default: break;
		}
			
		++cmdsReceived;
	}
	if (MF_DBGLEVEL >= 2) 
		Dbprintf("Emulator stopped. Tracing: %d  trace length: %d ", tracing, BigBuf_get_traceLen());
	switch_off(); //simulate
}

//=============================================================================
// An ISO 14443 Type B reader. We take layer two commands, code them
// appropriately, and then send them to the tag. We then listen for the
// tag's response, which we leave in the buffer to be demodulated on the
// PC side.
//=============================================================================

/*
 * Handles reception of a bit from the tag
 *
 * This function is called 2 times per bit (every 4 subcarrier cycles).
 * Subcarrier frequency fs is 848kHz, 1/fs = 1,18us, i.e. function is called every 4,72us
 *
 * LED handling:
 * LED C -> ON once we have received the SOF and are expecting the rest.
 * LED C -> OFF once we have received EOF or are unsynced
 *
 * Returns: true if we received a EOF
 *          false if we are still waiting for some more
 *
 */
static RAMFUNC int Handle14443bTagSamplesDemod(int ci, int cq) {
	int v = 0, myI = ABS(ci), myQ = ABS(cq);

// The soft decision on the bit uses an estimate of just the
// quadrant of the reference angle, not the exact angle.
#define MAKE_SOFT_DECISION() { \
		if(Demod.sumI > 0) { \
			v = ci; \
		} else { \
			v = -ci; \
		} \
		if(Demod.sumQ > 0) { \
			v += cq; \
		} else { \
			v -= cq; \
		} \
	}

// Subcarrier amplitude v = sqrt(ci^2 + cq^2), approximated here by abs(ci) + abs(cq)
// Subcarrier amplitude v = sqrt(ci^2 + cq^2), approximated here by max(abs(ci),abs(cq)) + 1/2*min(abs(ci),abs(cq)))
#define CHECK_FOR_SUBCARRIER_old() { \
		if(ci < 0) { \
			if(cq < 0) { /* ci < 0, cq < 0 */ \
				if (cq < ci) { \
					v = -cq - (ci >> 1); \
				} else { \
					v = -ci - (cq >> 1); \
				} \
			} else {	/* ci < 0, cq >= 0 */ \
				if (cq < -ci) { \
					v = -ci + (cq >> 1); \
				} else { \
					v = cq - (ci >> 1); \
				} \
			} \
		} else { \
			if(cq < 0) { /* ci >= 0, cq < 0 */ \
				if (-cq < ci) { \
					v = ci - (cq >> 1); \
				} else { \
					v = -cq + (ci >> 1); \
				} \
			} else {	/* ci >= 0, cq >= 0 */ \
				if (cq < ci) { \
					v = ci + (cq >> 1); \
				} else { \
					v = cq + (ci >> 1); \
				} \
			} \
		} \
	}

//note: couldn't we just use MAX(ABS(ci),ABS(cq)) + (MIN(ABS(ci),ABS(cq))/2) from common.h - marshmellow
#define CHECK_FOR_SUBCARRIER() { v = MAX(myI, myQ) + (MIN(myI, myQ) >> 1); }

	switch(Demod.state) {
		case DEMOD_UNSYNCD:

			CHECK_FOR_SUBCARRIER();
		
			// subcarrier detected
			if (v > SUBCARRIER_DETECT_THRESHOLD) {
				Demod.state = DEMOD_PHASE_REF_TRAINING;
				Demod.sumI = ci;
				Demod.sumQ = cq;
				Demod.posCount = 1;
			}
			break;

		case DEMOD_PHASE_REF_TRAINING:
			if (Demod.posCount < 8) {

				CHECK_FOR_SUBCARRIER();
				
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
			
			MAKE_SOFT_DECISION();
			
			if (v < 0) {	// logic '0' detected
				Demod.state = DEMOD_GOT_FALLING_EDGE_OF_SOF;
				Demod.posCount = 0;	// start of SOF sequence
			} else {
				// maximum length of TR1 = 200 1/fs
				if(Demod.posCount > 26*2) Demod.state = DEMOD_UNSYNCD;
			}
			++Demod.posCount;
			break;

		case DEMOD_GOT_FALLING_EDGE_OF_SOF:
			++Demod.posCount;
			
			MAKE_SOFT_DECISION();
			
			if (v > 0) {
				// low phase of SOF too short (< 9 etu). Note: spec is >= 10, but FPGA tends to "smear" edges
				if (Demod.posCount < 8*2) { 
					Demod.state = DEMOD_UNSYNCD;
				} else {
					LED_C_ON(); // Got SOF
					//Demod.startTime = GetCountSspClk();
					Demod.state = DEMOD_AWAITING_START_BIT;
					Demod.posCount = 0;
					Demod.len = 0;
				}
			} else {
				// low phase of SOF too long (> 12 etu)
				if (Demod.posCount > 14*2) { 
					Demod.state = DEMOD_UNSYNCD;
					LED_C_OFF();
				}
			}
			break;

		case DEMOD_AWAITING_START_BIT:
			++Demod.posCount;
			
			MAKE_SOFT_DECISION();
			
			if (v > 0) {
				if(Demod.posCount > 2*2) { 		// max 19us between characters = 16 1/fs, max 3 etu after low phase of SOF = 24 1/fs
					Demod.state = DEMOD_UNSYNCD;
					LED_C_OFF();
				}
			} else {							// start bit detected
				Demod.bitCount = 0;
				Demod.posCount = 1;				// this was the first half
				Demod.thisBit = v;
				Demod.shiftReg = 0;
				Demod.state = DEMOD_RECEIVING_DATA;
			}
			break;

		case DEMOD_RECEIVING_DATA:
			
			MAKE_SOFT_DECISION();

			if (Demod.posCount == 0) { 
				// first half of bit
				Demod.thisBit = v;
				Demod.posCount = 1;
			} else {
				// second half of bit
				Demod.thisBit += v;
				Demod.shiftReg >>= 1;

				// OR in a logic '1'
				if (Demod.thisBit > 0)  Demod.shiftReg |= 0x200;

				++Demod.bitCount;
				
				// 1 start 8 data 1 stop = 10
				if (Demod.bitCount == 10) {
					
					uint16_t s = Demod.shiftReg;
					
					// stop bit == '1', start bit == '0'
					if ((s & 0x200) && (s & 0x001) == 0 ) { 
						// left shift to drop the startbit
						Demod.output[Demod.len] =  (s >> 1) & 0xFF;
						++Demod.len;
						Demod.state = DEMOD_AWAITING_START_BIT;
					} else {
						// this one is a bit hard,  either its a correc byte or its unsynced.
						Demod.state = DEMOD_UNSYNCD;
						//Demod.endTime = GetCountSspClk();
						LED_C_OFF();
						
						// This is EOF (start, stop and all data bits == '0'
						if (s == 0) return true;
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


/*
 *  Demodulate the samples we received from the tag, also log to tracebuffer
 *  quiet: set to 'TRUE' to disable debug output
 */
static void GetTagSamplesFor14443bDemod() {
	bool gotFrame = false, finished = false;
	int lastRxCounter = ISO14443B_DMA_BUFFER_SIZE;
	int ci = 0, cq = 0;
	uint32_t time_0 = 0, time_stop = 0;

	BigBuf_free();
	
	// Set up the demodulator for tag -> reader responses.
	DemodInit(BigBuf_malloc(MAX_FRAME_SIZE));
	
	// The DMA buffer, used to stream samples from the FPGA
	int8_t *dmaBuf = (int8_t*) BigBuf_malloc(ISO14443B_DMA_BUFFER_SIZE);
	int8_t *upTo = dmaBuf;
	
	// Setup and start DMA.
	if ( !FpgaSetupSscDma((uint8_t*) dmaBuf, ISO14443B_DMA_BUFFER_SIZE) ){
		if (MF_DBGLEVEL > 1) Dbprintf("FpgaSetupSscDma failed. Exiting"); 
		return;
	}

	// And put the FPGA in the appropriate mode
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ);

	// get current clock
	time_0 = GetCountSspClk();
	
	// rx counter - dma counter? (how much?) & (mod) mask > 2. (since 2bytes at the time is read)
	while ( !finished ) {

		LED_A_INV();
		WDT_HIT();

		// LSB is a fpga signal bit.
		ci = upTo[0] >> 1;
		cq = upTo[1] >> 1;
		upTo += 2;
		lastRxCounter -= 2;

		// restart DMA buffer to receive again.
		if(upTo >= dmaBuf + ISO14443B_DMA_BUFFER_SIZE) {
			upTo = dmaBuf;
			lastRxCounter = ISO14443B_DMA_BUFFER_SIZE;
			AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) upTo;
			AT91C_BASE_PDC_SSC->PDC_RNCR = ISO14443B_DMA_BUFFER_SIZE;
		}

		// https://github.com/Proxmark/proxmark3/issues/103
		gotFrame =  Handle14443bTagSamplesDemod(ci, cq);
		time_stop = GetCountSspClk() - time_0;

		finished = (time_stop > iso14b_timeout || gotFrame);
	}
	
	FpgaDisableSscDma();
	
	if ( upTo ) upTo = NULL;
	
	if (MF_DBGLEVEL >= 3) {
		Dbprintf("Demod.state = %d, Demod.len = %u,  PDC_RCR = %u",	
			Demod.state,
			Demod.len,
			AT91C_BASE_PDC_SSC->PDC_RCR
		);
	}
	
	// print the last batch of IQ values from FPGA
	if (MF_DBGLEVEL == 4)
		Dbhexdump(ISO14443B_DMA_BUFFER_SIZE, (uint8_t *)dmaBuf, false);	
	
	if ( Demod.len > 0 )
		LogTrace(Demod.output, Demod.len, time_0, time_stop, NULL, false);
}

//-----------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitFor14443b_AsReader(void) {

	// we could been in following mode:
	// FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ
	// if its second call or more
	
	// while(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
		// AT91C_BASE_SSC->SSC_THR = 0XFF;
	// }
	
	int c;	
	volatile uint32_t b;
	
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX | FPGA_HF_READER_TX_SHALLOW_MOD);
	SpinDelay(40);
									 
	// What does this loop do? Is it TR1?
	// 0xFF = 8 bits of 1.    1 bit == 1Etu,..  
	// loop 10 * 8 = 80 ETU of delay, with a non modulated signal.  why?
	// 80*9 = 720us.
/*
   	for(c = 0; c < 50;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0xFF;
			++c;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			b = AT91C_BASE_SSC->SSC_RHR; (void)b;
		}
	}
*/
	
	// Send frame loop
	for(c = 0; c < ToSendMax;) {
		if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = ToSend[c++];
		}
		if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			b = AT91C_BASE_SSC->SSC_RHR; (void)b;
		}					
	}
	//WaitForFpgaDelayQueueIsEmpty(delay);
	// We should wait here for the FPGA to send all bits.
	WDT_HIT();
}

//-----------------------------------------------------------------------------
// Code a layer 2 command (string of octets, including CRC) into ToSend[],
// so that it is ready to transmit to the tag using TransmitFor14443b().
//-----------------------------------------------------------------------------
static void CodeIso14443bAsReader(const uint8_t *cmd, int len) {
	/*
	*  Reader data transmission:
	*   - no modulation ONES
	*   - SOF
	*   - Command, data and CRC_B
	*   - EOF
	*   - no modulation ONES
	*
	* 	1 ETU == 1 BIT!
	*   TR0 - 8 ETUS minimum.
	*
	*   QUESTION:  how long is a 1 or 0 in pulses in the xcorr_848 mode?
	*              1 "stuffbit" = 1ETU (9us)
	*/
	int i;
	uint8_t b;
	
	ToSendReset();

	// Send SOF
	// 10-11 ETUs of ZERO 
	for(i = 0; i < 10; ++i) ToSendStuffBit(0);
	
	// 2-3 ETUs of ONE
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	ToSendStuffBit(1);
	
	// Sending cmd, LSB
	// from here we add BITS
	for(i = 0; i < len; ++i) {
	    // Start bit
		ToSendStuffBit(0);
		// Data bits
		b = cmd[i];		
		// if (  b & 1 )    ToSendStuffBit(1); else ToSendStuffBit(0);
		// if ( (b>>1) & 1) ToSendStuffBit(1); else ToSendStuffBit(0);
		// if ( (b>>2) & 1) ToSendStuffBit(1); else ToSendStuffBit(0);
		// if ( (b>>3) & 1) ToSendStuffBit(1); else ToSendStuffBit(0);
		// if ( (b>>4) & 1) ToSendStuffBit(1); else ToSendStuffBit(0);
		// if ( (b>>5) & 1) ToSendStuffBit(1); else ToSendStuffBit(0);
		// if ( (b>>6) & 1) ToSendStuffBit(1); else ToSendStuffBit(0);
		// if ( (b>>7) & 1) ToSendStuffBit(1); else ToSendStuffBit(0);	

		ToSendStuffBit(  b & 1); 
		ToSendStuffBit( (b>>1) & 1); 		
		ToSendStuffBit( (b>>2) & 1); 
		ToSendStuffBit( (b>>3) & 1); 
		ToSendStuffBit( (b>>4) & 1); 
		ToSendStuffBit( (b>>5) & 1); 
		ToSendStuffBit( (b>>6) & 1); 		
		ToSendStuffBit( (b>>7) & 1); 
		
		// Stop bit
		ToSendStuffBit(1);
		// EGT extra guard time
		// For PCD it ranges 0-57us (1etu = 9us)
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
	}
	
	// Send EOF
	// 10-11 ETUs of ZERO
	for(i = 0; i < 10; ++i) ToSendStuffBit(0);

	// Transition time. TR0 - guard time
	// 8ETUS minum?
	// Per specification, Subcarrier must be stopped no later than 2 ETUs after EOF.	
	// I'm guessing this is for the FPGA to be able to send all bits before we switch to listening mode
	for(i = 0; i < 32 ; ++i) ToSendStuffBit(1);
	
	// TR1 - Synchronization time
	// Convert from last character reference to length
	ToSendMax++;
}

/*
*  Convenience function to encode, transmit and trace iso 14443b comms
*/
static void CodeAndTransmit14443bAsReader(const uint8_t *cmd, int len) {

	uint32_t time_start = GetCountSspClk();
	
	CodeIso14443bAsReader(cmd, len);

	TransmitFor14443b_AsReader();

	if(trigger) LED_A_ON();

	LogTrace(cmd, len, time_start, GetCountSspClk()-time_start, NULL, true);
}

/* Sends an APDU to the tag
 * TODO: check CRC and preamble
 */
uint8_t iso14443b_apdu(uint8_t const *message, size_t message_length, uint8_t *response) {

	uint8_t message_frame[message_length + 4];
	// PCB
	message_frame[0] = 0x0A | pcb_blocknum;
	pcb_blocknum ^= 1;
	// CID
	message_frame[1] = 0;
	// INF
	memcpy(message_frame + 2, message, message_length);
	// EDC (CRC)
	AddCrc14B(message_frame, message_length + 2);
	// send
	CodeAndTransmit14443bAsReader(message_frame, message_length + 4); //no
	// get response
	GetTagSamplesFor14443bDemod(); //no
	if(Demod.len < 3)
		return 0;
	
	// VALIDATE CRC
	if (!check_crc(CRC_14443_B, Demod.output, Demod.len))
		return 0;
	
	// copy response contents
	if(response != NULL)
		memcpy(response, Demod.output, Demod.len);

	return Demod.len;
}

/**
* SRx Initialise.
*/
uint8_t iso14443b_select_srx_card(iso14b_card_select_t *card ) {
	// INITIATE command: wake up the tag using the INITIATE
	static const uint8_t init_srx[] = { ISO14443B_INITIATE, 0x00, 0x97, 0x5b };
	// SELECT command (with space for CRC)
	uint8_t select_srx[] = { ISO14443B_SELECT, 0x00, 0x00, 0x00};
	
	CodeAndTransmit14443bAsReader(init_srx, sizeof(init_srx));
	GetTagSamplesFor14443bDemod(); //no

	if (Demod.len == 0) return 2;

	// Randomly generated Chip ID	
	if (card) card->chipid = Demod.output[0];
	
	select_srx[1] = Demod.output[0];
	
	AddCrc14B(select_srx, 2);
	
	CodeAndTransmit14443bAsReader(select_srx, sizeof(select_srx));
	GetTagSamplesFor14443bDemod(); //no
	
	if (Demod.len != 3)	return 2;
	
	// Check the CRC of the answer:
	if (!check_crc(CRC_14443_B, Demod.output, Demod.len)) return 3;
	
	// Check response from the tag: should be the same UID as the command we just sent:
	if (select_srx[1] != Demod.output[0]) return 1;

	// First get the tag's UID:
	select_srx[0] = ISO14443B_GET_UID;

	AddCrc14B(select_srx, 1);
	CodeAndTransmit14443bAsReader(select_srx, 3); // Only first three bytes for this one
	GetTagSamplesFor14443bDemod(); //no

	if (Demod.len != 10) return 2;
	
	// The check the CRC of the answer	
	if (!check_crc(CRC_14443_B, Demod.output, Demod.len)) return 3;

	if (card) {
		card->uidlen = 8;
		memcpy(card->uid, Demod.output, 8);
	}

	return 0;
}
/* Perform the ISO 14443 B Card Selection procedure
 * Currently does NOT do any collision handling.
 * It expects 0-1 cards in the device's range.
 * TODO: Support multiple cards (perform anticollision)
 * TODO: Verify CRC checksums
 */
uint8_t iso14443b_select_card(iso14b_card_select_t *card ) {
	// WUPB command (including CRC)
	// Note: WUPB wakes up all tags, REQB doesn't wake up tags in HALT state
	static const uint8_t wupb[] = { ISO14443B_REQB, 0x00, 0x08, 0x39, 0x73 };
	// ATTRIB command (with space for CRC)
	uint8_t attrib[] = { ISO14443B_ATTRIB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00};
	
	// first, wake up the tag
	CodeAndTransmit14443bAsReader(wupb, sizeof(wupb));
	GetTagSamplesFor14443bDemod(); //select_card
	
	// ATQB too short?
	if (Demod.len < 14) return 2;
	
	// VALIDATE CRC
	if (!check_crc(CRC_14443_B, Demod.output, Demod.len))
		return 3;
	
	if (card) {
		card->uidlen = 4;
		memcpy(card->uid, Demod.output+1, 4);
		memcpy(card->atqb, Demod.output+5, 7);
	}

    // copy the PUPI to ATTRIB  ( PUPI == UID )
    memcpy(attrib + 1, Demod.output + 1, 4);
	
    // copy the protocol info from ATQB (Protocol Info -> Protocol_Type) into ATTRIB (Param 3)
    attrib[7] = Demod.output[10] & 0x0F;
    AddCrc14B(attrib, 9);

    CodeAndTransmit14443bAsReader(attrib, sizeof(attrib));
    GetTagSamplesFor14443bDemod();//select_card

    // Answer to ATTRIB too short?
    if(Demod.len < 3) return 2;

	// VALIDATE CRC
	if (!check_crc(CRC_14443_B, Demod.output, Demod.len) )
		return 3;

	if (card) { 
	
		// CID
		card->cid = Demod.output[0];

		// MAX FRAME
		uint16_t maxFrame = card->atqb[5] >> 4;
		if (maxFrame < 5) 		maxFrame = 8 * maxFrame + 16;
		else if (maxFrame == 5)	maxFrame = 64;
		else if (maxFrame == 6)	maxFrame = 96;
		else if (maxFrame == 7)	maxFrame = 128;
		else if (maxFrame == 8)	maxFrame = 256;
		else maxFrame = 257;
		iso14b_set_maxframesize(maxFrame);
		
		// FWT 
		uint8_t fwt = card->atqb[6] >> 4;
		if ( fwt < 16 ){
			uint32_t fwt_time = (302 << fwt);
			iso14b_set_timeout( fwt_time);
		}
	}
	// reset PCB block number
	pcb_blocknum = 0;
	return 0;
}

// Set up ISO 14443 Type B communication (similar to iso14443a_setup)
// field is setup for "Sending as Reader"
void iso14443b_setup() {
	if (MF_DBGLEVEL > 3) Dbprintf("iso1443b_setup Enter");
	LEDsoff();
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	//BigBuf_free();
	//BigBuf_Clear_ext(false);
	
	// Initialize Demod and Uart structs
	DemodInit(BigBuf_malloc(MAX_FRAME_SIZE));
	UartInit(BigBuf_malloc(MAX_FRAME_SIZE));

	// connect Demodulated Signal to ADC:
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Set up the synchronous serial port
	FpgaSetupSsc();
	
	// Signal field is on with the appropriate LED
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX | FPGA_HF_READER_TX_SHALLOW_MOD);
	SpinDelay(100);

	// Start the timer
	StartCountSspClk();
	
	LED_D_ON();
	if (MF_DBGLEVEL > 3) Dbprintf("iso1443b_setup Exit");
}

//-----------------------------------------------------------------------------
// Read a SRI512 ISO 14443B tag.
//
// SRI512 tags are just simple memory tags, here we're looking at making a dump
// of the contents of the memory. No anticollision algorithm is done, we assume
// we have a single tag in the field.
//
// I tried to be systematic and check every answer of the tag, every CRC, etc...
//-----------------------------------------------------------------------------
void ReadSTMemoryIso14443b(uint8_t numofblocks) {
	// Make sure that we start from off, since the tags are stateful;
	// confusing things will happen if we don't reset them between reads.
	switch_off();

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	FpgaSetupSsc();

	set_tracing(true);
	
	// Now give it time to spin up.
	// Signal field is on with the appropriate LED
	LED_D_ON();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ);
	SpinDelay(100);
	
	uint8_t i = 0x00;

	// First command: wake up the tag using the INITIATE command
	uint8_t cmd1[] = {ISO14443B_INITIATE, 0x00, 0x97, 0x5b};
	CodeAndTransmit14443bAsReader(cmd1, sizeof(cmd1)); //no
	GetTagSamplesFor14443bDemod(); // no

	if (Demod.len == 0) {
		DbpString("[!] No response from tag");
		set_tracing(false);	
		return;
	} else {
		Dbprintf("Randomly generated Chip ID (+ 2 byte CRC): %02x %02x %02x",
				Demod.output[0], Demod.output[1], Demod.output[2]);
	}

	// There is a response, SELECT the uid
	DbpString("[!] SELECT tag:");
	cmd1[0] = ISO14443B_SELECT; // 0x0E is SELECT
	cmd1[1] = Demod.output[0];
	AddCrc14B(cmd1, 2);
	CodeAndTransmit14443bAsReader(cmd1, sizeof(cmd1)); //no
	GetTagSamplesFor14443bDemod(); //no
	if (Demod.len != 3) {
		Dbprintf("[!] expected 3 bytes from tag, got %d", Demod.len);
		set_tracing(false);	
		return;
	}
	// Check the CRC of the answer:
	
	if (!check_crc(CRC_14443_B, Demod.output, Demod.len)) {
		DbpString("[!] CRC Error reading select response.");
		set_tracing(false);	
		return;
	}
	// Check response from the tag: should be the same UID as the command we just sent:
	if (cmd1[1] != Demod.output[0]) {
		Dbprintf("[!] Bad response to SELECT from Tag, aborting: %02x %02x", cmd1[1], Demod.output[0]);
		set_tracing(false);	
		return;
	}

	// Tag is now selected,
	// First get the tag's UID:
	cmd1[0] = ISO14443B_GET_UID;
	AddCrc14B(cmd1, 1);
	CodeAndTransmit14443bAsReader(cmd1, 3); // no --  Only first three bytes for this one
	GetTagSamplesFor14443bDemod(); //no
	if (Demod.len != 10) {
		Dbprintf("[!] expected 10 bytes from tag, got %d", Demod.len);
		set_tracing(false);	
		return;
	}
	// The check the CRC of the answer (use cmd1 as temporary variable):
	
	if (!check_crc(CRC_14443_B, Demod.output, Demod.len)) {
		Dbprintf("[!] CRC Error reading block! Expected: %04x got: %04x", (cmd1[2]<<8)+cmd1[3], (Demod.output[8]<<8)+Demod.output[9]);
	// Do not return;, let's go on... (we should retry, maybe ?)
	}
	Dbprintf("[+] Tag UID (64 bits): %08x %08x",
			(Demod.output[7]<<24) + (Demod.output[6]<<16) + (Demod.output[5]<<8) + Demod.output[4],
			(Demod.output[3]<<24) + (Demod.output[2]<<16) + (Demod.output[1]<<8) + Demod.output[0]);

	// Now loop to read all 16 blocks, address from 0 to last block
	Dbprintf("[+] Tag memory dump, block 0 to %d", numofblocks);
	cmd1[0] = 0x08;
	i = 0x00;
	++numofblocks;
	
	for (;;) {
		if (i == numofblocks) {
			DbpString("System area block (0xFF):");
			i = 0xff;
		}
		cmd1[1] = i;
		AddCrc14B(cmd1, 2);
		CodeAndTransmit14443bAsReader(cmd1, sizeof(cmd1)); //no
		GetTagSamplesFor14443bDemod(); //no
		
		if (Demod.len != 6) { // Check if we got an answer from the tag
			DbpString("[!] expected 6 bytes from tag, got less...");
			return;
		}
		// The check the CRC of the answer (use cmd1 as temporary variable):
		
		if (!check_crc(CRC_14443_B, Demod.output, Demod.len)) {
			Dbprintf("[!] CRC Error reading block! Expected: %04x got: %04x",
					(cmd1[2]<<8)+cmd1[3], (Demod.output[4]<<8)+Demod.output[5]);
		// Do not return;, let's go on... (we should retry, maybe ?)
		}
		// Now print out the memory location:
		Dbprintf("Address=%02x, Contents=%08x, CRC=%04x", i,
				(Demod.output[3]<<24) + (Demod.output[2]<<16) + (Demod.output[1]<<8) + Demod.output[0],
				(Demod.output[4]<<8)+Demod.output[5]);

		if (i == 0xff) break;
		++i;
	}
	
	set_tracing(false);
}

static void iso1444b_setup_sniff(void){
	if (MF_DBGLEVEL > 3) Dbprintf("iso1443b_setup_sniff Enter");
	LEDsoff();
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	BigBuf_free();
	BigBuf_Clear_ext(false); 
	clear_trace();//setup snoop
	set_tracing(true);

	// Initialize Demod and Uart structs
	DemodInit(BigBuf_malloc(MAX_FRAME_SIZE));
	UartInit(BigBuf_malloc(MAX_FRAME_SIZE));

	if (MF_DBGLEVEL > 1) {
		// Print debug information about the buffer sizes
		Dbprintf("[+] Sniff buffers initialized:");
		Dbprintf("[+]   trace: %i bytes", BigBuf_max_traceLen());
		Dbprintf("[+]   reader -> tag: %i bytes", MAX_FRAME_SIZE);
		Dbprintf("[+]   tag -> reader: %i bytes", MAX_FRAME_SIZE);
		Dbprintf("[+]   DMA: %i bytes", ISO14443B_DMA_BUFFER_SIZE);
	}

	// connect Demodulated Signal to ADC:
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Setup for the DMA.
	FpgaSetupSsc();

	// Set FPGA in the appropriate mode
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ | FPGA_HF_READER_RX_XCORR_SNOOP);
	SpinDelay(20);	

	// Start the SSP timer
	StartCountSspClk();

	if (MF_DBGLEVEL > 3) Dbprintf("iso1443b_setup_sniff Exit");
}

//=============================================================================
// Finally, the `sniffer' combines elements from both the reader and
// simulated tag, to show both sides of the conversation.
//=============================================================================

//-----------------------------------------------------------------------------
// Record the sequence of commands sent by the reader to the tag, with
// triggering so that we start recording at the point that the tag is moved
// near the reader.
//-----------------------------------------------------------------------------
/*
 * Memory usage for this function, (within BigBuf)
 * Last Received command (reader->tag) - MAX_FRAME_SIZE
 * Last Received command (tag->reader) - MAX_FRAME_SIZE
 * DMA Buffer - ISO14443B_DMA_BUFFER_SIZE
 * Demodulated samples received - all the rest
 */
void RAMFUNC SniffIso14443b(void) {

	uint32_t time_0 = 0, time_start = 0, time_stop = 0;
	int ci = 0, cq = 0;

	// We won't start recording the frames that we acquire until we trigger;
	// a good trigger condition to get started is probably when we see a
	// response from the tag.
	bool TagIsActive = false;
	bool ReaderIsActive = false;

	iso1444b_setup_sniff();
	
	// The DMA buffer, used to stream samples from the FPGA
	int8_t *dmaBuf = (int8_t*) BigBuf_malloc(ISO14443B_DMA_BUFFER_SIZE);
	int8_t *data = dmaBuf;

	// Setup and start DMA.
	if ( !FpgaSetupSscDma((uint8_t*) dmaBuf, ISO14443B_DMA_BUFFER_SIZE) ){
		if (MF_DBGLEVEL > 1) Dbprintf("[!] FpgaSetupSscDma failed. Exiting"); 
		BigBuf_free();
		return;
	}

	// time ZERO, the point from which it all is calculated.	
	time_0 = GetCountSspClk();
		
    // loop and listen
	while (!BUTTON_PRESS()) {
		WDT_HIT();

		ci = data[0];
		cq = data[1];
		data += 2;		
		
		if (data >= dmaBuf + ISO14443B_DMA_BUFFER_SIZE) {
			data = dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RNCR = ISO14443B_DMA_BUFFER_SIZE;		
		}

		// no need to try decoding reader data if the tag is sending
		if (!TagIsActive) {		
		
			LED_A_INV();
		
			if (Handle14443bReaderUartBit(ci & 0x01)) {
				time_stop = GetCountSspClk() - time_0;
				LogTrace(Uart.output, Uart.byteCnt, time_start, time_stop, NULL, true);
				UartReset();
				DemodReset();
			} else {
				time_start = GetCountSspClk() - time_0;
			}
			
			if (Handle14443bReaderUartBit(cq & 0x01)) {				
				time_stop = GetCountSspClk() - time_0;
				LogTrace(Uart.output, Uart.byteCnt, time_start, time_stop, NULL, true);
				UartReset();
				DemodReset();
			} else {
				time_start = GetCountSspClk() - time_0;
			}
			ReaderIsActive = (Uart.state > STATE_GOT_FALLING_EDGE_OF_SOF);
		}
		
		// no need to try decoding tag data if the reader is sending - and we cannot afford the time
		if (!ReaderIsActive) {

			// is this | 0x01 the error?   & 0xfe  in https://github.com/Proxmark/proxmark3/issues/103
			// LSB is a fpga signal bit.
			if (Handle14443bTagSamplesDemod(ci >> 1, cq >> 1)) {				
				time_stop = GetCountSspClk() - time_0;			
				LogTrace(Demod.output, Demod.len, time_start, time_stop, NULL, false);
				UartReset();				
				DemodReset();				
			} else {
				time_start = GetCountSspClk() - time_0;
			}
			TagIsActive = (Demod.state > DEMOD_GOT_FALLING_EDGE_OF_SOF);
		}
	}
	
	if (MF_DBGLEVEL >= 2) {
		DbpString("[+] Sniff statistics:");
		Dbprintf("[+]  uart State: %x  ByteCount: %i  ByteCountMax: %i", Uart.state,  Uart.byteCnt,  Uart.byteCntMax);
		Dbprintf("[+]  trace length: %i", BigBuf_get_traceLen());
	}
	
	switch_off();
}

void iso14b_set_trigger(bool enable) {
	trigger = enable;
}

/*
 * Send raw command to tag ISO14443B
 * @Input
 * param   flags enum ISO14B_COMMAND.  (mifare.h)
 * len     len of buffer data
 * data    buffer with bytes to send
 *
 * @Output
 * none
 *
 */
void SendRawCommand14443B_Ex(UsbCommand *c) {
	iso14b_command_t param = c->arg[0];
	size_t len = c->arg[1] & 0xffff;
	uint8_t *cmd = c->d.asBytes;
	uint8_t status = 0;
	uint32_t sendlen = sizeof(iso14b_card_select_t);
	uint8_t buf[USB_CMD_DATA_SIZE] = {0x00};

	if (MF_DBGLEVEL > 3) Dbprintf("14b raw: param, %04x", param );
	
	// turn on trigger (LED_A)
	if ((param & ISO14B_REQUEST_TRIGGER) == ISO14B_REQUEST_TRIGGER)
		iso14b_set_trigger(true);
	
	if ((param & ISO14B_CONNECT) == ISO14B_CONNECT) {
		// Make sure that we start from off, since the tags are stateful;
		// confusing things will happen if we don't reset them between reads.
		//switch_off();  // before connect in raw
		iso14443b_setup();
	}
	
	set_tracing(true);

	if ((param & ISO14B_SELECT_STD) == ISO14B_SELECT_STD) {
		iso14b_card_select_t *card = (iso14b_card_select_t*)buf;
		status = iso14443b_select_card(card);	
		cmd_send(CMD_ACK, status, sendlen, 0, buf, sendlen);
		// 0: OK 2: attrib fail, 3:crc fail,
		if ( status > 0 ) return;
	} 
	
	if ((param & ISO14B_SELECT_SR) == ISO14B_SELECT_SR) {
		iso14b_card_select_t *card = (iso14b_card_select_t*)buf;
		status = iso14443b_select_srx_card(card);
		cmd_send(CMD_ACK, status, sendlen, 0, buf, sendlen);
		// 0: OK 2: attrib fail, 3:crc fail,
		if ( status > 0 ) return;
	} 
	
	if ((param & ISO14B_APDU) == ISO14B_APDU) {
		status = iso14443b_apdu(cmd, len, buf);
		cmd_send(CMD_ACK, status, status, 0, buf, status);
	}
	
	if ((param & ISO14B_RAW) == ISO14B_RAW) {
		if((param & ISO14B_APPEND_CRC) == ISO14B_APPEND_CRC) {
			AddCrc14B(cmd, len);
			len += 2;
		}
	
		CodeAndTransmit14443bAsReader(cmd, len); // raw		
		GetTagSamplesFor14443bDemod(); // raw
		
		sendlen = MIN(Demod.len, USB_CMD_DATA_SIZE);
		status =  (Demod.len > 0) ? 0 : 1;
		cmd_send(CMD_ACK, status, sendlen, 0, Demod.output, sendlen);
	}
	
	// turn off trigger (LED_A)
	if ((param & ISO14B_REQUEST_TRIGGER) == ISO14B_REQUEST_TRIGGER)
		iso14b_set_trigger(false);

	// turn off antenna et al
	// we don't send a HALT command.
	if ((param & ISO14B_DISCONNECT) == ISO14B_DISCONNECT) {
		if (MF_DBGLEVEL > 3) Dbprintf("disconnect");
		switch_off(); // disconnect raw
	} else {
		//FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX | FPGA_HF_READER_TX_SHALLOW_MOD);		
	}
	
}