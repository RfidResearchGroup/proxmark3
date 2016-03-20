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

#define RECEIVE_SAMPLES_TIMEOUT 20000
#define ISO14443B_DMA_BUFFER_SIZE 256

// the block number for the ISO14443-4 PCB  (used with APDUs)
static uint8_t pcb_blocknum = 0;

//=============================================================================
// An ISO 14443 Type B tag. We listen for commands from the reader, using
// a UART kind of thing that's implemented in software. When we get a
// frame (i.e., a group of bytes between SOF and EOF), we check the CRC.
// If it's good, then we can do something appropriate with it, and send
// a response.
//=============================================================================


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
	uint16_t    shiftReg;
	int     bitCnt;
	int     byteCnt;
	int     byteCntMax;
	int     posCnt;
	uint8_t   *output;
} Uart;

static void UartReset()
{
	Uart.byteCntMax = MAX_FRAME_SIZE;
	Uart.state = STATE_UNSYNCD;
	Uart.byteCnt = 0;
	Uart.bitCnt = 0;
	Uart.posCnt = 0;
	memset(Uart.output, 0x00, MAX_FRAME_SIZE);
}

static void UartInit(uint8_t *data)
{
	Uart.output = data;
	UartReset();
}


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
/* this had been used to add RSSI (Received Signal Strength Indication) to traces. Currently not implemented.
	int     metric;
	int     metricN;
*/
	uint16_t    shiftReg;
	uint8_t   *output;
	int     len;
	int     sumI;
	int     sumQ;
} Demod;

static void DemodReset()
{
	// Clear out the state of the "UART" that receives from the tag.
	Demod.len = 0;
	Demod.state = DEMOD_UNSYNCD;
	Demod.posCount = 0;
	Demod.sumI = 0;
	Demod.sumQ = 0;
	Demod.bitCount = 0;
	Demod.thisBit = 0;
	Demod.shiftReg = 0;
	//memset(Demod.output, 0x00, MAX_FRAME_SIZE);
}


static void DemodInit(uint8_t *data)
{
	Demod.output = data;
	DemodReset();
}


void AppendCrc14443b(uint8_t* data, int len)
{
	ComputeCrc14443(CRC_14443_B,data,len,data+len,data+len+1);
}

//-----------------------------------------------------------------------------
// Code up a string of octets at layer 2 (including CRC, we don't generate
// that here) so that they can be transmitted to the reader. Doesn't transmit
// them yet, just leaves them ready to send in ToSend[].
//-----------------------------------------------------------------------------
static void CodeIso14443bAsTag(const uint8_t *cmd, int len)
{
	int i;

	ToSendReset();

	// Transmit a burst of ones, as the initial thing that lets the
	// reader get phase sync. This (TR1) must be > 80/fs, per spec,
	// but tag that I've tried (a Paypass) exceeds that by a fair bit,
	// so I will too.
	for(i = 0; i < 20; i++) {
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
	}

	// Send SOF.
	for(i = 0; i < 10; i++) {
		ToSendStuffBit(0);
		ToSendStuffBit(0);
		ToSendStuffBit(0);
		ToSendStuffBit(0);
	}
	for(i = 0; i < 2; i++) {
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
	}

	for(i = 0; i < len; i++) {
		int j;
		uint8_t b = cmd[i];

		// Start bit
		ToSendStuffBit(0);
		ToSendStuffBit(0);
		ToSendStuffBit(0);
		ToSendStuffBit(0);

		// Data bits
		for(j = 0; j < 8; j++) {
			if(b & 1) {
				ToSendStuffBit(1);
				ToSendStuffBit(1);
				ToSendStuffBit(1);
				ToSendStuffBit(1);
			} else {
				ToSendStuffBit(0);
				ToSendStuffBit(0);
				ToSendStuffBit(0);
				ToSendStuffBit(0);
			}
			b >>= 1;
		}

		// Stop bit
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
	}

	// Send EOF.
	for(i = 0; i < 10; i++) {
		ToSendStuffBit(0);
		ToSendStuffBit(0);
		ToSendStuffBit(0);
		ToSendStuffBit(0);
	}
	for(i = 0; i < 2; i++) {
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
	}

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
static RAMFUNC int Handle14443bUartBit(uint8_t bit)
{
	switch(Uart.state) {
		case STATE_UNSYNCD:
			if(!bit) {
				// we went low, so this could be the beginning
				// of an SOF
				Uart.state = STATE_GOT_FALLING_EDGE_OF_SOF;
				Uart.posCnt = 0;
				Uart.bitCnt = 0;
			}
			break;

		case STATE_GOT_FALLING_EDGE_OF_SOF:
			Uart.posCnt++;
			if(Uart.posCnt == 2) {	// sample every 4 1/fs in the middle of a bit
				if(bit) {
					if(Uart.bitCnt > 9) {
						// we've seen enough consecutive
						// zeros that it's a valid SOF
						Uart.posCnt = 0;
						Uart.byteCnt = 0;
						Uart.state = STATE_AWAITING_START_BIT;
						LED_A_ON(); // Indicate we got a valid SOF
					} else {
						// didn't stay down long enough
						// before going high, error
						Uart.state = STATE_UNSYNCD;
					}
				} else {
					// do nothing, keep waiting
				}
				Uart.bitCnt++;
			}
			if(Uart.posCnt >= 4) Uart.posCnt = 0;
			if(Uart.bitCnt > 12) {
				// Give up if we see too many zeros without
				// a one, too.
				LED_A_OFF();
				Uart.state = STATE_UNSYNCD;
			}
			break;

		case STATE_AWAITING_START_BIT:
			Uart.posCnt++;
			if(bit) {
				if(Uart.posCnt > 50/2) {	// max 57us between characters = 49 1/fs, max 3 etus after low phase of SOF = 24 1/fs
					// stayed high for too long between
					// characters, error
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
			if(Uart.posCnt == 2) {
				// time to sample a bit
				Uart.shiftReg >>= 1;
				if(bit) {
					Uart.shiftReg |= 0x200;
				}
				Uart.bitCnt++;
			}
			if(Uart.posCnt >= 4) {
				Uart.posCnt = 0;
			}
			if(Uart.bitCnt == 10) {
				if((Uart.shiftReg & 0x200) && !(Uart.shiftReg & 0x001))
				{
					// this is a data byte, with correct
					// start and stop bits
					Uart.output[Uart.byteCnt] = (Uart.shiftReg >> 1) & 0xff;
					Uart.byteCnt++;

					if(Uart.byteCnt >= Uart.byteCntMax) {
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
					if (Uart.byteCnt != 0) {
					return TRUE;
					}
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

	return FALSE;
}

//-----------------------------------------------------------------------------
// Receive a command (from the reader to us, where we are the simulated tag),
// and store it in the given buffer, up to the given maximum length. Keeps
// spinning, waiting for a well-framed command, until either we get one
// (returns TRUE) or someone presses the pushbutton on the board (FALSE).
//
// Assume that we're called with the SSC (to the FPGA) and ADC path set
// correctly.
//-----------------------------------------------------------------------------
static int GetIso14443bCommandFromReader(uint8_t *received, uint16_t *len)
{
	// Set FPGA mode to "simulated ISO 14443B tag", no modulation (listen
	// only, since we are receiving, not transmitting).
	// Signal field is off with the appropriate LED
	LED_D_OFF();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_NO_MODULATION);

	// Now run a `software UART' on the stream of incoming samples.
	UartInit(received);

	for(;;) {
		WDT_HIT();

		if(BUTTON_PRESS()) return FALSE;

		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			for(uint8_t mask = 0x80; mask != 0x00; mask >>= 1) {
				if(Handle14443bUartBit(b & mask)) {
					*len = Uart.byteCnt;
					return TRUE;
				}
			}
		}
	}
	
	return FALSE;
}

//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
void SimulateIso14443bTag(void)
{
	// the only commands we understand is WUPB, AFI=0, Select All, N=1:
	static const uint8_t cmd1[] = { ISO14443B_REQB, 0x00, 0x08, 0x39, 0x73 }; // WUPB
	// ... and REQB, AFI=0, Normal Request, N=1:
	static const uint8_t cmd2[] = { ISO14443B_REQB, 0x00, 0x00, 0x71, 0xFF }; // REQB
	// ... and HLTB
	static const uint8_t cmd3[] = { ISO14443B_HALT, 0xff, 0xff, 0xff, 0xff }; // HLTB
	// ... and ATTRIB
	static const uint8_t cmd4[] = { ISO14443B_ATTRIB, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // ATTRIB

	// ... and we always respond with ATQB, PUPI = 820de174, Application Data = 0x20381922,
	// supports only 106kBit/s in both directions, max frame size = 32Bytes,
	// supports ISO14443-4, FWI=8 (77ms), NAD supported, CID not supported:
	static const uint8_t response1[] = {
		0x50, 0x82, 0x0d, 0xe1, 0x74, 0x20, 0x38, 0x19, 0x22,
		0x00, 0x21, 0x85, 0x5e, 0xd7
	};
	// response to HLTB and ATTRIB
	static const uint8_t response2[] = {0x00, 0x78, 0xF0};
				
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

	clear_trace();
	set_tracing(TRUE);

	const uint8_t *resp;
	uint8_t *respCode;
	uint16_t respLen, respCodeLen;

	// allocate command receive buffer
	BigBuf_free(); BigBuf_Clear_ext(false);
	
	uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);

	uint16_t len;
	uint16_t cmdsRecvd = 0;

	// prepare the (only one) tag answer:
	CodeIso14443bAsTag(response1, sizeof(response1));
	uint8_t *resp1Code = BigBuf_malloc(ToSendMax);
	memcpy(resp1Code, ToSend, ToSendMax); 
	uint16_t resp1CodeLen = ToSendMax;

	// prepare the (other) tag answer:
	CodeIso14443bAsTag(response2, sizeof(response2));
	uint8_t *resp2Code = BigBuf_malloc(ToSendMax);
	memcpy(resp2Code, ToSend, ToSendMax); 
	uint16_t resp2CodeLen = ToSendMax;

	// We need to listen to the high-frequency, peak-detected path.
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

	cmdsRecvd = 0;

	for(;;) {

		if (!GetIso14443bCommandFromReader(receivedCmd, &len)) {
			Dbprintf("button pressed, received %d commands", cmdsRecvd);
			break;
		}

		if (tracing)
			LogTrace(receivedCmd, len, 0, 0, NULL, TRUE);	
			

		// Good, look at the command now.
		if ( (len == sizeof(cmd1) && memcmp(receivedCmd, cmd1, len) == 0)
			|| (len == sizeof(cmd2) && memcmp(receivedCmd, cmd2, len) == 0) ) {
			resp = response1; 
			respLen = sizeof(response1);
			respCode = resp1Code; 
			respCodeLen = resp1CodeLen;
		} else if ( (len == sizeof(cmd3) && receivedCmd[0] == cmd3[0])
			|| (len == sizeof(cmd4) && receivedCmd[0] == cmd4[0]) ) {
			resp = response2; 
			respLen = sizeof(response2);
			respCode = resp2Code; 
			respCodeLen = resp2CodeLen;
		} else {
			Dbprintf("new cmd from reader: len=%d, cmdsRecvd=%d", len, cmdsRecvd);

			// And print whether the CRC fails, just for good measure
			uint8_t b1, b2;
			if (len >= 3){ // if crc exists
				ComputeCrc14443(CRC_14443_B, receivedCmd, len-2, &b1, &b2);
				if(b1 != receivedCmd[len-2] || b2 != receivedCmd[len-1]) {
					// Not so good, try again.
					DbpString("+++CRC fail");
			
				} else {
					DbpString("CRC passes");
				}
			}
			//get rid of compiler warning
			respCodeLen = 0;
			resp = response1;
			respLen	= 0;
			respCode = resp1Code;
			//don't crash at new command just wait and see if reader will send other new cmds.
			//break;
		}

		++cmdsRecvd;

		if(cmdsRecvd > 0xFF) {
			DbpString("many commands later...");
			break;
		}

		if(respCodeLen <= 0) continue;

		// Modulate BPSK
		// Signal field is off with the appropriate LED
		LED_D_OFF();
		FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_BPSK);
		AT91C_BASE_SSC->SSC_THR = 0xff;
		FpgaSetupSsc();

		// Transmit the response.
		uint16_t i = 0;
		volatile uint8_t b;
		for(;;) {
			if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
				uint8_t b = respCode[i];

				AT91C_BASE_SSC->SSC_THR = b;

				++i;
				if(i > respCodeLen)
					break;

			}
			if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
				b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
				(void)b;
			}
		}
		
		if (tracing)
			LogTrace(resp, respLen, 0, 0, NULL, FALSE);
	}
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
#ifndef SUBCARRIER_DETECT_THRESHOLD
# define SUBCARRIER_DETECT_THRESHOLD	6
#endif

static RAMFUNC int Handle14443bSamplesDemod(int ci, int cq)
{
	int v = 0;
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
/* #define CHECK_FOR_SUBCARRIER() { \
		v = ci; \
		if(v < 0) v = -v; \
		if(cq > 0) { \
			v += cq; \
		} else { \
			v -= cq; \
		} \
	}
 */
// Subcarrier amplitude v = sqrt(ci^2 + cq^2), approximated here by max(abs(ci),abs(cq)) + 1/2*min(abs(ci),abs(cq)))
#define CHECK_FOR_SUBCARRIER() { \
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
#define CHECK_FOR_SUBCARRIER_duo() { \
		v = MAX(ABS(ci),ABS(cq)) + (MIN(ABS(ci),ABS(cq))/2); \
 	}

	switch(Demod.state) {
		case DEMOD_UNSYNCD:

			CHECK_FOR_SUBCARRIER();

			// subcarrier detected
			if(v > SUBCARRIER_DETECT_THRESHOLD) {
				Demod.state = DEMOD_PHASE_REF_TRAINING;
				Demod.sumI = ci;
				Demod.sumQ = cq;
				Demod.posCount = 1;
			}
			break;

		case DEMOD_PHASE_REF_TRAINING:
			if(Demod.posCount < 8) {

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
			
			//Dbprintf("ICE: %d %d %d %d %d", v, Demod.sumI, Demod.sumQ, ci, cq );
			if(v < 0) {	// logic '0' detected
				Demod.state = DEMOD_GOT_FALLING_EDGE_OF_SOF;
				Demod.posCount = 0;	// start of SOF sequence
			} else {
				// maximum length of TR1 = 200 1/fs
				if(Demod.posCount > 25*2) Demod.state = DEMOD_UNSYNCD;
			}
			++Demod.posCount;
			break;

		case DEMOD_GOT_FALLING_EDGE_OF_SOF:
			++Demod.posCount;
			
			MAKE_SOFT_DECISION();
			
			if(v > 0) {
				// low phase of SOF too short (< 9 etu). Note: spec is >= 10, but FPGA tends to "smear" edges
				if(Demod.posCount < 9*2) { 
					Demod.state = DEMOD_UNSYNCD;
				} else {
					LED_C_ON(); // Got SOF
					Demod.state = DEMOD_AWAITING_START_BIT;
					Demod.posCount = 0;
					Demod.len = 0;
				}
			} else {
				// low phase of SOF too long (> 12 etu)
				if (Demod.posCount > 12*2) { 
					Demod.state = DEMOD_UNSYNCD;
					LED_C_OFF();
				}
			}
			break;

		case DEMOD_AWAITING_START_BIT:
			++Demod.posCount;
			
			MAKE_SOFT_DECISION();
			
			if (v > 0) {
				if(Demod.posCount > 3*2) { 		// max 19us between characters = 16 1/fs, max 3 etu after low phase of SOF = 24 1/fs
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

				// logic '1'
				if(Demod.thisBit > 0)  Demod.shiftReg |= 0x200;

				++Demod.bitCount;
				
				if(Demod.bitCount == 10) {
					
					uint16_t s = Demod.shiftReg;
					
					// stop bit == '1', start bit == '0'
					if((s & 0x200) && !(s & 0x001)) { 
						uint8_t b = (s >> 1);
						Demod.output[Demod.len] = b;
						++Demod.len;
						Demod.state = DEMOD_AWAITING_START_BIT;
					} else {
						Demod.state = DEMOD_UNSYNCD;
						LED_C_OFF();
						
						// This is EOF (start, stop and all data bits == '0'
						if(s == 0) return TRUE;
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


/*
 *  Demodulate the samples we received from the tag, also log to tracebuffer
 *  quiet: set to 'TRUE' to disable debug output
 */
static void GetSamplesFor14443bDemod(int n, bool quiet)
{
	int max = 0;
	bool gotFrame = FALSE;
	int lastRxCounter, ci, cq, samples = 0;

	// Allocate memory from BigBuf for some buffers
	// free all previous allocations first
	///BigBuf_free();

	// The response (tag -> reader) that we're receiving.
	// Set up the demodulator for tag -> reader responses.
	// this init, can take some time to execute,  memset
	DemodInit(BigBuf_malloc(MAX_FRAME_SIZE));
	
	// The DMA buffer, used to stream samples from the FPGA
	int8_t *dmaBuf = (int8_t*) BigBuf_malloc(ISO14443B_DMA_BUFFER_SIZE);

	// And put the FPGA in the appropriate mode
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ);
	
	// Setup and start DMA.
	FpgaSetupSscDma((uint8_t*) dmaBuf, ISO14443B_DMA_BUFFER_SIZE);
	
	int8_t *upTo = dmaBuf;
	lastRxCounter = ISO14443B_DMA_BUFFER_SIZE;

	// Signal field is ON with the appropriate LED:
	LED_D_ON();
	for(;;) {
		int behindBy = lastRxCounter - AT91C_BASE_PDC_SSC->PDC_RCR;
		if(behindBy > max) max = behindBy;

		while(((lastRxCounter-AT91C_BASE_PDC_SSC->PDC_RCR) & (ISO14443B_DMA_BUFFER_SIZE-1)) > 2) {
			ci = upTo[0];
			cq = upTo[1];
			upTo += 2;
			if(upTo >= dmaBuf + ISO14443B_DMA_BUFFER_SIZE) {
				upTo = dmaBuf;
				AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) upTo;
				AT91C_BASE_PDC_SSC->PDC_RNCR = ISO14443B_DMA_BUFFER_SIZE;
			}
			lastRxCounter -= 2;

			if(lastRxCounter <= 0)
				lastRxCounter += ISO14443B_DMA_BUFFER_SIZE;

			samples += 2;

			// is this | 0x01 the error?   & 0xfe  in https://github.com/Proxmark/proxmark3/issues/103
			// can we double this?
			gotFrame = Handle14443bSamplesDemod(ci<<2 , cq<<2);
			if ( gotFrame )
				break;
		}

		if(samples > n || gotFrame)
			break;
	}

	//disable
	AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;

	if (!quiet) {
		Dbprintf("max behindby = %d, samples = %d, gotFrame = %s, Demod.state = %d, Demod.len = %d, Demod.sumI = %d, Demod.sumQ = %d",
			max,
			samples, 
			(gotFrame) ? "true" : "false", 
			Demod.state,
			Demod.len, 
			Demod.sumI, 
			Demod.sumQ
		);
	}

	 if (tracing > 0)
		LogTrace(Demod.output, Demod.len, samples, samples, NULL, FALSE);
}


//-----------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitFor14443b(void)
{
	int c;
	volatile uint32_t r;
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
			++c;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			r = AT91C_BASE_SSC->SSC_RHR;
			(void)r;
		}
		WDT_HIT();
	}

	c = 0;
	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = ToSend[c];
			++c;
			if(c >= ToSendMax)
				break;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			r = AT91C_BASE_SSC->SSC_RHR;
			(void)r;
		}
		WDT_HIT();
	}
	LED_B_OFF(); // Finished sending
}


//-----------------------------------------------------------------------------
// Code a layer 2 command (string of octets, including CRC) into ToSend[],
// so that it is ready to transmit to the tag using TransmitFor14443b().
//-----------------------------------------------------------------------------
static void CodeIso14443bAsReader(const uint8_t *cmd, int len)
{
	int i, j;
	uint8_t b;

	ToSendReset();

	// Establish initial reference level
	for(i = 0; i < 40; ++i)
		ToSendStuffBit(1);

	// Send SOF
	for(i = 0; i < 10; ++i)
		ToSendStuffBit(0);

	for(i = 0; i < len; ++i) {
		// Stop bits/EGT
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		// Start bit
		ToSendStuffBit(0);
		// Data bits
		b = cmd[i];
		for(j = 0; j < 8; ++j) {
			if(b & 1)
				ToSendStuffBit(1);
			else
				ToSendStuffBit(0);
			
			b >>= 1;
		}
	}
	// Send EOF
	ToSendStuffBit(1);
	for(i = 0; i < 10; ++i)
		ToSendStuffBit(0);
	
	for(i = 0; i < 8; ++i)
		ToSendStuffBit(1);


	// And then a little more, to make sure that the last character makes
	// it out before we switch to rx mode.
	for(i = 0; i < 24; ++i)
		ToSendStuffBit(1);

	// Convert from last character reference to length
	++ToSendMax;
}


/**
  Convenience function to encode, transmit and trace iso 14443b comms
  **/
static void CodeAndTransmit14443bAsReader(const uint8_t *cmd, int len)
{
	CodeIso14443bAsReader(cmd, len);
	TransmitFor14443b();

	if(trigger) LED_A_ON();
	
	if (tracing) LogTrace(cmd, len, 0, 0, NULL, TRUE);
}

/* Sends an APDU to the tag
 * TODO: check CRC and preamble
 */
uint8_t iso14443b_apdu(uint8_t const *message, size_t message_length, uint8_t *response)
{
	uint8_t crc[2] = {0x00, 0x00};
	uint8_t message_frame[message_length + 4];
	// PCB
	message_frame[0] = 0x0A | pcb_blocknum;
	pcb_blocknum ^= 1;
	// CID
	message_frame[1] = 0;
	// INF
	memcpy(message_frame + 2, message, message_length);
	// EDC (CRC)
	ComputeCrc14443(CRC_14443_B, message_frame, message_length + 2, &message_frame[message_length + 2], &message_frame[message_length + 3]);
	// send
	CodeAndTransmit14443bAsReader(message_frame, message_length + 4);
	// get response
	GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);
	if(Demod.len < 3)
		return 0;
	
	// VALIDATE CRC
    ComputeCrc14443(CRC_14443_B, Demod.output, Demod.len-2, &crc[0], &crc[1]);
	if ( crc[0] != Demod.output[Demod.len-2] || crc[1] != Demod.output[Demod.len-1] )
		return 0;
	
	// copy response contents
	if(response != NULL)
		memcpy(response, Demod.output, Demod.len);

	return Demod.len;
}

/**
* SRx Initialise.
*/
uint8_t iso14443b_select_srx_card(iso14b_card_select_t *card )
{
	// INITIATE command: wake up the tag using the INITIATE
	static const uint8_t init_srx[] = { ISO14443B_INITIATE, 0x00, 0x97, 0x5b };
	// SELECT command (with space for CRC)
	uint8_t select_srx[] = { ISO14443B_SELECT, 0x00, 0x00, 0x00};
	// temp to calc crc.
	uint8_t crc[2] = {0x00, 0x00};
	
	CodeAndTransmit14443bAsReader(init_srx, sizeof(init_srx));
	GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);

	if (Demod.len == 0) return 2;

	// Randomly generated Chip ID	
	if (card) card->chipid = Demod.output[0];
	
	select_srx[1] = Demod.output[0];
	
	ComputeCrc14443(CRC_14443_B, select_srx, 2, &select_srx[2], &select_srx[3]);
	CodeAndTransmit14443bAsReader(select_srx, sizeof(select_srx));
	GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);
	
	if (Demod.len != 3)	return 2;
	
	// Check the CRC of the answer:
	ComputeCrc14443(CRC_14443_B, Demod.output, Demod.len-2 , &crc[0], &crc[1]);
	if(crc[0] != Demod.output[1] || crc[1] != Demod.output[2]) return 3;
	
	// Check response from the tag: should be the same UID as the command we just sent:
	if (select_srx[1] != Demod.output[0]) return 1;

	// First get the tag's UID:
	select_srx[0] = ISO14443B_GET_UID;

	ComputeCrc14443(CRC_14443_B, select_srx, 1 , &select_srx[1], &select_srx[2]);
	CodeAndTransmit14443bAsReader(select_srx, 3); // Only first three bytes for this one
	GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);

	if (Demod.len != 10) return 2;
	
	// The check the CRC of the answer
	ComputeCrc14443(CRC_14443_B, Demod.output, Demod.len-2, &crc[0], &crc[1]);
	if(crc[0] != Demod.output[8] || crc[1] != Demod.output[9]) return 3;

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
uint8_t iso14443b_select_card(iso14b_card_select_t *card )
{
	// WUPB command (including CRC)
	// Note: WUPB wakes up all tags, REQB doesn't wake up tags in HALT state
	static const uint8_t wupb[] = { ISO14443B_REQB, 0x00, 0x08, 0x39, 0x73 };
	// ATTRIB command (with space for CRC)
	uint8_t attrib[] = { ISO14443B_ATTRIB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00};

	// temp to calc crc.
	uint8_t crc[2] = {0x00, 0x00};
	
	// first, wake up the tag
	CodeAndTransmit14443bAsReader(wupb, sizeof(wupb));
	GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);
	
	// ATQB too short?
	if (Demod.len < 14) return 2;
	
	// VALIDATE CRC
    ComputeCrc14443(CRC_14443_B, Demod.output, Demod.len-2, &crc[0], &crc[1]);
	if ( crc[0] != Demod.output[12] || crc[1] != Demod.output[13] )
		return 3;
	
	if (card) {
		card->uidlen = 4;
		memcpy(card->uid, Demod.output+1, 4);
		memcpy(card->atqb, Demod.output+5, 7);
	}

    // copy the PUPI to ATTRIB
    memcpy(attrib + 1, Demod.output + 1, 4);
	
    // copy the protocol info from ATQB (Protocol Info -> Protocol_Type) into ATTRIB (Param 3)
    attrib[7] = Demod.output[10] & 0x0F;
    ComputeCrc14443(CRC_14443_B, attrib, 9, attrib + 9, attrib + 10);

    CodeAndTransmit14443bAsReader(attrib, sizeof(attrib));
    GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);

    // Answer to ATTRIB too short?
    if(Demod.len < 3) return 2;

	// VALIDATE CRC
    ComputeCrc14443(CRC_14443_B, Demod.output, Demod.len-2, &crc[0], &crc[1]);
	if ( crc[0] != Demod.output[1] || crc[1] != Demod.output[2] ) 
		return 3;
	
	// CID
	if (card) card->cid = Demod.output[0];
	
	// reset PCB block number
	pcb_blocknum = 0;
	return 0;
}

// Set up ISO 14443 Type B communication (similar to iso14443a_setup)
void iso14443b_setup() {

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

	BigBuf_free(); BigBuf_Clear_ext(false);
	DemodReset();
	UartReset();
	
	// Set up the synchronous serial port
	FpgaSetupSsc();

	// connect Demodulated Signal to ADC:
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Signal field is on with the appropriate LED
    LED_D_ON();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_TX | FPGA_HF_READER_TX_SHALLOW_MOD);
	SpinDelay(400);

	// Start the timer
	StartCountSspClk();
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
void ReadSTMemoryIso14443b(uint8_t numofblocks)
{
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	clear_trace();
	set_tracing(TRUE);

	uint8_t i = 0x00;

	// Make sure that we start from off, since the tags are stateful;
	// confusing things will happen if we don't reset them between reads.
	LED_D_OFF();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelay(200);

	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

	// Now give it time to spin up.
	// Signal field is on with the appropriate LED
	LED_D_ON();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ);
	SpinDelay(300);

	// First command: wake up the tag using the INITIATE command
	uint8_t cmd1[] = {ISO14443B_INITIATE, 0x00, 0x97, 0x5b};
	CodeAndTransmit14443bAsReader(cmd1, sizeof(cmd1));
	GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);

	if (Demod.len == 0) {
		DbpString("No response from tag");
		set_tracing(FALSE);	
		return;
	} else {
		Dbprintf("Randomly generated Chip ID (+ 2 byte CRC): %02x %02x %02x",
				Demod.output[0], Demod.output[1], Demod.output[2]);
	}

	// There is a response, SELECT the uid
	DbpString("Now SELECT tag:");
	cmd1[0] = ISO14443B_SELECT; // 0x0E is SELECT
	cmd1[1] = Demod.output[0];
	ComputeCrc14443(CRC_14443_B, cmd1, 2, &cmd1[2], &cmd1[3]);
	CodeAndTransmit14443bAsReader(cmd1, sizeof(cmd1));
	GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);
	if (Demod.len != 3) {
		Dbprintf("Expected 3 bytes from tag, got %d", Demod.len);
		set_tracing(FALSE);	
		return;
	}
	// Check the CRC of the answer:
	ComputeCrc14443(CRC_14443_B, Demod.output, 1 , &cmd1[2], &cmd1[3]);
	if(cmd1[2] != Demod.output[1] || cmd1[3] != Demod.output[2]) {
		DbpString("CRC Error reading select response.");
		set_tracing(FALSE);	
		return;
	}
	// Check response from the tag: should be the same UID as the command we just sent:
	if (cmd1[1] != Demod.output[0]) {
		Dbprintf("Bad response to SELECT from Tag, aborting: %02x %02x", cmd1[1], Demod.output[0]);
		set_tracing(FALSE);	
		return;
	}

	// Tag is now selected,
	// First get the tag's UID:
	cmd1[0] = ISO14443B_GET_UID;
	ComputeCrc14443(CRC_14443_B, cmd1, 1 , &cmd1[1], &cmd1[2]);
	CodeAndTransmit14443bAsReader(cmd1, 3); // Only first three bytes for this one
	GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);
	if (Demod.len != 10) {
		Dbprintf("Expected 10 bytes from tag, got %d", Demod.len);
		set_tracing(FALSE);	
		return;
	}
	// The check the CRC of the answer (use cmd1 as temporary variable):
	ComputeCrc14443(CRC_14443_B, Demod.output, 8, &cmd1[2], &cmd1[3]);
	if(cmd1[2] != Demod.output[8] || cmd1[3] != Demod.output[9]) {
		Dbprintf("CRC Error reading block! Expected: %04x got: %04x",
				(cmd1[2]<<8)+cmd1[3], (Demod.output[8]<<8)+Demod.output[9]);
	// Do not return;, let's go on... (we should retry, maybe ?)
	}
	Dbprintf("Tag UID (64 bits): %08x %08x",
			(Demod.output[7]<<24) + (Demod.output[6]<<16) + (Demod.output[5]<<8) + Demod.output[4],
			(Demod.output[3]<<24) + (Demod.output[2]<<16) + (Demod.output[1]<<8) + Demod.output[0]);

	// Now loop to read all 16 blocks, address from 0 to last block
	Dbprintf("Tag memory dump, block 0 to %d", numofblocks);
	cmd1[0] = 0x08;
	i = 0x00;
	++numofblocks;
	
	for (;;) {
		if (i == numofblocks) {
			DbpString("System area block (0xff):");
			i = 0xff;
		}
		cmd1[1] = i;
		ComputeCrc14443(CRC_14443_B, cmd1, 2, &cmd1[2], &cmd1[3]);
		CodeAndTransmit14443bAsReader(cmd1, sizeof(cmd1));
		GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);
		
		if (Demod.len != 6) { // Check if we got an answer from the tag
			DbpString("Expected 6 bytes from tag, got less...");
			return;
		}
		// The check the CRC of the answer (use cmd1 as temporary variable):
		ComputeCrc14443(CRC_14443_B, Demod.output, 4, &cmd1[2], &cmd1[3]);
			if(cmd1[2] != Demod.output[4] || cmd1[3] != Demod.output[5]) {
			Dbprintf("CRC Error reading block! Expected: %04x got: %04x",
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
	
	set_tracing(FALSE);
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
void RAMFUNC SnoopIso14443b(void)
{
	// We won't start recording the frames that we acquire until we trigger;
	// a good trigger condition to get started is probably when we see a
	// response from the tag.
	int triggered = TRUE;			// TODO: set and evaluate trigger condition

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	BigBuf_free(); BigBuf_Clear_ext(false);

	clear_trace();
	set_tracing(TRUE);

	// The DMA buffer, used to stream samples from the FPGA
	int8_t *dmaBuf = (int8_t*) BigBuf_malloc(ISO14443B_DMA_BUFFER_SIZE);
	int lastRxCounter;
	int8_t *upTo;
	int ci, cq;
	int maxBehindBy = 0;

	// Count of samples received so far, so that we can include timing
	// information in the trace buffer.
	int samples = 0;

	DemodInit(BigBuf_malloc(MAX_FRAME_SIZE));
	UartInit(BigBuf_malloc(MAX_FRAME_SIZE));

	// Print some debug information about the buffer sizes
	Dbprintf("Snooping buffers initialized:");
	Dbprintf("  Trace: %i bytes", BigBuf_max_traceLen());
	Dbprintf("  Reader -> tag: %i bytes", MAX_FRAME_SIZE);
	Dbprintf("  tag -> Reader: %i bytes", MAX_FRAME_SIZE);
	Dbprintf("  DMA: %i bytes", ISO14443B_DMA_BUFFER_SIZE);

	// Signal field is off, no reader signal, no tag signal
	LEDsoff();

	// And put the FPGA in the appropriate mode
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ | FPGA_HF_READER_RX_XCORR_SNOOP);
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Setup for the DMA.
	FpgaSetupSsc();
	upTo = dmaBuf;
	lastRxCounter = ISO14443B_DMA_BUFFER_SIZE;
	FpgaSetupSscDma((uint8_t*) dmaBuf, ISO14443B_DMA_BUFFER_SIZE);

	bool TagIsActive = FALSE;
	bool ReaderIsActive = FALSE;
		
	// And now we loop, receiving samples.
	for(;;) {
		int behindBy = (lastRxCounter - AT91C_BASE_PDC_SSC->PDC_RCR) &
								(ISO14443B_DMA_BUFFER_SIZE-1);

		if(behindBy > maxBehindBy) maxBehindBy = behindBy;
		if(behindBy < 2) continue;

		ci = upTo[0];
		cq = upTo[1];
		upTo += 2;
		lastRxCounter -= 2;
		if(upTo >= dmaBuf + ISO14443B_DMA_BUFFER_SIZE) {
			upTo = dmaBuf;
			lastRxCounter += ISO14443B_DMA_BUFFER_SIZE;
			AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RNCR = ISO14443B_DMA_BUFFER_SIZE;
			WDT_HIT();
			if(behindBy > (9*ISO14443B_DMA_BUFFER_SIZE/10)) { // TODO: understand whether we can increase/decrease as we want or not?
				Dbprintf("blew circular buffer! behindBy=%d", behindBy);
				break;
			}
			
			if(!tracing) {
				DbpString("Trace full");
				break;
			}
			
			if(BUTTON_PRESS()) {
				DbpString("cancelled");
				break;
			}
		}

		samples += 2;

		if (!TagIsActive) {							// no need to try decoding reader data if the tag is sending
			if (Handle14443bUartBit(ci & 0x01)) {

				if(triggered && tracing)
					LogTrace(Uart.output, Uart.byteCnt, samples, samples, NULL, TRUE);

				/* And ready to receive another command. */
				UartReset();
				/* And also reset the demod code, which might have been */
				/* false-triggered by the commands from the reader. */
				DemodReset();
			}
			
			if (Handle14443bUartBit(cq & 0x01)) {
				if(triggered && tracing)
					LogTrace(Uart.output, Uart.byteCnt, samples, samples, NULL, TRUE);

					/* And ready to receive another command. */
					UartReset();
					/* And also reset the demod code, which might have been */
					/* false-triggered by the commands from the reader. */
					DemodReset();
			}
			ReaderIsActive = (Uart.state > STATE_GOT_FALLING_EDGE_OF_SOF);
		}

		if(!ReaderIsActive) {						// no need to try decoding tag data if the reader is sending - and we cannot afford the time
			// is this | 0x01 the error?   & 0xfe  in https://github.com/Proxmark/proxmark3/issues/103
			if(Handle14443bSamplesDemod(ci | 0x01, cq | 0x01)) {

				//Use samples as a time measurement
				if(tracing)
					LogTrace(Demod.output, Demod.len, samples, samples, NULL, FALSE);

				triggered = TRUE;

				// And ready to receive another response.
				DemodReset();
			}
			TagIsActive = (Demod.state > DEMOD_GOT_FALLING_EDGE_OF_SOF);
		}
	}

	FpgaDisableSscDma();
	LEDsoff();
	
	AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;
	DbpString("Snoop statistics:");
	Dbprintf("  Max behind by: %i", maxBehindBy);
	Dbprintf("  Uart State: %x", Uart.state);
	Dbprintf("  Uart ByteCnt: %i", Uart.byteCnt);
	Dbprintf("  Uart ByteCntMax: %i", Uart.byteCntMax);
	Dbprintf("  Trace length: %i", BigBuf_get_traceLen());
	set_tracing(FALSE);	
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
void SendRawCommand14443B_Ex(UsbCommand *c)
{
	iso14b_command_t param = c->arg[0];
	size_t len = c->arg[1] & 0xffff;
	uint8_t *cmd = c->d.asBytes;
	uint8_t status = 0;
	uint32_t sendlen = sizeof(iso14b_card_select_t);
	uint8_t buf[USB_CMD_DATA_SIZE] = {0x00};

	if (MF_DBGLEVEL > 3) Dbprintf("param, %04x", param );
	
	// turn on trigger (LED_A)
	if (param & ISO14B_REQUEST_TRIGGER)
		iso14b_set_trigger(TRUE);
	
	if (param & ISO14B_CONNECT) {
		// Make sure that we start from off, since the tags are stateful;
		// confusing things will happen if we don't reset them between reads.
		LED_D_OFF();
		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
		SpinDelay(200);
		clear_trace();
		iso14443b_setup();
	}
	
	set_tracing(TRUE);

	if ( param & ISO14B_SELECT_STD) {
		iso14b_card_select_t *card = (iso14b_card_select_t*)buf;
		status = iso14443b_select_card(card);	
		cmd_send(CMD_ACK, status, sendlen, 0, buf, sendlen);
		// 0: OK 2: attrib fail, 3:crc fail,
		if ( status > 0 ) return;
	} 
	
	if ( param & ISO14B_SELECT_SR) {
		iso14b_card_select_t *card = (iso14b_card_select_t*)buf;
		status = iso14443b_select_srx_card(card);
		cmd_send(CMD_ACK, status, sendlen, 0, buf, sendlen);
		// 0: OK 2: attrib fail, 3:crc fail,
		if ( status > 0 ) return;
	} 
	
	if (param & ISO14B_APDU) {
		status = iso14443b_apdu(cmd, len, buf);
		cmd_send(CMD_ACK, status, status, 0, buf, status);
	}
	
	if (param & ISO14B_RAW) {
		if(param & ISO14B_APPEND_CRC) {
			AppendCrc14443b(cmd, len);
			len += 2;
		}
	
		CodeAndTransmit14443bAsReader(cmd, len);
		GetSamplesFor14443bDemod(RECEIVE_SAMPLES_TIMEOUT, TRUE);
		
		sendlen = MIN(Demod.len, USB_CMD_DATA_SIZE);
		status =  (Demod.len > 0) ? 0 : 1;
		cmd_send(CMD_ACK, status, sendlen, 0, Demod.output, sendlen);
	}
	
	// turn off trigger (LED_A)
	if (param & ISO14B_REQUEST_TRIGGER)
		iso14a_set_trigger(FALSE);

	// turn off antenna et al
	// we don't send a HALT command.
	if ( param & ISO14B_DISCONNECT) {
		if (MF_DBGLEVEL > 3) Dbprintf("disconnect");
		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
		FpgaDisableSscDma();
		set_tracing(FALSE);
		LEDsoff();
	}
}