//-----------------------------------------------------------------------------
// Jonathan Westhues, split Nov 2006
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443. This includes both the reader software and
// the `fake tag' modes. At the moment only the Type B modulation is
// supported.
//-----------------------------------------------------------------------------

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"

#include "iso14443crc.h"

//static void GetSamplesFor14443(int weTx, int n);

/*#define DEMOD_TRACE_SIZE 4096
#define READER_TAG_BUFFER_SIZE 2048
#define TAG_READER_BUFFER_SIZE 2048
#define DEMOD_DMA_BUFFER_SIZE 1024
*/

#define RECEIVE_SAMPLES_TIMEOUT 2000

//=============================================================================
// An ISO 14443 Type B tag. We listen for commands from the reader, using
// a UART kind of thing that's implemented in software. When we get a
// frame (i.e., a group of bytes between SOF and EOF), we check the CRC.
// If it's good, then we can do something appropriate with it, and send
// a response.
//=============================================================================

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

	// Send SOF.
	for(i = 0; i < 10; i++) {
		ToSendStuffBit(0);
		ToSendStuffBit(0);
		ToSendStuffBit(0);
		ToSendStuffBit(0);
	}
	for(i = 0; i < 10; i++) {
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		ToSendStuffBit(1);
	}

	// Convert from last byte pos to length
	ToSendMax++;

	// Add a few more for slop
	ToSendMax += 2;
}

//-----------------------------------------------------------------------------
// The software UART that receives commands from the reader, and its state
// variables.
//-----------------------------------------------------------------------------
static struct {
	enum {
		STATE_UNSYNCD,
		STATE_GOT_FALLING_EDGE_OF_SOF,
		STATE_AWAITING_START_BIT,
		STATE_RECEIVING_DATA,
		STATE_ERROR_WAIT
	}       state;
	uint16_t    shiftReg;
	int     bitCnt;
	int     byteCnt;
	int     byteCntMax;
	int     posCnt;
	uint8_t   *output;
} Uart;

/* Receive & handle a bit coming from the reader.
 *
 * LED handling:
 * LED A -> ON once we have received the SOF and are expecting the rest.
 * LED A -> OFF once we have received EOF or are in error state or unsynced
 *
 * Returns: true if we received a EOF
 *          false if we are still waiting for some more
 */
static int Handle14443UartBit(int bit)
{
	switch(Uart.state) {
		case STATE_UNSYNCD:
			LED_A_OFF();
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
			if(Uart.posCnt == 2) {
				if(bit) {
					if(Uart.bitCnt >= 10) {
						// we've seen enough consecutive
						// zeros that it's a valid SOF
						Uart.posCnt = 0;
						Uart.byteCnt = 0;
						Uart.state = STATE_AWAITING_START_BIT;
						LED_A_ON(); // Indicate we got a valid SOF
					} else {
						// didn't stay down long enough
						// before going high, error
						Uart.state = STATE_ERROR_WAIT;
					}
				} else {
					// do nothing, keep waiting
				}
				Uart.bitCnt++;
			}
			if(Uart.posCnt >= 4) Uart.posCnt = 0;
			if(Uart.bitCnt > 14) {
				// Give up if we see too many zeros without
				// a one, too.
				Uart.state = STATE_ERROR_WAIT;
			}
			break;

		case STATE_AWAITING_START_BIT:
			Uart.posCnt++;
			if(bit) {
				if(Uart.posCnt > 25) {
					// stayed high for too long between
					// characters, error
					Uart.state = STATE_ERROR_WAIT;
				}
			} else {
				// falling edge, this starts the data byte
				Uart.posCnt = 0;
				Uart.bitCnt = 0;
				Uart.shiftReg = 0;
				Uart.state = STATE_RECEIVING_DATA;
				LED_A_ON(); // Indicate we're receiving
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
						Uart.posCnt = 0;
						Uart.state = STATE_ERROR_WAIT;
					} else {
						// so get the next byte now
						Uart.posCnt = 0;
						Uart.state = STATE_AWAITING_START_BIT;
					}
				} else if(Uart.shiftReg == 0x000) {
					// this is an EOF byte
					LED_A_OFF(); // Finished receiving
					return TRUE;
				} else {
					// this is an error
					Uart.posCnt = 0;
					Uart.state = STATE_ERROR_WAIT;
				}
			}
			break;

		case STATE_ERROR_WAIT:
			// We're all screwed up, so wait a little while
			// for whatever went wrong to finish, and then
			// start over.
			Uart.posCnt++;
			if(Uart.posCnt > 10) {
				Uart.state = STATE_UNSYNCD;
			}
			break;

		default:
			Uart.state = STATE_UNSYNCD;
			break;
	}

	// This row make the error blew circular buffer in hf 14b snoop
	//if (Uart.state == STATE_ERROR_WAIT) LED_A_OFF(); // Error

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
static int GetIso14443CommandFromReader(uint8_t *received, int *len, int maxLen)
{
	uint8_t mask;
	int i, bit;

	// Set FPGA mode to "simulated ISO 14443 tag", no modulation (listen
	// only, since we are receiving, not transmitting).
	// Signal field is off with the appropriate LED
	LED_D_OFF();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_NO_MODULATION);


	// Now run a `software UART' on the stream of incoming samples.
	Uart.output = received;
	Uart.byteCntMax = maxLen;
	Uart.state = STATE_UNSYNCD;

	for(;;) {
		WDT_HIT();

		if(BUTTON_PRESS()) return FALSE;

		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0x00;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

			mask = 0x80;
			for(i = 0; i < 8; i++, mask >>= 1) {
				bit = (b & mask);
				if(Handle14443UartBit(bit)) {
					*len = Uart.byteCnt;
					return TRUE;
				}
			}
		}
	}
}

//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
void SimulateIso14443Tag(void)
{
	static const uint8_t cmd1[] = { 0x05, 0x00, 0x08, 0x39, 0x73 };
	static const uint8_t response1[] = {
		0x50, 0x82, 0x0d, 0xe1, 0x74, 0x20, 0x38, 0x19, 0x22,
		0x00, 0x21, 0x85, 0x5e, 0xd7
	};

	uint8_t *resp;
	int respLen;

	uint8_t *resp1 = BigBuf_get_addr() + 800;
	int resp1Len;

	uint8_t *receivedCmd = BigBuf_get_addr();
	int len;

	int i;

	int cmdsRecvd = 0;

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	memset(receivedCmd, 0x44, 400);

	CodeIso14443bAsTag(response1, sizeof(response1));
	memcpy(resp1, ToSend, ToSendMax); resp1Len = ToSendMax;

	// We need to listen to the high-frequency, peak-detected path.
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

	cmdsRecvd = 0;

	for(;;) {
		uint8_t b1, b2;

		if(!GetIso14443CommandFromReader(receivedCmd, &len, 100)) {
		Dbprintf("button pressed, received %d commands", cmdsRecvd);
		break;
		}

		// Good, look at the command now.

		if(len == sizeof(cmd1) && memcmp(receivedCmd, cmd1, len)==0) {
			resp = resp1; respLen = resp1Len;
		} else {
			Dbprintf("new cmd from reader: len=%d, cmdsRecvd=%d", len, cmdsRecvd);
			// And print whether the CRC fails, just for good measure
			ComputeCrc14443(CRC_14443_B, receivedCmd, len-2, &b1, &b2);
			if(b1 != receivedCmd[len-2] || b2 != receivedCmd[len-1]) {
				// Not so good, try again.
				DbpString("+++CRC fail");
			} else {
				DbpString("CRC passes");
			}
			break;
		}

		memset(receivedCmd, 0x44, 32);

		cmdsRecvd++;

		if(cmdsRecvd > 0x30) {
			DbpString("many commands later...");
			break;
		}

		if(respLen <= 0) continue;

		// Modulate BPSK
		// Signal field is off with the appropriate LED
		LED_D_OFF();
		FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_BPSK);
		AT91C_BASE_SSC->SSC_THR = 0xff;
		FpgaSetupSsc();

		// Transmit the response.
		i = 0;
		for(;;) {
			if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
				uint8_t b = resp[i];

				AT91C_BASE_SSC->SSC_THR = b;

				i++;
				if(i > respLen) {
					break;
				}
			}
			if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
				volatile uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
				(void)b;
			}
		}
	}
}

//=============================================================================
// An ISO 14443 Type B reader. We take layer two commands, code them
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
		DEMOD_RECEIVING_DATA,
		DEMOD_ERROR_WAIT
	}       state;
	int     bitCount;
	int     posCount;
	int     thisBit;
	int     metric;
	int     metricN;
	uint16_t    shiftReg;
	uint8_t   *output;
	int     len;
	int     sumI;
	int     sumQ;
} Demod;

/*
 * Handles reception of a bit from the tag
 *
 * LED handling:
 * LED C -> ON once we have received the SOF and are expecting the rest.
 * LED C -> OFF once we have received EOF or are unsynced
 *
 * Returns: true if we received a EOF
 *          false if we are still waiting for some more
 *
 */
static RAMFUNC int Handle14443SamplesDemod(int ci, int cq)
{
	int v;

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

	switch(Demod.state) {
		case DEMOD_UNSYNCD:
			v = ci;
			if(v < 0) v = -v;
			if(cq > 0) {
				v += cq;
			} else {
				v -= cq;
			}
			if(v > 40) {
				Demod.posCount = 0;
				Demod.state = DEMOD_PHASE_REF_TRAINING;
				Demod.sumI = 0;
				Demod.sumQ = 0;
			}
			break;

		case DEMOD_PHASE_REF_TRAINING:
			if(Demod.posCount < 8) {
				Demod.sumI += ci;
				Demod.sumQ += cq;
			} else if(Demod.posCount > 100) {
				// error, waited too long
				Demod.state = DEMOD_UNSYNCD;
			} else {
				MAKE_SOFT_DECISION();
				if(v < 0) {
					Demod.state = DEMOD_AWAITING_FALLING_EDGE_OF_SOF;
					Demod.posCount = 0;
				}
			}
			Demod.posCount++;
			break;

		case DEMOD_AWAITING_FALLING_EDGE_OF_SOF:
			MAKE_SOFT_DECISION();
			if(v < 0) {
				Demod.state = DEMOD_GOT_FALLING_EDGE_OF_SOF;
				Demod.posCount = 0;
			} else {
				if(Demod.posCount > 100) {
					Demod.state = DEMOD_UNSYNCD;
				}
			}
			Demod.posCount++;
			break;

		case DEMOD_GOT_FALLING_EDGE_OF_SOF:
			MAKE_SOFT_DECISION();
			if(v > 0) {
				if(Demod.posCount < 12) {
					Demod.state = DEMOD_UNSYNCD;
				} else {
					LED_C_ON(); // Got SOF
					Demod.state = DEMOD_AWAITING_START_BIT;
					Demod.posCount = 0;
					Demod.len = 0;
					Demod.metricN = 0;
					Demod.metric = 0;
				}
			} else {
				if(Demod.posCount > 100) {
					Demod.state = DEMOD_UNSYNCD;
				}
			}
			Demod.posCount++;
			break;

		case DEMOD_AWAITING_START_BIT:
			MAKE_SOFT_DECISION();
			if(v > 0) {
				if(Demod.posCount > 10) {
					Demod.state = DEMOD_UNSYNCD;
				}
			} else {
				Demod.bitCount = 0;
				Demod.posCount = 1;
				Demod.thisBit = v;
				Demod.shiftReg = 0;
				Demod.state = DEMOD_RECEIVING_DATA;
			}
			break;

		case DEMOD_RECEIVING_DATA:
			MAKE_SOFT_DECISION();
			if(Demod.posCount == 0) {
				Demod.thisBit = v;
				Demod.posCount = 1;
			} else {
				Demod.thisBit += v;

				if(Demod.thisBit > 0) {
					Demod.metric += Demod.thisBit;
				} else {
					Demod.metric -= Demod.thisBit;
				}
				(Demod.metricN)++;

				Demod.shiftReg >>= 1;
				if(Demod.thisBit > 0) {
					Demod.shiftReg |= 0x200;
				}

				Demod.bitCount++;
				if(Demod.bitCount == 10) {
					uint16_t s = Demod.shiftReg;
					if((s & 0x200) && !(s & 0x001)) {
						uint8_t b = (s >> 1);
						Demod.output[Demod.len] = b;
						Demod.len++;
						Demod.state = DEMOD_AWAITING_START_BIT;
					} else if(s == 0x000) {
						// This is EOF
						LED_C_OFF();
						Demod.state = DEMOD_UNSYNCD;
						return TRUE;
					} else {
						Demod.state = DEMOD_UNSYNCD;
					}
				}
				Demod.posCount = 0;
			}
			break;

		default:
			Demod.state = DEMOD_UNSYNCD;
			break;
	}

	if (Demod.state == DEMOD_UNSYNCD) LED_C_OFF(); // Not synchronized...
	return FALSE;
}
static void DemodReset()
{
	// Clear out the state of the "UART" that receives from the tag.
	Demod.len = 0;
	Demod.state = DEMOD_UNSYNCD;
	memset(Demod.output, 0x00, MAX_FRAME_SIZE);
}
static void DemodInit(uint8_t *data)
{
	Demod.output = data;
	DemodReset();
}

static void UartReset()
{
	Uart.byteCntMax = MAX_FRAME_SIZE;
	Uart.state = STATE_UNSYNCD;
	Uart.byteCnt = 0;
	Uart.bitCnt = 0;
}
static void UartInit(uint8_t *data)
{
	Uart.output = data;
	UartReset();
}

/*
 *  Demodulate the samples we received from the tag, also log to tracebuffer
 *  weTx: set to 'TRUE' if we behave like a reader
 *        set to 'FALSE' if we behave like a snooper
 *  quiet: set to 'TRUE' to disable debug output
 */
static void GetSamplesFor14443Demod(int weTx, int n, int quiet)
{
	int max = 0;
	int gotFrame = FALSE;
	int lastRxCounter, ci, cq, samples = 0;

	// Allocate memory from BigBuf for some buffers
	// free all previous allocations first
	BigBuf_free();
	
	// The response (tag -> reader) that we're receiving.
	uint8_t *receivedResponse = BigBuf_malloc(MAX_FRAME_SIZE);
	
	// The DMA buffer, used to stream samples from the FPGA
	uint8_t *dmaBuf = BigBuf_malloc(DMA_BUFFER_SIZE);

	// Set up the demodulator for tag -> reader responses.
	DemodInit(receivedResponse);

	// Setup and start DMA.
	FpgaSetupSscDma(dmaBuf, DMA_BUFFER_SIZE);

	uint8_t *upTo= dmaBuf;
	lastRxCounter = DMA_BUFFER_SIZE;

	// Signal field is ON with the appropriate LED:
	if (weTx) LED_D_ON(); else LED_D_OFF();
	// And put the FPGA in the appropriate mode
	FpgaWriteConfWord(
		FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ |
		(weTx ? 0 : FPGA_HF_READER_RX_XCORR_SNOOP));

	for(;;) {
		int behindBy = lastRxCounter - AT91C_BASE_PDC_SSC->PDC_RCR;
		if(behindBy > max) max = behindBy;

		while(((lastRxCounter-AT91C_BASE_PDC_SSC->PDC_RCR) & (DMA_BUFFER_SIZE-1))
					> 2)
		{
			ci = upTo[0];
			cq = upTo[1];
			upTo += 2;
			if(upTo >= dmaBuf + DMA_BUFFER_SIZE) {
				upTo = dmaBuf;
				AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) upTo;
				AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
			}
			lastRxCounter -= 2;
			if(lastRxCounter <= 0) {
				lastRxCounter += DMA_BUFFER_SIZE;
			}

			samples += 2;

			if(Handle14443SamplesDemod(ci, cq)) {
				gotFrame = 1;
			}
		}

		if(samples > n) {
			break;
		}
	}
	AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;
	if (!quiet) Dbprintf("%x %x %x", max, gotFrame, Demod.len);
	//Tracing
	if (tracing && Demod.len > 0) {
		uint8_t parity[MAX_PARITY_SIZE];
		GetParity(Demod.output, Demod.len, parity);
		LogTrace(Demod.output, Demod.len, 0, 0, parity, FALSE);
	}
}

//-----------------------------------------------------------------------------
// Read the tag's response. We just receive a stream of slightly-processed
// samples from the FPGA, which we will later do some signal processing on,
// to get the bits.
//-----------------------------------------------------------------------------
/*static void GetSamplesFor14443(int weTx, int n)
{
	uint8_t *dest = (uint8_t *)BigBuf;
	int c;

	FpgaWriteConfWord(
		FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ |
		(weTx ? 0 : FPGA_HF_READER_RX_XCORR_SNOOP));

	c = 0;
	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0x43;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			int8_t b;
			b = (int8_t)AT91C_BASE_SSC->SSC_RHR;

			dest[c++] = (uint8_t)b;

			if(c >= n) {
				break;
			}
		}
	}
}*/

//-----------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitFor14443(void)
{
	int c;

	FpgaSetupSsc();

	while(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
		AT91C_BASE_SSC->SSC_THR = 0xff;
	}

	// Signal field is ON with the appropriate Red LED
	LED_D_ON();
	// Signal we are transmitting with the Green LED
	LED_B_ON();
	FpgaWriteConfWord(
		FPGA_MAJOR_MODE_HF_READER_TX | FPGA_HF_READER_TX_SHALLOW_MOD);

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
	LED_B_OFF(); // Finished sending
}

//-----------------------------------------------------------------------------
// Code a layer 2 command (string of octets, including CRC) into ToSend[],
// so that it is ready to transmit to the tag using TransmitFor14443().
//-----------------------------------------------------------------------------
static void CodeIso14443bAsReader(const uint8_t *cmd, int len)
{
	int i, j;
	uint8_t b;

	ToSendReset();

	// Establish initial reference level
	for(i = 0; i < 40; i++) {
		ToSendStuffBit(1);
	}
	// Send SOF
	for(i = 0; i < 10; i++) {
		ToSendStuffBit(0);
	}

	for(i = 0; i < len; i++) {
		// Stop bits/EGT
		ToSendStuffBit(1);
		ToSendStuffBit(1);
		// Start bit
		ToSendStuffBit(0);
		// Data bits
		b = cmd[i];
		for(j = 0; j < 8; j++) {
			if(b & 1) {
				ToSendStuffBit(1);
			} else {
				ToSendStuffBit(0);
			}
			b >>= 1;
		}
	}
	// Send EOF
	ToSendStuffBit(1);
	for(i = 0; i < 10; i++) {
		ToSendStuffBit(0);
	}
	for(i = 0; i < 8; i++) {
		ToSendStuffBit(1);
	}

	// And then a little more, to make sure that the last character makes
	// it out before we switch to rx mode.
	for(i = 0; i < 24; i++) {
		ToSendStuffBit(1);
	}

	// Convert from last character reference to length
	ToSendMax++;
}

//-----------------------------------------------------------------------------
// Read an ISO 14443 tag. We send it some set of commands, and record the
// responses.
// The command name is misleading, it actually decodes the reponse in HEX
// into the output buffer (read the result using hexsamples, not hisamples)
//
// obsolete function only for test
//-----------------------------------------------------------------------------
void AcquireRawAdcSamplesIso14443(uint32_t parameter)
{
	uint8_t cmd1[] = { 0x05, 0x00, 0x08, 0x39, 0x73 };

	SendRawCommand14443B(sizeof(cmd1),1,1,cmd1);
}

/**
  Convenience function to encode, transmit and trace iso 14443b comms
  **/
static void CodeAndTransmit14443bAsReader(const uint8_t *cmd, int len)
{
	CodeIso14443bAsReader(cmd, len);
	TransmitFor14443();
	if (tracing) {
		uint8_t parity[MAX_PARITY_SIZE];
		GetParity(cmd, len, parity);
		LogTrace(cmd,len, 0, 0, parity, TRUE);
	}
}

//-----------------------------------------------------------------------------
// Read a SRI512 ISO 14443 tag.
//
// SRI512 tags are just simple memory tags, here we're looking at making a dump
// of the contents of the memory. No anticollision algorithm is done, we assume
// we have a single tag in the field.
//
// I tried to be systematic and check every answer of the tag, every CRC, etc...
//-----------------------------------------------------------------------------
void ReadSTMemoryIso14443(uint32_t dwLast)
{
	clear_trace();
	set_tracing(TRUE);

	uint8_t i = 0x00;

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
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
	FpgaWriteConfWord(
		FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ);
	SpinDelay(200);

	// First command: wake up the tag using the INITIATE command
	uint8_t cmd1[] = { 0x06, 0x00, 0x97, 0x5b};

	CodeAndTransmit14443bAsReader(cmd1, sizeof(cmd1));
//    LED_A_ON();
	GetSamplesFor14443Demod(TRUE, RECEIVE_SAMPLES_TIMEOUT, TRUE);
//    LED_A_OFF();

	if (Demod.len == 0) {
	DbpString("No response from tag");
	return;
	} else {
	Dbprintf("Randomly generated UID from tag (+ 2 byte CRC): %x %x %x",
		Demod.output[0], Demod.output[1],Demod.output[2]);
	}
	// There is a response, SELECT the uid
	DbpString("Now SELECT tag:");
	cmd1[0] = 0x0E; // 0x0E is SELECT
	cmd1[1] = Demod.output[0];
	ComputeCrc14443(CRC_14443_B, cmd1, 2, &cmd1[2], &cmd1[3]);
	CodeAndTransmit14443bAsReader(cmd1, sizeof(cmd1));

//    LED_A_ON();
	GetSamplesFor14443Demod(TRUE, RECEIVE_SAMPLES_TIMEOUT, TRUE);
//    LED_A_OFF();
	if (Demod.len != 3) {
	Dbprintf("Expected 3 bytes from tag, got %d", Demod.len);
	return;
	}
	// Check the CRC of the answer:
	ComputeCrc14443(CRC_14443_B, Demod.output, 1 , &cmd1[2], &cmd1[3]);
	if(cmd1[2] != Demod.output[1] || cmd1[3] != Demod.output[2]) {
	DbpString("CRC Error reading select response.");
	return;
	}
	// Check response from the tag: should be the same UID as the command we just sent:
	if (cmd1[1] != Demod.output[0]) {
	Dbprintf("Bad response to SELECT from Tag, aborting: %x %x", cmd1[1], Demod.output[0]);
	return;
	}
	// Tag is now selected,
	// First get the tag's UID:
	cmd1[0] = 0x0B;
	ComputeCrc14443(CRC_14443_B, cmd1, 1 , &cmd1[1], &cmd1[2]);
	CodeAndTransmit14443bAsReader(cmd1, 3); // Only first three bytes for this one

//    LED_A_ON();
	GetSamplesFor14443Demod(TRUE, RECEIVE_SAMPLES_TIMEOUT, TRUE);
//    LED_A_OFF();
	if (Demod.len != 10) {
	Dbprintf("Expected 10 bytes from tag, got %d", Demod.len);
	return;
	}
	// The check the CRC of the answer (use cmd1 as temporary variable):
	ComputeCrc14443(CRC_14443_B, Demod.output, 8, &cmd1[2], &cmd1[3]);
		   if(cmd1[2] != Demod.output[8] || cmd1[3] != Demod.output[9]) {
	Dbprintf("CRC Error reading block! - Below: expected, got %x %x",
		(cmd1[2]<<8)+cmd1[3], (Demod.output[8]<<8)+Demod.output[9]);
	// Do not return;, let's go on... (we should retry, maybe ?)
	}
	Dbprintf("Tag UID (64 bits): %08x %08x",
	(Demod.output[7]<<24) + (Demod.output[6]<<16) + (Demod.output[5]<<8) + Demod.output[4],
	(Demod.output[3]<<24) + (Demod.output[2]<<16) + (Demod.output[1]<<8) + Demod.output[0]);

	// Now loop to read all 16 blocks, address from 0 to last block
	Dbprintf("Tag memory dump, block 0 to %d",dwLast);
	cmd1[0] = 0x08;
	i = 0x00;
	dwLast++;
	for (;;) {
		   if (i == dwLast) {
			DbpString("System area block (0xff):");
			i = 0xff;
		}
		cmd1[1] = i;
		ComputeCrc14443(CRC_14443_B, cmd1, 2, &cmd1[2], &cmd1[3]);
		CodeAndTransmit14443bAsReader(cmd1, sizeof(cmd1));

//	    LED_A_ON();
		GetSamplesFor14443Demod(TRUE, RECEIVE_SAMPLES_TIMEOUT, TRUE);
//	    LED_A_OFF();
		if (Demod.len != 6) { // Check if we got an answer from the tag
		DbpString("Expected 6 bytes from tag, got less...");
		return;
		}
		// The check the CRC of the answer (use cmd1 as temporary variable):
		ComputeCrc14443(CRC_14443_B, Demod.output, 4, &cmd1[2], &cmd1[3]);
			if(cmd1[2] != Demod.output[4] || cmd1[3] != Demod.output[5]) {
		Dbprintf("CRC Error reading block! - Below: expected, got %x %x",
			(cmd1[2]<<8)+cmd1[3], (Demod.output[4]<<8)+Demod.output[5]);
		// Do not return;, let's go on... (we should retry, maybe ?)
		}
		// Now print out the memory location:
		Dbprintf("Address=%x, Contents=%x, CRC=%x", i,
		(Demod.output[3]<<24) + (Demod.output[2]<<16) + (Demod.output[1]<<8) + Demod.output[0],
		(Demod.output[4]<<8)+Demod.output[5]);
		if (i == 0xff) {
		break;
		}
		i++;
	}
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
 * 0-4095 : Demodulated samples receive (4096 bytes) - DEMOD_TRACE_SIZE
 * 4096-6143 : Last Received command, 2048 bytes (reader->tag) - READER_TAG_BUFFER_SIZE
 * 6144-8191 : Last Received command, 2048 bytes(tag->reader) - TAG_READER_BUFFER_SIZE
 * 8192-9215 : DMA Buffer, 1024 bytes (samples) - DEMOD_DMA_BUFFER_SIZE
 */
void RAMFUNC SnoopIso14443(void)
{
	// We won't start recording the frames that we acquire until we trigger;
	// a good trigger condition to get started is probably when we see a
	// response from the tag.
	int triggered = TRUE;

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	BigBuf_free();

	clear_trace();
	set_tracing(TRUE);

	// The DMA buffer, used to stream samples from the FPGA
	uint8_t *dmaBuf = BigBuf_malloc(DMA_BUFFER_SIZE);
	int lastRxCounter;
	uint8_t *upTo;
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
	Dbprintf("  DMA: %i bytes", DMA_BUFFER_SIZE);

	// Signal field is off with the appropriate LED
	LED_D_OFF();

	// And put the FPGA in the appropriate mode
	FpgaWriteConfWord(
		FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ |
		FPGA_HF_READER_RX_XCORR_SNOOP);
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Setup for the DMA.
	FpgaSetupSsc();
	upTo = dmaBuf;
	lastRxCounter = DMA_BUFFER_SIZE;
	FpgaSetupSscDma((uint8_t *)dmaBuf, DMA_BUFFER_SIZE);
	uint8_t parity[MAX_PARITY_SIZE];
	LED_A_ON();
		
	// And now we loop, receiving samples.
	for(;;) {
		int behindBy = (lastRxCounter - AT91C_BASE_PDC_SSC->PDC_RCR) &
								(DMA_BUFFER_SIZE-1);
		if(behindBy > maxBehindBy) {
			maxBehindBy = behindBy;
			if(behindBy > (9*DMA_BUFFER_SIZE/10)) { // TODO: understand whether we can increase/decrease as we want or not?
				Dbprintf("blew circular buffer! behindBy=0x%x", behindBy);
				break;
			}
		}
		if(behindBy < 2) continue;

		ci = upTo[0];
		cq = upTo[1];
		upTo += 2;
		lastRxCounter -= 2;
		if(upTo >= dmaBuf + DMA_BUFFER_SIZE) {
			upTo = dmaBuf;
			lastRxCounter += DMA_BUFFER_SIZE;
			AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
		}

		samples += 2;

		if(Handle14443UartBit(ci & 1)) {
			if(triggered && tracing) {
				GetParity(Uart.output, Uart.byteCnt, parity);
				LogTrace(Uart.output,Uart.byteCnt,samples, samples,parity,TRUE);
			}
			if(Uart.byteCnt==0) Dbprintf("[1] Error, Uart.byteCnt==0, Uart.bitCnt=%d", Uart.bitCnt);

			/* And ready to receive another command. */
			UartReset();
			/* And also reset the demod code, which might have been */
			/* false-triggered by the commands from the reader. */
			DemodReset();
		}
		if(Handle14443UartBit(cq & 1)) {
			if(triggered && tracing) {
				GetParity(Uart.output, Uart.byteCnt, parity);
				LogTrace(Uart.output,Uart.byteCnt,samples, samples,parity,TRUE);
			}
			if(Uart.byteCnt==0) Dbprintf("[2] Error, Uart.byteCnt==0, Uart.bitCnt=%d", Uart.bitCnt);

			/* And ready to receive another command. */
			UartReset();
			/* And also reset the demod code, which might have been */
			/* false-triggered by the commands from the reader. */
			DemodReset();
		}

		if(Handle14443SamplesDemod(ci, cq)) {

			//Use samples as a time measurement
			if(tracing)
			{
				uint8_t parity[MAX_PARITY_SIZE];
				GetParity(Demod.output, Demod.len, parity);
				LogTrace(Demod.output,Demod.len,samples, samples,parity,FALSE);
			}
			triggered = TRUE;
			LED_A_OFF();
			LED_B_ON();

			// And ready to receive another response.
			DemodReset();
		}
		WDT_HIT();

		if(!tracing) {
			DbpString("Reached trace limit");
			break;
		}

		if(BUTTON_PRESS()) {
			DbpString("cancelled");
			break;
		}
	}
	FpgaDisableSscDma();
	LED_A_OFF();
	LED_B_OFF();
	LED_C_OFF();
	AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;
	DbpString("Snoop statistics:");
	Dbprintf("  Max behind by: %i", maxBehindBy);
	Dbprintf("  Uart State: %x", Uart.state);
	Dbprintf("  Uart ByteCnt: %i", Uart.byteCnt);
	Dbprintf("  Uart ByteCntMax: %i", Uart.byteCntMax);
	Dbprintf("  Trace length: %i", BigBuf_get_traceLen());
}

/*
 * Send raw command to tag ISO14443B
 * @Input
 * datalen     len of buffer data
 * recv        bool when true wait for data from tag and send to client
 * powerfield  bool leave the field on when true
 * data        buffer with byte to send
 *
 * @Output
 * none
 *
 */

void SendRawCommand14443B(uint32_t datalen, uint32_t recv,uint8_t powerfield, uint8_t data[])
{
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	if(!powerfield)
	{
		// Make sure that we start from off, since the tags are stateful;
		// confusing things will happen if we don't reset them between reads.
		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
		LED_D_OFF();
		SpinDelay(200);
	}

	if(!GETBIT(GPIO_LED_D))
	{
		SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
		FpgaSetupSsc();

		// Now give it time to spin up.
		// Signal field is on with the appropriate LED
		LED_D_ON();
		FpgaWriteConfWord(
			FPGA_MAJOR_MODE_HF_READER_RX_XCORR | FPGA_HF_READER_RX_XCORR_848_KHZ);
		SpinDelay(200);
	}

	CodeAndTransmit14443bAsReader(data, datalen);

	if(recv)
	{
		GetSamplesFor14443Demod(TRUE, RECEIVE_SAMPLES_TIMEOUT, TRUE);
		uint16_t iLen = MIN(Demod.len,USB_CMD_DATA_SIZE);
		cmd_send(CMD_ACK,iLen,0,0,Demod.output,iLen);
	}
	if(!powerfield)
	{
		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
		LED_D_OFF();
	}
}

