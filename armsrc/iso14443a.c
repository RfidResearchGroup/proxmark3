//-----------------------------------------------------------------------------
// Merlok - June 2011, 2012
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type A.
//-----------------------------------------------------------------------------

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"
#include "cmd.h"

#include "iso14443crc.h"
#include "iso14443a.h"
#include "crapto1.h"
#include "mifareutil.h"

static uint32_t iso14a_timeout;
uint8_t *trace = (uint8_t *) BigBuf+TRACE_OFFSET;
int traceLen = 0;
int rsamples = 0;
int tracing = TRUE;
uint8_t trigger = 0;
// the block number for the ISO14443-4 PCB
static uint8_t iso14_pcb_blocknum = 0;

// CARD TO READER - manchester
// Sequence D: 11110000 modulation with subcarrier during first half
// Sequence E: 00001111 modulation with subcarrier during second half
// Sequence F: 00000000 no modulation with subcarrier
// READER TO CARD - miller
// Sequence X: 00001100 drop after half a period
// Sequence Y: 00000000 no drop
// Sequence Z: 11000000 drop at start
#define	SEC_D 0xf0
#define	SEC_E 0x0f
#define	SEC_F 0x00
#define	SEC_X 0x0c
#define	SEC_Y 0x00
#define	SEC_Z 0xc0

const uint8_t OddByteParity[256] = {
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};


void iso14a_set_trigger(bool enable) {
	trigger = enable;
}

void iso14a_clear_trace() {
  memset(trace, 0x44, TRACE_SIZE);
	traceLen = 0;
}

void iso14a_set_tracing(bool enable) {
	tracing = enable;
}

void iso14a_set_timeout(uint32_t timeout) {
	iso14a_timeout = timeout;
}

//-----------------------------------------------------------------------------
// Generate the parity value for a byte sequence
//
//-----------------------------------------------------------------------------
byte_t oddparity (const byte_t bt)
{
	return OddByteParity[bt];
}

uint32_t GetParity(const uint8_t * pbtCmd, int iLen)
{
	int i;
	uint32_t dwPar = 0;

	// Generate the parity bits
	for (i = 0; i < iLen; i++) {
		// and save them to a 32Bit word
		dwPar |= ((OddByteParity[pbtCmd[i]]) << i);
	}
	return dwPar;
}

void AppendCrc14443a(uint8_t* data, int len)
{
	ComputeCrc14443(CRC_14443_A,data,len,data+len,data+len+1);
}

// The function LogTrace() is also used by the iClass implementation in iClass.c
int RAMFUNC LogTrace(const uint8_t * btBytes, int iLen, int iSamples, uint32_t dwParity, int bReader)
{
  // Return when trace is full
  if (traceLen >= TRACE_SIZE) return FALSE;

  // Trace the random, i'm curious
  rsamples += iSamples;
  trace[traceLen++] = ((rsamples >> 0) & 0xff);
  trace[traceLen++] = ((rsamples >> 8) & 0xff);
  trace[traceLen++] = ((rsamples >> 16) & 0xff);
  trace[traceLen++] = ((rsamples >> 24) & 0xff);
  if (!bReader) {
    trace[traceLen - 1] |= 0x80;
  }
  trace[traceLen++] = ((dwParity >> 0) & 0xff);
  trace[traceLen++] = ((dwParity >> 8) & 0xff);
  trace[traceLen++] = ((dwParity >> 16) & 0xff);
  trace[traceLen++] = ((dwParity >> 24) & 0xff);
  trace[traceLen++] = iLen;
  memcpy(trace + traceLen, btBytes, iLen);
  traceLen += iLen;
  return TRUE;
}

//-----------------------------------------------------------------------------
// The software UART that receives commands from the reader, and its state
// variables.
//-----------------------------------------------------------------------------
static tUart Uart;

static RAMFUNC int MillerDecoding(int bit)
{
	//int error = 0;
	int bitright;

	if(!Uart.bitBuffer) {
		Uart.bitBuffer = bit ^ 0xFF0;
		return FALSE;
	}
	else {
		Uart.bitBuffer <<= 4;
		Uart.bitBuffer ^= bit;
	}

	int EOC = FALSE;

	if(Uart.state != STATE_UNSYNCD) {
		Uart.posCnt++;

		if((Uart.bitBuffer & Uart.syncBit) ^ Uart.syncBit) {
			bit = 0x00;
		}
		else {
			bit = 0x01;
		}
		if(((Uart.bitBuffer << 1) & Uart.syncBit) ^ Uart.syncBit) {
			bitright = 0x00;
		}
		else {
			bitright = 0x01;
		}
		if(bit != bitright) { bit = bitright; }

		if(Uart.posCnt == 1) {
			// measurement first half bitperiod
			if(!bit) {
				Uart.drop = DROP_FIRST_HALF;
			}
		}
		else {
			// measurement second half bitperiod
			if(!bit & (Uart.drop == DROP_NONE)) {
				Uart.drop = DROP_SECOND_HALF;
			}
			else if(!bit) {
				// measured a drop in first and second half
				// which should not be possible
				Uart.state = STATE_ERROR_WAIT;
				//error = 0x01;
			}

			Uart.posCnt = 0;

			switch(Uart.state) {
				case STATE_START_OF_COMMUNICATION:
					Uart.shiftReg = 0;
					if(Uart.drop == DROP_SECOND_HALF) {
						// error, should not happen in SOC
						Uart.state = STATE_ERROR_WAIT;
						//error = 0x02;
					}
					else {
						// correct SOC
						Uart.state = STATE_MILLER_Z;
					}
					break;

				case STATE_MILLER_Z:
					Uart.bitCnt++;
					Uart.shiftReg >>= 1;
					if(Uart.drop == DROP_NONE) {
						// logic '0' followed by sequence Y
						// end of communication
						Uart.state = STATE_UNSYNCD;
						EOC = TRUE;
					}
					// if(Uart.drop == DROP_FIRST_HALF) {
					// 	Uart.state = STATE_MILLER_Z; stay the same
					// 	we see a logic '0' }
					if(Uart.drop == DROP_SECOND_HALF) {
						// we see a logic '1'
						Uart.shiftReg |= 0x100;
						Uart.state = STATE_MILLER_X;
					}
					break;

				case STATE_MILLER_X:
					Uart.shiftReg >>= 1;
					if(Uart.drop == DROP_NONE) {
						// sequence Y, we see a '0'
						Uart.state = STATE_MILLER_Y;
						Uart.bitCnt++;
					}
					if(Uart.drop == DROP_FIRST_HALF) {
						// Would be STATE_MILLER_Z
						// but Z does not follow X, so error
						Uart.state = STATE_ERROR_WAIT;
						//error = 0x03;
					}
					if(Uart.drop == DROP_SECOND_HALF) {
						// We see a '1' and stay in state X
						Uart.shiftReg |= 0x100;
						Uart.bitCnt++;
					}
					break;

				case STATE_MILLER_Y:
					Uart.bitCnt++;
					Uart.shiftReg >>= 1;
					if(Uart.drop == DROP_NONE) {
						// logic '0' followed by sequence Y
						// end of communication
						Uart.state = STATE_UNSYNCD;
						EOC = TRUE;
					}
					if(Uart.drop == DROP_FIRST_HALF) {
						// we see a '0'
						Uart.state = STATE_MILLER_Z;
					}
					if(Uart.drop == DROP_SECOND_HALF) {
						// We see a '1' and go to state X
						Uart.shiftReg |= 0x100;
						Uart.state = STATE_MILLER_X;
					}
					break;

				case STATE_ERROR_WAIT:
					// That went wrong. Now wait for at least two bit periods
					// and try to sync again
					if(Uart.drop == DROP_NONE) {
						Uart.highCnt = 6;
						Uart.state = STATE_UNSYNCD;
					}
					break;

				default:
					Uart.state = STATE_UNSYNCD;
					Uart.highCnt = 0;
					break;
			}

			Uart.drop = DROP_NONE;

			// should have received at least one whole byte...
			if((Uart.bitCnt == 2) && EOC && (Uart.byteCnt > 0)) {
				return TRUE;
			}

			if(Uart.bitCnt == 9) {
				Uart.output[Uart.byteCnt] = (Uart.shiftReg & 0xff);
				Uart.byteCnt++;

				Uart.parityBits <<= 1;
				Uart.parityBits ^= ((Uart.shiftReg >> 8) & 0x01);

				if(EOC) {
					// when End of Communication received and
					// all data bits processed..
					return TRUE;
				}
				Uart.bitCnt = 0;
			}

			/*if(error) {
				Uart.output[Uart.byteCnt] = 0xAA;
				Uart.byteCnt++;
				Uart.output[Uart.byteCnt] = error & 0xFF;
				Uart.byteCnt++;
				Uart.output[Uart.byteCnt] = 0xAA;
				Uart.byteCnt++;
				Uart.output[Uart.byteCnt] = (Uart.bitBuffer >> 8) & 0xFF;
				Uart.byteCnt++;
				Uart.output[Uart.byteCnt] = Uart.bitBuffer & 0xFF;
				Uart.byteCnt++;
				Uart.output[Uart.byteCnt] = (Uart.syncBit >> 3) & 0xFF;
				Uart.byteCnt++;
				Uart.output[Uart.byteCnt] = 0xAA;
				Uart.byteCnt++;
				return TRUE;
			}*/
		}

	}
	else {
		bit = Uart.bitBuffer & 0xf0;
		bit >>= 4;
		bit ^= 0x0F;
		if(bit) {
			// should have been high or at least (4 * 128) / fc
			// according to ISO this should be at least (9 * 128 + 20) / fc
			if(Uart.highCnt == 8) {
				// we went low, so this could be start of communication
				// it turns out to be safer to choose a less significant
				// syncbit... so we check whether the neighbour also represents the drop
				Uart.posCnt = 1;   // apparently we are busy with our first half bit period
				Uart.syncBit = bit & 8;
				Uart.samples = 3;
				if(!Uart.syncBit)	{ Uart.syncBit = bit & 4; Uart.samples = 2; }
				else if(bit & 4)	{ Uart.syncBit = bit & 4; Uart.samples = 2; bit <<= 2; }
				if(!Uart.syncBit)	{ Uart.syncBit = bit & 2; Uart.samples = 1; }
				else if(bit & 2)	{ Uart.syncBit = bit & 2; Uart.samples = 1; bit <<= 1; }
				if(!Uart.syncBit)	{ Uart.syncBit = bit & 1; Uart.samples = 0;
					if(Uart.syncBit && (Uart.bitBuffer & 8)) {
						Uart.syncBit = 8;

						// the first half bit period is expected in next sample
						Uart.posCnt = 0;
						Uart.samples = 3;
					}
				}
				else if(bit & 1)	{ Uart.syncBit = bit & 1; Uart.samples = 0; }

				Uart.syncBit <<= 4;
				Uart.state = STATE_START_OF_COMMUNICATION;
				Uart.drop = DROP_FIRST_HALF;
				Uart.bitCnt = 0;
				Uart.byteCnt = 0;
				Uart.parityBits = 0;
				//error = 0;
			}
			else {
				Uart.highCnt = 0;
			}
		}
		else {
			if(Uart.highCnt < 8) {
				Uart.highCnt++;
			}
		}
	}

    return FALSE;
}

//=============================================================================
// ISO 14443 Type A - Manchester decoder
//=============================================================================
// Basics:
// The tag will modulate the reader field by asserting different loads to it. As a consequence, the voltage
// at the reader antenna will be modulated as well. The FPGA detects the modulation for us and would deliver e.g. the following:
// ........ 0 0 1 1 1 1 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 .......
// The Manchester decoder needs to identify the following sequences:
// 4 ticks modulated followed by 4 ticks unmodulated: 	Sequence D = 1 (also used as "start of communication")
// 4 ticks unmodulated followed by 4 ticks modulated: 	Sequence E = 0
// 8 ticks unmodulated:									Sequence F = end of communication
// 8 ticks modulated:									A collision. Save the collision position and treat as Sequence D
// Note 1: the bitstream may start at any time (either in first or second nibble within the parameter bit). We therefore need to sync.
// Note 2: parameter offset is used to determine the position of the parity bits (required for the anticollision command only)
static tDemod Demod;

inline RAMFUNC bool IsModulation(byte_t b)
{
	if (b >= 5 || b == 3)		// majority decision: 2 or more bits are set
		return true;
	else
		return false;
	
}

inline RAMFUNC bool IsModulationNibble1(byte_t b)
{
	return IsModulation((b & 0xE0) >> 5);
}

inline RAMFUNC bool IsModulationNibble2(byte_t b)
{
	return IsModulation((b & 0x0E) >> 1);
}

static RAMFUNC int ManchesterDecoding(int bit, uint16_t offset)
{
	
	switch (Demod.state) {

		case DEMOD_UNSYNCD:						// not yet synced
			Demod.len = 0;						// initialize number of decoded data bytes
			Demod.bitCount = offset;			// initialize number of decoded data bits
			Demod.shiftReg = 0;					// initialize shiftreg to hold decoded data bits
			Demod.parityBits = 0;				// initialize parity bits
			Demod.collisionPos = 0;				// Position of collision bit
			
			if (IsModulationNibble1(bit) 
				&& !IsModulationNibble2(bit)) { 	 						// this is the start bit
				Demod.samples = 8;
				if(trigger) LED_A_OFF();
				Demod.state = DEMOD_MANCHESTER_DATA;
			} else if (!IsModulationNibble1(bit) && IsModulationNibble2(bit)) { // this may be the first half of the start bit
					Demod.samples = 4;
					Demod.state = DEMOD_HALF_SYNCD;
			}
			break;


		case DEMOD_HALF_SYNCD:
			Demod.samples += 8;
			if (IsModulationNibble1(bit)) {								// error: this was not a start bit.
				Demod.state = DEMOD_UNSYNCD;
			} else {
				if (IsModulationNibble2(bit)) {							// modulation in first half
					Demod.state = DEMOD_MOD_FIRST_HALF;
				} else {												// no modulation in first half
					Demod.state = DEMOD_NOMOD_FIRST_HALF;
				}
			}
			break;
			
			
		case DEMOD_MOD_FIRST_HALF:
			Demod.samples += 8;
			Demod.bitCount++;
			if (IsModulationNibble1(bit)) {								// modulation in both halfs - collision
				if (!Demod.collisionPos) {
					Demod.collisionPos = (Demod.len << 3) + Demod.bitCount;
				}
			}															// modulation in first half only - Sequence D = 1
			Demod.shiftReg = (Demod.shiftReg >> 1) | 0x100;				// add a 1 to the shiftreg
			if(Demod.bitCount >= 9) {									// if we decoded a full byte (including parity)
				Demod.parityBits <<= 1;									// make room for the parity bit
				Demod.output[Demod.len++] = (Demod.shiftReg & 0xff);
				Demod.parityBits |= ((Demod.shiftReg >> 8) & 0x01); 	// store parity bit
				Demod.bitCount = 0;
				Demod.shiftReg = 0;
			}
			if (IsModulationNibble2(bit)) {								// modulation in first half
				Demod.state = DEMOD_MOD_FIRST_HALF;
			} else {													// no modulation in first half
				Demod.state = DEMOD_NOMOD_FIRST_HALF;
			}
			break;


		case DEMOD_NOMOD_FIRST_HALF:
			if (IsModulationNibble1(bit)) {								// modulation in second half only - Sequence E = 0
				Demod.bitCount++;
				Demod.samples += 8;
				Demod.shiftReg = (Demod.shiftReg >> 1);		 			// add a 0 to the shiftreg
				if(Demod.bitCount >= 9) {								// if we decoded a full byte (including parity)
					Demod.parityBits <<= 1;								// make room for the new parity bit
					Demod.output[Demod.len++] = (Demod.shiftReg & 0xff);
					Demod.parityBits |= ((Demod.shiftReg >> 8) & 0x01); // store parity bit
					Demod.bitCount = 0;
					Demod.shiftReg = 0;
				}
			} else {													// no modulation in both halves - End of communication
				Demod.samples += 4;
				if(Demod.bitCount > 0) {								// if we decoded bits
					Demod.shiftReg >>= (9 - Demod.bitCount);			// add the remaining decoded bits to the output
					Demod.output[Demod.len++] = Demod.shiftReg & 0xff;
					// No parity bit, so just shift a 0
					Demod.parityBits <<= 1;
				}
				Demod.state = DEMOD_UNSYNCD;							// start from the beginning
				return TRUE;											// we are finished with decoding the raw data sequence
			}
			if (IsModulationNibble2(bit)) {								// modulation in first half
				Demod.state = DEMOD_MOD_FIRST_HALF;
			} else {													// no modulation in first half
				Demod.state = DEMOD_NOMOD_FIRST_HALF;
			}
			break;
			

		case DEMOD_MANCHESTER_DATA:
			Demod.samples += 8;
			if (IsModulationNibble1(bit)) {									// modulation in first half
				if (IsModulationNibble2(bit) & 0x0f) {						// ... and in second half = collision
					if (!Demod.collisionPos) {
						Demod.collisionPos = (Demod.len << 3) + Demod.bitCount;
					}
				}														// modulation in first half only - Sequence D = 1
				Demod.bitCount++;
				Demod.shiftReg = (Demod.shiftReg >> 1) | 0x100;			// in both cases, add a 1 to the shiftreg
				if(Demod.bitCount >= 9) {								// if we decoded a full byte (including parity)
					Demod.parityBits <<= 1;								// make room for the parity bit
					Demod.output[Demod.len++] = (Demod.shiftReg & 0xff);
					Demod.parityBits |= ((Demod.shiftReg >> 8) & 0x01); // store parity bit
					Demod.bitCount = 0;
					Demod.shiftReg = 0;
				}
			} else {													// no modulation in first half
				if (IsModulationNibble2(bit)) {							// and modulation in second half = Sequence E = 0
					Demod.bitCount++;
					Demod.shiftReg = (Demod.shiftReg >> 1);				// add a 0 to the shiftreg
					if(Demod.bitCount >= 9) {							// if we decoded a full byte (including parity)
						Demod.parityBits <<= 1;							// make room for the new parity bit
						Demod.output[Demod.len++] = (Demod.shiftReg & 0xff);
						Demod.parityBits |= ((Demod.shiftReg >> 8) & 0x01); // store parity bit
						Demod.bitCount = 0;
						Demod.shiftReg = 0;
					}
				} else {												// no modulation in both halves - End of communication
					if(Demod.bitCount > 0) {							// if we decoded bits
						Demod.shiftReg >>= (9 - Demod.bitCount);		// add the remaining decoded bits to the output
						Demod.output[Demod.len++] = Demod.shiftReg & 0xff;
						// No parity bit, so just shift a 0
						Demod.parityBits <<= 1;
					}
					Demod.state = DEMOD_UNSYNCD;						// start from the beginning
					return TRUE;										// we are finished with decoding the raw data sequence
				}
			}
			
	} 

    return FALSE;	// not finished yet, need more data
}

//=============================================================================
// Finally, a `sniffer' for ISO 14443 Type A
// Both sides of communication!
//=============================================================================

//-----------------------------------------------------------------------------
// Record the sequence of commands sent by the reader to the tag, with
// triggering so that we start recording at the point that the tag is moved
// near the reader.
//-----------------------------------------------------------------------------
void RAMFUNC SnoopIso14443a(uint8_t param) {
	// param:
	// bit 0 - trigger from first card answer
	// bit 1 - trigger from first reader 7-bit request
	
	LEDsoff();
	// init trace buffer
	iso14a_clear_trace();

	// We won't start recording the frames that we acquire until we trigger;
	// a good trigger condition to get started is probably when we see a
	// response from the tag.
	// triggered == FALSE -- to wait first for card
	int triggered = !(param & 0x03); 

	// The command (reader -> tag) that we're receiving.
	// The length of a received command will in most cases be no more than 18 bytes.
	// So 32 should be enough!
	uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
	// The response (tag -> reader) that we're receiving.
	uint8_t *receivedResponse = (((uint8_t *)BigBuf) + RECV_RES_OFFSET);

	// As we receive stuff, we copy it from receivedCmd or receivedResponse
	// into trace, along with its length and other annotations.
	//uint8_t *trace = (uint8_t *)BigBuf;
	
	// The DMA buffer, used to stream samples from the FPGA
	int8_t *dmaBuf = ((int8_t *)BigBuf) + DMA_BUFFER_OFFSET;
	int8_t *data = dmaBuf;
	int maxDataLen = 0;
	int dataLen = 0;

	// Set up the demodulator for tag -> reader responses.
	Demod.output = receivedResponse;
	Demod.len = 0;
	Demod.state = DEMOD_UNSYNCD;

	// Set up the demodulator for the reader -> tag commands
	memset(&Uart, 0, sizeof(Uart));
	Uart.output = receivedCmd;
	Uart.byteCntMax = 32;                        // was 100 (greg)//////////////////
	Uart.state = STATE_UNSYNCD;

	// Setup for the DMA.
	FpgaSetupSsc();
	FpgaSetupSscDma((uint8_t *)dmaBuf, DMA_BUFFER_SIZE);

	// And put the FPGA in the appropriate mode
	// Signal field is off with the appropriate LED
	LED_D_OFF();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_SNIFFER);
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Count of samples received so far, so that we can include timing
	// information in the trace buffer.
	rsamples = 0;
	// And now we loop, receiving samples.
	while(true) {
		if(BUTTON_PRESS()) {
			DbpString("cancelled by button");
			goto done;
		}

		LED_A_ON();
		WDT_HIT();

		int register readBufDataP = data - dmaBuf;
		int register dmaBufDataP = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR;
		if (readBufDataP <= dmaBufDataP){
			dataLen = dmaBufDataP - readBufDataP;
		} else {
			dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP + 1;
		}
		// test for length of buffer
		if(dataLen > maxDataLen) {
			maxDataLen = dataLen;
			if(dataLen > 400) {
				Dbprintf("blew circular buffer! dataLen=0x%x", dataLen);
				goto done;
			}
		}
		if(dataLen < 1) continue;

		// primary buffer was stopped( <-- we lost data!
		if (!AT91C_BASE_PDC_SSC->PDC_RCR) {
			AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
		}
		// secondary buffer sets as primary, secondary buffer was stopped
		if (!AT91C_BASE_PDC_SSC->PDC_RNCR) {
			AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
		}

		LED_A_OFF();
		
		rsamples += 4;
		if(MillerDecoding((data[0] & 0xF0) >> 4)) {
			LED_C_ON();

			// check - if there is a short 7bit request from reader
			if ((!triggered) && (param & 0x02) && (Uart.byteCnt == 1) && (Uart.bitCnt = 9)) triggered = TRUE;

			if(triggered) {
				if (!LogTrace(receivedCmd, Uart.byteCnt, 0 - Uart.samples, Uart.parityBits, TRUE)) break;
			}
			/* And ready to receive another command. */
			Uart.state = STATE_UNSYNCD;
			/* And also reset the demod code, which might have been */
			/* false-triggered by the commands from the reader. */
			Demod.state = DEMOD_UNSYNCD;
			LED_B_OFF();
		}

		if(ManchesterDecoding(data[0], 0)) {
			LED_B_ON();

			if (!LogTrace(receivedResponse, Demod.len, 0 - Demod.samples, Demod.parityBits, FALSE)) break;

			if ((!triggered) && (param & 0x01)) triggered = TRUE;

			// And ready to receive another response.
			memset(&Demod, 0, sizeof(Demod));
			Demod.output = receivedResponse;
			Demod.state = DEMOD_UNSYNCD;
			LED_C_OFF();
		}

		data++;
		if(data > dmaBuf + DMA_BUFFER_SIZE) {
			data = dmaBuf;
		}
	} // main cycle

	DbpString("COMMAND FINISHED");

done:
	AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;
	Dbprintf("maxDataLen=%x, Uart.state=%x, Uart.byteCnt=%x", maxDataLen, Uart.state, Uart.byteCnt);
	Dbprintf("Uart.byteCntMax=%x, traceLen=%x, Uart.output[0]=%08x", Uart.byteCntMax, traceLen, (int)Uart.output[0]);
	LEDsoff();
}

//-----------------------------------------------------------------------------
// Prepare tag messages
//-----------------------------------------------------------------------------
static void CodeIso14443aAsTagPar(const uint8_t *cmd, int len, uint32_t dwParity)
{
	int i;

	ToSendReset();

	// Correction bit, might be removed when not needed
	ToSendStuffBit(0);
	ToSendStuffBit(0);
	ToSendStuffBit(0);
	ToSendStuffBit(0);
	ToSendStuffBit(1);  // 1
	ToSendStuffBit(0);
	ToSendStuffBit(0);
	ToSendStuffBit(0);
	
	// Send startbit
	ToSend[++ToSendMax] = SEC_D;

	for(i = 0; i < len; i++) {
		int j;
		uint8_t b = cmd[i];

		// Data bits
		for(j = 0; j < 8; j++) {
			if(b & 1) {
				ToSend[++ToSendMax] = SEC_D;
			} else {
				ToSend[++ToSendMax] = SEC_E;
			}
			b >>= 1;
		}

		// Get the parity bit
		if ((dwParity >> i) & 0x01) {
			ToSend[++ToSendMax] = SEC_D;
		} else {
			ToSend[++ToSendMax] = SEC_E;
		}
	}

	// Send stopbit
	ToSend[++ToSendMax] = SEC_F;

	// Convert from last byte pos to length
	ToSendMax++;
}

static void CodeIso14443aAsTag(const uint8_t *cmd, int len){
	CodeIso14443aAsTagPar(cmd, len, GetParity(cmd, len));
}

////-----------------------------------------------------------------------------
//// This is to send a NACK kind of answer, its only 3 bits, I know it should be 4
////-----------------------------------------------------------------------------
//static void CodeStrangeAnswerAsTag()
//{
//	int i;
//
//	ToSendReset();
//
//	// Correction bit, might be removed when not needed
//	ToSendStuffBit(0);
//	ToSendStuffBit(0);
//	ToSendStuffBit(0);
//	ToSendStuffBit(0);
//	ToSendStuffBit(1);  // 1
//	ToSendStuffBit(0);
//	ToSendStuffBit(0);
//	ToSendStuffBit(0);
//
//	// Send startbit
//	ToSend[++ToSendMax] = SEC_D;
//
//	// 0
//	ToSend[++ToSendMax] = SEC_E;
//
//	// 0
//	ToSend[++ToSendMax] = SEC_E;
//
//	// 1
//	ToSend[++ToSendMax] = SEC_D;
//
//	// Send stopbit
//	ToSend[++ToSendMax] = SEC_F;
//
//	// Flush the buffer in FPGA!!
//	for(i = 0; i < 5; i++) {
//		ToSend[++ToSendMax] = SEC_F;
//	}
//
//	// Convert from last byte pos to length
//	ToSendMax++;
//}

static void Code4bitAnswerAsTag(uint8_t cmd)
{
	int i;

	ToSendReset();

	// Correction bit, might be removed when not needed
	ToSendStuffBit(0);
	ToSendStuffBit(0);
	ToSendStuffBit(0);
	ToSendStuffBit(0);
	ToSendStuffBit(1);  // 1
	ToSendStuffBit(0);
	ToSendStuffBit(0);
	ToSendStuffBit(0);

	// Send startbit
	ToSend[++ToSendMax] = SEC_D;

	uint8_t b = cmd;
	for(i = 0; i < 4; i++) {
		if(b & 1) {
			ToSend[++ToSendMax] = SEC_D;
		} else {
			ToSend[++ToSendMax] = SEC_E;
		}
		b >>= 1;
	}

	// Send stopbit
	ToSend[++ToSendMax] = SEC_F;

	// Flush the buffer in FPGA!!
	for(i = 0; i < 5; i++) {
		ToSend[++ToSendMax] = SEC_F;
	}

	// Convert from last byte pos to length
	ToSendMax++;
}

//-----------------------------------------------------------------------------
// Wait for commands from reader
// Stop when button is pressed
// Or return TRUE when command is captured
//-----------------------------------------------------------------------------
static int GetIso14443aCommandFromReader(uint8_t *received, int *len, int maxLen)
{
    // Set FPGA mode to "simulated ISO 14443 tag", no modulation (listen
    // only, since we are receiving, not transmitting).
    // Signal field is off with the appropriate LED
    LED_D_OFF();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_LISTEN);

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
			if(MillerDecoding((b & 0xf0) >> 4)) {
				*len = Uart.byteCnt;
				return TRUE;
			}
			if(MillerDecoding(b & 0x0f)) {
				*len = Uart.byteCnt;
				return TRUE;
			}
        }
    }
}

static int EmSendCmd14443aRaw(uint8_t *resp, int respLen, int correctionNeeded);
int EmSend4bitEx(uint8_t resp, int correctionNeeded);
int EmSend4bit(uint8_t resp);
int EmSendCmdExPar(uint8_t *resp, int respLen, int correctionNeeded, uint32_t par);
int EmSendCmdExPar(uint8_t *resp, int respLen, int correctionNeeded, uint32_t par);
int EmSendCmdEx(uint8_t *resp, int respLen, int correctionNeeded);
int EmSendCmd(uint8_t *resp, int respLen);
int EmSendCmdPar(uint8_t *resp, int respLen, uint32_t par);

static uint8_t* free_buffer_pointer = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET);

typedef struct {
  uint8_t* response;
  size_t   response_n;
  uint8_t* modulation;
  size_t   modulation_n;
} tag_response_info_t;

void reset_free_buffer() {
  free_buffer_pointer = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET);
}

bool prepare_tag_modulation(tag_response_info_t* response_info, size_t max_buffer_size) {
	// Exmaple response, answer to MIFARE Classic read block will be 16 bytes + 2 CRC = 18 bytes
	// This will need the following byte array for a modulation sequence
	//    144        data bits (18 * 8)
	//     18        parity bits
	//      2        Start and stop
	//      1        Correction bit (Answer in 1172 or 1236 periods, see FPGA)
	//      1        just for the case
	// ----------- +
	//    166 bytes, since every bit that needs to be send costs us a byte
	//
  
  // Prepare the tag modulation bits from the message
  CodeIso14443aAsTag(response_info->response,response_info->response_n);
  
  // Make sure we do not exceed the free buffer space
  if (ToSendMax > max_buffer_size) {
    Dbprintf("Out of memory, when modulating bits for tag answer:");
    Dbhexdump(response_info->response_n,response_info->response,false);
    return false;
  }
  
  // Copy the byte array, used for this modulation to the buffer position
  memcpy(response_info->modulation,ToSend,ToSendMax);
  
  // Store the number of bytes that were used for encoding/modulation
  response_info->modulation_n = ToSendMax;
  
  return true;
}

bool prepare_allocated_tag_modulation(tag_response_info_t* response_info) {
  // Retrieve and store the current buffer index
  response_info->modulation = free_buffer_pointer;
  
  // Determine the maximum size we can use from our buffer
  size_t max_buffer_size = (((uint8_t *)BigBuf)+FREE_BUFFER_OFFSET+FREE_BUFFER_SIZE)-free_buffer_pointer;
  
  // Forward the prepare tag modulation function to the inner function
  if (prepare_tag_modulation(response_info,max_buffer_size)) {
    // Update the free buffer offset
    free_buffer_pointer += ToSendMax;
    return true;
  } else {
    return false;
  }
}

//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
void SimulateIso14443aTag(int tagType, int uid_1st, int uid_2nd, byte_t* data)
{
	// Enable and clear the trace
	tracing = TRUE;
	iso14a_clear_trace();

	// This function contains the tag emulation
	uint8_t sak;

	// The first response contains the ATQA (note: bytes are transmitted in reverse order).
	uint8_t response1[2];
	
	switch (tagType) {
		case 1: { // MIFARE Classic
			// Says: I am Mifare 1k - original line
			response1[0] = 0x04;
			response1[1] = 0x00;
			sak = 0x08;
		} break;
		case 2: { // MIFARE Ultralight
			// Says: I am a stupid memory tag, no crypto
			response1[0] = 0x04;
			response1[1] = 0x00;
			sak = 0x00;
		} break;
		case 3: { // MIFARE DESFire
			// Says: I am a DESFire tag, ph33r me
			response1[0] = 0x04;
			response1[1] = 0x03;
			sak = 0x20;
		} break;
		case 4: { // ISO/IEC 14443-4
			// Says: I am a javacard (JCOP)
			response1[0] = 0x04;
			response1[1] = 0x00;
			sak = 0x28;
		} break;
		default: {
			Dbprintf("Error: unkown tagtype (%d)",tagType);
			return;
		} break;
	}
	
	// The second response contains the (mandatory) first 24 bits of the UID
	uint8_t response2[5];

	// Check if the uid uses the (optional) part
	uint8_t response2a[5];
	if (uid_2nd) {
		response2[0] = 0x88;
		num_to_bytes(uid_1st,3,response2+1);
		num_to_bytes(uid_2nd,4,response2a);
		response2a[4] = response2a[0] ^ response2a[1] ^ response2a[2] ^ response2a[3];

		// Configure the ATQA and SAK accordingly
		response1[0] |= 0x40;
		sak |= 0x04;
	} else {
		num_to_bytes(uid_1st,4,response2);
		// Configure the ATQA and SAK accordingly
		response1[0] &= 0xBF;
		sak &= 0xFB;
	}

	// Calculate the BitCountCheck (BCC) for the first 4 bytes of the UID.
	response2[4] = response2[0] ^ response2[1] ^ response2[2] ^ response2[3];

	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t response3[3];
	response3[0] = sak;
	ComputeCrc14443(CRC_14443_A, response3, 1, &response3[1], &response3[2]);

	// Prepare the optional second SAK (for 7 byte UID), drop the cascade bit
	uint8_t response3a[3];
	response3a[0] = sak & 0xFB;
	ComputeCrc14443(CRC_14443_A, response3a, 1, &response3a[1], &response3a[2]);

	uint8_t response5[] = { 0x00, 0x00, 0x00, 0x00 }; // Very random tag nonce
	uint8_t response6[] = { 0x04, 0x58, 0x00, 0x02, 0x00, 0x00 }; // dummy ATS (pseudo-ATR), answer to RATS
	ComputeCrc14443(CRC_14443_A, response6, 4, &response6[4], &response6[5]);

  #define TAG_RESPONSE_COUNT 7
  tag_response_info_t responses[TAG_RESPONSE_COUNT] = {
    { .response = response1,  .response_n = sizeof(response1)  },  // Answer to request - respond with card type
    { .response = response2,  .response_n = sizeof(response2)  },  // Anticollision cascade1 - respond with uid
    { .response = response2a, .response_n = sizeof(response2a) },  // Anticollision cascade2 - respond with 2nd half of uid if asked
    { .response = response3,  .response_n = sizeof(response3)  },  // Acknowledge select - cascade 1
    { .response = response3a, .response_n = sizeof(response3a) },  // Acknowledge select - cascade 2
    { .response = response5,  .response_n = sizeof(response5)  },  // Authentication answer (random nonce)
    { .response = response6,  .response_n = sizeof(response6)  },  // dummy ATS (pseudo-ATR), answer to RATS
  };

  // Allocate 512 bytes for the dynamic modulation, created when the reader querries for it
  // Such a response is less time critical, so we can prepare them on the fly
  #define DYNAMIC_RESPONSE_BUFFER_SIZE 64
  #define DYNAMIC_MODULATION_BUFFER_SIZE 512
  uint8_t dynamic_response_buffer[DYNAMIC_RESPONSE_BUFFER_SIZE];
  uint8_t dynamic_modulation_buffer[DYNAMIC_MODULATION_BUFFER_SIZE];
  tag_response_info_t dynamic_response_info = {
    .response = dynamic_response_buffer,
    .response_n = 0,
    .modulation = dynamic_modulation_buffer,
    .modulation_n = 0
  };
  
  // Reset the offset pointer of the free buffer
  reset_free_buffer();
  
  // Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
  for (size_t i=0; i<TAG_RESPONSE_COUNT; i++) {
    prepare_allocated_tag_modulation(&responses[i]);
  }

	uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
	int len;

	// To control where we are in the protocol
	int order = 0;
	int lastorder;

	// Just to allow some checks
	int happened = 0;
	int happened2 = 0;
	int cmdsRecvd = 0;

	// We need to listen to the high-frequency, peak-detected path.
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

	cmdsRecvd = 0;
  tag_response_info_t* p_response;

	LED_A_ON();
	for(;;) {
    // Clean receive command buffer
    memset(receivedCmd, 0x44, RECV_CMD_SIZE);
	
		if(!GetIso14443aCommandFromReader(receivedCmd, &len, RECV_CMD_SIZE)) {
			DbpString("Button press");
			break;
		}
    
		if (tracing) {
			LogTrace(receivedCmd,len, 0, Uart.parityBits, TRUE);
		}
    
    p_response = NULL;
    
		// doob - added loads of debug strings so we can see what the reader is saying to us during the sim as hi14alist is not populated
		// Okay, look at the command now.
		lastorder = order;
		if(receivedCmd[0] == 0x26) { // Received a REQUEST
			p_response = &responses[0]; order = 1;
		} else if(receivedCmd[0] == 0x52) { // Received a WAKEUP
			p_response = &responses[0]; order = 6;
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
			p_response = &responses[1]; order = 2;
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x95) { // Received request for UID (cascade 2)
			p_response = &responses[2]; order = 20;
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
			p_response = &responses[3]; order = 3;
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x95) {	// Received a SELECT (cascade 2)
			p_response = &responses[4]; order = 30;
		} else if(receivedCmd[0] == 0x30) {	// Received a (plain) READ
			EmSendCmdEx(data+(4*receivedCmd[0]),16,false);
			Dbprintf("Read request from reader: %x %x",receivedCmd[0],receivedCmd[1]);
			// We already responded, do not send anything with the EmSendCmd14443aRaw() that is called below
      p_response = NULL;
		} else if(receivedCmd[0] == 0x50) {	// Received a HALT
//			DbpString("Reader requested we HALT!:");
      p_response = NULL;
		} else if(receivedCmd[0] == 0x60 || receivedCmd[0] == 0x61) {	// Received an authentication request
			p_response = &responses[5]; order = 7;
		} else if(receivedCmd[0] == 0xE0) {	// Received a RATS request
			p_response = &responses[6]; order = 70;
		} else if (order == 7 && len ==8) { // Received authentication request
      uint32_t nr = bytes_to_num(receivedCmd,4);
      uint32_t ar = bytes_to_num(receivedCmd+4,4);
      Dbprintf("Auth attempt {nr}{ar}: %08x %08x",nr,ar);
    } else {
      // Check for ISO 14443A-4 compliant commands, look at left nibble
      switch (receivedCmd[0]) {

        case 0x0B:
        case 0x0A: { // IBlock (command)
          dynamic_response_info.response[0] = receivedCmd[0];
          dynamic_response_info.response[1] = 0x00;
          dynamic_response_info.response[2] = 0x90;
          dynamic_response_info.response[3] = 0x00;
          dynamic_response_info.response_n = 4;
        } break;

        case 0x1A:
        case 0x1B: { // Chaining command
          dynamic_response_info.response[0] = 0xaa | ((receivedCmd[0]) & 1);
          dynamic_response_info.response_n = 2;
        } break;

        case 0xaa:
        case 0xbb: {
          dynamic_response_info.response[0] = receivedCmd[0] ^ 0x11;
          dynamic_response_info.response_n = 2;
        } break;
          
        case 0xBA: { //
          memcpy(dynamic_response_info.response,"\xAB\x00",2);
          dynamic_response_info.response_n = 2;
        } break;

        case 0xCA:
        case 0xC2: { // Readers sends deselect command
          memcpy(dynamic_response_info.response,"\xCA\x00",2);
          dynamic_response_info.response_n = 2;
        } break;

        default: {
          // Never seen this command before
          Dbprintf("Received unknown command (len=%d):",len);
          Dbhexdump(len,receivedCmd,false);
          // Do not respond
          dynamic_response_info.response_n = 0;
        } break;
      }
      
      if (dynamic_response_info.response_n > 0) {
        // Copy the CID from the reader query
        dynamic_response_info.response[1] = receivedCmd[1];

        // Add CRC bytes, always used in ISO 14443A-4 compliant cards
        AppendCrc14443a(dynamic_response_info.response,dynamic_response_info.response_n);
        dynamic_response_info.response_n += 2;
        
        if (prepare_tag_modulation(&dynamic_response_info,DYNAMIC_MODULATION_BUFFER_SIZE) == false) {
          Dbprintf("Error preparing tag response");
          break;
        }
        p_response = &dynamic_response_info;
      }
		}

		// Count number of wakeups received after a halt
		if(order == 6 && lastorder == 5) { happened++; }

		// Count number of other messages after a halt
		if(order != 6 && lastorder == 5) { happened2++; }

		// Look at last parity bit to determine timing of answer
		if((Uart.parityBits & 0x01) || receivedCmd[0] == 0x52) {
			// 1236, so correction bit needed
			//i = 0;
		}

		if(cmdsRecvd > 999) {
			DbpString("1000 commands later...");
			break;
		}
		cmdsRecvd++;

		if (p_response != NULL) {
      EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, receivedCmd[0] == 0x52);
      if (tracing) {
        LogTrace(p_response->response,p_response->response_n,0,SwapBits(GetParity(p_response->response,p_response->response_n),p_response->response_n),FALSE);
        if(traceLen > TRACE_SIZE) {
          DbpString("Trace full");
//          break;
        }
      }
    }
  }

	Dbprintf("%x %x %x", happened, happened2, cmdsRecvd);
	LED_A_OFF();
}


// prepare a delayed transfer. This simply shifts ToSend[] by a number
// of bits specified in the delay parameter.
void PrepareDelayedTransfer(uint16_t delay)
{
	uint8_t bitmask = 0;
	uint8_t bits_to_shift = 0;
	uint8_t bits_shifted = 0;
	
	delay &= 0x07;
	if (delay) {
		for (uint16_t i = 0; i < delay; i++) {
			bitmask |= (0x01 << i);
		}
		ToSend[++ToSendMax] = 0x00;
		for (uint16_t i = 0; i < ToSendMax; i++) {
			bits_to_shift = ToSend[i] & bitmask;
			ToSend[i] = ToSend[i] >> delay;
			ToSend[i] = ToSend[i] | (bits_shifted << (8 - delay));
			bits_shifted = bits_to_shift;
		}
	}
}

//-----------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
// Parameter timing:
// if NULL: ignored
// if == 0:	return time of transfer
// if != 0: delay transfer until time specified
//-----------------------------------------------------------------------------
static void TransmitFor14443a(const uint8_t *cmd, int len, uint32_t *timing)
{
	int c;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);


	if (timing) {
		if(*timing == 0) {										// Measure time
			*timing = (GetCountMifare() + 8) & 0xfffffff8;
		} else {
			PrepareDelayedTransfer(*timing & 0x00000007);		// Delay transfer (fine tuning - up to 7 MF clock ticks)
		}
		if(MF_DBGLEVEL >= 4 && GetCountMifare() >= (*timing & 0xfffffff8)) Dbprintf("TransmitFor14443a: Missed timing");
		while(GetCountMifare() < (*timing & 0xfffffff8));		// Delay transfer (multiple of 8 MF clock ticks)
	}

	for(c = 0; c < 10;) {	// standard delay for each transfer (allow tag to be ready after last transmission?)
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0x00;	
			c++;
		}
	}
	
	c = 0;
	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = cmd[c];
			c++;
			if(c >= len) {
				break;
			}
		}
	}

}

//-----------------------------------------------------------------------------
// Prepare reader command (in bits, support short frames) to send to FPGA
//-----------------------------------------------------------------------------
void CodeIso14443aBitsAsReaderPar(const uint8_t * cmd, int bits, uint32_t dwParity)
{
  int i, j;
  int last;
  uint8_t b;

  ToSendReset();

  // Start of Communication (Seq. Z)
  ToSend[++ToSendMax] = SEC_Z;
  last = 0;

  size_t bytecount = nbytes(bits);
  // Generate send structure for the data bits
  for (i = 0; i < bytecount; i++) {
    // Get the current byte to send
    b = cmd[i];
    size_t bitsleft = MIN((bits-(i*8)),8);

    for (j = 0; j < bitsleft; j++) {
      if (b & 1) {
        // Sequence X
    	  ToSend[++ToSendMax] = SEC_X;
        last = 1;
      } else {
        if (last == 0) {
          // Sequence Z
        	ToSend[++ToSendMax] = SEC_Z;
        } else {
          // Sequence Y
        	ToSend[++ToSendMax] = SEC_Y;
          last = 0;
        }
      }
      b >>= 1;
    }

    // Only transmit (last) parity bit if we transmitted a complete byte
    if (j == 8) {
      // Get the parity bit
      if ((dwParity >> i) & 0x01) {
        // Sequence X
        ToSend[++ToSendMax] = SEC_X;
        last = 1;
      } else {
        if (last == 0) {
          // Sequence Z
          ToSend[++ToSendMax] = SEC_Z;
        } else {
          // Sequence Y
          ToSend[++ToSendMax] = SEC_Y;
          last = 0;
        }
      }
    }
  }

  // End of Communication
  if (last == 0) {
    // Sequence Z
	  ToSend[++ToSendMax] = SEC_Z;
  } else {
    // Sequence Y
	  ToSend[++ToSendMax] = SEC_Y;
    last = 0;
  }
  // Sequence Y
  ToSend[++ToSendMax] = SEC_Y;

  // Just to be sure!
  ToSend[++ToSendMax] = SEC_Y;
  ToSend[++ToSendMax] = SEC_Y;
  ToSend[++ToSendMax] = SEC_Y;

  // Convert from last character reference to length
  ToSendMax++;
}

//-----------------------------------------------------------------------------
// Prepare reader command to send to FPGA
//-----------------------------------------------------------------------------
void CodeIso14443aAsReaderPar(const uint8_t * cmd, int len, uint32_t dwParity)
{
  CodeIso14443aBitsAsReaderPar(cmd,len*8,dwParity);
}

//-----------------------------------------------------------------------------
// Wait for commands from reader
// Stop when button is pressed (return 1) or field was gone (return 2)
// Or return 0 when command is captured
//-----------------------------------------------------------------------------
static int EmGetCmd(uint8_t *received, int *len, int maxLen)
{
	*len = 0;

	uint32_t timer = 0, vtime = 0;
	int analogCnt = 0;
	int analogAVG = 0;

	// Set FPGA mode to "simulated ISO 14443 tag", no modulation (listen
	// only, since we are receiving, not transmitting).
	// Signal field is off with the appropriate LED
	LED_D_OFF();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_LISTEN);

	// Set ADC to read field strength
	AT91C_BASE_ADC->ADC_CR = AT91C_ADC_SWRST;
	AT91C_BASE_ADC->ADC_MR =
				ADC_MODE_PRESCALE(32) |
				ADC_MODE_STARTUP_TIME(16) |
				ADC_MODE_SAMPLE_HOLD_TIME(8);
	AT91C_BASE_ADC->ADC_CHER = ADC_CHANNEL(ADC_CHAN_HF);
	// start ADC
	AT91C_BASE_ADC->ADC_CR = AT91C_ADC_START;
	
	// Now run a 'software UART' on the stream of incoming samples.
	Uart.output = received;
	Uart.byteCntMax = maxLen;
	Uart.state = STATE_UNSYNCD;

	for(;;) {
		WDT_HIT();

		if (BUTTON_PRESS()) return 1;

		// test if the field exists
		if (AT91C_BASE_ADC->ADC_SR & ADC_END_OF_CONVERSION(ADC_CHAN_HF)) {
			analogCnt++;
			analogAVG += AT91C_BASE_ADC->ADC_CDR[ADC_CHAN_HF];
			AT91C_BASE_ADC->ADC_CR = AT91C_ADC_START;
			if (analogCnt >= 32) {
				if ((33000 * (analogAVG / analogCnt) >> 10) < MF_MINFIELDV) {
					vtime = GetTickCount();
					if (!timer) timer = vtime;
					// 50ms no field --> card to idle state
					if (vtime - timer > 50) return 2;
				} else
					if (timer) timer = 0;
				analogCnt = 0;
				analogAVG = 0;
			}
		}
		// transmit none
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0x00;
		}
		// receive and test the miller decoding
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			volatile uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			if(MillerDecoding((b & 0xf0) >> 4)) {
				*len = Uart.byteCnt;
				if (tracing) LogTrace(received, *len, GetDeltaCountUS(), Uart.parityBits, TRUE);
				return 0;
			}
			if(MillerDecoding(b & 0x0f)) {
				*len = Uart.byteCnt;
				if (tracing) LogTrace(received, *len, GetDeltaCountUS(), Uart.parityBits, TRUE);
				return 0;
			}
		}
	}
}

static int EmSendCmd14443aRaw(uint8_t *resp, int respLen, int correctionNeeded)
{
	int i, u = 0;
	uint8_t b = 0;

	// Modulate Manchester
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_MOD);
	AT91C_BASE_SSC->SSC_THR = 0x00;
	FpgaSetupSsc();
	
	// include correction bit
	i = 1;
	if((Uart.parityBits & 0x01) || correctionNeeded) {
		// 1236, so correction bit needed
		i = 0;
	}
	
	// send cycle
	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			volatile uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			(void)b;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			if(i > respLen) {
				b = 0xff; // was 0x00
				u++;
			} else {
				b = resp[i];
				i++;
			}
			AT91C_BASE_SSC->SSC_THR = b;

			if(u > 4) break;
		}
		if(BUTTON_PRESS()) {
			break;
		}
	}

	return 0;
}

int EmSend4bitEx(uint8_t resp, int correctionNeeded){
  Code4bitAnswerAsTag(resp);
	int res = EmSendCmd14443aRaw(ToSend, ToSendMax, correctionNeeded);
  if (tracing) LogTrace(&resp, 1, GetDeltaCountUS(), GetParity(&resp, 1), FALSE);
	return res;
}

int EmSend4bit(uint8_t resp){
	return EmSend4bitEx(resp, 0);
}

int EmSendCmdExPar(uint8_t *resp, int respLen, int correctionNeeded, uint32_t par){
  CodeIso14443aAsTagPar(resp, respLen, par);
	int res = EmSendCmd14443aRaw(ToSend, ToSendMax, correctionNeeded);
  if (tracing) LogTrace(resp, respLen, GetDeltaCountUS(), par, FALSE);
	return res;
}

int EmSendCmdEx(uint8_t *resp, int respLen, int correctionNeeded){
	return EmSendCmdExPar(resp, respLen, correctionNeeded, GetParity(resp, respLen));
}

int EmSendCmd(uint8_t *resp, int respLen){
	return EmSendCmdExPar(resp, respLen, 0, GetParity(resp, respLen));
}

int EmSendCmdPar(uint8_t *resp, int respLen, uint32_t par){
	return EmSendCmdExPar(resp, respLen, 0, par);
}

//-----------------------------------------------------------------------------
// Wait a certain time for tag response
//  If a response is captured return TRUE
//  If it takes too long return FALSE
//-----------------------------------------------------------------------------
static int GetIso14443aAnswerFromTag(uint8_t *receivedResponse, uint16_t offset, int maxLen, int *samples)
{
	int c;
	
	// Set FPGA mode to "reader listen mode", no modulation (listen
	// only, since we are receiving, not transmitting).
	// Signal field is on with the appropriate LED
	LED_D_ON();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_LISTEN);
	
	// Now get the answer from the card
	Demod.output = receivedResponse;
	Demod.len = 0;
	Demod.state = DEMOD_UNSYNCD;

	uint8_t b;

	c = 0;
	for(;;) {
		WDT_HIT();

		// if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			// AT91C_BASE_SSC->SSC_THR = 0x00;  // To make use of exact timing of next command from reader!!
			// if (elapsed) (*elapsed)++;
		// }
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			if(c < iso14a_timeout) { c++; } else { return FALSE; }
			b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			if(ManchesterDecoding(b, offset)) {
				*samples = Demod.samples;
				return TRUE;
			}
		}
	}
}

void ReaderTransmitBitsPar(uint8_t* frame, int bits, uint32_t par, uint32_t *timing)
{

  CodeIso14443aBitsAsReaderPar(frame,bits,par);
  
  // Send command to tag
  TransmitFor14443a(ToSend, ToSendMax, timing);
  if(trigger)
  	LED_A_ON();
  
  // Log reader command in trace buffer
  if (tracing) LogTrace(frame,nbytes(bits),0,par,TRUE);
}

void ReaderTransmitPar(uint8_t* frame, int len, uint32_t par, uint32_t *timing)
{
  ReaderTransmitBitsPar(frame,len*8,par, timing);
}

void ReaderTransmitBits(uint8_t* frame, int len, uint32_t *timing)
{
  // Generate parity and redirect
  ReaderTransmitBitsPar(frame,len,GetParity(frame,len/8), timing);
}

void ReaderTransmit(uint8_t* frame, int len, uint32_t *timing)
{
  // Generate parity and redirect
  ReaderTransmitBitsPar(frame,len*8,GetParity(frame,len), timing);
}

int ReaderReceiveOffset(uint8_t* receivedAnswer, uint16_t offset)
{
	int samples = 0;
	if (!GetIso14443aAnswerFromTag(receivedAnswer,offset,160,&samples)) return FALSE;
	if (tracing) LogTrace(receivedAnswer,Demod.len,samples,Demod.parityBits,FALSE);
	if(samples == 0) return FALSE;
	return Demod.len;
}

int ReaderReceive(uint8_t* receivedAnswer)
{
	return ReaderReceiveOffset(receivedAnswer, 0);
}

int ReaderReceivePar(uint8_t *receivedAnswer, uint32_t *parptr)
{
	int samples = 0;
	if (!GetIso14443aAnswerFromTag(receivedAnswer,0,160,&samples)) return FALSE;
	if (tracing) LogTrace(receivedAnswer,Demod.len,samples,Demod.parityBits,FALSE);
	*parptr = Demod.parityBits;
	if(samples == 0) return FALSE;
	return Demod.len;
}

/* performs iso14443a anticollision procedure
 * fills the uid pointer unless NULL
 * fills resp_data unless NULL */
int iso14443a_select_card(byte_t* uid_ptr, iso14a_card_select_t* p_hi14a_card, uint32_t* cuid_ptr) {
  uint8_t wupa[]       = { 0x52 };  // 0x26 - REQA  0x52 - WAKE-UP
  uint8_t sel_all[]    = { 0x93,0x20 };
  uint8_t sel_uid[]    = { 0x93,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  uint8_t rats[]       = { 0xE0,0x80,0x00,0x00 }; // FSD=256, FSDI=8, CID=0
  uint8_t* resp = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET);	// was 3560 - tied to other size changes
  byte_t uid_resp[4];
  size_t uid_resp_len;

  uint8_t sak = 0x04; // cascade uid
  int cascade_level = 0;
  int len;
	 
  // Broadcast for a card, WUPA (0x52) will force response from all cards in the field
    ReaderTransmitBitsPar(wupa,7,0, NULL);
  // Receive the ATQA
  if(!ReaderReceive(resp)) return 0;
  // Dbprintf("atqa: %02x %02x",resp[0],resp[1]);

  if(p_hi14a_card) {
    memcpy(p_hi14a_card->atqa, resp, 2);
    p_hi14a_card->uidlen = 0;
    memset(p_hi14a_card->uid,0,10);
  }

  // clear uid
  if (uid_ptr) {
    memset(uid_ptr,0,10);
  }

  // OK we will select at least at cascade 1, lets see if first byte of UID was 0x88 in
  // which case we need to make a cascade 2 request and select - this is a long UID
  // While the UID is not complete, the 3nd bit (from the right) is set in the SAK.
  for(; sak & 0x04; cascade_level++) {
    // SELECT_* (L1: 0x93, L2: 0x95, L3: 0x97)
    sel_uid[0] = sel_all[0] = 0x93 + cascade_level * 2;

    // SELECT_ALL
    ReaderTransmit(sel_all,sizeof(sel_all), NULL);
    if (!ReaderReceive(resp)) return 0;

	if (Demod.collisionPos) {			// we had a collision and need to construct the UID bit by bit
		memset(uid_resp, 0, 4);
		uint16_t uid_resp_bits = 0;
		uint16_t collision_answer_offset = 0;
		// anti-collision-loop:
		while (Demod.collisionPos) {
			Dbprintf("Multiple tags detected. Collision after Bit %d", Demod.collisionPos);
			for (uint16_t i = collision_answer_offset; i < Demod.collisionPos; i++, uid_resp_bits++) {	// add valid UID bits before collision point
				uint16_t UIDbit = (resp[i/8] >> (i % 8)) & 0x01;
				uid_resp[uid_resp_bits & 0xf8] |= UIDbit << (uid_resp_bits % 8);
			}
			uid_resp[uid_resp_bits/8] |= 1 << (uid_resp_bits % 8);					// next time select the card(s) with a 1 in the collision position
			uid_resp_bits++;
			// construct anticollosion command:
			sel_uid[1] = ((2 + uid_resp_bits/8) << 4) | (uid_resp_bits & 0x07);  	// length of data in bytes and bits
			for (uint16_t i = 0; i <= uid_resp_bits/8; i++) {
				sel_uid[2+i] = uid_resp[i];
			}
			collision_answer_offset = uid_resp_bits%8;
			ReaderTransmitBits(sel_uid, 16 + uid_resp_bits, NULL);
			if (!ReaderReceiveOffset(resp, collision_answer_offset)) return 0;
		}
		// finally, add the last bits and BCC of the UID
		for (uint16_t i = collision_answer_offset; i < (Demod.len-1)*8; i++, uid_resp_bits++) {
			uint16_t UIDbit = (resp[i/8] >> (i%8)) & 0x01;
			uid_resp[uid_resp_bits/8] |= UIDbit << (uid_resp_bits % 8);
		}

	} else {		// no collision, use the response to SELECT_ALL as current uid
		memcpy(uid_resp,resp,4);
	}
	uid_resp_len = 4;
    //    Dbprintf("uid: %02x %02x %02x %02x",uid_resp[0],uid_resp[1],uid_resp[2],uid_resp[3]);

    // calculate crypto UID. Always use last 4 Bytes.
    if(cuid_ptr) {
        *cuid_ptr = bytes_to_num(uid_resp, 4);
    }

    // Construct SELECT UID command
	sel_uid[1] = 0x70;													// transmitting a full UID (1 Byte cmd, 1 Byte NVB, 4 Byte UID, 1 Byte BCC, 2 Bytes CRC)
    memcpy(sel_uid+2,uid_resp,4);										// the UID
	sel_uid[6] = sel_uid[2] ^ sel_uid[3] ^ sel_uid[4] ^ sel_uid[5];  	// calculate and add BCC
    AppendCrc14443a(sel_uid,7);											// calculate and add CRC
    ReaderTransmit(sel_uid,sizeof(sel_uid), NULL);

    // Receive the SAK
    if (!ReaderReceive(resp)) return 0;
    sak = resp[0];

    // Test if more parts of the uid are comming
    if ((sak & 0x04) /* && uid_resp[0] == 0x88 */) {
      // Remove first byte, 0x88 is not an UID byte, it CT, see page 3 of:
      // http://www.nxp.com/documents/application_note/AN10927.pdf
      memcpy(uid_resp, uid_resp + 1, 3);
      uid_resp_len = 3;
    }

    if(uid_ptr) {
      memcpy(uid_ptr + (cascade_level*3), uid_resp, uid_resp_len);
    }

    if(p_hi14a_card) {
      memcpy(p_hi14a_card->uid + (cascade_level*3), uid_resp, uid_resp_len);
      p_hi14a_card->uidlen += uid_resp_len;
    }
  }

  if(p_hi14a_card) {
    p_hi14a_card->sak = sak;
    p_hi14a_card->ats_len = 0;
  }

  if( (sak & 0x20) == 0) {
    return 2; // non iso14443a compliant tag
  }

  // Request for answer to select
  AppendCrc14443a(rats, 2);
  ReaderTransmit(rats, sizeof(rats), NULL);

  if (!(len = ReaderReceive(resp))) return 0;

  if(p_hi14a_card) {
    memcpy(p_hi14a_card->ats, resp, sizeof(p_hi14a_card->ats));
    p_hi14a_card->ats_len = len;
  }

  // reset the PCB block number
  iso14_pcb_blocknum = 0;
  return 1;
}

void iso14443a_setup() {
	// Set up the synchronous serial port
	FpgaSetupSsc();
	// Start from off (no field generated)
	// Signal field is off with the appropriate LED
//	LED_D_OFF();
//	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	// SpinDelay(50);

	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Now give it time to spin up.
	// Signal field is on with the appropriate LED
	LED_D_ON();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);
	SpinDelay(7); // iso14443-3 specifies 5ms max.

	Demod.state = DEMOD_UNSYNCD;
	iso14a_timeout = 2048; //default
}

int iso14_apdu(uint8_t * cmd, size_t cmd_len, void * data) {
	uint8_t real_cmd[cmd_len+4];
	real_cmd[0] = 0x0a; //I-Block
	// put block number into the PCB
	real_cmd[0] |= iso14_pcb_blocknum;
	real_cmd[1] = 0x00; //CID: 0 //FIXME: allow multiple selected cards
	memcpy(real_cmd+2, cmd, cmd_len);
	AppendCrc14443a(real_cmd,cmd_len+2);
 
	ReaderTransmit(real_cmd, cmd_len+4, NULL);
	size_t len = ReaderReceive(data);
	uint8_t * data_bytes = (uint8_t *) data;
	if (!len)
		return 0; //DATA LINK ERROR
	// if we received an I- or R(ACK)-Block with a block number equal to the
	// current block number, toggle the current block number
	else if (len >= 4 // PCB+CID+CRC = 4 bytes
	         && ((data_bytes[0] & 0xC0) == 0 // I-Block
	             || (data_bytes[0] & 0xD0) == 0x80) // R-Block with ACK bit set to 0
	         && (data_bytes[0] & 0x01) == iso14_pcb_blocknum) // equal block numbers
	{
		iso14_pcb_blocknum ^= 1;
	}

	return len;
}

//-----------------------------------------------------------------------------
// Read an ISO 14443a tag. Send out commands and store answers.
//
//-----------------------------------------------------------------------------
void ReaderIso14443a(UsbCommand * c)
{
	iso14a_command_t param = c->arg[0];
	uint8_t * cmd = c->d.asBytes;
	size_t len = c->arg[1];
	size_t lenbits = c->arg[2];
	uint32_t arg0 = 0;
	byte_t buf[USB_CMD_DATA_SIZE];
  
	if(param & ISO14A_CONNECT) {
		iso14a_clear_trace();
	}

	iso14a_set_tracing(true);

	if(param & ISO14A_REQUEST_TRIGGER) {
		iso14a_set_trigger(1);
	}

	if(param & ISO14A_CONNECT) {
		iso14443a_setup();
		if(!(param & ISO14A_NO_SELECT)) {
			iso14a_card_select_t *card = (iso14a_card_select_t*)buf;
			arg0 = iso14443a_select_card(NULL,card,NULL);
			cmd_send(CMD_ACK,arg0,card->uidlen,0,buf,sizeof(iso14a_card_select_t));
		}
	}

	if(param & ISO14A_SET_TIMEOUT) {
		iso14a_timeout = c->arg[2];
	}

	if(param & ISO14A_SET_TIMEOUT) {
		iso14a_timeout = c->arg[2];
	}

	if(param & ISO14A_APDU) {
		arg0 = iso14_apdu(cmd, len, buf);
		cmd_send(CMD_ACK,arg0,0,0,buf,sizeof(buf));
	}

	if(param & ISO14A_RAW) {
		if(param & ISO14A_APPEND_CRC) {
			AppendCrc14443a(cmd,len);
			len += 2;
		}
		if(lenbits>0) {
			ReaderTransmitBitsPar(cmd,lenbits,GetParity(cmd,lenbits/8), NULL);
		} else {
			ReaderTransmit(cmd,len, NULL);
		}
		arg0 = ReaderReceive(buf);
		cmd_send(CMD_ACK,arg0,0,0,buf,sizeof(buf));
	}

	if(param & ISO14A_REQUEST_TRIGGER) {
		iso14a_set_trigger(0);
	}

	if(param & ISO14A_NO_DISCONNECT) {
		return;
	}

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
}


// Determine the distance between two nonces.
// Assume that the difference is small, but we don't know which is first.
// Therefore try in alternating directions.
int32_t dist_nt(uint32_t nt1, uint32_t nt2) {

	uint16_t i;
	uint32_t nttmp1, nttmp2;

	if (nt1 == nt2) return 0;

	nttmp1 = nt1;
	nttmp2 = nt2;
	
	for (i = 1; i < 32768; i++) {
		nttmp1 = prng_successor(nttmp1, 1);
		if (nttmp1 == nt2) return i;
		nttmp2 = prng_successor(nttmp2, 1);
			if (nttmp2 == nt1) return -i;
		}
	
	return(-99999); // either nt1 or nt2 are invalid nonces
}


//-----------------------------------------------------------------------------
// Recover several bits of the cypher stream. This implements (first stages of)
// the algorithm described in "The Dark Side of Security by Obscurity and
// Cloning MiFare Classic Rail and Building Passes, Anywhere, Anytime"
// (article by Nicolas T. Courtois, 2009)
//-----------------------------------------------------------------------------
void ReaderMifare(bool first_try)
{
	// Mifare AUTH
	uint8_t mf_auth[]    = { 0x60,0x00,0xf5,0x7b };
	uint8_t mf_nr_ar[]   = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	static uint8_t mf_nr_ar3;

	uint8_t* receivedAnswer = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET);
	traceLen = 0;
	tracing = false;

	byte_t nt_diff = 0;
	byte_t par = 0;
	//byte_t par_mask = 0xff;
	static byte_t par_low = 0;
	bool led_on = TRUE;
	uint8_t uid[10];
	uint32_t cuid;

	uint32_t nt, previous_nt;
	static uint32_t nt_attacked = 0;
	byte_t par_list[8] = {0,0,0,0,0,0,0,0};
	byte_t ks_list[8] = {0,0,0,0,0,0,0,0};

	static uint32_t sync_time;
	static uint32_t sync_cycles;
	int catch_up_cycles = 0;
	int last_catch_up = 0;
	uint16_t consecutive_resyncs = 0;
	int isOK = 0;



	if (first_try) { 
		StartCountMifare();
		mf_nr_ar3 = 0;
		iso14443a_setup();
		while((GetCountMifare() & 0xffff0000) != 0x10000);		// wait for counter to reset and "warm up" 
		sync_time = GetCountMifare() & 0xfffffff8;
		sync_cycles = 65536;									// theory: Mifare Classic's random generator repeats every 2^16 cycles (and so do the nonces).
		nt_attacked = 0;
		nt = 0;
		par = 0;
	}
	else {
		// we were unsuccessful on a previous call. Try another READER nonce (first 3 parity bits remain the same)
		// nt_attacked = prng_successor(nt_attacked, 1);
		mf_nr_ar3++;
		mf_nr_ar[3] = mf_nr_ar3;
		par = par_low;
	}

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();
	
  
	for(uint16_t i = 0; TRUE; i++) {
		
		WDT_HIT();

		// Test if the action was cancelled
		if(BUTTON_PRESS()) {
			break;
		}
		
		LED_C_ON();

		if(!iso14443a_select_card(uid, NULL, &cuid)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Mifare: Can't select card");
			continue;
		}

		//keep the card active
		FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);

		sync_time = (sync_time & 0xfffffff8) + sync_cycles + catch_up_cycles;
		catch_up_cycles = 0;

		// if we missed the sync time already, advance to the next nonce repeat
		while(GetCountMifare() > sync_time) {
			sync_time = (sync_time & 0xfffffff8) + sync_cycles;
		}

		// Transmit MIFARE_CLASSIC_AUTH at synctime. Should result in returning the same tag nonce (== nt_attacked) 
		ReaderTransmit(mf_auth, sizeof(mf_auth), &sync_time);

		// Receive the (4 Byte) "random" nonce
		if (!ReaderReceive(receivedAnswer)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Mifare: Couldn't receive tag nonce");
			continue;
		  }

		previous_nt = nt;
		nt = bytes_to_num(receivedAnswer, 4);

		// Transmit reader nonce with fake par
		ReaderTransmitPar(mf_nr_ar, sizeof(mf_nr_ar), par, NULL);

		if (first_try && previous_nt && !nt_attacked) { // we didn't calibrate our clock yet
			int nt_distance = dist_nt(previous_nt, nt);
			if (nt_distance == 0) {
				nt_attacked = nt;
			}
			else {
				if (nt_distance == -99999) { // invalid nonce received, try again
					continue;
				}
				sync_cycles = (sync_cycles - nt_distance);
				if (MF_DBGLEVEL >= 3) Dbprintf("calibrating in cycle %d. nt_distance=%d, Sync_cycles: %d\n", i, nt_distance, sync_cycles);
				continue;
			}
		}

		if ((nt != nt_attacked) && nt_attacked) { 	// we somehow lost sync. Try to catch up again...
			catch_up_cycles = -dist_nt(nt_attacked, nt);
			if (catch_up_cycles == 99999) {			// invalid nonce received. Don't resync on that one.
				catch_up_cycles = 0;
				continue;
			}
			if (catch_up_cycles == last_catch_up) {
				consecutive_resyncs++;
			}
			else {
				last_catch_up = catch_up_cycles;
			    consecutive_resyncs = 0;
			}
			if (consecutive_resyncs < 3) {
				if (MF_DBGLEVEL >= 3) Dbprintf("Lost sync in cycle %d. nt_distance=%d. Consecutive Resyncs = %d. Trying one time catch up...\n", i, -catch_up_cycles, consecutive_resyncs);
			}
			else {	
				sync_cycles = sync_cycles + catch_up_cycles;
				if (MF_DBGLEVEL >= 3) Dbprintf("Lost sync in cycle %d for the fourth time consecutively (nt_distance = %d). Adjusting sync_cycles to %d.\n", i, -catch_up_cycles, sync_cycles);
			}
			continue;
		}
 
		consecutive_resyncs = 0;
		
		// Receive answer. This will be a 4 Bit NACK when the 8 parity bits are OK after decoding
		if (ReaderReceive(receivedAnswer))
		{
			catch_up_cycles = 8; 	// the PRNG is delayed by 8 cycles due to the NAC (4Bits = 0x05 encrypted) transfer
	
			if (nt_diff == 0)
			{
				par_low = par & 0x07; // there is no need to check all parities for other nt_diff. Parity Bits for mf_nr_ar[0..2] won't change
			}

			led_on = !led_on;
			if(led_on) LED_B_ON(); else LED_B_OFF();

			par_list[nt_diff] = par;
			ks_list[nt_diff] = receivedAnswer[0] ^ 0x05;

			// Test if the information is complete
			if (nt_diff == 0x07) {
				isOK = 1;
				break;
			}

			nt_diff = (nt_diff + 1) & 0x07;
			mf_nr_ar[3] = (mf_nr_ar[3] & 0x1F) | (nt_diff << 5);
			par = par_low;
		} else {
			if (nt_diff == 0 && first_try)
			{
				par++;
			} else {
				par = (((par >> 3) + 1) << 3) | par_low;
			}
		}
	}

	LogTrace((const uint8_t *)&nt, 4, 0, GetParity((const uint8_t *)&nt, 4), TRUE);
	LogTrace(par_list, 8, 0, GetParity(par_list, 8), TRUE);
	LogTrace(ks_list, 8, 0, GetParity(ks_list, 8), TRUE);

	mf_nr_ar[3] &= 0x1F;
	
	byte_t buf[28];
	memcpy(buf + 0,  uid, 4);
	num_to_bytes(nt, 4, buf + 4);
	memcpy(buf + 8,  par_list, 8);
	memcpy(buf + 16, ks_list, 8);
	memcpy(buf + 24, mf_nr_ar, 4);
		
	cmd_send(CMD_ACK,isOK,0,0,buf,28);

	// Thats it...
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	tracing = TRUE;
}

//-----------------------------------------------------------------------------
// MIFARE 1K simulate. 
// 
//-----------------------------------------------------------------------------
void Mifare1ksim(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain)
{
	int cardSTATE = MFEMUL_NOFIELD;
	int _7BUID = 0;
	int vHf = 0;	// in mV
	//int nextCycleTimeout = 0;
	int res;
//	uint32_t timer = 0;
	uint32_t selTimer = 0;
	uint32_t authTimer = 0;
	uint32_t par = 0;
	int len = 0;
	uint8_t cardWRBL = 0;
	uint8_t cardAUTHSC = 0;
	uint8_t cardAUTHKEY = 0xff;  // no authentication
	//uint32_t cardRn = 0;
	uint32_t cardRr = 0;
	uint32_t cuid = 0;
	uint32_t rn_enc = 0;
	uint32_t ans = 0;
	uint32_t cardINTREG = 0;
	uint8_t cardINTBLOCK = 0;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;
	
	uint8_t* receivedCmd = eml_get_bigbufptr_recbuf();
	uint8_t *response = eml_get_bigbufptr_sendbuf();
	
	static uint8_t rATQA[] = {0x04, 0x00}; // Mifare classic 1k 4BUID

	static uint8_t rUIDBCC1[] = {0xde, 0xad, 0xbe, 0xaf, 0x62}; 
	static uint8_t rUIDBCC2[] = {0xde, 0xad, 0xbe, 0xaf, 0x62}; // !!!
		
	static uint8_t rSAK[] = {0x08, 0xb6, 0xdd};
	static uint8_t rSAK1[] = {0x04, 0xda, 0x17};

	static uint8_t rAUTH_NT[] = {0x01, 0x02, 0x03, 0x04};
//	static uint8_t rAUTH_NT[] = {0x1a, 0xac, 0xff, 0x4f};
	static uint8_t rAUTH_AT[] = {0x00, 0x00, 0x00, 0x00};

	// clear trace
	traceLen = 0;
	tracing = true;

  // Authenticate response - nonce
	uint32_t nonce = bytes_to_num(rAUTH_NT, 4);
	
	// get UID from emul memory
	emlGetMemBt(receivedCmd, 7, 1);
	_7BUID = !(receivedCmd[0] == 0x00);
	if (!_7BUID) {                     // ---------- 4BUID
		rATQA[0] = 0x04;

		emlGetMemBt(rUIDBCC1, 0, 4);
		rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
	} else {                           // ---------- 7BUID
		rATQA[0] = 0x44;

		rUIDBCC1[0] = 0x88;
		emlGetMemBt(&rUIDBCC1[1], 0, 3);
		rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
		emlGetMemBt(rUIDBCC2, 3, 4);
		rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
	}

// --------------------------------------	test area

// --------------------------------------	END test area
	// start mkseconds counter
	StartCountUS();

	// We need to listen to the high-frequency, peak-detected path.
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

  FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_LISTEN);
	SpinDelay(200);

	if (MF_DBGLEVEL >= 1)	Dbprintf("Started. 7buid=%d", _7BUID);
	// calibrate mkseconds counter
	GetDeltaCountUS();
	while (true) {
		WDT_HIT();

		if(BUTTON_PRESS()) {
			break;
		}

		// find reader field
		// Vref = 3300mV, and an 10:1 voltage divider on the input
		// can measure voltages up to 33000 mV
		if (cardSTATE == MFEMUL_NOFIELD) {
			vHf = (33000 * AvgAdc(ADC_CHAN_HF)) >> 10;
			if (vHf > MF_MINFIELDV) {
				cardSTATE_TO_IDLE();
				LED_A_ON();
			}
		} 

		if (cardSTATE != MFEMUL_NOFIELD) {
			res = EmGetCmd(receivedCmd, &len, RECV_CMD_SIZE); // (+ nextCycleTimeout)
			if (res == 2) {
				cardSTATE = MFEMUL_NOFIELD;
				LEDsoff();
				continue;
			}
			if(res) break;
		}
		
		//nextCycleTimeout = 0;
		
//		if (len) Dbprintf("len:%d cmd: %02x %02x %02x %02x", len, receivedCmd[0], receivedCmd[1], receivedCmd[2], receivedCmd[3]);

		if (len != 4 && cardSTATE != MFEMUL_NOFIELD) { // len != 4 <---- speed up the code 4 authentication
			// REQ or WUP request in ANY state and WUP in HALTED state
			if (len == 1 && ((receivedCmd[0] == 0x26 && cardSTATE != MFEMUL_HALTED) || receivedCmd[0] == 0x52)) {
				selTimer = GetTickCount();
				EmSendCmdEx(rATQA, sizeof(rATQA), (receivedCmd[0] == 0x52));
				cardSTATE = MFEMUL_SELECT1;

				// init crypto block
				LED_B_OFF();
				LED_C_OFF();
				crypto1_destroy(pcs);
				cardAUTHKEY = 0xff;
			}
		}
		
		switch (cardSTATE) {
			case MFEMUL_NOFIELD:{
				break;
			}
			case MFEMUL_HALTED:{
				break;
			}
			case MFEMUL_IDLE:{
				break;
			}
			case MFEMUL_SELECT1:{
				// select all
				if (len == 2 && (receivedCmd[0] == 0x93 && receivedCmd[1] == 0x20)) {
					EmSendCmd(rUIDBCC1, sizeof(rUIDBCC1));
					break;
				}

				// select card
				if (len == 9 && 
						(receivedCmd[0] == 0x93 && receivedCmd[1] == 0x70 && memcmp(&receivedCmd[2], rUIDBCC1, 4) == 0)) {
					if (!_7BUID) 
						EmSendCmd(rSAK, sizeof(rSAK));
					else
						EmSendCmd(rSAK1, sizeof(rSAK1));

					cuid = bytes_to_num(rUIDBCC1, 4);
					if (!_7BUID) {
						cardSTATE = MFEMUL_WORK;
						LED_B_ON();
						if (MF_DBGLEVEL >= 4)	Dbprintf("--> WORK. anticol1 time: %d", GetTickCount() - selTimer);
						break;
					} else {
						cardSTATE = MFEMUL_SELECT2;
						break;
					}
				}
				
				break;
			}
			case MFEMUL_SELECT2:{
				if (!len) break;
			
				if (len == 2 && (receivedCmd[0] == 0x95 && receivedCmd[1] == 0x20)) {
					EmSendCmd(rUIDBCC2, sizeof(rUIDBCC2));
					break;
				}

				// select 2 card
				if (len == 9 && 
						(receivedCmd[0] == 0x95 && receivedCmd[1] == 0x70 && memcmp(&receivedCmd[2], rUIDBCC2, 4) == 0)) {
					EmSendCmd(rSAK, sizeof(rSAK));

					cuid = bytes_to_num(rUIDBCC2, 4);
					cardSTATE = MFEMUL_WORK;
					LED_B_ON();
					if (MF_DBGLEVEL >= 4)	Dbprintf("--> WORK. anticol2 time: %d", GetTickCount() - selTimer);
					break;
				}
				
				// i guess there is a command). go into the work state.
				if (len != 4) break;
				cardSTATE = MFEMUL_WORK;
				goto lbWORK;
			}
			case MFEMUL_AUTH1:{
				if (len == 8) {
					// --- crypto
					rn_enc = bytes_to_num(receivedCmd, 4);
					crypto1_word(pcs, rn_enc , 1);
					cardRr = bytes_to_num(&receivedCmd[4], 4) ^ crypto1_word(pcs, 0, 0);
					// test if auth OK
					if (cardRr != prng_successor(nonce, 64)){
						if (MF_DBGLEVEL >= 4)	Dbprintf("AUTH FAILED. cardRr=%08x, succ=%08x", cardRr, prng_successor(nonce, 64));
						cardSTATE_TO_IDLE();
						break;
					}
					ans = prng_successor(nonce, 96) ^ crypto1_word(pcs, 0, 0);
					num_to_bytes(ans, 4, rAUTH_AT);
					// --- crypto
					EmSendCmd(rAUTH_AT, sizeof(rAUTH_AT));
					cardSTATE = MFEMUL_AUTH2;
				} else {
					cardSTATE_TO_IDLE();
				}
				if (cardSTATE != MFEMUL_AUTH2) break;
			}
			case MFEMUL_AUTH2:{
				LED_C_ON();
				cardSTATE = MFEMUL_WORK;
				if (MF_DBGLEVEL >= 4)	Dbprintf("AUTH COMPLETED. sec=%d, key=%d time=%d", cardAUTHSC, cardAUTHKEY, GetTickCount() - authTimer);
				break;
			}
			case MFEMUL_WORK:{
lbWORK:	if (len == 0) break;
				
				if (cardAUTHKEY == 0xff) {
					// first authentication
					if (len == 4 && (receivedCmd[0] == 0x60 || receivedCmd[0] == 0x61)) {
						authTimer = GetTickCount();

						cardAUTHSC = receivedCmd[1] / 4;  // received block num
						cardAUTHKEY = receivedCmd[0] - 0x60;

						// --- crypto
						crypto1_create(pcs, emlGetKey(cardAUTHSC, cardAUTHKEY));
						ans = nonce ^ crypto1_word(pcs, cuid ^ nonce, 0); 
						num_to_bytes(nonce, 4, rAUTH_AT);
						EmSendCmd(rAUTH_AT, sizeof(rAUTH_AT));
						// --- crypto
						
//   last working revision 
//						EmSendCmd14443aRaw(resp1, resp1Len, 0);
//						LogTrace(NULL, 0, GetDeltaCountUS(), 0, true);

						cardSTATE = MFEMUL_AUTH1;
						//nextCycleTimeout = 10;
						break;
					}
				} else {
					// decrypt seqence
					mf_crypto1_decrypt(pcs, receivedCmd, len);
					
					// nested authentication
					if (len == 4 && (receivedCmd[0] == 0x60 || receivedCmd[0] == 0x61)) {
						authTimer = GetTickCount();

						cardAUTHSC = receivedCmd[1] / 4;  // received block num
						cardAUTHKEY = receivedCmd[0] - 0x60;

						// --- crypto
						crypto1_create(pcs, emlGetKey(cardAUTHSC, cardAUTHKEY));
						ans = nonce ^ crypto1_word(pcs, cuid ^ nonce, 0); 
						num_to_bytes(ans, 4, rAUTH_AT);
						EmSendCmd(rAUTH_AT, sizeof(rAUTH_AT));
						// --- crypto

						cardSTATE = MFEMUL_AUTH1;
						//nextCycleTimeout = 10;
						break;
					}
				}
				
				// rule 13 of 7.5.3. in ISO 14443-4. chaining shall be continued
				// BUT... ACK --> NACK
				if (len == 1 && receivedCmd[0] == CARD_ACK) {
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
					break;
				}
				
				// rule 12 of 7.5.3. in ISO 14443-4. R(NAK) --> R(ACK)
				if (len == 1 && receivedCmd[0] == CARD_NACK_NA) {
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
					break;
				}
				
				// read block
				if (len == 4 && receivedCmd[0] == 0x30) {
					if (receivedCmd[1] >= 16 * 4 || receivedCmd[1] / 4 != cardAUTHSC) {
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
						break;
					}
					emlGetMem(response, receivedCmd[1], 1);
					AppendCrc14443a(response, 16);
					mf_crypto1_encrypt(pcs, response, 18, &par);
					EmSendCmdPar(response, 18, par);
					break;
				}
				
				// write block
				if (len == 4 && receivedCmd[0] == 0xA0) {
					if (receivedCmd[1] >= 16 * 4 || receivedCmd[1] / 4 != cardAUTHSC) {
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
						break;
					}
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
					//nextCycleTimeout = 50;
					cardSTATE = MFEMUL_WRITEBL2;
					cardWRBL = receivedCmd[1];
					break;
				}
			
				// works with cardINTREG
				
				// increment, decrement, restore
				if (len == 4 && (receivedCmd[0] == 0xC0 || receivedCmd[0] == 0xC1 || receivedCmd[0] == 0xC2)) {
					if (receivedCmd[1] >= 16 * 4 || 
							receivedCmd[1] / 4 != cardAUTHSC || 
							emlCheckValBl(receivedCmd[1])) {
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
						break;
					}
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
					if (receivedCmd[0] == 0xC1)
						cardSTATE = MFEMUL_INTREG_INC;
					if (receivedCmd[0] == 0xC0)
						cardSTATE = MFEMUL_INTREG_DEC;
					if (receivedCmd[0] == 0xC2)
						cardSTATE = MFEMUL_INTREG_REST;
					cardWRBL = receivedCmd[1];
					
					break;
				}
				

				// transfer
				if (len == 4 && receivedCmd[0] == 0xB0) {
					if (receivedCmd[1] >= 16 * 4 || receivedCmd[1] / 4 != cardAUTHSC) {
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
						break;
					}
					
					if (emlSetValBl(cardINTREG, cardINTBLOCK, receivedCmd[1]))
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
					else
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
						
					break;
				}

				// halt
				if (len == 4 && (receivedCmd[0] == 0x50 && receivedCmd[1] == 0x00)) {
					LED_B_OFF();
					LED_C_OFF();
					cardSTATE = MFEMUL_HALTED;
					if (MF_DBGLEVEL >= 4)	Dbprintf("--> HALTED. Selected time: %d ms",  GetTickCount() - selTimer);
					break;
				}
				
				// command not allowed
				if (len == 4) {
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
					break;
				}

				// case break
				break;
			}
			case MFEMUL_WRITEBL2:{
				if (len == 18){
					mf_crypto1_decrypt(pcs, receivedCmd, len);
					emlSetMem(receivedCmd, cardWRBL, 1);
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
					cardSTATE = MFEMUL_WORK;
					break;
				} else {
					cardSTATE_TO_IDLE();
					break;
				}
				break;
			}
			
			case MFEMUL_INTREG_INC:{
				mf_crypto1_decrypt(pcs, receivedCmd, len);
				memcpy(&ans, receivedCmd, 4);
				if (emlGetValBl(&cardINTREG, &cardINTBLOCK, cardWRBL)) {
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
					cardSTATE_TO_IDLE();
					break;
				}
				cardINTREG = cardINTREG + ans;
				cardSTATE = MFEMUL_WORK;
				break;
			}
			case MFEMUL_INTREG_DEC:{
				mf_crypto1_decrypt(pcs, receivedCmd, len);
				memcpy(&ans, receivedCmd, 4);
				if (emlGetValBl(&cardINTREG, &cardINTBLOCK, cardWRBL)) {
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
					cardSTATE_TO_IDLE();
					break;
				}
				cardINTREG = cardINTREG - ans;
				cardSTATE = MFEMUL_WORK;
				break;
			}
			case MFEMUL_INTREG_REST:{
				mf_crypto1_decrypt(pcs, receivedCmd, len);
				memcpy(&ans, receivedCmd, 4);
				if (emlGetValBl(&cardINTREG, &cardINTBLOCK, cardWRBL)) {
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
					cardSTATE_TO_IDLE();
					break;
				}
				cardSTATE = MFEMUL_WORK;
				break;
			}
		}
	}

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();

	// add trace trailer
	memset(rAUTH_NT, 0x44, 4);
	LogTrace(rAUTH_NT, 4, 0, 0, TRUE);

	if (MF_DBGLEVEL >= 1)	Dbprintf("Emulator stopped. Tracing: %d  trace length: %d ",	tracing, traceLen);
}

//-----------------------------------------------------------------------------
// MIFARE sniffer. 
// 
//-----------------------------------------------------------------------------
void RAMFUNC SniffMifare(uint8_t param) {
	// param:
	// bit 0 - trigger from first card answer
	// bit 1 - trigger from first reader 7-bit request

	// C(red) A(yellow) B(green)
	LEDsoff();
	// init trace buffer
    iso14a_clear_trace();

	// The command (reader -> tag) that we're receiving.
	// The length of a received command will in most cases be no more than 18 bytes.
	// So 32 should be enough!
	uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
	// The response (tag -> reader) that we're receiving.
	uint8_t *receivedResponse = (((uint8_t *)BigBuf) + RECV_RES_OFFSET);

	// As we receive stuff, we copy it from receivedCmd or receivedResponse
	// into trace, along with its length and other annotations.
	//uint8_t *trace = (uint8_t *)BigBuf;
	
	// The DMA buffer, used to stream samples from the FPGA
	int8_t *dmaBuf = ((int8_t *)BigBuf) + DMA_BUFFER_OFFSET;
	int8_t *data = dmaBuf;
	int maxDataLen = 0;
	int dataLen = 0;

	// Set up the demodulator for tag -> reader responses.
	Demod.output = receivedResponse;
	Demod.len = 0;
	Demod.state = DEMOD_UNSYNCD;

	// Set up the demodulator for the reader -> tag commands
	memset(&Uart, 0, sizeof(Uart));
	Uart.output = receivedCmd;
	Uart.byteCntMax = 32; // was 100 (greg)//////////////////
	Uart.state = STATE_UNSYNCD;

	// Setup for the DMA.
	FpgaSetupSsc();
	FpgaSetupSscDma((uint8_t *)dmaBuf, DMA_BUFFER_SIZE);

	// And put the FPGA in the appropriate mode
	// Signal field is off with the appropriate LED
	LED_D_OFF();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_SNIFFER);
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	
	// init sniffer
	MfSniffInit();
	int sniffCounter = 0;

	// And now we loop, receiving samples.
	while(true) {
		if(BUTTON_PRESS()) {
			DbpString("cancelled by button");
			goto done;
		}

		LED_A_ON();
		WDT_HIT();
		
		if (++sniffCounter > 65) {
			if (MfSniffSend(2000)) {
				FpgaEnableSscDma();
			}
			sniffCounter = 0;
		}

		int register readBufDataP = data - dmaBuf;
		int register dmaBufDataP = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR;
		if (readBufDataP <= dmaBufDataP){
			dataLen = dmaBufDataP - readBufDataP;
		} else {
			dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP + 1;
		}
		// test for length of buffer
		if(dataLen > maxDataLen) {
			maxDataLen = dataLen;
			if(dataLen > 400) {
				Dbprintf("blew circular buffer! dataLen=0x%x", dataLen);
				goto done;
			}
		}
		if(dataLen < 1) continue;

		// primary buffer was stopped( <-- we lost data!
		if (!AT91C_BASE_PDC_SSC->PDC_RCR) {
			AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
			Dbprintf("RxEmpty ERROR!!! data length:%d", dataLen); // temporary
		}
		// secondary buffer sets as primary, secondary buffer was stopped
		if (!AT91C_BASE_PDC_SSC->PDC_RNCR) {
			AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
		}

		LED_A_OFF();
		
		if(MillerDecoding((data[0] & 0xF0) >> 4)) {
			LED_C_INV();
			// check - if there is a short 7bit request from reader
			if (MfSniffLogic(receivedCmd, Uart.byteCnt, Uart.parityBits, Uart.bitCnt, TRUE)) break;

			/* And ready to receive another command. */
			Uart.state = STATE_UNSYNCD;
			
			/* And also reset the demod code */
			Demod.state = DEMOD_UNSYNCD;
		}

		if(ManchesterDecoding(data[0], 0)) {
			LED_C_INV();

			if (MfSniffLogic(receivedResponse, Demod.len, Demod.parityBits, Demod.bitCount, FALSE)) break;

			// And ready to receive another response.
			memset(&Demod, 0, sizeof(Demod));
			Demod.output = receivedResponse;
			Demod.state = DEMOD_UNSYNCD;

			/* And also reset the uart code */
			Uart.state = STATE_UNSYNCD;
		}

		data++;
		if(data > dmaBuf + DMA_BUFFER_SIZE) {
			data = dmaBuf;
		}
	} // main cycle

	DbpString("COMMAND FINISHED");

done:
	FpgaDisableSscDma();
	MfSniffEnd();
	
	Dbprintf("maxDataLen=%x, Uart.state=%x, Uart.byteCnt=%x Uart.byteCntMax=%x", maxDataLen, Uart.state, Uart.byteCnt, Uart.byteCntMax);
	LEDsoff();
}
