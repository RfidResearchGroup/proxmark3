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


void iso14a_set_trigger(int enable) {
	trigger = enable;
}

void iso14a_clear_trace(void) {
    memset(trace, 0x44, TRACE_SIZE);
	traceLen = 0;
}

void iso14a_set_tracing(int enable) {
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

  // Generate the encrypted data
  for (i = 0; i < iLen; i++) {
    // Save the encrypted parity bit
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
// ISO 14443 Type A - Manchester
//=============================================================================
static tDemod Demod;

static RAMFUNC int ManchesterDecoding(int v)
{
	int bit;
	int modulation;
	//int error = 0;

	if(!Demod.buff) {
		Demod.buff = 1;
		Demod.buffer = v;
		return FALSE;
	}
	else {
		bit = Demod.buffer;
		Demod.buffer = v;
	}

	if(Demod.state==DEMOD_UNSYNCD) {
		Demod.output[Demod.len] = 0xfa;
		Demod.syncBit = 0;
		//Demod.samples = 0;
		Demod.posCount = 1;		// This is the first half bit period, so after syncing handle the second part

		if(bit & 0x08) {
			Demod.syncBit = 0x08;
		}

		if(bit & 0x04) {
			if(Demod.syncBit) {
				bit <<= 4;
			}
			Demod.syncBit = 0x04;
		}

		if(bit & 0x02) {
			if(Demod.syncBit) {
				bit <<= 2;
			}
			Demod.syncBit = 0x02;
		}

		if(bit & 0x01 && Demod.syncBit) {
			Demod.syncBit = 0x01;
		}
		
		if(Demod.syncBit) {
			Demod.len = 0;
			Demod.state = DEMOD_START_OF_COMMUNICATION;
			Demod.sub = SUB_FIRST_HALF;
			Demod.bitCount = 0;
			Demod.shiftReg = 0;
			Demod.parityBits = 0;
			Demod.samples = 0;
			if(Demod.posCount) {
				if(trigger) LED_A_OFF();
				switch(Demod.syncBit) {
					case 0x08: Demod.samples = 3; break;
					case 0x04: Demod.samples = 2; break;
					case 0x02: Demod.samples = 1; break;
					case 0x01: Demod.samples = 0; break;
				}
			}
			//error = 0;
		}
	}
	else {
		//modulation = bit & Demod.syncBit;
		modulation = ((bit << 1) ^ ((Demod.buffer & 0x08) >> 3)) & Demod.syncBit;

		Demod.samples += 4;

		if(Demod.posCount==0) {
			Demod.posCount = 1;
			if(modulation) {
				Demod.sub = SUB_FIRST_HALF;
			}
			else {
				Demod.sub = SUB_NONE;
			}
		}
		else {
			Demod.posCount = 0;
			if(modulation && (Demod.sub == SUB_FIRST_HALF)) {
				if(Demod.state!=DEMOD_ERROR_WAIT) {
					Demod.state = DEMOD_ERROR_WAIT;
					Demod.output[Demod.len] = 0xaa;
					//error = 0x01;
				}
			}
			else if(modulation) {
				Demod.sub = SUB_SECOND_HALF;
			}

			switch(Demod.state) {
				case DEMOD_START_OF_COMMUNICATION:
					if(Demod.sub == SUB_FIRST_HALF) {
						Demod.state = DEMOD_MANCHESTER_D;
					}
					else {
						Demod.output[Demod.len] = 0xab;
						Demod.state = DEMOD_ERROR_WAIT;
						//error = 0x02;
					}
					break;

				case DEMOD_MANCHESTER_D:
				case DEMOD_MANCHESTER_E:
					if(Demod.sub == SUB_FIRST_HALF) {
						Demod.bitCount++;
						Demod.shiftReg = (Demod.shiftReg >> 1) ^ 0x100;
						Demod.state = DEMOD_MANCHESTER_D;
					}
					else if(Demod.sub == SUB_SECOND_HALF) {
						Demod.bitCount++;
						Demod.shiftReg >>= 1;
						Demod.state = DEMOD_MANCHESTER_E;
					}
					else {
						Demod.state = DEMOD_MANCHESTER_F;
					}
					break;

				case DEMOD_MANCHESTER_F:
					// Tag response does not need to be a complete byte!
					if(Demod.len > 0 || Demod.bitCount > 0) {
						if(Demod.bitCount > 0) {
							Demod.shiftReg >>= (9 - Demod.bitCount);
							Demod.output[Demod.len] = Demod.shiftReg & 0xff;
							Demod.len++;
							// No parity bit, so just shift a 0
							Demod.parityBits <<= 1;
						}

						Demod.state = DEMOD_UNSYNCD;
						return TRUE;
					}
					else {
						Demod.output[Demod.len] = 0xad;
						Demod.state = DEMOD_ERROR_WAIT;
						//error = 0x03;
					}
					break;

				case DEMOD_ERROR_WAIT:
					Demod.state = DEMOD_UNSYNCD;
					break;

				default:
					Demod.output[Demod.len] = 0xdd;
					Demod.state = DEMOD_UNSYNCD;
					break;
			}

			if(Demod.bitCount>=9) {
				Demod.output[Demod.len] = Demod.shiftReg & 0xff;
				Demod.len++;

				Demod.parityBits <<= 1;
				Demod.parityBits ^= ((Demod.shiftReg >> 8) & 0x01);

				Demod.bitCount = 0;
				Demod.shiftReg = 0;
			}

			/*if(error) {
				Demod.output[Demod.len] = 0xBB;
				Demod.len++;
				Demod.output[Demod.len] = error & 0xFF;
				Demod.len++;
				Demod.output[Demod.len] = 0xBB;
				Demod.len++;
				Demod.output[Demod.len] = bit & 0xFF;
				Demod.len++;
				Demod.output[Demod.len] = Demod.buffer & 0xFF;
				Demod.len++;
				Demod.output[Demod.len] = Demod.syncBit & 0xFF;
				Demod.len++;
				Demod.output[Demod.len] = 0xBB;
				Demod.len++;
				return TRUE;
			}*/

		}

	} // end (state != UNSYNCED)

    return FALSE;
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

		if(ManchesterDecoding(data[0] & 0x0F)) {
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

//-----------------------------------------------------------------------------
// This is to send a NACK kind of answer, its only 3 bits, I know it should be 4
//-----------------------------------------------------------------------------
static void CodeStrangeAnswerAsTag()
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

	// 0
	ToSend[++ToSendMax] = SEC_E;

	// 0
	ToSend[++ToSendMax] = SEC_E;

	// 1
	ToSend[++ToSendMax] = SEC_D;

    // Send stopbit
	ToSend[++ToSendMax] = SEC_F;

	// Flush the buffer in FPGA!!
	for(i = 0; i < 5; i++) {
		ToSend[++ToSendMax] = SEC_F;
	}

    // Convert from last byte pos to length
    ToSendMax++;
}

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

//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
void SimulateIso14443aTag(int tagType, int uid_1st, int uid_2nd)
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
	uint8_t response6[] = { 0x03, 0x3B, 0x00, 0x00, 0x00 }; // dummy ATS (pseudo-ATR), answer to RATS
	ComputeCrc14443(CRC_14443_A, response6, 3, &response6[3], &response6[4]);

	uint8_t *resp;
	int respLen;

  // Longest possible response will be 16 bytes + 2 CRC = 18 bytes
	// This will need
	//    144        data bits (18 * 8)
	//     18        parity bits
	//      2        Start and stop
	//      1        Correction bit (Answer in 1172 or 1236 periods, see FPGA)
	//      1        just for the case
	// ----------- +
	//    166
	//
	// 166 bytes, since every bit that needs to be send costs us a byte
	//

	// Respond with card type
	uint8_t *resp1 = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET);
	int resp1Len;

	// Anticollision cascade1 - respond with uid
	uint8_t *resp2 = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET + 166);
	int resp2Len;

	// Anticollision cascade2 - respond with 2nd half of uid if asked
	// we're only going to be asked if we set the 1st byte of the UID (during cascade1) to 0x88
	uint8_t *resp2a = (((uint8_t *)BigBuf) + 1140);
	int resp2aLen;

	// Acknowledge select - cascade 1
	uint8_t *resp3 = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET + (166*2));
	int resp3Len;

	// Acknowledge select - cascade 2
	uint8_t *resp3a = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET + (166*3));
	int resp3aLen;

	// Response to a read request - not implemented atm
	uint8_t *resp4 = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET + (166*4));
	int resp4Len;

	// Authenticate response - nonce
	uint8_t *resp5 = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET + (166*5));
	int resp5Len;

	// Authenticate response - nonce
	uint8_t *resp6 = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET + (166*6));
	int resp6Len;

	uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
	int len;

	// To control where we are in the protocol
	int order = 0;
	int lastorder;

	// Just to allow some checks
	int happened = 0;
	int happened2 = 0;

	int cmdsRecvd = 0;
	uint8_t* respdata = NULL;
	int respsize = 0;
	uint8_t nack = 0x04;

	memset(receivedCmd, 0x44, RECV_CMD_SIZE);

	// Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA

	// Answer to request
	CodeIso14443aAsTag(response1, sizeof(response1));
	memcpy(resp1, ToSend, ToSendMax); resp1Len = ToSendMax;

	// Send our UID (cascade 1)
	CodeIso14443aAsTag(response2, sizeof(response2));
	memcpy(resp2, ToSend, ToSendMax); resp2Len = ToSendMax;

	// Answer to select (cascade1)
	CodeIso14443aAsTag(response3, sizeof(response3));
	memcpy(resp3, ToSend, ToSendMax); resp3Len = ToSendMax;

	// Send the cascade 2 2nd part of the uid
	CodeIso14443aAsTag(response2a, sizeof(response2a));
	memcpy(resp2a, ToSend, ToSendMax); resp2aLen = ToSendMax;

	// Answer to select (cascade 2)
	CodeIso14443aAsTag(response3a, sizeof(response3a));
	memcpy(resp3a, ToSend, ToSendMax); resp3aLen = ToSendMax;

	// Strange answer is an example of rare message size (3 bits)
	CodeStrangeAnswerAsTag();
	memcpy(resp4, ToSend, ToSendMax); resp4Len = ToSendMax;

	// Authentication answer (random nonce)
	CodeIso14443aAsTag(response5, sizeof(response5));
	memcpy(resp5, ToSend, ToSendMax); resp5Len = ToSendMax;

	// dummy ATS (pseudo-ATR), answer to RATS
	CodeIso14443aAsTag(response6, sizeof(response6));
	memcpy(resp6, ToSend, ToSendMax); resp6Len = ToSendMax;

	// We need to listen to the high-frequency, peak-detected path.
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

	cmdsRecvd = 0;

	LED_A_ON();
	for(;;) {
	
		if(!GetIso14443aCommandFromReader(receivedCmd, &len, RECV_CMD_SIZE)) {
			DbpString("button press");
			break;
		}
		// doob - added loads of debug strings so we can see what the reader is saying to us during the sim as hi14alist is not populated
		// Okay, look at the command now.
		lastorder = order;
		if(receivedCmd[0] == 0x26) { // Received a REQUEST
			resp = resp1; respLen = resp1Len; order = 1;
			respdata = response1;
			respsize = sizeof(response1);
		} else if(receivedCmd[0] == 0x52) { // Received a WAKEUP
			resp = resp1; respLen = resp1Len; order = 6;
			respdata = response1;
			respsize = sizeof(response1);
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
			resp = resp2; respLen = resp2Len; order = 2;
			respdata = response2;
			respsize = sizeof(response2);
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x95) { // Received request for UID (cascade 2)
			resp = resp2a; respLen = resp2aLen; order = 20;
			respdata = response2a;
			respsize = sizeof(response2a);
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
			resp = resp3; respLen = resp3Len; order = 3;
			respdata = response3;
			respsize = sizeof(response3);
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x95) {	// Received a SELECT (cascade 2)
			resp = resp3a; respLen = resp3aLen; order = 30;
			respdata = response3a;
			respsize = sizeof(response3a);
		} else if(receivedCmd[0] == 0x30) {	// Received a (plain) READ
			resp = resp4; respLen = resp4Len; order = 4; // Do nothing
			Dbprintf("Read request from reader: %x %x",receivedCmd[0],receivedCmd[1]);
			respdata = &nack;
			respsize = sizeof(nack); // 4-bit answer
		} else if(receivedCmd[0] == 0x50) {	// Received a HALT
			DbpString("Reader requested we HALT!:");
			// Do not respond
			resp = resp1; respLen = 0; order = 0;
			respdata = NULL;
			respsize = 0;
		} else if(receivedCmd[0] == 0x60 || receivedCmd[0] == 0x61) {	// Received an authentication request
			resp = resp5; respLen = resp5Len; order = 7;
			respdata = response5;
			respsize = sizeof(response5);
		} else if(receivedCmd[0] == 0xE0) {	// Received a RATS request
			resp = resp6; respLen = resp6Len; order = 70;
			respdata = response6;
			respsize = sizeof(response6);
		} else {
			// Never seen this command before
			Dbprintf("Received (len=%d): %02x %02x %02x %02x %02x %02x %02x %02x %02x",
			len,
			receivedCmd[0], receivedCmd[1], receivedCmd[2],
			receivedCmd[3], receivedCmd[4], receivedCmd[5],
			receivedCmd[6], receivedCmd[7], receivedCmd[8]);
			// Do not respond
			resp = resp1; respLen = 0; order = 0;
			respdata = NULL;
			respsize = 0;
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
		} else {
			cmdsRecvd++;
		}

		if(respLen > 0) {
			EmSendCmd14443aRaw(resp, respLen, receivedCmd[0] == 0x52);
		}
		
		if (tracing) {
			LogTrace(receivedCmd,len, 0, Uart.parityBits, TRUE);
			if (respdata != NULL) {
				LogTrace(respdata,respsize, 0, SwapBits(GetParity(respdata,respsize),respsize), FALSE);
			}
			if(traceLen > TRACE_SIZE) {
				DbpString("Trace full");
				break;
			}
		}

		memset(receivedCmd, 0x44, RECV_CMD_SIZE);
  }

	Dbprintf("%x %x %x", happened, happened2, cmdsRecvd);
	LED_A_OFF();
}

//-----------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitFor14443a(const uint8_t *cmd, int len, int *samples, int *wait)
{
  int c;

  FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);

	if (wait)
    if(*wait < 10)
      *wait = 10;

  for(c = 0; c < *wait;) {
    if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
      AT91C_BASE_SSC->SSC_THR = 0x00;		// For exact timing!
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
      AT91C_BASE_SSC->SSC_THR = cmd[c];
      c++;
      if(c >= len) {
        break;
      }
    }
    if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
      volatile uint32_t r = AT91C_BASE_SSC->SSC_RHR;
      (void)r;
    }
    WDT_HIT();
  }
	if (samples) *samples = (c + *wait) << 3;
}

//-----------------------------------------------------------------------------
// Code a 7-bit command without parity bit
// This is especially for 0x26 and 0x52 (REQA and WUPA)
//-----------------------------------------------------------------------------
void ShortFrameFromReader(const uint8_t bt)
{
	int j;
	int last;
  uint8_t b;

	ToSendReset();

	// Start of Communication (Seq. Z)
	ToSend[++ToSendMax] = SEC_Z;
	last = 0;

	b = bt;
	for(j = 0; j < 7; j++) {
		if(b & 1) {
			// Sequence X
			ToSend[++ToSendMax] = SEC_X;
			last = 1;
		} else {
			if(last == 0) {
				// Sequence Z
				ToSend[++ToSendMax] = SEC_Z;
			}
			else {
				// Sequence Y
				ToSend[++ToSendMax] = SEC_Y;
				last = 0;
			}
		}
		b >>= 1;
	}

	// End of Communication
	if(last == 0) {
		// Sequence Z
		ToSend[++ToSendMax] = SEC_Z;
	}
	else {
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
//
//-----------------------------------------------------------------------------
void CodeIso14443aAsReaderPar(const uint8_t * cmd, int len, uint32_t dwParity)
{
  int i, j;
  int last;
  uint8_t b;

  ToSendReset();

  // Start of Communication (Seq. Z)
  ToSend[++ToSendMax] = SEC_Z;
  last = 0;

  // Generate send structure for the data bits
  for (i = 0; i < len; i++) {
    // Get the current byte to send
    b = cmd[i];

    for (j = 0; j < 8; j++) {
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
//  If it takes to long return FALSE
//-----------------------------------------------------------------------------
static int GetIso14443aAnswerFromTag(uint8_t *receivedResponse, int maxLen, int *samples, int *elapsed) //uint8_t *buffer
{
	// buffer needs to be 512 bytes
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
	if (elapsed) *elapsed = 0;

	c = 0;
	for(;;) {
		WDT_HIT();

		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0x00;  // To make use of exact timing of next command from reader!!
			if (elapsed) (*elapsed)++;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			if(c < iso14a_timeout) { c++; } else { return FALSE; }
			b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			if(ManchesterDecoding((b>>4) & 0xf)) {
				*samples = ((c - 1) << 3) + 4;
				return TRUE;
			}
			if(ManchesterDecoding(b & 0x0f)) {
				*samples = c << 3;
				return TRUE;
			}
		}
	}
}

void ReaderTransmitShort(const uint8_t* bt)
{
  int wait = 0;
  int samples = 0;

  ShortFrameFromReader(*bt);

  // Select the card
  TransmitFor14443a(ToSend, ToSendMax, &samples, &wait);

  // Store reader command in buffer
  if (tracing) LogTrace(bt,1,0,GetParity(bt,1),TRUE);
}

void ReaderTransmitPar(uint8_t* frame, int len, uint32_t par)
{
  int wait = 0;
  int samples = 0;

  // This is tied to other size changes
  // 	uint8_t* frame_addr = ((uint8_t*)BigBuf) + 2024;
  CodeIso14443aAsReaderPar(frame,len,par);

  // Select the card
  TransmitFor14443a(ToSend, ToSendMax, &samples, &wait);
  if(trigger)
  	LED_A_ON();

  // Store reader command in buffer
  if (tracing) LogTrace(frame,len,0,par,TRUE);
}


void ReaderTransmit(uint8_t* frame, int len)
{
  // Generate parity and redirect
  ReaderTransmitPar(frame,len,GetParity(frame,len));
}

int ReaderReceive(uint8_t* receivedAnswer)
{
  int samples = 0;
  if (!GetIso14443aAnswerFromTag(receivedAnswer,160,&samples,0)) return FALSE;
  if (tracing) LogTrace(receivedAnswer,Demod.len,samples,Demod.parityBits,FALSE);
  if(samples == 0) return FALSE;
  return Demod.len;
}

int ReaderReceivePar(uint8_t* receivedAnswer, uint32_t * parptr)
{
  int samples = 0;
  if (!GetIso14443aAnswerFromTag(receivedAnswer,160,&samples,0)) return FALSE;
  if (tracing) LogTrace(receivedAnswer,Demod.len,samples,Demod.parityBits,FALSE);
	*parptr = Demod.parityBits;
  if(samples == 0) return FALSE;
  return Demod.len;
}

/* performs iso14443a anticolision procedure
 * fills the uid pointer unless NULL
 * fills resp_data unless NULL */
int iso14443a_select_card(uint8_t * uid_ptr, iso14a_card_select_t * resp_data, uint32_t * cuid_ptr) {
	uint8_t wupa[]       = { 0x52 };  // 0x26 - REQA  0x52 - WAKE-UP
	uint8_t sel_all[]    = { 0x93,0x20 };
	uint8_t sel_uid[]    = { 0x93,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	uint8_t rats[]       = { 0xE0,0x80,0x00,0x00 }; // FSD=256, FSDI=8, CID=0

	uint8_t* resp = (((uint8_t *)BigBuf) + 3560);	// was 3560 - tied to other size changes

	uint8_t sak = 0x04; // cascade uid
	int cascade_level = 0;

	int len;
	
	// clear uid
	memset(uid_ptr, 0, 8);

	// Broadcast for a card, WUPA (0x52) will force response from all cards in the field
	ReaderTransmitShort(wupa);
	// Receive the ATQA
	if(!ReaderReceive(resp)) return 0;

	if(resp_data)
		memcpy(resp_data->atqa, resp, 2);
	
	// OK we will select at least at cascade 1, lets see if first byte of UID was 0x88 in
	// which case we need to make a cascade 2 request and select - this is a long UID
	// While the UID is not complete, the 3nd bit (from the right) is set in the SAK.
	for(; sak & 0x04; cascade_level++)
	{
		// SELECT_* (L1: 0x93, L2: 0x95, L3: 0x97)
		sel_uid[0] = sel_all[0] = 0x93 + cascade_level * 2;

		// SELECT_ALL
		ReaderTransmit(sel_all,sizeof(sel_all));
		if (!ReaderReceive(resp)) return 0;
		if(uid_ptr) memcpy(uid_ptr + cascade_level*4, resp, 4);
		
		// calculate crypto UID
		if(cuid_ptr) *cuid_ptr = bytes_to_num(resp, 4);

		// Construct SELECT UID command
		memcpy(sel_uid+2,resp,5);
		AppendCrc14443a(sel_uid,7);
		ReaderTransmit(sel_uid,sizeof(sel_uid));

		// Receive the SAK
		if (!ReaderReceive(resp)) return 0;
		sak = resp[0];
	}
	if(resp_data) {
		resp_data->sak = sak;
		resp_data->ats_len = 0;
	}
	//--  this byte not UID, it CT.  http://www.nxp.com/documents/application_note/AN10927.pdf  page 3
	if (uid_ptr[0] == 0x88) {  
		memcpy(uid_ptr, uid_ptr + 1, 7);
		uid_ptr[7] = 0;
	}

	if( (sak & 0x20) == 0)
		return 2; // non iso14443a compliant tag

	// Request for answer to select
	if(resp_data) {  // JCOP cards - if reader sent RATS then there is no MIFARE session at all!!!
		AppendCrc14443a(rats, 2);
		ReaderTransmit(rats, sizeof(rats));
		
		if (!(len = ReaderReceive(resp))) return 0;
		
		memcpy(resp_data->ats, resp, sizeof(resp_data->ats));
		resp_data->ats_len = len;
	}
	
	// reset the PCB block number
	iso14_pcb_blocknum = 0;
	
	return 1;
}

void iso14443a_setup() {
	// Setup SSC
	FpgaSetupSsc();
	// Start from off (no field generated)
	// Signal field is off with the appropriate LED
	LED_D_OFF();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelay(200);

	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Now give it time to spin up.
	// Signal field is on with the appropriate LED
	LED_D_ON();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);
	SpinDelay(200);

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
 
	ReaderTransmit(real_cmd, cmd_len+4);
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
void ReaderIso14443a(UsbCommand * c, UsbCommand * ack)
{
	iso14a_command_t param = c->arg[0];
	uint8_t * cmd = c->d.asBytes;
	size_t len = c->arg[1];

	if(param & ISO14A_REQUEST_TRIGGER) iso14a_set_trigger(1);

	if(param & ISO14A_CONNECT) {
		iso14443a_setup();
		ack->arg[0] = iso14443a_select_card(ack->d.asBytes, (iso14a_card_select_t *) (ack->d.asBytes+12), NULL);
		UsbSendPacket((void *)ack, sizeof(UsbCommand));
	}

	if(param & ISO14A_SET_TIMEOUT) {
		iso14a_timeout = c->arg[2];
	}

	if(param & ISO14A_SET_TIMEOUT) {
		iso14a_timeout = c->arg[2];
	}

	if(param & ISO14A_APDU) {
		ack->arg[0] = iso14_apdu(cmd, len, ack->d.asBytes);
		UsbSendPacket((void *)ack, sizeof(UsbCommand));
	}

	if(param & ISO14A_RAW) {
		if(param & ISO14A_APPEND_CRC) {
			AppendCrc14443a(cmd,len);
			len += 2;
		}
		ReaderTransmit(cmd,len);
		ack->arg[0] = ReaderReceive(ack->d.asBytes);
		UsbSendPacket((void *)ack, sizeof(UsbCommand));
	}

	if(param & ISO14A_REQUEST_TRIGGER) iso14a_set_trigger(0);

	if(param & ISO14A_NO_DISCONNECT)
		return;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
}

//-----------------------------------------------------------------------------
// Read an ISO 14443a tag. Send out commands and store answers.
//
//-----------------------------------------------------------------------------
void ReaderMifare(uint32_t parameter)
{
	// Mifare AUTH
	uint8_t mf_auth[]    = { 0x60,0x00,0xf5,0x7b };
	uint8_t mf_nr_ar[]   = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

	uint8_t* receivedAnswer = (((uint8_t *)BigBuf) + 3560);	// was 3560 - tied to other size changes
	traceLen = 0;
	tracing = false;

	iso14443a_setup();

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();

	byte_t nt_diff = 0;
	LED_A_OFF();
	byte_t par = 0;
	//byte_t par_mask = 0xff;
	byte_t par_low = 0;
	int led_on = TRUE;
	uint8_t uid[8];
	uint32_t cuid;

	tracing = FALSE;
	byte_t nt[4] = {0,0,0,0};
	byte_t nt_attacked[4], nt_noattack[4];
	byte_t par_list[8] = {0,0,0,0,0,0,0,0};
	byte_t ks_list[8] = {0,0,0,0,0,0,0,0};
	num_to_bytes(parameter, 4, nt_noattack);
	int isOK = 0, isNULL = 0;

	while(TRUE)
	{
		LED_C_ON();
		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
		SpinDelay(200);
		FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);
		LED_C_OFF();

		// Test if the action was cancelled
		if(BUTTON_PRESS()) {
			break;
		}

		if(!iso14443a_select_card(uid, NULL, &cuid)) continue;

		// Transmit MIFARE_CLASSIC_AUTH
		ReaderTransmit(mf_auth, sizeof(mf_auth));

		// Receive the (16 bit) "random" nonce
		if (!ReaderReceive(receivedAnswer)) continue;
		memcpy(nt, receivedAnswer, 4);

		// Transmit reader nonce and reader answer
		ReaderTransmitPar(mf_nr_ar, sizeof(mf_nr_ar),par);

		// Receive 4 bit answer
		if (ReaderReceive(receivedAnswer))
		{
			if ( (parameter != 0) && (memcmp(nt, nt_noattack, 4) == 0) ) continue;

			isNULL = !(nt_attacked[0] == 0) && (nt_attacked[1] == 0) && (nt_attacked[2] == 0) && (nt_attacked[3] == 0);
			if ( (isNULL != 0 ) && (memcmp(nt, nt_attacked, 4) != 0) ) continue;

			if (nt_diff == 0)
			{
				LED_A_ON();
				memcpy(nt_attacked, nt, 4);
				//par_mask = 0xf8;
				par_low = par & 0x07;
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
			mf_nr_ar[3] = nt_diff << 5;
			par = par_low;
		} else {
			if (nt_diff == 0)
			{
				par++;
			} else {
				par = (((par >> 3) + 1) << 3) | par_low;
			}
		}
	}

	LogTrace(nt, 4, 0, GetParity(nt, 4), TRUE);
	LogTrace(par_list, 8, 0, GetParity(par_list, 8), TRUE);
	LogTrace(ks_list, 8, 0, GetParity(ks_list, 8), TRUE);

	UsbCommand ack = {CMD_ACK, {isOK, 0, 0}};
	memcpy(ack.d.asBytes + 0,  uid, 4);
	memcpy(ack.d.asBytes + 4,  nt, 4);
	memcpy(ack.d.asBytes + 8,  par_list, 8);
	memcpy(ack.d.asBytes + 16, ks_list, 8);
		
	LED_B_ON();
	UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
	LED_B_OFF();	

	// Thats it...
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	tracing = TRUE;
	
	if (MF_DBGLEVEL >= 1)	DbpString("COMMAND mifare FINISHED");
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
	//uint32_t rn_enc = 0;
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
					//rn_enc = bytes_to_num(receivedCmd, 4);
					//cardRn = rn_enc ^ crypto1_word(pcs, rn_enc , 1);
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

		if(ManchesterDecoding(data[0] & 0x0F)) {
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