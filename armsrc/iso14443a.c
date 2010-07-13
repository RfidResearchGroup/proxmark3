//-----------------------------------------------------------------------------
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

static uint8_t *trace = (uint8_t *) BigBuf;
static int traceLen = 0;
static int rsamples = 0;
static int tracing = TRUE;
static uint32_t iso14a_timeout;

// CARD TO READER
// Sequence D: 11110000 modulation with subcarrier during first half
// Sequence E: 00001111 modulation with subcarrier during second half
// Sequence F: 00000000 no modulation with subcarrier
// READER TO CARD
// Sequence X: 00001100 drop after half a period
// Sequence Y: 00000000 no drop
// Sequence Z: 11000000 drop at start
#define	SEC_D 0xf0
#define	SEC_E 0x0f
#define	SEC_F 0x00
#define	SEC_X 0x0c
#define	SEC_Y 0x00
#define	SEC_Z 0xc0

static const uint8_t OddByteParity[256] = {
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

// BIG CHANGE - UNDERSTAND THIS BEFORE WE COMMIT
#define RECV_CMD_OFFSET   3032
#define RECV_RES_OFFSET   3096
#define DMA_BUFFER_OFFSET 3160
#define DMA_BUFFER_SIZE   4096
#define TRACE_LENGTH      3000

uint8_t trigger = 0;
void iso14a_set_trigger(int enable) {
	trigger = enable;
}

//-----------------------------------------------------------------------------
// Generate the parity value for a byte sequence
//
//-----------------------------------------------------------------------------
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

int LogTrace(const uint8_t * btBytes, int iLen, int iSamples, uint32_t dwParity, int bReader)
{
  // Return when trace is full
  if (traceLen >= TRACE_LENGTH) return FALSE;

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
static struct {
    enum {
        STATE_UNSYNCD,
        STATE_START_OF_COMMUNICATION,
		STATE_MILLER_X,
		STATE_MILLER_Y,
		STATE_MILLER_Z,
        STATE_ERROR_WAIT
    }       state;
    uint16_t    shiftReg;
    int     bitCnt;
    int     byteCnt;
    int     byteCntMax;
    int     posCnt;
    int     syncBit;
	int     parityBits;
	int     samples;
    int     highCnt;
    int     bitBuffer;
	enum {
		DROP_NONE,
		DROP_FIRST_HALF,
		DROP_SECOND_HALF
	}		drop;
    uint8_t   *output;
} Uart;

static int MillerDecoding(int bit)
{
	int error = 0;
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
				error = 0x01;
			}

			Uart.posCnt = 0;

			switch(Uart.state) {
				case STATE_START_OF_COMMUNICATION:
					Uart.shiftReg = 0;
					if(Uart.drop == DROP_SECOND_HALF) {
						// error, should not happen in SOC
						Uart.state = STATE_ERROR_WAIT;
						error = 0x02;
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
						error = 0x03;
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
					if(Uart.syncBit & (Uart.bitBuffer & 8)) {
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
				error = 0;
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

static struct {
    enum {
        DEMOD_UNSYNCD,
		DEMOD_START_OF_COMMUNICATION,
		DEMOD_MANCHESTER_D,
		DEMOD_MANCHESTER_E,
		DEMOD_MANCHESTER_F,
        DEMOD_ERROR_WAIT
    }       state;
    int     bitCount;
    int     posCount;
	int     syncBit;
	int     parityBits;
    uint16_t    shiftReg;
	int     buffer;
	int     buff;
	int     samples;
    int     len;
	enum {
		SUB_NONE,
		SUB_FIRST_HALF,
		SUB_SECOND_HALF
	}		sub;
    uint8_t   *output;
} Demod;

static int ManchesterDecoding(int v)
{
	int bit;
	int modulation;
	int error = 0;

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
		if(bit & 0x08) { Demod.syncBit = 0x08; }
		if(!Demod.syncBit)	{
			if(bit & 0x04) { Demod.syncBit = 0x04; }
		}
		else if(bit & 0x04) { Demod.syncBit = 0x04; bit <<= 4; }
		if(!Demod.syncBit)	{
			if(bit & 0x02) { Demod.syncBit = 0x02; }
		}
		else if(bit & 0x02) { Demod.syncBit = 0x02; bit <<= 4; }
		if(!Demod.syncBit)	{
			if(bit & 0x01) { Demod.syncBit = 0x01; }

			if(Demod.syncBit & (Demod.buffer & 0x08)) {
				Demod.syncBit = 0x08;

				// The first half bitperiod is expected in next sample
				Demod.posCount = 0;
				Demod.output[Demod.len] = 0xfb;
			}
		}
		else if(bit & 0x01) { Demod.syncBit = 0x01; }

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
			error = 0;
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
					error = 0x01;
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
						error = 0x02;
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
						error = 0x03;
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
void SnoopIso14443a(void)
{
//	#define RECV_CMD_OFFSET 	2032	// original (working as of 21/2/09) values
//	#define RECV_RES_OFFSET		2096	// original (working as of 21/2/09) values
//	#define DMA_BUFFER_OFFSET	2160	// original (working as of 21/2/09) values
//	#define DMA_BUFFER_SIZE 	4096	// original (working as of 21/2/09) values
//	#define TRACE_LENGTH	 	2000	// original (working as of 21/2/09) values

    // We won't start recording the frames that we acquire until we trigger;
    // a good trigger condition to get started is probably when we see a
    // response from the tag.
    int triggered = FALSE; // FALSE to wait first for card

    // The command (reader -> tag) that we're receiving.
	// The length of a received command will in most cases be no more than 18 bytes.
	// So 32 should be enough!
    uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
    // The response (tag -> reader) that we're receiving.
    uint8_t *receivedResponse = (((uint8_t *)BigBuf) + RECV_RES_OFFSET);

    // As we receive stuff, we copy it from receivedCmd or receivedResponse
    // into trace, along with its length and other annotations.
    //uint8_t *trace = (uint8_t *)BigBuf;
    //int traceLen = 0;

    // The DMA buffer, used to stream samples from the FPGA
    int8_t *dmaBuf = ((int8_t *)BigBuf) + DMA_BUFFER_OFFSET;
    int lastRxCounter;
    int8_t *upTo;
    int smpl;
    int maxBehindBy = 0;

    // Count of samples received so far, so that we can include timing
    // information in the trace buffer.
    int samples = 0;
	int rsamples = 0;

    memset(trace, 0x44, RECV_CMD_OFFSET);

    // Set up the demodulator for tag -> reader responses.
    Demod.output = receivedResponse;
    Demod.len = 0;
    Demod.state = DEMOD_UNSYNCD;

    // Setup for the DMA.
    FpgaSetupSsc();
    upTo = dmaBuf;
    lastRxCounter = DMA_BUFFER_SIZE;
    FpgaSetupSscDma((uint8_t *)dmaBuf, DMA_BUFFER_SIZE);

    // And the reader -> tag commands
    memset(&Uart, 0, sizeof(Uart));
    Uart.output = receivedCmd;
    Uart.byteCntMax = 32; // was 100 (greg)////////////////////////////////////////////////////////////////////////
    Uart.state = STATE_UNSYNCD;

    // And put the FPGA in the appropriate mode
    // Signal field is off with the appropriate LED
    LED_D_OFF();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_SNIFFER);
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);


    // And now we loop, receiving samples.
    for(;;) {
        LED_A_ON();
        WDT_HIT();
        int behindBy = (lastRxCounter - AT91C_BASE_PDC_SSC->PDC_RCR) &
                                (DMA_BUFFER_SIZE-1);
        if(behindBy > maxBehindBy) {
            maxBehindBy = behindBy;
            if(behindBy > 400) {
                Dbprintf("blew circular buffer! behindBy=0x%x", behindBy);
                goto done;
            }
        }
        if(behindBy < 1) continue;

	LED_A_OFF();
        smpl = upTo[0];
        upTo++;
        lastRxCounter -= 1;
        if(upTo - dmaBuf > DMA_BUFFER_SIZE) {
            upTo -= DMA_BUFFER_SIZE;
            lastRxCounter += DMA_BUFFER_SIZE;
            AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) upTo;
            AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
        }

        samples += 4;
        if(MillerDecoding((smpl & 0xF0) >> 4)) {
            rsamples = samples - Uart.samples;
            LED_C_ON();
            if(triggered) {
                trace[traceLen++] = ((rsamples >>  0) & 0xff);
                trace[traceLen++] = ((rsamples >>  8) & 0xff);
                trace[traceLen++] = ((rsamples >> 16) & 0xff);
                trace[traceLen++] = ((rsamples >> 24) & 0xff);
                trace[traceLen++] = ((Uart.parityBits >>  0) & 0xff);
                trace[traceLen++] = ((Uart.parityBits >>  8) & 0xff);
                trace[traceLen++] = ((Uart.parityBits >> 16) & 0xff);
                trace[traceLen++] = ((Uart.parityBits >> 24) & 0xff);
                trace[traceLen++] = Uart.byteCnt;
                memcpy(trace+traceLen, receivedCmd, Uart.byteCnt);
                traceLen += Uart.byteCnt;
                if(traceLen > TRACE_LENGTH) break;
            }
            /* And ready to receive another command. */
            Uart.state = STATE_UNSYNCD;
            /* And also reset the demod code, which might have been */
            /* false-triggered by the commands from the reader. */
            Demod.state = DEMOD_UNSYNCD;
            LED_B_OFF();
        }

        if(ManchesterDecoding(smpl & 0x0F)) {
            rsamples = samples - Demod.samples;
            LED_B_ON();

            // timestamp, as a count of samples
            trace[traceLen++] = ((rsamples >>  0) & 0xff);
            trace[traceLen++] = ((rsamples >>  8) & 0xff);
            trace[traceLen++] = ((rsamples >> 16) & 0xff);
            trace[traceLen++] = 0x80 | ((rsamples >> 24) & 0xff);
            trace[traceLen++] = ((Demod.parityBits >>  0) & 0xff);
            trace[traceLen++] = ((Demod.parityBits >>  8) & 0xff);
            trace[traceLen++] = ((Demod.parityBits >> 16) & 0xff);
            trace[traceLen++] = ((Demod.parityBits >> 24) & 0xff);
            // length
            trace[traceLen++] = Demod.len;
            memcpy(trace+traceLen, receivedResponse, Demod.len);
            traceLen += Demod.len;
            if(traceLen > TRACE_LENGTH) break;

            triggered = TRUE;

            // And ready to receive another response.
            memset(&Demod, 0, sizeof(Demod));
            Demod.output = receivedResponse;
            Demod.state = DEMOD_UNSYNCD;
            LED_C_OFF();
        }

        if(BUTTON_PRESS()) {
            DbpString("cancelled_a");
            goto done;
        }
    }

    DbpString("COMMAND FINISHED");

    Dbprintf("%x %x %x", maxBehindBy, Uart.state, Uart.byteCnt);
    Dbprintf("%x %x %x", Uart.byteCntMax, traceLen, (int)Uart.output[0]);

done:
    AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;
    Dbprintf("%x %x %x", maxBehindBy, Uart.state, Uart.byteCnt);
    Dbprintf("%x %x %x", Uart.byteCntMax, traceLen, (int)Uart.output[0]);
    LED_A_OFF();
    LED_B_OFF();
	LED_C_OFF();
	LED_D_OFF();
}

//-----------------------------------------------------------------------------
// Prepare tag messages
//-----------------------------------------------------------------------------
static void CodeIso14443aAsTag(const uint8_t *cmd, int len)
{
    int i;
	int oddparity;

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
        oddparity = 0x01;
		for(j = 0; j < 8; j++) {
            oddparity ^= (b & 1);
			if(b & 1) {
				ToSend[++ToSendMax] = SEC_D;
			} else {
				ToSend[++ToSendMax] = SEC_E;
            }
            b >>= 1;
        }

        // Parity bit
        if(oddparity) {
        	ToSend[++ToSendMax] = SEC_D;
		} else {
			ToSend[++ToSendMax] = SEC_E;
		}
    }

    // Send stopbit
    ToSend[++ToSendMax] = SEC_F;

	// Flush the buffer in FPGA!!
	for(i = 0; i < 5; i++) {
		ToSend[++ToSendMax] = SEC_F;
	}

    // Convert from last byte pos to length
    ToSendMax++;

    // Add a few more for slop
    ToSend[ToSendMax++] = 0x00;
	ToSend[ToSendMax++] = 0x00;
    //ToSendMax += 2;
}

//-----------------------------------------------------------------------------
// This is to send a NACK kind of answer, its only 3 bits, I know it should be 4
//-----------------------------------------------------------------------------
static void CodeStrangeAnswer()
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

    // Add a few more for slop
    ToSend[ToSendMax++] = 0x00;
	ToSend[ToSendMax++] = 0x00;
    //ToSendMax += 2;
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

//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
void SimulateIso14443aTag(int tagType, int TagUid)
{
	// This function contains the tag emulation

	// Prepare protocol messages
    // static const uint8_t cmd1[] = { 0x26 };
//     static const uint8_t response1[] = { 0x02, 0x00 }; // Says: I am Mifare 4k - original line - greg
//
	static const uint8_t response1[] = { 0x44, 0x03 }; // Says: I am a DESFire Tag, ph33r me
//	static const uint8_t response1[] = { 0x44, 0x00 }; // Says: I am a ULTRALITE Tag, 0wn me

	// UID response
    // static const uint8_t cmd2[] = { 0x93, 0x20 };
    //static const uint8_t response2[] = { 0x9a, 0xe5, 0xe4, 0x43, 0xd8 }; // original value - greg

// my desfire
    static const uint8_t response2[] = { 0x88, 0x04, 0x21, 0x3f, 0x4d }; // known uid - note cascade (0x88), 2nd byte (0x04) = NXP/Phillips


// When reader selects us during cascade1 it will send cmd3
//uint8_t response3[] = { 0x04, 0x00, 0x00 }; // SAK Select (cascade1) successful response (ULTRALITE)
uint8_t response3[] = { 0x24, 0x00, 0x00 }; // SAK Select (cascade1) successful response (DESFire)
ComputeCrc14443(CRC_14443_A, response3, 1, &response3[1], &response3[2]);

// send cascade2 2nd half of UID
static const uint8_t response2a[] = { 0x51, 0x48, 0x1d, 0x80, 0x84 }; //  uid - cascade2 - 2nd half (4 bytes) of UID+ BCCheck
// NOTE : THE CRC on the above may be wrong as I have obfuscated the actual UID

// When reader selects us during cascade2 it will send cmd3a
//uint8_t response3a[] = { 0x00, 0x00, 0x00 }; // SAK Select (cascade2) successful response (ULTRALITE)
uint8_t response3a[] = { 0x20, 0x00, 0x00 }; // SAK Select (cascade2) successful response (DESFire)
ComputeCrc14443(CRC_14443_A, response3a, 1, &response3a[1], &response3a[2]);

    static const uint8_t response5[] = { 0x00, 0x00, 0x00, 0x00 }; // Very random tag nonce

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
    uint8_t *resp1 = (((uint8_t *)BigBuf) + 800);
    int resp1Len;

    // Anticollision cascade1 - respond with uid
    uint8_t *resp2 = (((uint8_t *)BigBuf) + 970);
    int resp2Len;

    // Anticollision cascade2 - respond with 2nd half of uid if asked
    // we're only going to be asked if we set the 1st byte of the UID (during cascade1) to 0x88
    uint8_t *resp2a = (((uint8_t *)BigBuf) + 1140);
    int resp2aLen;

    // Acknowledge select - cascade 1
    uint8_t *resp3 = (((uint8_t *)BigBuf) + 1310);
    int resp3Len;

    // Acknowledge select - cascade 2
    uint8_t *resp3a = (((uint8_t *)BigBuf) + 1480);
    int resp3aLen;

    // Response to a read request - not implemented atm
    uint8_t *resp4 = (((uint8_t *)BigBuf) + 1550);
    int resp4Len;

    // Authenticate response - nonce
    uint8_t *resp5 = (((uint8_t *)BigBuf) + 1720);
    int resp5Len;

    uint8_t *receivedCmd = (uint8_t *)BigBuf;
    int len;

    int i;
	int u;
	uint8_t b;

	// To control where we are in the protocol
	int order = 0;
	int lastorder;

	// Just to allow some checks
	int happened = 0;
	int happened2 = 0;

    int cmdsRecvd = 0;

	int fdt_indicator;

    memset(receivedCmd, 0x44, 400);

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
	CodeStrangeAnswer();
	memcpy(resp4, ToSend, ToSendMax); resp4Len = ToSendMax;

	// Authentication answer (random nonce)
	CodeIso14443aAsTag(response5, sizeof(response5));
    memcpy(resp5, ToSend, ToSendMax); resp5Len = ToSendMax;

    // We need to listen to the high-frequency, peak-detected path.
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
    FpgaSetupSsc();

    cmdsRecvd = 0;

    LED_A_ON();
	for(;;) {

		if(!GetIso14443aCommandFromReader(receivedCmd, &len, 100)) {
            DbpString("button press");
            break;
        }
	// doob - added loads of debug strings so we can see what the reader is saying to us during the sim as hi14alist is not populated
        // Okay, look at the command now.
        lastorder = order;
		i = 1; // first byte transmitted
        if(receivedCmd[0] == 0x26) {
			// Received a REQUEST
			resp = resp1; respLen = resp1Len; order = 1;
			//DbpString("Hello request from reader:");
		} else if(receivedCmd[0] == 0x52) {
			// Received a WAKEUP
			resp = resp1; respLen = resp1Len; order = 6;
//			//DbpString("Wakeup request from reader:");

		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// greg - cascade 1 anti-collision
			// Received request for UID (cascade 1)
			resp = resp2; respLen = resp2Len; order = 2;
//			DbpString("UID (cascade 1) request from reader:");
//			DbpIntegers(receivedCmd[0], receivedCmd[1], receivedCmd[2]);


		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] ==0x95) {	// greg - cascade 2 anti-collision
			// Received request for UID (cascade 2)
			resp = resp2a; respLen = resp2aLen; order = 20;
//			DbpString("UID (cascade 2) request from reader:");
//			DbpIntegers(receivedCmd[0], receivedCmd[1], receivedCmd[2]);


		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] ==0x93) {	// greg - cascade 1 select
			// Received a SELECT
			resp = resp3; respLen = resp3Len; order = 3;
//			DbpString("Select (cascade 1) request from reader:");
//			DbpIntegers(receivedCmd[0], receivedCmd[1], receivedCmd[2]);


		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] ==0x95) {	// greg - cascade 2 select
			// Received a SELECT
			resp = resp3a; respLen = resp3aLen; order = 30;
//			DbpString("Select (cascade 2) request from reader:");
//			DbpIntegers(receivedCmd[0], receivedCmd[1], receivedCmd[2]);


		} else if(receivedCmd[0] == 0x30) {
			// Received a READ
			resp = resp4; respLen = resp4Len; order = 4; // Do nothing
			Dbprintf("Read request from reader: %x %x %x",
				receivedCmd[0], receivedCmd[1], receivedCmd[2]);


		} else if(receivedCmd[0] == 0x50) {
			// Received a HALT
			resp = resp1; respLen = 0; order = 5; // Do nothing
			DbpString("Reader requested we HALT!:");

		} else if(receivedCmd[0] == 0x60) {
			// Received an authentication request
			resp = resp5; respLen = resp5Len; order = 7;
			Dbprintf("Authenticate request from reader: %x %x %x",
				receivedCmd[0], receivedCmd[1], receivedCmd[2]);

		} else if(receivedCmd[0] == 0xE0) {
			// Received a RATS request
			resp = resp1; respLen = 0;order = 70;
			Dbprintf("RATS request from reader: %x %x %x",
				receivedCmd[0], receivedCmd[1], receivedCmd[2]);
        } else {
            // Never seen this command before
		Dbprintf("Unknown command received from reader: %x %x %x %x %x %x %x %x %x",
			receivedCmd[0], receivedCmd[1], receivedCmd[2],
			receivedCmd[3], receivedCmd[3], receivedCmd[4],
			receivedCmd[5], receivedCmd[6], receivedCmd[7]);
			// Do not respond
			resp = resp1; respLen = 0; order = 0;
        }

		// Count number of wakeups received after a halt
		if(order == 6 && lastorder == 5) { happened++; }

		// Count number of other messages after a halt
		if(order != 6 && lastorder == 5) { happened2++; }

		// Look at last parity bit to determine timing of answer
		if((Uart.parityBits & 0x01) || receivedCmd[0] == 0x52) {
			// 1236, so correction bit needed
			i = 0;
		}

        memset(receivedCmd, 0x44, 32);

		if(cmdsRecvd > 999) {
			DbpString("1000 commands later...");
            break;
        }
		else {
			cmdsRecvd++;
		}

        if(respLen <= 0) continue;

        // Modulate Manchester
		FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_MOD);
        AT91C_BASE_SSC->SSC_THR = 0x00;
        FpgaSetupSsc();

		// ### Transmit the response ###
		u = 0;
		b = 0x00;
		fdt_indicator = FALSE;
        for(;;) {
            if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
				volatile uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
                (void)b;
            }
            if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
				if(i > respLen) {
					b = 0x00;
					u++;
				} else {
					b = resp[i];
					i++;
				}
				AT91C_BASE_SSC->SSC_THR = b;

                if(u > 4) {
                    break;
                }
            }
			if(BUTTON_PRESS()) {
			    break;
			}
        }

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
  if (!GetIso14443aAnswerFromTag(receivedAnswer,100,&samples,0)) return FALSE;
  if (tracing) LogTrace(receivedAnswer,Demod.len,samples,Demod.parityBits,FALSE);
  if(samples == 0) return FALSE;
  return Demod.len;
}

/* performs iso14443a anticolision procedure
 * fills the uid pointer unless NULL
 * fills resp_data unless NULL */
int iso14443a_select_card(uint8_t * uid_ptr, iso14a_card_select_t * resp_data) {
	uint8_t wupa[]       = { 0x52 };
	uint8_t sel_all[]    = { 0x93,0x20 };
	uint8_t sel_uid[]    = { 0x93,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	uint8_t rats[]       = { 0xE0,0x80,0x00,0x00 }; // FSD=256, FSDI=8, CID=0

	uint8_t* resp = (((uint8_t *)BigBuf) + 3560);	// was 3560 - tied to other size changes
	uint8_t* uid  = resp + 7;

	uint8_t sak = 0x04; // cascade uid
	int cascade_level = 0;

	int len;

	// Broadcast for a card, WUPA (0x52) will force response from all cards in the field
	ReaderTransmitShort(wupa);
	// Receive the ATQA
	if(!ReaderReceive(resp)) return 0;

	if(resp_data)
		memcpy(resp_data->atqa, resp, 2);
	
	ReaderTransmit(sel_all,sizeof(sel_all)); 
	if(!ReaderReceive(uid)) return 0;

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

	if( (sak & 0x20) == 0)
		return 2; // non iso14443a compliant tag

	// Request for answer to select
	AppendCrc14443a(rats, 2);
	ReaderTransmit(rats, sizeof(rats));
	if (!(len = ReaderReceive(resp))) return 0;
	if(resp_data) {
		memcpy(resp_data->ats, resp, sizeof(resp_data->ats));
		resp_data->ats_len = len;
	}

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
	real_cmd[1] = 0x00; //CID: 0 //FIXME: allow multiple selected cards
	memcpy(real_cmd+2, cmd, cmd_len);
	AppendCrc14443a(real_cmd,cmd_len+2);
 
	ReaderTransmit(real_cmd, cmd_len+4);
	size_t len = ReaderReceive(data);
	if(!len)
		return -1; //DATA LINK ERROR
	
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
		ack->arg[0] = iso14443a_select_card(ack->d.asBytes, (iso14a_card_select_t *) (ack->d.asBytes+12));
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
  byte_t par_mask = 0xff;
  byte_t par_low = 0;
  int led_on = TRUE;

  tracing = FALSE;
  byte_t nt[4];
  byte_t nt_attacked[4];
  byte_t par_list[8];
  byte_t ks_list[8];
  num_to_bytes(parameter,4,nt_attacked);

  while(TRUE)
  {
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    SpinDelay(200);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);

    // Test if the action was cancelled
    if(BUTTON_PRESS()) {
      break;
    }

    if(!iso14443a_select_card(NULL, NULL)) continue;

    // Transmit MIFARE_CLASSIC_AUTH
    ReaderTransmit(mf_auth,sizeof(mf_auth));

    // Receive the (16 bit) "random" nonce
    if (!ReaderReceive(receivedAnswer)) continue;
    memcpy(nt,receivedAnswer,4);

    // Transmit reader nonce and reader answer
    ReaderTransmitPar(mf_nr_ar,sizeof(mf_nr_ar),par);

    // Receive 4 bit answer
    if (ReaderReceive(receivedAnswer))
    {
      if (nt_diff == 0)
      {
        LED_A_ON();
        memcpy(nt_attacked,nt,4);
        par_mask = 0xf8;
        par_low = par & 0x07;
      }

      if (memcmp(nt,nt_attacked,4) != 0) continue;

      led_on = !led_on;
      if(led_on) LED_B_ON(); else LED_B_OFF();
      par_list[nt_diff] = par;
      ks_list[nt_diff] = receivedAnswer[0]^0x05;

      // Test if the information is complete
      if (nt_diff == 0x07) break;

      nt_diff = (nt_diff+1) & 0x07;
      mf_nr_ar[3] = nt_diff << 5;
      par = par_low;
    } else {
      if (nt_diff == 0)
      {
        par++;
      } else {
        par = (((par>>3)+1) << 3) | par_low;
      }
    }
  }

  LogTrace(nt,4,0,GetParity(nt,4),TRUE);
  LogTrace(par_list,8,0,GetParity(par_list,8),TRUE);
  LogTrace(ks_list,8,0,GetParity(ks_list,8),TRUE);

  // Thats it...
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
  tracing = TRUE;
}
