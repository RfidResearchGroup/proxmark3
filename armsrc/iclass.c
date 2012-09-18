//-----------------------------------------------------------------------------
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
// Gerhard de Koning Gans - May 2011
// Gerhard de Koning Gans - June 2012 - Added iClass card and reader emulation
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support iClass.
//-----------------------------------------------------------------------------
// Based on ISO14443a implementation. Still in experimental phase.
// Contribution made during a security research at Radboud University Nijmegen
// 
// Please feel free to contribute and extend iClass support!!
//-----------------------------------------------------------------------------
//
// FIX:
// ====
// We still have sometimes a demodulation error when snooping iClass communication.
// The resulting trace of a read-block-03 command may look something like this:
//
//  +  22279:    :     0c  03  e8  01    
//
//    ...with an incorrect answer...
//
//  +     85:   0: TAG ff! ff! ff! ff! ff! ff! ff! ff! bb  33  bb  00  01! 0e! 04! bb     !crc
//
// We still left the error signalling bytes in the traces like 0xbb
//
// A correct trace should look like this:
//
// +  21112:    :     0c  03  e8  01    
// +     85:   0: TAG ff  ff  ff  ff  ff  ff  ff  ff  ea  f5    
//
//-----------------------------------------------------------------------------

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"
#include "common.h"
// Needed for CRC in emulation mode;
// same construction as in ISO 14443;
// different initial value (CRC_ICLASS)
#include "iso14443crc.h"

static int timeout = 4096;

// CARD TO READER
// Sequence D: 11110000 modulation with subcarrier during first half
// Sequence E: 00001111 modulation with subcarrier during second half
// Sequence F: 00000000 no modulation with subcarrier
// READER TO CARD
// Sequence X: 00001100 drop after half a period
// Sequence Y: 00000000 no drop
// Sequence Z: 11000000 drop at start
#define	SEC_X 0x0c
#define	SEC_Y 0x00
#define	SEC_Z 0xc0

static int SendIClassAnswer(uint8_t *resp, int respLen, int delay);

//-----------------------------------------------------------------------------
// The software UART that receives commands from the reader, and its state
// variables.
//-----------------------------------------------------------------------------
static struct {
    enum {
        STATE_UNSYNCD,
        STATE_START_OF_COMMUNICATION,
	STATE_RECEIVING
    }       state;
    uint16_t    shiftReg;
    int     bitCnt;
    int     byteCnt;
    int     byteCntMax;
    int     posCnt;
    int     nOutOfCnt;
    int     OutOfCnt;
    int     syncBit;
    int     parityBits;
    int     samples;
    int     highCnt;
    int     swapper;
    int     counter;
    int     bitBuffer;
    int     dropPosition;
    uint8_t   *output;
} Uart;

static RAMFUNC int OutOfNDecoding(int bit)
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
	
	/*if(Uart.swapper) {
		Uart.output[Uart.byteCnt] = Uart.bitBuffer & 0xFF;
		Uart.byteCnt++;
		Uart.swapper = 0;
		if(Uart.byteCnt > 15) { return TRUE; }
	}
	else {
		Uart.swapper = 1;
	}*/

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

		
		// So, now we only have to deal with *bit*, lets see...
		if(Uart.posCnt == 1) {
			// measurement first half bitperiod
			if(!bit) {
				// Drop in first half means that we are either seeing
				// an SOF or an EOF.

				if(Uart.nOutOfCnt == 1) {
					// End of Communication
					Uart.state = STATE_UNSYNCD;
					Uart.highCnt = 0;
					if(Uart.byteCnt == 0) {
						// Its not straightforward to show single EOFs
						// So just leave it and do not return TRUE
						Uart.output[Uart.byteCnt] = 0xf0;
						Uart.byteCnt++;

						// Calculate the parity bit for the client...
						Uart.parityBits = 1;
					}
					else {
						return TRUE;
					}
				}
				else if(Uart.state != STATE_START_OF_COMMUNICATION) {
					// When not part of SOF or EOF, it is an error
					Uart.state = STATE_UNSYNCD;
					Uart.highCnt = 0;
					//error = 4;
				}
			}
		}
		else {
			// measurement second half bitperiod
			// Count the bitslot we are in... (ISO 15693)
			Uart.nOutOfCnt++;
			
			if(!bit) {
				if(Uart.dropPosition) {
					if(Uart.state == STATE_START_OF_COMMUNICATION) {
						//error = 1;
					}
					else {
						//error = 7;
					}
					// It is an error if we already have seen a drop in current frame
					Uart.state = STATE_UNSYNCD;
					Uart.highCnt = 0;
				}
				else {
					Uart.dropPosition = Uart.nOutOfCnt;
				}
			}

			Uart.posCnt = 0;

			
			if(Uart.nOutOfCnt == Uart.OutOfCnt && Uart.OutOfCnt == 4) {
				Uart.nOutOfCnt = 0;
				
				if(Uart.state == STATE_START_OF_COMMUNICATION) {
					if(Uart.dropPosition == 4) {
						Uart.state = STATE_RECEIVING;
						Uart.OutOfCnt = 256;
					}
					else if(Uart.dropPosition == 3) {
						Uart.state = STATE_RECEIVING;
						Uart.OutOfCnt = 4;
						//Uart.output[Uart.byteCnt] = 0xdd;
						//Uart.byteCnt++;
					}
					else {
						Uart.state = STATE_UNSYNCD;
						Uart.highCnt = 0;
					}
					Uart.dropPosition = 0;
				}
				else {
					// RECEIVING DATA
					// 1 out of 4
					if(!Uart.dropPosition) {
						Uart.state = STATE_UNSYNCD;
						Uart.highCnt = 0;
						//error = 9;
					}
					else {
						Uart.shiftReg >>= 2;
						
						// Swap bit order
						Uart.dropPosition--;
						//if(Uart.dropPosition == 1) { Uart.dropPosition = 2; }
						//else if(Uart.dropPosition == 2) { Uart.dropPosition = 1; }
						
						Uart.shiftReg ^= ((Uart.dropPosition & 0x03) << 6);
						Uart.bitCnt += 2;
						Uart.dropPosition = 0;

						if(Uart.bitCnt == 8) {
							Uart.output[Uart.byteCnt] = (Uart.shiftReg & 0xff);
							Uart.byteCnt++;

							// Calculate the parity bit for the client...
							Uart.parityBits <<= 1;
							Uart.parityBits ^= OddByteParity[(Uart.shiftReg & 0xff)];

							Uart.bitCnt = 0;
							Uart.shiftReg = 0;
						}
					}
				}
			}
			else if(Uart.nOutOfCnt == Uart.OutOfCnt) {
				// RECEIVING DATA
				// 1 out of 256
				if(!Uart.dropPosition) {
					Uart.state = STATE_UNSYNCD;
					Uart.highCnt = 0;
					//error = 3;
				}
				else {
					Uart.dropPosition--;
					Uart.output[Uart.byteCnt] = (Uart.dropPosition & 0xff);
					Uart.byteCnt++;

					// Calculate the parity bit for the client...
					Uart.parityBits <<= 1;
					Uart.parityBits ^= OddByteParity[(Uart.dropPosition & 0xff)];

					Uart.bitCnt = 0;
					Uart.shiftReg = 0;
					Uart.nOutOfCnt = 0;
					Uart.dropPosition = 0;
				}
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
		bit ^= 0x0F; // drops become 1s ;-)
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
				Uart.bitCnt = 0;
				Uart.byteCnt = 0;
				Uart.parityBits = 0;
				Uart.nOutOfCnt = 0;
				Uart.OutOfCnt = 4; // Start at 1/4, could switch to 1/256
				Uart.dropPosition = 0;
				Uart.shiftReg = 0;
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
// Manchester
//=============================================================================

static struct {
    enum {
        DEMOD_UNSYNCD,
		DEMOD_START_OF_COMMUNICATION,
		DEMOD_START_OF_COMMUNICATION2,
		DEMOD_START_OF_COMMUNICATION3,
		DEMOD_SOF_COMPLETE,
		DEMOD_MANCHESTER_D,
		DEMOD_MANCHESTER_E,
		DEMOD_END_OF_COMMUNICATION,
		DEMOD_END_OF_COMMUNICATION2,
		DEMOD_MANCHESTER_F,
        DEMOD_ERROR_WAIT
    }       state;
    int     bitCount;
    int     posCount;
	int     syncBit;
	int     parityBits;
    uint16_t    shiftReg;
	int     buffer;
	int     buffer2;
	int	buffer3;
	int     buff;
	int     samples;
    int     len;
	enum {
		SUB_NONE,
		SUB_FIRST_HALF,
		SUB_SECOND_HALF,
		SUB_BOTH
	}		sub;
    uint8_t   *output;
} Demod;

static RAMFUNC int ManchesterDecoding(int v)
{
	int bit;
	int modulation;
	int error = 0;

	bit = Demod.buffer;
	Demod.buffer = Demod.buffer2;
	Demod.buffer2 = Demod.buffer3;
	Demod.buffer3 = v;

	if(Demod.buff < 3) {
		Demod.buff++;
		return FALSE;
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
				//if(trigger) LED_A_OFF();  // Not useful in this case...
				switch(Demod.syncBit) {
					case 0x08: Demod.samples = 3; break;
					case 0x04: Demod.samples = 2; break;
					case 0x02: Demod.samples = 1; break;
					case 0x01: Demod.samples = 0; break;
				}
				// SOF must be long burst... otherwise stay unsynced!!!
				if(!(Demod.buffer & Demod.syncBit) || !(Demod.buffer2 & Demod.syncBit)) {
					Demod.state = DEMOD_UNSYNCD;
				}
			}
			else {
				// SOF must be long burst... otherwise stay unsynced!!!
				if(!(Demod.buffer2 & Demod.syncBit) || !(Demod.buffer3 & Demod.syncBit)) {
					Demod.state = DEMOD_UNSYNCD;
					error = 0x88;
				}

			}
			error = 0;

		}
	}
	else {
		modulation = bit & Demod.syncBit;
		modulation |= ((bit << 1) ^ ((Demod.buffer & 0x08) >> 3)) & Demod.syncBit;
		//modulation = ((bit << 1) ^ ((Demod.buffer & 0x08) >> 3)) & Demod.syncBit;

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
			/*(modulation && (Demod.sub == SUB_FIRST_HALF)) {
				if(Demod.state!=DEMOD_ERROR_WAIT) {
					Demod.state = DEMOD_ERROR_WAIT;
					Demod.output[Demod.len] = 0xaa;
					error = 0x01;
				}
			}*/
			//else if(modulation) {
			if(modulation) {
				if(Demod.sub == SUB_FIRST_HALF) {
					Demod.sub = SUB_BOTH;
				}
				else {
					Demod.sub = SUB_SECOND_HALF;
				}
			}
			else if(Demod.sub == SUB_NONE) {
				if(Demod.state == DEMOD_SOF_COMPLETE) {
					Demod.output[Demod.len] = 0x0f;
					Demod.len++;
					Demod.parityBits <<= 1;
					Demod.parityBits ^= OddByteParity[0x0f];
					Demod.state = DEMOD_UNSYNCD;
//					error = 0x0f;
					return TRUE;
				}
				else {
					Demod.state = DEMOD_ERROR_WAIT;
					error = 0x33;
				}
				/*if(Demod.state!=DEMOD_ERROR_WAIT) {
					Demod.state = DEMOD_ERROR_WAIT;
					Demod.output[Demod.len] = 0xaa;
					error = 0x01;
				}*/
			}

			switch(Demod.state) {
				case DEMOD_START_OF_COMMUNICATION:
					if(Demod.sub == SUB_BOTH) {
						//Demod.state = DEMOD_MANCHESTER_D;
						Demod.state = DEMOD_START_OF_COMMUNICATION2;
						Demod.posCount = 1;
						Demod.sub = SUB_NONE;
					}
					else {
						Demod.output[Demod.len] = 0xab;
						Demod.state = DEMOD_ERROR_WAIT;
						error = 0xd2;
					}
					break;
				case DEMOD_START_OF_COMMUNICATION2:
					if(Demod.sub == SUB_SECOND_HALF) {
						Demod.state = DEMOD_START_OF_COMMUNICATION3;
					}
					else {
						Demod.output[Demod.len] = 0xab;
						Demod.state = DEMOD_ERROR_WAIT;
						error = 0xd3;
					}
					break;
				case DEMOD_START_OF_COMMUNICATION3:
					if(Demod.sub == SUB_SECOND_HALF) {
//						Demod.state = DEMOD_MANCHESTER_D;
						Demod.state = DEMOD_SOF_COMPLETE;
						//Demod.output[Demod.len] = Demod.syncBit & 0xFF;
						//Demod.len++;
					}
					else {
						Demod.output[Demod.len] = 0xab;
						Demod.state = DEMOD_ERROR_WAIT;
						error = 0xd4;
					}
					break;
				case DEMOD_SOF_COMPLETE:
				case DEMOD_MANCHESTER_D:
				case DEMOD_MANCHESTER_E:
					// OPPOSITE FROM ISO14443 - 11110000 = 0 (1 in 14443)
					//                          00001111 = 1 (0 in 14443)
					if(Demod.sub == SUB_SECOND_HALF) { // SUB_FIRST_HALF
						Demod.bitCount++;
						Demod.shiftReg = (Demod.shiftReg >> 1) ^ 0x100;
						Demod.state = DEMOD_MANCHESTER_D;
					}
					else if(Demod.sub == SUB_FIRST_HALF) { // SUB_SECOND_HALF
						Demod.bitCount++;
						Demod.shiftReg >>= 1;
						Demod.state = DEMOD_MANCHESTER_E;
					}
					else if(Demod.sub == SUB_BOTH) {
						Demod.state = DEMOD_MANCHESTER_F;
					}
					else {
						Demod.state = DEMOD_ERROR_WAIT;
						error = 0x55;
					}
					break;

				case DEMOD_MANCHESTER_F:
					// Tag response does not need to be a complete byte!
					if(Demod.len > 0 || Demod.bitCount > 0) {
						if(Demod.bitCount > 1) {  // was > 0, do not interpret last closing bit, is part of EOF
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

			/*if(Demod.bitCount>=9) {
				Demod.output[Demod.len] = Demod.shiftReg & 0xff;
				Demod.len++;

				Demod.parityBits <<= 1;
				Demod.parityBits ^= ((Demod.shiftReg >> 8) & 0x01);

				Demod.bitCount = 0;
				Demod.shiftReg = 0;
			}*/
			if(Demod.bitCount>=8) {
				Demod.shiftReg >>= 1;
				Demod.output[Demod.len] = (Demod.shiftReg & 0xff);
				Demod.len++;

				// FOR ISO15639 PARITY NOT SEND OTA, JUST CALCULATE IT FOR THE CLIENT
				Demod.parityBits <<= 1;
				Demod.parityBits ^= OddByteParity[(Demod.shiftReg & 0xff)];

				Demod.bitCount = 0;
				Demod.shiftReg = 0;
			}

			if(error) {
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
				// Look harder ;-)
				Demod.output[Demod.len] = Demod.buffer2 & 0xFF;
				Demod.len++;
				Demod.output[Demod.len] = Demod.syncBit & 0xFF;
				Demod.len++;
				Demod.output[Demod.len] = 0xBB;
				Demod.len++;
				return TRUE;
			}

		}

	} // end (state != UNSYNCED)

    return FALSE;
}

//=============================================================================
// Finally, a `sniffer' for iClass communication
// Both sides of communication!
//=============================================================================

//-----------------------------------------------------------------------------
// Record the sequence of commands sent by the reader to the tag, with
// triggering so that we start recording at the point that the tag is moved
// near the reader.
//-----------------------------------------------------------------------------
void RAMFUNC SnoopIClass(void)
{
// DEFINED ABOVE
// #define RECV_CMD_OFFSET   3032
// #define RECV_RES_OFFSET   3096
// #define DMA_BUFFER_OFFSET 3160
// #define DMA_BUFFER_SIZE   4096
// #define TRACE_SIZE        3000

    // We won't start recording the frames that we acquire until we trigger;
    // a good trigger condition to get started is probably when we see a
    // response from the tag.
    //int triggered = FALSE; // FALSE to wait first for card

    // The command (reader -> tag) that we're receiving.
	// The length of a received command will in most cases be no more than 18 bytes.
	// So 32 should be enough!
    uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
    // The response (tag -> reader) that we're receiving.
    uint8_t *receivedResponse = (((uint8_t *)BigBuf) + RECV_RES_OFFSET);

    // As we receive stuff, we copy it from receivedCmd or receivedResponse
    // into trace, along with its length and other annotations.
    //uint8_t *trace = (uint8_t *)BigBuf;
    
    // reset traceLen to 0
    iso14a_set_tracing(TRUE);
    iso14a_clear_trace();
    iso14a_set_trigger(FALSE);

    // The DMA buffer, used to stream samples from the FPGA
    int8_t *dmaBuf = ((int8_t *)BigBuf) + DMA_BUFFER_OFFSET;
    int lastRxCounter;
    int8_t *upTo;
    int smpl;
    int maxBehindBy = 0;

    // Count of samples received so far, so that we can include timing
    // information in the trace buffer.
    int samples = 0;
    rsamples = 0;

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

    int div = 0;
    //int div2 = 0;
    int decbyte = 0;
    int decbyter = 0;

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

        //samples += 4;
	samples += 1;
	//div2++;	

	//if(div2 > 3) {
		//div2 = 0;
	//decbyte ^= ((smpl & 0x01) << (3 - div));
	//decbyte ^= (((smpl & 0x01) | ((smpl & 0x02) >> 1)) << (3 - div)); // better already...
	//decbyte ^= (((smpl & 0x01) | ((smpl & 0x02) >> 1) | ((smpl & 0x04) >> 2)) << (3 - div)); // even better...
	if(smpl & 0xF) {
		decbyte ^= (1 << (3 - div));
	}
	//decbyte ^= (MajorityNibble[(smpl & 0x0F)] << (3 - div));
	
	// FOR READER SIDE COMMUMICATION...
	//decbyte ^=  ((smpl & 0x10) << (3 - div));
	decbyter <<= 2;
	decbyter ^= (smpl & 0x30);

	div++;
	
	if((div + 1) % 2 == 0) {
		smpl = decbyter;	
		if(OutOfNDecoding((smpl & 0xF0) >> 4)) {
		    rsamples = samples - Uart.samples;
		    LED_C_ON();
		    //if(triggered) {
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
			if(traceLen > TRACE_SIZE) break;
		    //}
		    /* And ready to receive another command. */
		    Uart.state = STATE_UNSYNCD;
		    /* And also reset the demod code, which might have been */
		    /* false-triggered by the commands from the reader. */
		    Demod.state = DEMOD_UNSYNCD;
		    LED_B_OFF();
		    Uart.byteCnt = 0;
		}
		decbyter = 0;
	}

	if(div > 3) {
		smpl = decbyte;
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
		    if(traceLen > TRACE_SIZE) break;

		    //triggered = TRUE;

		    // And ready to receive another response.
		    memset(&Demod, 0, sizeof(Demod));
		    Demod.output = receivedResponse;
		    Demod.state = DEMOD_UNSYNCD;
		    LED_C_OFF();
		}
		
		div = 0;
		decbyte = 0x00;
	}
	//}

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

void rotateCSN(uint8_t* originalCSN, uint8_t* rotatedCSN) {
	int i; 
	for(i = 0; i < 8; i++) {
		rotatedCSN[i] = (originalCSN[i] >> 3) | (originalCSN[(i+1)%8] << 5);
	}
}

//-----------------------------------------------------------------------------
// Wait for commands from reader
// Stop when button is pressed
// Or return TRUE when command is captured
//-----------------------------------------------------------------------------
static int GetIClassCommandFromReader(uint8_t *received, int *len, int maxLen)
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
			/*if(OutOfNDecoding((b & 0xf0) >> 4)) {
				*len = Uart.byteCnt;
				return TRUE;
			}*/
			if(OutOfNDecoding(b & 0x0f)) {
				*len = Uart.byteCnt;
				return TRUE;
			}
        }
    }
}


//-----------------------------------------------------------------------------
// Prepare tag messages
//-----------------------------------------------------------------------------
static void CodeIClassTagAnswer(const uint8_t *cmd, int len)
{
	int i;

	ToSendReset();

	// Send SOF
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0xff;
	ToSend[++ToSendMax] = 0xff;
	ToSend[++ToSendMax] = 0xff;
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0xff;

	for(i = 0; i < len; i++) {
		int j;
		uint8_t b = cmd[i];

		// Data bits
		for(j = 0; j < 8; j++) {
			if(b & 1) {
				ToSend[++ToSendMax] = 0x00;
				ToSend[++ToSendMax] = 0xff;
			} else {
				ToSend[++ToSendMax] = 0xff;
				ToSend[++ToSendMax] = 0x00;
			}
			b >>= 1;
		}
	}

	// Send EOF
	ToSend[++ToSendMax] = 0xff;
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0xff;
	ToSend[++ToSendMax] = 0xff;
	ToSend[++ToSendMax] = 0xff;
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0x00;

	// Convert from last byte pos to length
	ToSendMax++;
}

// Only SOF 
static void CodeIClassTagSOF()
{
	ToSendReset();

	// Send SOF
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0xff;
	ToSend[++ToSendMax] = 0xff;
	ToSend[++ToSendMax] = 0xff;
	ToSend[++ToSendMax] = 0x00;
	ToSend[++ToSendMax] = 0xff;
	
	// Convert from last byte pos to length
	ToSendMax++;
}

//-----------------------------------------------------------------------------
// Simulate iClass Card
// Only CSN (Card Serial Number)
// 
//-----------------------------------------------------------------------------
void SimulateIClass(uint8_t arg0, uint8_t *datain)
{
	uint8_t simType = arg0;

  // Enable and clear the trace
	tracing = TRUE;
	traceLen = 0;
  memset(trace, 0x44, TRACE_SIZE);

	// CSN followed by two CRC bytes
	uint8_t response2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t response3[] = { 0x03, 0x1f, 0xec, 0x8a, 0xf7, 0xff, 0x12, 0xe0, 0x00, 0x00 };

	// e-Purse
	uint8_t response4[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	if(simType == 0) {
		// Use the CSN from commandline
		memcpy(response3, datain, 8);
	}

	// Construct anticollision-CSN
	rotateCSN(response3,response2);

	// Compute CRC on both CSNs
	ComputeCrc14443(CRC_ICLASS, response2, 8, &response2[8], &response2[9]);
	ComputeCrc14443(CRC_ICLASS, response3, 8, &response3[8], &response3[9]);

	// Reader 0a
	// Tag    0f
	// Reader 0c
	// Tag    anticoll. CSN
	// Reader 81 anticoll. CSN
	// Tag    CSN

	uint8_t *resp;
	int respLen;
	uint8_t* respdata = NULL;
	int respsize = 0;
	uint8_t sof = 0x0f;

	// Respond SOF -- takes 8 bytes
	uint8_t *resp1 = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET);
	int resp1Len;

	// Anticollision CSN (rotated CSN)
	// 176: Takes 16 bytes for SOF/EOF and 10 * 16 = 160 bytes (2 bytes/bit)
	uint8_t *resp2 = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET + 10);
	int resp2Len;

	// CSN
	// 176: Takes 16 bytes for SOF/EOF and 10 * 16 = 160 bytes (2 bytes/bit)
	uint8_t *resp3 = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET + 190);
	int resp3Len;

	// e-Purse
	// 144: Takes 16 bytes for SOF/EOF and 8 * 16 = 128 bytes (2 bytes/bit)
	uint8_t *resp4 = (((uint8_t *)BigBuf) + FREE_BUFFER_OFFSET + 370);
	int resp4Len;

	// + 1720..
  uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
	memset(receivedCmd, 0x44, RECV_CMD_SIZE);
	int len;

	// Prepare card messages
	ToSendMax = 0;

	// First card answer: SOF
	CodeIClassTagSOF();
	memcpy(resp1, ToSend, ToSendMax); resp1Len = ToSendMax;

	// Anticollision CSN
	CodeIClassTagAnswer(response2, sizeof(response2));
	memcpy(resp2, ToSend, ToSendMax); resp2Len = ToSendMax;

	// CSN
	CodeIClassTagAnswer(response3, sizeof(response3));
	memcpy(resp3, ToSend, ToSendMax); resp3Len = ToSendMax;

	// e-Purse
	CodeIClassTagAnswer(response4, sizeof(response4));
	memcpy(resp4, ToSend, ToSendMax); resp4Len = ToSendMax;

	// We need to listen to the high-frequency, peak-detected path.
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc();

	// To control where we are in the protocol
	int cmdsRecvd = 0;

	LED_A_ON();
	for(;;) {
		LED_B_OFF();
		if(!GetIClassCommandFromReader(receivedCmd, &len, 100)) {
			DbpString("button press");
			break;
		}

		// Okay, look at the command now.
		if(receivedCmd[0] == 0x0a) {
			// Reader in anticollission phase
			resp = resp1; respLen = resp1Len; //order = 1;
			respdata = &sof;
			respsize = sizeof(sof);
			//resp = resp2; respLen = resp2Len; order = 2;
			//DbpString("Hello request from reader:");
		} else if(receivedCmd[0] == 0x0c) {
			// Reader asks for anticollission CSN
			resp = resp2; respLen = resp2Len; //order = 2;
			respdata = response2;
			respsize = sizeof(response2);
			//DbpString("Reader requests anticollission CSN:");
		} else if(receivedCmd[0] == 0x81) {
			// Reader selects anticollission CSN.
			// Tag sends the corresponding real CSN
			resp = resp3; respLen = resp3Len; //order = 3;
			respdata = response3;
			respsize = sizeof(response3);
			//DbpString("Reader selects anticollission CSN:");
		} else if(receivedCmd[0] == 0x88) {
			// Read e-purse (88 02)
			resp = resp4; respLen = resp4Len; //order = 4;
			respdata = response4;
			respsize = sizeof(response4);
			LED_B_ON();
		} else if(receivedCmd[0] == 0x05) {
			// Reader random and reader MAC!!!
			// Lets store this ;-)
/*
			Dbprintf("                CSN: %02x %02x %02x %02x %02x %02x %02x %02x",
			response3[0], response3[1], response3[2],
			response3[3], response3[4], response3[5],
			response3[6], response3[7]);
*/			
			Dbprintf("READER AUTH (len=%02d): %02x %02x %02x %02x %02x %02x %02x %02x %02x",
			len,
			receivedCmd[0], receivedCmd[1], receivedCmd[2],
			receivedCmd[3], receivedCmd[4], receivedCmd[5],
			receivedCmd[6], receivedCmd[7], receivedCmd[8]);

			// Do not respond
			// We do not know what to answer, so lets keep quit
			resp = resp1; respLen = 0; //order = 5;
			respdata = NULL;
			respsize = 0;
		} else if(receivedCmd[0] == 0x00 && len == 1) {
			// Reader ends the session
			resp = resp1; respLen = 0; //order = 0;
			respdata = NULL;
			respsize = 0;
		} else {
			// Never seen this command before
			Dbprintf("Unknown command received from reader (len=%d): %x %x %x %x %x %x %x %x %x",
			len,
			receivedCmd[0], receivedCmd[1], receivedCmd[2],
			receivedCmd[3], receivedCmd[4], receivedCmd[5],
			receivedCmd[6], receivedCmd[7], receivedCmd[8]);
			// Do not respond
			resp = resp1; respLen = 0; //order = 0;
			respdata = NULL;
			respsize = 0;
		}

		if(cmdsRecvd > 999) {
			DbpString("1000 commands later...");
			break;
		}
		else {
			cmdsRecvd++;
		}

		if(respLen > 0) {
			SendIClassAnswer(resp, respLen, 21);
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

	Dbprintf("%x", cmdsRecvd);
	LED_A_OFF();
	LED_B_OFF();
}

static int SendIClassAnswer(uint8_t *resp, int respLen, int delay)
{
	int i = 0, u = 0, d = 0;
	uint8_t b = 0;
	// return 0;
	// Modulate Manchester
	// FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_MOD424);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_MOD);
	AT91C_BASE_SSC->SSC_THR = 0x00;
	FpgaSetupSsc();
	
	// send cycle
	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			volatile uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			(void)b;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			if(d < delay) {
				b = 0x00;
				d++;
			}
			else if(i >= respLen) {
				b = 0x00;
				u++;
			} else {
				b = resp[i];
				u++;
				if(u > 1) { i++; u = 0; }
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

/// THE READER CODE

//-----------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
//-----------------------------------------------------------------------------
static void TransmitIClassCommand(const uint8_t *cmd, int len, int *samples, int *wait)
{
  int c;

  FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);
  AT91C_BASE_SSC->SSC_THR = 0x00;
  FpgaSetupSsc();

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

  uint8_t sendbyte;
  bool firstpart = TRUE;
  c = 0;
  for(;;) {
    if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {

      // DOUBLE THE SAMPLES!
      if(firstpart) {
	sendbyte = (cmd[c] & 0xf0) | (cmd[c] >> 4); 
      }
      else {
	sendbyte = (cmd[c] & 0x0f) | (cmd[c] << 4);
        c++;
      }
      if(sendbyte == 0xff) {
	sendbyte = 0xfe;
      }
      AT91C_BASE_SSC->SSC_THR = sendbyte;
      firstpart = !firstpart;

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
// Prepare iClass reader command to send to FPGA
//-----------------------------------------------------------------------------
void CodeIClassCommand(const uint8_t * cmd, int len)
{
  int i, j, k;
  uint8_t b;

  ToSendReset();

  // Start of Communication: 1 out of 4
  ToSend[++ToSendMax] = 0xf0;
  ToSend[++ToSendMax] = 0x00;
  ToSend[++ToSendMax] = 0x0f;
  ToSend[++ToSendMax] = 0x00;

  // Modulate the bytes 
  for (i = 0; i < len; i++) {
    b = cmd[i];
    for(j = 0; j < 4; j++) {
      for(k = 0; k < 4; k++) {
	if(k == (b & 3)) {
	    ToSend[++ToSendMax] = 0x0f;
	}
	else {
	    ToSend[++ToSendMax] = 0x00;
	}
      }
      b >>= 2;
    }
  }

  // End of Communication
  ToSend[++ToSendMax] = 0x00;
  ToSend[++ToSendMax] = 0x00;
  ToSend[++ToSendMax] = 0xf0;
  ToSend[++ToSendMax] = 0x00;

  // Convert from last character reference to length
  ToSendMax++;
}

void ReaderTransmitIClass(uint8_t* frame, int len)
{
  int wait = 0;
  int samples = 0;
  int par = 0;

  // This is tied to other size changes
  // 	uint8_t* frame_addr = ((uint8_t*)BigBuf) + 2024;
  CodeIClassCommand(frame,len);

  // Select the card
  TransmitIClassCommand(ToSend, ToSendMax, &samples, &wait);
  if(trigger)
  	LED_A_ON();

  // Store reader command in buffer
  if (tracing) LogTrace(frame,len,0,par,TRUE);
}

//-----------------------------------------------------------------------------
// Wait a certain time for tag response
//  If a response is captured return TRUE
//  If it takes too long return FALSE
//-----------------------------------------------------------------------------
static int GetIClassAnswer(uint8_t *receivedResponse, int maxLen, int *samples, int *elapsed) //uint8_t *buffer
{
	// buffer needs to be 512 bytes
	int c;

	// Set FPGA mode to "reader listen mode", no modulation (listen
	// only, since we are receiving, not transmitting).
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_LISTEN);

	// Now get the answer from the card
	Demod.output = receivedResponse;
	Demod.len = 0;
	Demod.state = DEMOD_UNSYNCD;

	uint8_t b;
	if (elapsed) *elapsed = 0;

	bool skip = FALSE;

	c = 0;
	for(;;) {
		WDT_HIT();

	        if(BUTTON_PRESS()) return FALSE;

		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0x00;  // To make use of exact timing of next command from reader!!
			if (elapsed) (*elapsed)++;
		}
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			if(c < timeout) { c++; } else { return FALSE; }
			b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			skip = !skip;
			if(skip) continue;
			/*if(ManchesterDecoding((b>>4) & 0xf)) {
				*samples = ((c - 1) << 3) + 4;
				return TRUE;
			}*/
			if(ManchesterDecoding(b & 0x0f)) {
				*samples = c << 3;
				return  TRUE;
			}
		}
	}
}

int ReaderReceiveIClass(uint8_t* receivedAnswer)
{
  int samples = 0;
  if (!GetIClassAnswer(receivedAnswer,160,&samples,0)) return FALSE;
  if (tracing) LogTrace(receivedAnswer,Demod.len,samples,Demod.parityBits,FALSE);
  if(samples == 0) return FALSE;
  return Demod.len;
}

// Reader iClass Anticollission
void ReaderIClass(uint8_t arg0) {
	uint8_t act_all[]     = { 0x0a };
	uint8_t identify[]    = { 0x0c };
	uint8_t select[]      = { 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	uint8_t* resp = (((uint8_t *)BigBuf) + 3560);	// was 3560 - tied to other size changes

	// Reset trace buffer
    	memset(trace, 0x44, RECV_CMD_OFFSET);
	traceLen = 0;

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
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);
	SpinDelay(200);

	LED_A_ON();

	for(;;) {
	
		if(traceLen > TRACE_SIZE) {
			DbpString("Trace full");
			break;
		}
		
		if (BUTTON_PRESS()) break;

		// Send act_all
		ReaderTransmitIClass(act_all, 1);
		// Card present?
		if(ReaderReceiveIClass(resp)) {
			ReaderTransmitIClass(identify, 1);
			if(ReaderReceiveIClass(resp) == 10) {
				// Select card          
				memcpy(&select[1],resp,8);
				ReaderTransmitIClass(select, sizeof(select));

				if(ReaderReceiveIClass(resp) == 10) {
					Dbprintf("     Selected CSN: %02x %02x %02x %02x %02x %02x %02x %02x",
					resp[0], resp[1], resp[2],
					resp[3], resp[4], resp[5],
					resp[6], resp[7]);
				}
				// Card selected, whats next... ;-)
			}
		}
		WDT_HIT();
	}
	
	LED_A_OFF();
}


