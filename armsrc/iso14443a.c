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
#include "iso14443a.h"

static uint32_t iso14a_timeout;
int rsamples = 0;
uint8_t trigger = 0;
// the block number for the ISO14443-4 PCB
static uint8_t iso14_pcb_blocknum = 0;

static uint8_t* free_buffer_pointer;

//
// ISO14443 timing:
//
// minimum time between the start bits of consecutive transfers from reader to tag: 7000 carrier (13.56Mhz) cycles
#define REQUEST_GUARD_TIME (7000/16 + 1)
// minimum time between last modulation of tag and next start bit from reader to tag: 1172 carrier cycles 
#define FRAME_DELAY_TIME_PICC_TO_PCD (1172/16 + 1) 
// bool LastCommandWasRequest = FALSE;

//
// Total delays including SSC-Transfers between ARM and FPGA. These are in carrier clock cycles (1/13,56MHz)
//
// When the PM acts as reader and is receiving tag data, it takes
// 3 ticks delay in the AD converter
// 16 ticks until the modulation detector completes and sets curbit
// 8 ticks until bit_to_arm is assigned from curbit
// 8*16 ticks for the transfer from FPGA to ARM
// 4*16 ticks until we measure the time
// - 8*16 ticks because we measure the time of the previous transfer 
#define DELAY_AIR2ARM_AS_READER (3 + 16 + 8 + 8*16 + 4*16 - 8*16) 

// When the PM acts as a reader and is sending, it takes
// 4*16 ticks until we can write data to the sending hold register
// 8*16 ticks until the SHR is transferred to the Sending Shift Register
// 8 ticks until the first transfer starts
// 8 ticks later the FPGA samples the data
// 1 tick to assign mod_sig_coil
#define DELAY_ARM2AIR_AS_READER (4*16 + 8*16 + 8 + 8 + 1)

// When the PM acts as tag and is receiving it takes
// 2 ticks delay in the RF part (for the first falling edge),
// 3 ticks for the A/D conversion,
// 8 ticks on average until the start of the SSC transfer,
// 8 ticks until the SSC samples the first data
// 7*16 ticks to complete the transfer from FPGA to ARM
// 8 ticks until the next ssp_clk rising edge
// 4*16 ticks until we measure the time 
// - 8*16 ticks because we measure the time of the previous transfer 
#define DELAY_AIR2ARM_AS_TAG (2 + 3 + 8 + 8 + 7*16 + 8 + 4*16 - 8*16)
 
// The FPGA will report its internal sending delay in
uint16_t FpgaSendQueueDelay;
// the 5 first bits are the number of bits buffered in mod_sig_buf
// the last three bits are the remaining ticks/2 after the mod_sig_buf shift
#define DELAY_FPGA_QUEUE (FpgaSendQueueDelay<<1)

// When the PM acts as tag and is sending, it takes
// 4*16 ticks until we can write data to the sending hold register
// 8*16 ticks until the SHR is transferred to the Sending Shift Register
// 8 ticks until the first transfer starts
// 8 ticks later the FPGA samples the data
// + a varying number of ticks in the FPGA Delay Queue (mod_sig_buf)
// + 1 tick to assign mod_sig_coil
#define DELAY_ARM2AIR_AS_TAG (4*16 + 8*16 + 8 + 8 + DELAY_FPGA_QUEUE + 1)

// When the PM acts as sniffer and is receiving tag data, it takes
// 3 ticks A/D conversion
// 14 ticks to complete the modulation detection
// 8 ticks (on average) until the result is stored in to_arm
// + the delays in transferring data - which is the same for
// sniffing reader and tag data and therefore not relevant
#define DELAY_TAG_AIR2ARM_AS_SNIFFER (3 + 14 + 8) 
 
// When the PM acts as sniffer and is receiving reader data, it takes
// 2 ticks delay in analogue RF receiver (for the falling edge of the 
// start bit, which marks the start of the communication)
// 3 ticks A/D conversion
// 8 ticks on average until the data is stored in to_arm.
// + the delays in transferring data - which is the same for
// sniffing reader and tag data and therefore not relevant
#define DELAY_READER_AIR2ARM_AS_SNIFFER (2 + 3 + 8) 

//variables used for timing purposes:
//these are in ssp_clk cycles:
static uint32_t NextTransferTime;
static uint32_t LastTimeProxToAirStart;
static uint32_t LastProxToAirDuration;

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

void iso14a_set_trigger(bool enable) {
	trigger = enable;
}

void iso14a_set_timeout(uint32_t timeout) {
	iso14a_timeout = timeout;
	if(MF_DBGLEVEL >= 3) Dbprintf("ISO14443A Timeout set to %ld (%dms)", iso14a_timeout, iso14a_timeout / 106);
}

void iso14a_set_ATS_timeout(uint8_t *ats) {
	uint8_t tb1;
	uint8_t fwi; 
	uint32_t fwt;
	
	if (ats[0] > 1) {							// there is a format byte T0
		if ((ats[1] & 0x20) == 0x20) {			// there is an interface byte TB(1)

			if ((ats[1] & 0x10) == 0x10)		// there is an interface byte TA(1) preceding TB(1)
				tb1 = ats[3];
			else
				tb1 = ats[2];

			fwi = (tb1 & 0xf0) >> 4;			// frame waiting indicator (FWI)
			fwt = 256 * 16 * (1 << fwi);		// frame waiting time (FWT) in 1/fc
			//fwt = 4096 * (1 << fwi);
			
			iso14a_set_timeout(fwt/(8*16));
			//iso14a_set_timeout(fwt/128);
		}
	}
}

//-----------------------------------------------------------------------------
// Generate the parity value for a byte sequence
//
//-----------------------------------------------------------------------------
void GetParity(const uint8_t *pbtCmd, uint16_t iLen, uint8_t *par) {
	uint16_t paritybit_cnt = 0;
	uint16_t paritybyte_cnt = 0;
	uint8_t parityBits = 0;

	for (uint16_t i = 0; i < iLen; i++) {
		// Generate the parity bits
		parityBits |= ((oddparity8(pbtCmd[i])) << (7-paritybit_cnt));
		if (paritybit_cnt == 7) {
			par[paritybyte_cnt] = parityBits;	// save 8 Bits parity
			parityBits = 0;						// and advance to next Parity Byte
			paritybyte_cnt++;
			paritybit_cnt = 0;
		} else {
			paritybit_cnt++;
		}
	}

	// save remaining parity bits
	par[paritybyte_cnt] = parityBits;	
}

void AppendCrc14443a(uint8_t* data, int len) {
	ComputeCrc14443(CRC_14443_A,data,len,data+len,data+len+1);
}

//=============================================================================
// ISO 14443 Type A - Miller decoder
//=============================================================================
// Basics:
// This decoder is used when the PM3 acts as a tag.
// The reader will generate "pauses" by temporarily switching of the field. 
// At the PM3 antenna we will therefore measure a modulated antenna voltage. 
// The FPGA does a comparison with a threshold and would deliver e.g.:
// ........  1 1 1 1 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 0 1 1 1 1 1 1 1 1 1 1  .......
// The Miller decoder needs to identify the following sequences:
// 2 (or 3) ticks pause followed by 6 (or 5) ticks unmodulated: 	pause at beginning - Sequence Z ("start of communication" or a "0")
// 8 ticks without a modulation: 									no pause - Sequence Y (a "0" or "end of communication" or "no information")
// 4 ticks unmodulated followed by 2 (or 3) ticks pause:			pause in second half - Sequence X (a "1")
// Note 1: the bitstream may start at any time. We therefore need to sync.
// Note 2: the interpretation of Sequence Y and Z depends on the preceding sequence.
//-----------------------------------------------------------------------------
static tUart Uart;

// Lookup-Table to decide if 4 raw bits are a modulation.
// We accept the following:
// 0001  -   a 3 tick wide pause
// 0011  -   a 2 tick wide pause, or a three tick wide pause shifted left
// 0111  -   a 2 tick wide pause shifted left
// 1001  -   a 2 tick wide pause shifted right
const bool Mod_Miller_LUT[] = {
	FALSE,  TRUE, FALSE, TRUE,  FALSE, FALSE, FALSE, TRUE,
	FALSE,  TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE
};
#define IsMillerModulationNibble1(b) (Mod_Miller_LUT[(b & 0x000000F0) >> 4])
#define IsMillerModulationNibble2(b) (Mod_Miller_LUT[(b & 0x0000000F)])

void UartReset() {
	Uart.state = STATE_UNSYNCD;
	Uart.bitCount = 0;
	Uart.len = 0;						// number of decoded data bytes
	Uart.parityLen = 0;					// number of decoded parity bytes
	Uart.shiftReg = 0;					// shiftreg to hold decoded data bits
	Uart.parityBits = 0;				// holds 8 parity bits
	Uart.startTime = 0;
	Uart.endTime = 0;
	
	Uart.byteCntMax = 0;
	Uart.posCnt = 0;
	Uart.syncBit = 9999;
}

void UartInit(uint8_t *data, uint8_t *parity) {
	Uart.output = data;
	Uart.parity = parity;
	Uart.fourBits = 0x00000000;			// clear the buffer for 4 Bits
	UartReset();
}

// use parameter non_real_time to provide a timestamp. Set to 0 if the decoder should measure real time
static RAMFUNC bool MillerDecoding(uint8_t bit, uint32_t non_real_time) {
	Uart.fourBits = (Uart.fourBits << 8) | bit;
	
	if (Uart.state == STATE_UNSYNCD) {											// not yet synced
			Uart.syncBit = 9999; 												// not set
		
		// 00x11111 2|3 ticks pause followed by 6|5 ticks unmodulated	 	Sequence Z (a "0" or "start of communication")
		// 11111111 8 ticks unmodulation									Sequence Y (a "0" or "end of communication" or "no information")
		// 111100x1 4 ticks unmodulated followed by 2|3 ticks pause			Sequence X (a "1")

		// The start bit is one ore more Sequence Y followed by a Sequence Z (... 11111111 00x11111). We need to distinguish from
		// Sequence X followed by Sequence Y followed by Sequence Z     (111100x1 11111111 00x11111)
		// we therefore look for a ...xx1111 11111111 00x11111xxxxxx... pattern 
		// (12 '1's followed by 2 '0's, eventually followed by another '0', followed by 5 '1's)
		//
#define ISO14443A_STARTBIT_MASK		0x07FFEF80		// mask is    00001111 11111111 1110 1111 10000000
#define ISO14443A_STARTBIT_PATTERN	0x07FF8F80		// pattern is 00001111 11111111 1000 1111 10000000

		if		((Uart.fourBits & (ISO14443A_STARTBIT_MASK >> 0)) == ISO14443A_STARTBIT_PATTERN >> 0) Uart.syncBit = 7;
		else if ((Uart.fourBits & (ISO14443A_STARTBIT_MASK >> 1)) == ISO14443A_STARTBIT_PATTERN >> 1) Uart.syncBit = 6;
		else if ((Uart.fourBits & (ISO14443A_STARTBIT_MASK >> 2)) == ISO14443A_STARTBIT_PATTERN >> 2) Uart.syncBit = 5;
		else if ((Uart.fourBits & (ISO14443A_STARTBIT_MASK >> 3)) == ISO14443A_STARTBIT_PATTERN >> 3) Uart.syncBit = 4;
		else if ((Uart.fourBits & (ISO14443A_STARTBIT_MASK >> 4)) == ISO14443A_STARTBIT_PATTERN >> 4) Uart.syncBit = 3;
		else if ((Uart.fourBits & (ISO14443A_STARTBIT_MASK >> 5)) == ISO14443A_STARTBIT_PATTERN >> 5) Uart.syncBit = 2;
		else if ((Uart.fourBits & (ISO14443A_STARTBIT_MASK >> 6)) == ISO14443A_STARTBIT_PATTERN >> 6) Uart.syncBit = 1;
		else if ((Uart.fourBits & (ISO14443A_STARTBIT_MASK >> 7)) == ISO14443A_STARTBIT_PATTERN >> 7) Uart.syncBit = 0;

		if (Uart.syncBit != 9999) {												// found a sync bit
			Uart.startTime = non_real_time ? non_real_time : (GetCountSspClk() & 0xfffffff8);
			Uart.startTime -= Uart.syncBit;
			Uart.endTime = Uart.startTime;
			Uart.state = STATE_START_OF_COMMUNICATION;
		}
	} else {

		if (IsMillerModulationNibble1(Uart.fourBits >> Uart.syncBit)) {			
			if (IsMillerModulationNibble2(Uart.fourBits >> Uart.syncBit)) {		// Modulation in both halves - error
				UartReset();
			} else {															// Modulation in first half = Sequence Z = logic "0"
				if (Uart.state == STATE_MILLER_X) {								// error - must not follow after X
					UartReset();
				} else {
					Uart.bitCount++;
					Uart.shiftReg = (Uart.shiftReg >> 1);						// add a 0 to the shiftreg
					Uart.state = STATE_MILLER_Z;
					Uart.endTime = Uart.startTime + 8*(9*Uart.len + Uart.bitCount + 1) - 6;
					if(Uart.bitCount >= 9) {									// if we decoded a full byte (including parity)
						Uart.output[Uart.len++] = (Uart.shiftReg & 0xff);
						Uart.parityBits <<= 1;									// make room for the parity bit
						Uart.parityBits |= ((Uart.shiftReg >> 8) & 0x01);		// store parity bit
						Uart.bitCount = 0;
						Uart.shiftReg = 0;
						if((Uart.len&0x0007) == 0) {							// every 8 data bytes
							Uart.parity[Uart.parityLen++] = Uart.parityBits;	// store 8 parity bits
							Uart.parityBits = 0;
						}
					}
				}
			}
		} else {
			if (IsMillerModulationNibble2(Uart.fourBits >> Uart.syncBit)) {		// Modulation second half = Sequence X = logic "1"
				Uart.bitCount++;
				Uart.shiftReg = (Uart.shiftReg >> 1) | 0x100;					// add a 1 to the shiftreg
				Uart.state = STATE_MILLER_X;
				Uart.endTime = Uart.startTime + 8*(9*Uart.len + Uart.bitCount + 1) - 2;
				if(Uart.bitCount >= 9) {										// if we decoded a full byte (including parity)
					Uart.output[Uart.len++] = (Uart.shiftReg & 0xff);
					Uart.parityBits <<= 1;										// make room for the new parity bit
					Uart.parityBits |= ((Uart.shiftReg >> 8) & 0x01); 			// store parity bit
					Uart.bitCount = 0;
					Uart.shiftReg = 0;
					if ((Uart.len&0x0007) == 0) {								// every 8 data bytes
						Uart.parity[Uart.parityLen++] = Uart.parityBits;		// store 8 parity bits
						Uart.parityBits = 0;
					}
				}
			} else {															// no modulation in both halves - Sequence Y
				if (Uart.state == STATE_MILLER_Z || Uart.state == STATE_MILLER_Y) {	// Y after logic "0" - End of Communication
					Uart.state = STATE_UNSYNCD;
					Uart.bitCount--;											// last "0" was part of EOC sequence
					Uart.shiftReg <<= 1;										// drop it
					if(Uart.bitCount > 0) {										// if we decoded some bits
						Uart.shiftReg >>= (9 - Uart.bitCount);					// right align them
						Uart.output[Uart.len++] = (Uart.shiftReg & 0xff);		// add last byte to the output
						Uart.parityBits <<= 1;									// add a (void) parity bit
						Uart.parityBits <<= (8 - (Uart.len&0x0007));			// left align parity bits
						Uart.parity[Uart.parityLen++] = Uart.parityBits;		// and store it
						return TRUE;
					} else if (Uart.len & 0x0007) {								// there are some parity bits to store
						Uart.parityBits <<= (8 - (Uart.len&0x0007));			// left align remaining parity bits
						Uart.parity[Uart.parityLen++] = Uart.parityBits;		// and store them
					}
					if (Uart.len) {
						return TRUE;											// we are finished with decoding the raw data sequence
					} else {
						UartReset();											// Nothing received - start over
					}
				}
				if (Uart.state == STATE_START_OF_COMMUNICATION) {				// error - must not follow directly after SOC
					UartReset();
				} else {														// a logic "0"
					Uart.bitCount++;
					Uart.shiftReg = (Uart.shiftReg >> 1);						// add a 0 to the shiftreg
					Uart.state = STATE_MILLER_Y;
					if(Uart.bitCount >= 9) {									// if we decoded a full byte (including parity)
						Uart.output[Uart.len++] = (Uart.shiftReg & 0xff);
						Uart.parityBits <<= 1;									// make room for the parity bit
						Uart.parityBits |= ((Uart.shiftReg >> 8) & 0x01); 		// store parity bit
						Uart.bitCount = 0;
						Uart.shiftReg = 0;
						if ((Uart.len&0x0007) == 0) {							// every 8 data bytes
							Uart.parity[Uart.parityLen++] = Uart.parityBits;	// store 8 parity bits
							Uart.parityBits = 0;
						}
					}
				}
			}
		}
	} 
    return FALSE;	// not finished yet, need more data
}

//=============================================================================
// ISO 14443 Type A - Manchester decoder
//=============================================================================
// Basics:
// This decoder is used when the PM3 acts as a reader.
// The tag will modulate the reader field by asserting different loads to it. As a consequence, the voltage
// at the reader antenna will be modulated as well. The FPGA detects the modulation for us and would deliver e.g. the following:
// ........ 0 0 1 1 1 1 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 .......
// The Manchester decoder needs to identify the following sequences:
// 4 ticks modulated followed by 4 ticks unmodulated: 	Sequence D = 1 (also used as "start of communication")
// 4 ticks unmodulated followed by 4 ticks modulated: 	Sequence E = 0
// 8 ticks unmodulated:									Sequence F = end of communication
// 8 ticks modulated:									A collision. Save the collision position and treat as Sequence D
// Note 1: the bitstream may start at any time. We therefore need to sync.
// Note 2: parameter offset is used to determine the position of the parity bits (required for the anticollision command only)
static tDemod Demod;

// Lookup-Table to decide if 4 raw bits are a modulation.
// We accept three or four "1" in any position
const bool Mod_Manchester_LUT[] = {
	FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, TRUE,
	FALSE, FALSE, FALSE, TRUE,  FALSE, TRUE,  TRUE,  TRUE
};

#define IsManchesterModulationNibble1(b) (Mod_Manchester_LUT[(b & 0x00F0) >> 4])
#define IsManchesterModulationNibble2(b) (Mod_Manchester_LUT[(b & 0x000F)])

void DemodReset() {
	Demod.state = DEMOD_UNSYNCD;
	Demod.len = 0;						// number of decoded data bytes
	Demod.parityLen = 0;
	Demod.shiftReg = 0;					// shiftreg to hold decoded data bits
	Demod.parityBits = 0;				// 
	Demod.collisionPos = 0;				// Position of collision bit
	Demod.twoBits = 0xffff;				// buffer for 2 Bits
	Demod.highCnt = 0;
	Demod.startTime = 0;
	Demod.endTime = 0;	
	Demod.bitCount = 0;
	Demod.syncBit = 0xFFFF;
	Demod.samples = 0;
}

void DemodInit(uint8_t *data, uint8_t *parity) {
	Demod.output = data;
	Demod.parity = parity;
	DemodReset();
}

// use parameter non_real_time to provide a timestamp. Set to 0 if the decoder should measure real time
static RAMFUNC int ManchesterDecoding(uint8_t bit, uint16_t offset, uint32_t non_real_time) {
	Demod.twoBits = (Demod.twoBits << 8) | bit;
	
	if (Demod.state == DEMOD_UNSYNCD) {

		if (Demod.highCnt < 2) {											// wait for a stable unmodulated signal
			if (Demod.twoBits == 0x0000) {
				Demod.highCnt++;
			} else {
				Demod.highCnt = 0;
			}
		} else {
			Demod.syncBit = 0xFFFF;			// not set
			if 		((Demod.twoBits & 0x7700) == 0x7000) Demod.syncBit = 7; 
			else if ((Demod.twoBits & 0x3B80) == 0x3800) Demod.syncBit = 6;
			else if ((Demod.twoBits & 0x1DC0) == 0x1C00) Demod.syncBit = 5;
			else if ((Demod.twoBits & 0x0EE0) == 0x0E00) Demod.syncBit = 4;
			else if ((Demod.twoBits & 0x0770) == 0x0700) Demod.syncBit = 3;
			else if ((Demod.twoBits & 0x03B8) == 0x0380) Demod.syncBit = 2;
			else if ((Demod.twoBits & 0x01DC) == 0x01C0) Demod.syncBit = 1;
			else if ((Demod.twoBits & 0x00EE) == 0x00E0) Demod.syncBit = 0;
			if (Demod.syncBit != 0xFFFF) {
				Demod.startTime = non_real_time?non_real_time:(GetCountSspClk() & 0xfffffff8);
				Demod.startTime -= Demod.syncBit;
				Demod.bitCount = offset;			// number of decoded data bits
				Demod.state = DEMOD_MANCHESTER_DATA;
			}
		}
	} else {

		if (IsManchesterModulationNibble1(Demod.twoBits >> Demod.syncBit)) {		// modulation in first half
			if (IsManchesterModulationNibble2(Demod.twoBits >> Demod.syncBit)) {	// ... and in second half = collision
				if (!Demod.collisionPos) {
					Demod.collisionPos = (Demod.len << 3) + Demod.bitCount;
				}
			}															// modulation in first half only - Sequence D = 1
			Demod.bitCount++;
			Demod.shiftReg = (Demod.shiftReg >> 1) | 0x100;				// in both cases, add a 1 to the shiftreg
			if(Demod.bitCount == 9) {									// if we decoded a full byte (including parity)
				Demod.output[Demod.len++] = (Demod.shiftReg & 0xff);
				Demod.parityBits <<= 1;									// make room for the parity bit
				Demod.parityBits |= ((Demod.shiftReg >> 8) & 0x01); 	// store parity bit
				Demod.bitCount = 0;
				Demod.shiftReg = 0;
				if((Demod.len&0x0007) == 0) {							// every 8 data bytes
					Demod.parity[Demod.parityLen++] = Demod.parityBits;	// store 8 parity bits
					Demod.parityBits = 0;
				}
			}
			Demod.endTime = Demod.startTime + 8*(9*Demod.len + Demod.bitCount + 1) - 4;
		} else {														// no modulation in first half
			if (IsManchesterModulationNibble2(Demod.twoBits >> Demod.syncBit)) {	// and modulation in second half = Sequence E = 0
				Demod.bitCount++;
				Demod.shiftReg = (Demod.shiftReg >> 1);					// add a 0 to the shiftreg
				if(Demod.bitCount >= 9) {								// if we decoded a full byte (including parity)
					Demod.output[Demod.len++] = (Demod.shiftReg & 0xff);
					Demod.parityBits <<= 1;								// make room for the new parity bit
					Demod.parityBits |= ((Demod.shiftReg >> 8) & 0x01); // store parity bit
					Demod.bitCount = 0;
					Demod.shiftReg = 0;
					if ((Demod.len&0x0007) == 0) {						// every 8 data bytes
						Demod.parity[Demod.parityLen++] = Demod.parityBits;	// store 8 parity bits1
						Demod.parityBits = 0;
					}
				}
				Demod.endTime = Demod.startTime + 8*(9*Demod.len + Demod.bitCount + 1);
			} else {													// no modulation in both halves - End of communication
				if(Demod.bitCount > 0) {								// there are some remaining data bits
					Demod.shiftReg >>= (9 - Demod.bitCount);			// right align the decoded bits
					Demod.output[Demod.len++] = Demod.shiftReg & 0xff;	// and add them to the output
					Demod.parityBits <<= 1;								// add a (void) parity bit
					Demod.parityBits <<= (8 - (Demod.len&0x0007));		// left align remaining parity bits
					Demod.parity[Demod.parityLen++] = Demod.parityBits;	// and store them
					return TRUE;
				} else if (Demod.len & 0x0007) {						// there are some parity bits to store
					Demod.parityBits <<= (8 - (Demod.len&0x0007));		// left align remaining parity bits
					Demod.parity[Demod.parityLen++] = Demod.parityBits;	// and store them
				}
				if (Demod.len) {
					return TRUE;										// we are finished with decoding the raw data sequence
				} else { 												// nothing received. Start over
					DemodReset();
				}
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
// "hf 14a sniff"
//-----------------------------------------------------------------------------
void RAMFUNC SniffIso14443a(uint8_t param) {
	// param:
	// bit 0 - trigger from first card answer
	// bit 1 - trigger from first reader 7-bit request
	LEDsoff();

	iso14443a_setup(FPGA_HF_ISO14443A_SNIFFER);
	
	// Allocate memory from BigBuf for some buffers
	// free all previous allocations first
	BigBuf_free(); BigBuf_Clear_ext(false);
	clear_trace();
	set_tracing(TRUE);
	
	// The command (reader -> tag) that we're receiving.
	uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);
	uint8_t *receivedCmdPar = BigBuf_malloc(MAX_PARITY_SIZE);
	
	// The response (tag -> reader) that we're receiving.
	uint8_t *receivedResponse = BigBuf_malloc(MAX_FRAME_SIZE);
	uint8_t *receivedResponsePar = BigBuf_malloc(MAX_PARITY_SIZE);
	
	// The DMA buffer, used to stream samples from the FPGA
	uint8_t *dmaBuf = BigBuf_malloc(DMA_BUFFER_SIZE);

	uint8_t *data = dmaBuf;
	uint8_t previous_data = 0;
	int maxDataLen = 0;
	int dataLen = 0;
	bool TagIsActive = FALSE;
	bool ReaderIsActive = FALSE;
	
	// Set up the demodulator for tag -> reader responses.
	DemodInit(receivedResponse, receivedResponsePar);
	
	// Set up the demodulator for the reader -> tag commands
	UartInit(receivedCmd, receivedCmdPar);
	
	// Setup and start DMA.
	if ( !FpgaSetupSscDma((uint8_t*) dmaBuf, DMA_BUFFER_SIZE) ){
		if (MF_DBGLEVEL > 1) Dbprintf("FpgaSetupSscDma failed. Exiting"); 
		return;
	}
	
	// We won't start recording the frames that we acquire until we trigger;
	// a good trigger condition to get started is probably when we see a
	// response from the tag.
	// triggered == FALSE -- to wait first for card
	bool triggered = !(param & 0x03); 
	
	// And now we loop, receiving samples.
	for(uint32_t rsamples = 0; TRUE; ) {

		if(BUTTON_PRESS()) {
			DbpString("cancelled by button");
			break;
		}

		LED_A_ON();
		WDT_HIT();

		int register readBufDataP = data - dmaBuf;
		int register dmaBufDataP = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR;
		if (readBufDataP <= dmaBufDataP){
			dataLen = dmaBufDataP - readBufDataP;
		} else {
			dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP;
		}
		// test for length of buffer
		if(dataLen > maxDataLen) {
			maxDataLen = dataLen;
			if(dataLen > (9 * DMA_BUFFER_SIZE / 10)) {
				Dbprintf("blew circular buffer! dataLen=%d", dataLen);
				break;
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
		
		if (rsamples & 0x01) {				// Need two samples to feed Miller and Manchester-Decoder

			if(!TagIsActive) {		// no need to try decoding reader data if the tag is sending
				uint8_t readerdata = (previous_data & 0xF0) | (*data >> 4);
				if (MillerDecoding(readerdata, (rsamples-1)*4)) {
					LED_C_ON();

					// check - if there is a short 7bit request from reader
					if ((!triggered) && (param & 0x02) && (Uart.len == 1) && (Uart.bitCount == 7)) triggered = TRUE;

					if(triggered) {
						if (!LogTrace(receivedCmd, 
										Uart.len, 
										Uart.startTime*16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
										Uart.endTime*16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
										Uart.parity, 
										TRUE)) break;
					}
					/* And ready to receive another command. */
					UartReset();
					/* And also reset the demod code, which might have been */
					/* false-triggered by the commands from the reader. */
					DemodReset();
					LED_B_OFF();
				}
				ReaderIsActive = (Uart.state != STATE_UNSYNCD);
			}

			if(!ReaderIsActive) {		// no need to try decoding tag data if the reader is sending - and we cannot afford the time
				uint8_t tagdata = (previous_data << 4) | (*data & 0x0F);
				if(ManchesterDecoding(tagdata, 0, (rsamples-1)*4)) {
					LED_B_ON();

					if (!LogTrace(receivedResponse, 
									Demod.len, 
									Demod.startTime*16 - DELAY_TAG_AIR2ARM_AS_SNIFFER, 
									Demod.endTime*16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
									Demod.parity,
									FALSE)) break;

					if ((!triggered) && (param & 0x01)) triggered = TRUE;

					// And ready to receive another response.
					DemodReset();
					// And reset the Miller decoder including itS (now outdated) input buffer
					UartInit(receivedCmd, receivedCmdPar);
					LED_C_OFF();
				} 
				TagIsActive = (Demod.state != DEMOD_UNSYNCD);
			}
		}

		previous_data = *data;
		rsamples++;
		data++;
		if(data == dmaBuf + DMA_BUFFER_SIZE) {
			data = dmaBuf;
		}
	} // main cycle

	if (MF_DBGLEVEL >= 1) {
		Dbprintf("maxDataLen=%d, Uart.state=%x, Uart.len=%d", maxDataLen, Uart.state, Uart.len);
		Dbprintf("traceLen=%d, Uart.output[0]=%08x", BigBuf_get_traceLen(), (uint32_t)Uart.output[0]);
	}
	FpgaDisableSscDma();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);	
}

//-----------------------------------------------------------------------------
// Prepare tag messages
//-----------------------------------------------------------------------------
static void CodeIso14443aAsTagPar(const uint8_t *cmd, uint16_t len, uint8_t *parity) {
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
	LastProxToAirDuration = 8 * ToSendMax - 4;

	for(uint16_t i = 0; i < len; i++) {
		uint8_t b = cmd[i];

		// Data bits
		for(uint16_t j = 0; j < 8; j++) {
			if(b & 1) {
				ToSend[++ToSendMax] = SEC_D;
			} else {
				ToSend[++ToSendMax] = SEC_E;
			}
			b >>= 1;
		}

		// Get the parity bit
		if (parity[i>>3] & (0x80>>(i&0x0007))) {
			ToSend[++ToSendMax] = SEC_D;
			LastProxToAirDuration = 8 * ToSendMax - 4;
		} else {
			ToSend[++ToSendMax] = SEC_E;
			LastProxToAirDuration = 8 * ToSendMax;
		}
	}

	// Send stopbit
	ToSend[++ToSendMax] = SEC_F;

	// Convert from last byte pos to length
	++ToSendMax;
}

static void CodeIso14443aAsTag(const uint8_t *cmd, uint16_t len) {
	uint8_t par[MAX_PARITY_SIZE] = {0};
	GetParity(cmd, len, par);
	CodeIso14443aAsTagPar(cmd, len, par);
}

static void Code4bitAnswerAsTag(uint8_t cmd) {
	uint8_t b = cmd;

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

	for(uint8_t i = 0; i < 4; i++) {
		if(b & 1) {
			ToSend[++ToSendMax] = SEC_D;
			LastProxToAirDuration = 8 * ToSendMax - 4;
		} else {
			ToSend[++ToSendMax] = SEC_E;
			LastProxToAirDuration = 8 * ToSendMax;
		}
		b >>= 1;
	}

	// Send stopbit
	ToSend[++ToSendMax] = SEC_F;

	// Convert from last byte pos to length
	ToSendMax++;
}

//-----------------------------------------------------------------------------
// Wait for commands from reader
// Stop when button is pressed
// Or return TRUE when command is captured
//-----------------------------------------------------------------------------
static int GetIso14443aCommandFromReader(uint8_t *received, uint8_t *parity, int *len) {
    // Set FPGA mode to "simulated ISO 14443 tag", no modulation (listen
    // only, since we are receiving, not transmitting).
    // Signal field is off with the appropriate LED
    LED_D_OFF();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    // Now run a `software UART` on the stream of incoming samples.
	UartInit(received, parity);

	// clear RXRDY:
    uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

    for(;;) {
        WDT_HIT();

        if(BUTTON_PRESS()) return FALSE;
		
        if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			if(MillerDecoding(b, 0)) {
				*len = Uart.len;
				return TRUE;
			}
 		}
    }
}

bool prepare_tag_modulation(tag_response_info_t* response_info, size_t max_buffer_size) {
	// Example response, answer to MIFARE Classic read block will be 16 bytes + 2 CRC = 18 bytes
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
		return FALSE;
	}

	// Copy the byte array, used for this modulation to the buffer position
	memcpy(response_info->modulation,ToSend,ToSendMax);

	// Store the number of bytes that were used for encoding/modulation and the time needed to transfer them
	response_info->modulation_n = ToSendMax;
	response_info->ProxToAirDuration = LastProxToAirDuration;
	return TRUE;
}

// "precompile" responses. There are 7 predefined responses with a total of 28 bytes data to transmit.
// Coded responses need one byte per bit to transfer (data, parity, start, stop, correction) 
// 28 * 8 data bits, 28 * 1 parity bits, 7 start bits, 7 stop bits, 7 correction bits
// -> need 273 bytes buffer
// 44 * 8 data bits, 44 * 1 parity bits, 9 start bits, 9 stop bits, 9 correction bits --370
// 47 * 8 data bits, 47 * 1 parity bits, 10 start bits, 10 stop bits, 10 correction bits 
#define ALLOCATED_TAG_MODULATION_BUFFER_SIZE 453 

bool prepare_allocated_tag_modulation(tag_response_info_t* response_info) {
	// Retrieve and store the current buffer index
	response_info->modulation = free_buffer_pointer;

	// Determine the maximum size we can use from our buffer
	size_t max_buffer_size = ALLOCATED_TAG_MODULATION_BUFFER_SIZE;

	// Forward the prepare tag modulation function to the inner function
	if (prepare_tag_modulation(response_info, max_buffer_size)) {
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
// 'hf 14a sim'
//-----------------------------------------------------------------------------
void SimulateIso14443aTag(int tagType, int flags, byte_t* data) {

	uint8_t sak = 0;
	uint32_t cuid = 0;			
	uint32_t nonce = 0;
	
	// PACK response to PWD AUTH for EV1/NTAG
	uint8_t response8[4] = {0,0,0,0};
	// Counter for EV1/NTAG
	uint32_t counters[] = {0,0,0};
	
	// The first response contains the ATQA (note: bytes are transmitted in reverse order).
	uint8_t response1[] = {0,0};

	// Here, we collect CUID, block1, keytype1, NT1, NR1, AR1, CUID, block2, keytyp2, NT2, NR2, AR2
	// it should also collect block, keytype.
	uint8_t cardAUTHSC = 0;
	uint8_t cardAUTHKEY = 0xff;  // no authentication
	// allow collecting up to 8 sets of nonces to allow recovery of up to 8 keys
	#define ATTACK_KEY_COUNT 8 // keep same as define in cmdhfmf.c -> readerAttack()
	nonces_t ar_nr_resp[ATTACK_KEY_COUNT*2]; // for 2 separate attack types (nml, moebius)
	memset(ar_nr_resp, 0x00, sizeof(ar_nr_resp));

	uint8_t ar_nr_collected[ATTACK_KEY_COUNT*2]; // for 2nd attack type (moebius)
	memset(ar_nr_collected, 0x00, sizeof(ar_nr_collected));
	uint8_t	nonce1_count = 0;
	uint8_t	nonce2_count = 0;
	uint8_t	moebius_n_count = 0;
	bool gettingMoebius = false;
	uint8_t	mM = 0; // moebius_modifier for collection storage

	
	switch (tagType) {
		case 1: { // MIFARE Classic 1k 
			response1[0] = 0x04;
			sak = 0x08;
		} break;
		case 2: { // MIFARE Ultralight
			response1[0] = 0x44;
			sak = 0x00;
		} break;
		case 3: { // MIFARE DESFire
			response1[0] = 0x04;
			response1[1] = 0x03;
			sak = 0x20;
		} break;
		case 4: { // ISO/IEC 14443-4 - javacard (JCOP)
			response1[0] = 0x04;
			sak = 0x28;
		} break;
		case 5: { // MIFARE TNP3XXX
			response1[0] = 0x01;
			response1[1] = 0x0f;
			sak = 0x01;
		} break;
		case 6: { // MIFARE Mini 320b
			response1[0] = 0x44;
			sak = 0x09;
		} break;
		case 7: { // NTAG
			response1[0] = 0x44;
			sak = 0x00;
			// PACK
			response8[0] = 0x80;
			response8[1] = 0x80;
			ComputeCrc14443(CRC_14443_A, response8, 2, &response8[2], &response8[3]);
			// uid not supplied then get from emulator memory
			if (data[0]==0) {
				uint16_t start = 4 * (0+12);  
				uint8_t emdata[8];
				emlGetMemBt( emdata, start, sizeof(emdata));
				memcpy(data, emdata, 3); // uid bytes 0-2
				memcpy(data+3, emdata+4, 4); // uid bytes 3-7
				flags |= FLAG_7B_UID_IN_DATA;
			}
		} break;		
		default: {
			Dbprintf("Error: unkown tagtype (%d)",tagType);
			return;
		} break;
	}
	
	// The second response contains the (mandatory) first 24 bits of the UID
	uint8_t response2[5] = {0x00};

	// For UID size 7, 
	uint8_t response2a[5] = {0x00};
	
	if ( (flags & FLAG_7B_UID_IN_DATA) == FLAG_7B_UID_IN_DATA ) {
		response2[0] = 0x88;  // Cascade Tag marker
		response2[1] = data[0];
		response2[2] = data[1];
		response2[3] = data[2];

		response2a[0] = data[3];
		response2a[1] = data[4];
		response2a[2] = data[5];
		response2a[3] = data[6]; //??
		response2a[4] = response2a[0] ^ response2a[1] ^ response2a[2] ^ response2a[3];

		// Configure the ATQA and SAK accordingly
		response1[0] |= 0x40;
		sak |= 0x04;
		
		cuid = bytes_to_num(data+3, 4);
	} else {
		memcpy(response2, data, 4);
		// Configure the ATQA and SAK accordingly
		response1[0] &= 0xBF;
		sak &= 0xFB;
		cuid = bytes_to_num(data, 4);
	}

	// Calculate the BitCountCheck (BCC) for the first 4 bytes of the UID.
	response2[4] = response2[0] ^ response2[1] ^ response2[2] ^ response2[3];

	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t response3[3]  = {sak, 0x00, 0x00};
	ComputeCrc14443(CRC_14443_A, response3, 1, &response3[1], &response3[2]);

	// Prepare the optional second SAK (for 7 byte UID), drop the cascade bit
	uint8_t response3a[3]  = {0x00};
	response3a[0] = sak & 0xFB;
	ComputeCrc14443(CRC_14443_A, response3a, 1, &response3a[1], &response3a[2]);

	uint8_t response5[] = { 0x01, 0x01, 0x01, 0x01 }; 				// Very random tag nonce
	uint8_t response6[] = { 0x04, 0x58, 0x80, 0x02, 0x00, 0x00 }; 	// dummy ATS (pseudo-ATR), answer to RATS: 
	// Format byte = 0x58: FSCI=0x08 (FSC=256), TA(1) and TC(1) present, 
	// TA(1) = 0x80: different divisors not supported, DR = 1, DS = 1
	// TB(1) = not present. Defaults: FWI = 4 (FWT = 256 * 16 * 2^4 * 1/fc = 4833us), SFGI = 0 (SFG = 256 * 16 * 2^0 * 1/fc = 302us)
	// TC(1) = 0x02: CID supported, NAD not supported
	ComputeCrc14443(CRC_14443_A, response6, 4, &response6[4], &response6[5]);

	// the randon nonce
	nonce = bytes_to_num(response5, 4);	
	
	// Prepare GET_VERSION (different for UL EV-1 / NTAG)
	// uint8_t response7_EV1[] = {0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0b, 0x03, 0xfd, 0xf7};  //EV1 48bytes VERSION.
	// uint8_t response7_NTAG[] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03, 0x01, 0x9e}; //NTAG 215	
	// Prepare CHK_TEARING
	// uint8_t response9[] =  {0xBD,0x90,0x3f};
	
	#define TAG_RESPONSE_COUNT 10
	tag_response_info_t responses[TAG_RESPONSE_COUNT] = {
		{ .response = response1,  .response_n = sizeof(response1)  },  // Answer to request - respond with card type
		{ .response = response2,  .response_n = sizeof(response2)  },  // Anticollision cascade1 - respond with uid
		{ .response = response2a, .response_n = sizeof(response2a) },  // Anticollision cascade2 - respond with 2nd half of uid if asked
		{ .response = response3,  .response_n = sizeof(response3)  },  // Acknowledge select - cascade 1
		{ .response = response3a, .response_n = sizeof(response3a) },  // Acknowledge select - cascade 2
		{ .response = response5,  .response_n = sizeof(response5)  },  // Authentication answer (random nonce)
		{ .response = response6,  .response_n = sizeof(response6)  },  // dummy ATS (pseudo-ATR), answer to RATS

		{ .response = response8,   .response_n = sizeof(response8) }  // EV1/NTAG PACK response
	};	
		// { .response = response7_NTAG, .response_n = sizeof(response7_NTAG)}, // EV1/NTAG GET_VERSION response
		// { .response = response9,      .response_n = sizeof(response9)     }  // EV1/NTAG CHK_TEAR response
	

	// Allocate 512 bytes for the dynamic modulation, created when the reader queries for it
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
  
	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

	BigBuf_free_keep_EM();
	clear_trace();
	set_tracing(TRUE);

	// allocate buffers:
	uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);
	uint8_t *receivedCmdPar = BigBuf_malloc(MAX_PARITY_SIZE);
	free_buffer_pointer = BigBuf_malloc(ALLOCATED_TAG_MODULATION_BUFFER_SIZE);

	// Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
	for (size_t i=0; i<TAG_RESPONSE_COUNT; i++)
		prepare_allocated_tag_modulation(&responses[i]);

	int len = 0;

	// To control where we are in the protocol
	int order = 0;
	int lastorder;

	// Just to allow some checks
	int happened = 0;
	int happened2 = 0;
	int cmdsRecvd = 0;
	tag_response_info_t* p_response;

	LED_A_ON();
	for(;;) {	
		WDT_HIT();
		
		// Clean receive command buffer
		if(!GetIso14443aCommandFromReader(receivedCmd, receivedCmdPar, &len)) {
			DbpString("Button press");
			break;
		}
		
		// incease nonce at every command recieved
		nonce++;
		num_to_bytes(nonce, 4, response5);
		
		p_response = NULL;
		
		// Okay, look at the command now.
		lastorder = order;
		if(receivedCmd[0] == ISO14443A_CMD_REQA) { // Received a REQUEST
			p_response = &responses[0]; order = 1;
		} else if(receivedCmd[0] == ISO14443A_CMD_WUPA) { // Received a WAKEUP
			p_response = &responses[0]; order = 6;
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT) {	// Received request for UID (cascade 1)
			p_response = &responses[1]; order = 2;
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2) { 	// Received request for UID (cascade 2)
			p_response = &responses[2]; order = 20;
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT) {	// Received a SELECT (cascade 1)
			p_response = &responses[3]; order = 3;
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2) {	// Received a SELECT (cascade 2)
			p_response = &responses[4]; order = 30;		
		} else if(receivedCmd[0] == ISO14443A_CMD_READBLOCK) {	// Received a (plain) READ
			uint8_t block = receivedCmd[1];
			// if Ultralight or NTAG (4 byte blocks)
			if ( tagType == 7 || tagType == 2 ) {
				// first 12 blocks of emu are [getversion answer - check tearing - pack - 0x00 - signature]
				uint16_t start = 4 * (block+12);  
				uint8_t emdata[MAX_MIFARE_FRAME_SIZE];
				emlGetMemBt( emdata, start, 16);
				AppendCrc14443a(emdata, 16);
				EmSendCmdEx(emdata, sizeof(emdata), false);
				// We already responded, do not send anything with the EmSendCmd14443aRaw() that is called below
				p_response = NULL;
			} else { // all other tags (16 byte block tags)
				uint8_t emdata[MAX_MIFARE_FRAME_SIZE];
				emlGetMemBt( emdata, block, 16);
				AppendCrc14443a(emdata, 16);
				EmSendCmdEx(emdata, sizeof(emdata), false);
				// EmSendCmdEx(data+(4*receivedCmd[1]),16,false);
				// Dbprintf("Read request from reader: %x %x",receivedCmd[0],receivedCmd[1]);
				// We already responded, do not send anything with the EmSendCmd14443aRaw() that is called below
				p_response = NULL;
			}
		} else if(receivedCmd[0] == MIFARE_ULEV1_FASTREAD) {	// Received a FAST READ (ranged read)				
			uint8_t emdata[MAX_FRAME_SIZE];
			// first 12 blocks of emu are [getversion answer - check tearing - pack - 0x00 - signature]
			int start =  (receivedCmd[1]+12) * 4; 
			int len   = (receivedCmd[2] - receivedCmd[1] + 1) * 4;
			emlGetMemBt( emdata, start, len);
			AppendCrc14443a(emdata, len);
			EmSendCmdEx(emdata, len+2, false);				
			p_response = NULL;		
		} else if(receivedCmd[0] == MIFARE_ULEV1_READSIG && tagType == 7) {	// Received a READ SIGNATURE -- 
			// first 12 blocks of emu are [getversion answer - check tearing - pack - 0x00 - signature]
			uint16_t start = 4 * 4;
			uint8_t emdata[34];
			emlGetMemBt( emdata, start, 32);
			AppendCrc14443a(emdata, 32);
			EmSendCmdEx(emdata, sizeof(emdata), false);
			p_response = NULL;					
		} else if (receivedCmd[0] == MIFARE_ULEV1_READ_CNT && tagType == 7) {	// Received a READ COUNTER -- 
			uint8_t index = receivedCmd[1];
			uint8_t data[] =  {0x00,0x00,0x00,0x14,0xa5};
			if ( counters[index] > 0) {
				num_to_bytes(counters[index], 3, data);
				AppendCrc14443a(data, sizeof(data)-2);
			}
			EmSendCmdEx(data,sizeof(data),false);				
			p_response = NULL;
		} else if (receivedCmd[0] == MIFARE_ULEV1_INCR_CNT && tagType == 7) {	// Received a INC COUNTER -- 
			// number of counter
			uint8_t counter = receivedCmd[1];
			uint32_t val = bytes_to_num(receivedCmd+2,4);
			counters[counter] = val;
		
			// send ACK
			uint8_t ack[] = {0x0a};
			EmSendCmdEx(ack,sizeof(ack),false);
			p_response = NULL;			
		} else if(receivedCmd[0] == MIFARE_ULEV1_CHECKTEAR && tagType == 7) {	// Received a CHECK_TEARING_EVENT -- 
			// first 12 blocks of emu are [getversion answer - check tearing - pack - 0x00 - signature]
			uint8_t emdata[3];
			uint8_t counter=0;
			if (receivedCmd[1]<3) counter = receivedCmd[1];
			emlGetMemBt( emdata, 10+counter, 1);
			AppendCrc14443a(emdata, sizeof(emdata)-2);
			EmSendCmdEx(emdata, sizeof(emdata), false);	
			p_response = NULL;		
		} else if(receivedCmd[0] == ISO14443A_CMD_HALT) {	// Received a HALT
			LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
			p_response = NULL;
		} else if(receivedCmd[0] == MIFARE_AUTH_KEYA || receivedCmd[0] == MIFARE_AUTH_KEYB) {	// Received an authentication request				
			if ( tagType == 7 ) {   // IF NTAG /EV1  0x60 == GET_VERSION, not a authentication request.
				uint8_t emdata[10];
				emlGetMemBt( emdata, 0, 8 );
				AppendCrc14443a(emdata, sizeof(emdata)-2);
				EmSendCmdEx(emdata, sizeof(emdata), false);
				p_response = NULL;
			} else {
				cardAUTHSC = receivedCmd[1] / 4; // received block num
				cardAUTHKEY = receivedCmd[0] - 0x60;
				p_response = &responses[5]; order = 7;
			}
		} else if(receivedCmd[0] == ISO14443A_CMD_RATS) {	// Received a RATS request
			if (tagType == 1 || tagType == 2) {	// RATS not supported
				EmSend4bit(CARD_NACK_NA);
				p_response = NULL;
			} else {
				p_response = &responses[6]; order = 70;
			}
		} else if (order == 7 && len == 8) { // Received {nr] and {ar} (part of authentication)
			LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
			uint32_t nr = bytes_to_num(receivedCmd,4);
			uint32_t ar = bytes_to_num(receivedCmd+4,4);

			// Collect AR/NR per keytype & sector
			if ( (flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK ) {
					for (uint8_t i = 0; i < ATTACK_KEY_COUNT; i++) {
						if ( ar_nr_collected[i+mM]==0 || ((cardAUTHSC == ar_nr_resp[i+mM].sector) && (cardAUTHKEY == ar_nr_resp[i+mM].keytype) && (ar_nr_collected[i+mM] > 0)) ) {
							// if first auth for sector, or matches sector and keytype of previous auth
							if (ar_nr_collected[i+mM] < 2) {
								// if we haven't already collected 2 nonces for this sector
								if (ar_nr_resp[ar_nr_collected[i+mM]].ar != ar) {
									// Avoid duplicates... probably not necessary, ar should vary. 
									if (ar_nr_collected[i+mM]==0) {
										// first nonce collect
										ar_nr_resp[i+mM].cuid = cuid;
										ar_nr_resp[i+mM].sector = cardAUTHSC;
										ar_nr_resp[i+mM].keytype = cardAUTHKEY;
										ar_nr_resp[i+mM].nonce = nonce;
										ar_nr_resp[i+mM].nr = nr;
										ar_nr_resp[i+mM].ar = ar;
										nonce1_count++;
										// add this nonce to first moebius nonce
										ar_nr_resp[i+ATTACK_KEY_COUNT].cuid = cuid;
										ar_nr_resp[i+ATTACK_KEY_COUNT].sector = cardAUTHSC;
										ar_nr_resp[i+ATTACK_KEY_COUNT].keytype = cardAUTHKEY;
										ar_nr_resp[i+ATTACK_KEY_COUNT].nonce = nonce;
										ar_nr_resp[i+ATTACK_KEY_COUNT].nr = nr;
										ar_nr_resp[i+ATTACK_KEY_COUNT].ar = ar;
										ar_nr_collected[i+ATTACK_KEY_COUNT]++;
									} else { // second nonce collect (std and moebius)
										ar_nr_resp[i+mM].nonce2 = nonce;
										ar_nr_resp[i+mM].nr2 = nr;
										ar_nr_resp[i+mM].ar2 = ar;
										if (!gettingMoebius) {
											nonce2_count++;
											// check if this was the last second nonce we need for std attack
											if ( nonce2_count == nonce1_count ) {
												// done collecting std test switch to moebius
												// first finish incrementing last sample
												ar_nr_collected[i+mM]++; 
												// switch to moebius collection
												gettingMoebius = true;
												mM = ATTACK_KEY_COUNT;
												break;
											}
										} else {
											moebius_n_count++;
											// if we've collected all the nonces we need - finish.
											if (nonce1_count == moebius_n_count) {
												cmd_send(CMD_ACK,CMD_SIMULATE_MIFARE_CARD,0,0,&ar_nr_resp,sizeof(ar_nr_resp));
												nonce1_count = 0;
												nonce2_count = 0;
												moebius_n_count = 0;
												gettingMoebius = false;
											}
										}
									}
									ar_nr_collected[i+mM]++;
								}
							}
							// we found right spot for this nonce stop looking
							break;
						}
					}
				}
			
		} else if (receivedCmd[0] == MIFARE_ULC_AUTH_1 ) { // ULC authentication, or Desfire Authentication
		} else if (receivedCmd[0] == MIFARE_ULEV1_AUTH) { // NTAG / EV-1 authentication
			if ( tagType == 7 ) {
				uint16_t start = 13; // first 4 blocks of emu are [getversion answer - check tearing - pack - 0x00]
				uint8_t emdata[4];
				emlGetMemBt( emdata, start, 2);
				AppendCrc14443a(emdata, 2);
				EmSendCmdEx(emdata, sizeof(emdata), false);
				p_response = NULL;
				uint32_t pwd = bytes_to_num(receivedCmd+1,4);
				
				if ( MF_DBGLEVEL >= 3) Dbprintf("Auth attempt: %08x", pwd);	
			}
		} else {
			// Check for ISO 14443A-4 compliant commands, look at left nibble
			switch (receivedCmd[0]) {
				case 0x02:
				case 0x03: {  // IBlock (command no CID)
					dynamic_response_info.response[0] = receivedCmd[0];
					dynamic_response_info.response[1] = 0x90;
					dynamic_response_info.response[2] = 0x00;
					dynamic_response_info.response_n = 3;
				} break;
				case 0x0B:
				case 0x0A: { // IBlock (command CID)
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
				  
				case 0xBA: { // ping / pong
					dynamic_response_info.response[0] = 0xAB;
					dynamic_response_info.response[1] = 0x00;
					dynamic_response_info.response_n = 2;
				} break;

				case 0xCA:
				case 0xC2: { // Readers sends deselect command
					dynamic_response_info.response[0] = 0xCA;
					dynamic_response_info.response[1] = 0x00;
					dynamic_response_info.response_n = 2;
				} break;

				default: {
					// Never seen this command before
					LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
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
					LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
					break;
				}
				p_response = &dynamic_response_info;
			}
		}

		// Count number of wakeups received after a halt
		if(order == 6 && lastorder == 5) { happened++; }

		// Count number of other messages after a halt
		if(order != 6 && lastorder == 5) { happened2++; }

		// comment this limit if you want to simulation longer		
		if (!tracing) {
			Dbprintf("Trace Full. Simulation stopped.");
			break;
		}
		// comment this limit if you want to simulation longer
		if(cmdsRecvd > 999) {
			DbpString("1000 commands later...");
			break;
		}
		cmdsRecvd++;

		if (p_response != NULL) {
			EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, receivedCmd[0] == 0x52);
			// do the tracing for the previous reader request and this tag answer:
			uint8_t par[MAX_PARITY_SIZE] = {0x00};
			GetParity(p_response->response, p_response->response_n, par);
	
			EmLogTrace(Uart.output, 
						Uart.len, 
						Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, 
						Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, 
						Uart.parity,
						p_response->response, 
						p_response->response_n,
						LastTimeProxToAirStart*16 + DELAY_ARM2AIR_AS_TAG,
						(LastTimeProxToAirStart + p_response->ProxToAirDuration)*16 + DELAY_ARM2AIR_AS_TAG, 
						par);
		}
	}

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	set_tracing(FALSE);
	BigBuf_free_keep_EM();
	LED_A_OFF();
	
		if(flags & FLAG_NR_AR_ATTACK && MF_DBGLEVEL >= 1) {
		for ( uint8_t	i = 0; i < ATTACK_KEY_COUNT; i++) {
			if (ar_nr_collected[i] == 2) {
				Dbprintf("Collected two pairs of AR/NR which can be used to extract %s from reader for sector %d:", (i<ATTACK_KEY_COUNT/2) ? "keyA" : "keyB", ar_nr_resp[i].sector);
				Dbprintf("../tools/mfkey/mfkey32 %08x %08x %08x %08x %08x %08x",
						ar_nr_resp[i].cuid,  //UID
						ar_nr_resp[i].nonce, //NT
						ar_nr_resp[i].nr,    //NR1
						ar_nr_resp[i].ar,    //AR1
						ar_nr_resp[i].nr2,   //NR2
						ar_nr_resp[i].ar2    //AR2
						);
			}
		}	
		for ( uint8_t	i = ATTACK_KEY_COUNT; i < ATTACK_KEY_COUNT*2; i++) {
			if (ar_nr_collected[i] == 2) {
				Dbprintf("Collected two pairs of AR/NR which can be used to extract %s from reader for sector %d:", (i<ATTACK_KEY_COUNT/2) ? "keyA" : "keyB", ar_nr_resp[i].sector);
				Dbprintf("../tools/mfkey/mfkey32v2 %08x %08x %08x %08x %08x %08x %08x",
						ar_nr_resp[i].cuid,  //UID
						ar_nr_resp[i].nonce, //NT
						ar_nr_resp[i].nr,    //NR1
						ar_nr_resp[i].ar,    //AR1
						ar_nr_resp[i].nonce2,//NT2
						ar_nr_resp[i].nr2,   //NR2
						ar_nr_resp[i].ar2    //AR2
						);
			}
		}
	}
	
	if (MF_DBGLEVEL >= 4){
		Dbprintf("-[ Wake ups after halt [%d]", happened);
		Dbprintf("-[ Messages after halt [%d]", happened2);
		Dbprintf("-[ Num of received cmd [%d]", cmdsRecvd);
	}
}

// prepare a delayed transfer. This simply shifts ToSend[] by a number
// of bits specified in the delay parameter.
void PrepareDelayedTransfer(uint16_t delay) {
	delay &= 0x07;
	if (!delay) return;

	uint8_t bitmask = 0;
	uint8_t bits_to_shift = 0;
	uint8_t bits_shifted = 0;
	uint16_t i = 0;

	for (i = 0; i < delay; ++i)
		bitmask |= (0x01 << i);

	ToSend[++ToSendMax] = 0x00;

	for (i = 0; i < ToSendMax; ++i) {
			bits_to_shift = ToSend[i] & bitmask;
			ToSend[i] = ToSend[i] >> delay;
			ToSend[i] = ToSend[i] | (bits_shifted << (8 - delay));
			bits_shifted = bits_to_shift;
		}
	}


//-------------------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
// Parameter timing:
// if NULL: transfer at next possible time, taking into account
// 			request guard time and frame delay time
// if == 0:	transfer immediately and return time of transfer
// if != 0: delay transfer until time specified
//-------------------------------------------------------------------------------------
static void TransmitFor14443a(const uint8_t *cmd, uint16_t len, uint32_t *timing) {
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);

	uint32_t ThisTransferTime = 0;

	if (timing) {
		if(*timing == 0) {										// Measure time
			*timing = (GetCountSspClk() + 8) & 0xfffffff8;
		} else {
			PrepareDelayedTransfer(*timing & 0x00000007);		// Delay transfer (fine tuning - up to 7 MF clock ticks)
		}
		if(MF_DBGLEVEL >= 4 && GetCountSspClk() >= (*timing & 0xfffffff8)) Dbprintf("TransmitFor14443a: Missed timing");
		while(GetCountSspClk() < (*timing & 0xfffffff8));		// Delay transfer (multiple of 8 MF clock ticks)
		LastTimeProxToAirStart = *timing;
	} else {
		ThisTransferTime = ((MAX(NextTransferTime, GetCountSspClk()) & 0xfffffff8) + 8);

		while(GetCountSspClk() < ThisTransferTime);

		LastTimeProxToAirStart = ThisTransferTime;
	}
	
	// clear TXRDY
	AT91C_BASE_SSC->SSC_THR = SEC_Y;

	uint16_t c = 0;
	for(;;) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = cmd[c];
			++c;
			if(c >= len)
				break;
		}
	}
	
	NextTransferTime = MAX(NextTransferTime, LastTimeProxToAirStart + REQUEST_GUARD_TIME);
}

//-----------------------------------------------------------------------------
// Prepare reader command (in bits, support short frames) to send to FPGA
//-----------------------------------------------------------------------------
void CodeIso14443aBitsAsReaderPar(const uint8_t *cmd, uint16_t bits, const uint8_t *parity) {
	int i, j;
	int last = 0;
	uint8_t b;

	ToSendReset();

	// Start of Communication (Seq. Z)
	ToSend[++ToSendMax] = SEC_Z;
	LastProxToAirDuration = 8 * (ToSendMax+1) - 6;

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
				LastProxToAirDuration = 8 * (ToSendMax+1) - 2;
				last = 1;
			} else {
				if (last == 0) {
				// Sequence Z
				ToSend[++ToSendMax] = SEC_Z;
				LastProxToAirDuration = 8 * (ToSendMax+1) - 6;
				} else {
					// Sequence Y
					ToSend[++ToSendMax] = SEC_Y;
					last = 0;
				}
			}
			b >>= 1;
		}

		// Only transmit parity bit if we transmitted a complete byte
		if (j == 8 && parity != NULL) {
			// Get the parity bit
			if (parity[i>>3] & (0x80 >> (i&0x0007))) {
				// Sequence X
				ToSend[++ToSendMax] = SEC_X;
				LastProxToAirDuration = 8 * (ToSendMax+1) - 2;
				last = 1;
			} else {
				if (last == 0) {
					// Sequence Z
					ToSend[++ToSendMax] = SEC_Z;
					LastProxToAirDuration = 8 * (ToSendMax+1) - 6;
				} else {
					// Sequence Y
					ToSend[++ToSendMax] = SEC_Y;
					last = 0;
				}
			}
		}
	}

	// End of Communication: Logic 0 followed by Sequence Y
	if (last == 0) {
		// Sequence Z
		ToSend[++ToSendMax] = SEC_Z;
		LastProxToAirDuration = 8 * (ToSendMax+1) - 6;
	} else {
		// Sequence Y
		ToSend[++ToSendMax] = SEC_Y;
		last = 0;
	}
	ToSend[++ToSendMax] = SEC_Y;

	// Convert to length of command:
	++ToSendMax;
}

//-----------------------------------------------------------------------------
// Prepare reader command to send to FPGA
//-----------------------------------------------------------------------------
void CodeIso14443aAsReaderPar(const uint8_t *cmd, uint16_t len, const uint8_t *parity) {
  CodeIso14443aBitsAsReaderPar(cmd, len*8, parity);
}

//-----------------------------------------------------------------------------
// Wait for commands from reader
// Stop when button is pressed (return 1) or field was gone (return 2)
// Or return 0 when command is captured
//-----------------------------------------------------------------------------
static int EmGetCmd(uint8_t *received, uint16_t *len, uint8_t *parity) {
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
				ADC_MODE_PRESCALE(63) |
				ADC_MODE_STARTUP_TIME(1) |
				ADC_MODE_SAMPLE_HOLD_TIME(15);
	AT91C_BASE_ADC->ADC_CHER = ADC_CHANNEL(ADC_CHAN_HF);
	// start ADC
	AT91C_BASE_ADC->ADC_CR = AT91C_ADC_START;
	
	// Now run a 'software UART' on the stream of incoming samples.
	UartInit(received, parity);

	// Clear RXRDY:
    uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
	
	for(;;) {
		WDT_HIT();

		if (BUTTON_PRESS()) return 1;

		// test if the field exists
		if (AT91C_BASE_ADC->ADC_SR & ADC_END_OF_CONVERSION(ADC_CHAN_HF)) {
			analogCnt++;
			analogAVG += AT91C_BASE_ADC->ADC_CDR[ADC_CHAN_HF];
			AT91C_BASE_ADC->ADC_CR = AT91C_ADC_START;
			if (analogCnt >= 32) {
				if ((MAX_ADC_HF_VOLTAGE * (analogAVG / analogCnt) >> 10) < MF_MINFIELDV) {
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

		// receive and test the miller decoding
        if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			if(MillerDecoding(b, 0)) {
				*len = Uart.len;
				return 0;
			}
        }
	}
}

int EmSendCmd14443aRaw(uint8_t *resp, uint16_t respLen, bool correctionNeeded) {
	uint8_t b;
	uint16_t i = 0;
	uint32_t ThisTransferTime;
	
	// Modulate Manchester
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_MOD);

	// include correction bit if necessary
	if (Uart.parityBits & 0x01) {
		correctionNeeded = TRUE;
	}
	// 1236, so correction bit needed
	i = (correctionNeeded) ? 0 : 1;

 	// clear receiving shift register and holding register
	while(!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY));
	b = AT91C_BASE_SSC->SSC_RHR; (void) b;
	while(!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY));
	b = AT91C_BASE_SSC->SSC_RHR; (void) b;
	
	// wait for the FPGA to signal fdt_indicator == 1 (the FPGA is ready to queue new data in its delay line)
	for (uint8_t j = 0; j < 5; j++) {	// allow timeout - better late than never
		while(!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY));
		if (AT91C_BASE_SSC->SSC_RHR) break;
	}

	while ((ThisTransferTime = GetCountSspClk()) & 0x00000007);

	// Clear TXRDY:
	AT91C_BASE_SSC->SSC_THR = SEC_F;

	// send cycle
	for(; i < respLen; ) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = resp[i++];
			FpgaSendQueueDelay = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
		}
	
		if(BUTTON_PRESS()) break;
	}

	// Ensure that the FPGA Delay Queue is empty before we switch to TAGSIM_LISTEN again:
	uint8_t fpga_queued_bits = FpgaSendQueueDelay >> 3;  // twich /8 ??   >>3, 
	for (i = 0; i <= fpga_queued_bits/8 + 1; ) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = SEC_F;
			FpgaSendQueueDelay = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			i++;
		}
	}
	LastTimeProxToAirStart = ThisTransferTime + (correctionNeeded?8:0);
	return 0;
}

int EmSend4bitEx(uint8_t resp, bool correctionNeeded){
	Code4bitAnswerAsTag(resp);
	int res = EmSendCmd14443aRaw(ToSend, ToSendMax, correctionNeeded);
	// do the tracing for the previous reader request and this tag answer:
	uint8_t par[1] = {0x00};
	GetParity(&resp, 1, par);
	EmLogTrace(Uart.output, 
				Uart.len, 
				Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, 
				Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, 
				Uart.parity,
				&resp, 
				1, 
				LastTimeProxToAirStart*16 + DELAY_ARM2AIR_AS_TAG,
				(LastTimeProxToAirStart + LastProxToAirDuration)*16 + DELAY_ARM2AIR_AS_TAG, 
				par);
	return res;
}

int EmSend4bit(uint8_t resp){
	return EmSend4bitEx(resp, false);
}

int EmSendCmdExPar(uint8_t *resp, uint16_t respLen, bool correctionNeeded, uint8_t *par){
	CodeIso14443aAsTagPar(resp, respLen, par);
	int res = EmSendCmd14443aRaw(ToSend, ToSendMax, correctionNeeded);
	// do the tracing for the previous reader request and this tag answer:
	EmLogTrace(Uart.output, 
				Uart.len, 
				Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, 
				Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, 
				Uart.parity,
				resp, 
				respLen, 
				LastTimeProxToAirStart*16 + DELAY_ARM2AIR_AS_TAG,
				(LastTimeProxToAirStart + LastProxToAirDuration)*16 + DELAY_ARM2AIR_AS_TAG, 
				par);
	return res;
}

int EmSendCmdEx(uint8_t *resp, uint16_t respLen, bool correctionNeeded){
	uint8_t par[MAX_PARITY_SIZE] = {0x00};
	GetParity(resp, respLen, par);
	return EmSendCmdExPar(resp, respLen, correctionNeeded, par);
}

int EmSendCmd(uint8_t *resp, uint16_t respLen){
	uint8_t par[MAX_PARITY_SIZE] = {0x00};
	GetParity(resp, respLen, par);
	return EmSendCmdExPar(resp, respLen, false, par);
}

int EmSendCmdPar(uint8_t *resp, uint16_t respLen, uint8_t *par){
	return EmSendCmdExPar(resp, respLen, false, par);
}

bool EmLogTrace(uint8_t *reader_data, uint16_t reader_len, uint32_t reader_StartTime, uint32_t reader_EndTime, uint8_t *reader_Parity,
				 uint8_t *tag_data, uint16_t tag_len, uint32_t tag_StartTime, uint32_t tag_EndTime, uint8_t *tag_Parity)
{
	// we cannot exactly measure the end and start of a received command from reader. However we know that the delay from
	// end of the received command to start of the tag's (simulated by us) answer is n*128+20 or n*128+84 resp.
	// with n >= 9. The start of the tags answer can be measured and therefore the end of the received command be calculated:
	uint16_t reader_modlen = reader_EndTime - reader_StartTime;
	uint16_t approx_fdt = tag_StartTime - reader_EndTime;
	uint16_t exact_fdt = (approx_fdt - 20 + 32)/64 * 64 + 20;
	reader_EndTime = tag_StartTime - exact_fdt;
	reader_StartTime = reader_EndTime - reader_modlen;
		
	if (!LogTrace(reader_data, reader_len, reader_StartTime, reader_EndTime, reader_Parity, TRUE))
		return FALSE;
	else 
		return(!LogTrace(tag_data, tag_len, tag_StartTime, tag_EndTime, tag_Parity, FALSE));

}

//-----------------------------------------------------------------------------
// Wait a certain time for tag response
//  If a response is captured return TRUE
//  If it takes too long return FALSE
//-----------------------------------------------------------------------------
static int GetIso14443aAnswerFromTag(uint8_t *receivedResponse, uint8_t *receivedResponsePar, uint16_t offset) {
	uint32_t c = 0x00;
	
	// Set FPGA mode to "reader listen mode", no modulation (listen
	// only, since we are receiving, not transmitting).
	// Signal field is on with the appropriate LED
	LED_D_ON();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_LISTEN);
	
	// Now get the answer from the card
	DemodInit(receivedResponse, receivedResponsePar);

	// clear RXRDY:
    uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;

	for(;;) {
		WDT_HIT();

		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
			if(ManchesterDecoding(b, offset, 0)) {
				NextTransferTime = MAX(NextTransferTime, Demod.endTime - (DELAY_AIR2ARM_AS_READER + DELAY_ARM2AIR_AS_READER)/16 + FRAME_DELAY_TIME_PICC_TO_PCD);
				return TRUE;
			} else if (c++ > iso14a_timeout && Demod.state == DEMOD_UNSYNCD) {
				return FALSE; 
			}
		}
	}
}

void ReaderTransmitBitsPar(uint8_t* frame, uint16_t bits, uint8_t *par, uint32_t *timing) {

	CodeIso14443aBitsAsReaderPar(frame, bits, par);
	// Send command to tag
	TransmitFor14443a(ToSend, ToSendMax, timing);
	if(trigger) LED_A_ON();
  
	LogTrace(frame, nbytes(bits), (LastTimeProxToAirStart<<4) + DELAY_ARM2AIR_AS_READER, ((LastTimeProxToAirStart + LastProxToAirDuration)<<4) + DELAY_ARM2AIR_AS_READER, par, TRUE);
}

void ReaderTransmitPar(uint8_t* frame, uint16_t len, uint8_t *par, uint32_t *timing) {
  ReaderTransmitBitsPar(frame, len*8, par, timing);
}

void ReaderTransmitBits(uint8_t* frame, uint16_t len, uint32_t *timing) {
	// Generate parity and redirect
	uint8_t par[MAX_PARITY_SIZE] = {0x00};
	GetParity(frame, len/8, par);  
	ReaderTransmitBitsPar(frame, len, par, timing);
}

void ReaderTransmit(uint8_t* frame, uint16_t len, uint32_t *timing) {
	// Generate parity and redirect
	uint8_t par[MAX_PARITY_SIZE] = {0x00};
	GetParity(frame, len, par);
	ReaderTransmitBitsPar(frame, len*8, par, timing);
}

int ReaderReceiveOffset(uint8_t* receivedAnswer, uint16_t offset, uint8_t *parity) {
	if (!GetIso14443aAnswerFromTag(receivedAnswer, parity, offset))
		return FALSE;
	LogTrace(receivedAnswer, Demod.len, Demod.startTime*16 - DELAY_AIR2ARM_AS_READER, Demod.endTime*16 - DELAY_AIR2ARM_AS_READER, parity, FALSE);
	return Demod.len;
}

int ReaderReceive(uint8_t *receivedAnswer, uint8_t *parity) {
	if (!GetIso14443aAnswerFromTag(receivedAnswer, parity, 0))
		return FALSE;
	LogTrace(receivedAnswer, Demod.len, Demod.startTime*16 - DELAY_AIR2ARM_AS_READER, Demod.endTime*16 - DELAY_AIR2ARM_AS_READER, parity, FALSE);
	return Demod.len;
}

// performs iso14443a anticollision (optional) and card select procedure
// fills the uid and cuid pointer unless NULL
// fills the card info record unless NULL
// if anticollision is false, then the UID must be provided in uid_ptr[] 
// and num_cascades must be set (1: 4 Byte UID, 2: 7 Byte UID, 3: 10 Byte UID)
int iso14443a_select_card(byte_t *uid_ptr, iso14a_card_select_t *p_hi14a_card, uint32_t *cuid_ptr, bool anticollision, uint8_t num_cascades) {
	uint8_t wupa[]       = { 0x52 };  // 0x26 - REQA  0x52 - WAKE-UP
	uint8_t sel_all[]    = { 0x93,0x20 };
	uint8_t sel_uid[]    = { 0x93,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t rats[]       = { 0xE0,0x80,0x00,0x00 }; // FSD=256, FSDI=8, CID=0
	uint8_t resp[MAX_FRAME_SIZE] = {0}; // theoretically. A usual RATS will be much smaller
	uint8_t resp_par[MAX_PARITY_SIZE] = {0};
	byte_t uid_resp[4] = {0};
	size_t uid_resp_len = 0;

	uint8_t sak = 0x04; // cascade uid
	int cascade_level = 0;
	int len;

	// Broadcast for a card, WUPA (0x52) will force response from all cards in the field
    ReaderTransmitBitsPar(wupa, 7, NULL, NULL);
	
	// Receive the ATQA
	if(!ReaderReceive(resp, resp_par)) return 0;

	if(p_hi14a_card) {
		memcpy(p_hi14a_card->atqa, resp, 2);
		p_hi14a_card->uidlen = 0;
		memset(p_hi14a_card->uid,0,10);
	}

	if (anticollision) {
		// clear uid
		if (uid_ptr)
			memset(uid_ptr,0,10);
	}

	// check for proprietary anticollision:
	if ((resp[0] & 0x1F) == 0) return 3;
	
	// OK we will select at least at cascade 1, lets see if first byte of UID was 0x88 in
	// which case we need to make a cascade 2 request and select - this is a long UID
	// While the UID is not complete, the 3nd bit (from the right) is set in the SAK.
	for(; sak & 0x04; cascade_level++) {
		// SELECT_* (L1: 0x93, L2: 0x95, L3: 0x97)
		sel_uid[0] = sel_all[0] = 0x93 + cascade_level * 2;

		if (anticollision) {
		// SELECT_ALL
			ReaderTransmit(sel_all, sizeof(sel_all), NULL);
			if (!ReaderReceive(resp, resp_par)) return 0;

			if (Demod.collisionPos) {			// we had a collision and need to construct the UID bit by bit
				memset(uid_resp, 0, 4);
				uint16_t uid_resp_bits = 0;
				uint16_t collision_answer_offset = 0;
				// anti-collision-loop:
				while (Demod.collisionPos) {
					Dbprintf("Multiple tags detected. Collision after Bit %d", Demod.collisionPos);
					for (uint16_t i = collision_answer_offset; i < Demod.collisionPos; i++, uid_resp_bits++) {	// add valid UID bits before collision point
						uint16_t UIDbit = (resp[i/8] >> (i % 8)) & 0x01;
						uid_resp[uid_resp_bits / 8] |= UIDbit << (uid_resp_bits % 8);
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
					if (!ReaderReceiveOffset(resp, collision_answer_offset, resp_par)) return 0;
				}
				// finally, add the last bits and BCC of the UID
				for (uint16_t i = collision_answer_offset; i < (Demod.len-1)*8; i++, uid_resp_bits++) {
					uint16_t UIDbit = (resp[i/8] >> (i%8)) & 0x01;
					uid_resp[uid_resp_bits/8] |= UIDbit << (uid_resp_bits % 8);
				}

			} else {		// no collision, use the response to SELECT_ALL as current uid
				memcpy(uid_resp, resp, 4);
			}
			
		} else {
			if (cascade_level < num_cascades - 1) {
				uid_resp[0] = 0x88;
				memcpy(uid_resp+1, uid_ptr+cascade_level*3, 3);
			} else {
				memcpy(uid_resp, uid_ptr+cascade_level*3, 4);
			}
		}
		uid_resp_len = 4;

		// calculate crypto UID. Always use last 4 Bytes.
		if(cuid_ptr)
			*cuid_ptr = bytes_to_num(uid_resp, 4);

		// Construct SELECT UID command
		sel_uid[1] = 0x70;													// transmitting a full UID (1 Byte cmd, 1 Byte NVB, 4 Byte UID, 1 Byte BCC, 2 Bytes CRC)
		memcpy(sel_uid+2, uid_resp, 4);										// the UID received during anticollision, or the provided UID
		sel_uid[6] = sel_uid[2] ^ sel_uid[3] ^ sel_uid[4] ^ sel_uid[5];  	// calculate and add BCC
		AppendCrc14443a(sel_uid, 7);										// calculate and add CRC
		ReaderTransmit(sel_uid, sizeof(sel_uid), NULL);

		// Receive the SAK
		if (!ReaderReceive(resp, resp_par)) return 0;
		
		sak = resp[0];

		// Test if more parts of the uid are coming
		if ((sak & 0x04) /* && uid_resp[0] == 0x88 */) {
			// Remove first byte, 0x88 is not an UID byte, it CT, see page 3 of:
			// http://www.nxp.com/documents/application_note/AN10927.pdf
			uid_resp[0] = uid_resp[1];
			uid_resp[1] = uid_resp[2];
			uid_resp[2] = uid_resp[3]; 
			uid_resp_len = 3;
		}

		if(uid_ptr && anticollision)
			memcpy(uid_ptr + (cascade_level*3), uid_resp, uid_resp_len);

		if(p_hi14a_card) {
			memcpy(p_hi14a_card->uid + (cascade_level*3), uid_resp, uid_resp_len);
			p_hi14a_card->uidlen += uid_resp_len;
		}
	}

	if(p_hi14a_card) {
		p_hi14a_card->sak = sak;
		p_hi14a_card->ats_len = 0;
	}

	// non iso14443a compliant tag
	if( (sak & 0x20) == 0) return 2; 

	// Request for answer to select
	AppendCrc14443a(rats, 2);
	ReaderTransmit(rats, sizeof(rats), NULL);

	if (!(len = ReaderReceive(resp, resp_par))) return 0;
	
	if(p_hi14a_card) {
		memcpy(p_hi14a_card->ats, resp, sizeof(p_hi14a_card->ats));
		p_hi14a_card->ats_len = len;
	}

	// reset the PCB block number
	iso14_pcb_blocknum = 0;

	// set default timeout based on ATS
	iso14a_set_ATS_timeout(resp);

	return 1;	
}

void iso14443a_setup(uint8_t fpga_minor_mode) {

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	// Set up the synchronous serial port
	FpgaSetupSsc();
	// connect Demodulated Signal to ADC:
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	LED_D_OFF();
	// Signal field is on with the appropriate LED
	if (fpga_minor_mode == FPGA_HF_ISO14443A_READER_MOD ||
		fpga_minor_mode == FPGA_HF_ISO14443A_READER_LISTEN)
		LED_D_ON();

	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | fpga_minor_mode);
	
	// Start the timer
	StartCountSspClk();
	
	// Prepare the demodulation functions
	DemodReset();
	UartReset();
	NextTransferTime = 2 * DELAY_ARM2AIR_AS_READER;
	iso14a_set_timeout(10*106); // 10ms default	
}

int iso14_apdu(uint8_t *cmd, uint16_t cmd_len, void *data) {
	uint8_t parity[MAX_PARITY_SIZE] = {0x00};
	uint8_t real_cmd[cmd_len+4];
	real_cmd[0] = 0x0a; //I-Block
	// put block number into the PCB
	real_cmd[0] |= iso14_pcb_blocknum;
	real_cmd[1] = 0x00; //CID: 0 //FIXME: allow multiple selected cards
	memcpy(real_cmd+2, cmd, cmd_len);
	AppendCrc14443a(real_cmd,cmd_len+2);
 
	ReaderTransmit(real_cmd, cmd_len+4, NULL);
	size_t len = ReaderReceive(data, parity);
	 //DATA LINK ERROR
	if (!len) return 0;
	
	uint8_t *data_bytes = (uint8_t *) data;

	// if we received an I- or R(ACK)-Block with a block number equal to the
	// current block number, toggle the current block number
	if (len >= 4 // PCB+CID+CRC = 4 bytes
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
void ReaderIso14443a(UsbCommand *c) {
	iso14a_command_t param = c->arg[0];
	size_t len = c->arg[1] & 0xffff;
	size_t lenbits = c->arg[1] >> 16;
	uint32_t timeout = c->arg[2];
	uint8_t *cmd = c->d.asBytes;
	uint32_t arg0 = 0;
	byte_t buf[USB_CMD_DATA_SIZE] = {0x00};
	uint8_t par[MAX_PARITY_SIZE] = {0x00};
  
	if (param & ISO14A_CONNECT)
		clear_trace();

	set_tracing(TRUE);

	if (param & ISO14A_REQUEST_TRIGGER)
		iso14a_set_trigger(TRUE);

	if (param & ISO14A_CONNECT) {
		iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
		if(!(param & ISO14A_NO_SELECT)) {
			iso14a_card_select_t *card = (iso14a_card_select_t*)buf;
			arg0 = iso14443a_select_card(NULL,card,NULL, true, 0);
			cmd_send(CMD_ACK, arg0, card->uidlen, 0, buf, sizeof(iso14a_card_select_t));
			// if it fails,  the cmdhf14a.c client quites.. however this one still executes.
			if ( arg0 == 0 ) return;
		}
	}

	if (param & ISO14A_SET_TIMEOUT)
		iso14a_set_timeout(timeout);

	if (param & ISO14A_APDU) {
		arg0 = iso14_apdu(cmd, len, buf);
		cmd_send(CMD_ACK,arg0,0,0,buf,sizeof(buf));
	}

	if (param & ISO14A_RAW) {
		if(param & ISO14A_APPEND_CRC) {
			if(param & ISO14A_TOPAZMODE) {
				AppendCrc14443b(cmd,len);
			} else {
				AppendCrc14443a(cmd,len);
			}
			len += 2;
			if (lenbits) lenbits += 16;
		}
		if(lenbits>0) {				// want to send a specific number of bits (e.g. short commands)
			if(param & ISO14A_TOPAZMODE) {
				int bits_to_send = lenbits;
				uint16_t i = 0;
				ReaderTransmitBitsPar(&cmd[i++], MIN(bits_to_send, 7), NULL, NULL);		// first byte is always short (7bits) and no parity
				bits_to_send -= 7;
				while (bits_to_send > 0) {
					ReaderTransmitBitsPar(&cmd[i++], MIN(bits_to_send, 8), NULL, NULL);	// following bytes are 8 bit and no parity
					bits_to_send -= 8;
				}
			} else {
			GetParity(cmd, lenbits/8, par);
				ReaderTransmitBitsPar(cmd, lenbits, par, NULL);							// bytes are 8 bit with odd parity
			}
		} else {					// want to send complete bytes only
			if(param & ISO14A_TOPAZMODE) {
				uint16_t i = 0;
				ReaderTransmitBitsPar(&cmd[i++], 7, NULL, NULL);						// first byte: 7 bits, no paritiy
				while (i < len) {
					ReaderTransmitBitsPar(&cmd[i++], 8, NULL, NULL);					// following bytes: 8 bits, no paritiy
				}
		} else {
				ReaderTransmit(cmd,len, NULL);											// 8 bits, odd parity
			}
		}
		arg0 = ReaderReceive(buf, par);
		cmd_send(CMD_ACK,arg0,0,0,buf,sizeof(buf));
	}

	if (param & ISO14A_REQUEST_TRIGGER)
		iso14a_set_trigger(FALSE);

	if (param & ISO14A_NO_DISCONNECT)
		return;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	set_tracing(FALSE);
	LEDsoff();
}

// Determine the distance between two nonces.
// Assume that the difference is small, but we don't know which is first.
// Therefore try in alternating directions.
int32_t dist_nt(uint32_t nt1, uint32_t nt2) {

	if (nt1 == nt2) return 0;
	
	uint32_t nttmp1 = nt1;
	uint32_t nttmp2 = nt2;

	for (uint16_t i = 1; i < 32768/8; ++i) {
		nttmp1 = prng_successor(nttmp1, 1);	if (nttmp1 == nt2) return i;
		nttmp2 = prng_successor(nttmp2, 1);	if (nttmp2 == nt1) return -i;
		
		nttmp1 = prng_successor(nttmp1, 1);	if (nttmp1 == nt2) return i+1;
		nttmp2 = prng_successor(nttmp2, 1);	if (nttmp2 == nt1) return -(i+1);
		
		nttmp1 = prng_successor(nttmp1, 1);	if (nttmp1 == nt2) return i+2;
		nttmp2 = prng_successor(nttmp2, 1);	if (nttmp2 == nt1) return -(i+2);

		nttmp1 = prng_successor(nttmp1, 1);	if (nttmp1 == nt2) return i+3;
		nttmp2 = prng_successor(nttmp2, 1);	if (nttmp2 == nt1) return -(i+3);
		
		nttmp1 = prng_successor(nttmp1, 1);	if (nttmp1 == nt2) return i+4;
		nttmp2 = prng_successor(nttmp2, 1);	if (nttmp2 == nt1) return -(i+4);
		
		nttmp1 = prng_successor(nttmp1, 1);	if (nttmp1 == nt2) return i+5;
		nttmp2 = prng_successor(nttmp2, 1);	if (nttmp2 == nt1) return -(i+5);
		
		nttmp1 = prng_successor(nttmp1, 1);	if (nttmp1 == nt2) return i+6;
		nttmp2 = prng_successor(nttmp2, 1);	if (nttmp2 == nt1) return -(i+6);
		
		nttmp1 = prng_successor(nttmp1, 1);	if (nttmp1 == nt2) return i+7;
		nttmp2 = prng_successor(nttmp2, 1);	if (nttmp2 == nt1) return -(i+7);		
	}
	// either nt1 or nt2 are invalid nonces	
	return(-99999); 
}

//-----------------------------------------------------------------------------
// Recover several bits of the cypher stream. This implements (first stages of)
// the algorithm described in "The Dark Side of Security by Obscurity and
// Cloning MiFare Classic Rail and Building Passes, Anywhere, Anytime"
// (article by Nicolas T. Courtois, 2009)
//-----------------------------------------------------------------------------

void ReaderMifare(bool first_try, uint8_t block, uint8_t keytype ) {
	
	uint8_t mf_auth[] 	= { keytype, block, 0x00, 0x00 };
	uint8_t mf_nr_ar[]	= { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	uint8_t uid[10]		= {0,0,0,0,0,0,0,0,0,0};
	uint8_t par_list[8]	= {0,0,0,0,0,0,0,0};
	uint8_t ks_list[8]	= {0,0,0,0,0,0,0,0};
	uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
	uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};
	uint8_t par[1] = {0};	// maximum 8 Bytes to be sent here, 1 byte parity is therefore enough
	byte_t nt_diff = 0;
	uint32_t nt = 0;
	uint32_t previous_nt = 0;	
	uint32_t cuid = 0;
	
	int32_t catch_up_cycles = 0;
	int32_t last_catch_up = 0;
	int32_t isOK = 0;
	int32_t nt_distance = 0;
	
	uint16_t elapsed_prng_sequences = 1;
	uint16_t consecutive_resyncs = 0;
	uint16_t unexpected_random = 0;
	uint16_t sync_tries = 0;

	// static variables here, is re-used in the next call
	static uint32_t nt_attacked = 0;
	static uint32_t sync_time = 0;
	static uint32_t sync_cycles = 0;
	static uint8_t par_low = 0;
	static uint8_t mf_nr_ar3 = 0;
	
	#define PRNG_SEQUENCE_LENGTH	(1 << 16)
	#define MAX_UNEXPECTED_RANDOM	4		// maximum number of unexpected (i.e. real) random numbers when trying to sync. Then give up.
	#define MAX_SYNC_TRIES		32
	
	AppendCrc14443a(mf_auth, 2);
	
	BigBuf_free(); BigBuf_Clear_ext(false);	
	clear_trace();
	set_tracing(TRUE);	
	iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);

	sync_time = GetCountSspClk() & 0xfffffff8;
	sync_cycles = PRNG_SEQUENCE_LENGTH; // Mifare Classic's random generator repeats every 2^16 cycles (and so do the nonces).		
	nt_attacked = 0;
	
   if (MF_DBGLEVEL >= 4)	Dbprintf("Mifare::Sync %08x", sync_time);
				
	if (first_try) {
		mf_nr_ar3 = 0;
		par_low = 0;
	} else {
		// we were unsuccessful on a previous call. 
		// Try another READER nonce (first 3 parity bits remain the same)
		++mf_nr_ar3;
		mf_nr_ar[3] = mf_nr_ar3;
		par[0] = par_low;
	}

	bool have_uid = FALSE;
	uint8_t cascade_levels = 0;

	LED_C_ON(); 
	uint16_t i;
	for(i = 0; TRUE; ++i) {

		WDT_HIT();

		// Test if the action was cancelled
		if(BUTTON_PRESS()) {
			isOK = -1;
			break;
		}
		
		// this part is from Piwi's faster nonce collecting part in Hardnested.
		if (!have_uid) { // need a full select cycle to get the uid first
			iso14a_card_select_t card_info;		
			if(!iso14443a_select_card(uid, &card_info, &cuid, true, 0)) {
				if (MF_DBGLEVEL >= 4)	Dbprintf("Mifare: Can't select card (ALL)");
				break;
			}
			switch (card_info.uidlen) {
				case 4 : cascade_levels = 1; break;
				case 7 : cascade_levels = 2; break;
				case 10: cascade_levels = 3; break;
				default: break;
			}
			have_uid = TRUE;	
		} else { // no need for anticollision. We can directly select the card
			if(!iso14443a_select_card(uid, NULL, &cuid, false, cascade_levels)) {
				if (MF_DBGLEVEL >= 4)	Dbprintf("Mifare: Can't select card (UID)");
				continue;
			}
		}
		
		// Sending timeslot of ISO14443a frame		
		sync_time = (sync_time & 0xfffffff8 ) + sync_cycles + catch_up_cycles;
		catch_up_cycles = 0;
								
		// if we missed the sync time already, advance to the next nonce repeat
		while( GetCountSspClk() > sync_time) {
			++elapsed_prng_sequences;
			sync_time = (sync_time & 0xfffffff8 ) + sync_cycles;
		}		

		// Transmit MIFARE_CLASSIC_AUTH at synctime. Should result in returning the same tag nonce (== nt_attacked)
		ReaderTransmit(mf_auth, sizeof(mf_auth), &sync_time);

		// Receive the (4 Byte) "random" nonce from TAG
		if (!ReaderReceive(receivedAnswer, receivedAnswerPar))
			continue;

		previous_nt = nt;
		nt = bytes_to_num(receivedAnswer, 4);
		
		// Transmit reader nonce with fake par
		ReaderTransmitPar(mf_nr_ar, sizeof(mf_nr_ar), par, NULL);
	
		// we didn't calibrate our clock yet,
		// iceman: has to be calibrated every time.
		if (previous_nt && !nt_attacked) { 

			nt_distance = dist_nt(previous_nt, nt);
			
			// if no distance between,  then we are in sync.
			if (nt_distance == 0) {
				nt_attacked = nt;
			} else {
				if (nt_distance == -99999) { // invalid nonce received
					++unexpected_random;
					if (unexpected_random > MAX_UNEXPECTED_RANDOM) {
						isOK = -3;		// Card has an unpredictable PRNG. Give up	
						break;
					} else {						
						if (sync_cycles <= 0) sync_cycles += PRNG_SEQUENCE_LENGTH;
						LED_B_OFF();
						continue;		// continue trying...
					}
				}
				
				if (++sync_tries > MAX_SYNC_TRIES) {
					isOK = -4; 			// Card's PRNG runs at an unexpected frequency or resets unexpectedly
					break;
				}
				
				sync_cycles = (sync_cycles - nt_distance)/elapsed_prng_sequences;
				
				if (sync_cycles <= 0)
					sync_cycles += PRNG_SEQUENCE_LENGTH;
				
				if (MF_DBGLEVEL >= 4)
					Dbprintf("calibrating in cycle %d. nt_distance=%d, elapsed_prng_sequences=%d, new sync_cycles: %d\n", i, nt_distance, elapsed_prng_sequences, sync_cycles);

				LED_B_OFF();
				continue;
			}
		}
		LED_B_OFF();

		if ( (nt != nt_attacked) && nt_attacked) { 	// we somehow lost sync. Try to catch up again...
			
			catch_up_cycles = ABS(dist_nt(nt_attacked, nt));
			if (catch_up_cycles == 99999) {			// invalid nonce received. Don't resync on that one.
				catch_up_cycles = 0;
				continue;
			}		
			// average? 
			catch_up_cycles /= elapsed_prng_sequences;
		
			if (catch_up_cycles == last_catch_up) {
				++consecutive_resyncs;
			} else {
				last_catch_up = catch_up_cycles;
			    consecutive_resyncs = 0;
			}		
			
			if (consecutive_resyncs < 3) {
				if (MF_DBGLEVEL >= 4)
					Dbprintf("Lost sync in cycle %d. nt_distance=%d. Consecutive Resyncs = %d. Trying one time catch up...\n", i, catch_up_cycles, consecutive_resyncs);
			} else {	
				sync_cycles += catch_up_cycles;
				
				if (MF_DBGLEVEL >= 4) 
					Dbprintf("Lost sync in cycle %d for the fourth time consecutively (nt_distance = %d). Adjusting sync_cycles to %d.\n", i, catch_up_cycles, sync_cycles);

				last_catch_up = 0;
				catch_up_cycles = 0;
				consecutive_resyncs = 0;
			}
			continue;
		}
 
		// Receive answer. This will be a 4 Bit NACK when the 8 parity bits are OK after decoding
		if (ReaderReceive(receivedAnswer, receivedAnswerPar)) {
			catch_up_cycles = 8; 	// the PRNG is delayed by 8 cycles due to the NAC (4Bits = 0x05 encrypted) transfer
	
			if (nt_diff == 0)
				par_low = par[0] & 0xE0; // there is no need to check all parities for other nt_diff. Parity Bits for mf_nr_ar[0..2] won't change

			par_list[nt_diff] = SwapBits(par[0], 8);
			ks_list[nt_diff] = receivedAnswer[0] ^ 0x05;  // xor with NACK value to get keystream

			// Test if the information is complete
			if (nt_diff == 0x07) {
				isOK = 1;
				break;
			}

			nt_diff = (nt_diff + 1) & 0x07;
			mf_nr_ar[3] = (mf_nr_ar[3] & 0x1F) | (nt_diff << 5);
			par[0] = par_low;
			
		} else {
			// No NACK.	
			if (nt_diff == 0 && first_try) {
				par[0]++;
				if (par[0] == 0x00) {	// tried all 256 possible parities without success. Card doesn't send NACK.
					isOK = -2;
					break;
				}
			} else {
				// Why this?
				par[0] = ((par[0] & 0x1F) + 1) | par_low;
			}
		}
		
		// reset the resyncs since we got a complete transaction on right time.
		consecutive_resyncs = 0;
	} // end for loop

	mf_nr_ar[3] &= 0x1F;

	if (MF_DBGLEVEL >= 4) Dbprintf("Number of sent auth requestes: %u", i);
	
	uint8_t buf[28] = {0x00};
	memset(buf, 0x00, sizeof(buf));
	num_to_bytes(cuid, 4, buf);
	num_to_bytes(nt, 4, buf + 4);
	memcpy(buf + 8,  par_list, 8);
	memcpy(buf + 16, ks_list, 8);
	memcpy(buf + 24, mf_nr_ar, 4);
		
	cmd_send(CMD_ACK, isOK, 0, 0, buf, sizeof(buf) );

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);
}


/**
  *MIFARE 1K simulate.
  *
  *@param flags :
  *	FLAG_INTERACTIVE		- In interactive mode, we are expected to finish the operation with an ACK
  * FLAG_4B_UID_IN_DATA		- use 4-byte UID in the data-section
  * FLAG_7B_UID_IN_DATA		- use 7-byte UID in the data-section
  * FLAG_10B_UID_IN_DATA	- use 10-byte UID in the data-section
  * FLAG_UID_IN_EMUL 		- use 4-byte UID from emulator memory
  *	FLAG_NR_AR_ATTACK  		- collect NR_AR responses for bruteforcing later
  *@param exitAfterNReads, exit simulation after n blocks have been read, 0 is inifite
  */
void Mifare1ksim(uint8_t flags, uint8_t exitAfterNReads, uint8_t arg2, uint8_t *datain) {
	int cardSTATE = MFEMUL_NOFIELD;
	int _UID_LEN = 0;  // 4, 7, 10
	int vHf = 0;	// in mV
	int res = 0;
	uint32_t selTimer = 0;
	uint32_t authTimer = 0;
	uint16_t len = 0;
	uint8_t cardWRBL = 0;
	uint8_t cardAUTHSC = 0;
	uint8_t cardAUTHKEY = 0xff;  // no authentication
	uint32_t cuid = 0;
	uint32_t ans = 0;
	uint32_t cardINTREG = 0;
	uint8_t cardINTBLOCK = 0;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;
	uint32_t numReads = 0;	// Counts numer of times reader read a block
	uint8_t receivedCmd[MAX_MIFARE_FRAME_SIZE] = {0x00};
	uint8_t receivedCmd_par[MAX_MIFARE_PARITY_SIZE] = {0x00};
	uint8_t response[MAX_MIFARE_FRAME_SIZE] = {0x00};
	uint8_t response_par[MAX_MIFARE_PARITY_SIZE] = {0x00};
	
	uint8_t atqa[]   = {0x04, 0x00}; // Mifare classic 1k
	uint8_t sak_4[]  = {0x0C, 0x00, 0x00}; // CL1 - 4b uid
	uint8_t sak_7[]  = {0x0C, 0x00, 0x00}; // CL2 - 7b uid
	uint8_t sak_10[] = {0x0C, 0x00, 0x00}; // CL3 - 10b uid
	// uint8_t sak[] = {0x09, 0x3f, 0xcc };  // Mifare Mini 
	
	uint8_t rUIDBCC1[] = {0xde, 0xad, 0xbe, 0xaf, 0x62}; 
	uint8_t rUIDBCC2[] = {0xde, 0xad, 0xbe, 0xaf, 0x62}; 
	uint8_t rUIDBCC3[] = {0xde, 0xad, 0xbe, 0xaf, 0x62};

	uint8_t rAUTH_NT[] = {0x01, 0x01, 0x01, 0x01};	// very random nonce
	// uint8_t rAUTH_NT[] = {0x55, 0x41, 0x49, 0x92};// nonce from nested? why this?
	uint8_t rAUTH_AT[] = {0x00, 0x00, 0x00, 0x00};
		
	// Here, we collect CUID, NT, NR, AR, CUID2, NT2, NR2, AR2
	// This can be used in a reader-only attack.
	uint32_t ar_nr_responses[] = {0,0,0,0,0,0,0,0,0};
	uint8_t ar_nr_collected = 0;

	// Authenticate response - nonce
	uint32_t nonce = bytes_to_num(rAUTH_NT, 4);
	ar_nr_responses[1] = nonce;
	
	// -- Determine the UID
	// Can be set from emulator memory or incoming data
	// Length: 4,7,or 10 bytes
	if ( (flags & FLAG_UID_IN_EMUL) == FLAG_UID_IN_EMUL)
		emlGetMemBt(datain, 0, 10);  // load 10bytes from EMUL to the datain pointer. to be used below.
	
	if ( (flags & FLAG_4B_UID_IN_DATA) == FLAG_4B_UID_IN_DATA) {
		memcpy(rUIDBCC1, datain, 4);
		_UID_LEN = 4;
	} else if ( (flags & FLAG_7B_UID_IN_DATA) == FLAG_7B_UID_IN_DATA) {
		memcpy(&rUIDBCC1[1], datain,   3);
		memcpy( rUIDBCC2,    datain+3, 4);
		_UID_LEN = 7;
	} else if ( (flags & FLAG_10B_UID_IN_DATA) == FLAG_10B_UID_IN_DATA) {
		memcpy(&rUIDBCC1[1], datain,   3);
		memcpy(&rUIDBCC2[1], datain+3, 3);
		memcpy( rUIDBCC3,    datain+6, 4);
		_UID_LEN = 10;
	}

	switch (_UID_LEN) {
		case 4:
			sak_4[0] &= 0xFB;		
			// save CUID
			ar_nr_responses[0] = cuid = bytes_to_num(rUIDBCC1, 4);
			// BCC
			rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
			if (MF_DBGLEVEL >= 2)	{
				Dbprintf("4B UID: %02x%02x%02x%02x", 
					rUIDBCC1[0],
					rUIDBCC1[1],
					rUIDBCC1[2],
					rUIDBCC1[3]
				);
			}
			break;
		case 7:
			atqa[0] |= 0x40;
			sak_7[0] &= 0xFB;						
			// save CUID
			ar_nr_responses[0] = cuid = bytes_to_num(rUIDBCC2, 4);			
			 // CascadeTag, CT
			rUIDBCC1[0] = 0x88;
			// BCC
			rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3]; 
			rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3]; 
			if (MF_DBGLEVEL >= 2)	{
				Dbprintf("7B UID: %02x %02x %02x %02x %02x %02x %02x",
					rUIDBCC1[1],
					rUIDBCC1[2],
					rUIDBCC1[3],
					rUIDBCC2[0],
					rUIDBCC2[1],
					rUIDBCC2[2],
					rUIDBCC2[3]
				);
			}
			break;
		case 10:
			atqa[0] |= 0x80;
			sak_10[0] &= 0xFB;					
			// save CUID
			ar_nr_responses[0] = cuid = bytes_to_num(rUIDBCC3, 4);
			 // CascadeTag, CT
			rUIDBCC1[0] = 0x88;
			rUIDBCC2[0] = 0x88;
			// BCC
			rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
			rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
			rUIDBCC3[4] = rUIDBCC3[0] ^ rUIDBCC3[1] ^ rUIDBCC3[2] ^ rUIDBCC3[3];

			if (MF_DBGLEVEL >= 2)	{
				Dbprintf("10B UID: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
					rUIDBCC1[1],
					rUIDBCC1[2],
					rUIDBCC1[3],
					rUIDBCC2[1],
					rUIDBCC2[2],
					rUIDBCC2[3],
					rUIDBCC3[0],
					rUIDBCC3[1],
					rUIDBCC3[2],
					rUIDBCC3[3]
				);
			}
			break;
		default: 
			break;
	}
	// calc some crcs
	ComputeCrc14443(CRC_14443_A, sak_4, 1, &sak_4[1], &sak_4[2]);
	ComputeCrc14443(CRC_14443_A, sak_7, 1, &sak_7[1], &sak_7[2]);
	ComputeCrc14443(CRC_14443_A, sak_10, 1, &sak_10[1], &sak_10[2]);
	
	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

	// free eventually allocated BigBuf memory but keep Emulator Memory
	BigBuf_free_keep_EM();
	clear_trace();
	set_tracing(TRUE);

	bool finished = FALSE;
	while (!BUTTON_PRESS() && !finished && !usb_poll_validate_length()) {
		WDT_HIT();

		// find reader field
		if (cardSTATE == MFEMUL_NOFIELD) {
			vHf = (MAX_ADC_HF_VOLTAGE * AvgAdc(ADC_CHAN_HF)) >> 10;
			if (vHf > MF_MINFIELDV) {
				cardSTATE_TO_IDLE();
				LED_A_ON();
			}
		} 
		if (cardSTATE == MFEMUL_NOFIELD) continue;

		// Now, get data
		res = EmGetCmd(receivedCmd, &len, receivedCmd_par);
		if (res == 2) { //Field is off!
			cardSTATE = MFEMUL_NOFIELD;
			LEDsoff();
			continue;
		} else if (res == 1) {
			break; 	// return value 1 means button press
		}
			
		// REQ or WUP request in ANY state and WUP in HALTED state
		// this if-statement doesn't match the specification above. (iceman)
		if (len == 1 && ((receivedCmd[0] == ISO14443A_CMD_REQA && cardSTATE != MFEMUL_HALTED) || receivedCmd[0] == ISO14443A_CMD_WUPA)) {
			selTimer = GetTickCount();
			EmSendCmdEx(atqa, sizeof(atqa), (receivedCmd[0] == ISO14443A_CMD_WUPA));
			cardSTATE = MFEMUL_SELECT1;
			crypto1_destroy(pcs);
			cardAUTHKEY = 0xff;
			LEDsoff();
			nonce++; 
			continue;
		}
		
		switch (cardSTATE) {
			case MFEMUL_NOFIELD:
			case MFEMUL_HALTED:
			case MFEMUL_IDLE:{
				LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
				break;
			}
			case MFEMUL_SELECT1:{
				if (len == 2 && (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && receivedCmd[1] == 0x20)) {
					if (MF_DBGLEVEL >= 4)	Dbprintf("SELECT ALL received");
					EmSendCmd(rUIDBCC1, sizeof(rUIDBCC1));
					break;
				}
				// select card
				if (len == 9 && 
						( receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT &&
						  receivedCmd[1] == 0x70 && 
						  memcmp(&receivedCmd[2], rUIDBCC1, 4) == 0)) {
					
					// SAK 4b 
					EmSendCmd(sak_4, sizeof(sak_4));
					switch(_UID_LEN){
						case 4:
							cardSTATE = MFEMUL_WORK;
							LED_B_ON();
							if (MF_DBGLEVEL >= 4)	Dbprintf("--> WORK. anticol1 time: %d", GetTickCount() - selTimer);
							continue;
						case 7:
						case 10:
							cardSTATE = MFEMUL_SELECT2;
							continue;
						default:break;
					}
				} else {
					cardSTATE_TO_IDLE();
				}
				break;
			}
			case MFEMUL_SELECT2:{
				if (!len) { 
					LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
					break;
				}
				if (len == 2 && (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && receivedCmd[1] == 0x20)) {
					EmSendCmd(rUIDBCC2, sizeof(rUIDBCC2));
					break;
				}
				if (len == 9 && 
						(receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 &&
						 receivedCmd[1] == 0x70 && 
						 memcmp(&receivedCmd[2], rUIDBCC2, 4) == 0) ) {
							 
					EmSendCmd(sak_7, sizeof(sak_7));
					switch(_UID_LEN){
						case 7:
							cardSTATE = MFEMUL_WORK;
							LED_B_ON();
							if (MF_DBGLEVEL >= 4)	Dbprintf("--> WORK. anticol2 time: %d", GetTickCount() - selTimer);
							continue;
						case 10:
							cardSTATE = MFEMUL_SELECT3;
							continue;
						default:break;
					}
				} 
				cardSTATE_TO_IDLE();
				break;
			}
			case MFEMUL_SELECT3:{
				if (!len) { 
					LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
					break;
				}
				if (len == 2 && (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 && receivedCmd[1] == 0x20)) {
					EmSendCmd(rUIDBCC3, sizeof(rUIDBCC3));
					break;
				}
				if (len == 9 && 
						(receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 &&
						 receivedCmd[1] == 0x70 && 
						 memcmp(&receivedCmd[2], rUIDBCC3, 4) == 0) ) {

					EmSendCmd(sak_10, sizeof(sak_10));
					cardSTATE = MFEMUL_WORK;
					LED_B_ON();
					if (MF_DBGLEVEL >= 4)	Dbprintf("--> WORK. anticol3 time: %d", GetTickCount() - selTimer);
					break;
				}
				cardSTATE_TO_IDLE();
				break;
			}
			case MFEMUL_AUTH1:{
				if( len != 8) {
					cardSTATE_TO_IDLE();
					LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
					break;
				}

				uint32_t nr = bytes_to_num(receivedCmd, 4);
				uint32_t ar = bytes_to_num(&receivedCmd[4], 4);

				// Collect AR/NR
				// if(ar_nr_collected < 2 && cardAUTHSC == 2){
				if(ar_nr_collected < 2) {					
					// if(ar_nr_responses[2] != nr) {
						ar_nr_responses[ar_nr_collected*4]   = cuid;
						ar_nr_responses[ar_nr_collected*4+1] = nonce;
						ar_nr_responses[ar_nr_collected*4+2] = nr;
						ar_nr_responses[ar_nr_collected*4+3] = ar;
						ar_nr_collected++;
					// }					
		
					// Interactive mode flag, means we need to send ACK
					finished = ( ((flags & FLAG_INTERACTIVE) == FLAG_INTERACTIVE)&& ar_nr_collected == 2);
				}
				/*
				crypto1_word(pcs, ar , 1);
				cardRr = nr ^ crypto1_word(pcs, 0, 0);
				
				test if auth OK
				if (cardRr != prng_successor(nonce, 64)){
					
					if (MF_DBGLEVEL >= 4) Dbprintf("AUTH FAILED for sector %d with key %c. cardRr=%08x, succ=%08x",
						cardAUTHSC, cardAUTHKEY == 0 ? 'A' : 'B',
							cardRr, prng_successor(nonce, 64));
					Shouldn't we respond anything here?
					Right now, we don't nack or anything, which causes the
					reader to do a WUPA after a while. /Martin
					-- which is the correct response. /piwi
					cardSTATE_TO_IDLE();
					LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
					break;
				}
				*/
				
				ans = prng_successor(nonce, 96) ^ crypto1_word(pcs, 0, 0);
				num_to_bytes(ans, 4, rAUTH_AT);
				EmSendCmd(rAUTH_AT, sizeof(rAUTH_AT));
				LED_C_ON();
				
				if (MF_DBGLEVEL >= 4) {
					Dbprintf("AUTH COMPLETED for sector %d with key %c. time=%d", 
						cardAUTHSC, 
						cardAUTHKEY == 0 ? 'A' : 'B',
						GetTickCount() - authTimer
					);
				}
				cardSTATE = MFEMUL_WORK;
				break;
			}
			case MFEMUL_WORK:{
				if (len == 0) {
					LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
					break;
				}		
				bool encrypted_data = (cardAUTHKEY != 0xFF) ;

				if(encrypted_data)
					mf_crypto1_decrypt(pcs, receivedCmd, len);
				
				if (len == 4 && (receivedCmd[0] == MIFARE_AUTH_KEYA || 
				                 receivedCmd[0] == MIFARE_AUTH_KEYB)  ) {

					authTimer = GetTickCount();
					cardAUTHSC = receivedCmd[1] / 4;  // received block num
					cardAUTHKEY = receivedCmd[0] - 0x60; // & 1
					crypto1_destroy(pcs);
					crypto1_create(pcs, emlGetKey(cardAUTHSC, cardAUTHKEY));

					if (!encrypted_data) { 
						// first authentication
						crypto1_word(pcs, cuid ^ nonce, 0);// Update crypto state
						num_to_bytes(nonce, 4, rAUTH_AT); // Send nonce
						
						if (MF_DBGLEVEL >= 4) Dbprintf("Reader authenticating for block %d (0x%02x) with key %d",receivedCmd[1] ,receivedCmd[1],cardAUTHKEY  );

					} else {
						// nested authentication
						ans = nonce ^ crypto1_word(pcs, cuid ^ nonce, 0); 
						num_to_bytes(ans, 4, rAUTH_AT);

						if (MF_DBGLEVEL >= 4) Dbprintf("Reader doing nested authentication for block %d (0x%02x) with key %d",receivedCmd[1] ,receivedCmd[1],cardAUTHKEY );
					}

					EmSendCmd(rAUTH_AT, sizeof(rAUTH_AT));
					cardSTATE = MFEMUL_AUTH1;
					break;
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
				
				if(len != 4) {
					LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
					break;
				}

				if ( receivedCmd[0] == ISO14443A_CMD_READBLOCK ||
					 receivedCmd[0] == ISO14443A_CMD_WRITEBLOCK ||
					 receivedCmd[0] == MIFARE_CMD_INC ||
					 receivedCmd[0] == MIFARE_CMD_DEC ||
					 receivedCmd[0] == MIFARE_CMD_RESTORE ||
					 receivedCmd[0] == MIFARE_CMD_TRANSFER ) {
						
					if (receivedCmd[1] >= 16 * 4) {
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
						if (MF_DBGLEVEL >= 4) Dbprintf("Reader tried to operate (0x%02) on out of range block: %d (0x%02x), nacking",receivedCmd[0],receivedCmd[1],receivedCmd[1]);
						break;
					}

					if (receivedCmd[1] / 4 != cardAUTHSC) {
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
						if (MF_DBGLEVEL >= 4) Dbprintf("Reader tried to operate (0x%02) on block (0x%02x) not authenticated for (0x%02x), nacking",receivedCmd[0],receivedCmd[1],cardAUTHSC);
						break;
					}
				}
				// read block
				if (receivedCmd[0] == ISO14443A_CMD_READBLOCK) {
					if (MF_DBGLEVEL >= 4) Dbprintf("Reader reading block %d (0x%02x)", receivedCmd[1], receivedCmd[1]);

					emlGetMem(response, receivedCmd[1], 1);
					AppendCrc14443a(response, 16);
					mf_crypto1_encrypt(pcs, response, 18, response_par);
					EmSendCmdPar(response, 18, response_par);
					numReads++;
					if(exitAfterNReads > 0 && numReads >= exitAfterNReads) {
						Dbprintf("%d reads done, exiting", numReads);
						finished = true;
					}
					break;
				}
				// write block
				if (receivedCmd[0] == ISO14443A_CMD_WRITEBLOCK) {
					if (MF_DBGLEVEL >= 4) Dbprintf("RECV 0xA0 write block %d (%02x)", receivedCmd[1], receivedCmd[1]);
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
					cardSTATE = MFEMUL_WRITEBL2;
					cardWRBL = receivedCmd[1];
					break;
				}
				// increment, decrement, restore
				if ( receivedCmd[0] == MIFARE_CMD_INC || 
				     receivedCmd[0] == MIFARE_CMD_DEC || 
					 receivedCmd[0] == MIFARE_CMD_RESTORE) {

					 if (MF_DBGLEVEL >= 4) Dbprintf("RECV 0x%02x inc(0xC1)/dec(0xC0)/restore(0xC2) block %d (%02x)",receivedCmd[0], receivedCmd[1], receivedCmd[1]);

					if (emlCheckValBl(receivedCmd[1])) {
						if (MF_DBGLEVEL >= 4) Dbprintf("Reader tried to operate on block, but emlCheckValBl failed, nacking");
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
						break;
					}
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
					if (receivedCmd[0] == MIFARE_CMD_INC)		cardSTATE = MFEMUL_INTREG_INC;
					if (receivedCmd[0] == MIFARE_CMD_DEC)		cardSTATE = MFEMUL_INTREG_DEC;
					if (receivedCmd[0] == MIFARE_CMD_RESTORE)	cardSTATE = MFEMUL_INTREG_REST;
					cardWRBL = receivedCmd[1];
					break;
				}
				// transfer
				if (receivedCmd[0] == MIFARE_CMD_TRANSFER) {
					if (MF_DBGLEVEL >= 4) Dbprintf("RECV 0x%02x transfer block %d (%02x)", receivedCmd[0], receivedCmd[1], receivedCmd[1]);
					if (emlSetValBl(cardINTREG, cardINTBLOCK, receivedCmd[1]))
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
					else
						EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
					break;
				}
				// halt
				if (receivedCmd[0] == ISO14443A_CMD_HALT && receivedCmd[1] == 0x00) {
					LED_B_OFF();
					LED_C_OFF();
					cardSTATE = MFEMUL_HALTED;
					if (MF_DBGLEVEL >= 4)	Dbprintf("--> HALTED. Selected time: %d ms",  GetTickCount() - selTimer);
					LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
					break;
				}
				// RATS
				if (receivedCmd[0] == ISO14443A_CMD_RATS) {
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
					break;
				}
				// command not allowed
				if (MF_DBGLEVEL >= 4)	Dbprintf("Received command not allowed, nacking");
				EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
				break;
			}
			case MFEMUL_WRITEBL2:{
				if (len == 18) {
					mf_crypto1_decrypt(pcs, receivedCmd, len);
					emlSetMem(receivedCmd, cardWRBL, 1);
					EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
					cardSTATE = MFEMUL_WORK;
				} else {
					cardSTATE_TO_IDLE();
					LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
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
				LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
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
				LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
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
				LogTrace(Uart.output, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, TRUE);
				cardSTATE = MFEMUL_WORK;
				break;
			}
		}
	}

	// Interactive mode flag, means we need to send ACK
	if((flags & FLAG_INTERACTIVE) == FLAG_INTERACTIVE) {
		// May just aswell send the collected ar_nr in the response aswell
		uint8_t len = ar_nr_collected * 4 * 4;
		cmd_send(CMD_ACK, CMD_SIMULATE_MIFARE_CARD, len, 0, &ar_nr_responses, len);
	}

	if( ((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK ) && MF_DBGLEVEL >= 1 ) {
		if(ar_nr_collected > 1 ) {
			Dbprintf("Collected two pairs of AR/NR which can be used to extract keys from reader:");
			Dbprintf("../tools/mfkey/mfkey32v2.exe %08x %08x %08x %08x %08x %08x %08x",
					ar_nr_responses[0], // CUID
					ar_nr_responses[1], // NT1
					ar_nr_responses[2], // NR1
					ar_nr_responses[3], // AR1
					// ar_nr_responses[4], // CUID2
					ar_nr_responses[5],  // NT2
					ar_nr_responses[6], // NR2
					ar_nr_responses[7]  // AR2
				);
		} else {
			Dbprintf("Failed to obtain two AR/NR pairs!");
			if(ar_nr_collected == 1 ) {
				Dbprintf("Only got these: UID=%08x, nonce=%08x, NR1=%08x, AR1=%08x",
						ar_nr_responses[0], // CUID
						ar_nr_responses[1], // NT
						ar_nr_responses[2], // NR1
						ar_nr_responses[3]  // AR1
					);
			}
		}
	}
	if (MF_DBGLEVEL >= 1) Dbprintf("Emulator stopped. Tracing: %d  trace length: %d ", tracing, BigBuf_get_traceLen());
	
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);
}


//-----------------------------------------------------------------------------
// MIFARE sniffer. 
// 
// if no activity for 2sec, it sends the collected data to the client.
//-----------------------------------------------------------------------------
// "hf mf sniff"
void RAMFUNC SniffMifare(uint8_t param) {

	LEDsoff();

	// free eventually allocated BigBuf memory
	BigBuf_free(); BigBuf_Clear_ext(false);
	clear_trace();
	set_tracing(TRUE);

	// The command (reader -> tag) that we're receiving.
	uint8_t receivedCmd[MAX_MIFARE_FRAME_SIZE] = {0x00};	
	uint8_t receivedCmdPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

	// The response (tag -> reader) that we're receiving.
	uint8_t receivedResponse[MAX_MIFARE_FRAME_SIZE] = {0x00};
	uint8_t receivedResponsePar[MAX_MIFARE_PARITY_SIZE] = {0x00};

	iso14443a_setup(FPGA_HF_ISO14443A_SNIFFER);

	// allocate the DMA buffer, used to stream samples from the FPGA
	// [iceman] is this sniffed data unsigned?
	uint8_t *dmaBuf = BigBuf_malloc(DMA_BUFFER_SIZE);
	uint8_t *data = dmaBuf;
	uint8_t previous_data = 0;
	int maxDataLen = 0;
	int dataLen = 0;
	bool ReaderIsActive = FALSE;
	bool TagIsActive = FALSE;

	// Set up the demodulator for tag -> reader responses.
	DemodInit(receivedResponse, receivedResponsePar);

	// Set up the demodulator for the reader -> tag commands
	UartInit(receivedCmd, receivedCmdPar);

	// Setup and start DMA.
	// set transfer address and number of bytes. Start transfer.
	if ( !FpgaSetupSscDma((uint8_t*) dmaBuf, DMA_BUFFER_SIZE) ){
		if (MF_DBGLEVEL > 1) Dbprintf("FpgaSetupSscDma failed. Exiting"); 
		return;
	}

	LED_D_OFF();

	MfSniffInit();

	// And now we loop, receiving samples.
	for(uint32_t sniffCounter = 0;; ) {

		LED_A_ON();
		WDT_HIT();
	
		if(BUTTON_PRESS()) {
			DbpString("cancelled by button");
			break;
		}
	
 		if ((sniffCounter & 0x0000FFFF) == 0) {	// from time to time
			// check if a transaction is completed (timeout after 2000ms).
			// if yes, stop the DMA transfer and send what we have so far to the client
			if (MfSniffSend(2000)) {			
				// Reset everything - we missed some sniffed data anyway while the DMA was stopped
				sniffCounter = 0;
				data = dmaBuf;
				maxDataLen = 0;
				ReaderIsActive = FALSE;
				TagIsActive = FALSE;
				// Setup and start DMA. set transfer address and number of bytes. Start transfer.
				if ( !FpgaSetupSscDma((uint8_t*) dmaBuf, DMA_BUFFER_SIZE) ){
					if (MF_DBGLEVEL > 1) Dbprintf("FpgaSetupSscDma failed. Exiting"); 
					return;
				}				
			}
		}
		
		int register readBufDataP = data - dmaBuf;	// number of bytes we have processed so far
		int register dmaBufDataP = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR; // number of bytes already transferred

		if (readBufDataP <= dmaBufDataP)			// we are processing the same block of data which is currently being transferred
			dataLen = dmaBufDataP - readBufDataP;	// number of bytes still to be processed
		else
			dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP; // number of bytes still to be processed

		// test for length of buffer
		if(dataLen > maxDataLen) {					// we are more behind than ever...
			maxDataLen = dataLen;					
			if(dataLen > (9 * DMA_BUFFER_SIZE / 10)) {
				Dbprintf("blew circular buffer! dataLen=0x%x", dataLen);
				break;
			}
		}
		if(dataLen < 1) continue;

		// primary buffer was stopped ( <-- we lost data!
		if (!AT91C_BASE_PDC_SSC->PDC_RCR) {
			AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
			Dbprintf("RxEmpty ERROR, data length:%d", dataLen); // temporary
		}
		// secondary buffer sets as primary, secondary buffer was stopped
		if (!AT91C_BASE_PDC_SSC->PDC_RNCR) {
			AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
		}

		LED_A_OFF();
		
		if (sniffCounter & 0x01) {

			// no need to try decoding tag data if the reader is sending
			if(!TagIsActive) {		
				uint8_t readerdata = (previous_data & 0xF0) | (*data >> 4);
				if(MillerDecoding(readerdata, (sniffCounter-1)*4)) {
					LED_C_INV();

					if (MfSniffLogic(receivedCmd, Uart.len, Uart.parity, Uart.bitCount, TRUE)) break;

					UartInit(receivedCmd, receivedCmdPar);
					DemodReset();
				}
				ReaderIsActive = (Uart.state != STATE_UNSYNCD);
			}
			
			// no need to try decoding tag data if the reader is sending
			if(!ReaderIsActive) {		
				uint8_t tagdata = (previous_data << 4) | (*data & 0x0F);
				if(ManchesterDecoding(tagdata, 0, (sniffCounter-1)*4)) {
					LED_C_INV();

					if (MfSniffLogic(receivedResponse, Demod.len, Demod.parity, Demod.bitCount, FALSE)) break;

					DemodReset();
					UartInit(receivedCmd, receivedCmdPar);
				}
				TagIsActive = (Demod.state != DEMOD_UNSYNCD);
			}
		}

		previous_data = *data;
		sniffCounter++;
		data++;

		if(data == dmaBuf + DMA_BUFFER_SIZE)
			data = dmaBuf;

	} // main cycle
	
	if (MF_DBGLEVEL >= 1) Dbprintf("maxDataLen=%x, Uart.state=%x, Uart.len=%x", maxDataLen, Uart.state, Uart.len);
	
	FpgaDisableSscDma();
	MfSniffEnd();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);
}
