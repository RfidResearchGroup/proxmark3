//-----------------------------------------------------------------------------
// Jonathan Westhues, split Nov 2006
// Modified by Greg Jones, Jan 2009
// Modified by Adrian Dabrowski "atrox", Mar-Sept 2010,Oct 2011
// Modified by Christian Herrmann "iceman", 2017
// Modified by piwi, Oct 2018
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 15693. This includes both the reader software and
// the `fake tag' modes.
//-----------------------------------------------------------------------------

// The ISO 15693 describes two transmission modes from reader to tag, and four
// transmission modes from tag to reader. As of Oct 2018 this code supports
// both reader modes and the high speed variant with one subcarrier from card to reader.
// As long as the card fully support ISO 15693 this is no problem, since the
// reader chooses both data rates, but some non-standard tags do not.
// For card simulation, the code supports both high and low speed modes with one subcarrier.
//
// VCD (reader) -> VICC (tag)
// 1 out of 256:
//  data rate: 1,66 kbit/s (fc/8192)
//  used for long range
// 1 out of 4:
//  data rate: 26,48 kbit/s (fc/512)
//  used for short range, high speed
//
// VICC (tag) -> VCD (reader)
// Modulation:
//    ASK / one subcarrier (423,75 kHz)
//    FSK / two subcarriers (423,75 kHz && 484,28 kHz)
// Data Rates / Modes:
//  low ASK: 6,62 kbit/s
//  low FSK: 6.67 kbit/s
//  high ASK: 26,48 kbit/s
//  high FSK: 26,69 kbit/s
//-----------------------------------------------------------------------------
// added "1 out of 256" mode (for VCD->PICC) - atrox 20100911


// Random Remarks:
// *) UID is always used "transmission order" (LSB), which is reverse to display order

// TODO / BUGS / ISSUES:
// *) signal decoding is unable to detect collisions.
// *) add anti-collision support for inventory-commands
// *) read security status of a block
// *) sniffing and simulation do not support two subcarrier modes.
// *) remove or refactor code under "deprecated"
// *) document all the functions

#include "iso15693.h"

#include "proxmark3_arm.h"
#include "util.h"
#include "string.h"
#include "iso15693tools.h"
#include "cmd.h"
#include "appmain.h"
#include "dbprint.h"
#include "fpgaloader.h"
#include "commonutil.h"
#include "ticks.h"
#include "BigBuf.h"
#include "crc16.h"
					
// Delays in SSP_CLK ticks.
// SSP_CLK runs at 13,56MHz / 32 = 423.75kHz when simulating a tag
#define DELAY_READER_TO_ARM               8
#define DELAY_ARM_TO_READER               0

//SSP_CLK runs at 13.56MHz / 4 = 3,39MHz when acting as reader. All values should be multiples of 16
#define DELAY_ARM_TO_TAG                 16
#define DELAY_TAG_TO_ARM                 32

//SSP_CLK runs at 13.56MHz / 4 = 3,39MHz when snooping. All values should be multiples of 16
#define DELAY_TAG_TO_ARM_SNIFF           32
#define DELAY_READER_TO_ARM_SNIFF        32

// times in samples @ 212kHz when acting as reader
#define ISO15693_READER_TIMEOUT             330 // 330/212kHz = 1558us, should be even enough for iClass tags responding to ACTALL
#define ISO15693_READER_TIMEOUT_WRITE      4700 // 4700/212kHz = 22ms, nominal 20ms


///////////////////////////////////////////////////////////////////////
// ISO 15693 Part 2 - Air Interface
// This section basically contains transmission and receiving of bits
///////////////////////////////////////////////////////////////////////

// buffers
#define ISO15693_DMA_BUFFER_SIZE        256 // must be a power of 2
#define ISO15693_MAX_RESPONSE_LENGTH     36 // allows read single block with the maximum block size of 256bits. Read multiple blocks not supported yet
#define ISO15693_MAX_COMMAND_LENGTH      45 // allows write single block with the maximum block size of 256bits. Write multiple blocks not supported yet


// 32 + 2 crc + 1
#define ISO15_MAX_FRAME 35
#define CMD_ID_RESP     5
#define CMD_READ_RESP   13
#define CMD_INV_RESP    12

#define FrameSOF              Iso15693FrameSOF
#define Logic0                Iso15693Logic0
#define Logic1                Iso15693Logic1
#define FrameEOF              Iso15693FrameEOF

//#define Crc(data, len)        Crc(CRC_15693, (data), (len))
#define CheckCrc15(data, len)   check_crc(CRC_15693, (data), (len))
#define AddCrc15(data, len)     compute_crc(CRC_15693, (data), (len), (data)+(len), (data)+(len)+1)

static void BuildIdentifyRequest(uint8_t *cmd);
static void BuildInventoryResponse(uint8_t *uid);

// ---------------------------
// Signal Processing
// ---------------------------

// prepare data using "1 out of 4" code for later transmission
// resulting data rate is 26.48 kbit/s (fc/512)
// cmd ... data
// n ... length of data
static void CodeIso15693AsReader(uint8_t *cmd, int n) {

 	ToSendReset();

	// SOF for 1of4
	ToSend[++ToSendMax] = 0x84; //10000100

	// data
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < 8; j += 2) {
			int these = (cmd[i] >> j) & 0x03;
			switch(these) {
				case 0:
					ToSend[++ToSendMax] = 0x40; //01000000
					break;
				case 1:
					ToSend[++ToSendMax] = 0x10; //00010000
					break;
				case 2:
					ToSend[++ToSendMax] = 0x04; //00000100
					break;
				case 3:
					ToSend[++ToSendMax] = 0x01; //00000001
					break;
			}
		}
	}

	// EOF
	ToSend[++ToSendMax] = 0x20; //0010 + 0000 padding

	ToSendMax++;
}

// Encode EOF only
static void CodeIso15693AsReaderEOF(void) {
	ToSendReset();
	ToSend[++ToSendMax] = 0x20;
	ToSendMax++;
}


// encode data using "1 out of 256" scheme
// data rate is 1,66 kbit/s (fc/8192)
// is designed for more robust communication over longer distances
static void CodeIso15693AsReader256(uint8_t *cmd, int n) {

	ToSendReset();

	// SOF for 1of256
	ToSend[++ToSendMax] = 0x81; //10000001

	// data
	for(int i = 0; i < n; i++) {
		for (int j = 0; j <= 255; j++) {
			if (cmd[i] == j) {
				ToSendStuffBit(0);
				ToSendStuffBit(1);
			} else {
				ToSendStuffBit(0);
				ToSendStuffBit(0);
			}
		}
	}

	// EOF
	ToSend[++ToSendMax] = 0x20; //0010 + 0000 padding

	ToSendMax++;
}

static const uint8_t encode_4bits[16] = { 0xaa, 0x6a, 0x9a, 0x5a, 0xa6, 0x66, 0x96, 0x56, 0xa9, 0x69, 0x99, 0x59, 0xa5, 0x65, 0x95, 0x55 };

static void CodeIso15693AsTag(uint8_t *cmd, size_t len) {
	/*
	 * SOF comprises 3 parts;
	 * * An unmodulated time of 56.64 us
	 * * 24 pulses of 423.75 kHz (fc/32)
	 * * A logic 1, which starts with an unmodulated time of 18.88us
	 *   followed by 8 pulses of 423.75kHz (fc/32)
	 *
	 * EOF comprises 3 parts:
	 * - A logic 0 (which starts with 8 pulses of fc/32 followed by an unmodulated
	 *   time of 18.88us.
	 * - 24 pulses of fc/32
	 * - An unmodulated time of 56.64 us
	 *
	 * A logic 0 starts with 8 pulses of fc/32
	 * followed by an unmodulated time of 256/fc (~18,88us).
	 *
	 * A logic 0 starts with unmodulated time of 256/fc (~18,88us) followed by
	 * 8 pulses of fc/32 (also 18.88us)
	 *
	 * A bit here becomes 8 pulses of fc/32. Therefore:
	 * The SOF can be written as 00011101 = 0x1D
	 * The EOF can be written as 10111000 = 0xb8
	 * A logic 1 is 01
	 * A logic 0 is 10
	 *
	 * */

	ToSendReset();

	// SOF
	ToSend[++ToSendMax] = 0x1D;  // 00011101

	// data
	for (int i = 0; i < len; i++) {
		ToSend[++ToSendMax] = encode_4bits[cmd[i] & 0xF];
		ToSend[++ToSendMax] = encode_4bits[cmd[i] >> 4];
	}

	// EOF
	ToSend[++ToSendMax] = 0xB8; // 10111000

	ToSendMax++;
}

// Transmit the command (to the tag) that was placed in cmd[].
static void TransmitTo15693Tag(const uint8_t *cmd, int len, uint32_t *start_time) {

	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SEND_FULL_MOD);

	if (*start_time < DELAY_ARM_TO_TAG) {
		*start_time = DELAY_ARM_TO_TAG;
	}

	*start_time = (*start_time - DELAY_ARM_TO_TAG) & 0xfffffff0;

	if (GetCountSspClk() > *start_time) { // we may miss the intended time
		*start_time = (GetCountSspClk() + 16) & 0xfffffff0; // next possible time
	}

	while (GetCountSspClk() < *start_time)
		/* wait */ ;

	LED_B_ON();
	for (int c = 0; c < len; c++) {
		uint8_t data = cmd[c];
		for (int i = 0; i < 8; i++) {
			uint16_t send_word = (data & 0x80) ? 0xffff : 0x0000;
			while (!(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))) ;
			AT91C_BASE_SSC->SSC_THR = send_word;
			while (!(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))) ;
			AT91C_BASE_SSC->SSC_THR = send_word;
			data <<= 1;
		}
		WDT_HIT();
	}
	LED_B_OFF();

	*start_time = *start_time + DELAY_ARM_TO_TAG;
}

//-----------------------------------------------------------------------------
// Transmit the command (to the reader) that was placed in cmd[].
//-----------------------------------------------------------------------------
static void TransmitTo15693Reader(const uint8_t *cmd, size_t len, uint32_t *start_time, uint32_t slot_time, bool slow) {

	// don't use the FPGA_HF_SIMULATOR_MODULATE_424K_8BIT minor mode. It would spoil GetCountSspClk()
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_MODULATE_424K);

	uint32_t modulation_start_time = *start_time - DELAY_ARM_TO_READER + 3 * 8;  // no need to transfer the unmodulated start of SOF

	while (GetCountSspClk() > (modulation_start_time & 0xfffffff8) + 3) { // we will miss the intended time
		if (slot_time) {
			modulation_start_time += slot_time; // use next available slot
		} else {
			modulation_start_time = (modulation_start_time & 0xfffffff8) + 8; // next possible time
		}
	}

	while (GetCountSspClk() < (modulation_start_time & 0xfffffff8))
		/* wait */ ;

	uint8_t shift_delay = modulation_start_time & 0x00000007;

	*start_time = modulation_start_time + DELAY_ARM_TO_READER - 3 * 8;

	LED_C_ON();
	uint8_t bits_to_shift = 0x00;
	uint8_t bits_to_send = 0x00;
	for (size_t c = 0; c < len; c++) {
		for (int i = (c==0?4:7); i >= 0; i--) {
			uint8_t cmd_bits = ((cmd[c] >> i) & 0x01) ? 0xff : 0x00;
			for (int j = 0; j < (slow?4:1); ) {
				if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) {
					bits_to_send = bits_to_shift << (8 - shift_delay) | cmd_bits >> shift_delay;
					AT91C_BASE_SSC->SSC_THR = bits_to_send;
					bits_to_shift = cmd_bits;
					j++;
				}
			}
		}
		WDT_HIT();
	}
	// send the remaining bits, padded with 0:
	bits_to_send = bits_to_shift << (8 - shift_delay);
	for ( ; ; ) {
		if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) {
			AT91C_BASE_SSC->SSC_THR = bits_to_send;
			break;
		}
	}
	LED_C_OFF();
}

//=============================================================================
// An ISO 15693 decoder for tag responses (one subcarrier only).
// Uses cross correlation to identify each bit and EOF.
// This function is called 8 times per bit (every 2 subcarrier cycles).
// Subcarrier frequency fs is 424kHz, 1/fs = 2,36us,
// i.e. function is called every 4,72us
// LED handling:
//    LED C -> ON once we have received the SOF and are expecting the rest.
//    LED C -> OFF once we have received EOF or are unsynced
//
// Returns: true if we received a EOF
//          false if we are still waiting for some more
//=============================================================================

#define NOISE_THRESHOLD          80                   // don't try to correlate noise
#define MAX_PREVIOUS_AMPLITUDE   (-1 - NOISE_THRESHOLD)

typedef struct DecodeTag {
	enum {
		STATE_TAG_SOF_LOW,
		STATE_TAG_SOF_RISING_EDGE,
		STATE_TAG_SOF_HIGH,
		STATE_TAG_SOF_HIGH_END,
		STATE_TAG_RECEIVING_DATA,
		STATE_TAG_EOF,
		STATE_TAG_EOF_TAIL
	}         state;
	int       bitCount;
	int       posCount;
	enum {
		LOGIC0,
		LOGIC1,
		SOF_PART1,
		SOF_PART2
	}         lastBit;
	uint16_t  shiftReg;
	uint16_t  max_len;
	uint8_t   *output;
	int       len;
	int       sum1, sum2;
	int       threshold_sof;
	int       threshold_half;
	uint16_t  previous_amplitude;
} DecodeTag_t;

//-----------------------------------------------------------------------------
// DEMODULATE tag answer
//-----------------------------------------------------------------------------
static RAMFUNC int Handle15693SamplesFromTag(uint16_t amplitude, DecodeTag_t *DecodeTag) {
	switch (DecodeTag->state) {
		case STATE_TAG_SOF_LOW:
			// waiting for a rising edge
			if (amplitude > NOISE_THRESHOLD + DecodeTag->previous_amplitude) {
				if (DecodeTag->posCount > 10) {
					DecodeTag->threshold_sof = amplitude - DecodeTag->previous_amplitude; // to be divided by 2
					DecodeTag->threshold_half = 0;
					DecodeTag->state = STATE_TAG_SOF_RISING_EDGE;
				} else {
					DecodeTag->posCount = 0;
				}
			} else {
				DecodeTag->posCount++;
				DecodeTag->previous_amplitude = amplitude;
			}
			break;

		case STATE_TAG_SOF_RISING_EDGE:
			if (amplitude > DecodeTag->threshold_sof + DecodeTag->previous_amplitude) { // edge still rising
				if (amplitude > DecodeTag->threshold_sof + DecodeTag->threshold_sof) { // steeper edge, take this as time reference
					DecodeTag->posCount = 1;
				} else {
					DecodeTag->posCount = 2;
				}
				DecodeTag->threshold_sof = (amplitude - DecodeTag->previous_amplitude) / 2;
			} else {
				DecodeTag->posCount = 2;
				DecodeTag->threshold_sof = DecodeTag->threshold_sof/2;
			}
			// DecodeTag->posCount = 2;
			DecodeTag->state = STATE_TAG_SOF_HIGH;
			break;

		case STATE_TAG_SOF_HIGH:
			// waiting for 10 times high. Take average over the last 8
			if (amplitude > DecodeTag->threshold_sof) {
				DecodeTag->posCount++;
				if (DecodeTag->posCount > 2) {
					DecodeTag->threshold_half += amplitude; // keep track of average high value
				}
				if (DecodeTag->posCount == 10) {
					DecodeTag->threshold_half >>= 2; // (4 times 1/2 average)
					DecodeTag->state = STATE_TAG_SOF_HIGH_END;
				}
			} else { // high phase was too short
				DecodeTag->posCount = 1;
				DecodeTag->previous_amplitude = amplitude;
				DecodeTag->state = STATE_TAG_SOF_LOW;
			}
			break;

		case STATE_TAG_SOF_HIGH_END:
			// check for falling edge
			if (DecodeTag->posCount == 13 && amplitude < DecodeTag->threshold_sof) {
				DecodeTag->lastBit = SOF_PART1;  // detected 1st part of SOF (12 samples low and 12 samples high)
				DecodeTag->shiftReg = 0;
				DecodeTag->bitCount = 0;
				DecodeTag->len = 0;
				DecodeTag->sum1 = amplitude;
				DecodeTag->sum2 = 0;
				DecodeTag->posCount = 2;
				DecodeTag->state = STATE_TAG_RECEIVING_DATA;
				// FpgaDisableTracing(); // DEBUGGING
				// Dbprintf("amplitude = %d, threshold_sof = %d, threshold_half/4 = %d, previous_amplitude = %d",
					// amplitude,
					// DecodeTag->threshold_sof,
					// DecodeTag->threshold_half/4,
					// DecodeTag->previous_amplitude); // DEBUGGING
				LED_C_ON();
			} else {
				DecodeTag->posCount++;
				if (DecodeTag->posCount > 13) { // high phase too long
					DecodeTag->posCount = 0;
					DecodeTag->previous_amplitude = amplitude;
					DecodeTag->state = STATE_TAG_SOF_LOW;
					LED_C_OFF();
				}
			}
			break;

		case STATE_TAG_RECEIVING_DATA:
				// FpgaDisableTracing(); // DEBUGGING
				// Dbprintf("amplitude = %d, threshold_sof = %d, threshold_half/4 = %d, previous_amplitude = %d",
					// amplitude,
					// DecodeTag->threshold_sof,
					// DecodeTag->threshold_half/4,
					// DecodeTag->previous_amplitude); // DEBUGGING
			if (DecodeTag->posCount == 1) {
				DecodeTag->sum1 = 0;
				DecodeTag->sum2 = 0;
			}
			if (DecodeTag->posCount <= 4) {
				DecodeTag->sum1 += amplitude;
			} else {
				DecodeTag->sum2 += amplitude;
			}
			if (DecodeTag->posCount == 8) {
				if (DecodeTag->sum1 > DecodeTag->threshold_half && DecodeTag->sum2 > DecodeTag->threshold_half) { // modulation in both halves
					if (DecodeTag->lastBit == LOGIC0) {  // this was already part of EOF
						DecodeTag->state = STATE_TAG_EOF;
					} else {
						DecodeTag->posCount = 0;
						DecodeTag->previous_amplitude = amplitude;
						DecodeTag->state = STATE_TAG_SOF_LOW;
						LED_C_OFF();
					}
				} else if (DecodeTag->sum1 < DecodeTag->threshold_half && DecodeTag->sum2 > DecodeTag->threshold_half) { // modulation in second half
					// logic 1
					if (DecodeTag->lastBit == SOF_PART1) { // still part of SOF
						DecodeTag->lastBit = SOF_PART2;    // SOF completed
					} else {
						DecodeTag->lastBit = LOGIC1;
						DecodeTag->shiftReg >>= 1;
						DecodeTag->shiftReg |= 0x80;
						DecodeTag->bitCount++;
						if (DecodeTag->bitCount == 8) {
							DecodeTag->output[DecodeTag->len] = DecodeTag->shiftReg;
							DecodeTag->len++;
							// if (DecodeTag->shiftReg == 0x12 && DecodeTag->len == 1) FpgaDisableTracing(); // DEBUGGING
							if (DecodeTag->len > DecodeTag->max_len) {
								// buffer overflow, give up
								LED_C_OFF();
								return true;
							}
							DecodeTag->bitCount = 0;
							DecodeTag->shiftReg = 0;
						}
					}
				} else if (DecodeTag->sum1 > DecodeTag->threshold_half && DecodeTag->sum2 < DecodeTag->threshold_half) { // modulation in first half
					// logic 0
					if (DecodeTag->lastBit == SOF_PART1) { // incomplete SOF
						DecodeTag->posCount = 0;
						DecodeTag->previous_amplitude = amplitude;
						DecodeTag->state = STATE_TAG_SOF_LOW;
						LED_C_OFF();
					} else {
						DecodeTag->lastBit = LOGIC0;
						DecodeTag->shiftReg >>= 1;
						DecodeTag->bitCount++;
						if (DecodeTag->bitCount == 8) {
							DecodeTag->output[DecodeTag->len] = DecodeTag->shiftReg;
							DecodeTag->len++;
							// if (DecodeTag->shiftReg == 0x12 && DecodeTag->len == 1) FpgaDisableTracing(); // DEBUGGING
							if (DecodeTag->len > DecodeTag->max_len) {
								// buffer overflow, give up
								DecodeTag->posCount = 0;
								DecodeTag->previous_amplitude = amplitude;
								DecodeTag->state = STATE_TAG_SOF_LOW;
								LED_C_OFF();
							}
							DecodeTag->bitCount = 0;
							DecodeTag->shiftReg = 0;
						}
					}
				} else { // no modulation
					if (DecodeTag->lastBit == SOF_PART2) { // only SOF (this is OK for iClass)
						LED_C_OFF();
						return true;
					} else {
						DecodeTag->posCount = 0;
						DecodeTag->state = STATE_TAG_SOF_LOW;
						LED_C_OFF();
					}
				}
				DecodeTag->posCount = 0;
			}
			DecodeTag->posCount++;
			break;

		case STATE_TAG_EOF:
			if (DecodeTag->posCount == 1) {
				DecodeTag->sum1 = 0;
				DecodeTag->sum2 = 0;
			}
			if (DecodeTag->posCount <= 4) {
				DecodeTag->sum1 += amplitude;
			} else {
				DecodeTag->sum2 += amplitude;
			}
			if (DecodeTag->posCount == 8) {
				if (DecodeTag->sum1 > DecodeTag->threshold_half && DecodeTag->sum2 < DecodeTag->threshold_half) { // modulation in first half
					DecodeTag->posCount = 0;
					DecodeTag->state = STATE_TAG_EOF_TAIL;
				} else {
					DecodeTag->posCount = 0;
					DecodeTag->previous_amplitude = amplitude;
					DecodeTag->state = STATE_TAG_SOF_LOW;
					LED_C_OFF();
				}
			}
			DecodeTag->posCount++;
			break;

		case STATE_TAG_EOF_TAIL:
			if (DecodeTag->posCount == 1) {
				DecodeTag->sum1 = 0;
				DecodeTag->sum2 = 0;
			}
			if (DecodeTag->posCount <= 4) {
				DecodeTag->sum1 += amplitude;
			} else {
				DecodeTag->sum2 += amplitude;
			}
			if (DecodeTag->posCount == 8) {
				if (DecodeTag->sum1 < DecodeTag->threshold_half && DecodeTag->sum2 < DecodeTag->threshold_half) { // no modulation in both halves
					LED_C_OFF();
					return true;
				} else {
					DecodeTag->posCount = 0;
					DecodeTag->previous_amplitude = amplitude;
					DecodeTag->state = STATE_TAG_SOF_LOW;
					LED_C_OFF();
				}
			}
			DecodeTag->posCount++;
			break;
	}

	return false;
}

static void DecodeTagInit(DecodeTag_t *DecodeTag, uint8_t *data, uint16_t max_len) {
	DecodeTag->previous_amplitude = MAX_PREVIOUS_AMPLITUDE;
	DecodeTag->posCount = 0;
	DecodeTag->state = STATE_TAG_SOF_LOW;
	DecodeTag->output = data;
	DecodeTag->max_len = max_len;
}

static void DecodeTagReset(DecodeTag_t *DecodeTag) {
	DecodeTag->posCount = 0;
	DecodeTag->state = STATE_TAG_SOF_LOW;
	DecodeTag->previous_amplitude = MAX_PREVIOUS_AMPLITUDE;
}


/*
 *  Receive and decode the tag response, also log to tracebuffer
 */
static int GetIso15693AnswerFromTag(uint8_t* response, uint16_t max_len, uint16_t timeout, uint32_t *eof_time) {

	int samples = 0;
	int ret = 0;

	uint16_t dmaBuf[ISO15693_DMA_BUFFER_SIZE];

	// the Decoder data structure
	DecodeTag_t DecodeTag = { 0 };
	DecodeTagInit(&DecodeTag, response, max_len);

	// wait for last transfer to complete
	while (!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXEMPTY));

	// And put the FPGA in the appropriate mode
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_SUBCARRIER_424_KHZ | FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE);

	// Setup and start DMA.
	FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);
	FpgaSetupSscDma((uint8_t*) dmaBuf, ISO15693_DMA_BUFFER_SIZE);
	uint32_t dma_start_time = 0;
	uint16_t *upTo = dmaBuf;

	for(;;) {
		uint16_t behindBy = ((uint16_t*)AT91C_BASE_PDC_SSC->PDC_RPR - upTo) & (ISO15693_DMA_BUFFER_SIZE-1);

		if (behindBy == 0) continue;

		samples++;
		if (samples == 1) {
			// DMA has transferred the very first data
			dma_start_time = GetCountSspClk() & 0xfffffff0;
		}

		uint16_t tagdata = *upTo++;

		if(upTo >= dmaBuf + ISO15693_DMA_BUFFER_SIZE) {                // we have read all of the DMA buffer content.
			upTo = dmaBuf;                                             // start reading the circular buffer from the beginning
			if (behindBy > (9*ISO15693_DMA_BUFFER_SIZE/10)) {
				Dbprintf("About to blow circular buffer - aborted! behindBy=%d", behindBy);
				ret = -1;
				break;
			}
		}
		if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_ENDRX)) {              // DMA Counter Register had reached 0, already rotated.
			AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;          // refresh the DMA Next Buffer and
			AT91C_BASE_PDC_SSC->PDC_RNCR = ISO15693_DMA_BUFFER_SIZE;   // DMA Next Counter registers
		}

		if (Handle15693SamplesFromTag(tagdata, &DecodeTag)) {
			*eof_time = dma_start_time + samples*16 - DELAY_TAG_TO_ARM; // end of EOF
			if (DecodeTag.lastBit == SOF_PART2) {
				*eof_time -= 8*16; // needed 8 additional samples to confirm single SOF (iCLASS)
			}
			if (DecodeTag.len > DecodeTag.max_len) {
				ret = -2; // buffer overflow
			}
			break;
		}

		if (samples > timeout && DecodeTag.state < STATE_TAG_RECEIVING_DATA) {
			ret = -1;   // timeout
			break;
		}

	}

	FpgaDisableSscDma();

	if (DBGLEVEL >= DBG_EXTENDED)  Dbprintf("samples = %d, ret = %d, Decoder: state = %d, lastBit = %d, len = %d, bitCount = %d, posCount = %d",
						samples, ret, DecodeTag.state, DecodeTag.lastBit, DecodeTag.len, DecodeTag.bitCount, DecodeTag.posCount);

	if (ret < 0) {
		return ret;
	}

	uint32_t sof_time = *eof_time
						- DecodeTag.len * 8 * 8 * 16 // time for byte transfers
						- 32 * 16  // time for SOF transfer
						- (DecodeTag.lastBit != SOF_PART2?32*16:0); // time for EOF transfer

	if (DBGLEVEL >= DBG_EXTENDED) Dbprintf("timing: sof_time = %d, eof_time = %d", sof_time, *eof_time);

	LogTrace(DecodeTag.output, DecodeTag.len, sof_time*4, *eof_time*4, NULL, false);

	return DecodeTag.len;
}


//=============================================================================
// An ISO15693 decoder for reader commands.
//
// This function is called 4 times per bit (every 2 subcarrier cycles).
// Subcarrier frequency fs is 848kHz, 1/fs = 1,18us, i.e. function is called every 2,36us
// LED handling:
//    LED B -> ON once we have received the SOF and are expecting the rest.
//    LED B -> OFF once we have received EOF or are in error state or unsynced
//
// Returns: true  if we received a EOF
//          false if we are still waiting for some more
//=============================================================================

typedef struct DecodeReader {
	enum {
		STATE_READER_UNSYNCD,
		STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF,
		STATE_READER_AWAIT_1ST_RISING_EDGE_OF_SOF,
		STATE_READER_AWAIT_2ND_FALLING_EDGE_OF_SOF,
		STATE_READER_AWAIT_2ND_RISING_EDGE_OF_SOF,
		STATE_READER_AWAIT_END_OF_SOF_1_OUT_OF_4,
		STATE_READER_RECEIVE_DATA_1_OUT_OF_4,
		STATE_READER_RECEIVE_DATA_1_OUT_OF_256,
		STATE_READER_RECEIVE_JAMMING
	}           state;
	enum {
		CODING_1_OUT_OF_4,
		CODING_1_OUT_OF_256
	}           Coding;
	uint8_t     shiftReg;
	uint8_t     bitCount;
	int         byteCount;
	int         byteCountMax;
	int         posCount;
	int         sum1, sum2;
	uint8_t     *output;
	uint8_t     jam_search_len;
	uint8_t     *jam_search_string;
} DecodeReader_t;

static void DecodeReaderInit(DecodeReader_t* DecodeReader, uint8_t *data, uint16_t max_len, uint8_t jam_search_len, uint8_t *jam_search_string) {
	DecodeReader->output = data;
	DecodeReader->byteCountMax = max_len;
	DecodeReader->state = STATE_READER_UNSYNCD;
	DecodeReader->byteCount = 0;
	DecodeReader->bitCount = 0;
	DecodeReader->posCount = 1;
	DecodeReader->shiftReg = 0;
	DecodeReader->jam_search_len = jam_search_len;
	DecodeReader->jam_search_string = jam_search_string;
}

static void DecodeReaderReset(DecodeReader_t* DecodeReader) {
	DecodeReader->state = STATE_READER_UNSYNCD;
}

static RAMFUNC int Handle15693SampleFromReader(bool bit, DecodeReader_t *DecodeReader) {
	switch (DecodeReader->state) {
		case STATE_READER_UNSYNCD:
			// wait for unmodulated carrier
			if (bit) {
				DecodeReader->state = STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF;
			}
			break;

		case STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF:
			if (!bit) {
				// we went low, so this could be the beginning of a SOF
				DecodeReader->posCount = 1;
				DecodeReader->state = STATE_READER_AWAIT_1ST_RISING_EDGE_OF_SOF;
			}
			break;

		case STATE_READER_AWAIT_1ST_RISING_EDGE_OF_SOF:
			DecodeReader->posCount++;
			if (bit) { // detected rising edge
				if (DecodeReader->posCount < 4) { // rising edge too early (nominally expected at 5)
					DecodeReader->state = STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF;
				} else { // SOF
					DecodeReader->state = STATE_READER_AWAIT_2ND_FALLING_EDGE_OF_SOF;
				}
			} else {
				if (DecodeReader->posCount > 5) { // stayed low for too long
					DecodeReaderReset(DecodeReader);
				} else {
					// do nothing, keep waiting
				}
			}
			break;

		case STATE_READER_AWAIT_2ND_FALLING_EDGE_OF_SOF:
			DecodeReader->posCount++;
			if (!bit) { // detected a falling edge
				if (DecodeReader->posCount < 20) {         // falling edge too early (nominally expected at 21 earliest)
					DecodeReaderReset(DecodeReader);
				} else if (DecodeReader->posCount < 23) {  // SOF for 1 out of 4 coding
					DecodeReader->Coding = CODING_1_OUT_OF_4;
					DecodeReader->state = STATE_READER_AWAIT_2ND_RISING_EDGE_OF_SOF;
				} else if (DecodeReader->posCount < 28) {  // falling edge too early (nominally expected at 29 latest)
					DecodeReaderReset(DecodeReader);
				} else {                                   // SOF for 1 out of 256 coding
					DecodeReader->Coding = CODING_1_OUT_OF_256;
					DecodeReader->state = STATE_READER_AWAIT_2ND_RISING_EDGE_OF_SOF;
				}
			} else {
				if (DecodeReader->posCount > 29) { // stayed high for too long
					DecodeReader->state = STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF;
				} else {
					// do nothing, keep waiting
				}
			}
			break;

		case STATE_READER_AWAIT_2ND_RISING_EDGE_OF_SOF:
			DecodeReader->posCount++;
			if (bit) { // detected rising edge
				if (DecodeReader->Coding == CODING_1_OUT_OF_256) {
					if (DecodeReader->posCount < 32) { // rising edge too early (nominally expected at 33)
						DecodeReader->state = STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF;
					} else {
						DecodeReader->posCount = 1;
						DecodeReader->bitCount = 0;
						DecodeReader->byteCount = 0;
						DecodeReader->sum1 = 1;
						DecodeReader->state = STATE_READER_RECEIVE_DATA_1_OUT_OF_256;
						LED_B_ON();
					}
				} else { // CODING_1_OUT_OF_4
					if (DecodeReader->posCount < 24) { // rising edge too early (nominally expected at 25)
						DecodeReader->state = STATE_READER_AWAIT_1ST_FALLING_EDGE_OF_SOF;
					} else {
						DecodeReader->posCount = 1;
						DecodeReader->state = STATE_READER_AWAIT_END_OF_SOF_1_OUT_OF_4;
					}
				}
			} else {
				if (DecodeReader->Coding == CODING_1_OUT_OF_256) {
					if (DecodeReader->posCount > 34) { // signal stayed low for too long
						DecodeReaderReset(DecodeReader);
					} else {
						// do nothing, keep waiting
					}
				} else { // CODING_1_OUT_OF_4
					if (DecodeReader->posCount > 26) { // signal stayed low for too long
						DecodeReaderReset(DecodeReader);
					} else {
						// do nothing, keep waiting
					}
				}
			}
			break;

		case STATE_READER_AWAIT_END_OF_SOF_1_OUT_OF_4:
			DecodeReader->posCount++;
			if (bit) {
				if (DecodeReader->posCount == 9) {
					DecodeReader->posCount = 1;
					DecodeReader->bitCount = 0;
					DecodeReader->byteCount = 0;
					DecodeReader->sum1 = 1;
					DecodeReader->state = STATE_READER_RECEIVE_DATA_1_OUT_OF_4;
					LED_B_ON();
				} else {
					// do nothing, keep waiting
				}
			} else { // unexpected falling edge
					DecodeReaderReset(DecodeReader);
			}
			break;

		case STATE_READER_RECEIVE_DATA_1_OUT_OF_4:
			DecodeReader->posCount++;
			if (DecodeReader->posCount == 1) {
				DecodeReader->sum1 = bit?1:0;
			} else if (DecodeReader->posCount <= 4) {
				if (bit) DecodeReader->sum1++;
			} else if (DecodeReader->posCount == 5) {
				DecodeReader->sum2 = bit?1:0;
			} else {
				if (bit) DecodeReader->sum2++;
			}
			if (DecodeReader->posCount == 8) {
				DecodeReader->posCount = 0;
				if (DecodeReader->sum1 <= 1 && DecodeReader->sum2 >= 3) { // EOF
					LED_B_OFF(); // Finished receiving
					DecodeReaderReset(DecodeReader);
					if (DecodeReader->byteCount != 0) {
						return true;
					}
				} else if (DecodeReader->sum1 >= 3 && DecodeReader->sum2 <= 1) { // detected a 2bit position
					DecodeReader->shiftReg >>= 2;
					DecodeReader->shiftReg |= (DecodeReader->bitCount << 6);
				}
				if (DecodeReader->bitCount == 15) { // we have a full byte
					DecodeReader->output[DecodeReader->byteCount++] = DecodeReader->shiftReg;
					if (DecodeReader->byteCount > DecodeReader->byteCountMax) {
						// buffer overflow, give up
						LED_B_OFF();
						DecodeReaderReset(DecodeReader);
					}
					DecodeReader->bitCount = 0;
					DecodeReader->shiftReg = 0;
					if (DecodeReader->byteCount == DecodeReader->jam_search_len) {
						if (!memcmp(DecodeReader->output, DecodeReader->jam_search_string, DecodeReader->jam_search_len)) {
							LED_D_ON();
							FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SEND_JAM);
							DecodeReader->state = STATE_READER_RECEIVE_JAMMING;
						}
					}
				} else {
					DecodeReader->bitCount++;
				}
			}
			break;

		case STATE_READER_RECEIVE_DATA_1_OUT_OF_256:
			DecodeReader->posCount++;
			if (DecodeReader->posCount == 1) {
				DecodeReader->sum1 = bit?1:0;
			} else if (DecodeReader->posCount <= 4) {
				if (bit) DecodeReader->sum1++;
			} else if (DecodeReader->posCount == 5) {
				DecodeReader->sum2 = bit?1:0;
			} else if (bit) {
				DecodeReader->sum2++;
			}
			if (DecodeReader->posCount == 8) {
				DecodeReader->posCount = 0;
				if (DecodeReader->sum1 <= 1 && DecodeReader->sum2 >= 3) { // EOF
					LED_B_OFF(); // Finished receiving
					DecodeReaderReset(DecodeReader);
					if (DecodeReader->byteCount != 0) {
						return true;
					}
				} else if (DecodeReader->sum1 >= 3 && DecodeReader->sum2 <= 1) { // detected the bit position
					DecodeReader->shiftReg = DecodeReader->bitCount;
				}
				if (DecodeReader->bitCount == 255) { // we have a full byte
					DecodeReader->output[DecodeReader->byteCount++] = DecodeReader->shiftReg;
					if (DecodeReader->byteCount > DecodeReader->byteCountMax) {
						// buffer overflow, give up
						LED_B_OFF();
						DecodeReaderReset(DecodeReader);
					}
					if (DecodeReader->byteCount == DecodeReader->jam_search_len) {
						if (!memcmp(DecodeReader->output, DecodeReader->jam_search_string, DecodeReader->jam_search_len)) {
							LED_D_ON();
							FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SEND_JAM);
							DecodeReader->state = STATE_READER_RECEIVE_JAMMING;
						}
					}
				}
				DecodeReader->bitCount++;
			}
			break;

		case STATE_READER_RECEIVE_JAMMING:
			DecodeReader->posCount++;
			if (DecodeReader->Coding == CODING_1_OUT_OF_4) {
				if (DecodeReader->posCount == 7*16) { // 7 bits jammed
					FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SNOOP_AMPLITUDE); // stop jamming
					// FpgaDisableTracing();
					LED_D_OFF();
				} else if (DecodeReader->posCount == 8*16) {
					DecodeReader->posCount = 0;
					DecodeReader->output[DecodeReader->byteCount++] = 0x00;
					DecodeReader->state = STATE_READER_RECEIVE_DATA_1_OUT_OF_4;
				}
			} else {
				if (DecodeReader->posCount == 7*256) { // 7 bits jammend
					FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SNOOP_AMPLITUDE); // stop jamming
					LED_D_OFF();
				} else if (DecodeReader->posCount == 8*256) {
					DecodeReader->posCount = 0;
					DecodeReader->output[DecodeReader->byteCount++] = 0x00;
					DecodeReader->state = STATE_READER_RECEIVE_DATA_1_OUT_OF_256;
				}
			}
			break;

		default:
			LED_B_OFF();
			DecodeReaderReset(DecodeReader);
			break;
	}

	return false;
}

//-----------------------------------------------------------------------------
// Receive a command (from the reader to us, where we are the simulated tag),
// and store it in the given buffer, up to the given maximum length. Keeps
// spinning, waiting for a well-framed command, until either we get one
// (returns len) or someone presses the pushbutton on the board (returns -1).
//
// Assume that we're called with the SSC (to the FPGA) and ADC path set
// correctly.
//-----------------------------------------------------------------------------

static int GetIso15693CommandFromReader(uint8_t *received, size_t max_len, uint32_t *eof_time) {
	int samples = 0;
	bool gotFrame = false;
	uint8_t b;

	uint8_t dmaBuf[ISO15693_DMA_BUFFER_SIZE];

	// the decoder data structure
	DecodeReader_t DecodeReader = {0};
	DecodeReaderInit(&DecodeReader, received, max_len, 0, NULL);

	// wait for last transfer to complete
	while (!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXEMPTY));

	LED_D_OFF();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_NO_MODULATION);

	// clear receive register and wait for next transfer
	uint32_t temp = AT91C_BASE_SSC->SSC_RHR;
	(void) temp;
	while (!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY)) ;

	uint32_t dma_start_time = GetCountSspClk() & 0xfffffff8;

	// Setup and start DMA.
	FpgaSetupSscDma(dmaBuf, ISO15693_DMA_BUFFER_SIZE);
	uint8_t *upTo = dmaBuf;

	for (;;) {
		uint16_t behindBy = ((uint8_t*)AT91C_BASE_PDC_SSC->PDC_RPR - upTo) & (ISO15693_DMA_BUFFER_SIZE-1);

		if (behindBy == 0) continue;

		b = *upTo++;
		if (upTo >= dmaBuf + ISO15693_DMA_BUFFER_SIZE) {               // we have read all of the DMA buffer content.
			upTo = dmaBuf;                                             // start reading the circular buffer from the beginning
			if (behindBy > (9*ISO15693_DMA_BUFFER_SIZE/10)) {
				Dbprintf("About to blow circular buffer - aborted! behindBy=%d", behindBy);
				break;
			}
		}
		if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_ENDRX)) {              // DMA Counter Register had reached 0, already rotated.
			AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;          // refresh the DMA Next Buffer and
			AT91C_BASE_PDC_SSC->PDC_RNCR = ISO15693_DMA_BUFFER_SIZE;   // DMA Next Counter registers
		}

		for (int i = 7; i >= 0; i--) {
			if (Handle15693SampleFromReader((b >> i) & 0x01, &DecodeReader)) {
				*eof_time = dma_start_time + samples - DELAY_READER_TO_ARM; // end of EOF
				gotFrame = true;
				break;
			}
			samples++;
		}

		if (gotFrame) {
			break;
		}

		if (BUTTON_PRESS()) {
			DecodeReader.byteCount = -1;
			break;
		}

		WDT_HIT();
	}

	FpgaDisableSscDma();

	if (DBGLEVEL >= DBG_EXTENDED)  Dbprintf("samples = %d, gotFrame = %d, Decoder: state = %d, len = %d, bitCount = %d, posCount = %d",
						samples, gotFrame, DecodeReader.state, DecodeReader.byteCount, DecodeReader.bitCount, DecodeReader.posCount);

	if (DecodeReader.byteCount > 0) {
		uint32_t sof_time = *eof_time
						- DecodeReader.byteCount * (DecodeReader.Coding==CODING_1_OUT_OF_4?128:2048) // time for byte transfers
						- 32  // time for SOF transfer
						- 16; // time for EOF transfer
		LogTrace(DecodeReader.output, DecodeReader.byteCount, sof_time*32, *eof_time*32, NULL, true);
	}

	return DecodeReader.byteCount;
}

//-----------------------------------------------------------------------------
// Start to read an ISO 15693 tag. We send an identify request, then wait
// for the response. The response is not demodulated, just left in the buffer
// so that it can be downloaded to a PC and processed there.
//-----------------------------------------------------------------------------
void AcquireRawAdcSamplesIso15693(void) {
	LED_A_ON();

    //iceman: needs malloc
	uint8_t *dest = BigBuf_get_addr();

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER);
	LED_D_ON();
	FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	uint8_t cmd[5];
	BuildIdentifyRequest(cmd);
	CodeIso15693AsReader(cmd, sizeof(cmd));

	// Give the tags time to energize
	SpinDelay(100);

	// Now send the command
	uint32_t start_time = 0;
	TransmitTo15693Tag(ToSend, ToSendMax, &start_time);

	// wait for last transfer to complete
	while (!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXEMPTY)) ;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_SUBCARRIER_424_KHZ | FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE);

	for(int c = 0; c < 4000; ) {
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			uint16_t r = AT91C_BASE_SSC->SSC_RHR;
			dest[c++] = r >> 5;
		}
	}

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
}

void SniffIso15693(uint8_t jam_search_len, uint8_t *jam_search_string) {

	LED_A_ON();

	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

	clear_trace();
	set_tracing(true);

	// The DMA buffer, used to stream samples from the FPGA
	uint16_t dmaBuf[ISO15693_DMA_BUFFER_SIZE];

	// Count of samples received so far, so that we can include timing
	// information in the trace buffer.
	int samples = 0;

	DecodeTag_t DecodeTag = {0};
	uint8_t response[ISO15693_MAX_RESPONSE_LENGTH];
	DecodeTagInit(&DecodeTag, response, sizeof(response));

	DecodeReader_t DecodeReader = {0};
	uint8_t cmd[ISO15693_MAX_COMMAND_LENGTH];
	DecodeReaderInit(&DecodeReader, cmd, sizeof(cmd), jam_search_len, jam_search_string);

	// Print some debug information about the buffer sizes
	if (DBGLEVEL >= DBG_EXTENDED) {
		Dbprintf("Sniffing buffers initialized:");
		Dbprintf("  Trace:         %i bytes", BigBuf_max_traceLen());
		Dbprintf("  Reader -> tag: %i bytes", ISO15693_MAX_COMMAND_LENGTH);
		Dbprintf("  tag -> Reader: %i bytes", ISO15693_MAX_RESPONSE_LENGTH);
		Dbprintf("  DMA:           %i bytes", ISO15693_DMA_BUFFER_SIZE * sizeof(uint16_t));
	}

	Dbprintf("Sniff started. Press PM3 Button to stop.");

	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SNOOP_AMPLITUDE);
	LED_D_OFF();
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);
	StartCountSspClk();
	FpgaSetupSscDma((uint8_t*) dmaBuf, ISO15693_DMA_BUFFER_SIZE);

	bool TagIsActive = false;
	bool ReaderIsActive = false;
	bool ExpectTagAnswer = false;
	uint32_t dma_start_time = 0;
	uint16_t *upTo = dmaBuf;

	uint16_t max_behindBy = 0;
	
	// And now we loop, receiving samples.
	for(;;) {
		uint16_t behindBy = ((uint16_t*)AT91C_BASE_PDC_SSC->PDC_RPR - upTo) & (ISO15693_DMA_BUFFER_SIZE-1);
		if (behindBy > max_behindBy) {
			max_behindBy = behindBy;
		}
		
		if (behindBy == 0) continue;

		samples++;
		if (samples == 1) {
			// DMA has transferred the very first data
			dma_start_time = GetCountSspClk() & 0xfffffff0;
		}

		uint16_t snoopdata = *upTo++;

		if (upTo >= dmaBuf + ISO15693_DMA_BUFFER_SIZE) {                   // we have read all of the DMA buffer content.
			upTo = dmaBuf;                                                 // start reading the circular buffer from the beginning
			if (behindBy > (9*ISO15693_DMA_BUFFER_SIZE/10)) {

				Dbprintf("About to blow circular buffer - aborted! behindBy=%d, samples=%d", behindBy, samples);
				break;
			}
			if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_ENDRX)) {              // DMA Counter Register had reached 0, already rotated.
				AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;          // refresh the DMA Next Buffer and
				AT91C_BASE_PDC_SSC->PDC_RNCR = ISO15693_DMA_BUFFER_SIZE;   // DMA Next Counter registers
				WDT_HIT();
				if (BUTTON_PRESS()) {
					DbpString("Sniff stopped.");
					break;
				}
			}
		}

		if (!TagIsActive) {                                                // no need to try decoding reader data if the tag is sending
			if (Handle15693SampleFromReader(snoopdata & 0x02, &DecodeReader)) {

				uint32_t eof_time = dma_start_time + samples*16 + 8 - DELAY_READER_TO_ARM_SNIFF; // end of EOF
				if (DecodeReader.byteCount > 0) {
					uint32_t sof_time = eof_time
									- DecodeReader.byteCount * (DecodeReader.Coding==CODING_1_OUT_OF_4?128*16:2048*16) // time for byte transfers
									- 32*16  // time for SOF transfer
									- 16*16; // time for EOF transfer
					LogTrace(DecodeReader.output, DecodeReader.byteCount, sof_time*4, eof_time*4, NULL, true);
				}
				// And ready to receive another command.
				DecodeReaderReset(&DecodeReader);
				// And also reset the demod code, which might have been
				// false-triggered by the commands from the reader.
				DecodeTagReset(&DecodeTag);
				ReaderIsActive = false;
				ExpectTagAnswer = true;

			} else if (Handle15693SampleFromReader(snoopdata & 0x01, &DecodeReader)) {

				uint32_t eof_time = dma_start_time + samples*16 + 16 - DELAY_READER_TO_ARM_SNIFF; // end of EOF
				if (DecodeReader.byteCount > 0) {
					uint32_t sof_time = eof_time
									- DecodeReader.byteCount * (DecodeReader.Coding==CODING_1_OUT_OF_4?128*16:2048*16) // time for byte transfers
									- 32*16  // time for SOF transfer
									- 16*16; // time for EOF transfer
					LogTrace(DecodeReader.output, DecodeReader.byteCount, sof_time*4, eof_time*4, NULL, true);
				}
				// And ready to receive another command
				DecodeReaderReset(&DecodeReader);

				// And also reset the demod code, which might have been
				// false-triggered by the commands from the reader.
				DecodeTagReset(&DecodeTag);
				ReaderIsActive = false;
				ExpectTagAnswer = true;

			} else {
				ReaderIsActive = (DecodeReader.state >= STATE_READER_RECEIVE_DATA_1_OUT_OF_4);
			}
		}

		if (!ReaderIsActive && ExpectTagAnswer) {                       // no need to try decoding tag data if the reader is currently sending or no answer expected yet
			if (Handle15693SamplesFromTag(snoopdata >> 2, &DecodeTag)) {

				uint32_t eof_time = dma_start_time + samples*16 - DELAY_TAG_TO_ARM_SNIFF; // end of EOF
				if (DecodeTag.lastBit == SOF_PART2) {
					eof_time -= 8*16; // needed 8 additional samples to confirm single SOF (iCLASS)
				}
				uint32_t sof_time = eof_time
									- DecodeTag.len * 8 * 8 * 16 // time for byte transfers
									- 32 * 16  // time for SOF transfer
									- (DecodeTag.lastBit != SOF_PART2?32*16:0); // time for EOF transfer
				LogTrace(DecodeTag.output, DecodeTag.len, sof_time*4, eof_time*4, NULL, false);
				// And ready to receive another response.
				DecodeTagReset(&DecodeTag);
				DecodeReaderReset(&DecodeReader);
				ExpectTagAnswer = false;
				TagIsActive = false;
			} else {
				TagIsActive = (DecodeTag.state >= STATE_TAG_RECEIVING_DATA);
			}
		}

	}

	FpgaDisableSscDma();

	DbpString("Sniff statistics:");
	Dbprintf("  ExpectTagAnswer: %d, TagIsActive: %d, ReaderIsActive: %d", ExpectTagAnswer, TagIsActive, ReaderIsActive);
	Dbprintf("  DecodeTag State: %d", DecodeTag.state);
	Dbprintf("  DecodeTag byteCnt: %d", DecodeTag.len);
	Dbprintf("  DecodeTag posCount: %d", DecodeTag.posCount);
	Dbprintf("  DecodeReader State: %d", DecodeReader.state);
	Dbprintf("  DecodeReader byteCnt: %d", DecodeReader.byteCount);
	Dbprintf("  DecodeReader posCount: %d", DecodeReader.posCount);
	Dbprintf("  Trace length: %d", BigBuf_get_traceLen());
	Dbprintf("  Max behindBy: %d", max_behindBy);
}

// Initialize the proxmark as iso15k reader
// (this might produces glitches that confuse some tags
void Iso15693InitReader(void) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // Start from off (no field generated)
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    SpinDelay(10);

	// switch field on
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER);
	LED_D_ON();
	
	// initialize SSC and select proper AD input
	FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// give tags some time to energize
	SpinDelay(250);
}

///////////////////////////////////////////////////////////////////////
// ISO 15693 Part 3 - Air Interface
// This section basicly contains transmission and receiving of bits
///////////////////////////////////////////////////////////////////////

// Encode an identify request, which is the first
// thing that you must send to a tag to get a response.
// It expects "cmdout" to be at least CMD_ID_RESP large
// When READER:
static void BuildIdentifyRequest(uint8_t *cmd) {
    // flags
    cmd[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
	// inventory command code
	cmd[1] = ISO15_CMD_INVENTORY;
	// no mask
	cmd[2] = 0x00;
    // CRC
    AddCrc15(cmd, 3);
}

// uid is in transmission order (which is reverse of display order)

// When SIM:  now the VICC>VCD responses when we are simulating a tag
static void BuildInventoryResponse(uint8_t *uid) {

    uint8_t cmd[CMD_INV_RESP] = {0};

    cmd[0] = 0; // No error, no protocol format extension
    cmd[1] = 0; // DSFID (data storage format identifier).  0x00 = not supported

    // 64-bit UID
    cmd[2] = uid[7];
    cmd[3] = uid[6];
    cmd[4] = uid[5];
    cmd[5] = uid[4];
    cmd[6] = uid[3];
    cmd[7] = uid[2];
    cmd[8] = uid[1];
    cmd[9] = uid[0];

    // CRC
    AddCrc15(cmd, 10);
    CodeIso15693AsTag(cmd, CMD_INV_RESP);
}

// Universal Method for sending to and recv bytes from a tag
//  init ... should we initialize the reader?
//  speed ... 0 low speed, 1 hi speed
//  **recv will return you a pointer to the received data
//  If you do not need the answer use NULL for *recv[]
//  return: length of received data
// logging enabled
int SendDataTag(uint8_t *send, int sendlen, bool init, bool speed_fast, uint8_t *recv, 
                uint16_t max_recv_len, uint32_t start_time, uint16_t timeout, uint32_t *eof_time) {

	if (init) {
		Iso15693InitReader();
		StartCountSspClk();
	}

	int answerLen = 0;

	if (speed_fast) {
		// high speed (1 out of 4)
		CodeIso15693AsReader(send, sendlen);
	} else {
		// low speed (1 out of 256)
		CodeIso15693AsReader256(send, sendlen);
	}

	TransmitTo15693Tag(ToSend, ToSendMax, &start_time);
	uint32_t end_time = start_time + 32*(8*ToSendMax-4); // substract the 4 padding bits after EOF
	LogTrace(send, sendlen, start_time*4, end_time*4, NULL, true);

	// Now wait for a response
	if (recv != NULL) {
		answerLen = GetIso15693AnswerFromTag(recv, max_recv_len, timeout, eof_time);
	}

	return answerLen;
}

int SendDataTagEOF(uint8_t *recv, uint16_t max_recv_len, uint32_t start_time, uint16_t timeout, uint32_t *eof_time) {

	int answerLen = 0;

	CodeIso15693AsReaderEOF();

	TransmitTo15693Tag(ToSend, ToSendMax, &start_time);
	uint32_t end_time = start_time + 32*(8*ToSendMax-4); // substract the 4 padding bits after EOF
	LogTrace(NULL, 0, start_time*4, end_time*4, NULL, true);

	// Now wait for a response
	if (recv != NULL) {
		answerLen = GetIso15693AnswerFromTag(recv, max_recv_len, timeout, eof_time);
	}

	return answerLen;
}

// --------------------------------------------------------------------
// Debug Functions
// --------------------------------------------------------------------

// Decodes a message from a tag and displays its metadata and content
#define DBD15STATLEN 48
static void DbdecodeIso15693Answer(int len, uint8_t *d) {

    if (len > 3) {

        char status[DBD15STATLEN + 1] = {0};

        if (d[0] & ISO15_RES_EXT)
            strncat(status, "ProtExt ", DBD15STATLEN - strlen(status));

        if (d[0] & ISO15_RES_ERROR) {
            // error
            strncat(status, "Error ", DBD15STATLEN - strlen(status));
            switch (d[1]) {
                case 0x01:
                    strncat(status, "01: not supported", DBD15STATLEN - strlen(status));
                    break;
                case 0x02:
                    strncat(status, "02: not recognized", DBD15STATLEN - strlen(status));
                    break;
                case 0x03:
                    strncat(status, "03: opt not supported", DBD15STATLEN - strlen(status));
                    break;
                case 0x0f:
                    strncat(status, "0F: no info", DBD15STATLEN - strlen(status));
                    break;
                case 0x10:
                    strncat(status, "10: don't exist", DBD15STATLEN - strlen(status));
                    break;
                case 0x11:
                    strncat(status, "11: lock again", DBD15STATLEN - strlen(status));
                    break;
                case 0x12:
                    strncat(status, "12: locked", DBD15STATLEN - strlen(status));
                    break;
                case 0x13:
                    strncat(status, "13: program error", DBD15STATLEN - strlen(status));
                    break;
                case 0x14:
                    strncat(status, "14: lock error", DBD15STATLEN - strlen(status));
                    break;
                default:
                    strncat(status, "unknown error", DBD15STATLEN - strlen(status));
            }
            strncat(status, " ", DBD15STATLEN - strlen(status));
        } else {
            strncat(status, "No error ", DBD15STATLEN - strlen(status));
        }

        if (CheckCrc15(d, len))
            strncat(status, "[+] crc (" _GREEN_("OK") ")", DBD15STATLEN - strlen(status));
        else
            strncat(status, "[!] crc (" _RED_("fail") ")", DBD15STATLEN - strlen(status));

        if (DBGLEVEL >= DBG_ERROR) Dbprintf("%s", status);
    }
}

///////////////////////////////////////////////////////////////////////
// Functions called via USB/Client
///////////////////////////////////////////////////////////////////////

//-----------------------------------------------------------------------------
// Act as ISO15693 reader, perform anti-collision and then attempt to read a sector
// all demodulation performed in arm rather than host. - greg
//-----------------------------------------------------------------------------
// ok
// parameter is unused !?!
void ReaderIso15693(uint32_t parameter) {

	LED_A_ON();
	set_tracing(true);

	uint8_t *answer = BigBuf_malloc(ISO15693_MAX_RESPONSE_LENGTH);
    memset(answer, 0x00, ISO15693_MAX_RESPONSE_LENGTH);

	// FIRST WE RUN AN INVENTORY TO GET THE TAG UID
	// THIS MEANS WE CAN PRE-BUILD REQUESTS TO SAVE CPU TIME

	// Send the IDENTIFY command
	uint8_t cmd[5] = {0};
	BuildIdentifyRequest(cmd);
	uint32_t start_time = 0;
	uint32_t eof_time;
	int answerLen = SendDataTag(cmd, sizeof(cmd), true, true, answer, ISO15693_MAX_RESPONSE_LENGTH, start_time, ISO15693_READER_TIMEOUT, &eof_time);
	start_time = eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;

    // we should do a better check than this
    if (answerLen >= 12) {
        uint8_t uid[8];
        uid[0] = answer[9]; // always E0
        uid[1] = answer[8]; // IC Manufacturer code
        uid[2] = answer[7];
        uid[3] = answer[6];
        uid[4] = answer[5];
        uid[5] = answer[4];
        uid[6] = answer[3];
        uid[7] = answer[2];

        if (DBGLEVEL >= DBG_EXTENDED) {
            Dbprintf("[+] UID = %02X%02X%02X%02X%02X%02X%02X%02X",
                     uid[0], uid[1], uid[2], uid[3],
                     uid[4], uid[5], uid[5], uid[6]
                    );
        }
        // send UID back to client.
        // arg0 = 1 = OK
        // arg1 = len of response (12 bytes)
        // arg2 = rtf
        // asbytes = uid.
        reply_mix(CMD_ACK, 1, sizeof(uid), 0, uid, sizeof(uid));
    }

    if (DBGLEVEL >= DBG_EXTENDED) {
        Dbprintf("[+] %d octets read from IDENTIFY request:", answerLen);
        DbdecodeIso15693Answer(answerLen, answer);
        Dbhexdump(answerLen, answer, true);
    }

    switch_off();
    BigBuf_free();
}

// When SIM: initialize the Proxmark3 as ISO15693 tag
static void Iso15693InitTag(void) {
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SIMULATOR | FPGA_HF_SIMULATOR_NO_MODULATION);
	FpgaSetupSsc(FPGA_MAJOR_MODE_HF_SIMULATOR);
	StartCountSspClk();
}

// Simulate an ISO15693 TAG, perform anti-collision and then print any reader commands
// all demodulation performed in arm rather than host. - greg
void SimTagIso15693(uint8_t *uid) {

    LEDsoff();
	Iso15693InitTag();

    LED_A_ON();

    Dbprintf("ISO-15963 Simulating uid: %02X%02X%02X%02X%02X%02X%02X%02X", uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7]);

    uint8_t buf[ISO15_MAX_FRAME];
    memset(buf, 0x00, sizeof(buf));

    LED_C_ON();

    // Build a suitable reponse to the reader INVENTORY cocmmand
    // not so obvious, but in the call to BuildInventoryResponse,  the command is copied to the global ToSend buffer used below.
    BuildInventoryResponse(uid);

    while (!BUTTON_PRESS()) {
        WDT_HIT();

        // Listen to reader
		uint8_t cmd[ISO15693_MAX_COMMAND_LENGTH];
		uint32_t eof_time = 0, start_time = 0;
		int cmd_len = GetIso15693CommandFromReader(cmd, sizeof(cmd), &eof_time);

		if ((cmd_len >= 5) && (cmd[0] & ISO15_REQ_INVENTORY) && (cmd[1] == ISO15_CMD_INVENTORY)) { // TODO: check more flags
			bool slow = !(cmd[0] & ISO15_REQ_DATARATE_HIGH);
			start_time = eof_time + DELAY_ISO15693_VCD_TO_VICC_SIM;
			TransmitTo15693Reader(ToSend, ToSendMax, &start_time, 0, slow);
		}

        if (DBGLEVEL >= DBG_EXTENDED) {
            Dbprintf(" %d bytes read from reader:", cmd_len);
            Dbhexdump(cmd_len, cmd, false);
        }
 	}
    
    switch_off();
}

// Since there is no standardized way of reading the AFI out of a tag, we will brute force it
// (some manufactures offer a way to read the AFI, though)
void BruteforceIso15693Afi(uint32_t speed) {

    uint8_t data[7] = {0};
    uint8_t recv[ISO15693_MAX_RESPONSE_LENGTH];   
    Iso15693InitReader();

    // first without AFI
    // Tags should respond wihtout AFI and with AFI=0 even when AFI is active

    data[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
    data[1] = ISO15_CMD_INVENTORY;
    data[2] = 0; // AFI
    AddCrc15(data, 3);

    int datalen = 5;    
    uint32_t eof_time = 0;
	uint32_t start_time = GetCountSspClk();
	int recvlen = SendDataTag(data, datalen, true, speed, recv, sizeof(recv), 0, ISO15693_READER_TIMEOUT, &eof_time);
	start_time = eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;

    WDT_HIT();

    if (recvlen >= 12) {
        Dbprintf("NoAFI UID = %s", iso15693_sprintUID(NULL, recv + 2));
    }

    // now with AFI
    data[0] |= ISO15_REQINV_AFI;
    data[2] = 0; // AFI
    data[3] = 0; // mask length

    // 4 + 2crc
    datalen = 6;

    bool aborted = false;
    for (uint16_t i = 0; i < 256; i++) {

        data[2] = i & 0xFF;
        AddCrc15(data, 4);

		recvlen = SendDataTag(data, datalen, false, speed, recv, sizeof(recv), start_time, ISO15693_READER_TIMEOUT, &eof_time);
		start_time = eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;
        
        WDT_HIT();

        if (recvlen >= 12) {
            Dbprintf("AFI = %i  UID = %s", i, iso15693_sprintUID(NULL, recv + 2));
        }

        aborted = BUTTON_PRESS();

        if (aborted) {
            DbpString("button pressed, aborting..");
            break;
        }
    }

    DbpString("AFI Bruteforcing done.");
    switch_off();

    if (aborted) {
        reply_ng(CMD_ACK, PM3_EOPABORTED, NULL, 0);
    } else {
        reply_ng(CMD_ACK, PM3_SUCCESS, NULL, 0);
    }
}

// Allows to directly send commands to the tag via the client
// OBS:  doesn't turn off rf field afterwards.
void DirectTag15693Command(uint32_t datalen, uint32_t speed, uint32_t recv, uint8_t *data) {

	LED_A_ON();

	int recvlen = 0;
	uint8_t recvbuf[ISO15693_MAX_RESPONSE_LENGTH];
	uint32_t eof_time;
	uint16_t timeout;
    bool request_answer = false;
	
	switch (data[1]) {
		case ISO15_CMD_WRITE:
		case ISO15_CMD_LOCK:
		case ISO15_CMD_WRITEMULTI:
		case ISO15_CMD_WRITEAFI:
		case ISO15_CMD_LOCKAFI:
		case ISO15_CMD_WRITEDSFID:
		case ISO15_CMD_LOCKDSFID:
			timeout = ISO15693_READER_TIMEOUT_WRITE;
			request_answer = data[0] & ISO15_REQ_OPTION;
			break;
		default:
			timeout = ISO15693_READER_TIMEOUT;
	}		

	if (DBGLEVEL >= DBG_EXTENDED) {
		Dbprintf("SEND:");
		Dbhexdump(datalen, data, false);
	}

	recvlen = SendDataTag(data, datalen, true, speed, (recv ? recvbuf : NULL), sizeof(recvbuf), 0, timeout, &eof_time);

    // send a single EOF to get the tag response
	if (request_answer) { 
		recvlen = SendDataTagEOF((recv ? recvbuf : NULL), sizeof(recvbuf), 0, ISO15693_READER_TIMEOUT, &eof_time);
	}
	
	// for the time being, switch field off to protect rdv4.0
	// note: this prevents using hf 15 cmd with s option - which isn't implemented yet anyway
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LED_D_OFF();

    if (recv) {

		if (recvlen > ISO15693_MAX_RESPONSE_LENGTH) {
			recvlen = ISO15693_MAX_RESPONSE_LENGTH;
		}
		reply_mix(CMD_ACK, recvlen, 0, 0, recvbuf, ISO15693_MAX_RESPONSE_LENGTH);


		if (DBGLEVEL >= DBG_EXTENDED) {
			Dbprintf("RECV:");
			if (recvlen > 0) {
				Dbhexdump(recvlen, recvbuf, false);
				DbdecodeIso15693Answer(recvlen, recvbuf);
			}
		}


    } else {
        reply_mix(CMD_ACK, 1, 0, 0, 0, 0);
    }
}


//-----------------------------------------------------------------------------
// Work with "magic Chinese" card.
//
//-----------------------------------------------------------------------------

// Set the UID on Magic ISO15693 tag (based on Iceman's LUA-script).
void SetTag15693Uid(uint8_t *uid) {

	LED_A_ON();

	uint8_t cmd[4][9] = {
		{ISO15_REQ_DATARATE_HIGH, ISO15_CMD_WRITE, 0x3e, 0x00, 0x00, 0x00, 0x00},
		{ISO15_REQ_DATARATE_HIGH, ISO15_CMD_WRITE, 0x3f, 0x69, 0x96, 0x00, 0x00},
		{ISO15_REQ_DATARATE_HIGH, ISO15_CMD_WRITE, 0x38},
		{ISO15_REQ_DATARATE_HIGH, ISO15_CMD_WRITE, 0x39}
	};

	int recvlen = 0;
	uint8_t recvbuf[ISO15693_MAX_RESPONSE_LENGTH];
	uint32_t eof_time;

	// Command 3 : 022138u8u7u6u5 (where uX = uid byte X)
	cmd[2][3] = uid[7];
	cmd[2][4] = uid[6];
	cmd[2][5] = uid[5];
	cmd[2][6] = uid[4];

	// Command 4 : 022139u4u3u2u1 (where uX = uid byte X)
	cmd[3][3] = uid[3];
	cmd[3][4] = uid[2];
	cmd[3][5] = uid[1];
	cmd[3][6] = uid[0];

    AddCrc15(cmd[0], 7);
    AddCrc15(cmd[1], 7);
    AddCrc15(cmd[2], 7);
    AddCrc15(cmd[3], 7);

	uint32_t start_time = 0;
	
	for (int i = 0; i < 4; i++) {
		
		recvlen = SendDataTag(cmd[i], sizeof(cmd[i]), i == 0 ? true : false, true, recvbuf, sizeof(recvbuf), start_time, ISO15693_READER_TIMEOUT_WRITE, &eof_time);
		start_time = eof_time + DELAY_ISO15693_VICC_TO_VCD_READER;

		if (DBGLEVEL >= DBG_EXTENDED) {
			Dbprintf("SEND:");
			Dbhexdump(sizeof(cmd[i]), cmd[i], false);
			Dbprintf("RECV:");
			if (recvlen > 0) {
				Dbhexdump(recvlen, recvbuf, false);
				DbdecodeIso15693Answer(recvlen, recvbuf);
			}
		}
	}

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
	reply_mix(CMD_ACK, recvlen, 0, 0, recvbuf, recvlen);
}
