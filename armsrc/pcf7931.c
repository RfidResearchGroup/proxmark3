//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
#include "pcf7931.h"

#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "util.h"
#include "lfsampling.h"
#include "string.h"

#define T0_PCF 8 //period for the pcf7931 in us
#define ALLOC 16

// IIR filter consts
#define IIR_CONST1 0.1f
#define IIR_CONST2 0.9f

// used to decimate samples. this allows DoAcquisition to sample for a longer duration.
// Decimation of 4 makes sure that all blocks can be sampled at once!
#define DECIMATION 4

#define CLOCK (64/DECIMATION) // this actually is 64, but since samples are decimated by 2, CLOCK is also /2
#define TOLERANCE (CLOCK / 8)
#define _16T0 (CLOCK/4)
#define _32T0 (CLOCK/2)
#define _64T0 (CLOCK)

// calculating the two possible pmc lengths, based on the clock. -4 at the end is to make sure not to increment too far
#define PMC_16T0_LEN ((128 + 127 + 16 + 32 + 33 + 16) * CLOCK/64);
#define PMC_32T0_LEN ((128 + 127 + 16 + 32 + 33 ) * CLOCK/64);

// theshold for recognition of positive/negative slope
#define THRESHOLD 80

size_t DemodPCF7931(uint8_t **outBlocks, bool ledcontrol) {
    uint8_t bits[256] = {0x00};
    uint8_t blocks[8][16];
    uint8_t *dest = BigBuf_get_addr();
    uint16_t g_GraphTraceLen = BigBuf_max_traceLen();
    // limit g_GraphTraceLen to a little more than 2 data frames.
    // To make sure a complete dataframe is in the dataset.
    // 1 Frame is 16 Byte -> 128byte. at a T0 of 64 -> 8129 Samples per frame.
    // + PMC -> 384T0  --> 8576 samples required for one block
    // to make sure that one complete block is definitely being sampled, we need 2 times that
    // which is ~17.xxx samples. round up. and clamp to this value.

    // TODO: Doublecheck why this is being limited? - seems not to be needed.
    // g_GraphTraceLen = (g_GraphTraceLen > 18000) ? 18000 : g_GraphTraceLen;

    BigBuf_Clear_keep_EM();
    LFSetupFPGAForADC(LF_DIVISOR_125, true);
    DoAcquisition(DECIMATION, 8, 0, 0, false, 0, 0, 0, ledcontrol);

    uint8_t j;
    uint8_t half_switch;
    uint8_t bitPos;

    uint32_t sample;    // to keep track of the current sample that is being analyzed
    uint32_t samplePosLastEdge;
    uint32_t samplePosCurrentEdge;
    uint8_t lastClockDuration; // used to store the duration of the last "clock", for decoding. clock may not be the correct term, maybe bit is better. The duration between two edges is meant
    uint8_t beforeLastClockDuration; // store the clock duration of the cycle before the last Clock duration. Basically clockduration -2


    uint8_t block_done;
    size_t num_blocks = 0;
    EdgeType expectedNextEdge = FALLING; // direction in which the next edge is expected should go.

    half_switch = 0;
    samplePosLastEdge = 0;
    block_done = 0;
    bitPos = 0;
    lastClockDuration = 0;

    for (sample = 1 ; sample < g_GraphTraceLen - 4; sample++) {
        // condition is searching for the next edge, in the expected diretion.
        //todo: without flouz
        dest[sample] = (uint8_t)(dest[sample - 1] * IIR_CONST1 +  dest[sample] * IIR_CONST2); // apply IIR filter

        if (((dest[sample] + THRESHOLD) < dest[sample - 1] && expectedNextEdge == FALLING) ||
                ((dest[sample] - THRESHOLD) > dest[sample - 1] && expectedNextEdge == RISING)) {
            //okay, next falling/rising edge found

            expectedNextEdge = (expectedNextEdge == FALLING) ? RISING : FALLING; //toggle the next expected edge
            samplePosCurrentEdge = sample;
            beforeLastClockDuration = lastClockDuration; // save the previous clock duration for PMC recognition
            lastClockDuration = samplePosCurrentEdge - samplePosLastEdge;
            samplePosLastEdge = sample;

            //  Dbprintf("%d, %d, edge found, len: %d, nextEdge: %d", sample, dest[sample], lastClockDuration*DECIMATION, expectedNextEdge);

            // Switch depending on lastClockDuration length:
            // 16T0
            if (ABS(lastClockDuration - _16T0) < TOLERANCE) {

                // if the clock before also was 16T0, it is a PMC!
                if (ABS(beforeLastClockDuration - _16T0) < TOLERANCE) {
                    // It's a PMC
                    Dbprintf(_GREEN_("PMC 16T0 FOUND:") " bitPos: %d, sample: %d", bitPos, sample);
                    sample += PMC_16T0_LEN;  // move to the sample after PMC

                    expectedNextEdge = FALLING;
                    samplePosLastEdge = sample;
                    block_done = 1;
                }

                // 32TO
            } else if (ABS(lastClockDuration - _32T0) < TOLERANCE) {
                // if the clock before also was 16T0, it is a PMC!
                if (ABS(beforeLastClockDuration - _16T0) < TOLERANCE) {
                    // It's a PMC !
                    Dbprintf(_GREEN_("PMC 32T0 FOUND:") " bitPos: %d, sample: %d", bitPos, sample);

                    sample += PMC_32T0_LEN;    // move to the sample after PMC

                    expectedNextEdge = FALLING;
                    samplePosLastEdge = sample;
                    block_done = 1;

                    // if no pmc, then its a normal bit.
                    // Check if its the second time, the edge changed if yes, then the bit is 0
                } else if (half_switch == 1) {
                    bits[bitPos] = 0;
                    // reset the edge counter to 0
                    half_switch = 0;
                    bitPos++;

                    // if it is the first time the edge changed. No bit value will be set here, bit if the
                    // edge changes again, it will be. see case above.
                } else
                    half_switch++;

                // 64T0
            } else if (ABS(lastClockDuration - _64T0) < TOLERANCE) {
                // this means, bit here is 1
                bits[bitPos] = 1;
                bitPos++;

                // Error
            } else {
                // some Error. maybe check tolerances.
                // likeley to happen in the first block.

                // In an Ideal world, this can be enabled. However, if only bad antenna field, this print will flood the output
                // and one might miss some "good" frames.
                //Dbprintf(_RED_("ERROR in demodulation") " Length last clock: %d - check threshold/tolerance/signal. Toss block", lastClockDuration*DECIMATION);

                // Toss this block.
                block_done = 1;
            }

            if (block_done == 1) {
                // Dbprintf(_YELLOW_("Block Done") " bitPos: %d, sample: %d", bitPos, sample);

                // check if it is a complete block. If bitpos <128, it means that we did not receive
                // a complete block. E.g. at the first start of a transmission.
                // only save if a complete block is being received.
                if (bitPos == 128) {
                    for (j = 0; j < 16; ++j) {
                        blocks[num_blocks][j] =
                            128 * bits[j * 8 + 7] +
                            64 * bits[j * 8 + 6] +
                            32 * bits[j * 8 + 5] +
                            16 * bits[j * 8 + 4] +
                            8 * bits[j * 8 + 3] +
                            4 * bits[j * 8 + 2] +
                            2 * bits[j * 8 + 1] +
                            bits[j * 8]
                            ;
                    }
                    num_blocks++;
                }
                // now start over for the next block / first complete block.
                bitPos = 0;
                block_done = 0;
                half_switch = 0;
            }

        } else {
            // Dbprintf("%d, %d", sample, dest[sample]);
        }

        // one block only holds 16byte (=128 bit) and then comes the PMC. so if more bit are found than 129, there must be an issue and PMC has not been identfied...
        // TODO: not sure what to do in such case...
        if (bitPos >= 129) {
            Dbprintf(_RED_("PMC should have been found...") " bitPos: %d, sample: %d", bitPos, sample);
            bitPos = 0;
        }

    }

    memcpy(outBlocks, blocks, 16 * num_blocks);
    return num_blocks;
}

bool IsBlock0PCF7931(uint8_t *block) {
    // assuming all RFU bits are set to 0
    // if PAC is enabled password is set to 0
    if (block[7] == 0x01) {
        if (!memcmp(block, "\x00\x00\x00\x00\x00\x00\x00", 7) &&
                !memcmp(block + 9, "\x00\x00\x00\x00\x00\x00\x00", 7)) {
            return true;
        }

    } else if (block[7] == 0x00) {
        if (!memcmp(block + 9, "\x00\x00\x00\x00\x00\x00\x00", 7)) {
            return true;
        }
    }
    return false;
}

bool IsBlock1PCF7931(const uint8_t *block) {
    // assuming all RFU bits are set to 0

    uint8_t rb1 = block[14] & 0x80;
    uint8_t rfb = block[14] & 0x7f;
    uint8_t rlb = block[15];

    if (block[10] == 0
            && block[11] == 0
            && block[12] == 0
            && block[13] == 0) {
        // block 1 is sent only if (RLB >= 1 && RFB <= 1) or RB1 enabled
        if (rfb <= rlb
                && rfb <= 9
                && rlb <= 9
                && ((rfb <= 1 && rlb >= 1) || rb1)) {
            return true;
        }
    }

    return false;
}

void ReadPCF7931(bool ledcontrol) {

    uint8_t maxBlocks = 8;   // readable blocks
    int found_blocks = 0; // successfully read blocks

    // TODO: Why 17 byte len? 16 should be good.
    uint8_t memory_blocks[maxBlocks][17]; // PCF content
    uint8_t single_blocks[maxBlocks][17]; // PFC blocks with unknown position
    uint8_t tmp_blocks[4][16]; // temporary read buffer

    int single_blocks_cnt = 0;

    size_t n; // transmitted blocks

    //uint8_t found_0_1 = 0; // flag: blocks 0 and 1 were found
    int errors = 0; // error counter
    int tries = 0; // tries counter

    // reuse lenghts and consts to properly clear
    memset(memory_blocks, 0, 8 * 17 * sizeof(uint8_t));
    memset(single_blocks, 0, 8 * 17 * sizeof(uint8_t));

    int i = 0;
    //j = 0;

    do {
        Dbprintf("ReadPCF7931() -- Reading Loop ==========");
        i = 0;

        memset(tmp_blocks, 0, 4 * 16 * sizeof(uint8_t));
        n = DemodPCF7931((uint8_t **)tmp_blocks, ledcontrol);
        if (!n)
            ++errors;

        // exit if no block is received
        if (errors >= 10 && found_blocks == 0 && single_blocks_cnt == 0) {
            Dbprintf("[!!] Error, no tag or bad tag");
            return;
        }
        // exit if too many tries without finding the first block
        if (tries > 10) {

            Dbprintf("End after 10 tries");
            if (g_dbglevel >= DBG_INFO) {
                Dbprintf("[!!] Error reading the tag, only partial content");
            }

            goto end;
        }

        // This part was not working properly.
        // So currently the blocks are not being sorted, but at least printed.

        // // our logic breaks if we don't get at least two blocks
        // if (n < 2) {
        //     // skip if all 0s block or no blocks
        //     if (n == 0 || !memcmp(tmp_blocks[0], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16))
        //         continue;

        //     // add block to single blocks list
        //     if (single_blocks_cnt < maxBlocks) {
        //         for (i = 0; i < single_blocks_cnt; ++i) {
        //             if (!memcmp(single_blocks[i], tmp_blocks[0], 16)) {
        //                 j = 1;
        //                 break;
        //             }
        //         }
        //         if (j != 1) {
        //             memcpy(single_blocks[single_blocks_cnt], tmp_blocks[0], 16);
        //             print_result("got single block", single_blocks[single_blocks_cnt], 16);
        //             single_blocks_cnt++;
        //         }
        //         j = 0;
        //     }
        //     ++tries;
        //     continue;
        // }

        // Dbprintf("(dbg) got %d blocks (%d/%d found) (%d tries, %d errors)", n, found_blocks, (maxBlocks == 0 ? found_blocks : maxBlocks), tries, errors);
        // if (g_dbglevel >= DBG_EXTENDED)
        //     Dbprintf("(dbg) got %d blocks (%d/%d found) (%d tries, %d errors)", n, found_blocks, (maxBlocks == 0 ? found_blocks : maxBlocks), tries, errors);

        // print blocks that have been found
        for (i = 0; i < n; ++i) {
            print_result("Block found: ", tmp_blocks[i], 16);
        }

        // i = 0;
        // if (!found_0_1) {
        //     while (i < n - 1) {
        //         if (IsBlock0PCF7931(tmp_blocks[i]) && IsBlock1PCF7931(tmp_blocks[i + 1])) {
        //             found_0_1 = 1;
        //             memcpy(memory_blocks[0], tmp_blocks[i], 16);
        //             memcpy(memory_blocks[1], tmp_blocks[i + 1], 16);
        //             memory_blocks[0][ALLOC] = memory_blocks[1][ALLOC] = 1;
        //             // block 1 tells how many blocks are going to be sent
        //             maxBlocks = MAX((memory_blocks[1][14] & 0x7f), memory_blocks[1][15]) + 1;
        //             found_blocks = 2;

        //             Dbprintf("Found blocks 0 and 1. PCF is transmitting %d blocks.", maxBlocks);

        //             // handle the following blocks
        //             for (j = i + 2; j < n; ++j) {
        //                 memcpy(memory_blocks[found_blocks], tmp_blocks[j], 16);
        //                 memory_blocks[found_blocks][ALLOC] = 1;
        //                 ++found_blocks;
        //             }
        //             break;
        //         }
        //         ++i;
        //     }
        // } else {
        //     // Trying to re-order blocks
        //     // Look for identical block in memory blocks
        //     while (i < n - 1) {
        //         // skip all zeroes blocks
        //         if (memcmp(tmp_blocks[i], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16)) {
        //             for (j = 1; j < maxBlocks - 1; ++j) {
        //                 if (!memcmp(tmp_blocks[i], memory_blocks[j], 16) && !memory_blocks[j + 1][ALLOC]) {
        //                     memcpy(memory_blocks[j + 1], tmp_blocks[i + 1], 16);
        //                     memory_blocks[j + 1][ALLOC] = 1;
        //                     if (++found_blocks >= maxBlocks) goto end;
        //                 }
        //             }
        //         }
        //         if (memcmp(tmp_blocks[i + 1], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16)) {
        //             for (j = 0; j < maxBlocks; ++j) {
        //                 if (!memcmp(tmp_blocks[i + 1], memory_blocks[j], 16) && !memory_blocks[(j == 0 ? maxBlocks : j) - 1][ALLOC]) {
        //                     if (j == 0) {
        //                         memcpy(memory_blocks[maxBlocks - 1], tmp_blocks[i], 16);
        //                         memory_blocks[maxBlocks - 1][ALLOC] = 1;
        //                     } else {
        //                         memcpy(memory_blocks[j - 1], tmp_blocks[i], 16);
        //                         memory_blocks[j - 1][ALLOC] = 1;
        //                     }
        //                     if (++found_blocks >= maxBlocks) goto end;
        //                 }
        //             }
        //         }
        //         ++i;
        //     }
        // }
        ++tries;
        if (BUTTON_PRESS()) {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("Button pressed, stopping.");

            goto end;
        }
    } while (found_blocks < maxBlocks);


end:
    /*
        Dbprintf("-----------------------------------------");
        Dbprintf("Memory content:");
        Dbprintf("-----------------------------------------");
        for (i = 0; i < maxBlocks; ++i) {
            if (memory_blocks[i][ALLOC])
                print_result("Block", memory_blocks[i], 16);
            else
                Dbprintf("<missing block %d>", i);
        }
        Dbprintf("-----------------------------------------");

        if (found_blocks < maxBlocks) {
            Dbprintf("-----------------------------------------");
            Dbprintf("Blocks with unknown position:");
            Dbprintf("-----------------------------------------");
            for (i = 0; i < single_blocks_cnt; ++i)
                print_result("Block", single_blocks[i], 16);

            Dbprintf("-----------------------------------------");
        }
    */

    reply_mix(CMD_ACK, 0, 0, 0, 0, 0);
}

static void RealWritePCF7931(
    uint8_t *pass,
    uint16_t init_delay,
    int8_t offsetPulseWidth, int8_t offsetPulsePosition,
    uint8_t address, uint8_t byte, uint8_t data,
    bool ledcontrol) {

    uint32_t tab[1024] = {0}; // data times frame
    uint32_t u = 0;
    uint8_t parity = 0;

    //BUILD OF THE DATA FRAME
    //alimentation of the tag (time for initializing)
    // ToDo: This could be optimized/automated. e.g. Read one cycle, find PMC and calculate time.
    // I dont understand, why 8192/2
    AddPatternPCF7931(init_delay, 0, 8192 / 2 * T0_PCF, tab);

    // why "... + 70"? Why not "... + x * T0"?
    // I think he just added 70 to be somewhere in The PMC window, which is 32T0 (=32*8 = 256)
    // 3*T0 = PMC width
    // 29*T0 = rest of PMC window (total 32T0 = 3+29)
    // after the PMC, it directly goes to the password indication bit.
    AddPatternPCF7931(8192 / 2 * T0_PCF + 319 * T0_PCF + 70, 3 * T0_PCF, 29 * T0_PCF, tab);
    //password indication bit
    AddBitPCF7931(1, tab, offsetPulseWidth, offsetPulsePosition);
    //password (on 56 bits)
    AddBytePCF7931(pass[0], tab, offsetPulseWidth, offsetPulsePosition);
    AddBytePCF7931(pass[1], tab, offsetPulseWidth, offsetPulsePosition);
    AddBytePCF7931(pass[2], tab, offsetPulseWidth, offsetPulsePosition);
    AddBytePCF7931(pass[3], tab, offsetPulseWidth, offsetPulsePosition);
    AddBytePCF7931(pass[4], tab, offsetPulseWidth, offsetPulsePosition);
    AddBytePCF7931(pass[5], tab, offsetPulseWidth, offsetPulsePosition);
    AddBytePCF7931(pass[6], tab, offsetPulseWidth, offsetPulsePosition);
    //programming mode (0 or 1) -> 0 = byte wise; 1 = block wise programming
    AddBitPCF7931(0, tab, offsetPulseWidth, offsetPulsePosition);

    //block address on 6 bits
    for (u = 0; u < 6; ++u) {
        if (address & (1 << u)) { // bit 1
            ++parity;
            AddBitPCF7931(1, tab, offsetPulseWidth, offsetPulsePosition);
        } else {              // bit 0
            AddBitPCF7931(0, tab, offsetPulseWidth, offsetPulsePosition);
        }
    }

    //byte address on 4 bits
    for (u = 0; u < 4; ++u) {
        if (byte & (1 << u)) { // bit 1
            parity++;
            AddBitPCF7931(1, tab, offsetPulseWidth, offsetPulsePosition);
        } else                // bit 0
            AddBitPCF7931(0, tab, offsetPulseWidth, offsetPulsePosition);
    }

    //data on 8 bits
    for (u = 0; u < 8; u++) {
        if (data & (1 << u)) { // bit 1
            parity++;
            AddBitPCF7931(1, tab, offsetPulseWidth, offsetPulsePosition);
        } else                //bit 0
            AddBitPCF7931(0, tab, offsetPulseWidth, offsetPulsePosition);
    }

    //parity bit
    if ((parity % 2) == 0)
        AddBitPCF7931(0, tab, offsetPulseWidth, offsetPulsePosition); //even parity
    else
        AddBitPCF7931(1, tab, offsetPulseWidth, offsetPulsePosition);//odd parity

    // time access memory (640T0)
    // Not sure why 335*T0, but should not matter. Since programming should be finished at that point
    AddPatternPCF7931((640 + 335)* T0_PCF, 0, 0, tab);

    SendCmdPCF7931(tab, ledcontrol);
}

/* Write on a byte of a PCF7931 tag
 * @param address : address of the block to write
 * @param byte : address of the byte to write
 * @param data : data to write
 */
void WritePCF7931(
    uint8_t pass1, uint8_t pass2, uint8_t pass3, uint8_t pass4, uint8_t pass5, uint8_t pass6, uint8_t pass7,
    uint16_t init_delay,
    int8_t offsetPulseWidth, int8_t offsetPulsePosition,
    uint8_t address, uint8_t byte, uint8_t data,
    bool ledcontrol) {

    if (g_dbglevel >= DBG_INFO) {
        Dbprintf("Initialization delay : %d us", init_delay);
        Dbprintf("Offsets : %d us on the low pulses width, %d us on the low pulses positions", offsetPulseWidth, offsetPulsePosition);
    }

    Dbprintf("Password (LSB first on each byte): %02x %02x %02x %02x %02x %02x %02x", pass1, pass2, pass3, pass4, pass5, pass6, pass7);
    Dbprintf("Block address : %02x", address);
    Dbprintf("Byte address : %02x", byte);
    Dbprintf("Data : %02x", data);

    uint8_t password[7] = {pass1, pass2, pass3, pass4, pass5, pass6, pass7};

    RealWritePCF7931(password, init_delay, offsetPulseWidth, offsetPulsePosition, address, byte, data, ledcontrol);
}


/* Send a frame to a PCF7931 tags
 * @param tab : array of the data frame
 */

void SendCmdPCF7931(uint32_t *tab, bool ledcontrol) {
    uint16_t u = 0, tempo = 0;

    if (g_dbglevel >= DBG_INFO) {
        Dbprintf("Sending data frame...");
    }

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125); //125kHz
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_PASSTHRU);

    if (ledcontrol) LED_A_ON();

    // rescale the values to match the time of the timer below.
    for (u = 0; u < 500; ++u) {
        tab[u] = (tab[u] * 3) / 2;
    }

    // compensation for the counter overflow
    // only one overflow should be possible.
    for (u = 0; tab[u] != 0; ++u)
        if (tab[u] > 0xFFFF) {
            tab[u] -= 0xFFFF;
            break;
        }


    // steal this pin from the SSP and use it to control the modulation
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;

    //initialization of the timer
    AT91C_BASE_PMC->PMC_PCER |= (0x1 << AT91C_ID_TC0);
    AT91C_BASE_TCB->TCB_BMR = AT91C_TCB_TC0XC0S_NONE | AT91C_TCB_TC1XC1S_TIOA0 | AT91C_TCB_TC2XC2S_NONE;
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS;                 // timer disable
    AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK;  // clock at 48/32 MHz (48Mhz clock, 32 = prescaler (div3))
    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN;

    // Assert a sync signal. This sets all timers to 0 on next active clock edge
    AT91C_BASE_TCB->TCB_BCR = 1;

    tempo = AT91C_BASE_TC0->TC_CV;
    for (u = 0; tab[u] != 0; u += 3) {
        // modulate antenna
        HIGH(GPIO_SSC_DOUT);
        while ((uint32_t)tempo < tab[u]) {
            tempo = AT91C_BASE_TC0->TC_CV;
        }

        // stop modulating antenna
        LOW(GPIO_SSC_DOUT);
        while ((uint32_t)tempo < tab[u + 1]) {
            tempo = AT91C_BASE_TC0->TC_CV;
        }

        // modulate antenna
        HIGH(GPIO_SSC_DOUT);
        while ((uint32_t)tempo < tab[u + 2]) {
            tempo = AT91C_BASE_TC0->TC_CV;
        }
    }

    if (ledcontrol) LED_A_OFF();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    SpinDelay(200);

    AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS; // timer disable
}


/* Add a byte for building the data frame of PCF7931 tags.
 * See Datasheet of PCF7931 diagramm on page 8. This explains pulse widht & positioning
 * Normally, no offset should be required.
 * @param b : byte to add
 * @param tab : array of the data frame
 * @param offsetPulseWidth : offset on low pulse width in µs (default pulse widht is 6T0)
 * @param offsetPulsePosition : offset on low pulse positioning in µs
 */
bool AddBytePCF7931(uint8_t byte, uint32_t *tab, int8_t offsetPulseWidth, int8_t offsetPulsePosition) {
    uint32_t u;
    for (u = 0; u < 8; ++u) {
        if (byte & (1 << u)) { //bit is 1
            AddBitPCF7931(1, tab, offsetPulseWidth, offsetPulsePosition);
        } else { //bit is 0
            AddBitPCF7931(0, tab, offsetPulseWidth, offsetPulsePosition);
        }
    }

    return false;
}

/* Add a bits for building the data frame of PCF7931 tags.
 * See Datasheet of PCF7931 diagramm on page 8. This explains pulse widht & positioning
 * Normally, no offset should be required.
 * @param b : bit to add
 * @param tab : array of the data frame
 * @param offsetPulseWidth : offset on low pulse width in µs (default pulse widht is 6T0)
 * @param offsetPulsePosition : offset on low pulse positioning in µs
 */
bool AddBitPCF7931(bool b, uint32_t *tab, int8_t offsetPulseWidth, int8_t offsetPulsePosition) {
    uint8_t u = 0;

    //we put the cursor at the last value of the array
    for (u = 0; tab[u] != 0; u += 3) { };

    if (b == 1) {   //add a bit 1
        if (u == 0)
            tab[u] = 34 * T0_PCF + offsetPulsePosition;
        else
            tab[u] = 34 * T0_PCF + tab[u - 1] + offsetPulsePosition;

        tab[u + 1] =  6 * T0_PCF + tab[u] + offsetPulseWidth;
        tab[u + 2] = 88 * T0_PCF + tab[u + 1] - offsetPulseWidth - offsetPulsePosition;

    } else { //add a bit 0
        if (u == 0)
            tab[u] = 98 * T0_PCF + offsetPulsePosition;
        else
            tab[u] = 98 * T0_PCF + tab[u - 1] + offsetPulsePosition;

        tab[u + 1] =  6 * T0_PCF + tab[u] + offsetPulseWidth;
        tab[u + 2] = 24 * T0_PCF + tab[u + 1] - offsetPulseWidth - offsetPulsePosition;

    }
    return true;
}

/* Add a custom pattern in the data frame
 * @param a : delay of the first high pulse
 * @param b : delay of the low pulse
 * @param c : delay of the last high pulse
 * @param tab : array of the data frame
 */
bool AddPatternPCF7931(uint32_t a, uint32_t b, uint32_t c, uint32_t *tab) {
    uint32_t u = 0;
    for (u = 0; tab[u] != 0; u += 3) {} //we put the cursor at the last value of the array

    tab[u]   = (u == 0) ? a : a + tab[u - 1];   // if it is the first value of the array, nothing needs to be added.
    tab[u + 1] = b + tab[u];                    // otherwise always add up the values, because later on it is compared to a counter
    tab[u + 2] = c + tab[u + 1];

    return true;
}
