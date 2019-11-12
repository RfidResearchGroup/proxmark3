//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Miscellaneous routines for low frequency tag operations.
// Tags supported here so far are Texas Instruments (TI), HID, EM4x05, EM410x
// Also routines for raw mode reading/simulating of LF waveform
//-----------------------------------------------------------------------------

#include "lfops.h"

#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "util.h"
#include "commonutil.h"

#include "crc16.h"
#include "string.h"
#include "printf.h"
#include "lfdemod.h"
#include "lfsampling.h"
#include "protocols.h"
#include "pmflash.h"
#include "flashmem.h" // persistence on flash

/*
Notes about EM4xxx timings.

The timing values differs between cards,  we got EM410x,  EM43x5, EM445x  etc.
We are trying to unify and enable the Proxmark to easily detect and select correct timings automatic.
The measures from datasheets doesn't always match correct the hardware features of RDV4 antenans and we still wanted to let other devices with other custom antennas
still benefit from this repo.  This is why its configurable and we use to set these dynamic settings in device external flash memory.


//  VALUES TAKEN FROM EM4x function: SendForward
//  START_GAP = 440;       (55*8) cycles at 125kHz (8us = 1cycle)
//  WRITE_GAP = 128;       (16*8)
//  WRITE_1   = 256 32*8;  (32*8)

//  These timings work for 4469/4269/4305 (with the 55*8 above)
//  WRITE_0 = 23*8 , 9*8

Not about ARM TIMERS
Short note about timers on Proxmark device ARM.  They are a bit differently implemented and gives decent correctness.

SAM7S has several timers, we will use the source TIMER_CLOCK1 (aka AT91C_TC_CLKS_TIMER_DIV1_CLOCK)
 TIMER_CLOCK1 = MCK/2, MCK is running at 48 MHz, Timer is running at 48/2 = 24 MHz

New timer implemenation in ticks.c, which is used in LFOPS.c
       1 μs = 1.5 ticks
 1 fc = 8 μs = 12 ticks

Terms you find in different datasheets and how they match.
1 Cycle = 8 microseconds (μs)  == 1 field clock (fc)

Note about HITAG timing
Hitag units (T0) have duration of 8 microseconds (us), which is 1/125000 per second (carrier)
 T0 = TIMER_CLOCK1 / 125000 = 192


  ==========================================================================================================
       T55x7 Timing
  ==========================================================================================================

    ATA5577 Downlink Protocol Timings.
    Note: All absolute times assume TC = 1 / fC = 8 μs (fC = 125 kHz)

    Note: These timings are from the datasheet and doesn't map the best to the features of the RVD4 LF antenna.
          RDV4 LF antenna has high voltage and the drop of power when turning off the rf field takes about 1-2 TC longer.

                                -----------------------------------------------------------------------
 Fixed-bit-length Protocol     |           Normal Downlink         |           Fast Downlink           |
 ------------------------------+-----------------------------------+-----------------------------------+------
| Parameter  | Remark | Symbol |    Min.   |    Typ.   |    Max.   |    Min.   |    Typ.   |    Max.   | Unit |
|------------+--------+--------+-----------+-----------+-----------+-----------+-----------+-----------+------|
| Start gap  |        | Sgap   |      8    |     15    |     50    |      8    |     15    |     50    |  Tc  |
| Write gap  |        | Wgap   |      8    |     10    |     20    |      8    |     10    |     20    |  Tc  |
|------------+--------+--------+-----------+-----------+-----------+-----------+-----------+-----------+------|
| coding     | 0 data | d0     |     16    |     24    |     32    |      8    |     12    |     16    |  Tc  |
|            | 1 data | d1     |     48    |     56    |     64    |     24    |     28    |     32    |  Tc  |
 -------------------------------------------------------------------------------------------------------------

                                -----------------------------------------------------------------------
 Long Leading Reference        |           Normal Downlink         |            Fast Downlink          |
 ------------------------------+-----------------------------------+-----------------------------------+------
| Parameter | Remark | Symbol  |    Min.   |    Typ.   |    Max.   |    Min.   |    Typ.   |    Max.   | Unit |
|-----------+--------+---------+-----------+-----------+-----------+-----------+-----------+-----------+------|
| Start gap |        | Sgap    |     8     |     10    |     50    |      8    |     10    |     50    |  Tc  |
| Write gap |        | Wgap    |     8     |     10    |     20    |      8    |     10    |     20    |  Tc  |
|-----------+--------+---------+-----------+-----------+-----------+-----------+-----------+-----------+------|
|   Write   | Ref    |         |    152    |    160    |    168    |     140   |     144   |    148    |  Tc  |
|   data    | Pulse  |  dref   |       136 clocks + 0 data bit     |       132 clocks + 0 data bit     |  Tc  |
|  coding   |--------+---------+-----------------------------------+-----------------------------------+------|
|           | 0 data | d0      |dref – 143 |dref – 136 |dref – 128 |dref – 135 |dref – 132 |dref – 124 |  Tc  |
|           | 1 data | d1      |dref – 111 |dref – 104 |dref – 96  |dref – 119 |dref – 116 |dref – 112 |  Tc  |
 -------------------------------------------------------------------------------------------------------------

                                -----------------------------------------------------------------------
 Leading-zero Reference        |           Normal Downlink         |            Fast Downlink          |
 ------------------------------+-----------------------------------+-----------------------------------+------
| Parameter | Remark | Symbol  |   Min.    |    Typ.   |    Max.   |    Min.   |   Typ.    |    Max.   | Unit |
|-----------+--------+---------+-----------+-----------+-----------+-----------+-----------+-----------+------|
| Start gap |        | Sgap    |     8     |      10   |     50    |      8    |     10    |     50    |  Tc  |
| Write gap |        | Wgap    |     8     |      10   |     20    |      8    |     10    |     20    |  Tc  |
|-----------+--------+---------+-----------+-----------+-----------+-----------+-----------+-----------+------|
| Write     | Ref    | dref    |    12     |      –    |     72    |      8    |     –     |     68    |  Tc  |
| data      | 0 data | d0      | dref – 7  |     dref  | dref + 8  | dref – 3  |   dref    | dref + 4  |  Tc  |
| coding    | 1 data | d1      | dref + 9  | dref + 16 | dref + 24 | dref + 5  | dref + 8  | dref + 12 |  Tc  |
 -------------------------------------------------------------------------------------------------------------

                                -----------------------------------------------------------------------
 1-of-4 Coding                 |           Normal Downlink         |           Fast Downlink           |
 ------------------------------+-----------------------------------+-----------------------------------+------
| Parameter | Remark | Symbol  |   Min.    |   Typ.    |    Max.   |    Min.   |    Typ.   |    Max.   | Unit |
|-----------+--------+---------+-----------+-----------+-----------+-----------+-----------+-----------+------|
| Start gap |        | Sgap    |     8     |     10    |     50    |       8   |      10   |     50    |  Tc  |
| Write gap |        | Wgap    |     8     |     10    |     20    |       8   |      10   |     20    |  Tc  |
|-----------+--------+---------+-----------+-----------+-----------+-----------+-----------+-----------+------|
| Write     | Ref 00 | dref    |     8     |     –     |     68    |      12   |      –    |     72    |  Tc  |
| data      |00 data | d00     | dref – 7  |   dref    | dref + 8  | dref – 3  |    dref   |  dref+ 4  |  Tc  |
| coding    |01 data | d01     | dref + 9  | dref + 16 | dref + 24 | dref + 5  | dref + 8  | dref + 12 |  Tc  |
|           |10 data | d10     | dref + 25 | dref + 32 | dref + 40 | dref + 13 | dref + 16 | dref + 20 |  Tc  |
|           |11 data | d11     | dref + 41 | dref + 48 | dref + 56 | dref + 21 | dref + 24 | dref + 28 |  Tc  |
 -------------------------------------------------------------------------------------------------------------

Initial values if not in flash

   SG = Start gap
   WG = Write gap
   RG = Read gap

 Explainations for array T55xx_Timing below

                           0        1       2       3
         SG     WG    Bit 00   Bit 01  Bit 10  Bit 11   RG
   --------------------------------------------------------------------
        { 29    , 17    , 15    , 47    , 0     , 0     , 15     }, // Default Fixed
        { 29    , 17    , 15    , 50    , 0     , 0     , 15     }, // Long Leading Ref.
        { 29    , 17    , 15    , 40    , 0     , 0     , 15     }, // Leading 0
        { 29    , 17    , 15    , 31    , 47    , 63    , 15     }  // 1 of 4
*/
t55xx_configurations_t T55xx_Timing  = {
    {
#ifdef WITH_FLASH
// PM3RDV4
        { 29 * 8, 17 * 8, 15 * 8, 47 * 8, 15 * 8, 0, 0 },           // Default Fixed
        { 29 * 8, 17 * 8, 15 * 8, 47 * 8, 15 * 8, 0, 0 },           // Long Leading Ref.
        { 29 * 8, 17 * 8, 15 * 8, 40 * 8, 15 * 8, 0, 0 },           // Leading 0
        { 29 * 8, 17 * 8, 15 * 8, 31 * 8, 15 * 8, 47 * 8, 63 * 8 }  // 1 of 4
#else
// PM3OTHER or like offical repo
        { 31 * 8, 20 * 8, 18 * 8, 50 * 8, 15 * 8, 0, 0 },           // Default Fixed
        { 31 * 8, 20 * 8, 18 * 8, 50 * 8, 15 * 8, 0, 0 },           // Long Leading Ref.
        { 31 * 8, 20 * 8, 18 * 8, 40 * 8, 15 * 8, 0, 0 },           // Leading 0
        { 31 * 8, 20 * 8, 18 * 8, 34 * 8, 15 * 8, 50 * 8, 66 * 8 }  // 1 of 4
#endif
    }
};


// Some defines for readability
#define T55XX_DLMODE_FIXED         0 // Default Mode
#define T55XX_DLMODE_LLR           1 // Long Leading Reference
#define T55XX_DLMODE_LEADING_ZERO  2 // Leading Zero
#define T55XX_DLMODE_1OF4          3 // 1 of 4
#define T55XX_LONGLEADINGREFERENCE 4 // Value to tell Write Bit to send long reference

// ATA55xx shared presets & routines
static uint32_t GetT55xxClockBit(uint32_t clock) {
    switch (clock) {
        case 128:
            return T55x7_BITRATE_RF_128;
        case 100:
            return T55x7_BITRATE_RF_100;
        case  64:
            return T55x7_BITRATE_RF_64;
        case  50:
            return T55x7_BITRATE_RF_50;
        case  40:
            return T55x7_BITRATE_RF_40;
        case  32:
            return T55x7_BITRATE_RF_32;
        case  16:
            return T55x7_BITRATE_RF_16;
        case   8:
            return T55x7_BITRATE_RF_8;
        default :
            return 0;
    }
}

void printT55xxConfig(void) {

#define PRN_NA   sprintf(s  + strlen(s), _RED_("N/A") "| ");

    DbpString(_BLUE_("LF T55XX config"));
    Dbprintf("           [r]               [a]   [b]   [c]   [d]   [e]   [f]   [g]");
    Dbprintf("           mode            |start|write|write|write| read|write|write");
    Dbprintf("                           | gap | gap |  0  |  1  | gap |  2  |  3");
    Dbprintf("---------------------------+-----+-----+-----+-----+-----+-----+------");

    for (uint8_t i = 0; i < 4; i++) {

        char s[160];
        memset(s, 0, sizeof(s));

        switch (i) {
            case T55XX_DLMODE_FIXED :
                sprintf(s, _YELLOW_("fixed bit length") _GREEN_("(default)") "|");
                break;
            case T55XX_DLMODE_LLR :
                sprintf(s, _YELLOW_("    long leading reference") "|");
                break;
            case T55XX_DLMODE_LEADING_ZERO :
                sprintf(s, _YELLOW_("              leading zero") "|");
                break;
            case T55XX_DLMODE_1OF4 :
                sprintf(s, _YELLOW_("   1 of 4 coding reference") "|");
                break;
            default:
                break;
        }

        if (T55xx_Timing.m[i].start_gap != 0xFFFF)
            sprintf(s + strlen(s), " %3d | ", T55xx_Timing.m[i].start_gap / 8);
        else
            PRN_NA;

        if (T55xx_Timing.m[i].write_gap != 0xFFFF)
            sprintf(s + strlen(s), "%3d | ", T55xx_Timing.m[i].write_gap / 8);
        else
            PRN_NA;

        if (T55xx_Timing.m[i].write_0 != 0xFFFF)
            sprintf(s + strlen(s), "%3d | ", T55xx_Timing.m[i].write_0 / 8);
        else
            PRN_NA;

        if (T55xx_Timing.m[i].write_1 != 0xFFFF)
            sprintf(s + strlen(s), "%3d | ", T55xx_Timing.m[i].write_1 / 8);
        else
            PRN_NA;

        if (T55xx_Timing.m[i].read_gap != 0xFFFF)
            sprintf(s + strlen(s), "%3d | ", T55xx_Timing.m[i].read_gap / 8);
        else
            PRN_NA;

        if (T55xx_Timing.m[i].write_2 != 0xFFFF && i == T55XX_DLMODE_1OF4)
            sprintf(s + strlen(s), "%3d | ", T55xx_Timing.m[i].write_2 / 8);
        else
            PRN_NA

            if (T55xx_Timing.m[i].write_3 != 0xFFFF && i == T55XX_DLMODE_1OF4)
                sprintf(s + strlen(s), "%3d | ", T55xx_Timing.m[i].write_3 / 8);
            else
                PRN_NA;

        s[strlen(s)] = 0;
        DbpString(s);
    }
    DbpString("");
}

void setT55xxConfig(uint8_t arg0, t55xx_configurations_t *c) {
    for (uint8_t i = 0; i < 4; i++) {
        if (c->m[i].start_gap != 0)
            T55xx_Timing.m[i].start_gap = c->m[i].start_gap;

        if (c->m[i].write_gap != 0)
            T55xx_Timing.m[i].write_gap = c->m[i].write_gap;

        if (c->m[i].write_0 != 0)
            T55xx_Timing.m[i].write_0 = c->m[i].write_0;

        if (c->m[i].write_1 != 0)
            T55xx_Timing.m[i].write_1 = c->m[i].write_1;

        if (i == T55XX_DLMODE_1OF4) {
            if (c->m[i].write_2 != 0)
                T55xx_Timing.m[i].write_2 = c->m[i].write_2;

            if (c->m[i].write_3 != 0)
                T55xx_Timing.m[i].write_3 = c->m[i].write_3;

        } else {
            T55xx_Timing.m[i].write_2 = 0x00;
            T55xx_Timing.m[i].write_3 = 0x00;
        }
        if (c->m[i].read_gap != 0)
            T55xx_Timing.m[i].read_gap = c->m[i].read_gap;
    }

    printT55xxConfig();

#ifdef WITH_FLASH
    // shall persist to flashmem
    if (arg0 == 0) {
        BigBuf_free();
        return;
    }

    if (!FlashInit()) {
        BigBuf_free();
        return;
    }

    uint8_t *buf = BigBuf_malloc(T55XX_CONFIG_LEN);
    Flash_CheckBusy(BUSY_TIMEOUT);
    uint16_t res = Flash_ReadDataCont(T55XX_CONFIG_OFFSET, buf, T55XX_CONFIG_LEN);
    if (res == 0) {
        FlashStop();
        BigBuf_free();
        return;
    }

    memcpy(buf, &T55xx_Timing, T55XX_CONFIG_LEN);

    // delete old configuration
    Flash_CheckBusy(BUSY_TIMEOUT);
    Flash_WriteEnable();
    Flash_Erase4k(3, 0xD);

    // write new
    res = Flash_Write(T55XX_CONFIG_OFFSET, buf, T55XX_CONFIG_LEN);

    if (res == T55XX_CONFIG_LEN && DBGLEVEL > 1) {
        DbpString("T55XX Config save " _GREEN_("success"));
    }

    BigBuf_free();
#endif
}

t55xx_configurations_t *getT55xxConfig(void) {
    return &T55xx_Timing;//_FixedBit;
}

void loadT55xxConfig(void) {
#ifdef WITH_FLASH

    if (!FlashInit()) {
        return;
    }

    uint8_t *buf = BigBuf_malloc(T55XX_CONFIG_LEN);

    Flash_CheckBusy(BUSY_TIMEOUT);
    uint16_t isok = Flash_ReadDataCont(T55XX_CONFIG_OFFSET, buf, T55XX_CONFIG_LEN);
    FlashStop();

    // verify read mem is actual data.
    uint8_t cntA = T55XX_CONFIG_LEN, cntB = T55XX_CONFIG_LEN;
    for (int i = 0; i < T55XX_CONFIG_LEN; i++) {
        if (buf[i] == 0xFF) cntA--;
        if (buf[i] == 0x00) cntB--;
    }
    if (!cntA || !cntB) {
        BigBuf_free();
        return;
    }

    if (buf[0] != 0xFF) // if not set for clear
        memcpy((uint8_t *)&T55xx_Timing, buf, T55XX_CONFIG_LEN);

    if (isok == T55XX_CONFIG_LEN) {
        if (DBGLEVEL > 1) DbpString("T55XX Config load success");
    }
#endif
}

/**
 * Function to do a modulation and then get samples.
 * @param delay_off
 * @param period_0
 * @param period_1
 * @param command (in binary char array)
 */
void ModThenAcquireRawAdcSamples125k(uint32_t delay_off, uint32_t period_0, uint32_t period_1, uint8_t *command) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // use lf config settings
    sample_config *sc = getSamplingConfig();


    // Make sure the tag is reset
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    // start timer
    StartTicks();

    WaitMS(100);

    // clear read buffer
    BigBuf_Clear_keep_EM();

    LFSetupFPGAForADC(sc->divisor, true);

    // little more time for the tag to fully power up
    WaitMS(20);

    // if delay_off = 0 then just bitbang 1 = antenna on 0 = off for respective periods.
    bool bitbang = (delay_off == 0);
    // now modulate the reader field
    if (bitbang) {
        // HACK it appears the loop and if statements take up about 7us so adjust waits accordingly...
        uint8_t hack_cnt = 7;
        if (period_0 < hack_cnt || period_1 < hack_cnt) {
            DbpString("[!] Warning periods cannot be less than 7us in bit bang mode");
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
            LED_D_OFF();
            reply_ng(CMD_LF_MOD_THEN_ACQ_RAW_ADC, PM3_EINVARG, NULL, 0);
            return;
        }

        // hack2 needed---  it appears to take about 8-16us to turn the antenna back on
        // leading to ~ 1 to 2 125kHz samples extra in every off period
        // so we should test for last 0 before next 1 and reduce period_0 by this extra amount...
        // but is this time different for every antenna or other hw builds???  more testing needed

        // prime cmd_len to save time comparing strings while modulating
        int cmd_len = 0;
        while (command[cmd_len] != '\0' && command[cmd_len] != ' ')
            cmd_len++;

        int counter = 0;
        bool off = false;
        for (counter = 0; counter < cmd_len; counter++) {
            // if cmd = 0 then turn field off
            if (command[counter] == '0') {
                // if field already off leave alone (affects timing otherwise)
                if (off == false) {
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    LED_D_OFF();
                    off = true;
                }
                // note we appear to take about 7us to switch over (or run the if statements/loop...)
                WaitUS(period_0 - hack_cnt);
                // else if cmd = 1 then turn field on
            } else {
                // if field already on leave alone (affects timing otherwise)
                if (off) {
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);
                    LED_D_ON();
                    off = false;
                }
                // note we appear to take about 7us to switch over (or run the if statements/loop...)
                WaitUS(period_1 - hack_cnt);
            }
        }
    } else { // old mode of cmd read using delay as off period
        while (*command != '\0' && *command != ' ') {
            LED_D_ON();
            if (*(command++) == '0')
                TurnReadLFOn(period_0);
            else
                TurnReadLFOn(period_1);

            LED_D_OFF();
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
            WaitUS(delay_off);
        }

        FpgaSendCommand(FPGA_CMD_SET_DIVISOR, sc->divisor);
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);

    // now do the read
    DoAcquisition_config(false, 0);

    // Turn off antenna
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    // tell client we are done
    reply_ng(CMD_LF_MOD_THEN_ACQ_RAW_ADC, PM3_SUCCESS, NULL, 0);
}

/* blank r/w tag data stream
...0000000000000000 01111111
1010101010101010101010101010101010101010101010101010101010101010
0011010010100001
01111111
101010101010101[0]000...

[5555fe852c5555555555555555fe0000]
*/
void ReadTItag(void) {
    StartTicks();
    // some hardcoded initial params
    // when we read a TI tag we sample the zerocross line at 2MHz
    // TI tags modulate a 1 as 16 cycles of 123.2kHz
    // TI tags modulate a 0 as 16 cycles of 134.2kHz
#define FSAMPLE 2000000
#define FREQLO 123200
#define FREQHI 134200

    signed char *dest = (signed char *)BigBuf_get_addr();
    uint16_t n = BigBuf_max_traceLen();
    // 128 bit shift register [shift3:shift2:shift1:shift0]
    uint32_t shift3 = 0, shift2 = 0, shift1 = 0, shift0 = 0;

    int i, cycles = 0, samples = 0;
    // how many sample points fit in 16 cycles of each frequency
    uint32_t sampleslo = (FSAMPLE << 4) / FREQLO, sampleshi = (FSAMPLE << 4) / FREQHI;
    // when to tell if we're close enough to one freq or another
    uint32_t threshold = (sampleslo - sampleshi + 1) >> 1;

    // TI tags charge at 134.2kHz
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_134); //~134kHz

    // Place FPGA in passthrough mode, in this mode the CROSS_LO line
    // connects to SSP_DIN and the SSP_DOUT logic level controls
    // whether we're modulating the antenna (high)
    // or listening to the antenna (low)
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_PASSTHRU);

    // get TI tag data into the buffer
    AcquireTiType();

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    for (i = 0; i < n - 1; i++) {
        // count cycles by looking for lo to hi zero crossings
        if ((dest[i] < 0) && (dest[i + 1] > 0)) {
            cycles++;
            // after 16 cycles, measure the frequency
            if (cycles > 15) {
                cycles = 0;
                samples = i - samples; // number of samples in these 16 cycles

                // TI bits are coming to us lsb first so shift them
                // right through our 128 bit right shift register
                shift0 = (shift0 >> 1) | (shift1 << 31);
                shift1 = (shift1 >> 1) | (shift2 << 31);
                shift2 = (shift2 >> 1) | (shift3 << 31);
                shift3 >>= 1;

                // check if the cycles fall close to the number
                // expected for either the low or high frequency
                if ((samples > (sampleslo - threshold)) && (samples < (sampleslo + threshold))) {
                    // low frequency represents a 1
                    shift3 |= (1u << 31);
                } else if ((samples > (sampleshi - threshold)) && (samples < (sampleshi + threshold))) {
                    // high frequency represents a 0
                } else {
                    // probably detected a gay waveform or noise
                    // use this as gaydar or discard shift register and start again
                    shift3 = shift2 = shift1 = shift0 = 0;
                }
                samples = i;

                // for each bit we receive, test if we've detected a valid tag

                // if we see 17 zeroes followed by 6 ones, we might have a tag
                // remember the bits are backwards
                if (((shift0 & 0x7fffff) == 0x7e0000)) {
                    // if start and end bytes match, we have a tag so break out of the loop
                    if (((shift0 >> 16) & 0xff) == ((shift3 >> 8) & 0xff)) {
                        cycles = 0xF0B; //use this as a flag (ugly but whatever)
                        break;
                    }
                }
            }
        }
    }

    // if flag is set we have a tag
    if (cycles != 0xF0B) {
        DbpString("Info: No valid tag detected.");
    } else {
        // put 64 bit data into shift1 and shift0
        shift0 = (shift0 >> 24) | (shift1 << 8);
        shift1 = (shift1 >> 24) | (shift2 << 8);

        // align 16 bit crc into lower half of shift2
        shift2 = ((shift2 >> 24) | (shift3 << 8)) & 0x0ffff;

        // if r/w tag, check ident match
        if (shift3 & (1 << 15)) {
            DbpString("Info: TI tag is rewriteable");
            // only 15 bits compare, last bit of ident is not valid
            if (((shift3 >> 16) ^ shift0) & 0x7fff) {
                DbpString("Error: Ident mismatch!");
            } else {
                DbpString("Info: TI tag ident is valid");
            }
        } else {
            DbpString("Info: TI tag is readonly");
        }

        // WARNING the order of the bytes in which we calc crc below needs checking
        // i'm 99% sure the crc algorithm is correct, but it may need to eat the
        // bytes in reverse or something
        // calculate CRC
        uint32_t crc = 0;

        crc = update_crc16(crc, (shift0) & 0xff);
        crc = update_crc16(crc, (shift0 >> 8) & 0xff);
        crc = update_crc16(crc, (shift0 >> 16) & 0xff);
        crc = update_crc16(crc, (shift0 >> 24) & 0xff);
        crc = update_crc16(crc, (shift1) & 0xff);
        crc = update_crc16(crc, (shift1 >> 8) & 0xff);
        crc = update_crc16(crc, (shift1 >> 16) & 0xff);
        crc = update_crc16(crc, (shift1 >> 24) & 0xff);

        Dbprintf("Info: Tag data: %x%08x, crc=%x", (unsigned int)shift1, (unsigned int)shift0, (unsigned int)shift2 & 0xFFFF);
        if (crc != (shift2 & 0xffff)) {
            Dbprintf("Error: CRC mismatch, expected %x", (unsigned int)crc);
        } else {
            DbpString("Info: CRC is good");
        }
    }
    StopTicks();
}

void WriteTIbyte(uint8_t b) {
    int i = 0;

    // modulate 8 bits out to the antenna
    for (i = 0; i < 8; i++) {
        if (b & (1 << i)) {
            // stop modulating antenna 1ms
            LOW(GPIO_SSC_DOUT);
            WaitUS(1000);
            // modulate antenna 1ms
            HIGH(GPIO_SSC_DOUT);
            WaitUS(1000);
        } else {
            // stop modulating antenna 0.3ms
            LOW(GPIO_SSC_DOUT);
            WaitUS(300);
            // modulate antenna 1.7ms
            HIGH(GPIO_SSC_DOUT);
            WaitUS(1700);
        }
    }
}

void AcquireTiType(void) {
    int i, j, n;
    // tag transmission is <20ms, sampling at 2M gives us 40K samples max
    // each sample is 1 bit stuffed into a uint32_t so we need 1250 uint32_t
#define TIBUFLEN 1250

    // clear buffer
    uint32_t *buf = (uint32_t *)BigBuf_get_addr();

    //clear buffer now so it does not interfere with timing later
    BigBuf_Clear_ext(false);

    // Set up the synchronous serial port
    AT91C_BASE_PIOA->PIO_PDR = GPIO_SSC_DIN;
    AT91C_BASE_PIOA->PIO_ASR = GPIO_SSC_DIN;

    // steal this pin from the SSP and use it to control the modulation
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;

    AT91C_BASE_SSC->SSC_CR = AT91C_SSC_SWRST;
    AT91C_BASE_SSC->SSC_CR = AT91C_SSC_RXEN | AT91C_SSC_TXEN;

    // Sample at 2 Mbit/s, so TI tags are 16.2 vs. 14.9 clocks long
    // 48/2 = 24 MHz clock must be divided by 12
    AT91C_BASE_SSC->SSC_CMR = 12;

    AT91C_BASE_SSC->SSC_RCMR = SSC_CLOCK_MODE_SELECT(0);
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(32) | AT91C_SSC_MSBF;
    // Transmit Clock Mode Register
    AT91C_BASE_SSC->SSC_TCMR = 0;
    // Transmit Frame Mode Register
    AT91C_BASE_SSC->SSC_TFMR = 0;
    // iceman, FpgaSetupSsc() ?? the code above? can it be replaced?
    LED_D_ON();

    // modulate antenna
    HIGH(GPIO_SSC_DOUT);

    // Charge TI tag for 50ms.
    WaitMS(50);

    // stop modulating antenna and listen
    LOW(GPIO_SSC_DOUT);

    LED_D_OFF();

    i = 0;
    for (;;) {
        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            buf[i] = AT91C_BASE_SSC->SSC_RHR; // store 32 bit values in buffer
            i++;
            if (i >= TIBUFLEN) break;
        }
        WDT_HIT();
    }

    // return stolen pin to SSP
    AT91C_BASE_PIOA->PIO_PDR = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_ASR = GPIO_SSC_DIN | GPIO_SSC_DOUT;

    char *dest = (char *)BigBuf_get_addr();
    n = TIBUFLEN * 32;

    // unpack buffer
    for (i = TIBUFLEN - 1; i >= 0; i--) {
        for (j = 0; j < 32; j++) {
            if (buf[i] & (1u << j)) {
                dest[--n] = 1;
            } else {
                dest[--n] = -1;
            }
        }
    }

    // reset SSC
    FpgaSetupSsc();
}

// arguments: 64bit data split into 32bit idhi:idlo and optional 16bit crc
// if crc provided, it will be written with the data verbatim (even if bogus)
// if not provided a valid crc will be computed from the data and written.
void WriteTItag(uint32_t idhi, uint32_t idlo, uint16_t crc) {
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    if (crc == 0) {
        crc = update_crc16(crc, (idlo) & 0xff);
        crc = update_crc16(crc, (idlo >> 8) & 0xff);
        crc = update_crc16(crc, (idlo >> 16) & 0xff);
        crc = update_crc16(crc, (idlo >> 24) & 0xff);
        crc = update_crc16(crc, (idhi) & 0xff);
        crc = update_crc16(crc, (idhi >> 8) & 0xff);
        crc = update_crc16(crc, (idhi >> 16) & 0xff);
        crc = update_crc16(crc, (idhi >> 24) & 0xff);
    }
    Dbprintf("Writing to tag: %x%08x, crc=%x", idhi, idlo, crc);

    // TI tags charge at 134.2kHz
    FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_134); //~134kHz
    // Place FPGA in passthrough mode, in this mode the CROSS_LO line
    // connects to SSP_DIN and the SSP_DOUT logic level controls
    // whether we're modulating the antenna (high)
    // or listening to the antenna (low)
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_PASSTHRU);
    StartTicks();

    LED_A_ON();

    // steal this pin from the SSP and use it to control the modulation
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;

    // writing algorithm:
    // a high bit consists of a field off for 1ms and field on for 1ms
    // a low bit consists of a field off for 0.3ms and field on for 1.7ms
    // initiate a charge time of 50ms (field on) then immediately start writing bits
    // start by writing 0xBB (keyword) and 0xEB (password)
    // then write 80 bits of data (or 64 bit data + 16 bit crc if you prefer)
    // finally end with 0x0300 (write frame)
    // all data is sent lsb first
    // finish with 50ms programming time

    // modulate antenna
    HIGH(GPIO_SSC_DOUT);
    WaitMS(50); // charge time

    WriteTIbyte(0xbb); // keyword
    WriteTIbyte(0xeb); // password
    WriteTIbyte((idlo) & 0xff);
    WriteTIbyte((idlo >> 8) & 0xff);
    WriteTIbyte((idlo >> 16) & 0xff);
    WriteTIbyte((idlo >> 24) & 0xff);
    WriteTIbyte((idhi) & 0xff);
    WriteTIbyte((idhi >> 8) & 0xff);
    WriteTIbyte((idhi >> 16) & 0xff);
    WriteTIbyte((idhi >> 24) & 0xff); // data hi to lo
    WriteTIbyte((crc) & 0xff);      // crc lo
    WriteTIbyte((crc >> 8) & 0xff); // crc hi
    WriteTIbyte(0x00); // write frame lo
    WriteTIbyte(0x03); // write frame hi
    HIGH(GPIO_SSC_DOUT);
    WaitMS(50); // programming time

    LED_A_OFF();

    // get TI tag data into the buffer
    AcquireTiType();

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    DbpString("Now use `lf ti read` to check");
    StopTicks();
}

// note:   a call to FpgaDownloadAndGo(FPGA_BITSTREAM_LF) must be done before, but
//  this may destroy the bigbuf so be sure this is called before calling SimulateTagLowFrequencyEx
void SimulateTagLowFrequencyEx(int period, int gap, bool ledcontrol, int numcycles) {

    // start us timer
    StartTicks();

    //FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT | FPGA_LF_EDGE_DETECT_TOGGLE_MODE );
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_EDGE_DETECT);
    WaitMS(20);

    int i = 0, x = 0;
    uint8_t *buf = BigBuf_get_addr();

    // set frequency,  get values from 'lf config' command
    sample_config *sc = getSamplingConfig();

    if ((sc->divisor == 1) || (sc->divisor < 0) || (sc->divisor > 255))
        FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_134); //~134kHz
    else if (sc->divisor == 0)
        FpgaSendCommand(FPGA_CMD_SET_DIVISOR, LF_DIVISOR_125); //125kHz
    else
        FpgaSendCommand(FPGA_CMD_SET_DIVISOR, sc->divisor);

    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT | GPIO_SSC_CLK;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_CLK;

    uint16_t check = 0;

    for (;;) {

        if (numcycles > -1) {
            if (x != numcycles) {
                ++x;
            } else {
                // exit without turning off field
                return;
            }
        }

        if (ledcontrol) LED_D_ON();

        // wait until SSC_CLK goes HIGH
        // used as a simple detection of a reader field?
        while (!(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK)) {
            WDT_HIT();
            if (check == 1000) {
                if (data_available() || BUTTON_PRESS())
                    goto OUT;
                check = 0;
            }
            ++check;
        }

        if (ledcontrol) LED_D_OFF();

        if (buf[i])
            OPEN_COIL();
        else
            SHORT_COIL();

        check = 0;

        //wait until SSC_CLK goes LOW
        while (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK) {
            WDT_HIT();
            if (check == 1000) {
                if (data_available() || BUTTON_PRESS())
                    goto OUT;
                check = 0;
            }
            ++check;
        }

        i++;
        if (i == period) {
            i = 0;
            if (gap) {
                SHORT_COIL();
                WaitUS(gap);
            }
        }
    }
OUT:
    StopTicks();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LED_D_OFF();
}

void SimulateTagLowFrequency(int period, int gap, bool ledcontrol) {
    SimulateTagLowFrequencyEx(period, gap, ledcontrol, -1);
}


#define DEBUG_FRAME_CONTENTS 1
void SimulateTagLowFrequencyBidir(int divisor, int max_bitlen) {
}

// compose fc/X fc/Y waveform (FSKx)
static void fcAll(uint8_t fc, int *n, uint8_t clock, int16_t *remainder) {
    uint8_t *dest = BigBuf_get_addr();
    uint8_t halfFC = fc >> 1;
    uint8_t wavesPerClock = (clock + *remainder) / fc;
    // loop through clock - step field clock
    for (uint8_t idx = 0; idx < wavesPerClock; idx++) {
        // put 1/2 FC length 1's and 1/2 0's per field clock wave (to create the wave)
        memset(dest + (*n), 0, fc - halfFC);  //in case of odd number use extra here
        memset(dest + (*n) + (fc - halfFC), 1, halfFC);
        *n += fc;
    }
    *remainder = (clock + *remainder) % fc;
    // if we've room for more than a half wave, add a full wave and use negative remainder
    if (*remainder > halfFC) {
        memset(dest + (*n), 0, fc - halfFC);  //in case of odd number use extra here
        memset(dest + (*n) + (fc - halfFC), 1, halfFC);
        *n += fc;
        *remainder -= fc;
    }
}

// prepare a waveform pattern in the buffer based on the ID given then
// simulate a HID tag until the button is pressed
void CmdHIDsimTAGEx(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT, bool ledcontrol, int numcycles) {

    /*
     HID tag bitstream format
     The tag contains a 44bit unique code. This is sent out MSB first in sets of 4 bits
     A 1 bit is represented as 6 fc8 and 5 fc10 patterns  (manchester 10) during 2 clock periods. (1bit = 1clock period)
     A 0 bit is represented as 5 fc10 and 6 fc8 patterns  (manchester 01)
     A fc8 is inserted before every 4 bits
     A special start of frame pattern is used consisting a0b0 where a and b are neither 0
     nor 1 bits, they are special patterns (a = set of 12 fc8 and b = set of 10 fc10)

     FSK2a
     bit 1 = fc10
     bit 0 = fc8
    */

    // special start of frame marker containing invalid Manchester bit sequences
    uint8_t bits[8 + 8 * 2 + 84 * 2] = { 0, 0, 0, 1, 1, 1, 0, 1 };
    uint8_t bitlen = 0;
    uint16_t n = 8;

    if (longFMT) {
        // Ensure no more than 84 bits supplied
        if (hi2 > 0xFFFFF) {
            DbpString("Tags can only have 84 bits.");
            return;
        }
        bitlen = 8 + 8 * 2 + 84 * 2;
        hi2 |= 0x9E00000; // 9E: long format identifier
        manchesterEncodeUint32(hi2, 16 + 12, bits, &n);
        manchesterEncodeUint32(hi, 32, bits, &n);
        manchesterEncodeUint32(lo, 32, bits, &n);
    } else {

        if (hi > 0xFFF) {
            DbpString("[!] tags can only have 44 bits. - USE lf simfsk for larger tags");
            return;
        }
        bitlen = 8 + 44 * 2;
        manchesterEncodeUint32(hi, 12, bits, &n);
        manchesterEncodeUint32(lo, 32, bits, &n);
    }
    CmdFSKsimTAGEx(10, 8, 0, 50, bitlen, bits, ledcontrol, numcycles);
}

void CmdHIDsimTAG(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT, bool ledcontrol) {
    CmdHIDsimTAGEx(hi2, hi, lo, longFMT, ledcontrol, -1);
    reply_ng(CMD_LF_HID_SIMULATE, PM3_EOPABORTED, NULL, 0);
}

// prepare a waveform pattern in the buffer based on the ID given then
// simulate a FSK tag until the button is pressed
// arg1 contains fcHigh and fcLow, arg2 contains STT marker and clock
void CmdFSKsimTAGEx(uint8_t fchigh, uint8_t fclow, uint8_t separator, uint8_t clk, uint16_t bitslen, uint8_t *bits, bool ledcontrol, int numcycles) {

    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // free eventually allocated BigBuf memory
    BigBuf_free();
    BigBuf_Clear_ext(false);
    clear_trace();
    set_tracing(false);

    int n = 0, i = 0;
    int16_t remainder = 0;

    if (separator) {
        //int fsktype = ( fchigh == 8 && fclow == 5) ? 1 : 2;
        //fcSTT(&n);
    }
    for (i = 0; i < bitslen; i++) {
        if (bits[i])
            fcAll(fchigh, &n, clk, &remainder);
        else
            fcAll(fclow, &n, clk, &remainder);
    }

    WDT_HIT();

    Dbprintf("Simulating with fcHigh: %d, fcLow: %d, clk: %d, STT: %d, n: %d", fchigh, fclow, clk, separator, n);

    if (ledcontrol) LED_A_ON();
    SimulateTagLowFrequencyEx(n, 0, ledcontrol, numcycles);
    if (ledcontrol) LED_A_OFF();
}

// prepare a waveform pattern in the buffer based on the ID given then
// simulate a FSK tag until the button is pressed
// arg1 contains fcHigh and fcLow, arg2 contains STT marker and clock
void CmdFSKsimTAG(uint8_t fchigh, uint8_t fclow, uint8_t separator, uint8_t clk, uint16_t bitslen, uint8_t *bits, bool ledcontrol) {
    CmdFSKsimTAGEx(fchigh, fclow, separator, clk, bitslen, bits, ledcontrol, -1);
    reply_ng(CMD_LF_FSK_SIMULATE, PM3_EOPABORTED, NULL, 0);
}

// compose ask waveform for one bit(ASK)
static void askSimBit(uint8_t c, int *n, uint8_t clock, uint8_t manchester) {
    uint8_t *dest = BigBuf_get_addr();
    uint8_t halfClk = clock / 2;
    // c = current bit 1 or 0
    if (manchester == 1) {
        memset(dest + (*n), c, halfClk);
        memset(dest + (*n) + halfClk, c ^ 1, halfClk);
    } else {
        memset(dest + (*n), c, clock);
    }
    *n += clock;
}

static void biphaseSimBit(uint8_t c, int *n, uint8_t clock, uint8_t *phase) {
    uint8_t *dest = BigBuf_get_addr();
    uint8_t halfClk = clock / 2;
    if (c) {
        memset(dest + (*n), c ^ 1 ^ *phase, halfClk);
        memset(dest + (*n) + halfClk, c ^ *phase, halfClk);
    } else {
        memset(dest + (*n), c ^ *phase, clock);
        *phase ^= 1;
    }
    *n += clock;
}

static void stAskSimBit(int *n, uint8_t clock) {
    uint8_t *dest = BigBuf_get_addr();
    uint8_t halfClk = clock / 2;
    //ST = .5 high .5 low 1.5 high .5 low 1 high
    memset(dest + (*n), 1, halfClk);
    memset(dest + (*n) + halfClk, 0, halfClk);
    memset(dest + (*n) + clock, 1, clock + halfClk);
    memset(dest + (*n) + clock * 2 + halfClk, 0, halfClk);
    memset(dest + (*n) + clock * 3, 1, clock);
    *n += clock * 4;
}
static void leadingZeroAskSimBits(int *n, uint8_t clock) {
    uint8_t *dest = BigBuf_get_addr();
    memset(dest + (*n), 0, clock * 8);
    *n += clock * 8;
}
/*
static void leadingZeroBiphaseSimBits(int *n, uint8_t clock, uint8_t *phase) {
    uint8_t *dest = BigBuf_get_addr();
    for (uint8_t i = 0; i < 8; i++) {
        memset(dest + (*n), 0 ^ *phase, clock);
        *phase ^= 1;
        *n += clock;
    }
}
*/


// args clock, ask/man or askraw, invert, transmission separator
void CmdASKsimTAG(uint8_t encoding, uint8_t invert, uint8_t separator, uint8_t clk, uint16_t size, uint8_t *bits, bool ledcontrol) {
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    set_tracing(false);

    int n = 0, i = 0;

    if (encoding == 2) { //biphase
        uint8_t phase = 0;

// iceman,  if I add this,  the demod includes these extra zero and detection fails.
// now, I only need to figure out just to add carrier without modulation
// the old bug, with adding ask zeros messed up the phase variable and deteion failed because of it in LF FDX
//        leadingZeroBiphaseSimBits(&n, clk, &phase);

        for (i = 0; i < size; i++) {
            biphaseSimBit(bits[i] ^ invert, &n, clk, &phase);
        }
        if (phase == 1) { //run a second set inverted to keep phase in check
            for (i = 0; i < size; i++) {
                biphaseSimBit(bits[i] ^ invert, &n, clk, &phase);
            }
        }
    } else {  // ask/manchester || ask/raw

        leadingZeroAskSimBits(&n, clk);

        for (i = 0; i < size; i++) {
            askSimBit(bits[i] ^ invert, &n, clk, encoding);
        }
        if (encoding == 0 && bits[0] == bits[size - 1]) { //run a second set inverted (for ask/raw || biphase phase)
            for (i = 0; i < size; i++) {
                askSimBit(bits[i] ^ invert ^ 1, &n, clk, encoding);
            }
        }
    }
    if (separator == 1 && encoding == 1)
        stAskSimBit(&n, clk);
    else if (separator == 1)
        Dbprintf("sorry but separator option not yet available");

    WDT_HIT();

    Dbprintf("Simulating with clk: %d, invert: %d, encoding: %s (%d), separator: %d, n: %d"
             , clk
             , invert
             , (encoding == 2) ? "BI" : (encoding == 1) ? "ASK" : "RAW"
             , encoding
             , separator
             , n
            );

    if (ledcontrol) LED_A_ON();
    SimulateTagLowFrequency(n, 0, ledcontrol);
    if (ledcontrol) LED_A_OFF();
    reply_ng(CMD_LF_ASK_SIMULATE, PM3_EOPABORTED, NULL, 0);
}

//carrier can be 2,4 or 8
static void pskSimBit(uint8_t waveLen, int *n, uint8_t clk, uint8_t *curPhase, bool phaseChg) {
    uint8_t *dest = BigBuf_get_addr();
    uint8_t halfWave = waveLen / 2;
    //uint8_t idx;
    int i = 0;
    if (phaseChg) {
        // write phase change
        memset(dest + (*n), *curPhase ^ 1, halfWave);
        memset(dest + (*n) + halfWave, *curPhase, halfWave);
        *n += waveLen;
        *curPhase ^= 1;
        i += waveLen;
    }
    //write each normal clock wave for the clock duration
    for (; i < clk; i += waveLen) {
        memset(dest + (*n), *curPhase, halfWave);
        memset(dest + (*n) + halfWave, *curPhase ^ 1, halfWave);
        *n += waveLen;
    }
}

// args clock, carrier, invert,
void CmdPSKsimTag(uint8_t carrier, uint8_t invert, uint8_t clk, uint16_t size, uint8_t *bits, bool ledcontrol) {
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    set_tracing(false);

    int n = 0, i = 0;
    uint8_t curPhase = 0;
    for (i = 0; i < size; i++) {
        if (bits[i] == curPhase) {
            pskSimBit(carrier, &n, clk, &curPhase, false);
        } else {
            pskSimBit(carrier, &n, clk, &curPhase, true);
        }
    }

    WDT_HIT();

    Dbprintf("Simulating with Carrier: %d, clk: %d, invert: %d, n: %d", carrier, clk, invert, n);

    if (ledcontrol) LED_A_ON();
    SimulateTagLowFrequency(n, 0, ledcontrol);
    if (ledcontrol) LED_A_OFF();
    reply_ng(CMD_LF_PSK_SIMULATE, PM3_EOPABORTED, NULL, 0);
}

// loop to get raw HID waveform then FSK demodulate the TAG ID from it
void CmdHIDdemodFSK(int findone, uint32_t *high, uint32_t *low, int ledcontrol) {
    uint8_t *dest = BigBuf_get_addr();
    size_t size;
    uint32_t hi2 = 0, hi = 0, lo = 0;
    int dummyIdx = 0;
    // Configure to go in 125kHz listen mode
    LFSetupFPGAForADC(LF_DIVISOR_125, true);

    //clear read buffer
    BigBuf_Clear_keep_EM();

    while (!BUTTON_PRESS() && !data_available()) {

        WDT_HIT();
        if (ledcontrol) LED_A_ON();

        DoAcquisition_default(-1, true);
        // FSK demodulator
        size = 50 * 128 * 2; //big enough to catch 2 sequences of largest format
        int idx = HIDdemodFSK(dest, &size, &hi2, &hi, &lo, &dummyIdx);
        if (idx < 0) continue;

        if (idx > 0 && lo > 0 && (size == 96 || size == 192)) {
            // go over previously decoded manchester data and decode into usable tag ID
            if (hi2 != 0) { //extra large HID tags  88/192 bits
                Dbprintf("TAG ID: %x%08x%08x (%d)",
                         hi2,
                         hi,
                         lo,
                         (lo >> 1) & 0xFFFF
                        );
            } else {  //standard HID tags 44/96 bits
                uint8_t bitlen = 0;
                uint32_t fac = 0;
                uint32_t cardnum = 0;

                if (((hi >> 5) & 1) == 1) { //if bit 38 is set then < 37 bit format is used
                    uint32_t lo2 = 0;
                    lo2 = (((hi & 31) << 12) | (lo >> 20)); //get bits 21-37 to check for format len bit
                    uint8_t idx3 = 1;
                    while (lo2 > 1) { //find last bit set to 1 (format len bit)
                        lo2 >>= 1;
                        idx3++;
                    }
                    bitlen = idx3 + 19;
                    fac = 0;
                    cardnum = 0;
                    if (bitlen == 26) {
                        cardnum = (lo >> 1) & 0xFFFF;
                        fac = (lo >> 17) & 0xFF;
                    }
                    if (bitlen == 37) {
                        cardnum = (lo >> 1) & 0x7FFFF;
                        fac = ((hi & 0xF) << 12) | (lo >> 20);
                    }
                    if (bitlen == 34) {
                        cardnum = (lo >> 1) & 0xFFFF;
                        fac = ((hi & 1) << 15) | (lo >> 17);
                    }
                    if (bitlen == 35) {
                        cardnum = (lo >> 1) & 0xFFFFF;
                        fac = ((hi & 1) << 11) | (lo >> 21);
                    }
                } else { //if bit 38 is not set then 37 bit format is used
                    bitlen = 37;
                    cardnum = (lo >> 1) & 0x7FFFF;
                    fac = ((hi & 0xF) << 12) | (lo >> 20);
                }
                Dbprintf("TAG ID: %x%08x (%d) - Format Len: %dbit - FC: %d - Card: %d",
                         hi,
                         lo,
                         (lo >> 1) & 0xFFFF,
                         bitlen,
                         fac,
                         cardnum
                        );
            }
            if (findone) {
                *high = hi;
                *low = lo;
                break;
            }
            // reset
        }
        hi2 = hi = lo = idx = 0;
    }
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    DbpString("HID fsk demod stopped");
    if (ledcontrol) LED_A_OFF();
}

// loop to get raw HID waveform then FSK demodulate the TAG ID from it
void CmdAWIDdemodFSK(int findone, uint32_t *high, uint32_t *low, int ledcontrol) {

    uint8_t *dest = BigBuf_get_addr();

    //big enough to catch 2 sequences of largest format but don't exeed whats available in bigbuff.
    size_t size = MIN(12800, BigBuf_max_traceLen()); //50 * 128 * 2;

    int dummyIdx = 0;

    BigBuf_Clear_keep_EM();

    LFSetupFPGAForADC(LF_DIVISOR_125, true);

    while (!BUTTON_PRESS() && !data_available()) {

        WDT_HIT();
        if (ledcontrol) LED_A_ON();

        DoAcquisition_default(-1, true);
        // FSK demodulator

        size  = BigBuf_max_traceLen();
        //askdemod and manchester decode
        if (size > 12800) size = 12800; //big enough to catch 2 sequences of largest format

        int idx = detectAWID(dest, &size, &dummyIdx);

        if (idx <= 0 || size != 96) continue;
        // Index map
        // 0            10            20            30              40            50              60
        // |            |             |             |               |             |               |
        // 01234567 890 1 234 5 678 9 012 3 456 7 890 1 234 5 678 9 012 3 456 7 890 1 234 5 678 9 012 3 - to 96
        // -----------------------------------------------------------------------------
        // 00000001 000 1 110 1 101 1 011 1 101 1 010 0 000 1 000 1 010 0 001 0 110 1 100 0 000 1 000 1
        // premable bbb o bbb o bbw o fff o fff o ffc o ccc o ccc o ccc o ccc o ccc o wxx o xxx o xxx o - to 96
        //          |---26 bit---|    |-----117----||-------------142-------------|
        // b = format bit len, o = odd parity of last 3 bits
        // f = facility code, c = card number
        // w = wiegand parity
        // (26 bit format shown)

        //get raw ID before removing parities
        uint32_t rawLo = bytebits_to_byte(dest + idx + 64, 32);
        uint32_t rawHi = bytebits_to_byte(dest + idx + 32, 32);
        uint32_t rawHi2 = bytebits_to_byte(dest + idx, 32);

        size = removeParity(dest, idx + 8, 4, 1, 88);
        if (size != 66) continue;
        // ok valid card found!

        // Index map
        // 0           10         20        30          40        50        60
        // |           |          |         |           |         |         |
        // 01234567 8 90123456 7890123456789012 3 456789012345678901234567890123456
        // -----------------------------------------------------------------------------
        // 00011010 1 01110101 0000000010001110 1 000000000000000000000000000000000
        // bbbbbbbb w ffffffff cccccccccccccccc w xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        // |26 bit|   |-117--| |-----142------|
        // b = format bit len, o = odd parity of last 3 bits
        // f = facility code, c = card number
        // w = wiegand parity
        // (26 bit format shown)

        uint8_t fmtLen = bytebits_to_byte(dest, 8);
        if (fmtLen == 26) {
            uint32_t fac = bytebits_to_byte(dest + 9, 8);
            uint32_t cardnum = bytebits_to_byte(dest + 17, 16);
            uint32_t code1 = bytebits_to_byte(dest + 8, fmtLen);
            Dbprintf("AWID Found - BitLength: %d, FC: %d, Card: %d - Wiegand: %x, Raw: %08x%08x%08x", fmtLen, fac, cardnum, code1, rawHi2, rawHi, rawLo);
        } else {
            uint32_t cardnum = bytebits_to_byte(dest + 8 + (fmtLen - 17), 16);
            if (fmtLen > 32) {
                uint32_t code1 = bytebits_to_byte(dest + 8, fmtLen - 32);
                uint32_t code2 = bytebits_to_byte(dest + 8 + (fmtLen - 32), 32);
                Dbprintf("AWID Found - BitLength: %d -unknown BitLength- (%d) - Wiegand: %x%08x, Raw: %08x%08x%08x", fmtLen, cardnum, code1, code2, rawHi2, rawHi, rawLo);
            } else {
                uint32_t code1 = bytebits_to_byte(dest + 8, fmtLen);
                Dbprintf("AWID Found - BitLength: %d -unknown BitLength- (%d) - Wiegand: %x, Raw: %08x%08x%08x", fmtLen, cardnum, code1, rawHi2, rawHi, rawLo);
            }
        }
        if (findone) {
            if (ledcontrol) LED_A_OFF();
            *high = rawHi;
            *low = rawLo;
            break;
        }
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    DbpString("AWID fsk demod stopped");
    if (ledcontrol) LED_A_OFF();
}

void CmdEM410xdemod(int findone, uint32_t *high, uint64_t *low, int ledcontrol) {
    uint8_t *dest = BigBuf_get_addr();

    size_t size, idx = 0;
    int clk = 0, invert = 0, maxErr = 20;
    uint32_t hi = 0;
    uint64_t lo = 0;

    BigBuf_Clear_keep_EM();

    LFSetupFPGAForADC(LF_DIVISOR_125, true);

    while (!BUTTON_PRESS() && !data_available()) {

        WDT_HIT();
        if (ledcontrol) LED_A_ON();

        DoAcquisition_default(-1, true);

        size  = BigBuf_max_traceLen();
        //askdemod and manchester decode
        if (size > 16385) size = 16385; //big enough to catch 2 sequences of largest format
        int errCnt = askdemod(dest, &size, &clk, &invert, maxErr, 0, 1);
        WDT_HIT();

        if (errCnt > 50) continue;

        errCnt = Em410xDecode(dest, &size, &idx, &hi, &lo);
        if (errCnt == 1) {
            if (size == 128) {
                Dbprintf("EM XL TAG ID: %06x%08x%08x - (%05d_%03d_%08d)",
                         hi,
                         (uint32_t)(lo >> 32),
                         (uint32_t)lo,
                         (uint32_t)(lo & 0xFFFF),
                         (uint32_t)((lo >> 16LL) & 0xFF),
                         (uint32_t)(lo & 0xFFFFFF));
            } else {
                Dbprintf("EM TAG ID: %02x%08x - (%05d_%03d_%08d)",
                         (uint32_t)(lo >> 32),
                         (uint32_t)lo,
                         (uint32_t)(lo & 0xFFFF),
                         (uint32_t)((lo >> 16LL) & 0xFF),
                         (uint32_t)(lo & 0xFFFFFF));
            }

            if (findone) {
                if (ledcontrol) LED_A_OFF();
                *high = hi;
                *low = lo;
                break;
            }
        }
        hi = lo = size = idx = 0;
        clk = invert = 0;
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    DbpString("EM man/ask demod stopped");
    if (ledcontrol) LED_A_OFF();
}

void CmdIOdemodFSK(int findone, uint32_t *high, uint32_t *low, int ledcontrol) {

    uint8_t *dest = BigBuf_get_addr();

    int dummyIdx = 0;
    uint32_t code = 0, code2 = 0;
    uint8_t version = 0, facilitycode = 0, crc = 0;
    uint16_t number = 0, calccrc = 0;

    size_t size = BigBuf_max_traceLen();

    BigBuf_Clear_keep_EM();

    // Configure to go in 125kHz listen mode
    LFSetupFPGAForADC(LF_DIVISOR_125, true);

    while (!BUTTON_PRESS() && !data_available()) {
        WDT_HIT();
        if (ledcontrol) LED_A_ON();

        DoAcquisition_default(-1, true);

        //fskdemod and get start index
        size  = BigBuf_max_traceLen();
        //askdemod and manchester decode
        if (size > 12000) size = 12000; //big enough to catch 2 sequences of largest format

        int idx = detectIOProx(dest, &size, &dummyIdx);
        if (idx < 0) continue;
        //valid tag found

        //Index map
        //0           10          20          30          40          50          60
        //|           |           |           |           |           |           |
        //01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
        //-----------------------------------------------------------------------------
        //00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1 checksum 11
        //
        //Checksum:
        //00000000 0 11110000 1 11100000 1 00000001 1 00000011 1 10110110 1 01110101 11
        //preamble      F0         E0         01         03         B6         75
        // How to calc checksum,
        // http://www.proxmark.org/forum/viewtopic.php?id=364&p=6
        //   F0 + E0 + 01 + 03 + B6 = 28A
        //   28A & FF = 8A
        //   FF - 8A = 75
        // Checksum: 0x75
        //XSF(version)facility:codeone+codetwo
        //Handle the data
        // if(findone){ //only print binary if we are doing one
        // Dbprintf("%d%d%d%d%d%d%d%d %d",dest[idx],   dest[idx+1],   dest[idx+2],dest[idx+3],dest[idx+4],dest[idx+5],dest[idx+6],dest[idx+7],dest[idx+8]);
        // Dbprintf("%d%d%d%d%d%d%d%d %d",dest[idx+9], dest[idx+10],dest[idx+11],dest[idx+12],dest[idx+13],dest[idx+14],dest[idx+15],dest[idx+16],dest[idx+17]);
        // Dbprintf("%d%d%d%d%d%d%d%d %d",dest[idx+18],dest[idx+19],dest[idx+20],dest[idx+21],dest[idx+22],dest[idx+23],dest[idx+24],dest[idx+25],dest[idx+26]);
        // Dbprintf("%d%d%d%d%d%d%d%d %d",dest[idx+27],dest[idx+28],dest[idx+29],dest[idx+30],dest[idx+31],dest[idx+32],dest[idx+33],dest[idx+34],dest[idx+35]);
        // Dbprintf("%d%d%d%d%d%d%d%d %d",dest[idx+36],dest[idx+37],dest[idx+38],dest[idx+39],dest[idx+40],dest[idx+41],dest[idx+42],dest[idx+43],dest[idx+44]);
        // Dbprintf("%d%d%d%d%d%d%d%d %d",dest[idx+45],dest[idx+46],dest[idx+47],dest[idx+48],dest[idx+49],dest[idx+50],dest[idx+51],dest[idx+52],dest[idx+53]);
        // Dbprintf("%d%d%d%d%d%d%d%d %d%d",dest[idx+54],dest[idx+55],dest[idx+56],dest[idx+57],dest[idx+58],dest[idx+59],dest[idx+60],dest[idx+61],dest[idx+62],dest[idx+63]);
        // }
        code = bytebits_to_byte(dest + idx, 32);
        code2 = bytebits_to_byte(dest + idx + 32, 32);
        version = bytebits_to_byte(dest + idx + 27, 8); //14,4
        facilitycode = bytebits_to_byte(dest + idx + 18, 8);
        number = (bytebits_to_byte(dest + idx + 36, 8) << 8) | (bytebits_to_byte(dest + idx + 45, 8)); //36,9

        crc = bytebits_to_byte(dest + idx + 54, 8);
        for (uint8_t i = 1; i < 6; ++i)
            calccrc += bytebits_to_byte(dest + idx + 9 * i, 8);
        calccrc &= 0xff;
        calccrc = 0xff - calccrc;

        char *crcStr = (crc == calccrc) ? "ok" : "!crc";

        Dbprintf("IO Prox XSF(%02d)%02x:%05d (%08x%08x)  [%02x %s]", version, facilitycode, number, code, code2, crc, crcStr);
        // if we're only looking for one tag
        if (findone) {
            if (ledcontrol) LED_A_OFF();
            *high = code;
            *low = code2;
            break;
        }
        code = code2 = 0;
        version = facilitycode = 0;
        number = 0;
        calccrc = 0;
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    DbpString("IOProx fsk demod stopped");
    if (ledcontrol) LED_A_OFF();
}

/*------------------------------
 * T5555/T5557/T5567/T5577 routines
 *------------------------------
 * NOTE: T55x7/T5555 configuration register definitions moved to protocols.h
 *
 * Relevant communication times in microsecond
 * To compensate antenna falling times shorten the write times
 * and enlarge the gap ones.
 * Q5 tags seems to have issues when these values changes.
 */

void TurnReadLFOn(uint32_t delay) {
    FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD);

    // measure antenna strength.
    //int adcval = ((MAX_ADC_LF_VOLTAGE * AvgAdc(ADC_CHAN_LF)) >> 10);
    WaitUS(delay);
}
void TurnReadLF_off(uint32_t delay) {
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    WaitUS(delay);
}

// Macro for code readability
#define BITSTREAM_BYTE(x) ((x) >> 3)   // iceman note:  isn't this NIBBLE???
#define BITSTREAM_BIT(x)  ((x) &  7)

#define T55_LLR_REF       (136 * 8)

// Write one bit to chip
void T55xxWriteBit(uint8_t bit, uint8_t downlink_idx) {

    switch (bit) {
        case 0 :
            // send bit 0/00
            TurnReadLFOn(T55xx_Timing.m[downlink_idx].write_0);
            break;
        case 1 :
            // send bit 1/01
            TurnReadLFOn(T55xx_Timing.m[downlink_idx].write_1);
            break;
        case 2 :
            // send bits 10 (1 of 4)
            TurnReadLFOn(T55xx_Timing.m[downlink_idx].write_2);
            break;
        case 3 :
            // send bits 11 (1 of 4)
            TurnReadLFOn(T55xx_Timing.m[downlink_idx].write_3);
            break;
        case 4 :
            // send Long Leading Reference
            TurnReadLFOn(T55xx_Timing.m[downlink_idx].write_0 + T55_LLR_REF);
            break;
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    WaitUS(T55xx_Timing.m[downlink_idx].write_gap);
}

// Function to abstract an Arbitrary length byte array to store bit pattern.
// bit_array    - Array to hold data/bit pattern
// start_offset - bit location to start storing new bits.
// data         - upto 32 bits of data to store
// num_bits     - how many bits (low x bits of data)  Max 32 bits at a time
// max_len      - how many bytes can the bit_array hold (ensure no buffer overflow)
// returns "Next" bit offset / bits stored (for next store)
uint8_t T55xx_SetBits(uint8_t *bs, uint8_t start_offset, uint32_t data, uint8_t num_bits, uint8_t max_len) {
    int8_t next_offset = start_offset;

    // Check if data will fit.
    if ((start_offset + num_bits) <= (max_len * 8)) {
        // Loop through the data and store
        for (int8_t offset = (num_bits - 1); offset >= 0; offset--) {

            if ((data >> offset) & 1)
                bs[BITSTREAM_BYTE(next_offset)] |= (1 << BITSTREAM_BIT(next_offset));  // Set 1
            else
                bs[BITSTREAM_BYTE(next_offset)] &= (0xff ^ (1 << BITSTREAM_BIT(next_offset))); // Set 0

            next_offset++;
        }
    } else {
        // Note: This should never happen unless some code changes cause it.
        // So short message for coders when testing.
        Dbprintf(_RED_("T55 too many bits"));
    }
    return next_offset;
}

// Send one downlink command to the card
void T55xx_SendCMD(uint32_t data, uint32_t pwd, uint16_t arg) {

    /*
    arg bits
    xxxx xxxxxxx1 0x001 password mode (Y/N)
    xxxx xxxxxx1x 0x002 page  (0|1)
    xxxx xxxxx1xx 0x004 test mode  (Y/N)
    xxxx xxx11xxx 0x018 selected downlink mode  (0|1|2|3|)
    xxxx xx1xxxxx 0x020 !reg_readmode  (ICEMAN ?? Why use negative in the bool ??)
    xxxx x1xxxxxx 0x040 called for a read, so no data packet  (Y/N)
    xxxx 1xxxxxxx 0x080 reset (Y/N)
    xxx1 xxxxxxxx 0x100 brute force (Y/N)
    111x xxxxxxxx 0xE00 block to write (0-7)
    */
    bool t55_send_pwdmode     = (arg & 0x1);
    bool t55_send_page        = ((arg >> 1) & 0x1);
    bool t55_send_testmode    = ((arg >> 2) & 0x1);
    bool t55_send_regreadmode = ((arg >> 5) & 0x1);
    bool t55_send_readcmd     = ((arg >> 6) & 0x1);
    bool t55_send_reset       = ((arg >> 7) & 0x1);
    bool t55_brute_mem        = ((arg >> 8) & 0x1);

    uint8_t downlink_mode     = (arg >> 3) & 0x03;
    uint8_t block_no          = (arg >> 9) & 0x07;

    // no startup delay when in bruteforce command
    uint8_t start_wait = (t55_brute_mem) ? 0 : 4;

    // Max Downlink Command size ~74 bits, so 10 bytes (80 bits)
    uint8_t bs[10];
    memset(bs, 0x00, sizeof(bs));

    uint8_t len = 0;

    // build bit stream to send.

    // add Leading 0
    if (downlink_mode == T55XX_DLMODE_LEADING_ZERO)
        len = T55xx_SetBits(bs, len, 0, 1, sizeof(bs));

    // add 1 of 4 reference bit
    if (downlink_mode == T55XX_DLMODE_1OF4) {
        len = T55xx_SetBits(bs, len, 0, 1, sizeof(bs));
        // add extra zero
        len = T55xx_SetBits(bs, len, 0, 1, sizeof(bs));
    }

    // add Opcode
    if (t55_send_reset) {
        //  reset : r*) 00
        len = T55xx_SetBits(bs, len, 0, 2, sizeof(bs));
    } else {

        if (t55_send_testmode)
            Dbprintf(_YELLOW_("Using Test Mode"));

        len = T55xx_SetBits(bs, len, t55_send_testmode ? 0 : 1, 1, sizeof(bs));

        len = T55xx_SetBits(bs, len, t55_send_testmode ? 1 : t55_send_page, 1, sizeof(bs));

        if (t55_send_pwdmode) {
            // Leading 0 and 1 of 4 00 fixed bits if passsword used
            if ((downlink_mode == T55XX_DLMODE_LEADING_ZERO) || (downlink_mode == T55XX_DLMODE_1OF4)) {
                len = T55xx_SetBits(bs, len, 0, 2, sizeof(bs));
            }
            len = T55xx_SetBits(bs, len, pwd, 32, sizeof(bs));
        }

        // Add Lock bit 0
        if (t55_send_regreadmode == false)
            len = T55xx_SetBits(bs, len, 0, 1, sizeof(bs));

        // Add Data if a write command
        if (t55_send_readcmd == false)
            len = T55xx_SetBits(bs, len, data, 32, sizeof(bs));

        // Add Address
        if (t55_send_regreadmode == false)
            len = T55xx_SetBits(bs, len, block_no, 3, sizeof(bs));
    }

    // Send Bits to T55xx
    // Set up FPGA, 125kHz
    LFSetupFPGAForADC(LF_DIVISOR_125, true);

    // make sure tag is fully powered up...
    WaitMS(start_wait);

    // Trigger T55x7 in mode.
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    WaitUS(T55xx_Timing.m[downlink_mode].start_gap);

    // If long leading 0 send long reference pulse
    if (downlink_mode == T55XX_DLMODE_LLR)
        T55xxWriteBit(T55XX_LONGLEADINGREFERENCE, downlink_mode);//Timing); // Send Long Leading Start Reference

    uint8_t sendbits;
    if ((downlink_mode == T55XX_DLMODE_1OF4) && (len > 0)) { // 1 of 4 need to send 2 bits at a time
        for (uint8_t i = 0; i < len - 1; i += 2) {
            sendbits  = (bs[BITSTREAM_BYTE(i)] >> (BITSTREAM_BIT(i)) & 1) << 1;       // Bit i
            sendbits += (bs[BITSTREAM_BYTE(i + 1)] >> (BITSTREAM_BIT(i + 1)) & 1);    // Bit i+1;
            T55xxWriteBit(sendbits & 3, downlink_mode);
        }
    } else {
        for (uint8_t i = 0; i < len; i++) {
            sendbits = (bs[BITSTREAM_BYTE(i)] >> BITSTREAM_BIT(i));
            T55xxWriteBit(sendbits & 1, downlink_mode);
        }
    }
}

// Send T5577 reset command then read stream (see if we can identify the start of the stream)
void T55xxResetRead(uint8_t flags) {

    uint8_t downlink_mode = ((flags >> 3) & 3);
    uint8_t arg           = 0x80 | downlink_mode;

    LED_A_ON();

    //clear buffer now so it does not interfere with timing later
    BigBuf_Clear_keep_EM();

    T55xx_SendCMD(0, 0, arg);

    TurnReadLFOn(T55xx_Timing.m[downlink_mode].read_gap);

    // Acquisition
    DoPartialAcquisition(0, true, BigBuf_max_traceLen(), 0);

    // Turn the field off
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    reply_ng(CMD_LF_T55XX_RESET_READ, PM3_SUCCESS, NULL, 0);
    LED_A_OFF();
}

void T55xxDangerousRawTest(uint8_t *data) {
    // supports only default downlink mode
    t55xx_test_block_t *c = (t55xx_test_block_t *)data;

    uint8_t start_wait = 4;
    uint8_t bs[128 / 8];
    memset(bs, 0x00, sizeof(bs));
    uint8_t len = 0;
    if (c->bitlen == 0 || c->bitlen > 128 || c->time == 0)
        reply_ng(CMD_LF_T55XX_DANGERRAW, PM3_EINVARG, NULL, 0);
    for (uint8_t i = 0; i < c->bitlen; i++)
        len = T55xx_SetBits(bs, len, c->data[i], 1, sizeof(bs));

    if (DBGLEVEL > 1) {
        Dbprintf("LEN %i, TIMING %i", len, c->time);
        for (uint8_t i = 0; i < len; i++) {
            uint8_t sendbits = (bs[BITSTREAM_BYTE(i)] >> BITSTREAM_BIT(i));
            Dbprintf("%02i: %i", i, sendbits & 1);
        }
    }

    LED_A_ON();
    LFSetupFPGAForADC(LF_DIVISOR_125, true);
    // make sure tag is fully powered up...
    WaitMS(start_wait);
    // Trigger T55x7 in mode.
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    WaitUS(T55xx_Timing.m[0].start_gap);
    uint8_t sendbits;
    for (uint8_t i = 0; i < len; i++) {
        sendbits = (bs[BITSTREAM_BYTE(i)] >> BITSTREAM_BIT(i));
        T55xxWriteBit(sendbits & 1, 0);
    }
    TurnReadLFOn(c->time);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    reply_ng(CMD_LF_T55XX_DANGERRAW, PM3_SUCCESS, NULL, 0);
    LED_A_OFF();
}

// Write one card block in page 0, no lock
//void T55xxWriteBlockExt(uint32_t data, uint8_t blockno, uint32_t pwd, uint8_t flags) {
void T55xxWriteBlock(uint8_t *data) {

    /*
    flag bits
    xxxxxxx1 0x01 PwdMode
    xxxxxx1x 0x02 Page
    xxxxx1xx 0x04 testMode
    xxx11xxx 0x18 downlink mode
    xx1xxxxx 0x20 !reg_readmode
    x1xxxxxx 0x40 called for a read, so no data packet
    1xxxxxxx 0x80 reset
    */

    t55xx_write_block_t *c = (t55xx_write_block_t *)data;
    // c->data, c->blockno, c->pwd, c->flags

    bool testMode = ((c->flags & 0x04) == 0x04);

    c->flags &= (0xff ^ 0x40); // Called for a write, so ensure it is clear/0

    LED_A_ON();
    T55xx_SendCMD(c->data, c->pwd, c->flags | (c->blockno << 9));

    // Perform write (nominal is 5.6 ms for T55x7 and 18ms for E5550,
    // so wait a little more)

    // "there is a clock delay before programming"
    //  - programming takes ~5.6ms for t5577 ~18ms for E5550 or t5567
    //  so we should wait 1 clock + 5.6ms then read response?
    //  but we need to know we are dealing with t5577 vs t5567 vs e5550 (or q5) marshmellow...
    if (testMode) {
        //TESTMODE TIMING TESTS:
        // <566us does nothing
        // 566-568 switches between wiping to 0s and doing nothing
        // 5184 wipes and allows 1 block to be programmed.
        // indefinite power on wipes and then programs all blocks with bitshifted data sent.
        TurnReadLFOn(5184);

    } else {
        TurnReadLFOn(20 * 1000);
        //could attempt to do a read to confirm write took
        // as the tag should repeat back the new block
        // until it is reset, but to confirm it we would
        // need to know the current block 0 config mode for
        // modulation clock an other details to demod the response...
        // response should be (for t55x7) a 0 bit then (ST if on)
        // block data written in on repeat until reset.

        //DoPartialAcquisition(20, true, 12000);
    }
    // turn field off
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    reply_ng(CMD_LF_T55XX_WRITEBL, PM3_SUCCESS, NULL, 0);
    LED_A_OFF();
}

/*
// uses NG format
void T55xxWriteBlock(uint8_t *data) {
    t55xx_write_block_t *c = (t55xx_write_block_t *)data;
    T55xxWriteBlockExt(c->data, c->blockno, c->pwd, c->flags);
    // reply_ng(CMD_LF_T55XX_WRITEBL, PM3_SUCCESS, NULL, 0);
}
*/
/*
// Read one card block in page [page]
void T55xxReadBlockExt(uint16_t flags, uint8_t block, uint32_t pwd) {
    / *
    flag bits
    xxxx xxxxxxx1 0x0001 PwdMode
    xxxx xxxxxx1x 0x0002 Page
    xxxx xxxxx1xx 0x0004 testMode
    xxxx xxx11xxx 0x0018 downlink mode
    xxxx xx1xxxxx 0x0020 !reg_readmode
    xxxx x1xxxxxx 0x0040 called for a read, so no data packet
    xxxx 1xxxxxxx 0x0080 reset
    xxx1 xxxxxxxx 0x0100 brute / leave field on
    * /
    size_t samples = 12000;
bool brute_mem = (flags & 0x0100) >> 8;

    LED_A_ON();

    if (brute_mem) samples = 1024;

    // Set Read Flag to ensure SendCMD does not add "data" to the packet
    flags |= 0x40;

    // RegRead Mode true block = 0xff, so read without an address
    if (block == 0xff) flags |= 0x20;

    //make sure block is at max 7
    block &= 0x7;

    //clear buffer now so it does not interfere with timing later
    BigBuf_Clear_keep_EM();

    T55xx_SendCMD(0,  pwd, flags | (block << 9));  //, true);

    // Turn field on to read the response
    // 137*8 seems to get to the start of data pretty well...
    //  but we want to go past the start and let the repeating data settle in...

    // TurnReadLFOn(210*8); // issues with block 1 reads so dropping down seemed to help
    TurnReadLFOn(137 * 8);

    // Acquisition
    // Now do the acquisition
    DoPartialAcquisition(0, true, samples, 0);

    // Turn the field off
    if (!brute_mem) {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        reply_ng(CMD_LF_T55XX_READBL, PM3_SUCCESS, NULL, 0);
        LED_A_OFF();
    }
}
*/
// Read one card block in page [page]
void T55xxReadBlock(uint8_t page, bool pwd_mode, bool brute_mem, uint8_t block, uint32_t pwd, uint8_t downlink_mode) {
    /*
    flag bits
    xxxx xxxxxxx1 0x0001 PwdMode
    xxxx xxxxxx1x 0x0002 Page
    xxxx xxxxx1xx 0x0004 testMode
    xxxx xxx11xxx 0x0018 downlink mode
    xxxx xx1xxxxx 0x0020 !reg_readmode
    xxxx x1xxxxxx 0x0040 called for a read, so no data packet
    xxxx 1xxxxxxx 0x0080 reset
    xxx1 xxxxxxxx 0x0100 brute / leave field on
    */
    uint16_t flags        = 0x0040; // read packet
    if (pwd_mode)  flags |= 0x0001;
    if (page)      flags |= 0x0002;
    flags                |= (downlink_mode & 3) << 3;
    if (brute_mem) flags |= 0x0100;

//    T55xxReadBlockExt (flags,block,pwd);
    size_t samples = 12000;
    // bool brute_mem = (flags & 0x0100) >> 8;

    LED_A_ON();

    if (brute_mem) samples = 1024;

    //-- Set Read Flag to ensure SendCMD does not add "data" to the packet
    //-- flags |= 0x40;

    // RegRead Mode true block = 0xff, so read without an address
    if (block == 0xff) flags |= 0x20;

    //make sure block is at max 7
    block &= 0x7;

    //clear buffer now so it does not interfere with timing later
    BigBuf_Clear_keep_EM();

    T55xx_SendCMD(0,  pwd, flags | (block << 9));  //, true);

    // Turn field on to read the response
    // 137*8 seems to get to the start of data pretty well...
    //  but we want to go past the start and let the repeating data settle in...

    // TurnReadLFOn(210*8); // issues with block 1 reads so dropping down seemed to help
    TurnReadLFOn(137 * 8);

    // Acquisition
    // Now do the acquisition
    DoPartialAcquisition(0, true, samples, 0);

    // Turn the field off
    if (!brute_mem) {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        reply_ng(CMD_LF_T55XX_READBL, PM3_SUCCESS, NULL, 0);
        LED_A_OFF();
    }

}

void T55xx_ChkPwds(uint8_t flags) {

    DbpString("[+] T55XX Check pwds using flashmemory starting");

    uint8_t ret = 0;
    // First get baseline and setup LF mode.
    // tends to mess up BigBuf
    uint8_t  *buf           = BigBuf_get_addr();
    uint32_t b1, baseline   = 0;
    uint8_t  downlink_mode  = (flags >> 3) & 0x03;

    // collect baseline for failed attempt
    uint8_t x = 32;
    while (x--) {
        b1 = 0;
        T55xxReadBlock(0, 0, true, 1, 0, downlink_mode);
        for (uint16_t j = 0; j < 1024; ++j)
            b1 += buf[j];

        b1 *= b1;
        b1 >>= 8;
        baseline += b1;
    }

    baseline >>= 5;
    Dbprintf("[=] Baseline determined [%u]", baseline);

    uint8_t *pwds = BigBuf_get_EM_addr();
    uint16_t pwdCount = 0;
    uint32_t candidate = 0;
#ifdef WITH_FLASH

    BigBuf_Clear_EM();
    uint16_t isok = 0;
    uint8_t counter[2] = {0x00, 0x00};
    isok = Flash_ReadData(DEFAULT_T55XX_KEYS_OFFSET, counter, sizeof(counter));
    if (isok != sizeof(counter))
        goto OUT;

    pwdCount = counter[1] << 8 | counter[0];

    if (pwdCount == 0 || pwdCount == 0xFFFF)
        goto OUT;

    isok = Flash_ReadData(DEFAULT_T55XX_KEYS_OFFSET + 2, pwds, pwdCount * 4);
    if (isok != pwdCount * 4)
        goto OUT;

    Dbprintf("[=] Password dictionary count %d ", pwdCount);
#endif

    uint32_t pwd = 0, curr = 0, prev = 0;
    for (uint16_t i = 0; i < pwdCount; ++i) {

        if (BUTTON_PRESS() && !data_available()) {
            goto OUT;
        }

        pwd = bytes_to_num(pwds + i * 4, 4);

        T55xxReadBlock(0, true, true, 0, pwd, downlink_mode);

        // calc mean of BigBuf 1024 samples.
        uint32_t sum = 0;
        for (uint16_t j = 0; j < 1024; ++j) {
            sum += buf[j];
        }

        sum *= sum;
        sum >>= 8;

        int32_t tmp = (sum - baseline);
        curr = ABS(tmp);

        Dbprintf("[=] Pwd %08X  | ABS %u", pwd, curr);

        if (curr > prev) {
            Dbprintf("[=]  --> ABS %u  Candidate %08X <--", curr, pwd);
            candidate = pwd;
            prev = curr;
        }
    }

    if (candidate)
        ret = 1;

OUT:
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    reply_mix(CMD_ACK, ret, candidate, 0, 0, 0);
    LEDsoff();
}

void T55xxWakeUp(uint32_t pwd, uint8_t flags) {

    flags |= 0x01 | 0x40 | 0x20; //Password | Read Call (no data) | reg_read no block
    LED_B_ON();

    T55xx_SendCMD(0, pwd, flags);

    //-- Turn and leave field on to let the begin repeating transmission
    TurnReadLFOn(20 * 1000);
    reply_ng(CMD_LF_T55XX_WAKEUP, PM3_SUCCESS, NULL, 0);
}


/*-------------- Cloning routines -----------*/
void WriteT55xx(uint32_t *blockdata, uint8_t startblock, uint8_t numblocks) {

    t55xx_write_block_t cmd;
    cmd.pwd     = 0;
    cmd.flags   = 0;

    for (uint8_t i = numblocks + startblock; i > startblock; i--) {
        cmd.data    = blockdata[i - 1];
        cmd.blockno = i - 1;
        T55xxWriteBlock((uint8_t *)&cmd);
    }

}

// Copy HID id to card and setup block 0 config
void CopyHIDtoT55x7(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT) {
    uint32_t data[] = {0, 0, 0, 0, 0, 0, 0};
    uint8_t last_block = 0;

    if (longFMT) {
        // Ensure no more than 84 bits supplied
        if (hi2 > 0xFFFFF) {
            DbpString("Tags can only have 84 bits.");
            return;
        }
        // Build the 6 data blocks for supplied 84bit ID
        last_block = 6;
        // load preamble (1D) & long format identifier (9E manchester encoded)
        data[1] = 0x1D96A900 | (manchesterEncode2Bytes((hi2 >> 16) & 0xF) & 0xFF);
        // load raw id from hi2, hi, lo to data blocks (manchester encoded)
        data[2] = manchesterEncode2Bytes(hi2 & 0xFFFF);
        data[3] = manchesterEncode2Bytes(hi >> 16);
        data[4] = manchesterEncode2Bytes(hi & 0xFFFF);
        data[5] = manchesterEncode2Bytes(lo >> 16);
        data[6] = manchesterEncode2Bytes(lo & 0xFFFF);
    } else {
        // Ensure no more than 44 bits supplied
        if (hi > 0xFFF) {
            DbpString("Tags can only have 44 bits.");
            return;
        }
        // Build the 3 data blocks for supplied 44bit ID
        last_block = 3;
        // load preamble
        data[1] = 0x1D000000 | (manchesterEncode2Bytes(hi) & 0xFFFFFF);
        data[2] = manchesterEncode2Bytes(lo >> 16);
        data[3] = manchesterEncode2Bytes(lo & 0xFFFF);
    }
    // load chip config block
    data[0] = T55x7_BITRATE_RF_50 | T55x7_MODULATION_FSK2a | last_block << T55x7_MAXBLOCK_SHIFT;

    //TODO add selection of chip for Q5 or T55x7
    // data[0] = T5555_SET_BITRATE(50) | T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | last_block << T5555_MAXBLOCK_SHIFT;

    LED_D_ON();
    WriteT55xx(data, 0, last_block + 1);
    LED_D_OFF();
}

// clone viking tag to T55xx
void CopyVikingtoT55xx(uint8_t *blocks, uint8_t Q5) {

    uint32_t data[] = {T55x7_BITRATE_RF_32 | T55x7_MODULATION_MANCHESTER | (2 << T55x7_MAXBLOCK_SHIFT), 0, 0};
    if (Q5)
        data[0] = T5555_SET_BITRATE(32) | T5555_MODULATION_MANCHESTER | 2 << T5555_MAXBLOCK_SHIFT;

    data[1] = bytes_to_num(blocks, 4);
    data[2] = bytes_to_num(blocks + 4, 4);

    // Program the data blocks for supplied ID and the block 0 config
    WriteT55xx(data, 0, 3);
    LED_D_OFF();
    reply_ng(CMD_LF_VIKING_CLONE, PM3_SUCCESS, NULL, 0);
}

// Define 9bit header for EM410x tags
#define EM410X_HEADER    0x1FF
#define EM410X_ID_LENGTH 40

void WriteEM410x(uint32_t card, uint32_t id_hi, uint32_t id_lo) {
    int i;
    uint64_t id = EM410X_HEADER;
    uint64_t rev_id = 0; // reversed ID
    int c_parity[4];     // column parity
    int r_parity = 0;    // row parity
    uint32_t clock = 0;

    // Reverse ID bits given as parameter (for simpler operations)
    for (i = 0; i < EM410X_ID_LENGTH; ++i) {
        if (i < 32) {
            rev_id = (rev_id << 1) | (id_lo & 1);
            id_lo >>= 1;
        } else {
            rev_id = (rev_id << 1) | (id_hi & 1);
            id_hi >>= 1;
        }
    }

    for (i = 0; i < EM410X_ID_LENGTH; ++i) {
        int id_bit = rev_id & 1;

        if (i % 4 == 0) {
            // Don't write row parity bit at start of parsing
            if (i)
                id = (id << 1) | r_parity;
            // Start counting parity for new row
            r_parity = id_bit;
        } else {
            // Count row parity
            r_parity ^= id_bit;
        }

        // First elements in column?
        if (i < 4)
            // Fill out first elements
            c_parity[i] = id_bit;
        else
            // Count column parity
            c_parity[i % 4] ^= id_bit;

        // Insert ID bit
        id = (id << 1) | id_bit;
        rev_id >>= 1;
    }

    // Insert parity bit of last row
    id = (id << 1) | r_parity;

    // Fill out column parity at the end of tag
    for (i = 0; i < 4; ++i)
        id = (id << 1) | c_parity[i];

    // Add stop bit
    id <<= 1;

    Dbprintf("Started writing %s tag ...", card ? "T55x7" : "T5555");
    LED_D_ON();

    // Write EM410x ID
    uint32_t data[] = {0, (uint32_t)(id >> 32), (uint32_t)(id & 0xFFFFFFFF)};

    clock = (card & 0xFF00) >> 8;
    clock = (clock == 0) ? 64 : clock;
    Dbprintf("Clock rate: %d", clock);
    if (card & 0xFF) { //t55x7
        clock = GetT55xxClockBit(clock);
        if (clock == 0) {
            Dbprintf("Invalid clock rate: %d", clock);
            return;
        }
        data[0] = clock | T55x7_MODULATION_MANCHESTER | (2 << T55x7_MAXBLOCK_SHIFT);
    } else { //t5555 (Q5)
        data[0] = T5555_SET_BITRATE(clock) | T5555_MODULATION_MANCHESTER | (2 << T5555_MAXBLOCK_SHIFT);
    }

    WriteT55xx(data, 0, 3);

    LED_D_OFF();
    Dbprintf("Tag %s written with 0x%08x%08x\n",
             card ? "T55x7" : "T5555",
             (uint32_t)(id >> 32),
             (uint32_t)id);
}

//-----------------------------------
// EM4469 / EM4305 routines
//-----------------------------------
// Below given command set.
// Commands are including the even parity, binary mirrored
#define FWD_CMD_LOGIN   0xC
#define FWD_CMD_WRITE   0xA
#define FWD_CMD_READ    0x9
#define FWD_CMD_DISABLE 0x5

uint8_t forwardLink_data[64]; //array of forwarded bits
uint8_t *forward_ptr;  //ptr for forward message preparation
uint8_t fwd_bit_sz; //forwardlink bit counter
uint8_t *fwd_write_ptr;  //forwardlink bit pointer

//====================================================================
// prepares command bits
// see EM4469 spec
//====================================================================
//--------------------------------------------------------------------
//  VALUES TAKEN FROM EM4x function: SendForward
//  START_GAP = 440;       (55*8) cycles at 125kHz (8us = 1cycle)
//  WRITE_GAP = 128;       (16*8)
//  WRITE_1   = 256 32*8;  (32*8)

//  These timings work for 4469/4269/4305 (with the 55*8 above)
//  WRITE_0 = 23*8 , 9*8

uint8_t Prepare_Cmd(uint8_t cmd) {

    *forward_ptr++ = 0; //start bit
    *forward_ptr++ = 0; //second pause for 4050 code

    *forward_ptr++ = cmd;
    cmd >>= 1;
    *forward_ptr++ = cmd;
    cmd >>= 1;
    *forward_ptr++ = cmd;
    cmd >>= 1;
    *forward_ptr++ = cmd;

    return 6; //return number of emited bits
}

//====================================================================
// prepares address bits
// see EM4469 spec
//====================================================================
uint8_t Prepare_Addr(uint8_t addr) {

    register uint8_t line_parity;

    uint8_t i;
    line_parity = 0;
    for (i = 0; i < 6; i++) {
        *forward_ptr++ = addr;
        line_parity ^= addr;
        addr >>= 1;
    }

    *forward_ptr++ = (line_parity & 1);

    return 7; //return number of emited bits
}

//====================================================================
// prepares data bits intreleaved with parity bits
// see EM4469 spec
//====================================================================
uint8_t Prepare_Data(uint16_t data_low, uint16_t data_hi) {

    register uint8_t column_parity;
    register uint8_t i, j;
    register uint16_t data;

    data = data_low;
    column_parity = 0;

    for (i = 0; i < 4; i++) {
        register uint8_t line_parity = 0;
        for (j = 0; j < 8; j++) {
            line_parity ^= data;
            column_parity ^= (data & 1) << j;
            *forward_ptr++ = data;
            data >>= 1;
        }
        *forward_ptr++ = line_parity;
        if (i == 1)
            data = data_hi;
    }

    for (j = 0; j < 8; j++) {
        *forward_ptr++ = column_parity;
        column_parity >>= 1;
    }
    *forward_ptr = 0;

    return 45; //return number of emited bits
}

//====================================================================
// Forward Link send function
// Requires: forwarLink_data filled with valid bits (1 bit per byte)
// fwd_bit_count set with number of bits to be sent
//====================================================================
void SendForward(uint8_t fwd_bit_count) {

// iceman,   21.3us increments for the USclock verification.
// 55FC * 8us == 440us / 21.3 === 20.65 steps.  could be too short. Go for 56FC instead
// 32FC * 8us == 256us / 21.3 ==  12.018 steps. ok
// 16FC * 8us == 128us / 21.3 ==  6.009 steps. ok
#ifndef EM_START_GAP
#define EM_START_GAP 55*8
#endif

    fwd_write_ptr = forwardLink_data;
    fwd_bit_sz = fwd_bit_count;

    // Set up FPGA, 125kHz or 95 divisor
    LFSetupFPGAForADC(LF_DIVISOR_125, true);

    // force 1st mod pulse (start gap must be longer for 4305)
    fwd_bit_sz--; //prepare next bit modulation
    fwd_write_ptr++;

    TurnReadLF_off(EM_START_GAP);
    TurnReadLFOn(18 * 8);

    // now start writting with bitbanging the antenna.
    while (fwd_bit_sz-- > 0) { //prepare next bit modulation
        if (((*fwd_write_ptr++) & 1) == 1) {
            WaitUS(32 * 8);
        } else {
            TurnReadLF_off(23 * 8);
            TurnReadLFOn(18 * 8);
        }
    }
}

void EM4xLogin(uint32_t pwd) {
    uint8_t len;
    forward_ptr = forwardLink_data;
    len = Prepare_Cmd(FWD_CMD_LOGIN);
    len += Prepare_Data(pwd & 0xFFFF, pwd >> 16);
    SendForward(len);
    //WaitUS(20); // no wait for login command.
    // should receive
    // 0000 1010 ok.
    // 0000 0001 fail
}

void EM4xReadWord(uint8_t addr, uint32_t pwd, uint8_t usepwd) {

    LED_A_ON();
    uint8_t len;

    //clear buffer now so it does not interfere with timing later
    BigBuf_Clear_ext(false);

    StartTicks();
    /* should we read answer from Logincommand?
    *
    * should receive
    * 0000 1010 ok.
    * 0000 0001 fail
    **/
    if (usepwd) EM4xLogin(pwd);

    forward_ptr = forwardLink_data;
    len = Prepare_Cmd(FWD_CMD_READ);
    len += Prepare_Addr(addr);

    SendForward(len);

    WaitUS(400);

    DoPartialAcquisition(20, true, 6000, 1000);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    reply_ng(CMD_LF_EM4X_READWORD, PM3_SUCCESS, NULL, 0);
    LED_A_OFF();
}

void EM4xWriteWord(uint8_t addr, uint32_t data, uint32_t pwd, uint8_t usepwd) {

    LED_A_ON();
    uint8_t len;

    //clear buffer now so it does not interfere with timing later
    BigBuf_Clear_ext(false);
    StartTicks();
    /* should we read answer from Logincommand?
    *
    * should receive
    * 0000 1010 ok.
    * 0000 0001 fail
    **/
    if (usepwd) EM4xLogin(pwd);

    forward_ptr = forwardLink_data;
    len = Prepare_Cmd(FWD_CMD_WRITE);
    len += Prepare_Addr(addr);
    len += Prepare_Data(data & 0xFFFF, data >> 16);

    SendForward(len);

    //Wait 20ms for write to complete?
    WaitMS(7);

    DoPartialAcquisition(20, true, 6000, 1000);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    reply_ng(CMD_LF_EM4X_WRITEWORD, PM3_SUCCESS, NULL, 0);
    LED_A_OFF();
}

/*
Reading COTAG.

COTAG needs the reader to send a startsequence and the card has an extreme slow datarate.
because of this, we can "sample" the data signal but we interpreate it to Manchester direct.

This behavior looks very similar to old ancient Motorola Flexpass

-----------------------------------------------------------------------
According to patent EP0040544B1:
Operating freq
  reader 132 kHz
  tag     66 kHz

Divide by 384 counter

PULSE repetition 5.82ms
LOW  2.91 ms
HIGH  2.91 ms

Also references to a half-bit format and leading zero.
-----------------------------------------------------------------------

READER START SEQUENCE:

burst 800 us  gap 2.2 ms
burst 3.6 ms  gap 2.2 ms
burst 800 us  gap 2.2 ms
pulse 3.6 ms

This triggers COTAG tag to response

*/
void Cotag(uint32_t arg0) {
#ifndef OFF
# define OFF(x)  { FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF); WaitUS((x)); }
#endif
#ifndef ON
# define ON(x)   { FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_ADC | FPGA_LF_ADC_READER_FIELD); WaitUS((x)); }
#endif
    uint8_t rawsignal = arg0 & 0xF;

    LED_A_ON();

    LFSetupFPGAForADC(LF_FREQ2DIV(132), true);

    //clear buffer now so it does not interfere with timing later
    BigBuf_Clear_ext(false);

    //send COTAG start pulse
    ON(740)  OFF(2035)
    ON(3330) OFF(2035)
    ON(740)  OFF(2035)
    ON(1000)

    switch (rawsignal) {
        case 0:
            doCotagAcquisition(40000);
            break;
        case 1:
            doCotagAcquisitionManchester();
            break;
        case 2:
            DoAcquisition_config(true, 0);
            break;
    }

    // Turn the field off
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF); // field off
    reply_ng(CMD_LF_COTAG_READ, PM3_SUCCESS, NULL, 0);
    LEDsoff();
}

/*
* EM4305 support
*/
