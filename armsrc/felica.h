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
// Definitions internal to the FeliCa functionality
//-----------------------------------------------------------------------------
#ifndef __FELICA_H
#define __FELICA_H

#include "common.h"
#include "cmd.h"

// In the ISO18092/FeliCa FPGA bitstream, the SSC clock is the RF bit clock:
// fc/64 at 212 kbit/s and fc/32 at 424 kbit/s. Trace timestamps are stored
// in carrier periods, so convert at the logging boundary.
#define FELICA_BITS_PER_BYTE 8U
#define FELICA_212K_CARRIER_PERIODS_PER_BIT 64U
#define FELICA_424K_CARRIER_PERIODS_PER_BIT 32U
#define FELICA_212K_CARRIER_TO_TIMER_TICKS(x) (((x) + FELICA_212K_CARRIER_PERIODS_PER_BIT - 1U) / FELICA_212K_CARRIER_PERIODS_PER_BIT)

#ifndef DELAY_AIR2ARM_AS_READER
#define DELAY_AIR2ARM_AS_READER (3 + 16 + 8 + 8*16 + 4*16 - 8*16) // 91
#endif
#ifndef DELAY_ARM2AIR_AS_READER
#define DELAY_ARM2AIR_AS_READER (4*16 + 8*16 + 8 + 8 + 1) // 209
#endif

//structure to hold incoming NFC frame, used for ISO/IEC 18092-compatible frames
typedef struct {
    enum {
        STATE_UNSYNCD,
        STATE_TRYING_SYNC,
        STATE_GET_LENGTH,
        STATE_GET_DATA,
        STATE_GET_CRC,
        STATE_FULL
    } state;

    uint16_t  shiftReg; //for synchronization and offset calculation
    uint16_t  shiftRegInv; // sync search helper while polarity is unknown
    int       posCnt;
    bool      crc_ok;
    int       rem_len;
    uint16_t  len;
    uint8_t   byte_offset;
    uint8_t   polarity;
    uint32_t  startTime;
    uint32_t  endTime;
    uint8_t   *framebytes;
//should be enough. maxlen is 255, 254 for data, 2 for sync, 2 for crc
// 0,1 -> SYNC, 2 - len,  3-(len+1)->data, then crc
} felica_frame_t;

enum {
    FELICA_POLARITY_UNKNOWN = 0,
    FELICA_POLARITY_NORMAL = 1,
    FELICA_POLARITY_INVERTED = 2
};

extern uint32_t felica_nexttransfertime;
extern felica_frame_t FelicaFrame;

bool felica_field_is_active(void);
void FelicaFrameReset(felica_frame_t *f);
uint32_t felica_timer_to_carrier_periods(uint32_t timer_ticks, bool highspeed);
uint32_t felica_get_rx_byte_start_time(void);
void Process18092Byte(felica_frame_t *f, uint8_t bt, uint32_t byte_start_time);
void TransmitFor18092_AsReader(const uint8_t *frame, uint16_t len, const uint32_t *NYI_timing_NYI,
                               uint8_t power, uint8_t highspeed);
bool WaitForFelicaReply(uint16_t maxbytes);
void iso18092_setup(uint8_t fpga_minor_mode);
bool iso18092_setup_ex(uint8_t fpga_minor_mode, uint32_t preserve_low_bytes);
void felica_reset_frame_mode(void);
void TransmitFor18092_AsReaderEx(const uint8_t *frame, uint16_t len, const uint32_t *NYI_timing_NYI,
                                 uint8_t power, uint8_t highspeed, bool reader2tag);

void felica_sendraw(const PacketCommandNG *c);
void felica_sniff(uint32_t samplesToSkip, uint32_t triggersToSkip);
void felica_sim_lite(const uint8_t *uid);
void felica_dump_lite_s(void);

#endif
