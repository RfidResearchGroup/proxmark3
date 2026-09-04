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
#ifndef __I2C_H
#define __I2C_H

#include "common.h"
#include "pm3_cmd.h"

#define I2C_DEVICE_ADDRESS_BOOT     0xB0
#define I2C_DEVICE_ADDRESS_MAIN     0xC0

#define I2C_DEVICE_CMD_GENERATE_ATR 0x01
#define I2C_DEVICE_CMD_SEND         0x02
#define I2C_DEVICE_CMD_READ         0x03
#define I2C_DEVICE_CMD_SETBAUD      0x04
#define I2C_DEVICE_CMD_SIM_CLC      0x05
#define I2C_DEVICE_CMD_GETVERSION   0x06
#define I2C_DEVICE_CMD_SEND_T0      0x07
// SIM module firmware v4.51 and up.  SEND_T1 takes a plain APDU and runs the
// whole T=1 block layer on the module - chaining, R block recovery, S(WTX),
// LRC/CRC - the same way SEND_T0 handles the T=0 procedure bytes.
#define I2C_DEVICE_CMD_SEND_T1      0x08
#define I2C_DEVICE_CMD_PPS          0x09
// SIM module firmware v4.65 and up.  A compatibility alias for T=0 in the
// current SIM_C build.  Grace response assembly remains PM3-side.
#define I2C_DEVICE_CMD_SEND_T0_AUTORESP 0x0A

// Disabled: live testing showed that opcode 0x0A itself is not reliable on the
// PM3<->SIM I2C path, even when the SIM handler is an exact SEND_T0 pass-through.
// Keep T=0 traffic on the established 0x07 transport until that low-level issue
// is understood.
#define SAM_T0_AUTORESP             0

// SIM module firmware versions this build knows about.
//
//   v4.42 - the stock firmware, T=0 only
//   v4.51 - adds SEND_T1 (0x08) and PPS (0x09)
//   v4.56 - T=0 reads to the expected length instead of an idle timeout
//   v4.57 - the ATR does too
#define SIM_MODULE_VERS_MIN_HI      4
#define SIM_MODULE_VERS_MIN_LO      57
#define SIM_MODULE_VERS_T1_HI       4
#define SIM_MODULE_VERS_T1_LO       51

// SAM secure-channel transport policy for the performance build.  Artemis
// offers T=0 first in its ATR; request its advertised T=1 service explicitly
// and use the validated Fi=512/Di=16 rate.  This is protocol selection only:
// it does not enable APDU dumps or other bring-up diagnostics.
#define SAM_SC_FORCE_T1_TA1_95      1
#define SAM_SC_T1_TA1               0x95

// The SIM module v4 supports up to 384 bytes for the length.
#define  ISO7816_MAX_FRAME 270

// Bit banged bus timing. 1CLK is spent twice per bit, 2CLK once, so the bit
// period is 2 * 1CLK + 2CLK, 62 us or about 16 kHz. Every timeout below derives
// from these, so they are the only two numbers to change.
//
// 5/7 (59 kHz) has been tried twice and is too fast: the link works for a while
// then corrupts, an ATR coming back with flipped bits and a mangled length
// header rather than not arriving at all. Anything below 20/22 wants a scope on
// SCL/SDA first.
#define I2C_DELAY_1CLK_US       20
#define I2C_DELAY_2CLK_US       22

// Only one delay per bit is rise time critical: the one bracketing an SDA
// transition, where a released line has to charge through the pull-up before
// it reads as a 1. Sampling before that is what corrupted the bus every time
// these were simply scaled down together. The others are padding - hold after
// SCL falls (spec 0.3 us) and SCL high width (spec 4 us) - so they get the
// standard mode minimum with margin instead of a full clock.
#define I2C_DELAY_SDA_US        15
#define I2C_DELAY_HOLD_US       2
#define I2C_DELAY_HIGH_US       6

// The SCL wait loops spend one 1CLK per iteration, so their timeouts are
// iteration counts. Written in ms and converted here so the two cannot drift.
#define I2C_ITERS_PER_MS        (1000U / I2C_DELAY_1CLK_US)
#define I2C_ITERS_FOR_MS(ms)    ((uint32_t)(ms) * (uint32_t)I2C_ITERS_PER_MS)

#define I2C_STRETCH_TIMEOUT_MS  100     // slave stretching SCL inside a transfer
#define I2C_WAIT_MAX_MS         60000   // clamp on a host supplied SC_WAIT

// Must cover the card's block waiting time: 1.4 s at BWI=4, 2.9 s at BWI=5.
#define SIM_WAIT_MS             3000
#define SIM_WAIT_DELAY          I2C_ITERS_FOR_MS(SIM_WAIT_MS)

// -std=c99, so no _Static_assert
#define I2C_BUILD_ASSERT(cond, name) typedef char i2c_assert_##name[(cond) ? 1 : -1]

I2C_BUILD_ASSERT((1000U % I2C_DELAY_1CLK_US) == 0, clk_divides_ms);
I2C_BUILD_ASSERT(SIM_WAIT_MS >= 3000, sim_wait_covers_bwt);
I2C_BUILD_ASSERT((uint64_t)I2C_WAIT_MAX_MS * I2C_ITERS_PER_MS <= 0xFFFFFFFFULL, wait_fits_u32);


void I2C_recovery(void);
void I2C_init(bool has_ticks);
void I2C_Reset(void); // TODO DXL: Not implemented but defined?
void I2C_SetResetStatus(uint8_t LineRST, uint8_t LineSCK, uint8_t LineSDA);

void I2C_Reset_EnterMainProgram(void);
void I2C_Reset_EnterBootloader(void);

bool I2C_WriteCmd(uint8_t device_cmd, uint8_t device_address);

bool I2C_WriteByte(uint8_t data, uint8_t device_cmd, uint8_t device_address);
bool I2C_BufferWrite(const uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);
int16_t I2C_BufferReadRaw(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);
int16_t I2C_BufferRead(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address);

// for firmware
int16_t I2C_ReadFW(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address);
bool I2C_WriteFW(const uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address);

// Which SIM module opcode a set of SC_RAW* flags asks for.
uint8_t sc_raw_device_cmd(smartcard_command_t flags);

// Which SIM module opcode matches the protocol the card is currently running,
// for callers that carry no SC_RAW* flags of their own. T=0 until a PPS says
// otherwise.
uint8_t sc_active_device_cmd(void);

// Request the configured T=1 profile for the next SAM-only GetATR().  The
// request is consumed once, so unrelated SmartCardRaw traffic still follows
// its own ATR/PPS policy.
void sc_request_sam_t1_profile(void);

// Log one smartcard frame, timestamped from the tick counter. Start is where
// the previous frame ended, so a Tag frame's span is how long the card took to
// answer and a Rdr frame's is how long the host took to ask.
void sc_log_trace(const uint8_t *d, uint16_t len, bool reader2tag);
void sc_log_trace_span(const uint8_t *d, uint16_t len, bool reader2tag, uint32_t start);
void sc_log_trace_reset(void);

bool sc_rx_bytes(uint8_t *dest, uint16_t *destlen, uint32_t wait);
//
bool GetATR(smart_card_atr_t *card_ptr, bool verbose);

// generice functions
void SmartCardAtr(void);
void SmartCardRaw(const smart_card_raw_t *p);
void SmartCardUpgrade(uint64_t arg0);
void SmartCardSetClock(uint64_t arg0);
void SmartCardPPS(const smart_card_pps_t *p);
void I2C_print_status(void);
int I2C_get_version(uint8_t *major, uint8_t *minor);

#endif
