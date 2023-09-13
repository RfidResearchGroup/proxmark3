//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, 2005
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
#ifndef __LFOPS_H
#define __LFOPS_H

#include "common.h"

#include "pm3_cmd.h" // struct

void ModThenAcquireRawAdcSamples125k(uint32_t delay_off, uint16_t period_0, uint16_t period_1,
                                     const uint8_t *symbol_extra, uint16_t *period_extra, uint8_t *command, bool verbose,
                                     bool keep_field_on, uint32_t samples, bool ledcontrol);

void ReadTItag(bool ledcontrol);
void WriteTItag(uint32_t idhi, uint32_t idlo, uint16_t crc, bool ledcontrol);

void AcquireTiType(bool ledcontrol);
void AcquireRawBitsTI(void);
void SimulateTagLowFrequencyEx(int period, int gap, bool ledcontrol, int numcycles);
void SimulateTagLowFrequency(int period, int gap, bool ledcontrol);
void SimulateTagLowFrequencyBidir(int divisor, int max_bitlen);

void CmdHIDsimTAGEx(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT, bool ledcontrol, int numcycles);
void CmdHIDsimTAG(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT, bool ledcontrol);

void CmdFSKsimTAGEx(uint8_t fchigh, uint8_t fclow, uint8_t separator, uint8_t clk, uint16_t bitslen,
                    const uint8_t *bits, bool ledcontrol, int numcycles);
void CmdFSKsimTAG(uint8_t fchigh, uint8_t fclow, uint8_t separator, uint8_t clk, uint16_t bitslen,
                  const uint8_t *bits, bool ledcontrol);
void CmdASKsimTAG(uint8_t encoding, uint8_t invert, uint8_t separator, uint8_t clk, uint16_t size,
                  const uint8_t *bits, bool ledcontrol);
void CmdPSKsimTAG(uint8_t carrier, uint8_t invert, uint8_t clk, uint16_t size,
                  const uint8_t *bits, bool ledcontrol);
void CmdNRZsimTAG(uint8_t invert, uint8_t separator, uint8_t clk, uint16_t size,
                  const uint8_t *bits, bool ledcontrol);

int lf_hid_watch(int findone, uint32_t *high, uint32_t *low, bool ledcontrol);
int lf_awid_watch(int findone, uint32_t *high, uint32_t *low, bool ledcontrol); // Realtime demodulation mode for AWID26
int lf_em410x_watch(int findone, uint32_t *high, uint64_t *low, bool ledcontrol);
int lf_io_watch(int findone, uint32_t *high, uint32_t *low, bool ledcontrol);

void CopyHIDtoT55x7(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT, bool q5, bool em, bool ledcontrol); // Clone an HID card to T5557/T5567
void CopyVikingtoT55xx(const uint8_t *blocks, bool q5, bool em, bool ledcontrol);

int copy_em410x_to_t55xx(uint8_t card, uint8_t clock, uint32_t id_hi, uint32_t id_lo, bool ledcontrol);

void T55xxResetRead(uint8_t flags, bool ledcontrol);
//id T55xxWriteBlock(uint32_t data, uint8_t blockno, uint32_t pwd, uint8_t flags, bool ledcontrol);
void T55xxWriteBlock(uint8_t *data, bool ledcontrol);
// void T55xxWriteBlockExt(uint32_t data, uint8_t blockno, uint32_t pwd, uint8_t flags);
void T55xxReadBlock(uint8_t page, bool pwd_mode, bool brute_mem, uint8_t block, uint32_t pwd,
                    uint8_t downlink_mode, bool ledcontrol);
void T55xxWakeUp(uint32_t pwd, uint8_t flags, bool ledcontrol);
void T55xx_ChkPwds(uint8_t flags, bool ledcontrol);
void T55xxDangerousRawTest(const uint8_t *data, bool ledcontrol);

void turn_read_lf_on(uint32_t delay);
void turn_read_lf_off(uint32_t delay);

void EM4xLogin(uint32_t pwd, bool ledcontrol);
void EM4xBruteforce(uint32_t start_pwd, uint32_t n, bool ledcontrol);
void EM4xReadWord(uint8_t addr, uint32_t pwd, uint8_t usepwd, bool ledcontrol);
void EM4xWriteWord(uint8_t addr, uint32_t data, uint32_t pwd, uint8_t usepwd, bool ledcontrol);
void EM4xProtectWord(uint32_t data, uint32_t pwd, uint8_t usepwd, bool ledcontrol);

void Cotag(uint32_t arg0, bool ledcontrol);
void setT55xxConfig(uint8_t arg0, const t55xx_configurations_t *c);
t55xx_configurations_t *getT55xxConfig(void);
void printT55xxConfig(void);
void loadT55xxConfig(void);

#endif
