//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions internal to the app source.
//-----------------------------------------------------------------------------
#ifndef __LFOPS_H
#define __LFOPS_H

#include "common.h"

#include "pm3_cmd.h" // struct

extern uint8_t decimation;
extern uint8_t bits_per_sample ;
extern bool averaging;

void AcquireRawAdcSamples125k(int divisor);
void ModThenAcquireRawAdcSamples125k(uint32_t delay_off, uint32_t period_0, uint32_t period_1, uint8_t *command);
void ReadTItag(void);
void WriteTItag(uint32_t idhi, uint32_t idlo, uint16_t crc);

void AcquireTiType(void);
void AcquireRawBitsTI(void);
void SimulateTagLowFrequencyEx(int period, int gap, bool ledcontrol, int numcycles);
void SimulateTagLowFrequency(int period, int gap, bool ledcontrol);
void SimulateTagLowFrequencyBidir(int divisor, int max_bitlen);

void CmdHIDsimTAGEx(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT, bool ledcontrol, int numcycles);
void CmdHIDsimTAG(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT, bool ledcontrol);

void CmdFSKsimTAGEx(uint8_t fchigh, uint8_t fclow, uint8_t separator, uint8_t clk, uint16_t bitslen, uint8_t *bits, bool ledcontrol, int numcycles);
void CmdFSKsimTAG(uint8_t fchigh, uint8_t fclow, uint8_t separator, uint8_t clk, uint16_t bitslen, uint8_t *bits, bool ledcontrol);
void CmdASKsimTAG(uint8_t encoding, uint8_t invert, uint8_t separator, uint8_t clk, uint16_t size, uint8_t *bits, bool ledcontrol);
void CmdPSKsimTAG(uint8_t carrier, uint8_t invert, uint8_t clk, uint16_t size, uint8_t *bits, bool ledcontrol);
void CmdNRZsimTAG(uint8_t invert, uint8_t separator, uint8_t clk, uint16_t size, uint8_t *bits, bool ledcontrol);

void CmdHIDdemodFSK(int findone, uint32_t *high, uint32_t *low, int ledcontrol);
void CmdAWIDdemodFSK(int findone, uint32_t *high, uint32_t *low, int ledcontrol); // Realtime demodulation mode for AWID26
void CmdEM410xdemod(int findone, uint32_t *high, uint64_t *low, int ledcontrol);
void CmdIOdemodFSK(int findone, uint32_t *high, uint32_t *low, int ledcontrol);
void CopyHIDtoT55x7(uint32_t hi2, uint32_t hi, uint32_t lo, uint8_t longFMT); // Clone an HID card to T5557/T5567
void CopyVikingtoT55xx(uint8_t *blocks, uint8_t Q5);
void WriteEM410x(uint32_t card, uint32_t id_hi, uint32_t id_lo);
void T55xxResetRead(uint8_t flags);
//id T55xxWriteBlock(uint32_t data, uint8_t blockno, uint32_t pwd, uint8_t flags);
void T55xxWriteBlock(uint8_t *data);
// void T55xxWriteBlockExt(uint32_t data, uint8_t blockno, uint32_t pwd, uint8_t flags);
void T55xxReadBlock(uint8_t page, bool pwd_mode, bool brute_mem, uint8_t block, uint32_t pwd, uint8_t downlink_mode);
void T55xxWakeUp(uint32_t pwd, uint8_t flags);
void T55xx_ChkPwds(uint8_t flags);
void T55xxDangerousRawTest(uint8_t *data);

void TurnReadLFOn(uint32_t delay);

void EM4xReadWord(uint8_t addr, uint32_t pwd, uint8_t usepwd);
void EM4xWriteWord(uint8_t addr, uint32_t data, uint32_t pwd, uint8_t usepwd);

void Cotag(uint32_t arg0);
void setT55xxConfig(uint8_t arg0, t55xx_configurations_t *c);
t55xx_configurations_t *getT55xxConfig(void);
void printT55xxConfig(void);
void loadT55xxConfig(void);

#endif
