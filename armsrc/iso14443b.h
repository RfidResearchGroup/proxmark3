//-----------------------------------------------------------------------------
// Merlok - June 2011
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type B.
//-----------------------------------------------------------------------------

#ifndef __ISO14443B_H
#define __ISO14443B_H

#include "common.h"

#include "mifare.h"
#include "pm3_cmd.h"

#ifndef AddCrc14A
# define AddCrc14A(data, len) compute_crc(CRC_14443_A, (data), (len), (data)+(len), (data)+(len)+1)
#endif

#ifndef AddCrc14B
# define AddCrc14B(data, len) compute_crc(CRC_14443_B, (data), (len), (data)+(len), (data)+(len)+1)
#endif

void iso14443b_setup(void);
uint8_t iso14443b_apdu(uint8_t const *message, size_t message_length, uint8_t *response);
uint8_t iso14443b_select_card(iso14b_card_select_t *card);
uint8_t iso14443b_select_card_srx(iso14b_card_select_t *card);

void SimulateIso14443bTag(uint32_t pupi);
void AcquireRawAdcSamplesIso14443b(uint32_t parameter);
void ReadSTMemoryIso14443b(uint8_t numofblocks);
void RAMFUNC SniffIso14443b(void);
void SendRawCommand14443B(uint32_t, uint32_t, uint8_t, uint8_t[]);
void SendRawCommand14443B_Ex(PacketCommandNG *c);

// testfunctions
void WaitForFpgaDelayQueueIsEmpty(uint16_t delay);
void ClearFpgaShiftingRegisters(void);

// States for 14B SIM command
#define SIM_NOFIELD     0
#define SIM_IDLE        1
#define SIM_HALTED      2
#define SIM_SELECTING   3
#define SIM_HALTING     4
#define SIM_ACKNOWLEDGE 5
#define SIM_WORK        6

#endif /* __ISO14443B_H */
