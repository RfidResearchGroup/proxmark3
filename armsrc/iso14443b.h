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

#ifdef __cplusplus
extern "C" {
#endif

#include "proxmark3.h"
#include "common.h"  // access to global variable: MF_DBGLEVEL
#include "apps.h"
#include "util.h"
#include "string.h"
#include "crc16.h"
#include "mifare.h"
#include "protocols.h"

#ifndef AddCrc14A
# define AddCrc14A(data, len) compute_crc(CRC_14443_A, (data), (len), (data)+(len), (data)+(len)+1)
#endif

#ifndef AddCrc14B
# define AddCrc14B(data, len) compute_crc(CRC_14443_B, (data), (len), (data)+(len), (data)+(len)+1)
#endif

extern void SendRawCommand14443B_Ex(UsbCommand *c);
extern void iso14443b_setup();
extern uint8_t iso14443b_apdu(uint8_t const *message, size_t message_length, uint8_t *response);
extern uint8_t iso14443b_select_card(iso14b_card_select_t *card);
extern uint8_t iso14443b_select_card_srx(iso14b_card_select_t *card);

// testfunctions
extern void WaitForFpgaDelayQueueIsEmpty(uint16_t delay);
extern void ClearFpgaShiftingRegisters(void);

// States for 14B SIM command
#define SIM_NOFIELD     0
#define SIM_IDLE        1
#define SIM_HALTED      2
#define SIM_SELECTING   3
#define SIM_HALTING     4
#define SIM_ACKNOWLEDGE 5
#define SIM_WORK        6

#ifdef __cplusplus
}
#endif

#endif /* __ISO14443B_H */
