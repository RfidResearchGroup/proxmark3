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
// RDV4 card side: the SIM adapter, reached over the bit banged I2C bus.
//-----------------------------------------------------------------------------

#ifndef SMARTCARD_HW_RDV4_H
#define SMARTCARD_HW_RDV4_H

#include <stdbool.h>
#include <stdint.h>

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

// What this adapter can tell us beyond its version number. The write-up of a
// version belongs to the board that owns the firmware, so it lives here rather
// than in the shared interface.
typedef struct {
    bool ok;    // meets the minimum this build supports
    bool t1;    // T=1 and PPS in this adapter firmware
} smartcard_rdv4_info_t;

// Reset and line control of the adapter.
void SmartCard_HwSetAdapterLines(uint8_t LineRST, uint8_t LineSCK, uint8_t LineSDA);

// Wait until the adapter has taken the command and stopped stretching SCL,
// then until it has an answer ready. wait is an iteration count, build it with
// I2C_ITERS_FOR_MS().
bool SmartCard_HwWaitForSim(uint32_t wait);

// Read one answer frame from the adapter.
bool SmartCard_RxBytes(uint8_t *dest, uint16_t *destlen, uint32_t wait);

// Raw sequential access to the adapter's byte address space, used to write and
// verify its firmware. Only this board exposes an update path today, so these
// do not belong to the shared interface.
void SmartCard_HwOpenBootloader(void);
int16_t SmartCard_HwModuleRead(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address);
bool SmartCard_HwModuleWrite(const uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address);

#endif // SMARTCARD_HW_RDV4_H
