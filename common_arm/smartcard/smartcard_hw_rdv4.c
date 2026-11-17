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
#include "smartcard_hw_rdv4.h"

#include "i2c_apis.h"
#include "proxmark3_arm.h"
#include "ticks_apis.h"
#include "dbprint.h"

// set the reset state
void SmartCard_HwSetAdapterLines(uint8_t LineRST, uint8_t LineSCK, uint8_t LineSDA) {
    if (LineRST)
        RST_H;
    else
        RST_L;

    if (LineSCK)
        SCL_H;
    else
        SCL_L;

    if (LineSDA)
        SDA_H;
    else
        SDA_L;
}

// How long to allow the SIM module to *start* an operation, i.e. to pull SCL
// low after it has taken a command.
//
// This used to be 1200 ms, which is three orders of magnitude more than the
// module needs - its interrupt hands the command to the main loop and SCL goes
// low within microseconds of the STOP.  The only thing that long allowance ever
// bought was dead time: every caller that arrives when the module has *already*
// finished (SCL back high, and it is never going to go low again) sat here for
// the full 1200 ms before doing the read.  SmartCard_RxBytes() does exactly that on
// every call that follows a completed operation, which is why an ordinary
// `smart info` took about one and a half seconds.
//
// The result is ignored by SmartCard_RxBytes() anyway - reaching the end of this
// simply means the module is idle and the data is ready to read.
#define SIM_START_TIMEOUT_MS  50

static bool WaitSCL_L_timeout(void) {
    // How long the module may take to *start* stretching, not how long it may
    // hold. Polled at bus granularity: a command the module already finished
    // never shows SCL low at all, and at 1 ms a step that cost the full
    // timeout on every fast exchange.
    return I2C_WaitSCL_L(I2C_ITERS_FOR_MS(SIM_START_TIMEOUT_MS));
}

bool SmartCard_HwWaitForSim(uint32_t wait) {

    // wait for data from card
    if (WaitSCL_L_timeout() == false) {
        return false;
    }

    // wait is an iteration count; build it with I2C_ITERS_FOR_MS().
    return I2C_WaitSCL_H(wait);
}

bool SmartCard_RxBytes(uint8_t *dest, uint16_t *destlen, uint32_t wait) {

    uint8_t i = 10;
    int16_t len = 0;
    while (i--) {

        SmartCard_HwWaitForSim(wait);

        len = I2C_AdaptiveRead(dest, *destlen, I2C_DEVICE_CMD_READ, I2C_DEVICE_ADDRESS_MAIN);

        LED_C_ON();

        if (len > 1) {
            break;
        } else if (len == 1) {
            continue;
        } else {
            return false;
        }
    }

    *destlen = len;
    return true;
}
